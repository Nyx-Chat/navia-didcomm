use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    jws,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyAlg},
        did::did_or_url,
        secure_cmp::secure_string_eq,
    },
    FromPrior,
};
use askar_crypto::alg::{ed25519::Ed25519KeyPair, k256::K256KeyPair, p256::P256KeyPair};
use base64::prelude::*;

impl FromPrior {
    /// Unpacks a plaintext value from a signed `from_prior` JWT.
    /// https://identity.foundation/didcomm-messaging/spec/#did-rotation
    ///
    /// # Parameters
    /// - `from_prior_jwt` signed `from_prior` JWT.
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    ///
    /// # Returns
    /// Tuple (plaintext `from_prior` value, identifier of the issuer key used to sign `from_prior`)
    ///
    /// # Errors
    /// - `Malformed` Signed `from_prior` JWT is malformed, or its `iss` is not the DID of the
    ///   key that signed it.
    /// - `DIDNotResolved` Issuer DID not found.
    /// - `DIDUrlNotFound` Issuer authentication verification method is not found.
    /// - `Unsupported` Used crypto or method is unsupported.
    pub async fn unpack<'dr>(
        from_prior_jwt: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
    ) -> Result<(FromPrior, String)> {
        let mut buf = vec![];
        let parsed = jws::parse_compact(from_prior_jwt, &mut buf)?;

        let typ = parsed.parsed_header.typ;
        let alg = parsed.parsed_header.alg.clone();
        let kid = parsed.parsed_header.kid;

        if typ != "JWT" {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior is malformed: typ is not JWT",
            ))?;
        }

        let (did, did_url) = did_or_url(kid);

        if did_url.is_none() {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior kid is not DID URL",
            ))?;
        }

        let did_doc = did_resolver
            .resolve(did)
            .await
            .context("Unable to resolve from_prior issuer DID")?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDNotResolved,
                    "from_prior issuer DIDDoc not found",
                )
            })?;

        let kid = did_doc
            .authentication
            .iter()
            .find(|&k| k.as_str() == kid)
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDUrlNotFound,
                    "from_prior issuer kid not found in DIDDoc",
                )
            })?
            .as_str();

        let key = did_doc
            .verification_method
            .iter()
            .find(|&vm| secure_string_eq(&vm.id, kid))
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDUrlNotFound,
                    "from_prior issuer verification method not found in DIDDoc",
                )
            })?;

        // alg comes from the JWT header and the key type from the issuer's DID document,
        // so a mismatch between them is a fault of the JWT. An issuer key of a type this
        // crate doesn't support is not, whatever alg the JWT names.
        match (alg.key_alg(), key.key_alg()) {
            (Some(_), KnownKeyAlg::Unsupported) => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported from_prior issuer key type",
            ))?,
            (Some(expected), actual) if expected != actual => Err(err_msg(
                ErrorKind::Malformed,
                "from_prior alg does not match issuer key type",
            ))?,
            _ => {}
        }

        let valid = match alg {
            jws::Algorithm::EdDSA => {
                let key = key
                    .as_ed25519()
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed
                    .verify::<Ed25519KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Es256 => {
                let key = key
                    .as_p256()
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed
                    .verify::<P256KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Es256K => {
                let key = key
                    .as_k256()
                    .context("Unable to instantiate from_prior issuer key")?;

                parsed
                    .verify::<K256KeyPair>(&key)
                    .context("Unable to verify from_prior signature")?
            }
            jws::Algorithm::Other(_) => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported signature algorithm",
            ))?,
        };

        if !valid {
            Err(err_msg(ErrorKind::Malformed, "Wrong from_prior signature"))?;
        }

        let payload = BASE64_URL_SAFE_NO_PAD.decode(parsed.payload).kind(
            ErrorKind::Malformed,
            "from_prior payload is not a valid base64",
        )?;

        let payload = String::from_utf8(payload).kind(
            ErrorKind::Malformed,
            "Decoded from_prior payload is not a valid UTF-8",
        )?;

        let from_prior: FromPrior = serde_json::from_str(&payload)
            .kind(ErrorKind::Malformed, "Unable to parse from_prior")?;

        // The signature proves that the holder of `kid` wrote the payload, so `iss` has to
        // be that holder, not whoever the payload says.
        if from_prior.iss != did {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior `iss` is not the DID of the signing key",
            ))?;
        }

        Ok((from_prior, kid.into()))
    }

    /// Checks `exp` and `nbf` against `now` (seconds since the Unix epoch).
    ///
    /// # Errors
    /// - `Expired` `exp <= now`.
    /// - `NotYetValid` `nbf > now + future_skew_secs`.
    pub fn check_times(&self, now: u64, future_skew_secs: u64) -> Result<()> {
        if let Some(exp) = self.exp {
            if exp <= now {
                Err(err_msg(ErrorKind::Expired, "from_prior has expired"))?;
            }
        }

        if let Some(nbf) = self.nbf {
            if nbf > now.saturating_add(future_skew_secs) {
                Err(err_msg(
                    ErrorKind::NotYetValid,
                    "from_prior is not valid yet",
                ))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;
    use serde_json::Value;

    use crate::{
        did::{resolvers::ExampleDIDResolver, VerificationMaterial},
        error::ErrorKind,
        test_vectors::{
            ALICE_DID_DOC, CHARLIE_AUTH_METHOD_25519, CHARLIE_DID_DOC, FROM_PRIOR_FULL,
            FROM_PRIOR_JWT_FULL, FROM_PRIOR_JWT_INVALID, FROM_PRIOR_JWT_INVALID_SIGNATURE,
        },
        FromPrior,
    };

    #[test]
    fn check_times_separates_expired_from_not_yet_valid_at_the_boundaries() {
        const NOW: u64 = 1_000_000;
        const SKEW: u64 = 60;

        let with = |exp: Option<u64>, nbf: Option<u64>| {
            let mut builder = FromPrior::build("did:example:a".into(), "did:example:b".into());
            if let Some(exp) = exp {
                builder = builder.exp(exp);
            }
            if let Some(nbf) = nbf {
                builder = builder.nbf(nbf);
            }
            builder.finalize()
        };

        with(None, None)
            .check_times(NOW, SKEW)
            .expect("no time claims");
        with(Some(NOW + 1), Some(NOW + SKEW))
            .check_times(NOW, SKEW)
            .expect("exp one second ahead, nbf exactly the skew ahead");

        for exp in [NOW - 1, NOW] {
            let err = with(Some(exp), None)
                .check_times(NOW, SKEW)
                .expect_err("expired");
            assert_eq!(err.kind(), ErrorKind::Expired, "exp {exp}");
        }

        let err = with(None, Some(NOW + SKEW + 1))
            .check_times(NOW, SKEW)
            .expect_err("not valid yet");
        assert_eq!(err.kind(), ErrorKind::NotYetValid);

        let err = with(Some(NOW), Some(NOW + SKEW + 1))
            .check_times(NOW, SKEW)
            .expect_err("both");
        assert_eq!(err.kind(), ErrorKind::Expired, "exp is checked first");
    }

    #[tokio::test]
    async fn from_prior_unpack_works() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);

        let (from_prior, issuer_kid) = FromPrior::unpack(FROM_PRIOR_JWT_FULL, &did_resolver)
            .await
            .expect("unpack FromPrior failed");

        assert_eq!(&from_prior, &*FROM_PRIOR_FULL);
        assert_eq!(issuer_kid, CHARLIE_AUTH_METHOD_25519.id);
    }

    #[tokio::test]
    async fn from_prior_unpack_works_invalid() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);

        let err = FromPrior::unpack(FROM_PRIOR_JWT_INVALID, &did_resolver)
            .await
            .expect_err("res is ok");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(
            format!("{err}"),
            "Message malformed or invalid: Unable to parse compactly serialized JWS"
        );
    }

    #[tokio::test]
    async fn from_prior_unpack_works_invalid_signature() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);

        let err = FromPrior::unpack(FROM_PRIOR_JWT_INVALID_SIGNATURE, &did_resolver)
            .await
            .expect_err("res is ok");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(format!("{err}"), "Message malformed or invalid: Unable to verify from_prior signature: Unable decode signature: Invalid last symbol 66, offset 85.");
    }

    #[tokio::test]
    async fn from_prior_unpack_works_alg_key_mismatch() {
        let did_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), CHARLIE_DID_DOC.clone()]);

        // The issuer key (charlie#key-1) is Ed25519, the header claims ES256.
        let (header, rest) = FROM_PRIOR_JWT_FULL.split_once('.').unwrap();
        let mut header: Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        header["alg"] = "ES256".into();
        let jwt = format!(
            "{}.{rest}",
            BASE64_URL_SAFE_NO_PAD.encode(header.to_string())
        );

        let err = FromPrior::unpack(&jwt, &did_resolver)
            .await
            .expect_err("res is ok");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(
            format!("{err}"),
            "Message malformed or invalid: from_prior alg does not match issuer key type"
        );
    }

    #[tokio::test]
    async fn from_prior_unpack_works_unsupported_issuer_key_type() {
        // An Ed448 issuer key fits the EdDSA alg of the JWT, but this crate can't verify with it.
        let mut charlie_did_doc = CHARLIE_DID_DOC.clone();
        let issuer_key = charlie_did_doc
            .verification_method
            .iter_mut()
            .find(|vm| vm.id == CHARLIE_AUTH_METHOD_25519.id)
            .unwrap();
        let VerificationMaterial::JWK { public_key_jwk } = &mut issuer_key.verification_material
        else {
            panic!("charlie#key-1 is not a JWK");
        };
        public_key_jwk["crv"] = "Ed448".into();

        let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), charlie_did_doc]);

        let err = FromPrior::unpack(FROM_PRIOR_JWT_FULL, &did_resolver)
            .await
            .expect_err("res is ok");

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(
            format!("{err}"),
            "Unsupported cryptographic algorithm or method: Unsupported from_prior issuer key type"
        );
    }
}
