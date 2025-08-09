use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    message::from_prior::JWT_TYP,
    pqc_jws,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyPair},
        did::{did_or_url, is_did},
    },
    FromPrior,
};

impl FromPrior {
    /// Packs a plaintext `from_prior` value into a signed JWT.
    /// https://identity.foundation/didcomm-messaging/spec/#did-rotation
    ///
    /// # Parameters
    /// - `issuer_kid` (optional) identifier of the issuer key being used to sign `from_prior` JWT value.
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    /// - `secrets_resolver` instance of `SecretsResolver` to resolve issuer DID keys secrets.
    ///
    /// # Returns
    /// Tuple (signed `from_prior` JWT, identifier of the issuer key actually used to sign `from_prior`)
    ///
    /// # Errors
    /// - `Malformed` `from_prior` plaintext value has invalid format.
    /// - `IllegalArgument` `issuer_kid` is invalid or does not consist with `from_prior` plaintext value.
    /// - `DIDNotResolved` Issuer DID not found.
    /// - `DIDUrlNotFound` Issuer authentication verification method is not found.
    /// - `SecretNotFound` Issuer secret is not found.
    /// - `Unsupported` Used crypto or method is unsupported.
    /// - `InvalidState` Indicates a library error.
    pub async fn pack<'dr, 'sr>(
        &self,
        issuer_kid: Option<&str>,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    ) -> Result<(String, String)> {
        self.validate_pack(issuer_kid)?;

        let from_prior_str = serde_json::to_string(self)
            .kind(ErrorKind::InvalidState, "Unable serialize message")?;

        let did_doc = did_resolver
            .resolve(&self.iss)
            .await
            .context("Unable to resolve from_prior issuer DID")?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDNotResolved,
                    "from_prior issuer DIDDoc is not found",
                )
            })?;

        let authentication_kids: Vec<&str> = if let Some(issuer_kid) = issuer_kid {
            let (did, kid) = did_or_url(issuer_kid);

            let kid = kid.ok_or_else(|| {
                err_msg(
                    ErrorKind::IllegalArgument,
                    "issuer_kid content is not DID URL",
                )
            })?;

            if did != self.iss {
                Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "from_prior issuer kid does not belong to from_prior `iss`",
                ))?
            }

            let kid = did_doc
                .authentication
                .iter()
                .find(|a| *a == kid)
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::DIDUrlNotFound,
                        "Provided issuer_kid is not found in DIDDoc",
                    )
                })?;

            vec![kid]
        } else {
            did_doc.authentication.iter().map(|s| s.as_str()).collect()
        };

        let kid = *secrets_resolver
            .find_secrets(&authentication_kids)
            .await
            .context("Unable to find secrets")?
            .first()
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::SecretNotFound,
                    "No from_prior issuer secrets found",
                )
            })?;

        let secret = secrets_resolver
            .get_secret(kid)
            .await
            .context("Unable to find secret")?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::SecretNotFound,
                    "from_prior issuer secret not found",
                )
            })?;

        let sign_key = secret
            .as_key_pair()
            .context("Unable to instantiate from_prior issuer key")?;

        let from_prior_jwt = match sign_key {
            KnownKeyPair::MlDsa65(ref key) => {
                pqc_jws::sign_ml_dsa_65_compact(from_prior_str.as_bytes(), key, JWT_TYP)
            }
            KnownKeyPair::MlDsa87(ref key) => {
                pqc_jws::sign_ml_dsa_87_compact(from_prior_str.as_bytes(), key, JWT_TYP)
            }
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported signature alg"))?,
        }
        .context("Unable to produce signature")?;

        Ok((from_prior_jwt, String::from(kid)))
    }

    pub(crate) fn validate_pack(&self, issuer_kid: Option<&str>) -> Result<()> {
        if !is_did(&self.iss) || did_or_url(&self.iss).1.is_some() {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior `iss` must be a non-fragment DID",
            ))?;
        }

        if !is_did(&self.sub) || did_or_url(&self.sub).1.is_some() {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior `sub` must be a non-fragment DID",
            ))?;
        }

        if self.iss == self.sub {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior `iss` and `sub` values must not be equal",
            ))?;
        }

        if let Some(issuer_kid) = issuer_kid {
            let (did, kid) = did_or_url(issuer_kid);

            if kid.is_none() {
                Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "issuer_kid content is not DID URL",
                ))?;
            };

            if did != self.iss {
                Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "from_prior issuer kid does not belong to from_prior `iss`",
                ))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::ErrorKind,
        test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
        utils::did::did_or_url,
        FromPrior,
    };

    #[tokio::test]
    async fn test_pqc_from_prior_pack_works_with_issuer_kid() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());

        // Create a from_prior message for DID rotation (Alice -> Bob)
        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200), // 2022-01-01 00:00:00
            jti: None,
        };

        let alice_auth_kid = format!("{}#authentication-1", vectors.alice_did);

        let (from_prior_jwt, pack_kid) = from_prior
            .pack(Some(&alice_auth_kid), &did_resolver, &alice_secrets)
            .await
            .expect("Unable to pack FromPrior with PQC");

        assert_eq!(pack_kid, alice_auth_kid);

        let (unpacked_from_prior, unpack_kid) = FromPrior::unpack(&from_prior_jwt, &did_resolver)
            .await
            .expect("Unable to unpack FromPrior JWT with PQC");

        assert_eq!(&unpacked_from_prior, &from_prior);
        assert_eq!(unpack_kid, alice_auth_kid);
    }

    #[tokio::test]
    async fn test_pqc_from_prior_pack_works_without_issuer_kid() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());

        // Create a from_prior message for DID rotation (Alice -> Bob)
        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200), // 2022-01-01 00:00:00
            jti: None,
        };

        let (from_prior_jwt, pack_kid) = from_prior
            .pack(
                None, // No specific issuer kid - should pick first available
                &did_resolver,
                &alice_secrets,
            )
            .await
            .expect("Unable to pack FromPrior without specific kid");

        let (did, kid) = did_or_url(&pack_kid);
        assert!(kid.is_some());
        assert_eq!(did, vectors.alice_did);

        let (unpacked_from_prior, unpack_kid) = FromPrior::unpack(&from_prior_jwt, &did_resolver)
            .await
            .expect("Unable to unpack FromPrior JWT");

        assert_eq!(&unpacked_from_prior, &from_prior);
        assert_eq!(unpack_kid, pack_kid);
    }

    #[tokio::test]
    async fn test_pqc_from_prior_pack_wrong_issuer_kid() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());

        // Create a from_prior message for DID rotation (Alice -> Bob)
        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200),
            jti: None,
        };

        // Test with wrong issuer kid (Bob's key for Alice's iss)
        let bob_auth_kid = format!("{}#authentication-1", vectors.bob_did);
        let err = from_prior
            .pack(Some(&bob_auth_kid), &did_resolver, &alice_secrets)
            .await
            .expect_err("Should fail with wrong issuer kid");

        assert_eq!(err.kind(), ErrorKind::IllegalArgument);
        assert!(
            format!("{err}").contains("from_prior issuer kid does not belong to from_prior `iss`")
        );

        // Test with non-DID URL
        let err = from_prior
            .pack(Some(&vectors.alice_did), &did_resolver, &alice_secrets)
            .await
            .expect_err("Should fail with non-DID URL");

        assert_eq!(err.kind(), ErrorKind::IllegalArgument);
        assert!(format!("{err}").contains("issuer_kid content is not DID URL"));

        // Test with invalid string
        let err = from_prior
            .pack(Some("invalid"), &did_resolver, &alice_secrets)
            .await
            .expect_err("Should fail with invalid string");

        assert_eq!(err.kind(), ErrorKind::IllegalArgument);
        assert!(format!("{err}").contains("issuer_kid content is not DID URL"));
    }

    #[tokio::test]
    async fn test_pqc_from_prior_pack_invalid_inputs() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());

        // Test invalid iss (not a DID)
        let invalid_iss_from_prior = FromPrior {
            iss: "invalid-not-a-did".to_string(),
            sub: vectors.bob_did.clone(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200),
            jti: None,
        };

        let err = invalid_iss_from_prior
            .pack(None, &did_resolver, &alice_secrets)
            .await
            .expect_err("Should fail with invalid iss");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert!(format!("{err}").contains("from_prior `iss` must be a non-fragment DID"));

        // Test invalid sub (not a DID)
        let invalid_sub_from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: "invalid-not-a-did".to_string(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200),
            jti: None,
        };

        let err = invalid_sub_from_prior
            .pack(None, &did_resolver, &alice_secrets)
            .await
            .expect_err("Should fail with invalid sub");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert!(format!("{err}").contains("from_prior `sub` must be a non-fragment DID"));

        // Test equal iss and sub
        let equal_iss_sub_from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.alice_did.clone(), // Same as iss
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200),
            jti: None,
        };

        let err = equal_iss_sub_from_prior
            .pack(None, &did_resolver, &alice_secrets)
            .await
            .expect_err("Should fail with equal iss and sub");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert!(format!("{err}").contains("from_prior `iss` and `sub` values must not be equal"));
    }

    #[tokio::test]
    async fn test_pqc_from_prior_ml_kem_1024_ml_dsa_87() {
        let vectors = PQCTestVector::ml_kem_1024_ml_dsa_87()
            .expect("Failed to create ML-KEM-1024 test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());

        // Create a from_prior message for DID rotation using ML-DSA-87
        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(),
            aud: Some("test-audience".to_string()),
            exp: Some(1672531200), // 2023-01-01 00:00:00
            nbf: Some(1640995200), // 2022-01-01 00:00:00
            iat: Some(1640995200),
            jti: Some("test-jti-123".to_string()),
        };

        let (from_prior_jwt, pack_kid) = from_prior
            .pack(None, &did_resolver, &alice_secrets)
            .await
            .expect("Unable to pack FromPrior with ML-DSA-87");

        // Verify it uses ML-DSA-87 key
        assert!(pack_kid.contains("authentication-1"));

        let (unpacked_from_prior, unpack_kid) = FromPrior::unpack(&from_prior_jwt, &did_resolver)
            .await
            .expect("Unable to unpack FromPrior JWT with ML-DSA-87");

        assert_eq!(&unpacked_from_prior, &from_prior);
        assert_eq!(unpack_kid, pack_kid);

        // Verify all optional fields are preserved
        assert_eq!(unpacked_from_prior.aud, Some("test-audience".to_string()));
        assert_eq!(unpacked_from_prior.exp, Some(1672531200));
        assert_eq!(unpacked_from_prior.nbf, Some(1640995200));
        assert_eq!(unpacked_from_prior.jti, Some("test-jti-123".to_string()));
    }
}
