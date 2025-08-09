use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    pqc_jws::{self as jws, Algorithm},
    utils::{crypto::AsKnownKeyPair, did::did_or_url},
    FromPrior,
};
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
    /// - `Malformed` Signed `from_prior` JWT is malformed.
    /// - `DIDNotResolved` Issuer DID not found.
    /// - `DIDUrlNotFound` Issuer authentication verification method is not found.
    /// - `Unsupported` Used crypto or method is unsupported.
    pub async fn unpack<'dr>(
        from_prior_jwt: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
    ) -> Result<(FromPrior, String)> {
        let (protected_header, payload, signature) = jws::parse_compact(from_prior_jwt)?;

        let typ = &protected_header.typ;
        let alg = protected_header.alg.clone();

        if typ != "JWT" {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior is malformed: typ is not JWT",
            ))?;
        }

        // First decode the payload to get the issuer DID
        let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(&payload).kind(
            ErrorKind::Malformed,
            "from_prior payload is not a valid base64",
        )?;

        let payload_str = String::from_utf8(payload_bytes).kind(
            ErrorKind::Malformed,
            "Decoded from_prior payload is not a valid UTF-8",
        )?;

        let temp_from_prior: FromPrior = serde_json::from_str(&payload_str)
            .kind(ErrorKind::Malformed, "Unable to parse from_prior payload")?;

        // Resolve the issuer DID to find authentication keys
        let did_doc = did_resolver
            .resolve(&temp_from_prior.iss)
            .await
            .context("Unable to resolve from_prior issuer DID")?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDNotResolved,
                    "from_prior issuer DIDDoc not found",
                )
            })?;

        // Find authentication verification method that matches the algorithm
        let auth_method = did_doc
            .verification_method
            .iter()
            .find(|vm| {
                did_doc.authentication.contains(&vm.id)
                    && match &alg {
                        Algorithm::MlDsa65 => matches!(
                            vm.type_,
                            crate::did::VerificationMethodType::MlDsa65VerificationKey2025
                        ),
                        Algorithm::MlDsa87 => matches!(
                            vm.type_,
                            crate::did::VerificationMethodType::MlDsa87VerificationKey2025
                        ),
                        _ => false,
                    }
            })
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::DIDUrlNotFound,
                    "No compatible authentication verification method found for algorithm",
                )
            })?;

        let kid = &auth_method.id;
        let (_did, did_url) = did_or_url(kid);

        if did_url.is_none() {
            Err(err_msg(
                ErrorKind::Malformed,
                "from_prior kid is not DID URL",
            ))?
        }

        let valid = match alg {
            jws::Algorithm::MlDsa65 => {
                let signer_key = auth_method.as_ml_dsa_65().kind(
                    ErrorKind::InvalidState,
                    "Unable to instantiate from_prior issuer key",
                )?;

                let signature_bytes = BASE64_URL_SAFE_NO_PAD
                    .decode(&signature)
                    .kind(ErrorKind::InvalidState, "Unable to decode signature")?;

                let signing_input = format!(
                    "{}.{}",
                    BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected_header).unwrap()),
                    payload
                );

                crate::pqc_jws::verify_ml_dsa_65(
                    &signature_bytes,
                    signing_input.as_bytes(),
                    signer_key.public_key(),
                )
                .kind(
                    ErrorKind::Malformed,
                    "Unable verify ML-DSA-65 from_prior signature",
                )?
            }
            jws::Algorithm::MlDsa87 => {
                let signer_key = auth_method.as_ml_dsa_87().kind(
                    ErrorKind::InvalidState,
                    "Unable to instantiate from_prior issuer key",
                )?;

                let signature_bytes = BASE64_URL_SAFE_NO_PAD
                    .decode(&signature)
                    .kind(ErrorKind::InvalidState, "Unable to decode signature")?;

                let signing_input = format!(
                    "{}.{}",
                    BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected_header).unwrap()),
                    payload
                );

                crate::pqc_jws::verify_ml_dsa_87(
                    &signature_bytes,
                    signing_input.as_bytes(),
                    signer_key.public_key(),
                )
                .kind(
                    ErrorKind::Malformed,
                    "Unable verify ML-DSA-87 from_prior signature",
                )?
            }
            jws::Algorithm::Other => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported signature algorithm",
            ))?,
        };

        if !valid {
            Err(err_msg(ErrorKind::Malformed, "Wrong from_prior signature"))?
        }

        Ok((temp_from_prior, kid.clone()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::ErrorKind,
        pqc_jws,
        test_vectors::{PQCTestDIDResolver, PQCTestVector},
        utils::crypto::AsKnownKeyPair,
        FromPrior,
    };

    #[tokio::test]
    async fn test_pqc_from_prior_unpack_works() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        // Create a from_prior message
        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200),
            jti: None,
        };

        // Create a compact JWT manually using the ML-DSA-65 key
        let from_prior_str =
            serde_json::to_string(&from_prior).expect("Failed to serialize from_prior");
        let alice_ml_dsa_key = vectors
            .alice_secrets
            .values()
            .find(|s| {
                matches!(
                    s.type_,
                    crate::secrets::SecretType::MlDsa65VerificationKey2025
                )
            })
            .expect("Alice should have ML-DSA-65 key")
            .as_ml_dsa_65()
            .expect("Should convert to ML-DSA-65 keypair");

        let jwt =
            pqc_jws::sign_ml_dsa_65_compact(from_prior_str.as_bytes(), &alice_ml_dsa_key, "JWT")
                .expect("Failed to sign JWT");

        // Test unpacking
        let (unpacked_from_prior, issuer_kid) = FromPrior::unpack(&jwt, &did_resolver)
            .await
            .expect("Failed to unpack FromPrior JWT");

        assert_eq!(unpacked_from_prior.iss, vectors.alice_did);
        assert_eq!(unpacked_from_prior.sub, vectors.bob_did);
        assert_eq!(unpacked_from_prior.iat, Some(1640995200));
        assert!(issuer_kid.contains(&vectors.alice_did));
        assert!(issuer_kid.contains("authentication-1"));
    }

    #[tokio::test]
    async fn test_pqc_from_prior_unpack_ml_dsa_87() {
        let vectors = PQCTestVector::ml_kem_1024_ml_dsa_87()
            .expect("Failed to create ML-DSA-87 test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        // Create a from_prior message with all optional fields
        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(),
            aud: Some("test-audience".to_string()),
            exp: Some(1672531200),
            nbf: Some(1640995200),
            iat: Some(1640995200),
            jti: Some("test-jti-456".to_string()),
        };

        // Create a compact JWT using ML-DSA-87
        let from_prior_str =
            serde_json::to_string(&from_prior).expect("Failed to serialize from_prior");
        let alice_ml_dsa_key = vectors
            .alice_secrets
            .values()
            .find(|s| {
                matches!(
                    s.type_,
                    crate::secrets::SecretType::MlDsa87VerificationKey2025
                )
            })
            .expect("Alice should have ML-DSA-87 key")
            .as_ml_dsa_87()
            .expect("Should convert to ML-DSA-87 keypair");

        let jwt =
            pqc_jws::sign_ml_dsa_87_compact(from_prior_str.as_bytes(), &alice_ml_dsa_key, "JWT")
                .expect("Failed to sign JWT");

        // Test unpacking
        let (unpacked_from_prior, issuer_kid) = FromPrior::unpack(&jwt, &did_resolver)
            .await
            .expect("Failed to unpack FromPrior JWT with ML-DSA-87");

        assert_eq!(unpacked_from_prior, from_prior);
        assert!(issuer_kid.contains(&vectors.alice_did));
        assert!(issuer_kid.contains("authentication-1"));

        // Verify all optional fields are preserved
        assert_eq!(unpacked_from_prior.aud, Some("test-audience".to_string()));
        assert_eq!(unpacked_from_prior.exp, Some(1672531200));
        assert_eq!(unpacked_from_prior.nbf, Some(1640995200));
        assert_eq!(unpacked_from_prior.jti, Some("test-jti-456".to_string()));
    }

    #[tokio::test]
    async fn test_pqc_from_prior_unpack_invalid_format() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());

        // Test with invalid JWT format (not 3 parts)
        let invalid_jwt = "invalid.jwt";
        let err = FromPrior::unpack(invalid_jwt, &did_resolver)
            .await
            .expect_err("Should fail with invalid format");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert!(format!("{err}").contains("Invalid compact JWS format"));

        // Test with invalid base64
        let invalid_b64_jwt = "invalid-base64.payload.signature";
        let err = FromPrior::unpack(invalid_b64_jwt, &did_resolver)
            .await
            .expect_err("Should fail with invalid base64");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert!(format!("{err}").contains("Invalid base64"));
    }

    #[tokio::test]
    async fn test_pqc_from_prior_unpack_wrong_signature() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        // Create a valid from_prior message
        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200),
            jti: None,
        };

        let from_prior_str = serde_json::to_string(&from_prior).expect("Failed to serialize");
        let alice_key = vectors
            .alice_secrets
            .values()
            .find(|s| {
                matches!(
                    s.type_,
                    crate::secrets::SecretType::MlDsa65VerificationKey2025
                )
            })
            .expect("Alice should have ML-DSA-65 key")
            .as_ml_dsa_65()
            .expect("Should convert to keypair");

        // Create a valid JWT
        let jwt = pqc_jws::sign_ml_dsa_65_compact(from_prior_str.as_bytes(), &alice_key, "JWT")
            .expect("Failed to sign JWT");

        // Tamper with the signature (flip the last character)
        let mut jwt_parts: Vec<&str> = jwt.split('.').collect();
        let mut tampered_sig = jwt_parts[2].to_string();
        tampered_sig.pop();
        tampered_sig.push('X'); // Change last character
        jwt_parts[2] = &tampered_sig;
        let tampered_jwt = jwt_parts.join(".");

        // Test unpacking tampered JWT
        let err = FromPrior::unpack(&tampered_jwt, &did_resolver)
            .await
            .expect_err("Should fail with wrong signature");

        // Could be InvalidState (base64 decode failure) or Malformed (signature verification failure)
        let err_kind = err.kind();
        assert!(err_kind == ErrorKind::Malformed || err_kind == ErrorKind::InvalidState);
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("signature")
                || err_msg.contains("decode")
                || err_msg.contains("invalid")
        );
    }

    #[tokio::test]
    async fn test_pqc_from_prior_unpack_missing_did() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        // Create resolver without the required DID
        let did_resolver = PQCTestDIDResolver::new(); // Empty resolver

        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200),
            jti: None,
        };

        let from_prior_str = serde_json::to_string(&from_prior).expect("Failed to serialize");
        let alice_key = vectors
            .alice_secrets
            .values()
            .find(|s| {
                matches!(
                    s.type_,
                    crate::secrets::SecretType::MlDsa65VerificationKey2025
                )
            })
            .expect("Alice should have ML-DSA-65 key")
            .as_ml_dsa_65()
            .expect("Should convert to keypair");

        let jwt = pqc_jws::sign_ml_dsa_65_compact(from_prior_str.as_bytes(), &alice_key, "JWT")
            .expect("Failed to sign JWT");

        // Test unpacking with missing DID
        let err = FromPrior::unpack(&jwt, &did_resolver)
            .await
            .expect_err("Should fail with missing DID");

        assert_eq!(err.kind(), ErrorKind::DIDNotResolved);
        assert!(format!("{err}").contains("DIDDoc not found"));
    }
}
