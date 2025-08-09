use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultExt},
    FromPrior, Message,
};

impl Message {
    /// Produces `DIDComm Plaintext Messages`
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages.
    ///
    /// A DIDComm message in its plaintext form, not packaged into any protective envelope,
    /// is known as a DIDComm plaintext message. Plaintext messages lack confidentiality and integrity
    /// guarantees, and are repudiable. They are therefore not normally transported across security boundaries.
    /// However, this may be a helpful format to inspect in debuggers, since it exposes underlying semantics,
    /// and it is the format used in this spec to give examples of headers and other internals.
    /// Depending on ambient security, plaintext may or may not be an appropriate format for DIDComm data at rest.
    ///
    /// # Returns
    /// - a DIDComm plaintext message s JSON string
    ///
    /// # Errors
    /// - `Malformed` Signed `from_prior` JWT is malformed.
    /// - `DIDNotResolved` `from_prior` issuer DID not found.
    /// - `DIDUrlNotFound` `from_prior` issuer authentication verification method is not found.
    /// - `Unsupported` Crypto or method used for signing `from_prior` is unsupported.
    /// - `InvalidState` Indicates a library error.
    pub async fn pack_plaintext<'dr, 'sr>(
        &self,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
    ) -> Result<String> {
        let (from_prior, from_prior_issuer_kid) = match self.from_prior {
            Some(ref from_prior) => {
                let (from_prior, from_prior_issuer_kid) =
                    FromPrior::unpack(from_prior, did_resolver).await?;
                (Some(from_prior), Some(from_prior_issuer_kid))
            }
            None => (None, None),
        };

        self._validate_pack_plaintext(from_prior.as_ref(), from_prior_issuer_kid.as_deref())?;

        let msg = serde_json::to_string(self)
            .kind(ErrorKind::InvalidState, "Unable to serialize message")?;

        Ok(msg)
    }

    fn _validate_pack_plaintext(
        &self,
        from_prior: Option<&FromPrior>,
        from_prior_issuer_kid: Option<&str>,
    ) -> Result<()> {
        if let Some(from_prior) = from_prior {
            from_prior.validate_pack(from_prior_issuer_kid)?;

            if let Some(ref from) = self.from {
                if &from_prior.sub != from {
                    Err(err_msg(
                        ErrorKind::Malformed,
                        "from_prior `sub` value is not equal to message `from` value",
                    ))?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::ErrorKind,
        pqc_jws,
        test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
        utils::crypto::AsKnownKeyPair,
        FromPrior, Message, UnpackOptions,
    };
    use serde_json::{json, Value};

    #[tokio::test]
    async fn test_pqc_pack_plaintext_simple() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        // Create a simple message
        let message = Message::build(
            "test-plaintext-id".to_string(),
            "test/plaintext".to_string(),
            json!({
                "content": "Hello PQC World!",
                "mode": "plaintext"
            }),
        )
        .to(vectors.bob_did.clone())
        .from(vectors.alice_did.clone())
        .finalize();

        // Pack as plaintext
        let packed = message
            .pack_plaintext(&did_resolver)
            .await
            .expect("Failed to pack plaintext message");

        // Verify it's valid JSON and contains expected fields
        let parsed: Value =
            serde_json::from_str(&packed).expect("Packed message should be valid JSON");

        assert_eq!(parsed["id"], "test-plaintext-id");
        assert_eq!(parsed["type"], "test/plaintext");
        assert_eq!(parsed["body"]["content"], "Hello PQC World!");
        assert_eq!(parsed["to"][0], vectors.bob_did);
        assert_eq!(parsed["from"], vectors.alice_did);
    }

    #[tokio::test]
    async fn test_pqc_pack_plaintext_with_from_prior() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets.clone());

        // Create a from_prior JWT (Alice rotated to Bob)
        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(),
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(1640995200),
            jti: None,
        };

        let from_prior_str =
            serde_json::to_string(&from_prior).expect("Failed to serialize from_prior");
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

        let from_prior_jwt =
            pqc_jws::sign_ml_dsa_65_compact(from_prior_str.as_bytes(), &alice_key, "JWT")
                .expect("Failed to sign from_prior JWT");

        // Create message with from_prior
        let message = Message::build(
            "test-from-prior-id".to_string(),
            "test/from-prior".to_string(),
            json!({
                "content": "Message with from_prior",
                "rotation": true
            }),
        )
        .to(vectors.bob_did.clone())
        .from(vectors.bob_did.clone()) // Bob is the new identity
        .from_prior(from_prior_jwt)
        .finalize();

        // Pack as plaintext
        let packed = message
            .pack_plaintext(&did_resolver)
            .await
            .expect("Failed to pack plaintext with from_prior");

        // Verify packed message
        let parsed: Value =
            serde_json::from_str(&packed).expect("Packed message should be valid JSON");

        assert_eq!(parsed["from"], vectors.bob_did);
        assert!(parsed["from_prior"].is_string());

        // Test round-trip by unpacking
        let (unpacked_msg, unpack_metadata) = Message::unpack(
            &packed,
            &did_resolver,
            &bob_secrets,
            &UnpackOptions::default(),
        )
        .await
        .expect("Failed to unpack plaintext message");

        assert_eq!(unpacked_msg.from, Some(vectors.bob_did.clone()));
        assert_eq!(
            unpack_metadata.from_prior.as_ref().unwrap().iss,
            vectors.alice_did
        );
        assert_eq!(
            unpack_metadata.from_prior.as_ref().unwrap().sub,
            vectors.bob_did
        );
        assert!(unpack_metadata.from_prior_issuer_kid.is_some());
    }

    #[tokio::test]
    async fn test_pqc_pack_plaintext_from_prior_validation() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        // Create a from_prior JWT where sub != message.from (invalid)
        let from_prior = FromPrior {
            iss: vectors.alice_did.clone(),
            sub: vectors.bob_did.clone(), // from_prior.sub is Bob
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

        let from_prior_jwt =
            pqc_jws::sign_ml_dsa_65_compact(from_prior_str.as_bytes(), &alice_key, "JWT")
                .expect("Failed to sign from_prior JWT");

        // Create message with mismatched from field
        let message = Message::build(
            "test-invalid-id".to_string(),
            "test/invalid".to_string(),
            json!({"error": "mismatched from"}),
        )
        .to(vectors.bob_did.clone())
        .from(vectors.alice_did.clone()) // Message.from is Alice, but from_prior.sub is Bob
        .from_prior(from_prior_jwt)
        .finalize();

        // This should fail validation
        let err = message
            .pack_plaintext(&did_resolver)
            .await
            .expect_err("Should fail with mismatched from_prior.sub and message.from");

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert!(format!("{err}")
            .contains("from_prior `sub` value is not equal to message `from` value"));
    }

    #[tokio::test]
    async fn test_pqc_pack_plaintext_with_attachments() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        // Create message with attachment
        let attachment_data = crate::AttachmentData::Base64 {
            value: crate::Base64AttachmentData {
                base64: "SGVsbG8gUFFDIFdvcmxkIQ==".to_string(), // "Hello PQC World!" in base64
                jws: None,
            },
        };

        let attachment = crate::Attachment {
            id: Some("attachment-1".to_string()),
            description: Some("Test attachment".to_string()),
            filename: Some("test.txt".to_string()),
            media_type: Some("text/plain".to_string()),
            format: None,
            lastmod_time: None,
            byte_count: Some(16),
            data: attachment_data,
        };

        let message = Message::build(
            "test-attachment-id".to_string(),
            "test/attachment".to_string(),
            json!({
                "content": "Message with attachment"
            }),
        )
        .to(vectors.bob_did.clone())
        .from(vectors.alice_did.clone())
        .attachment(attachment)
        .finalize();

        // Pack as plaintext
        let packed = message
            .pack_plaintext(&did_resolver)
            .await
            .expect("Failed to pack plaintext with attachment");

        // Verify attachment is preserved
        let parsed: Value =
            serde_json::from_str(&packed).expect("Packed message should be valid JSON");

        assert!(parsed["attachments"].is_array());
        assert_eq!(parsed["attachments"][0]["id"], "attachment-1");
        assert_eq!(
            parsed["attachments"][0]["data"]["base64"],
            "SGVsbG8gUFFDIFdvcmxkIQ=="
        );
    }

    #[tokio::test]
    async fn test_pqc_pack_plaintext_minimal_message() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        // Create minimal message (only required fields)
        let message = Message::build(
            "minimal-id".to_string(),
            "minimal/type".to_string(),
            json!("minimal body"),
        )
        .to(vectors.bob_did.clone())
        .finalize(); // No from field

        // Pack as plaintext
        let packed = message
            .pack_plaintext(&did_resolver)
            .await
            .expect("Failed to pack minimal plaintext message");

        // Verify minimal structure
        let parsed: Value =
            serde_json::from_str(&packed).expect("Packed message should be valid JSON");

        assert_eq!(parsed["id"], "minimal-id");
        assert_eq!(parsed["type"], "minimal/type");
        assert_eq!(parsed["body"], "minimal body");
        assert_eq!(parsed["to"][0], vectors.bob_did);
        assert!(parsed.get("from").is_none()); // from field should be absent
    }
}
