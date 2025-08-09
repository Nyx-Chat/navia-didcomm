// PQC-only test vectors module
// This module contains only post-quantum cryptographic test data
// All classical cryptographic algorithms have been removed

use crate::{
    did::{DIDDoc, VerificationMaterial, VerificationMethod, VerificationMethodType},
    error::Result,
    secrets::{Secret, SecretMaterial, SecretType, SecretsResolver},
    utils::pqc::{MlDsa65KeyPair, MlDsa87KeyPair, MlKem1024KeyPair, MlKem768KeyPair},
};

#[cfg(test)]
use crate::{utils::crypto::AsKnownKeyPair, Message, PackEncryptedOptions, UnpackOptions};
use async_trait::async_trait;
use pqcrypto_traits::sign::PublicKey;
use std::collections::HashMap;

/// PQC Test Vector containing DID documents and secrets for testing
pub struct PQCTestVector {
    pub alice_did: String,
    pub alice_did_doc: DIDDoc,
    pub alice_secrets: HashMap<String, Secret>,
    pub bob_did: String,
    pub bob_did_doc: DIDDoc,
    pub bob_secrets: HashMap<String, Secret>,
}

impl PQCTestVector {
    /// Create ML-KEM-768 + ML-DSA-65 test vector
    pub fn ml_kem_768_ml_dsa_65() -> Result<Self> {
        // Generate Alice's keys
        let alice_kem_key = MlKem768KeyPair::generate([1u8; 64]);
        let alice_sign_key = MlDsa65KeyPair::generate();

        // Generate Bob's keys
        let bob_kem_key = MlKem768KeyPair::generate([2u8; 64]);
        let bob_sign_key = MlDsa65KeyPair::generate();

        let alice_did = "did:example:alice".to_string();
        let bob_did = "did:example:bob".to_string();

        let alice_kem_kid = format!("{alice_did}#key-agreement-1");
        let alice_sign_kid = format!("{alice_did}#authentication-1");
        let bob_kem_kid = format!("{bob_did}#key-agreement-1");
        let bob_sign_kid = format!("{bob_did}#authentication-1");

        // Create Alice's DID document
        let alice_did_doc = DIDDoc {
            id: alice_did.clone(),
            key_agreement: vec![alice_kem_kid.clone()],
            authentication: vec![alice_sign_kid.clone()],
            verification_method: vec![
                create_ml_kem_768_verification_method(&alice_kem_kid, &alice_kem_key),
                create_ml_dsa_65_verification_method(&alice_sign_kid, &alice_sign_key),
            ],
            service: vec![],
        };

        // Create Bob's DID document
        let bob_did_doc = DIDDoc {
            id: bob_did.clone(),
            key_agreement: vec![bob_kem_kid.clone()],
            authentication: vec![bob_sign_kid.clone()],
            verification_method: vec![
                create_ml_kem_768_verification_method(&bob_kem_kid, &bob_kem_key),
                create_ml_dsa_65_verification_method(&bob_sign_kid, &bob_sign_key),
            ],
            service: vec![],
        };

        // Create secrets
        let mut alice_secrets = HashMap::new();
        alice_secrets.insert(
            alice_kem_kid.clone(),
            create_ml_kem_768_secret(&alice_kem_kid, &alice_kem_key),
        );
        alice_secrets.insert(
            alice_sign_kid.clone(),
            create_ml_dsa_65_secret(&alice_sign_kid, &alice_sign_key),
        );

        let mut bob_secrets = HashMap::new();
        bob_secrets.insert(
            bob_kem_kid.clone(),
            create_ml_kem_768_secret(&bob_kem_kid, &bob_kem_key),
        );
        bob_secrets.insert(
            bob_sign_kid.clone(),
            create_ml_dsa_65_secret(&bob_sign_kid, &bob_sign_key),
        );

        Ok(PQCTestVector {
            alice_did,
            alice_did_doc,
            alice_secrets,
            bob_did,
            bob_did_doc,
            bob_secrets,
        })
    }

    /// Create ML-KEM-1024 + ML-DSA-87 test vector
    pub fn ml_kem_1024_ml_dsa_87() -> Result<Self> {
        // Generate Alice's keys
        let alice_kem_key = MlKem1024KeyPair::generate([3u8; 64]);
        let alice_sign_key = MlDsa87KeyPair::generate();

        // Generate Bob's keys
        let bob_kem_key = MlKem1024KeyPair::generate([4u8; 64]);
        let bob_sign_key = MlDsa87KeyPair::generate();

        let alice_did = "did:example:alice1024".to_string();
        let bob_did = "did:example:bob1024".to_string();

        let alice_kem_kid = format!("{alice_did}#key-agreement-1");
        let alice_sign_kid = format!("{alice_did}#authentication-1");
        let bob_kem_kid = format!("{bob_did}#key-agreement-1");
        let bob_sign_kid = format!("{bob_did}#authentication-1");

        // Create Alice's DID document
        let alice_did_doc = DIDDoc {
            id: alice_did.clone(),
            key_agreement: vec![alice_kem_kid.clone()],
            authentication: vec![alice_sign_kid.clone()],
            verification_method: vec![
                create_ml_kem_1024_verification_method(&alice_kem_kid, &alice_kem_key),
                create_ml_dsa_87_verification_method(&alice_sign_kid, &alice_sign_key),
            ],
            service: vec![],
        };

        // Create Bob's DID document
        let bob_did_doc = DIDDoc {
            id: bob_did.clone(),
            key_agreement: vec![bob_kem_kid.clone()],
            authentication: vec![bob_sign_kid.clone()],
            verification_method: vec![
                create_ml_kem_1024_verification_method(&bob_kem_kid, &bob_kem_key),
                create_ml_dsa_87_verification_method(&bob_sign_kid, &bob_sign_key),
            ],
            service: vec![],
        };

        // Create secrets
        let mut alice_secrets = HashMap::new();
        alice_secrets.insert(
            alice_kem_kid.clone(),
            create_ml_kem_1024_secret(&alice_kem_kid, &alice_kem_key),
        );
        alice_secrets.insert(
            alice_sign_kid.clone(),
            create_ml_dsa_87_secret(&alice_sign_kid, &alice_sign_key),
        );

        let mut bob_secrets = HashMap::new();
        bob_secrets.insert(
            bob_kem_kid.clone(),
            create_ml_kem_1024_secret(&bob_kem_kid, &bob_kem_key),
        );
        bob_secrets.insert(
            bob_sign_kid.clone(),
            create_ml_dsa_87_secret(&bob_sign_kid, &bob_sign_key),
        );

        Ok(PQCTestVector {
            alice_did,
            alice_did_doc,
            alice_secrets,
            bob_did,
            bob_did_doc,
            bob_secrets,
        })
    }
}

// Helper functions for creating verification methods and secrets

fn create_ml_kem_768_verification_method(id: &str, key: &MlKem768KeyPair) -> VerificationMethod {
    VerificationMethod {
        id: id.to_string(),
        controller: id.split('#').next().unwrap().to_string(),
        type_: VerificationMethodType::MlKem768KeyAgreementKey2025,
        verification_material: VerificationMaterial::Multibase {
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                key.public_key_bytes(),
            ),
        },
    }
}

fn create_ml_kem_1024_verification_method(id: &str, key: &MlKem1024KeyPair) -> VerificationMethod {
    VerificationMethod {
        id: id.to_string(),
        controller: id.split('#').next().unwrap().to_string(),
        type_: VerificationMethodType::MlKem1024KeyAgreementKey2025,
        verification_material: VerificationMaterial::Multibase {
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                key.public_key_bytes(),
            ),
        },
    }
}

fn create_ml_dsa_65_verification_method(id: &str, key: &MlDsa65KeyPair) -> VerificationMethod {
    VerificationMethod {
        id: id.to_string(),
        controller: id.split('#').next().unwrap().to_string(),
        type_: VerificationMethodType::MlDsa65VerificationKey2025,
        verification_material: VerificationMaterial::Multibase {
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                key.public_key().as_bytes(),
            ),
        },
    }
}

fn create_ml_dsa_87_verification_method(id: &str, key: &MlDsa87KeyPair) -> VerificationMethod {
    VerificationMethod {
        id: id.to_string(),
        controller: id.split('#').next().unwrap().to_string(),
        type_: VerificationMethodType::MlDsa87VerificationKey2025,
        verification_material: VerificationMaterial::Multibase {
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                key.public_key().as_bytes(),
            ),
        },
    }
}

fn create_ml_kem_768_secret(id: &str, key: &MlKem768KeyPair) -> Secret {
    let private_key_bytes = key.get_private_key_bytes().unwrap_or(&[0; 2400]);
    Secret {
        id: id.to_string(),
        type_: SecretType::MlKem768KeyAgreementKey2025,
        secret_material: SecretMaterial::Multibase {
            private_key_multibase: multibase::encode(multibase::Base::Base58Btc, private_key_bytes),
        },
    }
}

fn create_ml_kem_1024_secret(id: &str, key: &MlKem1024KeyPair) -> Secret {
    let private_key_bytes = key.get_private_key_bytes().unwrap_or(&[0; 3168]);
    Secret {
        id: id.to_string(),
        type_: SecretType::MlKem1024KeyAgreementKey2025,
        secret_material: SecretMaterial::Multibase {
            private_key_multibase: multibase::encode(multibase::Base::Base58Btc, private_key_bytes),
        },
    }
}

fn create_ml_dsa_65_secret(id: &str, key: &MlDsa65KeyPair) -> Secret {
    let combined_key_bytes = key
        .get_combined_key_bytes()
        .expect("ML-DSA-65 secret key should be available");
    Secret {
        id: id.to_string(),
        type_: SecretType::MlDsa65VerificationKey2025,
        secret_material: SecretMaterial::Multibase {
            private_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                &combined_key_bytes,
            ),
        },
    }
}

fn create_ml_dsa_87_secret(id: &str, key: &MlDsa87KeyPair) -> Secret {
    let combined_key_bytes = key
        .get_combined_key_bytes()
        .expect("ML-DSA-87 secret key should be available");
    Secret {
        id: id.to_string(),
        type_: SecretType::MlDsa87VerificationKey2025,
        secret_material: SecretMaterial::Multibase {
            private_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                &combined_key_bytes,
            ),
        },
    }
}

/// Test secrets resolver for PQC test vectors
pub struct PQCTestSecretsResolver {
    secrets: HashMap<String, Secret>,
}

impl PQCTestSecretsResolver {
    pub fn new(secrets: HashMap<String, Secret>) -> Self {
        Self { secrets }
    }
}

#[async_trait]
impl SecretsResolver for PQCTestSecretsResolver {
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>> {
        Ok(self.secrets.get(secret_id).cloned())
    }

    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>> {
        Ok(secret_ids
            .iter()
            .filter(|&&secret_id| self.secrets.contains_key(secret_id))
            .copied()
            .collect())
    }
}

/// Mock DID resolver for testing
pub struct PQCTestDIDResolver {
    did_docs: HashMap<String, DIDDoc>,
}

impl Default for PQCTestDIDResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl PQCTestDIDResolver {
    pub fn new() -> Self {
        Self {
            did_docs: HashMap::new(),
        }
    }

    pub fn add_did_doc(&mut self, did: String, did_doc: DIDDoc) {
        self.did_docs.insert(did, did_doc);
    }
}

#[async_trait]
impl crate::did::DIDResolver for PQCTestDIDResolver {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        Ok(self.did_docs.get(did).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pqc_ml_kem_768_test_vectors() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        // Verify Alice's keys
        assert!(!vectors.alice_secrets.is_empty());
        assert!(vectors.alice_secrets.len() >= 2); // KEM + DSA keys

        // Verify Bob's keys
        assert!(!vectors.bob_secrets.is_empty());
        assert!(vectors.bob_secrets.len() >= 2); // KEM + DSA keys

        // Verify DID documents have proper structure
        assert_eq!(vectors.alice_did_doc.id, vectors.alice_did);
        assert!(!vectors.alice_did_doc.key_agreement.is_empty());
        assert!(!vectors.alice_did_doc.authentication.is_empty());

        assert_eq!(vectors.bob_did_doc.id, vectors.bob_did);
        assert!(!vectors.bob_did_doc.key_agreement.is_empty());
        assert!(!vectors.bob_did_doc.authentication.is_empty());
    }

    #[tokio::test]
    async fn test_pqc_ml_kem_1024_test_vectors() {
        let vectors =
            PQCTestVector::ml_kem_1024_ml_dsa_87().expect("Failed to create test vectors");

        // Verify test vector completeness
        assert!(!vectors.alice_secrets.is_empty());
        assert!(!vectors.bob_secrets.is_empty());
        assert_ne!(vectors.alice_did, vectors.bob_did);

        // Verify verification methods contain PQC algorithms
        let alice_vm = &vectors.alice_did_doc.verification_method;
        let has_ml_kem_1024 = alice_vm
            .iter()
            .any(|vm| vm.type_ == VerificationMethodType::MlKem1024KeyAgreementKey2025);
        let has_ml_dsa_87 = alice_vm
            .iter()
            .any(|vm| vm.type_ == VerificationMethodType::MlDsa87VerificationKey2025);

        assert!(
            has_ml_kem_1024,
            "Alice should have ML-KEM-1024 verification method"
        );
        assert!(
            has_ml_dsa_87,
            "Alice should have ML-DSA-87 verification method"
        );
    }

    #[tokio::test]
    async fn test_pqc_message_round_trip() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        // Create resolvers
        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let _alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets);
        let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

        // Create test message using correct Message::build API
        let message = Message::build(
            "test-message-id".to_string(),
            "test-message-type".to_string(),
            serde_json::json!({"test": "data"}),
        )
        .to(vectors.bob_did.clone())
        .from(vectors.alice_did.clone())
        .finalize();

        // Test plaintext packing/unpacking
        let packed = message
            .pack_plaintext(&did_resolver)
            .await
            .expect("Failed to pack plaintext");
        let (unpacked, _) = Message::unpack(
            &packed,
            &did_resolver,
            &bob_secrets,
            &UnpackOptions::default(),
        )
        .await
        .expect("Failed to unpack message");

        assert_eq!(message.id, unpacked.id);
        assert_eq!(message.type_, unpacked.type_);
        assert_eq!(message.body, unpacked.body);
    }

    #[tokio::test]
    async fn test_pqc_signing_round_trip() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        // Create resolvers
        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets);
        let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

        // Create test message using correct Message::build API
        let message = Message::build(
            "test-signed-message".to_string(),
            "test-message-type".to_string(),
            serde_json::json!({"signed": "content"}),
        )
        .to(vectors.bob_did.clone())
        .from(vectors.alice_did.clone())
        .finalize();

        // Test signing round trip
        let (signed, _metadata) = message
            .pack_signed(&vectors.alice_did, &did_resolver, &alice_secrets)
            .await
            .expect("Failed to pack signed message");

        let (unpacked, unpack_metadata) = Message::unpack(
            &signed,
            &did_resolver,
            &bob_secrets,
            &UnpackOptions::default(),
        )
        .await
        .expect("Failed to unpack signed message");

        // Verify message integrity
        assert_eq!(message.id, unpacked.id);
        assert_eq!(message.body, unpacked.body);

        // Verify signature metadata
        assert!(unpack_metadata.authenticated);
        assert!(unpack_metadata.non_repudiation);
        assert!(unpack_metadata.sign_from.is_some());
    }

    #[tokio::test]
    async fn test_pqc_authcrypt_round_trip() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        // Create resolvers
        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets);
        let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

        // Create test message
        let message = Message::build(
            "test-authcrypt-message".to_string(),
            "test-message-type".to_string(),
            serde_json::json!({"encrypted": "content"}),
        )
        .to(vectors.bob_did.clone())
        .from(vectors.alice_did.clone())
        .finalize();

        // Test AuthCrypt (authenticated encryption) round trip
        let (encrypted, pack_metadata) = message
            .pack_encrypted(
                &vectors.bob_did,
                Some(&vectors.alice_did), // from - makes it AuthCrypt
                None,                     // no additional signing
                &did_resolver,
                &alice_secrets,
                &PackEncryptedOptions::default(),
            )
            .await
            .expect("Failed to pack encrypted message");

        // Verify pack metadata
        assert!(
            pack_metadata.from_kid.is_some(),
            "AuthCrypt should have from_kid"
        );
        assert!(
            !pack_metadata.to_kids.is_empty(),
            "Should have recipient keys"
        );

        let (unpacked, unpack_metadata) = Message::unpack(
            &encrypted,
            &did_resolver,
            &bob_secrets,
            &UnpackOptions::default(),
        )
        .await
        .expect("Failed to unpack encrypted message");

        // Verify message integrity
        assert_eq!(message.id, unpacked.id);
        assert_eq!(message.body, unpacked.body);

        // Verify AuthCrypt metadata
        assert!(
            unpack_metadata.authenticated,
            "AuthCrypt should be authenticated"
        );
        assert!(unpack_metadata.encrypted, "Message should be encrypted");
        assert!(
            !unpack_metadata.anonymous_sender,
            "AuthCrypt sender should not be anonymous"
        );
        assert!(
            !unpack_metadata.non_repudiation,
            "No additional signing, so not non-repudiable"
        );
    }

    #[tokio::test]
    async fn test_pqc_anoncrypt_round_trip() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        // Create resolvers
        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets);
        let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

        // Create test message (no from field for anonymous)
        let message = Message::build(
            "test-anoncrypt-message".to_string(),
            "test-message-type".to_string(),
            serde_json::json!({"anonymous": "content"}),
        )
        .to(vectors.bob_did.clone())
        .finalize(); // No from() - makes it anonymous

        // Test AnonCrypt (anonymous encryption) round trip
        let (encrypted, pack_metadata) = message
            .pack_encrypted(
                &vectors.bob_did,
                None, // no from - makes it AnonCrypt
                None, // no signing
                &did_resolver,
                &alice_secrets,
                &PackEncryptedOptions::default(),
            )
            .await
            .expect("Failed to pack anonymous encrypted message");

        // Verify pack metadata
        assert!(
            pack_metadata.from_kid.is_none(),
            "AnonCrypt should not have from_kid"
        );
        assert!(
            !pack_metadata.to_kids.is_empty(),
            "Should have recipient keys"
        );

        let (unpacked, unpack_metadata) = Message::unpack(
            &encrypted,
            &did_resolver,
            &bob_secrets,
            &UnpackOptions::default(),
        )
        .await
        .expect("Failed to unpack anonymous encrypted message");

        // Verify message integrity
        assert_eq!(message.id, unpacked.id);
        assert_eq!(message.body, unpacked.body);

        // Verify AnonCrypt metadata
        assert!(
            !unpack_metadata.authenticated,
            "AnonCrypt should not be authenticated"
        );
        assert!(unpack_metadata.encrypted, "Message should be encrypted");
        assert!(
            unpack_metadata.anonymous_sender,
            "AnonCrypt sender should be anonymous"
        );
        assert!(
            !unpack_metadata.non_repudiation,
            "No signing, so not non-repudiable"
        );
    }

    #[test]
    fn test_key_consistency_between_secret_and_did_doc() {
        // This test verifies that the DSA public key stored in the DID document
        // exactly matches the DSA public key from the secret used for signing
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        // Get Alice's authentication secret (used for signing)
        let alice_auth_kid = format!("{}#authentication-1", vectors.alice_did);
        let alice_auth_secret = &vectors.alice_secrets[&alice_auth_kid];
        let signing_keypair = alice_auth_secret
            .as_ml_dsa_65()
            .expect("Failed to get DSA keypair from secret");

        // Get Alice's authentication verification method (used for verification)
        let alice_auth_vm = vectors
            .alice_did_doc
            .verification_method
            .iter()
            .find(|vm| vm.id == alice_auth_kid)
            .expect("Failed to find auth verification method");
        let verification_keypair = alice_auth_vm
            .as_ml_dsa_65()
            .expect("Failed to get DSA keypair from DID doc");

        // Compare the public key bytes
        let signing_public_bytes = signing_keypair.public_key().as_bytes();
        let verification_public_bytes = verification_keypair.public_key().as_bytes();

        println!(
            "Signing public key bytes (first 32): {:?}",
            &signing_public_bytes[..32]
        );
        println!(
            "Verification public key bytes (first 32): {:?}",
            &verification_public_bytes[..32]
        );

        assert_eq!(
            signing_public_bytes, verification_public_bytes,
            "Public key from secret doesn't match public key from DID document"
        );
    }

    #[tokio::test]
    async fn test_pqc_signed_and_encrypted_round_trip() {
        let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

        // Create resolvers
        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets);
        let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

        // Create test message
        let message = Message::build(
            "test-signed-encrypted-message".to_string(),
            "test-message-type".to_string(),
            serde_json::json!({"signed_encrypted": "content"}),
        )
        .to(vectors.bob_did.clone())
        .from(vectors.alice_did.clone())
        .finalize();

        // Test signing + encryption (non-repudiable AuthCrypt)
        let (encrypted, pack_metadata) = message
            .pack_encrypted(
                &vectors.bob_did,
                Some(&vectors.alice_did), // from - makes it AuthCrypt
                Some(&vectors.alice_did), // sign_by - adds non-repudiation
                &did_resolver,
                &alice_secrets,
                &PackEncryptedOptions::default(),
            )
            .await
            .expect("Failed to pack signed and encrypted message");

        // Verify pack metadata
        assert!(pack_metadata.from_kid.is_some(), "Should have from_kid");
        assert!(
            pack_metadata.sign_by_kid.is_some(),
            "Should have sign_by_kid"
        );
        assert!(
            !pack_metadata.to_kids.is_empty(),
            "Should have recipient keys"
        );

        let (unpacked, unpack_metadata) = Message::unpack(
            &encrypted,
            &did_resolver,
            &bob_secrets,
            &UnpackOptions::default(),
        )
        .await
        .expect("Failed to unpack signed and encrypted message");

        // Verify message integrity
        assert_eq!(message.id, unpacked.id);
        assert_eq!(message.body, unpacked.body);

        // Verify signed + encrypted metadata
        assert!(unpack_metadata.authenticated, "Should be authenticated");
        assert!(unpack_metadata.encrypted, "Should be encrypted");
        assert!(
            unpack_metadata.non_repudiation,
            "Should be non-repudiable due to signing"
        );
        assert!(
            !unpack_metadata.anonymous_sender,
            "Sender should not be anonymous"
        );
        assert!(
            unpack_metadata.sign_from.is_some(),
            "Should have signer info"
        );
    }
}
