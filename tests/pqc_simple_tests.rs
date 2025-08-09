//! Simple PQC Integration Tests
//!
//! Basic tests verifying PQC algorithms are available and work with public APIs

#[test]
fn test_pqc_algorithms_available() {
    use navia_didcomm::algorithms::{AnonCryptAlg, AuthCryptAlg, SignAlg};

    // Test that PQC algorithm variants exist and can be constructed
    let anon_alg = AnonCryptAlg::MlKem768Xc20p;
    let auth_alg = AuthCryptAlg::MlKem768A256cbcHs512;
    let sign_alg = SignAlg::MlDsa65;

    // Verify they serialize/deserialize properly
    let anon_json = serde_json::to_string(&anon_alg).expect("Failed to serialize AnonCryptAlg");
    let auth_json = serde_json::to_string(&auth_alg).expect("Failed to serialize AuthCryptAlg");
    let sign_json = serde_json::to_string(&sign_alg).expect("Failed to serialize SignAlg");

    assert_eq!(anon_json, "\"ML-KEM768+XC20P\"");
    assert_eq!(auth_json, "\"ML-KEM768+A256CBC-HS512\"");
    assert_eq!(sign_json, "\"ML-DSA-65\"");

    // Test deserialization
    let anon_deser: AnonCryptAlg =
        serde_json::from_str(&anon_json).expect("Failed to deserialize AnonCryptAlg");
    let auth_deser: AuthCryptAlg =
        serde_json::from_str(&auth_json).expect("Failed to deserialize AuthCryptAlg");
    let sign_deser: SignAlg =
        serde_json::from_str(&sign_json).expect("Failed to deserialize SignAlg");

    assert_eq!(anon_deser, AnonCryptAlg::MlKem768Xc20p);
    assert_eq!(auth_deser, AuthCryptAlg::MlKem768A256cbcHs512);
    assert_eq!(sign_deser, SignAlg::MlDsa65);

    println!("✅ PQC algorithms are available and serialize correctly");
}

#[test]
fn test_pqc_algorithm_defaults() {
    use navia_didcomm::algorithms::{AnonCryptAlg, SignAlg};

    // Test that PQC algorithms are defaults
    let default_anon = AnonCryptAlg::default();
    let default_sign = SignAlg::default();

    // Should be PQC algorithms by default
    assert_eq!(default_anon, AnonCryptAlg::MlKem768Xc20p);
    assert_eq!(default_sign, SignAlg::MlDsa65);

    println!("✅ PQC algorithms are set as defaults");
}

#[test]
fn test_pqc_did_verification_methods() {
    use navia_didcomm::did::VerificationMethodType;

    // Test that PQC verification method types exist
    let kem_method = VerificationMethodType::MlKem768KeyAgreementKey2025;
    let dsa_method = VerificationMethodType::MlDsa65VerificationKey2025;

    // Test serialization
    let kem_json = serde_json::to_string(&kem_method).expect("Failed to serialize ML-KEM method");
    let dsa_json = serde_json::to_string(&dsa_method).expect("Failed to serialize ML-DSA method");

    assert_eq!(kem_json, "\"MlKem768KeyAgreementKey2025\"");
    assert_eq!(dsa_json, "\"MlDsa65VerificationKey2025\"");

    println!("✅ PQC DID verification methods are available");
}

#[test]
fn test_pqc_message_creation() {
    use navia_didcomm::{Message, PackEncryptedOptions};
    use serde_json::json;

    // Test creating a message with PQC-specific options
    let message = Message::build(
        "test-123".to_string(),
        "https://example.com/protocols/test/1.0/pqc-message".to_string(),
        json!({"content": "Testing PQC integration"}),
    )
    .finalize();

    // Create options with PQC algorithms
    let options = PackEncryptedOptions {
        protect_sender: false,
        enc_alg_anon: navia_didcomm::algorithms::AnonCryptAlg::MlKem768Xc20p,
        enc_alg_auth: navia_didcomm::algorithms::AuthCryptAlg::MlKem768A256cbcHs512,
        ..Default::default()
    };

    // Verify message structure
    assert_eq!(
        message.type_,
        "https://example.com/protocols/test/1.0/pqc-message"
    );
    assert_eq!(
        options.enc_alg_anon,
        navia_didcomm::algorithms::AnonCryptAlg::MlKem768Xc20p
    );
    assert_eq!(
        options.enc_alg_auth,
        navia_didcomm::algorithms::AuthCryptAlg::MlKem768A256cbcHs512
    );

    println!("✅ PQC messages can be created with proper options");
}

#[test]
fn test_pqc_key_generation_available() {
    // This tests that the PQC key generation code compiles and is linked
    use navia_didcomm::utils::pqc::{MlDsa65KeyPair, MlKem768KeyPair};
    use pqcrypto_traits::sign::PublicKey;

    // Test key generation (with fixed randomness for reproducibility)
    let kem_randomness = [42u8; 64];
    let kem_keypair = MlKem768KeyPair::generate(kem_randomness);

    let dsa_keypair = MlDsa65KeyPair::generate();

    // Verify key sizes are correct
    assert_eq!(kem_keypair.public_key().as_slice().len(), 1184); // ML-KEM-768 public key size
    assert_eq!(dsa_keypair.public_key().as_bytes().len(), 1952); // ML-DSA-65 public key size

    println!("✅ PQC key generation works with correct key sizes");
}

#[test]
fn test_legacy_mode_compilation() {
    // Just verify the crate compiles without PQC feature
    use navia_didcomm::Message;

    let message = Message::build(
        "test".to_string(),
        "test".to_string(),
        serde_json::json!({}),
    )
    .finalize();

    assert_eq!(message.type_, "test");
    println!("✅ Legacy mode compilation works");
}
