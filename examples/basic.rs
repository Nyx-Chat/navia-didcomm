// PQC-only basic DIDComm messaging example
// Uses ML-KEM and ML-DSA post-quantum cryptographic algorithms

use navia_didcomm::{
    algorithms::AuthCryptAlg,
    test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=================== PQC NON REPUDIABLE ENCRYPTION ===================");
    pqc_non_repudiable_encryption().await;
    println!("=================== PQC REPUDIABLE AUTHENTICATED ENCRYPTION ===================");
    pqc_repudiable_authenticated_encryption().await;
    println!("=================== PQC ANONYMOUS ENCRYPTION ===================");
    pqc_anonymous_encryption().await;
}

async fn pqc_non_repudiable_encryption() {
    // Create PQC test vectors with ML-KEM-768 and ML-DSA-65
    let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create PQC test vectors");

    // Set up resolvers
    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
    did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets);
    let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

    // Create message with from_prior header
    let message = Message::build(
        "example-1".to_string(),
        "https://example.com/protocols/hello/1.0/hello".to_string(),
        json!({ "messagespecificattribute": "and its value" }),
    )
    .to(vectors.bob_did.clone())
    .from(vectors.alice_did.clone())
    .finalize();

    println!(
        "Sending message: {}",
        serde_json::to_string_pretty(&message).unwrap()
    );

    // Pack with signing + encryption (non-repudiable)
    let (packed_msg, pack_metadata) = message
        .pack_encrypted(
            &vectors.bob_did,
            Some(&vectors.alice_did),
            Some(&vectors.alice_did), // sign with alice's key
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack encrypted message");

    println!("Packed Message: {packed_msg}");
    println!("Pack Metadata: {pack_metadata:?}");

    // Unpack message
    let (unpacked_msg, unpack_metadata) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack message");

    println!(
        "Unpacked Message: {}",
        serde_json::to_string_pretty(&unpacked_msg).unwrap()
    );
    println!("Unpack Metadata: {unpack_metadata:?}");

    // Verify non-repudiation properties
    assert!(
        unpack_metadata.non_repudiation,
        "Message should be non-repudiable"
    );
    assert!(
        unpack_metadata.authenticated,
        "Message should be authenticated"
    );
    assert!(unpack_metadata.encrypted, "Message should be encrypted");
    assert!(
        !unpack_metadata.anonymous_sender,
        "Sender should not be anonymous"
    );

    println!("✅ PQC non-repudiable encryption successful!");
}

async fn pqc_repudiable_authenticated_encryption() {
    // Create PQC test vectors with ML-KEM-1024 and ML-DSA-87 for variety
    let vectors =
        PQCTestVector::ml_kem_1024_ml_dsa_87().expect("Failed to create PQC test vectors");

    // Set up resolvers
    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
    did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets);
    let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

    // Create message
    let message = Message::build(
        "example-2".to_string(),
        "https://example.com/protocols/hello/1.0/hello".to_string(),
        json!({ "greetings": "Hello, Bob! This is Alice using PQC." }),
    )
    .to(vectors.bob_did.clone())
    .from(vectors.alice_did.clone())
    .finalize();

    println!(
        "Sending message: {}",
        serde_json::to_string_pretty(&message).unwrap()
    );

    // Pack with encryption only (no signing - repudiable)
    // Using ML-KEM-1024 to match the test vectors
    let pack_options = PackEncryptedOptions {
        enc_alg_auth: AuthCryptAlg::MlKem1024A256cbcHs512,
        ..Default::default()
    };

    let (packed_msg, pack_metadata) = message
        .pack_encrypted(
            &vectors.bob_did,
            Some(&vectors.alice_did),
            None, // no signing - message is repudiable
            &did_resolver,
            &alice_secrets,
            &pack_options,
        )
        .await
        .expect("Failed to pack encrypted message");

    println!("Packed Message: {packed_msg}");
    println!("Pack Metadata: {pack_metadata:?}");

    // Unpack message
    let (unpacked_msg, unpack_metadata) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack message");

    println!(
        "Unpacked Message: {}",
        serde_json::to_string_pretty(&unpacked_msg).unwrap()
    );
    println!("Unpack Metadata: {unpack_metadata:?}");

    // Verify authenticated encryption properties
    assert!(
        !unpack_metadata.non_repudiation,
        "Message should be repudiable"
    );
    assert!(
        unpack_metadata.authenticated,
        "Message should be authenticated"
    );
    assert!(unpack_metadata.encrypted, "Message should be encrypted");
    assert!(
        !unpack_metadata.anonymous_sender,
        "Sender should not be anonymous"
    );

    println!("✅ PQC repudiable authenticated encryption successful!");
}

async fn pqc_anonymous_encryption() {
    // Create PQC test vectors
    let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create PQC test vectors");

    // Set up resolvers
    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
    did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets);
    let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

    // Create message
    let message = Message::build(
        "example-3".to_string(),
        "https://example.com/protocols/hello/1.0/hello".to_string(),
        json!({ "anonymous": "This message sender is anonymous" }),
    )
    .to(vectors.bob_did.clone())
    .finalize(); // No from field - anonymous

    println!(
        "Sending message: {}",
        serde_json::to_string_pretty(&message).unwrap()
    );

    // Pack with anonymous encryption only
    let (packed_msg, pack_metadata) = message
        .pack_encrypted(
            &vectors.bob_did,
            None, // no from - anonymous
            None, // no signing
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack encrypted message");

    println!("Packed Message: {packed_msg}");
    println!("Pack Metadata: {pack_metadata:?}");

    // Unpack message
    let (unpacked_msg, unpack_metadata) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack message");

    println!(
        "Unpacked Message: {}",
        serde_json::to_string_pretty(&unpacked_msg).unwrap()
    );
    println!("Unpack Metadata: {unpack_metadata:?}");

    // Verify anonymous encryption properties
    assert!(
        !unpack_metadata.non_repudiation,
        "Message should be repudiable"
    );
    assert!(
        !unpack_metadata.authenticated,
        "Message should not be authenticated"
    );
    assert!(unpack_metadata.encrypted, "Message should be encrypted");
    assert!(
        unpack_metadata.anonymous_sender,
        "Sender should be anonymous"
    );

    println!("✅ PQC anonymous encryption successful!");
}
