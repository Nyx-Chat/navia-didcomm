// PQC-only DIDComm messaging example with attachments
// Uses ML-KEM and ML-DSA post-quantum cryptographic algorithms

use base64::Engine;
use navia_didcomm::{
    test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
    Attachment, Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=================== PQC ATTACHMENTS EXAMPLE ===================");
    pqc_attachments_example().await;
}

async fn pqc_attachments_example() {
    // Create PQC test vectors
    let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create PQC test vectors");

    // Set up resolvers
    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
    did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets);
    let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

    // Create message with various types of attachments
    let message = Message::build(
        "attachment-example".to_string(),
        "https://example.com/protocols/data-transfer/1.0/transfer".to_string(),
        json!({
            "description": "Message with PQC-secured attachments",
            "timestamp": "2024-01-01T12:00:00Z"
        }),
    )
    .to(vectors.bob_did.clone())
    .from(vectors.alice_did.clone())
    .attachments(vec![
        // Base64 encoded attachment
        Attachment::base64("SGVsbG8gUW9ybGQ=".to_string()) // "Hello World" in base64
            .media_type("text/plain".to_string())
            .filename("hello.txt".to_string())
            .finalize(),
        // JSON attachment
        Attachment::json(json!({
            "algorithm": "ML-KEM-768",
            "security_level": "NIST Level 1",
            "quantum_resistant": true
        }))
        .media_type("application/json".to_string())
        .filename("crypto_info.json".to_string())
        .finalize(),
        // Links attachment (referencing external content)
        Attachment::links(
            vec!["https://example.com/large-file.zip".to_string()],
            "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c".to_string(),
        )
        .media_type("application/zip".to_string())
        .filename("large-file.zip".to_string())
        .finalize(),
    ])
    .finalize();

    println!(
        "Message with attachments: {}",
        serde_json::to_string_pretty(&message).unwrap()
    );
    println!(
        "Number of attachments: {}",
        message.attachments.as_ref().map_or(0, |a| a.len())
    );

    // Pack the message with encryption
    let (packed_msg, pack_metadata) = message
        .pack_encrypted(
            &vectors.bob_did,
            Some(&vectors.alice_did),
            Some(&vectors.alice_did), // sign for non-repudiation
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack encrypted message with attachments");

    println!("Packed message with attachments: {packed_msg}");
    println!("Pack metadata: {pack_metadata:?}");

    // Unpack the message
    let (unpacked_msg, unpack_metadata) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack message with attachments");

    println!(
        "Unpacked message: {}",
        serde_json::to_string_pretty(&unpacked_msg).unwrap()
    );
    println!("Unpack metadata: {unpack_metadata:?}");

    // Verify message properties
    assert!(
        unpack_metadata.non_repudiation,
        "Message should be non-repudiable"
    );
    assert!(
        unpack_metadata.authenticated,
        "Message should be authenticated"
    );
    assert!(unpack_metadata.encrypted, "Message should be encrypted");

    // Verify attachments were preserved
    let attachments = unpacked_msg
        .attachments
        .as_ref()
        .expect("Attachments should be present");
    assert_eq!(attachments.len(), 3, "Should have 3 attachments");

    // Check each attachment type
    println!("\n--- Attachment Details ---");
    for (i, attachment) in attachments.iter().enumerate() {
        println!("Attachment {}: {:?}", i + 1, attachment);

        match &attachment.data {
            navia_didcomm::AttachmentData::Base64 { value } => {
                println!("  Base64 data: {} chars", value.base64.len());
                println!("  Media type: {:?}", attachment.media_type);
                println!("  Filename: {:?}", attachment.filename);

                // Decode the base64 content for verification
                if let Ok(decoded) = base64::prelude::BASE64_STANDARD.decode(&value.base64) {
                    if let Ok(text) = String::from_utf8(decoded) {
                        println!("  Content: {text}");
                    }
                }
            }
            navia_didcomm::AttachmentData::Json { value } => {
                println!(
                    "  JSON data: {}",
                    serde_json::to_string(&value.json).unwrap()
                );
                println!("  Media type: {:?}", attachment.media_type);
                println!("  Filename: {:?}", attachment.filename);
            }
            navia_didcomm::AttachmentData::Links { value } => {
                println!("  Links: {:?}", value.links);
                println!("  Hash: {}", value.hash);
                println!("  Media type: {:?}", attachment.media_type);
                println!("  Filename: {:?}", attachment.filename);
            }
        }
    }

    println!("✅ PQC attachments example successful!");
}
