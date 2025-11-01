//! Integration tests for multi-recipient DIDComm messaging

#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

pub(crate) use navia_didcomm as didcomm;

use navia_didcomm::{
    did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver, Message,
    PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use test_vectors::{
    ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID,
    CHARLIE_DID_DOC, CHARLIE_SECRETS, MEDIATOR1_DID_DOC, MEDIATOR2_DID_DOC, MEDIATOR3_DID_DOC,
};

#[tokio::test]
async fn test_multi_recipient_authcrypt() {
    // Setup resolvers (including mediators for routing)
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());
    let bob_recipient_secrets = ExampleSecretsResolver::new(BOB_SECRETS.clone());
    let charlie_recipient_secrets = ExampleSecretsResolver::new(CHARLIE_SECRETS.clone());

    // Alice sends to both Bob and Charlie
    let message = Message::build(
        "test-multi-1".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "test message"}),
    )
    .to(BOB_DID.to_owned())
    .to(CHARLIE_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack for multiple recipients
    let (packed, metadata) = message
        .pack_encrypted(
            &[BOB_DID.to_string(), CHARLIE_DID.to_string()],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: false, // Disable routing for test simplicity
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .unwrap();

    // Verify metadata shows both recipients
    assert!(metadata.to_kids.len() >= 2);
    assert!(metadata.from_kid.is_some());

    // Parse JWE to verify structure
    let jwe: serde_json::Value = serde_json::from_str(&packed).unwrap();
    let recipients = jwe.get("recipients").unwrap().as_array().unwrap();
    assert!(recipients.len() >= 2);

    // Both recipients should be able to decrypt
    let (msg1, meta1) = Message::unpack(
        &packed,
        &did_resolver,
        &bob_recipient_secrets,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    let (msg2, meta2) = Message::unpack(
        &packed,
        &did_resolver,
        &charlie_recipient_secrets,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    // Verify both got the same message
    assert_eq!(msg1.id, msg2.id);
    assert_eq!(msg1.body, msg2.body);
    assert!(meta1.authenticated);
    assert!(meta2.authenticated);
}

#[tokio::test]
async fn test_multi_recipient_anoncrypt() {
    // Setup resolvers (including mediators for routing)
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());
    let bob_recipient_secrets = ExampleSecretsResolver::new(BOB_SECRETS.clone());
    let charlie_recipient_secrets = ExampleSecretsResolver::new(CHARLIE_SECRETS.clone());

    // Create anonymous message for multiple recipients
    let message = Message::build(
        "test-multi-anon-1".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "anonymous message"}),
    )
    .to(BOB_DID.to_owned())
    .to(CHARLIE_DID.to_owned())
    .finalize();

    // Pack anonymously for multiple recipients
    let (packed, metadata) = message
        .pack_encrypted(
            &[BOB_DID.to_string(), CHARLIE_DID.to_string()],
            None, // No from - anonymous
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: false, // Disable routing for test simplicity
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .unwrap();

    // Verify metadata
    assert!(metadata.to_kids.len() >= 2);
    assert!(metadata.from_kid.is_none());

    // Both recipients should be able to decrypt
    let (msg1, meta1) = Message::unpack(
        &packed,
        &did_resolver,
        &bob_recipient_secrets,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    let (msg2, meta2) = Message::unpack(
        &packed,
        &did_resolver,
        &charlie_recipient_secrets,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    // Verify both got the same message
    assert_eq!(msg1.id, msg2.id);
    assert_eq!(msg1.body, msg2.body);
    assert!(!meta1.authenticated);
    assert!(!meta2.authenticated);
    assert!(meta1.anonymous_sender);
    assert!(meta2.anonymous_sender);
}

#[tokio::test]
async fn test_empty_recipients_error() {
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone()]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let message = Message::build(
        "test-empty".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "test"}),
    )
    .from(ALICE_DID.to_owned())
    .finalize();

    // Empty recipients array should fail
    let result = message
        .pack_encrypted(
            &[],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: false, // Disable routing for test simplicity
                ..PackEncryptedOptions::default()
            },
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_single_recipient_still_works() {
    // Verify that single recipient (the common case) still works
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());
    let recipient_secrets = ExampleSecretsResolver::new(BOB_SECRETS.clone());

    let message = Message::build(
        "test-single".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "single recipient test"}),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Single recipient in array
    let (packed, metadata) = message
        .pack_encrypted(
            &[BOB_DID.to_string()],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: false, // Disable routing for test simplicity
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .unwrap();

    assert!(metadata.to_kids.len() >= 1);

    // Should decrypt successfully
    let (msg, meta) = Message::unpack(
        &packed,
        &did_resolver,
        &recipient_secrets,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(msg.id, "test-single");
    assert!(meta.authenticated);
}

#[tokio::test]
async fn test_duplicate_recipients() {
    // Test what happens when same recipient appears multiple times
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());
    let recipient_secrets = ExampleSecretsResolver::new(BOB_SECRETS.clone());

    let message = Message::build(
        "test-duplicate".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "duplicate recipient test"}),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Same recipient appears twice in the array
    let result = message
        .pack_encrypted(
            &[BOB_DID.to_string(), BOB_DID.to_string()],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: false, // Disable routing for test simplicity
                ..PackEncryptedOptions::default()
            },
        )
        .await;

    // Should succeed (may deduplicate or not, both are valid)
    let (packed, _metadata) = result.expect("Should handle duplicate recipients");

    // Should still decrypt correctly
    let (msg, _meta) = Message::unpack(
        &packed,
        &did_resolver,
        &recipient_secrets,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(msg.id, "test-duplicate");
}
