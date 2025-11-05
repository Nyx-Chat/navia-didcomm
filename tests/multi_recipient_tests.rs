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
        .unwrap()
        .into_iter()
        .next()
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
        .unwrap()
        .into_iter()
        .next()
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
        .unwrap()
        .into_iter()
        .next()
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
    let (packed, _metadata) = result
        .expect("Should handle duplicate recipients")
        .into_iter()
        .next()
        .unwrap();

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

#[tokio::test]
async fn test_multi_recipient_with_same_routing_keys() {
    // Test multiple recipients that share the same routing path (same mediators)
    // This should result in a single forwarded message optimized for multiple recipients
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let message = Message::build(
        "test-same-routing".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "message with same routing"}),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack with forwarding enabled for Bob (who uses mediator1)
    let results = message
        .pack_encrypted(
            &[BOB_DID.to_string()],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: true,
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .unwrap();

    // When recipients share routing path, we should get optimized routing
    // (number of results depends on routing tree optimization)
    assert!(!results.is_empty());

    // Verify we got the forwarded message with proper metadata
    for (packed, metadata) in &results {
        // Should have messaging_service set when forwarding is used
        if metadata.messaging_service.is_some() {
            assert!(metadata.from_kid.is_some());
            assert!(!metadata.to_kids.is_empty());
        }

        // Verify message structure (should be a forward message)
        let jwe: serde_json::Value = serde_json::from_str(packed).unwrap();
        assert!(jwe.get("protected").is_some() || jwe.get("recipients").is_some());
    }
}

#[tokio::test]
async fn test_multi_recipient_with_different_routing_keys() {
    // Test multiple recipients with different routing paths
    // This should result in multiple forwarded messages (one per routing path)
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let message = Message::build(
        "test-different-routing".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "message with different routing"}),
    )
    .to(BOB_DID.to_owned())
    .to(CHARLIE_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack with forwarding enabled for both Bob and Charlie (different mediators)
    let results = message
        .pack_encrypted(
            &[BOB_DID.to_string(), CHARLIE_DID.to_string()],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: true,
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .unwrap();

    // With different routing paths, we may get multiple messages
    // (one optimized message per unique routing path)
    assert!(!results.is_empty());

    println!("Number of routing-optimized messages: {}", results.len());

    // Verify metadata for all results
    for (packed, metadata) in &results {
        // Each result should have proper metadata
        assert!(metadata.from_kid.is_some());
        assert!(!metadata.to_kids.is_empty());

        // Verify message structure
        let jwe: serde_json::Value = serde_json::from_str(packed).unwrap();
        assert!(jwe.get("protected").is_some() || jwe.get("recipients").is_some());
    }
}

#[tokio::test]
async fn test_multi_recipient_forward_with_anoncrypt() {
    // Test anonymous encryption with forwarding for multiple recipients
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let message = Message::build(
        "test-anon-forward".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "anonymous message with forwarding"}),
    )
    .to(BOB_DID.to_owned())
    .to(CHARLIE_DID.to_owned())
    .finalize();

    // Pack anonymously with forwarding enabled
    let results = message
        .pack_encrypted(
            &[BOB_DID.to_string(), CHARLIE_DID.to_string()],
            None, // Anonymous - no from
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: true,
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .unwrap();

    assert!(!results.is_empty());

    // Verify all results have proper anonymous metadata
    for (_packed, metadata) in &results {
        assert!(metadata.from_kid.is_none()); // Anonymous sender
        assert!(!metadata.to_kids.is_empty());
    }
}

#[tokio::test]
async fn test_multi_recipient_mixed_key_types() {
    // Test with multiple recipients that might have different key types
    // (X25519, P256, etc.)
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());
    let bob_recipient_secrets = ExampleSecretsResolver::new(BOB_SECRETS.clone());
    let charlie_recipient_secrets = ExampleSecretsResolver::new(CHARLIE_SECRETS.clone());

    let message = Message::build(
        "test-mixed-keys".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "message for mixed key types"}),
    )
    .to(BOB_DID.to_owned())
    .to(CHARLIE_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack for multiple recipients with potentially different key types
    let (packed, metadata) = message
        .pack_encrypted(
            &[BOB_DID.to_string(), CHARLIE_DID.to_string()],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: false,
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    // Verify metadata includes keys for all recipients
    assert!(metadata.to_kids.len() >= 2);
    assert!(metadata.from_kid.is_some());

    // Both recipients should be able to decrypt
    let (msg1, _) = Message::unpack(
        &packed,
        &did_resolver,
        &bob_recipient_secrets,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    let (msg2, _) = Message::unpack(
        &packed,
        &did_resolver,
        &charlie_recipient_secrets,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    // Both should get the same message
    assert_eq!(msg1.id, msg2.id);
    assert_eq!(msg1.body, msg2.body);
}
