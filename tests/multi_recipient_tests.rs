//! Integration tests for multi-recipient DIDComm messaging

#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

pub(crate) use navia_didcomm as didcomm;

use base64::Engine;
use navia_didcomm::{
    did::{resolvers::ExampleDIDResolver, DIDDoc},
    secrets::{resolvers::ExampleSecretsResolver, SecretsResolver},
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use test_vectors::{
    ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID,
    CHARLIE_DID_DOC, CHARLIE_SECRETS, DAVID_DID, DAVID_DID_DOC, DAVID_SECRETS, EVE_DID,
    EVE_DID_DOC, EVE_SECRETS, FRANK_DID, FRANK_DID_DOC, FRANK_SECRETS, MEDIATOR1_DID_DOC,
    MEDIATOR1_SECRETS, MEDIATOR2_DID_DOC, MEDIATOR2_SECRETS, MEDIATOR3_DID_DOC, MEDIATOR3_SECRETS,
    MEDIATOR4_DID_DOC, MEDIATOR4_SECRETS,
};

// Helper function to modify DID doc routing keys
fn with_routing_keys(did_doc: &DIDDoc, routing_keys: Vec<String>) -> DIDDoc {
    let mut cloned = did_doc.clone();
    for service in cloned.service.iter_mut() {
        if let navia_didcomm::did::ServiceKind::DIDCommMessaging { ref mut value } =
            service.service_endpoint
        {
            value.routing_keys = routing_keys.clone();
        }
    }
    cloned
}

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
            &[BOB_DID, CHARLIE_DID],
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
            &[BOB_DID, CHARLIE_DID],
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
            &[BOB_DID],
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

    assert!(!metadata.to_kids.is_empty());

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
            &[BOB_DID, BOB_DID],
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
            &[BOB_DID],
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
            &[BOB_DID, CHARLIE_DID],
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
            &[BOB_DID, CHARLIE_DID],
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
            &[BOB_DID, CHARLIE_DID],
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

#[tokio::test]
async fn test_multi_recipient_shared_first_hop_different_second_hop_with_routing_multi() {
    // Test recipients with complex 3-hop routing paths
    // David: mediator1 -> mediator2 -> mediator3
    // Eve:   mediator1 -> mediator2 -> mediator4
    // Frank: mediator1 -> mediator3 -> mediator4
    // This tests routing-multi optimization with multi-level routing
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        DAVID_DID_DOC.clone(),
        EVE_DID_DOC.clone(),
        FRANK_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
        MEDIATOR4_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let message = Message::build(
        "test-routing-multi".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "message with routing-multi optimization"}),
    )
    .to(DAVID_DID.to_owned())
    .to(EVE_DID.to_owned())
    .to(FRANK_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack with forwarding enabled and routing-multi=true (default)
    let results = message
        .pack_encrypted(
            &[DAVID_DID, EVE_DID, FRANK_DID],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: true,
                use_routing_multi: true, // Enable routing-multi optimization
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .unwrap();

    // With routing-multi optimization, should get ONE message to mediator1
    // The routing-multi message contains multiple attachments (one for each next hop)
    println!(
        "Number of messages with routing-multi (should be 1): {}",
        results.len()
    );

    assert_eq!(
        results.len(),
        1,
        "Should generate only 1 routing-multi message with multiple attachments"
    );

    // Verify metadata
    let (packed, metadata) = &results[0];
    assert!(metadata.from_kid.is_some());
    assert!(!metadata.to_kids.is_empty());

    // Verify message structure
    let jwe: serde_json::Value = serde_json::from_str(packed).unwrap();
    assert!(jwe.get("protected").is_some() || jwe.get("recipients").is_some());

    println!("✅ Routing-mod test passed: 1 message with multiple attachments");

    // --- Unpack at mediator1 to verify routing-multi structure ---
    let mediator1_secrets = ExampleSecretsResolver::new((*MEDIATOR1_SECRETS).clone());

    let (unpacked_msg, _unpack_metadata) = Message::unpack(
        packed,
        &did_resolver,
        &mediator1_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Mediator1 should be able to unpack the message");

    println!("Mediator1 unpacked message type: {}", unpacked_msg.type_);

    // Verify it's a routing-multi forward message
    assert_eq!(
        unpacked_msg.type_, "https://didcomm.org/routing-multi/1.0/forward",
        "Message should be routing-multi/1.0 forward type"
    );

    // Parse the routing-multi forward message
    let parsed_forward = navia_didcomm::protocols::routing::try_parse_forward_multi(&unpacked_msg)
        .expect("Should parse as routing-multi forward message");

    println!(
        "Number of NextDestination entries: {}",
        parsed_forward.next.len()
    );

    // Should have 2 NextDestination entries:
    // - One for mediator2 (David and Eve share this as second hop)
    // - One for mediator3 (Frank's second hop)
    // Routing paths: David [med1, med2, med3], Eve [med1, med2, med4], Frank [med1, med3, med4]
    // After grouping by common prefix [med1], individual paths are:
    //   David: [med2, med3], Eve: [med2, med4], Frank: [med3, med4]
    // Next hops (first element of individual paths):
    //   David -> med2, Eve -> med2, Frank -> med3
    assert_eq!(
        parsed_forward.next.len(),
        2,
        "Should have 2 NextDestination entries (mediator2 and mediator3)"
    );

    // Verify each NextDestination has correct structure
    let mut found_mediator2 = false;
    let mut found_mediator3 = false;

    for next_dest in &parsed_forward.next {
        println!(
            "NextDestination: to={:?}, attachment_id={}",
            next_dest.to, next_dest.attachment_id
        );

        // Each NextDestination should have exactly one target
        assert_eq!(
            next_dest.to.len(),
            1,
            "Each NextDestination should point to one mediator"
        );

        // Verify attachment_id is not empty
        assert!(
            !next_dest.attachment_id.is_empty(),
            "attachment_id should not be empty"
        );

        // Check which mediator this is for
        let target = &next_dest.to[0];
        if target.contains("mediator2") {
            found_mediator2 = true;
        } else if target.contains("mediator3") {
            found_mediator3 = true;
        }
    }

    assert!(
        found_mediator2,
        "Should have NextDestination for mediator2 (shared by David and Eve)"
    );
    assert!(
        found_mediator3,
        "Should have NextDestination for mediator3 (Frank's second hop)"
    );

    // Verify attachments exist
    assert!(
        unpacked_msg.attachments.is_some(),
        "Message should have attachments"
    );
    let attachments = unpacked_msg.attachments.as_ref().unwrap();

    println!("Number of attachments: {}", attachments.len());

    // Should have 2 attachments (one for each next hop group)
    assert_eq!(
        attachments.len(),
        2,
        "Should have 2 attachments for the 2 different next hops"
    );

    // Verify each attachment referenced in NextDestination exists
    for next_dest in &parsed_forward.next {
        let attachment_exists = attachments
            .iter()
            .any(|att| att.id.as_ref() == Some(&next_dest.attachment_id));
        assert!(
            attachment_exists,
            "Attachment {} should exist",
            next_dest.attachment_id
        );
    }

    // Verify each attachment contains encrypted JWE data
    for attachment in attachments {
        assert!(attachment.id.is_some(), "Each attachment should have an id");
        match &attachment.data {
            navia_didcomm::AttachmentData::Json { value } => {
                // Should be a JWE structure
                assert!(
                    value.json.get("protected").is_some() || value.json.get("recipients").is_some(),
                    "Attachment should contain JWE structure"
                );
            }
            _ => panic!("Attachment should be JSON type"),
        }
    }

    println!("✅ All routing-multi structure verifications passed:");
    println!("  - Message type is routing-multi/1.0/forward");
    println!("  - 2 NextDestination entries (mediator2 and mediator3)");
    println!("  - 2 attachments with valid JWE content");
    println!("  - All NextDestination.attachment_id references are valid");

    // --- Continue unpacking through mediator2 (David and Eve's path) ---
    println!("\n=== MEDIATOR2 Processing ===");

    // Find the attachment for mediator2
    let mediator2_next_dest = parsed_forward
        .next
        .iter()
        .find(|nd| nd.to[0].contains("mediator2"))
        .expect("Should have NextDestination for mediator2");

    println!(
        "Looking for attachment with ID: {}",
        mediator2_next_dest.attachment_id
    );

    let mediator2_attachment = attachments
        .iter()
        .find(|att| att.id.as_ref() == Some(&mediator2_next_dest.attachment_id))
        .expect("Should find mediator2 attachment");

    println!("Found attachment: {:?}", mediator2_attachment.id);

    // Extract the encrypted message for mediator2
    let mediator2_encrypted = match &mediator2_attachment.data {
        navia_didcomm::AttachmentData::Json { value } => {
            let encrypted = serde_json::to_string(&value.json).expect("Should serialize JWE");
            println!(
                "Mediator2 encrypted message (first 200 chars): {}",
                &encrypted[..encrypted.len().min(200)]
            );

            // Check the JWE structure to see who it's encrypted for
            println!("Full JWE structure:");
            println!(
                "{}",
                serde_json::to_string_pretty(&value.json).unwrap_or_default()
            );

            encrypted
        }
        _ => panic!("Attachment should be JSON type"),
    };

    // Unpack at mediator2
    let mediator2_secrets_vec = (*MEDIATOR2_SECRETS).clone();
    println!("Mediator2 secrets count: {}", mediator2_secrets_vec.len());
    for (i, secret) in mediator2_secrets_vec.iter().enumerate() {
        println!("  Secret {}: id={}", i, secret.id);
    }

    let mediator2_secrets = ExampleSecretsResolver::new(mediator2_secrets_vec);

    // Debug: try to get the secret directly
    let test_secret = mediator2_secrets
        .get_secret("did:example:mediator2#key-x25519-1")
        .await
        .unwrap();
    println!(
        "Direct secret lookup result: {:?}",
        test_secret.as_ref().map(|s| &s.id)
    );

    // Debug: parse JWE and extract kids manually
    let jwe_value: serde_json::Value =
        serde_json::from_str(&mediator2_encrypted).expect("Should parse JWE");
    if let Some(recipients) = jwe_value.get("recipients") {
        if let Some(recipients_array) = recipients.as_array() {
            println!("Manual kid extraction:");
            for (i, recipient) in recipients_array.iter().enumerate() {
                if let Some(header) = recipient.get("header") {
                    if let Some(kid) = header.get("kid") {
                        println!("  Recipient {}: kid={:?}", i, kid.as_str());
                    }
                }
            }
        }
    }

    let (mediator2_msg, _) = Message::unpack(
        &mediator2_encrypted,
        &did_resolver,
        &mediator2_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Mediator2 should be able to unpack the message");

    println!("Mediator2 unpacked message type: {}", mediator2_msg.type_);

    // Should be a routing-multi forward message since David and Eve diverge here
    assert_eq!(
        mediator2_msg.type_, "https://didcomm.org/routing-multi/1.0/forward",
        "Mediator2 should receive routing-multi forward message (David → med3, Eve → med4)"
    );

    let mediator2_forward =
        navia_didcomm::protocols::routing::try_parse_forward_multi(&mediator2_msg)
            .expect("Should parse as routing-multi forward message");

    // Should have 2 NextDestination entries (mediator3 and mediator4)
    assert_eq!(
        mediator2_forward.next.len(),
        2,
        "Mediator2 should have 2 NextDestination entries (mediator3 and mediator4)"
    );

    println!("Mediator2 routing-multi destinations:");
    for nd in &mediator2_forward.next {
        println!("  - to={:?}, attachment_id={}", nd.to, nd.attachment_id);
    }

    let mediator2_attachments = mediator2_msg
        .attachments
        .as_ref()
        .expect("Mediator2 message should have attachments");

    // --- Continue unpacking through mediator3 (for David) ---
    println!("\n=== MEDIATOR3 Processing (David's path) ===");

    // Find the attachment for mediator3
    let mediator3_next_dest = mediator2_forward
        .next
        .iter()
        .find(|nd| nd.to[0].contains("mediator3"))
        .expect("Should have NextDestination for mediator3");

    let mediator3_attachment = mediator2_attachments
        .iter()
        .find(|att| att.id.as_ref() == Some(&mediator3_next_dest.attachment_id))
        .expect("Should find mediator3 attachment");

    let mediator3_encrypted = match &mediator3_attachment.data {
        navia_didcomm::AttachmentData::Json { value } => {
            let encrypted = serde_json::to_string(&value.json).expect("Should serialize JWE");
            println!(
                "David's mediator3 JWE (first 300 chars): {}",
                &encrypted[..encrypted.len().min(300)]
            );

            // Debug: Check protected header for David's message
            if let Some(protected) = value.json.get("protected") {
                if let Some(protected_str) = protected.as_str() {
                    if let Ok(decoded) =
                        base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(protected_str)
                    {
                        if let Ok(protected_json) = String::from_utf8(decoded) {
                            println!("David's mediator3 JWE protected header:");
                            if let Ok(protected_value) =
                                serde_json::from_str::<serde_json::Value>(&protected_json)
                            {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&protected_value)
                                        .unwrap_or_default()
                                );
                            }
                        }
                    }
                }
            }
            encrypted
        }
        _ => panic!("Attachment should be JSON type"),
    };

    let mediator3_secrets = ExampleSecretsResolver::new((*MEDIATOR3_SECRETS).clone());
    let (mediator3_msg, _) = Message::unpack(
        &mediator3_encrypted,
        &did_resolver,
        &mediator3_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Mediator3 should be able to unpack the message");

    println!("Mediator3 unpacked message type: {}", mediator3_msg.type_);

    // Mediator3 should receive a forward message for David
    assert_eq!(
        mediator3_msg.type_, "https://didcomm.org/routing/2.0/forward",
        "Mediator3 should receive forward message for David"
    );

    let mediator3_forward = navia_didcomm::protocols::routing::try_parse_forward(&mediator3_msg)
        .expect("Should parse mediator3 forward message");

    // --- Unpack at David (final recipient) ---
    println!("\n=== DAVID Processing (final recipient) ===");

    let david_encrypted = mediator3_forward.forwarded_msg;
    let david_secrets = ExampleSecretsResolver::new((*DAVID_SECRETS).clone());

    let (david_msg, david_meta) = Message::unpack(
        &serde_json::to_string(&david_encrypted).unwrap(),
        &did_resolver,
        &david_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("David should be able to unpack the message");

    println!("David received message: {:?}", david_msg);
    println!("David metadata: {:?}", david_meta);

    // Verify David got the original message
    assert_eq!(david_msg.id, "test-routing-multi");
    assert_eq!(david_msg.type_, "https://example.com/test");
    assert_eq!(
        david_msg.body,
        json!({"content": "message with routing-multi optimization"})
    );
    assert!(david_meta.authenticated);
    assert_eq!(david_meta.from_prior, None);

    println!("✅ David successfully received the original message!");

    // --- Now process mediator4 for Eve ---
    println!("\n=== MEDIATOR4 Processing (Eve's path) ===");

    // Find the attachment for mediator4 from mediator2's routing-multi message
    let mediator4_next_dest = mediator2_forward
        .next
        .iter()
        .find(|nd| nd.to[0].contains("mediator4"))
        .expect("Should have NextDestination for mediator4");

    let mediator4_attachment = mediator2_attachments
        .iter()
        .find(|att| att.id.as_ref() == Some(&mediator4_next_dest.attachment_id))
        .expect("Should find mediator4 attachment");

    let mediator4_encrypted = match &mediator4_attachment.data {
        navia_didcomm::AttachmentData::Json { value } => {
            serde_json::to_string(&value.json).expect("Should serialize JWE")
        }
        _ => panic!("Attachment should be JSON type"),
    };

    let mediator4_secrets = ExampleSecretsResolver::new((*MEDIATOR4_SECRETS).clone());
    let (mediator4_msg, _) = Message::unpack(
        &mediator4_encrypted,
        &did_resolver,
        &mediator4_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Mediator4 should be able to unpack the message");

    println!("Mediator4 unpacked message type: {}", mediator4_msg.type_);

    // Mediator4 should receive a forward message for Eve
    assert_eq!(
        mediator4_msg.type_, "https://didcomm.org/routing/2.0/forward",
        "Mediator4 should receive forward message for Eve"
    );

    let mediator4_forward = navia_didcomm::protocols::routing::try_parse_forward(&mediator4_msg)
        .expect("Should parse mediator4 forward message");

    // --- Unpack at Eve (final recipient) ---
    println!("\n=== EVE Processing (final recipient) ===");

    let eve_encrypted = mediator4_forward.forwarded_msg;
    let eve_secrets = ExampleSecretsResolver::new((*EVE_SECRETS).clone());

    let (eve_msg, eve_meta) = Message::unpack(
        &serde_json::to_string(&eve_encrypted).unwrap(),
        &did_resolver,
        &eve_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Eve should be able to unpack the message");

    println!("Eve received message: {:?}", eve_msg);
    println!("Eve metadata: {:?}", eve_meta);

    // Verify Eve got the original message
    assert_eq!(eve_msg.id, "test-routing-multi");
    assert_eq!(eve_msg.type_, "https://example.com/test");
    assert_eq!(
        eve_msg.body,
        json!({"content": "message with routing-multi optimization"})
    );
    assert!(eve_meta.authenticated);

    println!("✅ Eve successfully received the original message!");

    // --- Now process Frank's path (mediator1 -> mediator3 -> mediator4 -> Frank) ---
    println!("\n=== FRANK's Path ===");
    println!("=== MEDIATOR3 Processing (Frank's first hop) ===");

    // Find the attachment for mediator3 from mediator1's routing-multi message
    let frank_mediator3_next_dest = parsed_forward
        .next
        .iter()
        .find(|nd| nd.to[0].contains("mediator3"))
        .expect("Should have NextDestination for mediator3 (Frank's path)");

    let frank_mediator3_attachment = attachments
        .iter()
        .find(|att| att.id.as_ref() == Some(&frank_mediator3_next_dest.attachment_id))
        .expect("Should find mediator3 attachment for Frank");

    // Extract the encrypted message for mediator3 (Frank's path)
    let frank_mediator3_encrypted = match &frank_mediator3_attachment.data {
        navia_didcomm::AttachmentData::Json { value } => {
            let encrypted = serde_json::to_string(&value.json).expect("Should serialize JWE");
            println!(
                "Frank's mediator3 encrypted JWE (first 300 chars): {}",
                &encrypted[..encrypted.len().min(300)]
            );

            // Debug: Check who this is encrypted for
            if let Some(recipients) = value.json.get("recipients") {
                if let Some(recipients_array) = recipients.as_array() {
                    println!("Frank's mediator3 JWE recipients:");
                    for (i, recipient) in recipients_array.iter().enumerate() {
                        if let Some(header) = recipient.get("header") {
                            if let Some(kid) = header.get("kid") {
                                println!("  Recipient {}: kid={:?}", i, kid.as_str());
                            }
                        }
                    }
                }
            }

            // Debug: Check protected header
            if let Some(protected) = value.json.get("protected") {
                if let Some(protected_str) = protected.as_str() {
                    // Decode base64url protected header
                    if let Ok(decoded) =
                        base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(protected_str)
                    {
                        if let Ok(protected_json) = String::from_utf8(decoded) {
                            println!("Frank's mediator3 JWE protected header:");
                            if let Ok(protected_value) =
                                serde_json::from_str::<serde_json::Value>(&protected_json)
                            {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&protected_value)
                                        .unwrap_or_default()
                                );
                            }
                        }
                    }
                }
            }
            encrypted
        }
        _ => panic!("Attachment should be JSON type"),
    };

    // Unpack at mediator3 (Frank's path)
    // Create a fresh secrets resolver for Frank's path
    let frank_mediator3_secrets = ExampleSecretsResolver::new((*MEDIATOR3_SECRETS).clone());
    let (frank_mediator3_msg, _) = Message::unpack(
        &frank_mediator3_encrypted,
        &did_resolver,
        &frank_mediator3_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Mediator3 should be able to unpack Frank's message");

    println!(
        "Mediator3 (Frank path) unpacked message type: {}",
        frank_mediator3_msg.type_
    );

    assert_eq!(
        frank_mediator3_msg.type_, "https://didcomm.org/routing/2.0/forward",
        "Mediator3 should receive forward message for Frank"
    );

    let frank_mediator3_forward =
        navia_didcomm::protocols::routing::try_parse_forward(&frank_mediator3_msg)
            .expect("Should parse Frank's mediator3 forward message");

    // --- Continue to mediator4 for Frank ---
    println!("=== MEDIATOR4 Processing (Frank's second hop) ===");

    let frank_mediator4_encrypted = frank_mediator3_forward.forwarded_msg;

    let (frank_mediator4_msg, _) = Message::unpack(
        &serde_json::to_string(&frank_mediator4_encrypted).unwrap(),
        &did_resolver,
        &mediator4_secrets, // Reuse mediator4 secrets
        &UnpackOptions::default(),
    )
    .await
    .expect("Mediator4 should be able to unpack Frank's message");

    println!(
        "Mediator4 (Frank path) unpacked message type: {}",
        frank_mediator4_msg.type_
    );

    assert_eq!(
        frank_mediator4_msg.type_, "https://didcomm.org/routing/2.0/forward",
        "Mediator4 should receive forward message for Frank"
    );

    let frank_mediator4_forward =
        navia_didcomm::protocols::routing::try_parse_forward(&frank_mediator4_msg)
            .expect("Should parse Frank's mediator4 forward message");

    // --- Unpack at Frank (final recipient) ---
    println!("\n=== FRANK Processing (final recipient) ===");

    let frank_encrypted = frank_mediator4_forward.forwarded_msg;
    let frank_secrets = ExampleSecretsResolver::new((*FRANK_SECRETS).clone());

    let (frank_msg, frank_meta) = Message::unpack(
        &serde_json::to_string(&frank_encrypted).unwrap(),
        &did_resolver,
        &frank_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Frank should be able to unpack the message");

    println!("Frank received message: {:?}", frank_msg);
    println!("Frank metadata: {:?}", frank_meta);

    // Verify Frank got the original message
    assert_eq!(frank_msg.id, "test-routing-multi");
    assert_eq!(frank_msg.type_, "https://example.com/test");
    assert_eq!(
        frank_msg.body,
        json!({"content": "message with routing-multi optimization"})
    );
    assert!(frank_meta.authenticated);

    println!("✅ Frank successfully received the original message!");

    // --- Final verification: all three recipients got the same message ---
    println!("\n=== FINAL VERIFICATION ===");
    assert_eq!(david_msg.id, eve_msg.id);
    assert_eq!(david_msg.id, frank_msg.id);
    assert_eq!(david_msg.body, eve_msg.body);
    assert_eq!(david_msg.body, frank_msg.body);

    println!("✅✅✅ All three recipients (David, Eve, Frank) successfully received the identical original message!");
    println!("✅ Complete end-to-end multi-hop routing verification passed!");
}

#[tokio::test]
async fn test_multi_recipient_shared_first_hop_without_routing_multi() {
    // Same scenario as above but with routing-multi disabled
    // This should create separate DIDComm 2.0 forward messages for each next hop
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        DAVID_DID_DOC.clone(),
        EVE_DID_DOC.clone(),
        FRANK_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
        MEDIATOR4_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let message = Message::build(
        "test-standard-didcomm".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "message with standard DIDComm 2.0 routing"}),
    )
    .to(DAVID_DID.to_owned())
    .to(EVE_DID.to_owned())
    .to(FRANK_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack with forwarding enabled but routing-multi=false
    let results = message
        .pack_encrypted(
            &[DAVID_DID, EVE_DID, FRANK_DID],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: true,
                use_routing_multi: false, // Disable routing-multi, use standard DIDComm 2.0
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .unwrap();

    // Without routing-multi, should get TWO separate messages (one per next hop)
    // David and Eve share mediator2 as next hop -> 1 message
    // Frank has mediator3 as next hop -> 1 message
    println!(
        "Number of messages without routing-multi (should be 2): {}",
        results.len()
    );

    assert_eq!(
        results.len(),
        2,
        "Should generate 2 separate DIDComm 2.0 forward messages (one for med2, one for med3)"
    );

    // Verify all messages have proper metadata
    for (packed, metadata) in &results {
        assert!(metadata.from_kid.is_some());
        assert!(!metadata.to_kids.is_empty());

        // Verify message structure
        let jwe: serde_json::Value = serde_json::from_str(packed).unwrap();
        assert!(jwe.get("protected").is_some() || jwe.get("recipients").is_some());
    }

    println!("✅ DIDComm 2.0 fallback test passed: 2 separate messages");
}

#[tokio::test]
async fn test_all_recipients_can_unpack_same_message() {
    // Test that all recipients can unpack the same multi-recipient message
    // This verifies the shared CEK approach works correctly
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        DAVID_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());
    let bob_secrets = ExampleSecretsResolver::new(BOB_SECRETS.clone());
    let charlie_secrets = ExampleSecretsResolver::new(CHARLIE_SECRETS.clone());
    let david_secrets = ExampleSecretsResolver::new(DAVID_SECRETS.clone());

    let message = Message::build(
        "test-all-unpack".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "message for all recipients", "data": [1, 2, 3]}),
    )
    .to(BOB_DID.to_owned())
    .to(CHARLIE_DID.to_owned())
    .to(DAVID_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack for all three recipients
    let (packed, metadata) = message
        .pack_encrypted(
            &[BOB_DID, CHARLIE_DID, DAVID_DID],
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

    // Verify metadata
    assert!(
        metadata.to_kids.len() >= 3,
        "Should have keys for 3 recipients"
    );
    assert!(metadata.from_kid.is_some());

    // All three recipients should be able to unpack
    let (bob_msg, bob_meta) = Message::unpack(
        &packed,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Bob should be able to unpack");

    let (charlie_msg, charlie_meta) = Message::unpack(
        &packed,
        &did_resolver,
        &charlie_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Charlie should be able to unpack");

    let (david_msg, david_meta) = Message::unpack(
        &packed,
        &did_resolver,
        &david_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("David should be able to unpack");

    // All should get the identical message
    assert_eq!(bob_msg.id, "test-all-unpack");
    assert_eq!(charlie_msg.id, "test-all-unpack");
    assert_eq!(david_msg.id, "test-all-unpack");

    assert_eq!(bob_msg.body, charlie_msg.body);
    assert_eq!(bob_msg.body, david_msg.body);
    assert_eq!(
        bob_msg.body,
        json!({"content": "message for all recipients", "data": [1, 2, 3]})
    );

    // All should have authenticated metadata
    assert!(bob_meta.authenticated);
    assert!(charlie_meta.authenticated);
    assert!(david_meta.authenticated);

    println!("✅ All 3 recipients successfully unpacked the same message");
}

#[tokio::test]
async fn test_multi_recipient_mixed_direct_and_routed() {
    // Test mix of direct recipients (no routing) and routed recipients (with mediators)
    // Bob: direct (no routing keys)
    // Charlie: routed through mediator1
    // David: routed through mediator2

    // Modify DIDs to have different routing configurations
    let bob_direct = with_routing_keys(&BOB_DID_DOC, vec![]); // No routing
    let charlie_routed =
        with_routing_keys(&CHARLIE_DID_DOC, vec!["did:example:mediator1".to_string()]);
    let david_routed = with_routing_keys(&DAVID_DID_DOC, vec!["did:example:mediator2".to_string()]);

    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        bob_direct,
        charlie_routed,
        david_routed,
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let message = Message::build(
        "test-mixed-routing".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "mixed direct and routed"}),
    )
    .to(BOB_DID.to_owned())
    .to(CHARLIE_DID.to_owned())
    .to(DAVID_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack with forwarding enabled
    let results = message
        .pack_encrypted(
            &[BOB_DID, CHARLIE_DID, DAVID_DID],
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

    // Should get multiple messages: one for direct (Bob), others for routed paths
    assert!(!results.is_empty());
    println!(
        "✅ Mixed routing test passed: {} message(s) generated",
        results.len()
    );
}

#[tokio::test]
async fn test_multi_recipient_varying_routing_depths() {
    // Test recipients with different routing depths
    // Bob: 1 hop (mediator1)
    // Charlie: 2 hops (mediator1 -> mediator2)
    // David: 3 hops (mediator1 -> mediator2 -> mediator3)

    // Create modified versions with different routing depths
    let bob_1hop = with_routing_keys(&BOB_DID_DOC, vec!["did:example:mediator1".to_string()]);
    let charlie_2hop = with_routing_keys(
        &CHARLIE_DID_DOC,
        vec![
            "did:example:mediator1".to_string(),
            "did:example:mediator2".to_string(),
        ],
    );
    let david_3hop = DAVID_DID_DOC.clone(); // Already has 3 hops in test vectors

    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        bob_1hop,
        charlie_2hop,
        david_3hop,
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let message = Message::build(
        "test-varying-depths".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "varying routing depths"}),
    )
    .to(BOB_DID.to_owned())
    .to(CHARLIE_DID.to_owned())
    .to(DAVID_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack with forwarding enabled
    let results = message
        .pack_encrypted(
            &[BOB_DID, CHARLIE_DID, DAVID_DID],
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

    // Should handle different depths correctly
    assert!(!results.is_empty());
    println!(
        "✅ Varying depths test passed: {} message(s) for different routing depths",
        results.len()
    );
}

#[tokio::test]
async fn test_mediators_cannot_decrypt_content() {
    // Security test: verify that mediators cannot decrypt the actual message content
    // They should only be able to decrypt the forward wrapper, not the inner message

    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());
    let mediator_secrets = ExampleSecretsResolver::new((*MEDIATOR1_SECRETS).clone());

    let message = Message::build(
        "test-mediator-security".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "sensitive data that mediator should NOT see"}),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack with forwarding through mediator1
    let results = message
        .pack_encrypted(
            &[BOB_DID],
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

    assert!(!results.is_empty());
    let (packed, _) = &results[0];

    // Mediator can unpack the forward wrapper
    let (mediator_msg, _) = Message::unpack(
        packed,
        &did_resolver,
        &mediator_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Mediator should unpack forward wrapper");

    // Should be a forward message type
    assert!(
        mediator_msg.type_.contains("forward"),
        "Mediator should only see forward message"
    );

    // Mediator should NOT be able to see the original message content
    assert_ne!(
        mediator_msg.body,
        json!({"content": "sensitive data that mediator should NOT see"}),
        "Mediator should NOT be able to read original message body"
    );

    println!("✅ Mediator security test passed: mediator cannot decrypt content");
}

#[tokio::test]
async fn test_multi_recipient_no_common_paths() {
    // Test when recipients have completely different mediator chains (no optimization possible)
    // Bob: mediator1
    // Charlie: mediator2
    // David: mediator3

    let bob_med1 = with_routing_keys(&BOB_DID_DOC, vec!["did:example:mediator1".to_string()]);
    let charlie_med2 =
        with_routing_keys(&CHARLIE_DID_DOC, vec!["did:example:mediator2".to_string()]);
    let david_med3 = with_routing_keys(&DAVID_DID_DOC, vec!["did:example:mediator3".to_string()]);

    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        bob_med1,
        charlie_med2,
        david_med3,
        MEDIATOR1_DID_DOC.clone(),
        MEDIATOR2_DID_DOC.clone(),
        MEDIATOR3_DID_DOC.clone(),
    ]);

    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let message = Message::build(
        "test-no-common".to_string(),
        "https://example.com/test".to_string(),
        json!({"content": "no common mediators"}),
    )
    .to(BOB_DID.to_owned())
    .to(CHARLIE_DID.to_owned())
    .to(DAVID_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    // Pack with forwarding enabled
    let results = message
        .pack_encrypted(
            &[BOB_DID, CHARLIE_DID, DAVID_DID],
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

    // Should create separate messages (one per routing destination)
    // With different mediators, we expect multiple messages (typically 2-3)
    assert!(
        results.len() >= 2,
        "Should create at least 2 separate messages for different mediators, got {}",
        results.len()
    );

    println!(
        "✅ No common paths test passed: {} separate message(s) created",
        results.len()
    );
}
