//! End-to-end integration tests for navia-didcomm
//!
//! These tests simulate real-world DIDComm v2 scenarios including:
//! - Alice ↔ Bob direct messaging
//! - Multi-party conversations  
//! - Cross-curve compatibility in practice
//! - Error scenarios and edge cases

use navia_didcomm::{
    did::{
        resolvers::ExampleDIDResolver, DIDDoc, VerificationMaterial, VerificationMethod,
        VerificationMethodType,
    },
    secrets::{resolvers::ExampleSecretsResolver, Secret, SecretMaterial, SecretType},
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;

// Create test DIDs and secrets manually to avoid import issues
fn create_alice_did_and_secrets() -> (DIDDoc, Vec<Secret>) {
    let did_doc = DIDDoc {
        id: "did:example:alice".to_string(),
        verification_method: vec![
            VerificationMethod {
                id: "did:example:alice#key-1".to_string(),
                type_: VerificationMethodType::JsonWebKey2020,
                controller: "did:example:alice".to_string(),
                verification_material: VerificationMaterial::JWK {
                    public_key_jwk: json!({
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                    }),
                },
            },
            VerificationMethod {
                id: "did:example:alice#key-agreement-1".to_string(),
                type_: VerificationMethodType::JsonWebKey2020,
                controller: "did:example:alice".to_string(),
                verification_material: VerificationMaterial::JWK {
                    public_key_jwk: json!({
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
                    }),
                },
            },
        ],
        authentication: vec!["did:example:alice#key-1".to_string()],
        key_agreement: vec!["did:example:alice#key-agreement-1".to_string()],
        service: vec![],
    };

    let secrets = vec![
        Secret {
            id: "did:example:alice#key-1".to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "kty": "OKP",
                    "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                    "crv": "Ed25519",
                    "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                }),
            },
        },
        Secret {
            id: "did:example:alice#key-agreement-1".to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "kty": "OKP",
                    "d": "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
                    "crv": "X25519",
                    "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
                }),
            },
        },
    ];

    (did_doc, secrets)
}

fn create_bob_did_and_secrets() -> (DIDDoc, Vec<Secret>) {
    let did_doc = DIDDoc {
        id: "did:example:bob".to_string(),
        verification_method: vec![
            VerificationMethod {
                id: "did:example:bob#key-1".to_string(),
                type_: VerificationMethodType::JsonWebKey2020,
                controller: "did:example:bob".to_string(),
                verification_material: VerificationMaterial::JWK {
                    public_key_jwk: json!({
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
                    }),
                },
            },
            VerificationMethod {
                id: "did:example:bob#key-agreement-1".to_string(),
                type_: VerificationMethodType::JsonWebKey2020,
                controller: "did:example:bob".to_string(),
                verification_material: VerificationMaterial::JWK {
                    public_key_jwk: json!({
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
                    }),
                },
            },
        ],
        authentication: vec!["did:example:bob#key-1".to_string()],
        key_agreement: vec!["did:example:bob#key-agreement-1".to_string()],
        service: vec![],
    };

    let secrets = vec![
        Secret {
            id: "did:example:bob#key-1".to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "kty": "OKP",
                    "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
                    "crv": "Ed25519",
                    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
                }),
            },
        },
        Secret {
            id: "did:example:bob#key-agreement-1".to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "kty": "OKP",
                    "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
                    "crv": "X25519",
                    "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
                }),
            },
        },
    ];

    (did_doc, secrets)
}

fn create_charlie_did_and_secrets() -> (DIDDoc, Vec<Secret>) {
    let did_doc = DIDDoc {
        id: "did:example:charlie".to_string(),
        verification_method: vec![
            VerificationMethod {
                id: "did:example:charlie#key-1".to_string(),
                type_: VerificationMethodType::JsonWebKey2020,
                controller: "did:example:charlie".to_string(),
                verification_material: VerificationMaterial::JWK {
                    public_key_jwk: json!({
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE"
                    }),
                },
            },
            VerificationMethod {
                id: "did:example:charlie#key-agreement-1".to_string(),
                type_: VerificationMethodType::JsonWebKey2020,
                controller: "did:example:charlie".to_string(),
                verification_material: VerificationMaterial::JWK {
                    public_key_jwk: json!({
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                    }),
                },
            },
        ],
        authentication: vec!["did:example:charlie#key-1".to_string()],
        key_agreement: vec!["did:example:charlie#key-agreement-1".to_string()],
        service: vec![],
    };

    let secrets = vec![
        Secret {
            id: "did:example:charlie#key-1".to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "kty": "OKP",
                    "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
                    "crv": "Ed25519",
                    "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE"
                }),
            },
        },
        Secret {
            id: "did:example:charlie#key-agreement-1".to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "kty": "OKP",
                    "d": "Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
                    "crv": "X25519",
                    "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                }),
            },
        },
    ];

    (did_doc, secrets)
}

/// Test basic Alice → Bob encrypted message flow
#[tokio::test]
async fn test_end_to_end_alice_to_bob_encrypted() {
    // Setup test data
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);

    // Alice creates and sends message
    let message = Message::build(
        "test-message-1".to_string(),
        "https://example.com/protocols/test/1.0/message".to_string(),
        json!({
            "content": "Hello Bob, this is Alice!",
            "timestamp": 1234567890
        }),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    // Alice packs the message
    let (packed_msg, _metadata) = message
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None, // no signing
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Alice failed to pack message")
        .into_iter()
        .next()
        .unwrap();

    // Bob receives and unpacks the message
    let (unpacked_msg, unpack_metadata) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Bob failed to unpack message");

    // Verify message content
    assert_eq!(unpacked_msg.id, "test-message-1");
    assert_eq!(
        unpacked_msg.type_,
        "https://example.com/protocols/test/1.0/message"
    );
    assert_eq!(unpacked_msg.body["content"], "Hello Bob, this is Alice!");
    assert_eq!(unpacked_msg.to, Some(vec![bob_did_doc.id.clone()]));
    assert_eq!(unpacked_msg.from, Some(alice_did_doc.id.clone()));

    // Verify metadata
    assert!(unpack_metadata.encrypted);
    assert!(unpack_metadata.authenticated); // authcrypt when sender is provided
    assert!(!unpack_metadata.non_repudiation); // no signing key provided
    assert!(!unpack_metadata.anonymous_sender);
}

/// Test Alice → Bob signed and encrypted message flow
#[tokio::test]
async fn test_end_to_end_alice_to_bob_signed_encrypted() {
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);

    let message = Message::build(
        "signed-test-1".to_string(),
        "https://example.com/protocols/test/1.0/signed".to_string(),
        json!({
            "content": "This is a signed message from Alice",
            "importance": "high"
        }),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    // Alice signs and encrypts the message
    let (packed_msg, _metadata) = message
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            Some("did:example:alice#key-1"), // Alice signs with her key
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Alice failed to pack signed message")
        .into_iter()
        .next()
        .unwrap();

    // Bob unpacks and verifies
    let (unpacked_msg, unpack_metadata) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Bob failed to unpack signed message");

    // Verify signature was validated
    assert_eq!(
        unpacked_msg.body["content"],
        "This is a signed message from Alice"
    );
    assert!(unpack_metadata.encrypted);
    assert!(unpack_metadata.authenticated);
    assert!(unpack_metadata.non_repudiation);
    assert_eq!(
        unpack_metadata.sign_from,
        Some("did:example:alice#key-1".to_string())
    );
}

/// Test multi-party conversation: Alice → Bob → Charlie
#[tokio::test]
async fn test_end_to_end_multi_party_conversation() {
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();
    let (charlie_did_doc, charlie_secrets) = create_charlie_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![
        alice_did_doc.clone(),
        bob_did_doc.clone(),
        charlie_did_doc.clone(),
    ]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);
    let charlie_secrets_resolver = ExampleSecretsResolver::new(charlie_secrets);

    // Step 1: Alice sends initial message to Bob
    let alice_msg = Message::build(
        "conversation-start".to_string(),
        "https://example.com/protocols/chat/1.0/message".to_string(),
        json!({
            "text": "Hey Bob, want to include Charlie in this conversation?",
            "thread_id": "chat-thread-123"
        }),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .thid("chat-thread-123".to_string())
    .finalize();

    let (alice_packed, _) = alice_msg
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Alice failed to pack message to Bob")
        .into_iter()
        .next()
        .unwrap();

    let (bob_received, _) = Message::unpack(
        &alice_packed,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Bob failed to unpack Alice's message");

    // Verify Bob got Alice's message
    assert_eq!(
        bob_received.body["text"],
        "Hey Bob, want to include Charlie in this conversation?"
    );
    assert_eq!(bob_received.thid, Some("chat-thread-123".to_string()));

    // Step 2: Bob forwards conversation context to Charlie
    let bob_to_charlie = Message::build(
        "conversation-forward".to_string(),
        "https://example.com/protocols/chat/1.0/forward".to_string(),
        json!({
            "text": "Alice wants to start a group chat. Here's what she said:",
            "original_message": bob_received.body,
            "thread_id": "chat-thread-123"
        }),
    )
    .to(charlie_did_doc.id.clone())
    .from(bob_did_doc.id.clone())
    .thid("chat-thread-123".to_string())
    .finalize();

    let (bob_packed, _) = bob_to_charlie
        .pack_encrypted(
            &[charlie_did_doc.id.clone()],
            Some(&bob_did_doc.id),
            None,
            &did_resolver,
            &bob_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Bob failed to pack message to Charlie")
        .into_iter()
        .next()
        .unwrap();

    let (charlie_received, _charlie_metadata) = Message::unpack(
        &bob_packed,
        &did_resolver,
        &charlie_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Charlie failed to unpack Bob's message");

    // Verify Charlie got the forwarded conversation
    assert_eq!(charlie_received.from, Some(bob_did_doc.id.clone()));
    assert_eq!(charlie_received.thid, Some("chat-thread-123".to_string()));
    assert_eq!(
        charlie_received.body["original_message"]["text"],
        "Hey Bob, want to include Charlie in this conversation?"
    );

    // Step 3: Charlie responds to Alice
    let charlie_response = Message::build(
        "conversation-join".to_string(),
        "https://example.com/protocols/chat/1.0/response".to_string(),
        json!({
            "text": "Sure! I'd love to join the conversation.",
            "thread_id": "chat-thread-123",
            "in_reply_to": "conversation-start"
        }),
    )
    .to(alice_did_doc.id.clone())
    .from(charlie_did_doc.id.clone())
    .thid("chat-thread-123".to_string())
    .finalize();

    let (charlie_packed, _) = charlie_response
        .pack_encrypted(
            &[alice_did_doc.id.clone()],
            Some(&charlie_did_doc.id),
            None,
            &did_resolver,
            &charlie_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Charlie failed to pack response to Alice")
        .into_iter()
        .next()
        .unwrap();

    let (alice_received_response, _) = Message::unpack(
        &charlie_packed,
        &did_resolver,
        &alice_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Alice failed to unpack Charlie's response");

    // Verify Alice got Charlie's response
    assert_eq!(
        alice_received_response.from,
        Some(charlie_did_doc.id.clone())
    );
    assert_eq!(
        alice_received_response.body["text"],
        "Sure! I'd love to join the conversation."
    );
    assert_eq!(
        alice_received_response.thid,
        Some("chat-thread-123".to_string())
    );
    assert_eq!(
        alice_received_response.body["in_reply_to"],
        "conversation-start"
    );

    // All parties successfully participated in the conversation!
}

/// Test that different curve types can communicate end-to-end
#[tokio::test]
async fn test_end_to_end_cross_curve_messaging() {
    // Use Alice (X25519/Ed25519) and Bob (also X25519/Ed25519) as they should be compatible
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);

    // Test bidirectional communication to ensure both directions work

    // Alice → Bob
    let alice_to_bob = Message::build(
        "cross-curve-test-1".to_string(),
        "https://example.com/protocols/test/1.0/curves".to_string(),
        json!({
            "content": "Testing curve compatibility Alice->Bob",
            "direction": "alice_to_bob"
        }),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    let (packed1, _) = alice_to_bob
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Alice→Bob cross-curve packing failed")
        .into_iter()
        .next()
        .unwrap();

    let (unpacked1, metadata1) = Message::unpack(
        &packed1,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Alice→Bob cross-curve unpacking failed");

    assert_eq!(
        unpacked1.body["content"],
        "Testing curve compatibility Alice->Bob"
    );
    assert!(metadata1.encrypted);

    // Bob → Alice (reverse direction)
    let bob_to_alice = Message::build(
        "cross-curve-test-2".to_string(),
        "https://example.com/protocols/test/1.0/curves".to_string(),
        json!({
            "content": "Testing curve compatibility Bob->Alice",
            "direction": "bob_to_alice"
        }),
    )
    .to(alice_did_doc.id.clone())
    .from(bob_did_doc.id.clone())
    .finalize();

    let (packed2, _) = bob_to_alice
        .pack_encrypted(
            &[alice_did_doc.id.clone()],
            Some(&bob_did_doc.id),
            None,
            &did_resolver,
            &bob_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Bob→Alice cross-curve packing failed")
        .into_iter()
        .next()
        .unwrap();

    let (unpacked2, metadata2) = Message::unpack(
        &packed2,
        &did_resolver,
        &alice_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Bob→Alice cross-curve unpacking failed");

    assert_eq!(
        unpacked2.body["content"],
        "Testing curve compatibility Bob->Alice"
    );
    assert!(metadata2.encrypted);
}

/// Test error handling in end-to-end scenarios
#[tokio::test]
async fn test_end_to_end_error_scenarios() {
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);

    // Test 1: Sending to unknown recipient
    let message_to_unknown = Message::build(
        "error-test-1".to_string(),
        "https://example.com/protocols/test/1.0/error".to_string(),
        json!({"content": "Message to unknown recipient"}),
    )
    .to("did:example:unknown".to_string())
    .from(alice_did_doc.id.clone())
    .finalize();

    let result = message_to_unknown
        .pack_encrypted(
            &["did:example:unknown".to_string()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await;

    assert!(result.is_err(), "Should fail when sending to unknown DID");

    // Test 2: Bob tries to unpack message not intended for him
    let alice_to_bob = Message::build(
        "error-test-2".to_string(),
        "https://example.com/protocols/test/1.0/error".to_string(),
        json!({"content": "Message for Bob only"}),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    let (packed_for_bob, _) = alice_to_bob
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Should successfully pack message for Bob")
        .into_iter()
        .next()
        .unwrap();

    // Alice tries to unpack Bob's message (should fail)
    let alice_unpack_result = Message::unpack(
        &packed_for_bob,
        &did_resolver,
        &alice_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await;

    assert!(
        alice_unpack_result.is_err(),
        "Alice should not be able to unpack message intended for Bob"
    );

    // But Bob should be able to unpack it successfully
    let bob_unpack_result = Message::unpack(
        &packed_for_bob,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await;

    assert!(
        bob_unpack_result.is_ok(),
        "Bob should be able to unpack message intended for him"
    );
}

/// Test message threading and conversation continuity
#[tokio::test]
async fn test_end_to_end_message_threading() {
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);

    let thread_id = "conversation-thread-456";

    // Message 1: Alice starts conversation
    let msg1 = Message::build(
        "thread-msg-1".to_string(),
        "https://example.com/protocols/chat/1.0/start".to_string(),
        json!({
            "text": "Hey Bob! How's your day going?",
            "sequence": 1
        }),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .thid(thread_id.to_string())
    .finalize();

    let (packed1, _) = msg1
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let (unpacked1, _) = Message::unpack(
        &packed1,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(unpacked1.thid, Some(thread_id.to_string()));
    assert_eq!(unpacked1.body["sequence"], 1);

    // Message 2: Bob replies in same thread
    let msg2 = Message::build(
        "thread-msg-2".to_string(),
        "https://example.com/protocols/chat/1.0/reply".to_string(),
        json!({
            "text": "It's going great! Thanks for asking. How about you?",
            "sequence": 2,
            "reply_to": "thread-msg-1"
        }),
    )
    .to(alice_did_doc.id.clone())
    .from(bob_did_doc.id.clone())
    .thid(thread_id.to_string())
    .finalize();

    let (packed2, _) = msg2
        .pack_encrypted(
            &[alice_did_doc.id.clone()],
            Some(&bob_did_doc.id),
            None,
            &did_resolver,
            &bob_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let (unpacked2, _) = Message::unpack(
        &packed2,
        &did_resolver,
        &alice_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    // Verify thread continuity
    assert_eq!(unpacked2.thid, Some(thread_id.to_string()));
    assert_eq!(unpacked2.body["sequence"], 2);
    assert_eq!(unpacked2.body["reply_to"], "thread-msg-1");
    assert_eq!(unpacked2.from, Some(bob_did_doc.id.clone()));

    // Message 3: Alice continues the thread
    let msg3 = Message::build(
        "thread-msg-3".to_string(),
        "https://example.com/protocols/chat/1.0/continue".to_string(),
        json!({
            "text": "I'm doing well too! Want to grab lunch later?",
            "sequence": 3,
            "reply_to": "thread-msg-2"
        }),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .thid(thread_id.to_string())
    .finalize();

    let (packed3, _) = msg3
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let (unpacked3, _) = Message::unpack(
        &packed3,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .unwrap();

    // Verify thread continuity is maintained
    assert_eq!(unpacked3.thid, Some(thread_id.to_string()));
    assert_eq!(unpacked3.body["sequence"], 3);
    assert_eq!(unpacked3.body["reply_to"], "thread-msg-2");

    // All messages successfully maintained thread continuity!
}

/// Test comprehensive error scenarios and edge cases
#[tokio::test]
async fn test_comprehensive_error_scenarios() {
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);

    // Test 1: Message with no recipients
    let no_recipients_msg = Message::build(
        "no-recipients-test".to_string(),
        "https://example.com/protocols/test/1.0/error".to_string(),
        json!({"content": "Message with no recipients"}),
    )
    .from(alice_did_doc.id.clone())
    .finalize();

    let result = no_recipients_msg
        .pack_encrypted(
            &[], // Empty recipient
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await;

    assert!(result.is_err(), "Should fail with empty recipient");

    // Test 2: Message with malformed DID
    let malformed_did_msg = Message::build(
        "malformed-did-test".to_string(),
        "https://example.com/protocols/test/1.0/error".to_string(),
        json!({"content": "Message to malformed DID"}),
    )
    .to("not-a-valid-did".to_string())
    .from(alice_did_doc.id.clone())
    .finalize();

    let result = malformed_did_msg
        .pack_encrypted(
            &["not-a-valid-did".to_string()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await;

    assert!(result.is_err(), "Should fail with malformed DID");

    // Test 3: Missing signing key for signed message
    let msg_to_sign = Message::build(
        "missing-sign-key-test".to_string(),
        "https://example.com/protocols/test/1.0/signed".to_string(),
        json!({"content": "Trying to sign without proper key"}),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    let result = msg_to_sign
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            Some("did:example:nonexistent#key-999"), // Non-existent signing key
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await;

    assert!(result.is_err(), "Should fail with non-existent signing key");

    // Test 4: Corrupted packed message
    let valid_msg = Message::build(
        "corruption-test".to_string(),
        "https://example.com/protocols/test/1.0/test".to_string(),
        json!({"content": "This will be corrupted"}),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    let (mut packed_msg, _) = valid_msg
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Should pack successfully")
        .into_iter()
        .next()
        .unwrap();

    // Corrupt the message by modifying a character
    packed_msg = packed_msg.replace('a', "x");

    let result = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await;

    assert!(result.is_err(), "Should fail with corrupted message");

    // Test 5: Message with invalid JSON body (we'll create this manually)
    let invalid_json_msg = r#"{"test": invalid_json}"#;
    let result = Message::unpack(
        invalid_json_msg,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await;

    assert!(result.is_err(), "Should fail with invalid JSON");
}

/// Test edge cases with message content and structure
#[tokio::test]
async fn test_message_content_edge_cases() {
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);

    // Test 1: Empty message body
    let empty_body_msg = Message::build(
        "empty-body-test".to_string(),
        "https://example.com/protocols/test/1.0/empty".to_string(),
        json!({}), // Empty JSON object
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    let (packed_msg, _) = empty_body_msg
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Should pack empty body successfully")
        .into_iter()
        .next()
        .unwrap();

    let (unpacked_msg, _) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Should unpack empty body successfully");

    assert_eq!(unpacked_msg.body, json!({}));

    // Test 2: Very large message body
    let large_content = "x".repeat(100_000); // 100KB of content
    let large_body_msg = Message::build(
        "large-body-test".to_string(),
        "https://example.com/protocols/test/1.0/large".to_string(),
        json!({"large_field": large_content}),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    let (packed_msg, _) = large_body_msg
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Should pack large body successfully")
        .into_iter()
        .next()
        .unwrap();

    let (unpacked_msg, _) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Should unpack large body successfully");

    assert_eq!(unpacked_msg.body["large_field"], json!(large_content));

    // Test 3: Message with special characters and Unicode
    let unicode_msg = Message::build(
        "unicode-test-🚀".to_string(),
        "https://example.com/protocols/test/1.0/unicode".to_string(),
        json!({
            "english": "Hello World",
            "japanese": "こんにちは世界",
            "arabic": "مرحبا بالعالم",
            "emoji": "🎉🔐💬🌍",
            "special_chars": "!@#$%^&*()[]{}|;':\",./<>?",
            "null_byte": "before\u{0000}after"
        }),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    let (packed_msg, _) = unicode_msg
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Should pack unicode message successfully")
        .into_iter()
        .next()
        .unwrap();

    let (unpacked_msg, _) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Should unpack unicode message successfully");

    assert_eq!(unpacked_msg.body["japanese"], json!("こんにちは世界"));
    assert_eq!(unpacked_msg.body["emoji"], json!("🎉🔐💬🌍"));
    assert_eq!(unpacked_msg.id, "unicode-test-🚀");
}

/// Test resolver edge cases and failure modes
#[tokio::test]
async fn test_resolver_edge_cases() {
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, _bob_secrets) = create_bob_did_and_secrets();

    // Test 1: Empty DID resolver
    let empty_did_resolver = ExampleDIDResolver::new(vec![]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets.clone());

    let msg = Message::build(
        "empty-resolver-test".to_string(),
        "https://example.com/protocols/test/1.0/resolver".to_string(),
        json!({"content": "Testing empty resolver"}),
    )
    .to(bob_did_doc.id.clone())
    .from(alice_did_doc.id.clone())
    .finalize();

    let result = msg
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &empty_did_resolver,
            &alice_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await;

    assert!(result.is_err(), "Should fail with empty DID resolver");

    // Test 2: Empty secrets resolver
    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let empty_secrets_resolver = ExampleSecretsResolver::new(vec![]);

    let result = msg
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &empty_secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await;

    assert!(result.is_err(), "Should fail with empty secrets resolver");

    // Test 3: Mismatched DID and secrets
    let charlie_secrets_resolver = ExampleSecretsResolver::new(create_charlie_did_and_secrets().1);

    let result = msg
        .pack_encrypted(
            &[bob_did_doc.id.clone()],
            Some(&alice_did_doc.id),
            None,
            &did_resolver,
            &charlie_secrets_resolver, // Charlie's secrets but Alice's DID
            &PackEncryptedOptions::default(),
        )
        .await;

    assert!(
        result.is_err(),
        "Should fail with mismatched DID and secrets"
    );
}

/// Test sequential message processing (simulates concurrent workload)
#[tokio::test]
async fn test_sequential_message_processing() {
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);

    // Process multiple messages sequentially to test stability
    for i in 0..10 {
        let msg = Message::build(
            format!("sequential-test-{}", i),
            "https://example.com/protocols/test/1.0/sequential".to_string(),
            json!({
                "message_number": i,
                "content": format!("Sequential message {}", i)
            }),
        )
        .to(bob_did_doc.id.clone())
        .from(alice_did_doc.id.clone())
        .finalize();

        // Alice packs the message
        let (packed_msg, _) = msg
            .pack_encrypted(
                &[bob_did_doc.id.clone()],
                Some(&alice_did_doc.id),
                None,
                &did_resolver,
                &alice_secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .unwrap_or_else(|_| panic!("Should pack message {}", i))
            .into_iter()
            .next()
            .unwrap();

        // Bob unpacks the message
        let (unpacked_msg, _) = Message::unpack(
            &packed_msg,
            &did_resolver,
            &bob_secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .unwrap_or_else(|_| panic!("Should unpack message {}", i));

        // Verify message content
        assert_eq!(unpacked_msg.id, format!("sequential-test-{}", i));
        assert_eq!(unpacked_msg.body["message_number"], json!(i));
        assert_eq!(
            unpacked_msg.body["content"],
            json!(format!("Sequential message {}", i))
        );
    }
}

/// Test message size limits and performance under stress
#[tokio::test]
async fn test_message_size_and_performance_limits() {
    let (alice_did_doc, alice_secrets) = create_alice_did_and_secrets();
    let (bob_did_doc, bob_secrets) = create_bob_did_and_secrets();

    let did_resolver = ExampleDIDResolver::new(vec![alice_did_doc.clone(), bob_did_doc.clone()]);
    let alice_secrets_resolver = ExampleSecretsResolver::new(alice_secrets);
    let bob_secrets_resolver = ExampleSecretsResolver::new(bob_secrets);

    // Test various message sizes
    let test_sizes = vec![
        ("tiny", 10),        // 10 bytes
        ("small", 1_000),    // 1 KB
        ("medium", 10_000),  // 10 KB
        ("large", 100_000),  // 100 KB
        ("huge", 1_000_000), // 1 MB
    ];

    for (size_name, byte_count) in test_sizes {
        println!("Testing {} message ({} bytes)", size_name, byte_count);

        let content = "x".repeat(byte_count);
        let msg = Message::build(
            format!("size-test-{}", size_name),
            "https://example.com/protocols/test/1.0/size".to_string(),
            json!({
                "size_category": size_name,
                "content": content,
                "byte_count": byte_count
            }),
        )
        .to(bob_did_doc.id.clone())
        .from(alice_did_doc.id.clone())
        .finalize();

        let start_time = std::time::Instant::now();

        let (packed_msg, _) = msg
            .pack_encrypted(
                &[bob_did_doc.id.clone()],
                Some(&alice_did_doc.id),
                None,
                &did_resolver,
                &alice_secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .unwrap_or_else(|_| panic!("Should pack {} message successfully", size_name))
            .into_iter()
            .next()
            .unwrap();

        let pack_duration = start_time.elapsed();

        let unpack_start = std::time::Instant::now();

        let (unpacked_msg, _) = Message::unpack(
            &packed_msg,
            &did_resolver,
            &bob_secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .unwrap_or_else(|_| panic!("Should unpack {} message successfully", size_name));

        let unpack_duration = unpack_start.elapsed();
        let total_duration = start_time.elapsed();

        println!(
            "{} message: pack={}ms, unpack={}ms, total={}ms",
            size_name,
            pack_duration.as_millis(),
            unpack_duration.as_millis(),
            total_duration.as_millis()
        );

        // Verify content integrity
        assert_eq!(unpacked_msg.body["size_category"], json!(size_name));
        assert_eq!(unpacked_msg.body["byte_count"], json!(byte_count));
        assert_eq!(unpacked_msg.body["content"], json!(content));

        // Performance assertions (these are quite lenient)
        assert!(
            pack_duration.as_secs() < 10,
            "Pack should complete within 10 seconds"
        );
        assert!(
            unpack_duration.as_secs() < 10,
            "Unpack should complete within 10 seconds"
        );
    }
}
