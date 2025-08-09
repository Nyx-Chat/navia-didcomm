//! Comprehensive end-to-end PQC tests
//!
//! This test suite validates the complete DIDComm v2 messaging flow using
//! 100% Post-Quantum Cryptography (ML-KEM + ML-DSA) including:
//! - Alice-to-Bob direct messaging  
//! - All encryption modes: AuthCrypt, AnonCrypt, Signed+Encrypted
//! - Plaintext and signed messaging
//! - Large message handling
//! - Algorithm compatibility testing

use navia_didcomm::{
    algorithms::AuthCryptAlg,
    test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;

#[tokio::test]
async fn test_pqc_comprehensive_e2e_flow() {
    println!("=================== PQC COMPREHENSIVE E2E FLOW ===================");

    // This test validates the complete PQC DIDComm flow
    let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Test vectors");

    // Use the original DIDs from test vectors for consistency
    let alice_did = vectors.alice_did.clone();
    let bob_did = vectors.bob_did.clone();

    let mut did_resolver = PQCTestDIDResolver::new();

    // Use original DID docs
    did_resolver.add_did_doc(alice_did.clone(), vectors.alice_did_doc.clone());
    did_resolver.add_did_doc(bob_did.clone(), vectors.bob_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());
    let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets);

    // Test 1: Plaintext message (no encryption)
    println!("--- Test 1: Plaintext Message ---");
    let plaintext_msg = Message::build(
        "comprehensive-plaintext".to_string(),
        "https://example.com/protocols/test/1.0/plaintext".to_string(),
        json!({"test": "PQC plaintext messaging"}),
    )
    .to(bob_did.clone())
    .from(alice_did.clone())
    .finalize();

    let packed_plaintext = plaintext_msg
        .pack_plaintext(&did_resolver)
        .await
        .expect("Failed to pack plaintext");

    let (unpacked_plaintext, plaintext_metadata) = Message::unpack(
        &packed_plaintext,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack plaintext");

    assert_eq!(plaintext_msg.body, unpacked_plaintext.body);
    assert!(
        !plaintext_metadata.encrypted,
        "Plaintext should not be encrypted"
    );
    assert!(
        !plaintext_metadata.authenticated,
        "Plaintext should not be authenticated"
    );

    println!("✅ PQC plaintext messaging works");

    // Test 2: Signed message (no encryption)
    println!("--- Test 2: Signed Message ---");
    let (signed_msg, _signed_pack_metadata) = plaintext_msg
        .pack_signed(&alice_did, &did_resolver, &alice_secrets)
        .await
        .expect("Failed to pack signed message");

    let (unpacked_signed, signed_unpack_metadata) = Message::unpack(
        &signed_msg,
        &did_resolver,
        &bob_secrets, // Bob unpacks Alice's signed message
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack signed message");

    assert_eq!(plaintext_msg.body, unpacked_signed.body);
    assert!(
        !signed_unpack_metadata.encrypted,
        "Signed-only should not be encrypted"
    );
    assert!(
        signed_unpack_metadata.authenticated,
        "Signed message should be authenticated"
    );
    assert!(
        signed_unpack_metadata.non_repudiation,
        "Signed message should be non-repudiable"
    );

    println!("✅ PQC signed messaging works");

    // Test 3: AuthCrypt (authenticated encryption)
    println!("--- Test 3: AuthCrypt ---");
    let authcrypt_msg = Message::build(
        "comprehensive-authcrypt".to_string(),
        "https://example.com/protocols/test/1.0/authcrypt".to_string(),
        json!({"test": "PQC AuthCrypt messaging", "mode": "authenticated"}),
    )
    .to(bob_did.clone())
    .from(alice_did.clone())
    .finalize();

    let (authcrypt_packed, authcrypt_pack_metadata) = authcrypt_msg
        .pack_encrypted(
            &bob_did,
            Some(&alice_did),
            None,
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack AuthCrypt message");

    assert!(
        authcrypt_pack_metadata.from_kid.is_some(),
        "AuthCrypt should have from_kid"
    );

    let (authcrypt_unpacked, authcrypt_unpack_metadata) = Message::unpack(
        &authcrypt_packed,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack AuthCrypt message");

    assert_eq!(authcrypt_msg.body, authcrypt_unpacked.body);
    assert!(
        authcrypt_unpack_metadata.authenticated,
        "AuthCrypt should be authenticated"
    );
    assert!(
        authcrypt_unpack_metadata.encrypted,
        "AuthCrypt should be encrypted"
    );
    assert!(
        !authcrypt_unpack_metadata.anonymous_sender,
        "AuthCrypt sender should not be anonymous"
    );

    println!("✅ PQC AuthCrypt messaging works");

    // Test 4: AnonCrypt (anonymous encryption)
    println!("--- Test 4: AnonCrypt ---");
    let anoncrypt_msg = Message::build(
        "comprehensive-anoncrypt".to_string(),
        "https://example.com/protocols/test/1.0/anoncrypt".to_string(),
        json!({"test": "PQC AnonCrypt messaging", "mode": "anonymous"}),
    )
    .to(bob_did.clone())
    .finalize(); // No from field - anonymous

    let (anoncrypt_packed, anoncrypt_pack_metadata) = anoncrypt_msg
        .pack_encrypted(
            &bob_did,
            None, // No from - anonymous
            None, // No signing
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack AnonCrypt message");

    assert!(
        anoncrypt_pack_metadata.from_kid.is_none(),
        "AnonCrypt should not have from_kid"
    );

    let (anoncrypt_unpacked, anoncrypt_unpack_metadata) = Message::unpack(
        &anoncrypt_packed,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack AnonCrypt message");

    assert_eq!(anoncrypt_msg.body, anoncrypt_unpacked.body);
    assert!(
        !anoncrypt_unpack_metadata.authenticated,
        "AnonCrypt should not be authenticated"
    );
    assert!(
        anoncrypt_unpack_metadata.encrypted,
        "AnonCrypt should be encrypted"
    );
    assert!(
        anoncrypt_unpack_metadata.anonymous_sender,
        "AnonCrypt sender should be anonymous"
    );

    println!("✅ PQC AnonCrypt messaging works");

    // Test 5: Signed + Encrypted (non-repudiable)
    println!("--- Test 5: Signed + Encrypted ---");
    let signed_encrypted_msg = Message::build(
        "comprehensive-signed-encrypted".to_string(),
        "https://example.com/protocols/test/1.0/signed-encrypted".to_string(),
        json!({"test": "PQC Signed+Encrypted messaging", "mode": "non-repudiable"}),
    )
    .to(bob_did.clone())
    .from(alice_did.clone())
    .finalize();

    let (signed_encrypted_packed, signed_encrypted_pack_metadata) = signed_encrypted_msg
        .pack_encrypted(
            &bob_did,
            Some(&alice_did), // AuthCrypt
            Some(&alice_did), // Additional signing for non-repudiation
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack signed+encrypted message");

    assert!(
        signed_encrypted_pack_metadata.from_kid.is_some(),
        "Should have from_kid"
    );
    assert!(
        signed_encrypted_pack_metadata.sign_by_kid.is_some(),
        "Should have sign_by_kid"
    );

    let (signed_encrypted_unpacked, signed_encrypted_unpack_metadata) = Message::unpack(
        &signed_encrypted_packed,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack signed+encrypted message");

    assert_eq!(signed_encrypted_msg.body, signed_encrypted_unpacked.body);
    assert!(
        signed_encrypted_unpack_metadata.authenticated,
        "Should be authenticated"
    );
    assert!(
        signed_encrypted_unpack_metadata.encrypted,
        "Should be encrypted"
    );
    assert!(
        signed_encrypted_unpack_metadata.non_repudiation,
        "Should be non-repudiable"
    );
    assert!(
        !signed_encrypted_unpack_metadata.anonymous_sender,
        "Sender should not be anonymous"
    );

    println!("✅ PQC Signed+Encrypted messaging works");

    // Test 6: Large message handling
    println!("--- Test 6: Large Message ---");
    let large_data = "x".repeat(10000); // 10KB message
    let large_msg = Message::build(
        "comprehensive-large".to_string(),
        "https://example.com/protocols/test/1.0/large".to_string(),
        json!({"test": "Large PQC message", "data": large_data, "size": 10000}),
    )
    .to(bob_did.clone())
    .from(alice_did.clone())
    .finalize();

    let (large_packed, _) = large_msg
        .pack_encrypted(
            &bob_did,
            Some(&alice_did),
            None,
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack large message");

    let (large_unpacked, large_metadata) = Message::unpack(
        &large_packed,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack large message");

    assert_eq!(large_msg.body, large_unpacked.body);
    assert!(
        large_metadata.encrypted,
        "Large message should be encrypted"
    );

    println!("✅ PQC large message handling works");

    println!("✅ All PQC comprehensive e2e tests passed!");
    println!("=================== PQC COMPREHENSIVE E2E TEST COMPLETE ===================");
}

#[tokio::test]
async fn test_pqc_algorithm_compatibility_e2e() {
    println!("=================== PQC ALGORITHM COMPATIBILITY E2E ===================");

    // Test both ML-KEM-768 and ML-KEM-1024 compatibility
    let vectors_768 =
        PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create ML-KEM-768 vectors");
    let vectors_1024 =
        PQCTestVector::ml_kem_1024_ml_dsa_87().expect("Failed to create ML-KEM-1024 vectors");

    let mut did_resolver = PQCTestDIDResolver::new();

    // Add both test vectors to resolver
    did_resolver.add_did_doc(
        vectors_768.alice_did.clone(),
        vectors_768.alice_did_doc.clone(),
    );
    did_resolver.add_did_doc(vectors_768.bob_did.clone(), vectors_768.bob_did_doc.clone());
    did_resolver.add_did_doc(
        vectors_1024.alice_did.clone(),
        vectors_1024.alice_did_doc.clone(),
    );
    did_resolver.add_did_doc(
        vectors_1024.bob_did.clone(),
        vectors_1024.bob_did_doc.clone(),
    );

    let alice_768_secrets = PQCTestSecretsResolver::new(vectors_768.alice_secrets);
    let bob_768_secrets = PQCTestSecretsResolver::new(vectors_768.bob_secrets);
    let alice_1024_secrets = PQCTestSecretsResolver::new(vectors_1024.alice_secrets);
    let bob_1024_secrets = PQCTestSecretsResolver::new(vectors_1024.bob_secrets);

    // Test 1: ML-KEM-768 Alice to ML-KEM-768 Bob (should work)
    println!("--- Test 1: ML-KEM-768 to ML-KEM-768 ---");
    let msg_768 = Message::build(
        "test-768-768".to_string(),
        "https://example.com/protocols/test/1.0/768".to_string(),
        json!({"test": "ML-KEM-768 to ML-KEM-768"}),
    )
    .to(vectors_768.bob_did.clone())
    .from(vectors_768.alice_did.clone())
    .finalize();

    let (packed_768, _) = msg_768
        .pack_encrypted(
            &vectors_768.bob_did,
            Some(&vectors_768.alice_did),
            None,
            &did_resolver,
            &alice_768_secrets,
            &PackEncryptedOptions::default(), // ML-KEM-768
        )
        .await
        .expect("ML-KEM-768 should work");

    let (unpacked_768, metadata_768) = Message::unpack(
        &packed_768,
        &did_resolver,
        &bob_768_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Should unpack ML-KEM-768");

    assert_eq!(msg_768.body, unpacked_768.body);
    assert!(metadata_768.encrypted);
    println!("✅ ML-KEM-768 to ML-KEM-768 works");

    // Test 2: ML-KEM-1024 Alice to ML-KEM-1024 Bob (should work)
    println!("--- Test 2: ML-KEM-1024 to ML-KEM-1024 ---");
    let msg_1024 = Message::build(
        "test-1024-1024".to_string(),
        "https://example.com/protocols/test/1.0/1024".to_string(),
        json!({"test": "ML-KEM-1024 to ML-KEM-1024"}),
    )
    .to(vectors_1024.bob_did.clone())
    .from(vectors_1024.alice_did.clone())
    .finalize();

    let mut options_1024 = PackEncryptedOptions::default();
    options_1024.enc_alg_auth = AuthCryptAlg::MlKem1024A256cbcHs512;

    let (packed_1024, _) = msg_1024
        .pack_encrypted(
            &vectors_1024.bob_did,
            Some(&vectors_1024.alice_did),
            None,
            &did_resolver,
            &alice_1024_secrets,
            &options_1024, // ML-KEM-1024
        )
        .await
        .expect("ML-KEM-1024 should work");

    let (unpacked_1024, metadata_1024) = Message::unpack(
        &packed_1024,
        &did_resolver,
        &bob_1024_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Should unpack ML-KEM-1024");

    assert_eq!(msg_1024.body, unpacked_1024.body);
    assert!(metadata_1024.encrypted);
    println!("✅ ML-KEM-1024 to ML-KEM-1024 works");

    // Test 3: ML-KEM-768 to ML-KEM-1024 (should fail due to incompatibility)
    println!("--- Test 3: ML-KEM-768 to ML-KEM-1024 (incompatible) ---");
    let incompatible_msg = Message::build(
        "test-768-1024-incompatible".to_string(),
        "https://example.com/protocols/test/1.0/incompatible".to_string(),
        json!({"test": "Incompatible algorithms"}),
    )
    .to(vectors_1024.bob_did.clone()) // Bob has ML-KEM-1024
    .from(vectors_768.alice_did.clone()) // Alice has ML-KEM-768
    .finalize();

    // This should fail because Alice has ML-KEM-768 but Bob has ML-KEM-1024
    let result = incompatible_msg
        .pack_encrypted(
            &vectors_1024.bob_did,        // Bob with ML-KEM-1024
            Some(&vectors_768.alice_did), // Alice with ML-KEM-768
            None,
            &did_resolver,
            &alice_768_secrets,
            &PackEncryptedOptions::default(), // Uses ML-KEM-768
        )
        .await;

    // Verify that incompatible algorithms are properly detected
    assert!(
        result.is_err(),
        "Should fail due to algorithm incompatibility"
    );
    println!("✅ Algorithm incompatibility correctly detected");

    println!("✅ All PQC algorithm compatibility tests passed!");
    println!("=================== PQC ALGORITHM COMPATIBILITY E2E COMPLETE ===================");
}

#[tokio::test]
async fn test_pqc_bidirectional_messaging_e2e() {
    println!("=================== PQC BIDIRECTIONAL MESSAGING E2E ===================");

    // Test Alice -> Bob and Bob -> Alice in the same test
    let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Test vectors");

    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
    did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());
    let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets.clone());

    // Test 1: Alice sends to Bob
    println!("--- Alice -> Bob ---");
    let alice_to_bob = Message::build(
        "alice-to-bob".to_string(),
        "https://example.com/protocols/chat/1.0/message".to_string(),
        json!({"from": "Alice", "message": "Hello Bob! This is a PQC secured message."}),
    )
    .to(vectors.bob_did.clone())
    .from(vectors.alice_did.clone())
    .finalize();

    let (packed_alice_to_bob, _) = alice_to_bob
        .pack_encrypted(
            &vectors.bob_did,
            Some(&vectors.alice_did),
            Some(&vectors.alice_did), // Sign + encrypt
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Alice should be able to send to Bob");

    let (unpacked_alice_to_bob, metadata_alice_to_bob) = Message::unpack(
        &packed_alice_to_bob,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Bob should be able to unpack Alice's message");

    assert_eq!(alice_to_bob.body, unpacked_alice_to_bob.body);
    assert!(metadata_alice_to_bob.authenticated);
    assert!(metadata_alice_to_bob.encrypted);
    assert!(metadata_alice_to_bob.non_repudiation);
    println!("✅ Alice -> Bob works");

    // Test 2: Bob responds to Alice
    println!("--- Bob -> Alice ---");
    let bob_to_alice = Message::build(
        "bob-to-alice".to_string(),
        "https://example.com/protocols/chat/1.0/message".to_string(),
        json!({"from": "Bob", "message": "Hi Alice! I received your PQC message securely.", "in_reply_to": "alice-to-bob"})
    )
    .to(vectors.alice_did.clone())
    .from(vectors.bob_did.clone())
    .finalize();

    let (packed_bob_to_alice, _) = bob_to_alice
        .pack_encrypted(
            &vectors.alice_did,
            Some(&vectors.bob_did),
            Some(&vectors.bob_did), // Sign + encrypt
            &did_resolver,
            &bob_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Bob should be able to send to Alice");

    let (unpacked_bob_to_alice, metadata_bob_to_alice) = Message::unpack(
        &packed_bob_to_alice,
        &did_resolver,
        &alice_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Alice should be able to unpack Bob's message");

    assert_eq!(bob_to_alice.body, unpacked_bob_to_alice.body);
    assert!(metadata_bob_to_alice.authenticated);
    assert!(metadata_bob_to_alice.encrypted);
    assert!(metadata_bob_to_alice.non_repudiation);
    println!("✅ Bob -> Alice works");

    // Verify conversation flow
    let alice_message = unpacked_alice_to_bob.body.as_object().unwrap();
    let bob_message = unpacked_bob_to_alice.body.as_object().unwrap();

    assert_eq!(alice_message["from"], "Alice");
    assert_eq!(bob_message["from"], "Bob");
    assert_eq!(bob_message["in_reply_to"], "alice-to-bob");

    println!("✅ All PQC bidirectional messaging tests passed!");
    println!("=================== PQC BIDIRECTIONAL E2E TEST COMPLETE ===================");
}
