// PQC-only integration tests with real test vectors
use navia_didcomm::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;

#[tokio::test]
async fn test_pqc_message_round_trip() {
    println!("=================== PQC INTEGRATION ROUND TRIP TEST ===================");

    // Use real PQC test vectors instead of placeholder keys
    let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create PQC test vectors");

    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
    did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());
    let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets.clone());

    println!("✅ Set up real PQC test vectors for Alice and Bob");

    // Test 1: Anonymous encryption (AnonCrypt)
    println!("--- Test 1: AnonCrypt (ML-KEM only) ---");
    let anon_msg = Message::build(
        "test-anon".to_string(),
        "https://example.com/protocols/test/1.0/anon".to_string(),
        json!({
            "content": "Hello PQC World with AnonCrypt!",
            "timestamp": "2024-01-01T00:00:00Z",
            "mode": "anonymous"
        }),
    )
    .to(vectors.bob_did.clone())
    .finalize(); // No from field - anonymous

    let anon_options = PackEncryptedOptions {
        enc_alg_anon: AnonCryptAlg::MlKem768Xc20p,
        enc_alg_auth: AuthCryptAlg::MlKem768A256cbcHs512,
        protect_sender: false,
        forward: false,
        forward_headers: None,
        messaging_service: None,
    };

    let (anon_encrypted, anon_pack_meta) = anon_msg
        .pack_encrypted(
            &vectors.bob_did,
            None, // Anonymous - no sender specified
            None, // No signature
            &did_resolver,
            &alice_secrets,
            &anon_options,
        )
        .await
        .expect("Failed to pack anonymous encrypted message");

    assert!(
        anon_pack_meta.from_kid.is_none(),
        "AnonCrypt should have no from_kid"
    );
    println!("✅ AnonCrypt packed: {} bytes", anon_encrypted.len());

    let (anon_decrypted, anon_unpack_meta) = Message::unpack(
        &anon_encrypted,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack anonymous message");

    assert_eq!(
        anon_decrypted.body["content"],
        "Hello PQC World with AnonCrypt!"
    );
    assert!(
        !anon_unpack_meta.authenticated,
        "AnonCrypt should not be authenticated"
    );
    assert!(anon_unpack_meta.encrypted, "Should be encrypted");
    assert!(anon_unpack_meta.anonymous_sender, "Should be anonymous");

    println!("✅ AnonCrypt unpacked successfully");

    // Test 2: Authenticated encryption (AuthCrypt)
    println!("--- Test 2: AuthCrypt (ML-KEM + ML-DSA) ---");
    let auth_msg = Message::build(
        "test-auth".to_string(),
        "https://example.com/protocols/test/1.0/auth".to_string(),
        json!({
            "content": "Hello PQC World with AuthCrypt!",
            "timestamp": "2024-01-01T00:00:00Z",
            "mode": "authenticated"
        }),
    )
    .to(vectors.bob_did.clone())
    .from(vectors.alice_did.clone())
    .finalize();

    let (auth_encrypted, auth_pack_meta) = auth_msg
        .pack_encrypted(
            &vectors.bob_did,
            Some(&vectors.alice_did), // Authenticated
            None,                     // No additional signature
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack authenticated encrypted message");

    assert!(
        auth_pack_meta.from_kid.is_some(),
        "AuthCrypt should have from_kid"
    );
    println!("✅ AuthCrypt packed: {} bytes", auth_encrypted.len());

    let (auth_decrypted, auth_unpack_meta) = Message::unpack(
        &auth_encrypted,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack authenticated message");

    assert_eq!(
        auth_decrypted.body["content"],
        "Hello PQC World with AuthCrypt!"
    );
    assert_eq!(auth_decrypted.from.as_ref().unwrap(), &vectors.alice_did);
    assert!(
        auth_unpack_meta.authenticated,
        "AuthCrypt should be authenticated"
    );
    assert!(auth_unpack_meta.encrypted, "Should be encrypted");
    assert!(
        !auth_unpack_meta.anonymous_sender,
        "Should not be anonymous"
    );

    println!("✅ AuthCrypt unpacked successfully");

    // Test 3: Signed + Encrypted (non-repudiation)
    println!("--- Test 3: Signed + Encrypted ---");
    let signed_msg = Message::build(
        "test-signed".to_string(),
        "https://example.com/protocols/test/1.0/signed".to_string(),
        json!({
            "content": "Hello PQC World with signature!",
            "timestamp": "2024-01-01T00:00:00Z",
            "mode": "non-repudiable"
        }),
    )
    .to(vectors.bob_did.clone())
    .from(vectors.alice_did.clone())
    .finalize();

    let (signed_encrypted, signed_pack_meta) = signed_msg
        .pack_encrypted(
            &vectors.bob_did,
            Some(&vectors.alice_did), // Authenticated
            Some(&vectors.alice_did), // Additional signature for non-repudiation
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack signed+encrypted message");

    assert!(signed_pack_meta.from_kid.is_some(), "Should have from_kid");
    assert!(
        signed_pack_meta.sign_by_kid.is_some(),
        "Should have sign_by_kid"
    );
    println!(
        "✅ Signed+Encrypted packed: {} bytes",
        signed_encrypted.len()
    );

    let (signed_decrypted, signed_unpack_meta) = Message::unpack(
        &signed_encrypted,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack signed+encrypted message");

    assert_eq!(
        signed_decrypted.body["content"],
        "Hello PQC World with signature!"
    );
    assert!(signed_unpack_meta.authenticated, "Should be authenticated");
    assert!(signed_unpack_meta.encrypted, "Should be encrypted");
    assert!(
        signed_unpack_meta.non_repudiation,
        "Should provide non-repudiation"
    );
    assert!(
        !signed_unpack_meta.anonymous_sender,
        "Should not be anonymous"
    );

    println!("✅ Signed+Encrypted unpacked successfully");

    println!("✅ All PQC integration tests passed with real test vectors!");
    println!("=================== PQC INTEGRATION TEST COMPLETE ===================");
}
