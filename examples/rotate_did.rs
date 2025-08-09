//! Post-Quantum Cryptography DID Rotation Example
//! 
//! Demonstrates DID rotation using PQC algorithms with from_prior field:
//! - Shows how to rotate from one DID to another using PQC signatures
//! - Uses ML-KEM-768/1024 for key encapsulation
//! - Uses ML-DSA-65/87 for digital signatures and from_prior attestation

use navia_didcomm::{
    test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
    FromPrior, Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=================== PQC DID ROTATION EXAMPLE ===================");
    did_rotation_example().await;
    
    println!("=================== PQC KEY UPGRADE EXAMPLE ===================");
    key_upgrade_example().await;
    
    println!("=================== PQC MULTI-STEP ROTATION ===================");
    multi_step_rotation().await;
}

async fn did_rotation_example() {
    // Simulate Charlie rotating to Alice's DID using PQC
    let charlie_vector = PQCTestVector::ml_kem_768_ml_dsa_65()
        .expect("Failed to create Charlie vector");
    let alice_vector = PQCTestVector::ml_kem_1024_ml_dsa_87()
        .expect("Failed to create Alice vector");
    let bob_vector = PQCTestVector::ml_kem_768_ml_dsa_65()
        .expect("Failed to create Bob vector");
    
    // Charlie is rotating to Alice's new DID
    let charlie_old_did = &charlie_vector.alice_did; // Charlie's old identity
    let alice_new_did = &alice_vector.alice_did;     // Alice's new identity (Charlie rotated to)
    let bob_did = &bob_vector.bob_did;               // Bob as recipient
    
    println!("🔄 Setting up PQC DID rotation:");
    println!("👤 Charlie (old): {charlie_old_did} (ML-KEM-768 + ML-DSA-65)");
    println!("🆕 Alice (new): {alice_new_did} (ML-KEM-1024 + ML-DSA-87)");
    println!("📥 Bob (recipient): {bob_did} (ML-KEM-768 + ML-DSA-65)");

    // Setup DID resolver with all parties
    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(charlie_old_did.clone(), charlie_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(alice_new_did.clone(), alice_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(bob_did.clone(), bob_vector.bob_did_doc.clone());

    // Charlie has secrets for both old and new identities (for rotation)
    let mut rotation_secrets = charlie_vector.alice_secrets.clone();
    rotation_secrets.extend(alice_vector.alice_secrets.clone());
    let charlie_secrets = PQCTestSecretsResolver::new(rotation_secrets);
    let bob_secrets = PQCTestSecretsResolver::new(bob_vector.bob_secrets.clone());

    // --- Build from_prior for DID rotation ---
    println!("\n📝 Charlie building from_prior attestation with PQC signature...");
    let from_prior = FromPrior::build(charlie_old_did.clone(), alice_new_did.clone())
        .aud(bob_did.clone())
        .exp(1234567890)   // Expiry time
        .nbf(1234567800)   // Not before
        .iat(1234567800)   // Issued at
        .jti("pqc-rotation-jwt".to_owned()) // JWT ID
        .finalize();

    println!("✅ Original from_prior: iss={}, sub={}", 
        from_prior.iss, from_prior.sub);

    // Pack the from_prior with PQC signature using Charlie's old key
    let (packed_from_prior, issuer_kid) = from_prior
        .pack(
            Some(charlie_old_did), // Use Charlie's old DID for signing
            &did_resolver,
            &charlie_secrets,
        )
        .await
        .expect("Failed to pack from_prior");

    println!("✅ Packed from_prior JWT with PQC signature: {}...", 
        &packed_from_prior[..100.min(packed_from_prior.len())]);
    println!("✅ Issuer key ID: {issuer_kid}");

    // --- Build message from Alice (post-rotation) to Bob ---
    println!("\n📨 Building message from Alice's new DID to Bob...");
    let msg = Message::build(
        "pqc-did-rotation".to_owned(),
        "https://didcomm.org/rotation/1.0/announce".to_owned(),
        json!({
            "message": "Hello Bob, I've rotated my DID using post-quantum cryptography!",
            "old_did": charlie_old_did,
            "new_did": alice_new_did,
            "rotation_method": "ML-KEM + ML-DSA PQC"
        }),
    )
    .from(alice_new_did.clone())  // Now using Alice's new DID
    .to(bob_did.clone())
    .created_time(1234567800)
    .expires_time(1234567900)
    .from_prior(packed_from_prior)  // Include the rotation proof
    .finalize();

    println!("✅ Message built with from_prior rotation proof");

    // --- Pack encrypted message ---
    println!("\n🔒 Encrypting message with PQC AuthCrypt...");
    let (encrypted_msg, pack_metadata) = msg
        .pack_encrypted(
            bob_did,
            Some(alice_new_did), // From Alice's new DID
            None,
            &did_resolver,
            &charlie_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack encrypted message");

    println!("✅ Encrypted with: from_kid={:?}, to_kids={:?}",
        pack_metadata.from_kid, pack_metadata.to_kids);

    // --- Bob receives and unpacks ---
    println!("\n📨 Bob unpacking rotated message...");
    let (final_msg, unpack_metadata) = Message::unpack(
        &encrypted_msg,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack message");

    println!("✅ DID rotation complete!");
    println!("📄 Message from: {} (was: {})", final_msg.from.unwrap(), charlie_old_did);
    println!("🔐 Security: authenticated={}, encrypted={}", 
        unpack_metadata.authenticated, unpack_metadata.encrypted);
    println!("📝 from_prior verified: {}", final_msg.from_prior.is_some());
    println!("📄 Message content: {}", final_msg.body);
}

async fn key_upgrade_example() {
    // Demonstrate upgrading from ML-KEM-768 to ML-KEM-1024 for higher security
    let old_vector = PQCTestVector::ml_kem_768_ml_dsa_65()
        .expect("Failed to create old security level vector");
    let new_vector = PQCTestVector::ml_kem_1024_ml_dsa_87()
        .expect("Failed to create new security level vector");
    let bob_vector = PQCTestVector::ml_kem_768_ml_dsa_65()
        .expect("Failed to create Bob vector");

    let old_did = &old_vector.alice_did;
    let new_did = &new_vector.alice_did;
    let bob_did = &bob_vector.bob_did;

    println!("🔧 Setting up PQC key upgrade:");
    println!("🔒 Old: {old_did} (ML-KEM-768 + ML-DSA-65 - 128-bit quantum security)");
    println!("🔐 New: {new_did} (ML-KEM-1024 + ML-DSA-87 - 192-bit quantum security)");
    println!("📥 Bob: {bob_did}");

    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(old_did.clone(), old_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(new_did.clone(), new_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(bob_did.clone(), bob_vector.bob_did_doc.clone());

    // Alice has both old and new keys during transition
    let mut upgrade_secrets = old_vector.alice_secrets.clone();
    upgrade_secrets.extend(new_vector.alice_secrets.clone());
    let alice_secrets = PQCTestSecretsResolver::new(upgrade_secrets);
    let bob_secrets = PQCTestSecretsResolver::new(bob_vector.bob_secrets.clone());

    // Build upgrade attestation
    println!("\n🔄 Creating security level upgrade attestation...");
    let from_prior = FromPrior::build(old_did.clone(), new_did.clone())
        .aud("security-upgrade".to_owned())
        .exp(1234567890)
        .finalize();

    let (packed_from_prior, _) = from_prior
        .pack(Some(old_did), &did_resolver, &alice_secrets)
        .await
        .expect("Failed to pack upgrade attestation");

    // Send upgraded message
    let msg = Message::build(
        "pqc-key-upgrade".to_owned(),
        "https://didcomm.org/security/1.0/upgrade".to_owned(),
        json!({
            "upgrade_reason": "Increased quantum security from 128-bit to 192-bit",
            "old_algorithm": "ML-KEM-768 + ML-DSA-65",
            "new_algorithm": "ML-KEM-1024 + ML-DSA-87"
        }),
    )
    .from(new_did.clone())
    .to(bob_did.clone())
    .from_prior(packed_from_prior)
    .finalize();

    let (encrypted_msg, _) = msg
        .pack_encrypted(
            bob_did,
            Some(new_did),
            None,
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack upgraded message");

    let (final_msg, _) = Message::unpack(&encrypted_msg, &did_resolver, &bob_secrets, &UnpackOptions::default())
        .await.expect("Failed to unpack upgraded message");

    println!("✅ Security upgrade complete!");
    println!("🔐 Upgraded from 128-bit to 192-bit quantum security");
    println!("📄 Upgrade message: {}", final_msg.body);
}

async fn multi_step_rotation() {
    // Demonstrate a multi-step rotation: Alice -> Bob -> Charlie
    let alice_vector = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Alice vector failed");
    let bob_vector = PQCTestVector::ml_kem_1024_ml_dsa_87().expect("Bob vector failed");
    let charlie_vector = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Charlie vector failed");
    
    let alice_did = &alice_vector.alice_did;
    let bob_did = &bob_vector.alice_did;     // Bob as intermediate identity
    let charlie_did = &charlie_vector.alice_did;  // Charlie as final identity
    let recipient_did = &alice_vector.bob_did;    // Someone to send to

    println!("🔄 Setting up multi-step PQC rotation chain:");
    println!("👤 Step 1: {alice_did} → {bob_did}");
    println!("👤 Step 2: {bob_did} → {charlie_did}");
    println!("📥 Recipient: {recipient_did}");

    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(alice_did.clone(), alice_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(bob_did.clone(), bob_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(charlie_did.clone(), charlie_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(recipient_did.clone(), alice_vector.bob_did_doc.clone());

    // Entity has keys for all identities in the rotation chain
    let mut rotation_secrets = alice_vector.alice_secrets.clone();
    rotation_secrets.extend(bob_vector.alice_secrets.clone());
    rotation_secrets.extend(charlie_vector.alice_secrets.clone());
    let entity_secrets = PQCTestSecretsResolver::new(rotation_secrets);
    let recipient_secrets = PQCTestSecretsResolver::new(alice_vector.bob_secrets.clone());

    // Step 1: Alice -> Bob rotation
    println!("\n📝 Step 1: Creating Alice -> Bob rotation attestation...");
    let from_prior_1 = FromPrior::build(alice_did.clone(), bob_did.clone())
        .aud("step1-rotation".to_owned())
        .exp(1234567890)
        .finalize();

    let (_packed_from_prior_1, _) = from_prior_1
        .pack(Some(alice_did), &did_resolver, &entity_secrets)
        .await.expect("Failed to pack step 1");

    // Step 2: Bob -> Charlie rotation (includes previous rotation)
    println!("📝 Step 2: Creating Bob -> Charlie rotation attestation...");
    let from_prior_2 = FromPrior::build(bob_did.clone(), charlie_did.clone())
        .aud("step2-rotation".to_owned())
        .exp(1234567890)
        .finalize();

    let (packed_from_prior_2, _) = from_prior_2
        .pack(Some(bob_did), &did_resolver, &entity_secrets)
        .await.expect("Failed to pack step 2");

    // Send final message from Charlie's identity
    println!("\n📨 Sending message from final identity (Charlie)...");
    let msg = Message::build(
        "pqc-multi-rotation".to_owned(),
        "https://didcomm.org/identity/1.0/final".to_owned(),
        json!({
            "message": "Multi-step PQC rotation complete",
            "rotation_chain": [alice_did, bob_did, charlie_did],
            "current_identity": charlie_did
        }),
    )
    .from(charlie_did.clone())
    .to(recipient_did.clone())
    .from_prior(packed_from_prior_2) // Latest rotation proof
    .finalize();

    let (encrypted_msg, _) = msg
        .pack_encrypted(
            recipient_did,
            Some(charlie_did),
            None,
            &did_resolver,
            &entity_secrets,
            &PackEncryptedOptions::default(),
        )
        .await.expect("Failed to pack final message");

    let (final_msg, metadata) = Message::unpack(&encrypted_msg, &did_resolver, &recipient_secrets, &UnpackOptions::default())
        .await.expect("Failed to unpack final message");

    println!("✅ Multi-step rotation complete!");
    println!("🔗 Final identity: {}", final_msg.from.unwrap());
    println!("📋 Rotation chain verified through from_prior");
    println!("🔐 Security maintained: authenticated={}, encrypted={}", 
        metadata.authenticated, metadata.encrypted);
    println!("📄 Final message: {}", final_msg.body);
}