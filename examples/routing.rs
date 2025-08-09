//! Post-Quantum Cryptography Routing Example
//! 
//! Demonstrates DIDComm message routing through mediators using PQC algorithms:
//! - ML-KEM-768/1024 for key encapsulation
//! - ML-DSA-65/87 for digital signatures

use navia_didcomm::{
    algorithms::AnonCryptAlg,
    protocols::routing::{try_parse_forward, wrap_in_forward},
    test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=================== PQC SINGLE MEDIATOR ===================");
    single_mediator().await;

    println!("=================== PQC MESSAGE RELAY CHAIN ===================");
    message_relay_chain().await;
    
    println!("=================== PQC MULTI-HOP ROUTING ===================");
    multi_hop_routing().await;
}

async fn single_mediator() {
    // Create PQC test vector with Alice and Bob using ML-KEM-768 + ML-DSA-65
    let alice_bob_vector = PQCTestVector::ml_kem_768_ml_dsa_65()
        .expect("Failed to create Alice/Bob test vector");
    
    // Create a mediator using ML-KEM-1024 + ML-DSA-87 for higher security
    let mediator_vector = PQCTestVector::ml_kem_1024_ml_dsa_87()
        .expect("Failed to create mediator test vector");
    
    // Use Alice from first vector and mediator from second vector
    let mediator_did = mediator_vector.alice_did.clone();
    let mediator_did_doc = mediator_vector.alice_did_doc.clone();
    let mediator_secrets = mediator_vector.alice_secrets.clone();

    println!("🔐 Setting up PQC routing with ML-KEM and ML-DSA");
    println!("📤 Alice: {} (ML-KEM-768 + ML-DSA-65)", alice_bob_vector.alice_did);
    println!("📥 Bob: {} (ML-KEM-768 + ML-DSA-65)", alice_bob_vector.bob_did);
    println!("🔀 Mediator: {mediator_did} (ML-KEM-1024 + ML-DSA-87)");

    // --- Building message from Alice to Bob ---
    let msg = Message::build(
        "pqc-routing-1".to_owned(),
        "https://didcomm.org/routing/2.0/forward".to_owned(),
        json!({"content": "Post-quantum secure routing test!"}),
    )
    .to(alice_bob_vector.bob_did.clone())
    .from(alice_bob_vector.alice_did.clone())
    .finalize();

    // --- Setup resolvers ---
    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(alice_bob_vector.alice_did.clone(), alice_bob_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(alice_bob_vector.bob_did.clone(), alice_bob_vector.bob_did_doc.clone());
    did_resolver.add_did_doc(mediator_did.clone(), mediator_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(alice_bob_vector.alice_secrets.clone());
    let mediator_secrets_resolver = PQCTestSecretsResolver::new(mediator_secrets.clone());
    let bob_secrets = PQCTestSecretsResolver::new(alice_bob_vector.bob_secrets.clone());

    // --- Pack message for routing through mediator ---
    println!("\n📦 Alice packing message with PQC AuthCrypt...");
    let (packed_msg, pack_metadata) = msg
        .pack_encrypted(
            &alice_bob_vector.bob_did,
            Some(&alice_bob_vector.alice_did),
            None,
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack encrypted message");

    println!("✅ Pack metadata: authenticated={}, encrypted={}",
        pack_metadata.from_kid.is_some(), 
        !pack_metadata.to_kids.is_empty());

    // --- Alice sends to mediator ---
    println!("\n📡 Alice sending to mediator: {}...", &packed_msg[..100.min(packed_msg.len())]);

    // --- Mediator unpacks and forwards ---
    println!("\n🔀 Mediator unpacking message...");
    let (forwarded_msg, unpack_metadata) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &mediator_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack at mediator");

    println!("✅ Mediator unpack: authenticated={}, encrypted={}", 
        unpack_metadata.authenticated, unpack_metadata.encrypted);

    // --- Parse and forward the message ---
    let forward_info = try_parse_forward(&forwarded_msg)
        .expect("Failed to parse forward message");
    let forwarded_payload = serde_json::to_string(&forward_info.forwarded_msg)
        .expect("Failed to serialize forwarded message");

    println!("🔄 Mediator forwarding to Bob: {}...", &forwarded_payload[..100.min(forwarded_payload.len())]);

    // --- Bob receives and unpacks ---
    println!("\n📨 Bob unpacking final message...");
    let (final_msg, final_metadata) = Message::unpack(
        &forwarded_payload,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack final message");

    println!("✅ Bob received message: id={}, type={}", final_msg.id, final_msg.type_);
    println!("✅ Final metadata: authenticated={}, encrypted={}, sender={:?}", 
        final_metadata.authenticated, 
        final_metadata.encrypted,
        final_metadata.encrypted_from_kid);
    println!("📄 Message body: {}", final_msg.body);
}

async fn message_relay_chain() {
    // Demonstrate relay chain with multiple participants using different PQC security levels
    let vector1 = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create vector1");
    let vector2 = PQCTestVector::ml_kem_1024_ml_dsa_87().expect("Failed to create vector2");
    
    // Alice -> Mediator1 -> Mediator2 -> Bob
    let alice_did = &vector1.alice_did;
    let alice_secrets = &vector1.alice_secrets;
    let bob_did = &vector1.bob_did;
    let bob_secrets = &vector1.bob_secrets;
    
    let mediator1_did = &vector2.alice_did;  // Use alice from vector2 as mediator1
    let mediator1_secrets = &vector2.alice_secrets;
    let mediator2_did = &vector2.bob_did;    // Use bob from vector2 as mediator2
    let mediator2_secrets = &vector2.bob_secrets;

    println!("🔗 Setting up PQC relay chain:");
    println!("📤 Alice: {alice_did} → 🔀 Mediator1: {mediator1_did} → 🔀 Mediator2: {mediator2_did} → 📥 Bob: {bob_did}");

    // Setup DID resolver with all parties
    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(alice_did.clone(), vector1.alice_did_doc.clone());
    did_resolver.add_did_doc(bob_did.clone(), vector1.bob_did_doc.clone());
    did_resolver.add_did_doc(mediator1_did.clone(), vector2.alice_did_doc.clone());
    did_resolver.add_did_doc(mediator2_did.clone(), vector2.bob_did_doc.clone());

    let alice_resolver = PQCTestSecretsResolver::new(alice_secrets.clone());
    let mediator1_resolver = PQCTestSecretsResolver::new(mediator1_secrets.clone());
    let mediator2_resolver = PQCTestSecretsResolver::new(mediator2_secrets.clone());
    let bob_resolver = PQCTestSecretsResolver::new(bob_secrets.clone());

    // --- Build message ---
    let msg = Message::build(
        "pqc-relay-chain".to_owned(),
        "https://didcomm.org/basicmessage/2.0/message".to_owned(),
        json!({"text": "PQC relay chain message with ML-KEM + ML-DSA"}),
    )
    .to(bob_did.clone())
    .from(alice_did.clone())
    .finalize();

    // --- Pack for the chain ---
    println!("\n📦 Alice packing message for relay chain...");
    let (packed_msg, _) = msg
        .pack_encrypted(
            bob_did,
            Some(alice_did),
            None,
            &did_resolver,
            &alice_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack message");

    // --- Step 1: Mediator1 processes ---
    println!("\n🔀 Mediator1 processing message...");
    let (msg1, _) = Message::unpack(&packed_msg, &did_resolver, &mediator1_resolver, &UnpackOptions::default())
        .await.expect("Mediator1 unpack failed");
    
    let forward1 = try_parse_forward(&msg1).expect("Failed to parse forward at mediator1");
    let relay_msg = serde_json::to_string(&forward1.forwarded_msg).expect("Failed to serialize");
    
    // --- Step 2: Mediator2 processes ---
    println!("🔀 Mediator2 processing message...");
    let (msg2, _) = Message::unpack(&relay_msg, &did_resolver, &mediator2_resolver, &UnpackOptions::default())
        .await.expect("Mediator2 unpack failed");
        
    let forward2 = try_parse_forward(&msg2).expect("Failed to parse forward at mediator2");
    let final_relay_msg = serde_json::to_string(&forward2.forwarded_msg).expect("Failed to serialize");

    // --- Step 3: Bob receives final message ---
    println!("📨 Bob receiving final message...");
    let (final_msg, final_metadata) = Message::unpack(&final_relay_msg, &did_resolver, &bob_resolver, &UnpackOptions::default())
        .await.expect("Bob unpack failed");

    println!("✅ Relay chain complete!");
    println!("📄 Final message: {}", final_msg.body);
    println!("🔐 Security: authenticated={}, encrypted={}", 
        final_metadata.authenticated, final_metadata.encrypted);
}

async fn multi_hop_routing() {
    // Demonstrate re-wrapping for unknown intermediate mediators
    let alice_bob_vector = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create AB vector");
    let mediator_vector = PQCTestVector::ml_kem_1024_ml_dsa_87().expect("Failed to create mediator vector");
    
    let alice_did = &alice_bob_vector.alice_did;
    let bob_did = &alice_bob_vector.bob_did;
    let mediator_did = &mediator_vector.alice_did;
    
    println!("🌐 Setting up PQC multi-hop routing with re-wrapping:");
    println!("📤 Alice → 🔀 Mediator → 📥 Bob (with unknown intermediate hops)");

    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(alice_did.clone(), alice_bob_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(bob_did.clone(), alice_bob_vector.bob_did_doc.clone());
    did_resolver.add_did_doc(mediator_did.clone(), mediator_vector.alice_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(alice_bob_vector.alice_secrets.clone());
    let mediator_secrets = PQCTestSecretsResolver::new(mediator_vector.alice_secrets.clone());
    let bob_secrets = PQCTestSecretsResolver::new(alice_bob_vector.bob_secrets.clone());

    // --- Build message ---
    let msg = Message::build(
        "pqc-multi-hop".to_owned(),
        "https://didcomm.org/basicmessage/2.0/message".to_owned(),
        json!({"text": "Multi-hop PQC routing with re-wrapping"}),
    )
    .to(bob_did.clone())
    .from(alice_did.clone())
    .finalize();

    // --- Pack message ---
    println!("\n📦 Alice packing message for multi-hop routing...");
    let (packed_msg, _) = msg
        .pack_encrypted(
            bob_did,
            Some(alice_did),
            None,
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Failed to pack message");

    // --- Mediator unpacks and re-wraps ---
    println!("\n🔀 Mediator processing and re-wrapping message...");
    let (mediator_msg, _) = Message::unpack(&packed_msg, &did_resolver, &mediator_secrets, &UnpackOptions::default())
        .await.expect("Mediator unpack failed");
    
    let forward_info = try_parse_forward(&mediator_msg).expect("Failed to parse forward");
    let inner_msg = serde_json::to_string(&forward_info.forwarded_msg).expect("Failed to serialize");
    
    // Get Bob's key agreement key for re-wrapping
    let bob_key_id = format!("{bob_did}#key-agreement-1");
    
    // Re-wrap for final recipient using AnonCrypt (anonymous encryption)
    let rewrapped_msg = wrap_in_forward(
        &inner_msg,
        None, // Anonymous sender
        &forward_info.next,
        &[bob_key_id],
        &AnonCryptAlg::default(),
        &did_resolver,
    )
    .await
    .expect("Failed to re-wrap message");

    println!("🔄 Message re-wrapped for final recipient");

    // --- Bob receives final message ---
    println!("\n📨 Bob unpacking re-wrapped message...");
    let (final_msg, final_metadata) = Message::unpack(&rewrapped_msg, &did_resolver, &bob_secrets, &UnpackOptions::default())
        .await.expect("Bob unpack failed");

    println!("✅ Multi-hop routing complete!");
    println!("📄 Final message: {}", final_msg.body);
    println!("🔐 Security: authenticated={}, encrypted={}, anonymous={}", 
        final_metadata.authenticated, 
        final_metadata.encrypted,
        final_metadata.anonymous_sender);
}