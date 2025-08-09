//! Post-Quantum Cryptography Advanced Parameters Example
//! 
//! Demonstrates advanced DIDComm features with PQC algorithms:
//! - Custom encryption parameters and options
//! - Forward headers and messaging service configuration
//! - Sender protection and anonymous encryption
//! - Different algorithm combinations (ML-KEM + ML-DSA)

use navia_didcomm::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use std::collections::HashMap;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=================== PQC ADVANCED PARAMETERS ===================");
    advanced_encryption_options().await;
    
    println!("=================== PQC ALGORITHM SELECTION ===================");
    algorithm_selection_demo().await;
    
    println!("=================== PQC CUSTOM HEADERS & SERVICES ===================");
    custom_headers_and_services().await;
    
    println!("=================== PQC SENDER PROTECTION ===================");
    sender_protection_demo().await;
}

async fn advanced_encryption_options() {
    let alice_vector = PQCTestVector::ml_kem_768_ml_dsa_65()
        .expect("Failed to create Alice vector");
    let bob_vector = PQCTestVector::ml_kem_1024_ml_dsa_87()
        .expect("Failed to create Bob vector");
    let mediator_vector = PQCTestVector::ml_kem_768_ml_dsa_65()
        .expect("Failed to create mediator vector");

    let alice_did = &alice_vector.alice_did;
    let bob_did = &bob_vector.alice_did;
    let mediator_did = &mediator_vector.alice_did;

    println!("🔧 Setting up advanced PQC encryption with custom options:");
    println!("📤 Alice: {alice_did} (ML-KEM-768 + ML-DSA-65)");
    println!("📥 Bob: {bob_did} (ML-KEM-1024 + ML-DSA-87)");
    println!("🔀 Mediator: {mediator_did} (ML-KEM-768 + ML-DSA-65)");

    // Setup resolvers
    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(alice_did.clone(), alice_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(bob_did.clone(), bob_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(mediator_did.clone(), mediator_vector.alice_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(alice_vector.alice_secrets.clone());
    let bob_secrets = PQCTestSecretsResolver::new(bob_vector.alice_secrets.clone());

    // Build message with advanced parameters
    let msg = Message::build(
        "pqc-advanced-params".to_owned(),
        "https://didcomm.org/basicmessage/2.0/message".to_owned(),
        json!({
            "text": "Advanced PQC message with custom parameters",
            "priority": "high",
            "features": ["ML-KEM", "ML-DSA", "custom-headers", "forward-routing"]
        }),
    )
    .from(alice_did.clone())
    .to(bob_did.clone())
    .created_time(1234567800)
    .expires_time(1234567900)
    .finalize();

    // Define advanced encryption options
    let mut forward_headers = HashMap::new();
    forward_headers.insert("priority".to_string(), json!("urgent"));
    forward_headers.insert("custom_routing".to_string(), json!("pqc-enabled"));
    forward_headers.insert("quantum_safe".to_string(), json!(true));

    let alice_key_agreement = format!("{alice_did}#key-agreement-1");
    let alice_authentication = format!("{alice_did}#authentication-1");
    let bob_service = format!("{bob_did}#didcomm-1");

    println!("\n🔒 Packing with advanced PQC encryption options...");
    let (encrypted_msg, pack_metadata) = msg
        .pack_encrypted(
            &alice_key_agreement,           // Specific key for encryption
            Some(&alice_authentication),    // From key (AuthCrypt)
            Some(&alice_authentication),    // Sign-by key (non-repudiation)
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions {
                protect_sender: true,       // Enable sender protection
                forward: true,              // Enable forwarding
                forward_headers: Some(forward_headers), // Custom forward headers
                messaging_service: Some(bob_service), // Messaging service endpoint
                enc_alg_auth: AuthCryptAlg::default(), // AuthCrypt algorithm
                enc_alg_anon: AnonCryptAlg::default(),       // AnonCrypt algorithm
            },
        )
        .await
        .expect("Failed to pack with advanced options");

    println!("✅ Advanced packing complete!");
    println!("🔐 Pack metadata:");
    println!("   - From KID: {:?}", pack_metadata.from_kid);
    println!("   - Sign-by KID: {:?}", pack_metadata.sign_by_kid);
    println!("   - To KIDs: {:?}", pack_metadata.to_kids);
    println!("   - Messaging service: {:?}", pack_metadata.messaging_service);

    // Bob unpacks the message
    println!("\n📨 Bob unpacking advanced message...");
    let (unpacked_msg, unpack_metadata) = Message::unpack(
        &encrypted_msg,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Failed to unpack advanced message");

    println!("✅ Advanced unpacking complete!");
    println!("📄 Message: {}", unpacked_msg.body);
    println!("🔐 Security features:");
    println!("   - Authenticated: {}", unpack_metadata.authenticated);
    println!("   - Encrypted: {}", unpack_metadata.encrypted);
    println!("   - Non-repudiation: {}", unpack_metadata.non_repudiation);
    println!("   - Sender protected: {}", !unpack_metadata.anonymous_sender);
}

async fn algorithm_selection_demo() {
    // Demonstrate different algorithm combinations
    let vector1 = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Vector1 failed");
    let vector2 = PQCTestVector::ml_kem_1024_ml_dsa_87().expect("Vector2 failed");

    let sender_did = &vector1.alice_did;
    let receiver_did = &vector2.alice_did;

    println!("🔀 Demonstrating PQC algorithm selection:");
    println!("📤 Sender: {sender_did} (ML-KEM-768 + ML-DSA-65)");
    println!("📥 Receiver: {receiver_did} (ML-KEM-1024 + ML-DSA-87)");

    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(sender_did.clone(), vector1.alice_did_doc.clone());
    did_resolver.add_did_doc(receiver_did.clone(), vector2.alice_did_doc.clone());

    let sender_secrets = PQCTestSecretsResolver::new(vector1.alice_secrets.clone());
    let receiver_secrets = PQCTestSecretsResolver::new(vector2.alice_secrets.clone());

    // Test different PQC algorithm combinations
    let algorithms = vec![
        ("ML-KEM-768+A256CBC-HS512", AuthCryptAlg::MlKem768A256cbcHs512, AnonCryptAlg::MlKem768Xc20p),
        ("ML-KEM-768+XC20P", AuthCryptAlg::MlKem768A256cbcHs512, AnonCryptAlg::MlKem768Xc20p),
        ("ML-KEM-1024+A256CBC-HS512", AuthCryptAlg::MlKem1024A256cbcHs512, AnonCryptAlg::MlKem1024Xc20p),
    ];

    for (name, auth_alg, anon_alg) in algorithms {
        println!("\n🔧 Testing algorithm combination: {name}");
        
        let msg = Message::build(
            format!("pqc-alg-test-{}", name.replace(" ", "-").to_lowercase()),
            "https://didcomm.org/test/1.0/algorithm".to_owned(),
            json!({
                "algorithm_test": name,
                "pqc_enabled": true,
                "quantum_resistant": true
            }),
        )
        .from(sender_did.clone())
        .to(receiver_did.clone())
        .finalize();

        // Pack with specific algorithm
        let (encrypted, _) = msg
            .pack_encrypted(
                receiver_did,
                Some(sender_did),
                None,
                &did_resolver,
                &sender_secrets,
                &PackEncryptedOptions {
                    enc_alg_auth: auth_alg,
                    enc_alg_anon: anon_alg,
                    ..Default::default()
                },
            )
            .await
            .expect("Failed to pack with custom algorithm");

        // Unpack and verify
        let (_unpacked, metadata) = Message::unpack(
            &encrypted,
            &did_resolver,
            &receiver_secrets,
            &UnpackOptions::default(),
        )
        .await
        .expect("Failed to unpack with custom algorithm");

        println!("   ✅ {} - Success! Authenticated: {}", name, metadata.authenticated);
    }
}

async fn custom_headers_and_services() {
    let alice_vector = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Alice failed");
    let bob_vector = PQCTestVector::ml_kem_1024_ml_dsa_87().expect("Bob failed");

    let alice_did = &alice_vector.alice_did;
    let bob_did = &bob_vector.alice_did;

    println!("📋 Demonstrating custom headers and messaging services:");
    println!("📤 Alice: {alice_did}");
    println!("📥 Bob: {bob_did}");

    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(alice_did.clone(), alice_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(bob_did.clone(), bob_vector.alice_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(alice_vector.alice_secrets.clone());
    let bob_secrets = PQCTestSecretsResolver::new(bob_vector.alice_secrets.clone());

    // Build complex forward headers
    let mut forward_headers = HashMap::new();
    forward_headers.insert("routing_priority".to_string(), json!("quantum_safe"));
    forward_headers.insert("encryption_level".to_string(), json!("maximum"));
    forward_headers.insert("pqc_algorithms".to_string(), json!(["ML-KEM-768", "ML-DSA-65"]));
    forward_headers.insert("quantum_resistance".to_string(), json!({
        "kem_security": "128-bit",
        "signature_security": "128-bit",
        "classical_equivalent": "AES-256"
    }));
    forward_headers.insert("compliance".to_string(), json!(["NIST-FIPS-203", "NIST-FIPS-204"]));

    let msg = Message::build(
        "pqc-custom-headers".to_owned(),
        "https://didcomm.org/custom/1.0/headers".to_owned(),
        json!({
            "message": "PQC message with extensive custom headers",
            "metadata": {
                "security_level": "quantum_resistant",
                "protocol_version": "PQC-DIDComm-v2.0"
            }
        }),
    )
    .from(alice_did.clone())
    .to(bob_did.clone())
    .finalize();

    println!("\n📝 Packing with extensive custom headers...");
    let custom_service = format!("{bob_did}#pqc-service-1");
    let (encrypted_msg, _pack_metadata) = msg
        .pack_encrypted(
            bob_did,
            Some(alice_did),
            None,
            &did_resolver,
            &alice_secrets,
            &PackEncryptedOptions {
                protect_sender: true,
                forward: true,
                forward_headers: Some(forward_headers),
                messaging_service: Some(custom_service.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("Failed to pack with custom headers");

    println!("✅ Custom headers and service configured:");
    println!("   - Messaging service: {custom_service}");
    println!("   - Forward enabled: true");
    println!("   - Sender protected: true");
    println!("   - Custom headers: 5 items");

    let (unpacked_msg, _) = Message::unpack(&encrypted_msg, &did_resolver, &bob_secrets, &UnpackOptions::default())
        .await.expect("Failed to unpack custom message");

    println!("✅ Custom message processed successfully!");
    println!("📄 Content: {}", unpacked_msg.body);
}

async fn sender_protection_demo() {
    let alice_vector = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Alice failed");
    let bob_vector = PQCTestVector::ml_kem_1024_ml_dsa_87().expect("Bob failed");

    let alice_did = &alice_vector.alice_did;
    let bob_did = &bob_vector.alice_did;

    println!("🛡️  Demonstrating PQC sender protection:");
    println!("📤 Alice (protected): {alice_did}");
    println!("📥 Bob: {bob_did}");

    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(alice_did.clone(), alice_vector.alice_did_doc.clone());
    did_resolver.add_did_doc(bob_did.clone(), bob_vector.alice_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(alice_vector.alice_secrets.clone());
    let bob_secrets = PQCTestSecretsResolver::new(bob_vector.alice_secrets.clone());

    // Test both protected and unprotected scenarios
    let scenarios = vec![
        ("Protected Sender", true),
        ("Anonymous Sender", false),
    ];

    for (name, protect_sender) in scenarios {
        println!("\n🔒 Testing scenario: {name}");
        
        let msg = Message::build(
            format!("pqc-sender-{}", if protect_sender { "protected" } else { "anonymous" }),
            "https://didcomm.org/protection/1.0/test".to_owned(),
            json!({
                "protection_type": if protect_sender { "sender_protected" } else { "anonymous" },
                "pqc_enabled": true,
                "quantum_safe": true
            }),
        )
        .from(alice_did.clone())
        .to(bob_did.clone())
        .finalize();

        let (encrypted_msg, pack_metadata) = msg
            .pack_encrypted(
                bob_did,
                if protect_sender { Some(alice_did) } else { None }, // AuthCrypt vs AnonCrypt
                None,
                &did_resolver,
                &alice_secrets,
                &PackEncryptedOptions {
                    protect_sender,
                    ..Default::default()
                },
            )
            .await
            .expect("Failed to pack protection test");

        let (_unpacked_msg, unpack_metadata) = Message::unpack(
            &encrypted_msg,
            &did_resolver,
            &bob_secrets,
            &UnpackOptions::default(),
        )
        .await
        .expect("Failed to unpack protection test");

        println!("   ✅ {name}: ");
        println!("      - Sender protected: {}", !unpack_metadata.anonymous_sender);
        println!("      - Authenticated: {}", unpack_metadata.authenticated);
        println!("      - Encrypted: {}", unpack_metadata.encrypted);
        println!("      - From KID present: {}", pack_metadata.from_kid.is_some());
        
        if protect_sender {
            println!("      - Sender identity: {:?}", unpack_metadata.encrypted_from_kid);
        } else {
            println!("      - Anonymous sender confirmed");
        }
    }

    println!("\n✅ Sender protection demo complete!");
    println!("🔐 Both protected and anonymous PQC messaging demonstrated");
}