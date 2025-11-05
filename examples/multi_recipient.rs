//! Multi-recipient DIDComm messaging example.
//!
//! This example demonstrates sending a single encrypted message to multiple recipients.
//! The message is encrypted once with all recipients sharing the same ciphertext,
//! but each recipient gets their own encrypted key in the JWE recipients array.

#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

// Allows test vectors usage inside and outside crate
pub(crate) use navia_didcomm as didcomm;

use navia_didcomm::{
    did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver, Message,
    PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use test_vectors::{ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("=================== MULTI-RECIPIENT ENCRYPTION ===================\n");
    multi_recipient_encryption().await;
}

async fn multi_recipient_encryption() {
    // Set up DID resolver
    let did_resolver = ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

    // Set up secrets resolvers
    let sender_secrets = ExampleSecretsResolver::new(ALICE_SECRETS.clone());
    let bob_secrets = ExampleSecretsResolver::new(BOB_SECRETS.clone());

    println!("📝 Creating message for Bob (demonstrating multi-key recipient)...");
    println!("   Sender: {}", ALICE_DID);
    println!("   Recipient: {} (has 3 key agreement keys)", BOB_DID);
    println!();

    // Create message addressed to Bob
    // Bob has multiple key agreement keys, so this demonstrates multi-recipient encryption
    // where the same plaintext is encrypted once, with separate encrypted_key entries for each key
    let message = Message::build(
        "multi-recipient-example-1".to_string(),
        "https://example.com/protocols/broadcast/1.0/announcement".to_string(),
        json!({
            "announcement": "This message demonstrates multi-recipient DIDComm encryption!",
            "priority": "high"
        }),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .finalize();

    println!("Message body:");
    println!("{}", serde_json::to_string_pretty(&message).unwrap());
    println!();

    // Pack the message - Bob has 3 keys, so this creates 3 encrypted_key entries
    println!("🔒 Encrypting message (Bob has 3 key agreement keys)...");
    let (packed_msg, pack_metadata) = message
        .pack_encrypted(
            &[BOB_DID.to_string()],
            Some(ALICE_DID),
            None,
            &did_resolver,
            &sender_secrets,
            &PackEncryptedOptions {
                forward: false, // Disable routing for simplicity
                ..PackEncryptedOptions::default()
            },
        )
        .await
        .expect("Failed to pack encrypted message")
        .into_iter()
        .next()
        .unwrap();

    println!("✅ Message encrypted successfully!");
    println!("   Metadata:");
    println!("     - Sender key: {:?}", pack_metadata.from_kid);
    println!(
        "     - Recipient keys: {} keys (Bob has 3 key agreement keys)",
        pack_metadata.to_kids.len()
    );
    for (i, kid) in pack_metadata.to_kids.iter().enumerate() {
        println!("       {}. {}", i + 1, kid);
    }
    println!();

    // Show that the ciphertext is shared but each key has its own encrypted_key
    println!("📦 JWE Structure Analysis:");
    let jwe: serde_json::Value = serde_json::from_str(&packed_msg).expect("Failed to parse JWE");

    if let Some(recipients) = jwe.get("recipients").and_then(|r| r.as_array()) {
        println!("   - Number of recipients in JWE: {}", recipients.len());
        println!("   - Each of Bob's keys has a unique encrypted_key entry");
        println!("   - All keys share the same ciphertext (efficient!)");
        println!(
            "   - Ciphertext size: {} bytes",
            jwe.get("ciphertext")
                .and_then(|c| c.as_str())
                .map(|s| s.len())
                .unwrap_or(0)
        );
    }
    println!();

    // Bob decrypts
    println!("🔓 Decryption Phase:");
    println!();

    println!("👤 Bob decrypting message...");
    let (bob_msg, bob_metadata) = Message::unpack(
        &packed_msg,
        &did_resolver,
        &bob_secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Bob failed to unpack message");

    println!("   ✅ Bob successfully decrypted!");
    println!("   - Message ID: {}", bob_msg.id);
    println!("   - Authenticated: {}", bob_metadata.authenticated);
    println!("   - Sender: {:?}", bob_metadata.encrypted_from_kid);
    println!("   - Message content:");
    println!(
        "     {}",
        serde_json::to_string_pretty(&bob_msg.body).unwrap()
    );
    println!();

    println!("✅ Message successfully delivered and decrypted!");
    println!();
    println!("🎯 Multi-Recipient Key Benefits:");
    println!("   ✓ Message encrypted ONCE (single CEK for all recipient keys)");
    println!("   ✓ Each recipient key gets unique encrypted_key in JWE");
    println!("   ✓ Efficiency: O(1) encryption + O(N) key wrapping");
    println!("   ✓ Standard DIDComm v2 encryption");
    println!("   ✓ API supports: pack_encrypted(&[did1, did2, did3, ...], ...)");
    println!();
    println!("Bob could decrypt using any of his 3 keys - the DIDComm library");
    println!("automatically finds a matching key and decrypts the message.");
}
