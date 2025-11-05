#[allow(unused_imports, dead_code)]
#[path = "../src/test_vectors/mod.rs"]
mod test_vectors;

// TODO: look for better solution
// Allows test vectors usage inside and outside crate
pub(crate) use navia_didcomm as didcomm;

use navia_didcomm::{
    did::resolvers::ExampleDIDResolver, secrets::resolvers::ExampleSecretsResolver, Message,
    PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;
use test_vectors::{
    ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS, MEDIATOR1_DID_DOC,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // --- Building message from ALICE to BOB ---
    let msg = Message::build(
        "example-1".to_owned(),
        "example/v1".to_owned(),
        json!("example-body"),
    )
    .from(ALICE_DID.to_owned())
    .to(BOB_DID.to_owned())
    .created_time(1516269022)
    .expires_time(1516385931)
    .finalize();

    // --- Packing encrypted and authenticated message ---
    let did_resolver = ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ]);

    let secrets_resolver = ExampleSecretsResolver::new(ALICE_SECRETS.clone());

    let (msg, metadata) = msg
        .pack_encrypted(
            &["did:example:bob#key-p256-1".to_string()],
            "did:example:alice#key-p256-1".into(),
            "did:example:alice#key-2".into(),
            &did_resolver,
            &secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Unable pack_encrypted")
        .into_iter()
        .next()
        .unwrap();

    println!("Packed Message: {}", msg);
    println!("Pack Metadata: {:?}", metadata);
    println!("   - Sign-by KID: {:?}", metadata.sign_by_kid);
    println!("   - To KIDs: {:?}", metadata.to_kids);
    println!("   - Messaging service: {:?}", metadata.messaging_service);

    // Bob unpacks the message
    let bob_secrets_resolver = ExampleSecretsResolver::new(BOB_SECRETS.clone());
    let (unpacked_msg, unpack_metadata) = Message::unpack(
        &msg,
        &did_resolver,
        &bob_secrets_resolver,
        &UnpackOptions::default(),
    )
    .await
    .expect("Unable unpack");

    println!("✅ Advanced unpacking complete!");
    println!("📄 Message: {}", unpacked_msg.body);
    println!("🔐 Security features:");
    println!("   - Authenticated: {}", unpack_metadata.authenticated);
    println!("   - Encrypted: {}", unpack_metadata.encrypted);
    println!("   - Non-repudiation: {}", unpack_metadata.non_repudiation);
    println!(
        "   - Sender protected: {}",
        !unpack_metadata.anonymous_sender
    );
}
