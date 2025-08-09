//! End-to-End DIDComm PQC Performance Benchmarks
//!
//! These benchmarks measure the complete DIDComm message processing pipeline
//! with post-quantum cryptography, from message creation to unpacking.

use criterion::{criterion_group, criterion_main, Criterion};
use navia_didcomm::{
    test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector},
    Message, PackEncryptedOptions, UnpackOptions,
};
use serde_json::json;

async fn setup_test_environment() -> (
    PQCTestVector,
    PQCTestDIDResolver,
    PQCTestSecretsResolver,
    PQCTestSecretsResolver,
) {
    let vectors = PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create test vectors");

    let mut did_resolver = PQCTestDIDResolver::new();
    did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
    did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

    let alice_secrets = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());
    let bob_secrets = PQCTestSecretsResolver::new(vectors.bob_secrets.clone());

    (vectors, did_resolver, alice_secrets, bob_secrets)
}

fn bench_message_plaintext(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("PQC Plaintext Message End-to-End", |b| {
        b.to_async(&rt).iter(|| async {
            let (vectors, did_resolver, _alice_secrets, bob_secrets) =
                setup_test_environment().await;

            let message = Message::build(
                "bench-plaintext".to_string(),
                "benchmark/plaintext/1.0".to_string(),
                json!({"data": "benchmark plaintext message"}),
            )
            .to(vectors.bob_did.clone())
            .from(vectors.alice_did.clone())
            .finalize();

            let packed = message.pack_plaintext(&did_resolver).await.unwrap();
            let (_unpacked, _metadata) = Message::unpack(
                &packed,
                &did_resolver,
                &bob_secrets,
                &UnpackOptions::default(),
            )
            .await
            .unwrap();
        })
    });
}

fn bench_message_signed(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("PQC Signed Message End-to-End", |b| {
        b.to_async(&rt).iter(|| async {
            let (vectors, did_resolver, alice_secrets, bob_secrets) =
                setup_test_environment().await;

            let message = Message::build(
                "bench-signed".to_string(),
                "benchmark/signed/1.0".to_string(),
                json!({"data": "benchmark signed message"}),
            )
            .to(vectors.bob_did.clone())
            .from(vectors.alice_did.clone())
            .finalize();

            let (packed, _pack_metadata) = message
                .pack_signed(&vectors.alice_did, &did_resolver, &alice_secrets)
                .await
                .unwrap();

            let (_unpacked, _metadata) = Message::unpack(
                &packed,
                &did_resolver,
                &bob_secrets,
                &UnpackOptions::default(),
            )
            .await
            .unwrap();
        })
    });
}

fn bench_message_authcrypt(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("PQC AuthCrypt Message End-to-End", |b| {
        b.to_async(&rt).iter(|| async {
            let (vectors, did_resolver, alice_secrets, bob_secrets) =
                setup_test_environment().await;

            let message = Message::build(
                "bench-authcrypt".to_string(),
                "benchmark/authcrypt/1.0".to_string(),
                json!({"data": "benchmark authcrypt message"}),
            )
            .to(vectors.bob_did.clone())
            .from(vectors.alice_did.clone())
            .finalize();

            let (_packed, _pack_metadata) = message
                .pack_encrypted(
                    &vectors.bob_did,
                    Some(&vectors.alice_did), // AuthCrypt
                    None,
                    &did_resolver,
                    &alice_secrets,
                    &PackEncryptedOptions::default(),
                )
                .await
                .unwrap();

            let (_unpacked, _metadata) = Message::unpack(
                &_packed,
                &did_resolver,
                &bob_secrets,
                &UnpackOptions::default(),
            )
            .await
            .unwrap();
        })
    });
}

fn bench_message_anoncrypt(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("PQC AnonCrypt Message End-to-End", |b| {
        b.to_async(&rt).iter(|| async {
            let (vectors, did_resolver, alice_secrets, bob_secrets) =
                setup_test_environment().await;

            let message = Message::build(
                "bench-anoncrypt".to_string(),
                "benchmark/anoncrypt/1.0".to_string(),
                json!({"data": "benchmark anoncrypt message"}),
            )
            .to(vectors.bob_did.clone())
            .finalize(); // No from - anonymous

            let (_packed, _pack_metadata) = message
                .pack_encrypted(
                    &vectors.bob_did,
                    None, // AnonCrypt
                    None,
                    &did_resolver,
                    &alice_secrets,
                    &PackEncryptedOptions::default(),
                )
                .await
                .unwrap();

            let (_unpacked, _metadata) = Message::unpack(
                &_packed,
                &did_resolver,
                &bob_secrets,
                &UnpackOptions::default(),
            )
            .await
            .unwrap();
        })
    });
}

fn bench_message_signed_encrypted(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("PQC Signed+Encrypted Message End-to-End", |b| {
        b.to_async(&rt).iter(|| async {
            let (vectors, did_resolver, alice_secrets, bob_secrets) =
                setup_test_environment().await;

            let message = Message::build(
                "bench-signed-encrypted".to_string(),
                "benchmark/signed-encrypted/1.0".to_string(),
                json!({"data": "benchmark signed encrypted message"}),
            )
            .to(vectors.bob_did.clone())
            .from(vectors.alice_did.clone())
            .finalize();

            let (_packed, _pack_metadata) = message
                .pack_encrypted(
                    &vectors.bob_did,
                    Some(&vectors.alice_did), // AuthCrypt
                    Some(&vectors.alice_did), // Additional signing
                    &did_resolver,
                    &alice_secrets,
                    &PackEncryptedOptions::default(),
                )
                .await
                .unwrap();

            let (_unpacked, _metadata) = Message::unpack(
                &_packed,
                &did_resolver,
                &bob_secrets,
                &UnpackOptions::default(),
            )
            .await
            .unwrap();
        })
    });
}

fn bench_large_message(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("Large Message Processing");

    group.bench_function("PQC Large Message (10KB) AuthCrypt", |b| {
        b.to_async(&rt).iter(|| async {
            let (vectors, did_resolver, alice_secrets, bob_secrets) =
                setup_test_environment().await;

            let large_data = "x".repeat(10000); // 10KB
            let message = Message::build(
                "bench-large".to_string(),
                "benchmark/large/1.0".to_string(),
                json!({"data": large_data, "size": 10000}),
            )
            .to(vectors.bob_did.clone())
            .from(vectors.alice_did.clone())
            .finalize();

            let (_packed, _pack_metadata) = message
                .pack_encrypted(
                    &vectors.bob_did,
                    Some(&vectors.alice_did),
                    None,
                    &did_resolver,
                    &alice_secrets,
                    &PackEncryptedOptions::default(),
                )
                .await
                .unwrap();

            let (_unpacked, _metadata) = Message::unpack(
                &_packed,
                &did_resolver,
                &bob_secrets,
                &UnpackOptions::default(),
            )
            .await
            .unwrap();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_message_plaintext,
    bench_message_signed,
    bench_message_authcrypt,
    bench_message_anoncrypt,
    bench_message_signed_encrypted,
    bench_large_message
);

criterion_main!(benches);
