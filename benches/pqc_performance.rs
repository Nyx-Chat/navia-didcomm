//! Post-Quantum Cryptography Performance Benchmarks
//!
//! Performance benchmarks for PQC algorithms in DIDComm messaging

use askar_crypto::random;
use criterion::{criterion_group, criterion_main, Criterion};
use navia_didcomm::utils::pqc::{
    MlDsa65KeyPair, MlDsa87KeyPair, MlKem1024KeyPair, MlKem768KeyPair,
};

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("PQC Key Generation");

    group.bench_function("ML-KEM-768", |b| {
        b.iter(|| {
            let mut randomness = [0u8; 64];
            random::fill_random(&mut randomness);
            MlKem768KeyPair::generate(randomness)
        })
    });

    group.bench_function("ML-KEM-1024", |b| {
        b.iter(|| {
            let mut randomness = [0u8; 64];
            random::fill_random(&mut randomness);
            MlKem1024KeyPair::generate(randomness)
        })
    });

    group.bench_function("ML-DSA-65", |b| b.iter(MlDsa65KeyPair::generate));

    group.bench_function("ML-DSA-87", |b| b.iter(MlDsa87KeyPair::generate));

    group.finish();
}

fn bench_ml_kem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Operations");

    // Generate keys for testing
    let mut randomness1 = [0u8; 64];
    random::fill_random(&mut randomness1);
    let ml_kem_768_key = MlKem768KeyPair::generate(randomness1);

    let mut randomness2 = [0u8; 64];
    random::fill_random(&mut randomness2);
    let ml_kem_1024_key = MlKem1024KeyPair::generate(randomness2);

    // Pre-generate ciphertexts for decapsulation tests
    let mut encap_randomness = [0u8; 32];
    random::fill_random(&mut encap_randomness);
    let (kem_768_ciphertext, _) =
        MlKem768KeyPair::encapsulate(&ml_kem_768_key.public_key(), encap_randomness);

    let mut encap_randomness2 = [0u8; 32];
    random::fill_random(&mut encap_randomness2);
    let (kem_1024_ciphertext, _) =
        MlKem1024KeyPair::encapsulate(&ml_kem_1024_key.public_key(), encap_randomness2);

    group.bench_function("ML-KEM-768 Encapsulate", |b| {
        b.iter(|| {
            let mut encap_randomness = [0u8; 32];
            random::fill_random(&mut encap_randomness);
            MlKem768KeyPair::encapsulate(&ml_kem_768_key.public_key(), encap_randomness)
        })
    });

    group.bench_function("ML-KEM-768 Decapsulate", |b| {
        b.iter(|| ml_kem_768_key.decapsulate(&kem_768_ciphertext).unwrap())
    });

    group.bench_function("ML-KEM-1024 Encapsulate", |b| {
        b.iter(|| {
            let mut encap_randomness = [0u8; 32];
            random::fill_random(&mut encap_randomness);
            MlKem1024KeyPair::encapsulate(&ml_kem_1024_key.public_key(), encap_randomness)
        })
    });

    group.bench_function("ML-KEM-1024 Decapsulate", |b| {
        b.iter(|| ml_kem_1024_key.decapsulate(&kem_1024_ciphertext).unwrap())
    });

    group.finish();
}

fn bench_ml_dsa_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Operations");

    // Generate keys for testing
    let ml_dsa_65_key = MlDsa65KeyPair::generate();
    let ml_dsa_87_key = MlDsa87KeyPair::generate();

    let test_message =
        b"Hello, post-quantum world! This is a test message for signature benchmarking.";

    // Pre-generate signatures for verification tests
    let signature_65 = ml_dsa_65_key.sign(test_message).unwrap();
    let signature_87 = ml_dsa_87_key.sign(test_message).unwrap();

    group.bench_function("ML-DSA-65 Sign", |b| {
        b.iter(|| ml_dsa_65_key.sign(test_message).unwrap())
    });

    group.bench_function("ML-DSA-65 Verify", |b| {
        b.iter(|| MlDsa65KeyPair::verify(&signature_65, ml_dsa_65_key.public_key()).unwrap())
    });

    group.bench_function("ML-DSA-87 Sign", |b| {
        b.iter(|| ml_dsa_87_key.sign(test_message).unwrap())
    });

    group.bench_function("ML-DSA-87 Verify", |b| {
        b.iter(|| MlDsa87KeyPair::verify(&signature_87, ml_dsa_87_key.public_key()).unwrap())
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_ml_kem_operations,
    bench_ml_dsa_operations
);

criterion_main!(benches);
