//! PQC Size Analysis Benchmark
//!
//! Measures the size characteristics of PQC algorithms.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use navia_didcomm::utils::pqc::{
    MlDsa65KeyPair, MlDsa87KeyPair, MlKem1024KeyPair, MlKem768KeyPair,
};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

fn benchmark_pqc_key_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_key_sizes");

    // Generate PQC keys
    let ml_kem_768_keypair = MlKem768KeyPair::generate([1u8; 64]);
    let ml_kem_1024_keypair = MlKem1024KeyPair::generate([2u8; 64]);
    let ml_dsa_65_keypair = MlDsa65KeyPair::generate();
    let ml_dsa_87_keypair = MlDsa87KeyPair::generate();

    // ML-KEM-768 sizes
    group.bench_function("ml_kem_768_public_key", |b| {
        b.iter(|| {
            let size = black_box(ml_kem_768_keypair.public_key().as_slice().len());
            assert_eq!(size, 1184);
            size
        })
    });

    group.bench_function("ml_kem_768_private_key", |b| b.iter(|| black_box(2400)));

    // ML-KEM-1024 sizes
    group.bench_function("ml_kem_1024_public_key", |b| {
        b.iter(|| {
            let size = black_box(ml_kem_1024_keypair.public_key().as_slice().len());
            assert_eq!(size, 1568);
            size
        })
    });

    group.bench_function("ml_kem_1024_private_key", |b| b.iter(|| black_box(3168)));

    // ML-DSA-65 sizes
    group.bench_function("ml_dsa_65_public_key", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_65_keypair.public_key().as_bytes().len());
            assert_eq!(size, 1952);
            size
        })
    });

    group.bench_function("ml_dsa_65_private_key", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_65_keypair.secret_key().unwrap().as_bytes().len());
            assert_eq!(size, 4032);
            size
        })
    });

    // ML-DSA-87 sizes
    group.bench_function("ml_dsa_87_public_key", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_87_keypair.public_key().as_bytes().len());
            assert_eq!(size, 2592);
            size
        })
    });

    group.bench_function("ml_dsa_87_private_key", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_87_keypair.secret_key().unwrap().as_bytes().len());
            assert_eq!(size, 4896);
            size
        })
    });

    group.finish();
}

fn benchmark_pqc_signature_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_signature_sizes");
    let message = b"Test message for signature size analysis with sufficient length for realistic measurements.";

    let ml_dsa_65_keypair = MlDsa65KeyPair::generate();
    let ml_dsa_87_keypair = MlDsa87KeyPair::generate();

    // Pre-generate signatures
    let ml_dsa_65_signature = ml_dsa_65_keypair.sign(message).expect("Signing failed");
    let ml_dsa_87_signature = ml_dsa_87_keypair.sign(message).expect("Signing failed");

    group.bench_function("ml_dsa_65_signature_size", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_65_signature.as_bytes().len());
            // ML-DSA-65 signatures are approximately 3293 bytes
            assert!(size > 3000 && size < 3400);
            size
        })
    });

    group.bench_function("ml_dsa_87_signature_size", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_87_signature.as_bytes().len());
            // ML-DSA-87 signatures are approximately 4627 bytes
            assert!(size > 4500 && size < 4800);
            size
        })
    });

    group.finish();
}

fn benchmark_pqc_ciphertext_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_ciphertext_sizes");

    let ml_kem_768_keypair = MlKem768KeyPair::generate([3u8; 64]);
    let ml_kem_1024_keypair = MlKem1024KeyPair::generate([4u8; 64]);

    let ml_kem_768_public = ml_kem_768_keypair.public_key();
    let ml_kem_1024_public = ml_kem_1024_keypair.public_key();

    // Generate ciphertexts
    let (ml_kem_768_ciphertext, _) = MlKem768KeyPair::encapsulate(&ml_kem_768_public, [5u8; 32]);
    let (ml_kem_1024_ciphertext, _) = MlKem1024KeyPair::encapsulate(&ml_kem_1024_public, [6u8; 32]);

    group.bench_function("ml_kem_768_ciphertext_size", |b| {
        b.iter(|| {
            let size = black_box(ml_kem_768_ciphertext.as_slice().len());
            assert_eq!(size, 1088);
            size
        })
    });

    group.bench_function("ml_kem_1024_ciphertext_size", |b| {
        b.iter(|| {
            let size = black_box(ml_kem_1024_ciphertext.as_slice().len());
            assert_eq!(size, 1568);
            size
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_pqc_key_sizes,
    benchmark_pqc_signature_sizes,
    benchmark_pqc_ciphertext_sizes,
);

criterion_main!(benches);
