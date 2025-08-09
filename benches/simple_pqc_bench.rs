//! Simple PQC Benchmarks
//!
//! Basic benchmarks for post-quantum cryptographic operations.
//! This provides a quick overview of PQC performance characteristics.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use navia_didcomm::utils::pqc::{
    MlDsa65KeyPair, MlDsa87KeyPair, MlKem1024KeyPair, MlKem768KeyPair,
};
use pqcrypto_traits::sign::{PublicKey, SecretKey};

fn benchmark_pqc_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_key_generation_simple");

    group.bench_function("ML-KEM-768", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let randomness = [counter as u8; 64];
            counter = counter.wrapping_add(1);
            let _keypair = black_box(MlKem768KeyPair::generate(randomness));
        })
    });

    group.bench_function("ML-KEM-1024", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let randomness = [counter as u8; 64];
            counter = counter.wrapping_add(1);
            let _keypair = black_box(MlKem1024KeyPair::generate(randomness));
        })
    });

    group.bench_function("ML-DSA-65", |b| {
        b.iter(|| {
            let _keypair = black_box(MlDsa65KeyPair::generate());
        })
    });

    group.bench_function("ML-DSA-87", |b| {
        b.iter(|| {
            let _keypair = black_box(MlDsa87KeyPair::generate());
        })
    });

    group.finish();
}

fn benchmark_pqc_key_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_key_sizes");

    // Generate keys once for size comparison
    let ml_kem_768_keypair = MlKem768KeyPair::generate([42u8; 64]);
    let ml_kem_1024_keypair = MlKem1024KeyPair::generate([43u8; 64]);
    let ml_dsa_65_keypair = MlDsa65KeyPair::generate();
    let ml_dsa_87_keypair = MlDsa87KeyPair::generate();

    group.bench_function("ML-KEM-768_public_key_size", |b| {
        b.iter(|| {
            let size = black_box(ml_kem_768_keypair.public_key().as_slice().len());
            assert_eq!(size, 1184); // ML-KEM-768 public key is 1184 bytes
            size
        })
    });

    group.bench_function("ML-KEM-1024_public_key_size", |b| {
        b.iter(|| {
            let size = black_box(ml_kem_1024_keypair.public_key().as_slice().len());
            assert_eq!(size, 1568); // ML-KEM-1024 public key is 1568 bytes
            size
        })
    });

    group.bench_function("ML-DSA-65_public_key_size", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_65_keypair.public_key().as_bytes().len());
            assert_eq!(size, 1952); // ML-DSA-65 public key is 1952 bytes
            size
        })
    });

    group.bench_function("ML-DSA-87_public_key_size", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_87_keypair.public_key().as_bytes().len());
            assert_eq!(size, 2592); // ML-DSA-87 public key is 2592 bytes
            size
        })
    });

    // Private key sizes
    group.bench_function("ML-DSA-65_private_key_size", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_65_keypair.secret_key().unwrap().as_bytes().len());
            assert_eq!(size, 4032); // ML-DSA-65 private key is 4032 bytes
            size
        })
    });

    group.bench_function("ML-DSA-87_private_key_size", |b| {
        b.iter(|| {
            let size = black_box(ml_dsa_87_keypair.secret_key().unwrap().as_bytes().len());
            assert_eq!(size, 4896); // ML-DSA-87 private key is 4896 bytes
            size
        })
    });

    group.finish();
}

fn benchmark_pqc_signature_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_signature_operations_simple");
    let message = b"Hello, post-quantum world! This is a test message for signature benchmarking.";

    // ML-DSA-65
    let ml_dsa_65_keypair = MlDsa65KeyPair::generate();
    group.bench_function("ML-DSA-65_sign", |b| {
        b.iter(|| {
            let _signature = black_box(ml_dsa_65_keypair.sign(message).expect("Signing failed"));
        })
    });

    let ml_dsa_65_signature = ml_dsa_65_keypair.sign(message).expect("Signing failed");
    group.bench_function("ML-DSA-65_verify", |b| {
        b.iter(|| {
            let _result = black_box(
                MlDsa65KeyPair::verify(&ml_dsa_65_signature, ml_dsa_65_keypair.public_key())
                    .expect("Verification failed"),
            );
        })
    });

    // ML-DSA-87
    let ml_dsa_87_keypair = MlDsa87KeyPair::generate();
    group.bench_function("ML-DSA-87_sign", |b| {
        b.iter(|| {
            let _signature = black_box(ml_dsa_87_keypair.sign(message).expect("Signing failed"));
        })
    });

    let ml_dsa_87_signature = ml_dsa_87_keypair.sign(message).expect("Signing failed");
    group.bench_function("ML-DSA-87_verify", |b| {
        b.iter(|| {
            let _result = black_box(
                MlDsa87KeyPair::verify(&ml_dsa_87_signature, ml_dsa_87_keypair.public_key())
                    .expect("Verification failed"),
            );
        })
    });

    group.finish();
}

fn benchmark_pqc_kem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_kem_operations_simple");

    // ML-KEM-768
    let ml_kem_768_keypair = MlKem768KeyPair::generate([44u8; 64]);
    let ml_kem_768_public = ml_kem_768_keypair.public_key();

    group.bench_function("ML-KEM-768_encapsulate", |b| {
        let mut counter = 0u32;
        b.iter(|| {
            let randomness = [counter as u8; 32];
            counter = counter.wrapping_add(1);
            let (_ciphertext, _shared_secret) =
                black_box(MlKem768KeyPair::encapsulate(&ml_kem_768_public, randomness));
        })
    });

    let (ml_kem_768_ciphertext, _) = MlKem768KeyPair::encapsulate(&ml_kem_768_public, [100u8; 32]);
    group.bench_function("ML-KEM-768_decapsulate", |b| {
        b.iter(|| {
            let _shared_secret = black_box(
                ml_kem_768_keypair
                    .decapsulate(&ml_kem_768_ciphertext)
                    .expect("Decapsulation failed"),
            );
        })
    });

    // ML-KEM-1024
    let ml_kem_1024_keypair = MlKem1024KeyPair::generate([45u8; 64]);
    let ml_kem_1024_public = ml_kem_1024_keypair.public_key();

    group.bench_function("ML-KEM-1024_encapsulate", |b| {
        let mut counter = 0u32;
        b.iter(|| {
            let randomness = [counter as u8; 32];
            counter = counter.wrapping_add(1);
            let (_ciphertext, _shared_secret) = black_box(MlKem1024KeyPair::encapsulate(
                &ml_kem_1024_public,
                randomness,
            ));
        })
    });

    let (ml_kem_1024_ciphertext, _) =
        MlKem1024KeyPair::encapsulate(&ml_kem_1024_public, [101u8; 32]);
    group.bench_function("ML-KEM-1024_decapsulate", |b| {
        b.iter(|| {
            let _shared_secret = black_box(
                ml_kem_1024_keypair
                    .decapsulate(&ml_kem_1024_ciphertext)
                    .expect("Decapsulation failed"),
            );
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_pqc_key_generation,
    benchmark_pqc_key_sizes,
    benchmark_pqc_signature_operations,
    benchmark_pqc_kem_operations,
);

criterion_main!(benches);
