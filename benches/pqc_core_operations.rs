//! Core PQC Operations Benchmarks
//!
//! Benchmarks for fundamental post-quantum cryptographic operations
//! used in the navia-didcomm library.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use navia_didcomm::utils::pqc::{
    MlDsa65KeyPair, MlDsa87KeyPair, MlKem1024KeyPair, MlKem768KeyPair,
};
use pqcrypto_traits::sign::{PublicKey, SecretKey};

/// Benchmark key generation for all PQC algorithms
fn benchmark_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_key_generation");

    group.bench_function("ML-KEM-768", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            // Use different randomness each time for realistic benchmarking
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

/// Benchmark ML-KEM encapsulation and decapsulation
fn benchmark_kem_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_kem_operations");

    // ML-KEM-768
    let kem768_keypair = MlKem768KeyPair::generate([42u8; 64]);
    let kem768_public = kem768_keypair.public_key();

    group.bench_function("ML-KEM-768_encapsulate", |b| {
        let mut counter = 0u32;
        b.iter(|| {
            let randomness = [counter as u8; 32];
            counter = counter.wrapping_add(1);
            let (_ciphertext, _shared_secret) =
                black_box(MlKem768KeyPair::encapsulate(&kem768_public, randomness));
        })
    });

    let (kem768_ciphertext, _) = MlKem768KeyPair::encapsulate(&kem768_public, [99u8; 32]);
    group.bench_function("ML-KEM-768_decapsulate", |b| {
        b.iter(|| {
            let _shared_secret = black_box(
                kem768_keypair
                    .decapsulate(&kem768_ciphertext)
                    .expect("Decapsulation failed"),
            );
        })
    });

    // ML-KEM-1024
    let kem1024_keypair = MlKem1024KeyPair::generate([43u8; 64]);
    let kem1024_public = kem1024_keypair.public_key();

    group.bench_function("ML-KEM-1024_encapsulate", |b| {
        let mut counter = 0u32;
        b.iter(|| {
            let randomness = [counter as u8; 32];
            counter = counter.wrapping_add(1);
            let (_ciphertext, _shared_secret) =
                black_box(MlKem1024KeyPair::encapsulate(&kem1024_public, randomness));
        })
    });

    let (kem1024_ciphertext, _) = MlKem1024KeyPair::encapsulate(&kem1024_public, [98u8; 32]);
    group.bench_function("ML-KEM-1024_decapsulate", |b| {
        b.iter(|| {
            let _shared_secret = black_box(
                kem1024_keypair
                    .decapsulate(&kem1024_ciphertext)
                    .expect("Decapsulation failed"),
            );
        })
    });

    group.finish();
}

/// Benchmark ML-DSA signature operations
fn benchmark_signature_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_signature_operations");
    let message = b"Hello, post-quantum world! This is a test message for signature benchmarking with sufficient length to be realistic.";

    // ML-DSA-65
    let dsa65_keypair = MlDsa65KeyPair::generate();

    group.bench_function("ML-DSA-65_sign", |b| {
        b.iter(|| {
            let _signature = black_box(dsa65_keypair.sign(message).expect("Signing failed"));
        })
    });

    let dsa65_signature = dsa65_keypair.sign(message).expect("Signing failed");
    group.bench_function("ML-DSA-65_verify", |b| {
        b.iter(|| {
            let _result = black_box(
                MlDsa65KeyPair::verify(&dsa65_signature, dsa65_keypair.public_key())
                    .expect("Verification failed"),
            );
        })
    });

    // ML-DSA-87
    let dsa87_keypair = MlDsa87KeyPair::generate();

    group.bench_function("ML-DSA-87_sign", |b| {
        b.iter(|| {
            let _signature = black_box(dsa87_keypair.sign(message).expect("Signing failed"));
        })
    });

    let dsa87_signature = dsa87_keypair.sign(message).expect("Signing failed");
    group.bench_function("ML-DSA-87_verify", |b| {
        b.iter(|| {
            let _result = black_box(
                MlDsa87KeyPair::verify(&dsa87_signature, dsa87_keypair.public_key())
                    .expect("Verification failed"),
            );
        })
    });

    group.finish();
}

/// Benchmark key reconstruction from private key bytes (critical for production)
fn benchmark_key_reconstruction(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_key_reconstruction");

    // Generate key pairs and extract private key bytes
    let kem768_keypair = MlKem768KeyPair::generate([44u8; 64]);
    let kem768_private_bytes = *kem768_keypair
        .get_private_key_bytes()
        .expect("Generated keypair should have private key bytes");

    let kem1024_keypair = MlKem1024KeyPair::generate([45u8; 64]);
    let kem1024_private_bytes = *kem1024_keypair
        .get_private_key_bytes()
        .expect("Generated keypair should have private key bytes");

    // Create secure combined key formats for ML-DSA
    let dsa65_keypair = MlDsa65KeyPair::generate();
    let dsa65_secret_bytes = dsa65_keypair.secret_key().unwrap().as_bytes();
    let dsa65_public_bytes = dsa65_keypair.public_key().as_bytes();
    let mut dsa65_combined = Vec::new();
    dsa65_combined.extend_from_slice(dsa65_secret_bytes);
    dsa65_combined.extend_from_slice(dsa65_public_bytes);

    let dsa87_keypair = MlDsa87KeyPair::generate();
    let dsa87_secret_bytes = dsa87_keypair.secret_key().unwrap().as_bytes();
    let dsa87_public_bytes = dsa87_keypair.public_key().as_bytes();
    let mut dsa87_combined = Vec::new();
    dsa87_combined.extend_from_slice(dsa87_secret_bytes);
    dsa87_combined.extend_from_slice(dsa87_public_bytes);

    group.bench_function("ML-KEM-768_reconstruct", |b| {
        b.iter(|| {
            let _keypair = black_box(
                MlKem768KeyPair::from_private_key(&kem768_private_bytes)
                    .expect("Reconstruction failed"),
            );
        })
    });

    group.bench_function("ML-KEM-1024_reconstruct", |b| {
        b.iter(|| {
            let _keypair = black_box(
                MlKem1024KeyPair::from_private_key(&kem1024_private_bytes)
                    .expect("Reconstruction failed"),
            );
        })
    });

    group.bench_function("ML-DSA-65_reconstruct", |b| {
        b.iter(|| {
            let _keypair = black_box(
                MlDsa65KeyPair::from_private_key(&dsa65_combined).expect("Reconstruction failed"),
            );
        })
    });

    group.bench_function("ML-DSA-87_reconstruct", |b| {
        b.iter(|| {
            let _keypair = black_box(
                MlDsa87KeyPair::from_private_key(&dsa87_combined).expect("Reconstruction failed"),
            );
        })
    });

    group.finish();
}

/// Benchmark throughput for various message sizes
fn benchmark_signature_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("pqc_signature_throughput");

    let dsa65_keypair = MlDsa65KeyPair::generate();
    let message_sizes = [64, 256, 1024, 4096, 16384]; // bytes

    for size in message_sizes.iter() {
        let message = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("ML-DSA-65_sign", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let _signature = black_box(dsa65_keypair.sign(msg).expect("Signing failed"));
                })
            },
        );

        // Pre-sign for verification benchmark
        let signature = dsa65_keypair.sign(&message).expect("Signing failed");
        group.bench_with_input(
            BenchmarkId::new("ML-DSA-65_verify", size),
            &signature,
            |b, sig| {
                b.iter(|| {
                    let _result = black_box(
                        MlDsa65KeyPair::verify(sig, dsa65_keypair.public_key())
                            .expect("Verification failed"),
                    );
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_kem_operations,
    benchmark_signature_operations,
    benchmark_key_reconstruction,
    benchmark_signature_throughput,
);

criterion_main!(benches);
