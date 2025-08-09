//! PQC Throughput and Memory Benchmarks
//!
//! Specialized benchmarks for measuring throughput and memory efficiency
//! of PQC operations in high-volume scenarios.

use askar_crypto::random;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use navia_didcomm::utils::pqc::{
    MlDsa65KeyPair, MlDsa87KeyPair, MlKem1024KeyPair, MlKem768KeyPair,
};

fn bench_batch_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Key Generation");

    for batch_size in [1, 10, 100].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("ML-KEM-768", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut keys = Vec::with_capacity(size as usize);
                    for _ in 0..size {
                        let mut randomness = [0u8; 64];
                        random::fill_random(&mut randomness);
                        keys.push(MlKem768KeyPair::generate(randomness));
                    }
                    keys
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("ML-DSA-65", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut keys = Vec::with_capacity(size as usize);
                    for _ in 0..size {
                        keys.push(MlDsa65KeyPair::generate());
                    }
                    keys
                })
            },
        );
    }

    group.finish();
}

fn bench_batch_encapsulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Encapsulation");

    // Pre-generate keys
    let mut randomness = [0u8; 64];
    random::fill_random(&mut randomness);
    let ml_kem_768_key = MlKem768KeyPair::generate(randomness);

    let mut randomness2 = [0u8; 64];
    random::fill_random(&mut randomness2);
    let ml_kem_1024_key = MlKem1024KeyPair::generate(randomness2);

    for batch_size in [1, 10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("ML-KEM-768", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut results = Vec::with_capacity(size as usize);
                    for _ in 0..size {
                        let mut encap_randomness = [0u8; 32];
                        random::fill_random(&mut encap_randomness);
                        results.push(MlKem768KeyPair::encapsulate(
                            &ml_kem_768_key.public_key(),
                            encap_randomness,
                        ));
                    }
                    results
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("ML-KEM-1024", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut results = Vec::with_capacity(size as usize);
                    for _ in 0..size {
                        let mut encap_randomness = [0u8; 32];
                        random::fill_random(&mut encap_randomness);
                        results.push(MlKem1024KeyPair::encapsulate(
                            &ml_kem_1024_key.public_key(),
                            encap_randomness,
                        ));
                    }
                    results
                })
            },
        );
    }

    group.finish();
}

fn bench_batch_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Signing");

    // Pre-generate keys
    let ml_dsa_65_key = MlDsa65KeyPair::generate();
    let ml_dsa_87_key = MlDsa87KeyPair::generate();

    let test_messages = [b"Message 1".to_vec(),
        b"Message 2 - slightly longer".to_vec(),
        b"Message 3 - even longer with more content to sign".to_vec(),
        b"Message 4 - maximum length test message with lots of content for comprehensive signature benchmarking".to_vec()];

    for batch_size in [1, 10, 100].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("ML-DSA-65", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut signatures = Vec::with_capacity(size);
                    for i in 0..size {
                        let message = &test_messages[i % test_messages.len()];
                        signatures.push(ml_dsa_65_key.sign(message).unwrap());
                    }
                    signatures
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("ML-DSA-87", batch_size),
            batch_size,
            |b, &size| {
                b.iter(|| {
                    let mut signatures = Vec::with_capacity(size);
                    for i in 0..size {
                        let message = &test_messages[i % test_messages.len()];
                        signatures.push(ml_dsa_87_key.sign(message).unwrap());
                    }
                    signatures
                })
            },
        );
    }

    group.finish();
}

fn bench_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("Mixed PQC Workload");

    group.bench_function("Realistic Mixed Operations", |b| {
        b.iter(|| {
            // Simulate a realistic mixed workload:
            // 1. Generate ML-KEM and ML-DSA keys
            let mut kem_randomness = [0u8; 64];
            random::fill_random(&mut kem_randomness);
            let kem_key = MlKem768KeyPair::generate(kem_randomness);
            let dsa_key = MlDsa65KeyPair::generate();

            // 2. Perform key encapsulation
            let mut encap_randomness = [0u8; 32];
            random::fill_random(&mut encap_randomness);
            let (ciphertext, shared_secret) =
                MlKem768KeyPair::encapsulate(&kem_key.public_key(), encap_randomness);

            // 3. Sign a message
            let message = b"Mixed workload test message";
            let signature = dsa_key.sign(message).unwrap();

            // 4. Decapsulate
            let decapsulated_secret = kem_key.decapsulate(&ciphertext).unwrap();

            // 5. Verify signature
            let verified = MlDsa65KeyPair::verify(&signature, dsa_key.public_key()).unwrap();

            // Verify operations completed correctly
            assert_eq!(shared_secret, decapsulated_secret);
            assert_eq!(verified, message);
        })
    });

    group.finish();
}

fn bench_memory_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory Efficiency");

    group.bench_function("Key Storage Efficiency", |b| {
        b.iter(|| {
            // Test memory efficiency of key storage patterns
            let mut keys = Vec::new();

            // Generate and store keys in different ways
            for i in 0..10 {
                let mut randomness = [0u8; 64];
                randomness[0] = i; // Vary randomness
                random::fill_random(&mut randomness[1..]);

                let kem_key = MlKem768KeyPair::generate(randomness);
                let dsa_key = MlDsa65KeyPair::generate();

                keys.push((kem_key, dsa_key));
            }

            // Use the keys to ensure they're not optimized away
            let total_operations = keys.len();
            keys.clear();
            total_operations
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_batch_key_generation,
    bench_batch_encapsulation,
    bench_batch_signing,
    bench_mixed_workload,
    bench_memory_efficiency
);

criterion_main!(benches);
