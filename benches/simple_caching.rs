//! Simple benchmark to test DID resolution caching effectiveness

use criterion::{async_executor::FuturesExecutor, criterion_group, criterion_main, Criterion};
use navia_didcomm::{
    did::{resolvers::ExampleDIDResolver, CachingDIDResolver, DIDDoc, DIDResolver},
};
use serde_json::json;

fn create_test_did_doc() -> DIDDoc {
    let did_doc_json = json!({
        "id": "did:example:alice",
        "verificationMethod": [
            {
                "id": "did:example:alice#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:example:alice",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                }
            }
        ],
        "authentication": ["did:example:alice#key-1"],
        "keyAgreement": ["did:example:alice#key-1"],
        "service": []
    });
    serde_json::from_value(did_doc_json).expect("Invalid DID doc")
}

async fn resolve_with_cache(resolver: &CachingDIDResolver<'_>, repetitions: usize) {
    for _ in 0..repetitions {
        let _ = resolver.resolve("did:example:alice").await;
    }
}

async fn resolve_without_cache(resolver: &ExampleDIDResolver, repetitions: usize) {
    for _ in 0..repetitions {
        let _ = resolver.resolve("did:example:alice").await;
    }
}

fn benchmarks(c: &mut Criterion) {
    let did_doc = create_test_did_doc();
    let resolver = ExampleDIDResolver::new(vec![did_doc]);
    
    let repetitions = 100;

    let caching_resolver = CachingDIDResolver::new(&resolver);
    c.bench_function("with_caching_100_resolves", |b| {
        b.to_async(FuturesExecutor)
            .iter(|| resolve_with_cache(&caching_resolver, repetitions));
    });

    c.bench_function("without_caching_100_resolves", |b| {
        b.to_async(FuturesExecutor)
            .iter(|| resolve_without_cache(&resolver, repetitions));
    });
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);