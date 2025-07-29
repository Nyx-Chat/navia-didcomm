//! Caching DID resolver wrapper to avoid duplicate resolutions

use async_trait::async_trait;
use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use crate::{
    did::{DIDDoc, DIDResolver},
    error::Result,
};

/// A caching wrapper around a DID resolver to avoid duplicate resolutions
/// during a single operation (e.g., pack_encrypted).
///
/// This is a simple in-memory cache that stores resolved DID documents
/// for the lifetime of the CachingDIDResolver instance.
pub struct CachingDIDResolver<'r> {
    resolver: &'r dyn DIDResolver,
    cache: RwLock<HashMap<String, Option<DIDDoc>>>,
    #[cfg(test)]
    pub(crate) resolution_count: AtomicUsize,
}

impl<'r> CachingDIDResolver<'r> {
    /// Creates a new caching resolver wrapping the given resolver
    pub fn new(resolver: &'r dyn DIDResolver) -> Self {
        Self {
            resolver,
            cache: RwLock::new(HashMap::new()),
            #[cfg(test)]
            resolution_count: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn get_resolution_count(&self) -> usize {
        self.resolution_count.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl<'r> DIDResolver for CachingDIDResolver<'r> {
    async fn resolve(&self, did: &str) -> Result<Option<DIDDoc>> {
        // Check cache first
        if let Ok(cache) = self.cache.read() {
            if let Some(cached_result) = cache.get(did) {
                return Ok(cached_result.clone());
            }
        }

        // Resolve and cache the result
        #[cfg(test)]
        self.resolution_count.fetch_add(1, Ordering::Relaxed);

        let result = self.resolver.resolve(did).await?;
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(did.to_string(), result.clone());
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::resolvers::ExampleDIDResolver;
    use crate::test_vectors::*;

    #[tokio::test]
    async fn test_caching_resolver_avoids_duplicate_resolutions() {
        let base_resolver =
            ExampleDIDResolver::new(vec![ALICE_DID_DOC.clone(), BOB_DID_DOC.clone()]);

        let caching_resolver = CachingDIDResolver::new(&base_resolver);

        // First resolution should hit the underlying resolver
        let alice_did = "did:example:alice";
        let result1 = caching_resolver.resolve(alice_did).await.unwrap();
        assert!(result1.is_some());
        assert_eq!(caching_resolver.get_resolution_count(), 1);

        // Second resolution of same DID should use cache
        let result2 = caching_resolver.resolve(alice_did).await.unwrap();
        assert!(result2.is_some());
        assert_eq!(caching_resolver.get_resolution_count(), 1); // Still 1!

        // Different DID should hit underlying resolver
        let bob_did = "did:example:bob";
        let result3 = caching_resolver.resolve(bob_did).await.unwrap();
        assert!(result3.is_some());
        assert_eq!(caching_resolver.get_resolution_count(), 2);

        // Resolving Alice again should still use cache
        let result4 = caching_resolver.resolve(alice_did).await.unwrap();
        assert!(result4.is_some());
        assert_eq!(caching_resolver.get_resolution_count(), 2); // Still 2!
    }

    #[tokio::test]
    async fn test_caching_resolver_handles_not_found() {
        let base_resolver = ExampleDIDResolver::new(vec![]);
        let caching_resolver = CachingDIDResolver::new(&base_resolver);

        let unknown_did = "did:example:unknown";

        // First resolution should return None and increment counter
        let result1 = caching_resolver.resolve(unknown_did).await.unwrap();
        assert!(result1.is_none());
        assert_eq!(caching_resolver.get_resolution_count(), 1);

        // Second resolution should use cached None result
        let result2 = caching_resolver.resolve(unknown_did).await.unwrap();
        assert!(result2.is_none());
        assert_eq!(caching_resolver.get_resolution_count(), 1); // Still 1!
    }
}
