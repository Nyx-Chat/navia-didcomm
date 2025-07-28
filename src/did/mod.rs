pub mod resolvers;

pub(crate) mod caching_resolver;
pub(crate) mod did_doc;
pub(crate) mod did_resolver;

pub use did_doc::{
    DIDCommMessagingService, DIDDoc, Service, ServiceKind, VerificationMaterial,
    VerificationMethod, VerificationMethodType,
};

pub use caching_resolver::CachingDIDResolver;
pub use did_resolver::DIDResolver;
