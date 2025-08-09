//! # Navia-DIDComm
//!
//! Production-ready DIDComm v2 implementation for secure peer-to-peer messaging.
//!
//! This library provides a complete implementation of the [DIDComm v2 specification](https://identity.foundation/didcomm-messaging/spec/)
//! with modern cryptographic libraries and production-ready security features.
//!
//! ## Features
//!
//! - **Complete DIDComm v2 Support**: Full specification implementation
//! - **Post-Quantum Cryptography**: ML-KEM-768/1024, ML-DSA-65/87 (NIST FIPS 203/204)
//! - **Secure Messaging**: Encrypted (anoncrypt/authcrypt) and signed messages
//! - **Message Routing**: Forward protocol and mediation support
//! - **DID Rotation**: Full `fromPrior` field support
//! - **Production Ready**: Comprehensive testing, security audits, and performance optimization
//!
//! ## Quick Start
//!
//! ```rust
//! use navia_didcomm::{Message, PackEncryptedOptions};
//! use serde_json::json;
//!
//! // Build a message
//! let msg = Message::build(
//!     "example-1".into(),
//!     "example/v1".into(),
//!     json!("Hello, DIDComm!"),
//! )
//! .to("did:example:recipient".into())
//! .from("did:example:sender".into())
//! .finalize();
//!
//! // Pack and send (async context required)
//! // let (packed_msg, metadata) = msg.pack_encrypted(...).await?;
//! ```
//!
//! For complete examples, see the [examples](https://github.com/Nyx-Chat/navia-didcomm/tree/main/examples) directory.

#![doc(html_root_url = "https://docs.rs/navia-didcomm/1.0.0")]
#![warn(rust_2018_idioms)]
#![allow(missing_docs)] // Enhanced API documentation ongoing - key APIs documented
#![deny(unsafe_code)]
#![allow(clippy::result_large_err)] // Large error types acceptable for comprehensive crypto error context

mod jwk;
mod message;
mod pqc_jwe;
mod pqc_jws;
/// Utilities for cryptographic operations and post-quantum algorithms.
pub mod utils;

/// Test vectors for post-quantum cryptographic operations and DIDComm message processing.
///
/// This module provides test vectors and mock resolvers for testing PQC implementations
/// with ML-KEM and ML-DSA algorithms.
pub mod test_vectors;

// PQC-only - classical crypto debug tests completely removed

/// DIDComm cryptographic algorithms and protocol configuration.
///
/// This module defines the supported encryption and signing algorithms
/// for DIDComm v2 messages, including authentication encryption (authcrypt),
/// anonymous encryption (anoncrypt), and digital signatures.
pub mod algorithms;
/// Decentralized Identifier (DID) resolution and document handling.
///
/// This module provides interfaces for resolving DID documents and working
/// with DID-based verification methods. It includes the core `DIDResolver` trait
/// and supporting types for DID document structure and verification methods.
pub mod did;
/// Error types and handling for DIDComm operations.
///
/// This module defines the comprehensive error system used throughout
/// the library, including error kinds, result types, and extension traits
/// for ergonomic error handling.
pub mod error;
/// DIDComm protocol implementations and message routing.
///
/// This module contains implementations of DIDComm protocols including
/// the forward/routing protocol for message mediation and multi-hop delivery.
pub mod protocols;
pub mod secrets;
/// Temporary PQC API testing module for development purposes.
pub mod test_pqc_api;

pub use message::{
    Attachment, AttachmentBuilder, AttachmentData, Base64AttachmentData, FromPrior,
    JsonAttachmentData, LinksAttachmentData, Message, MessageBuilder, MessagingServiceMetadata,
    PackEncryptedMetadata, PackEncryptedOptions, PackSignedMetadata, UnpackMetadata, UnpackOptions,
};

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{Message, PackEncryptedOptions, UnpackOptions};

    #[tokio::test]
    async fn demo_works_with_pqc() {
        // This demo now works with full PQC implementation
        use crate::test_vectors::{PQCTestDIDResolver, PQCTestSecretsResolver, PQCTestVector};

        let vectors =
            PQCTestVector::ml_kem_768_ml_dsa_65().expect("Failed to create PQC test vectors");

        // --- Build message ---
        let msg = Message::build(
            "demo-example-1".into(),
            "demo/v1".into(),
            json!("Hello PQC DIDComm World!"),
        )
        .to(vectors.bob_did.clone())
        .from(vectors.alice_did.clone())
        .finalize();

        // --- Setup resolvers with PQC test vectors ---
        let mut did_resolver = PQCTestDIDResolver::new();
        did_resolver.add_did_doc(vectors.alice_did.clone(), vectors.alice_did_doc.clone());
        did_resolver.add_did_doc(vectors.bob_did.clone(), vectors.bob_did_doc.clone());

        let alice_secrets_resolver = PQCTestSecretsResolver::new(vectors.alice_secrets.clone());
        let bob_secrets_resolver = PQCTestSecretsResolver::new(vectors.bob_secrets.clone());

        // --- Packing message with PQC AuthCrypt ---
        let (packed_msg, pack_metadata) = msg
            .pack_encrypted(
                &vectors.bob_did,
                Some(&vectors.alice_did),
                None,
                &did_resolver,
                &alice_secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .expect("PQC pack should work");

        // Verify pack metadata
        assert!(pack_metadata.from_kid.is_some());
        assert!(!pack_metadata.to_kids.is_empty());

        // --- Unpacking message with PQC ---
        let (unpacked_msg, unpack_metadata) = Message::unpack(
            &packed_msg,
            &did_resolver,
            &bob_secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("PQC unpack should work");

        // Verify the message was properly encrypted and authenticated with PQC
        assert!(unpack_metadata.encrypted);
        assert!(unpack_metadata.authenticated);
        assert!(!unpack_metadata.anonymous_sender);
        assert!(unpack_metadata.encrypted_from_kid.is_some());

        // Verify message content
        assert_eq!(unpacked_msg.from, Some(vectors.alice_did));
        assert_eq!(unpacked_msg.to, Some(vec![vectors.bob_did]));
        assert_eq!(unpacked_msg.body, json!("Hello PQC DIDComm World!"));

        println!("✅ PQC DIDComm demo successful! Message encrypted with ML-KEM-768 and authenticated with ML-DSA-65");
    }
}
