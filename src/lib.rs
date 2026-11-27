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
//! - **Modern Cryptography**: X25519, P-256, P-384, P-521, Ed25519, Secp256k1
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

#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]
#![allow(clippy::result_large_err)] // Large error types acceptable for comprehensive crypto error context

mod jwe;
mod jwk;
mod jws;
mod message;
mod utils;

// The shared test vectors name the crate `didcomm`.
#[cfg(test)]
pub(crate) use crate as didcomm;

// The integration tests, examples and benches include this file too and each uses a different
// part of it, so the unit tests leave some of it unused.
#[cfg(test)]
#[allow(dead_code)]
mod test_vectors;

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

pub use message::{
    Attachment, AttachmentBuilder, AttachmentData, Base64AttachmentData, FromPrior,
    JsonAttachmentData, LinksAttachmentData, Message, MessageBuilder, MessagingServiceMetadata,
    PackEncryptedMetadata, PackEncryptedOptions, PackSignedMetadata, PadFloor, PadRequirement,
    SenderRequirement, UnpackMetadata, UnpackOptions,
};
