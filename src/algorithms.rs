//! Post-Quantum Cryptographic Algorithms for DIDComm v2
//!
//! This module defines the quantum-resistant cryptographic algorithms supported by navia-didcomm,
//! including key encapsulation mechanisms (ML-KEM), digital signature algorithms (ML-DSA),
//! and their combinations for different message security modes.
//!
//! All algorithms follow NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) specifications
//! for quantum resistance and formal security validation.

use serde::{Deserialize, Serialize};

/// Post-Quantum algorithms for anonymous encryption (AnonCrypt).
///
/// These algorithms provide message confidentiality without sender authentication,
/// using ML-KEM key encapsulation with authenticated encryption primitives.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize, Default)]
pub enum AnonCryptAlg {
    /// ML-KEM-768 key encapsulation with XChaCha20-Poly1305 content encryption
    /// Provides 128-bit quantum security (~AES-128 equivalent)
    #[default]
    #[serde(rename = "ML-KEM768+XC20P")]
    MlKem768Xc20p,

    /// ML-KEM-768 key encapsulation with AES-256-GCM content encryption
    /// Provides 128-bit quantum security with AES-GCM
    #[serde(rename = "ML-KEM768+A256GCM")]
    MlKem768A256gcm,

    /// ML-KEM-1024 key encapsulation with XChaCha20-Poly1305 content encryption
    /// Provides 192-bit quantum security (~AES-192 equivalent)
    #[serde(rename = "ML-KEM1024+XC20P")]
    MlKem1024Xc20p,

    /// ML-KEM-1024 key encapsulation with AES-256-GCM content encryption
    /// Provides 192-bit quantum security with AES-GCM
    #[serde(rename = "ML-KEM1024+A256GCM")]
    MlKem1024A256gcm,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize, Default)]
/// Post-Quantum authentication encryption algorithms for DIDComm messages.
///
/// These algorithms provide both encryption and sender authentication,
/// ensuring that the recipient can verify the sender's identity while
/// maintaining message confidentiality using quantum-resistant cryptography.
pub enum AuthCryptAlg {
    /// ML-KEM-768 key encapsulation with AES-256-CBC + HMAC-SHA512 content encryption
    /// Provides 128-bit quantum security with authenticated encryption
    #[default]
    #[serde(rename = "ML-KEM768+A256CBC-HS512")]
    MlKem768A256cbcHs512,

    /// ML-KEM-1024 key encapsulation with AES-256-CBC + HMAC-SHA512 content encryption
    /// Provides 192-bit quantum security with authenticated encryption
    #[serde(rename = "ML-KEM1024+A256CBC-HS512")]
    MlKem1024A256cbcHs512,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize, Default)]
/// Post-Quantum digital signature algorithms for DIDComm messages.
///
/// These algorithms are used to create and verify digital signatures
/// on DIDComm messages, providing non-repudiation and message integrity
/// with quantum resistance.
pub enum SignAlg {
    /// ML-DSA-65 (Dilithium3) digital signature algorithm
    /// Provides 128-bit quantum security (~RSA-3072 equivalent)
    #[default]
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,

    /// ML-DSA-87 (Dilithium5) digital signature algorithm  
    /// Provides 192-bit quantum security (~RSA-15360 equivalent)
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
}
