//! Post-Quantum Cryptography utilities and key management
//!
//! This module provides wrapper types and utilities for PQC algorithms,
//! integrating ML-KEM (key encapsulation) and ML-DSA (digital signatures)
//! with the existing navia-didcomm architecture.
//!
//! # Security Features
//!
//! - **ML-KEM**: NIST FIPS 203 standardized key encapsulation mechanism using lattice cryptography
//! - **ML-DSA**: NIST FIPS 204 standardized digital signature algorithm based on Dilithium
//! - **Formal Verification**: Uses `libcrux-ml-kem` with formal security proofs
//! - **Production Ready**: Battle-tested `pqcrypto-dilithium` implementation
//!
//! # Key Sizes
//!
//! | Algorithm | Public Key | Private Key | Ciphertext/Signature | Security Level |
//! |-----------|------------|-------------|---------------------|----------------|
//! | ML-KEM-768 | 1,184 bytes | 2,400 bytes | 1,088 bytes | ~128-bit quantum |
//! | ML-KEM-1024 | 1,568 bytes | 3,168 bytes | 1,568 bytes | ~192-bit quantum |
//! | ML-DSA-65 | 1,952 bytes | 4,032 bytes | ~3,293 bytes | ~128-bit quantum |
//! | ML-DSA-87 | 2,592 bytes | 4,896 bytes | ~4,627 bytes | ~192-bit quantum |

use crate::error::{err_msg, ErrorKind, Result};
use pqcrypto_traits::sign::{PublicKey, SecretKey};

// Removed unused SecretBytes import

/// Post-Quantum Cryptographic algorithm identifiers.
///
/// These identifiers correspond to NIST standardized post-quantum algorithms
/// providing quantum resistance for key encapsulation and digital signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PQCKeyAlg {
    /// ML-KEM-512 (NIST FIPS 203) - 128-bit quantum security
    MlKem512,
    /// ML-KEM-768 (NIST FIPS 203) - 192-bit quantum security  
    MlKem768,
    /// ML-KEM-1024 (NIST FIPS 203) - 256-bit quantum security
    MlKem1024,
    /// ML-DSA-44 (NIST FIPS 204) - 128-bit quantum security
    MlDsa44,
    /// ML-DSA-65 (NIST FIPS 204) - 192-bit quantum security
    MlDsa65,
    /// ML-DSA-87 (NIST FIPS 204) - 256-bit quantum security
    MlDsa87,
}

/// Wrapper types for post-quantum key pairs.
///
/// This enum provides a unified interface for different PQC algorithms,
/// allowing polymorphic handling of keys while maintaining type safety.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PQCKeyPair {
    /// ML-KEM-768 key pair for key encapsulation
    MlKem768(MlKem768KeyPair),
    /// ML-KEM-1024 key pair for key encapsulation
    MlKem1024(MlKem1024KeyPair),
    /// ML-DSA-65 (Dilithium3) key pair for digital signatures
    MlDsa65(MlDsa65KeyPair),
    /// ML-DSA-87 (Dilithium5) key pair for digital signatures
    MlDsa87(MlDsa87KeyPair),
}

/// ML-KEM-768 key pair wrapper (1184-byte public key, 2400-byte private key).
///
/// Provides quantum-resistant key encapsulation with ~128-bit security level.
/// Uses formally verified `libcrux-ml-kem` implementation for high assurance.
pub struct MlKem768KeyPair {
    pub(crate) private_key_bytes: Option<[u8; 2400]>,
    pub(crate) public_key_bytes: [u8; 1184],
}

/// ML-KEM-1024 key pair wrapper (1568-byte public key, 3168-byte private key)
pub struct MlKem1024KeyPair {
    pub(crate) private_key_bytes: Option<[u8; 3168]>,
    pub(crate) public_key_bytes: [u8; 1568],
}

/// ML-DSA-65 (Dilithium3) key pair wrapper
pub struct MlDsa65KeyPair {
    pub(crate) public_key: pqcrypto_dilithium::dilithium3::PublicKey,
    pub(crate) secret_key: Option<pqcrypto_dilithium::dilithium3::SecretKey>,
}

/// ML-DSA-87 (Dilithium5) key pair wrapper
pub struct MlDsa87KeyPair {
    pub(crate) public_key: pqcrypto_dilithium::dilithium5::PublicKey,
    pub(crate) secret_key: Option<pqcrypto_dilithium::dilithium5::SecretKey>,
}

// Manual Debug implementations since crypto libraries don't implement Debug for security

impl std::fmt::Debug for MlKem768KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlKem768KeyPair").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MlKem1024KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlKem1024KeyPair").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MlDsa65KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsa65KeyPair").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for MlDsa87KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsa87KeyPair").finish_non_exhaustive()
    }
}

impl MlKem768KeyPair {
    /// Generate a new ML-KEM-768 key pair with both keys.
    ///
    /// # Parameters
    /// * `randomness` - 64 bytes of cryptographically secure random data
    ///
    /// # Returns
    /// A new key pair with both public and private key material available
    pub fn generate(randomness: [u8; 64]) -> Self {
        let key_pair = libcrux_ml_kem::mlkem768::generate_key_pair(randomness);
        let mut public_key_bytes = [0u8; 1184];
        public_key_bytes.copy_from_slice(key_pair.public_key().as_slice());
        let mut private_key_bytes = [0u8; 2400];
        private_key_bytes.copy_from_slice(key_pair.private_key().as_slice());
        Self {
            public_key_bytes,
            private_key_bytes: Some(private_key_bytes),
        }
    }

    /// Create from public key only (for DID document parsing)
    pub fn from_public_key(public_key: libcrux_ml_kem::MlKemPublicKey<1184>) -> Self {
        let mut public_key_bytes = [0u8; 1184];
        public_key_bytes.copy_from_slice(public_key.as_slice());
        Self {
            public_key_bytes,
            private_key_bytes: None,
        }
    }

    /// Create from private key bytes (for secrets resolver)
    pub fn from_private_key(private_key_bytes: &[u8]) -> crate::error::Result<Self> {
        if private_key_bytes.len() != 2400 {
            return Err(crate::error::err_msg(
                crate::error::ErrorKind::InvalidState,
                "Invalid ML-KEM-768 private key length",
            ));
        }
        let mut priv_key_array = [0u8; 2400];
        priv_key_array.copy_from_slice(private_key_bytes);
        let private_key = libcrux_ml_kem::MlKemPrivateKey::<2400>::from(priv_key_array);

        // Use the unpacked API to reconstruct the key pair from private key
        let mut key_pair_unpacked = libcrux_ml_kem::mlkem768::portable::unpacked::init_key_pair();
        libcrux_ml_kem::mlkem768::portable::unpacked::key_pair_from_private_mut(
            &private_key,
            &mut key_pair_unpacked,
        );

        // Extract the public key from the reconstructed key pair
        let public_key =
            libcrux_ml_kem::mlkem768::portable::unpacked::key_pair_serialized_public_key(
                &key_pair_unpacked,
            );
        let reconstructed_private_key =
            libcrux_ml_kem::mlkem768::portable::unpacked::key_pair_serialized_private_key(
                &key_pair_unpacked,
            );

        // Verify the reconstruction worked by checking the private key matches
        if reconstructed_private_key.as_slice() != private_key_bytes {
            return Err(crate::error::err_msg(
                crate::error::ErrorKind::InvalidState,
                "ML-KEM-768 key reconstruction failed",
            ));
        }

        let mut public_key_bytes = [0u8; 1184];
        public_key_bytes.copy_from_slice(public_key.as_slice());

        // Store the actual private key bytes for proper decapsulation
        Ok(Self {
            public_key_bytes,
            private_key_bytes: Some(priv_key_array),
        })
    }

    /// Create from raw public key bytes
    pub fn from_public_key_bytes(public_key_bytes: [u8; 1184]) -> Self {
        Self {
            public_key_bytes,
            private_key_bytes: None,
        }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8; 1184] {
        &self.public_key_bytes
    }

    /// Get the private key bytes (for testing and benchmarking)
    pub fn get_private_key_bytes(&self) -> Option<&[u8; 2400]> {
        self.private_key_bytes.as_ref()
    }

    /// Get the libcrux public key (recreated from bytes)
    pub fn public_key(&self) -> libcrux_ml_kem::MlKemPublicKey<1184> {
        libcrux_ml_kem::MlKemPublicKey::<1184>::from(self.public_key_bytes)
    }

    /// Check if private key is available
    pub fn has_private_key(&self) -> bool {
        self.private_key_bytes.is_some()
    }

    /// Encapsulate a shared secret to the public key
    pub fn encapsulate(
        public_key: &libcrux_ml_kem::MlKemPublicKey<1184>,
        randomness: [u8; 32],
    ) -> (libcrux_ml_kem::MlKemCiphertext<1088>, [u8; 32]) {
        libcrux_ml_kem::mlkem768::encapsulate(public_key, randomness)
    }

    /// Decapsulate a shared secret from the ciphertext (requires private key)
    pub fn decapsulate(
        &self,
        ciphertext: &libcrux_ml_kem::MlKemCiphertext<1088>,
    ) -> Result<[u8; 32]> {
        match &self.private_key_bytes {
            Some(private_key_bytes) => {
                let private_key = libcrux_ml_kem::MlKemPrivateKey::<2400>::from(*private_key_bytes);
                Ok(libcrux_ml_kem::mlkem768::decapsulate(
                    &private_key,
                    ciphertext,
                ))
            }
            None => Err(err_msg(
                ErrorKind::InvalidState,
                "Private key not available for decapsulation",
            )),
        }
    }
}

impl MlKem1024KeyPair {
    /// Generate a new ML-KEM-1024 key pair with both keys
    pub fn generate(randomness: [u8; 64]) -> Self {
        let key_pair = libcrux_ml_kem::mlkem1024::generate_key_pair(randomness);
        let mut public_key_bytes = [0u8; 1568];
        public_key_bytes.copy_from_slice(key_pair.public_key().as_slice());
        let mut private_key_bytes = [0u8; 3168];
        private_key_bytes.copy_from_slice(key_pair.private_key().as_slice());
        Self {
            public_key_bytes,
            private_key_bytes: Some(private_key_bytes),
        }
    }

    /// Create from public key only (for DID document parsing)
    pub fn from_public_key(public_key: libcrux_ml_kem::MlKemPublicKey<1568>) -> Self {
        let mut public_key_bytes = [0u8; 1568];
        public_key_bytes.copy_from_slice(public_key.as_slice());
        Self {
            public_key_bytes,
            private_key_bytes: None,
        }
    }

    /// Create from private key bytes (for secrets resolver)
    pub fn from_private_key(private_key_bytes: &[u8]) -> crate::error::Result<Self> {
        if private_key_bytes.len() != 3168 {
            return Err(crate::error::err_msg(
                crate::error::ErrorKind::InvalidState,
                "Invalid ML-KEM-1024 private key length",
            ));
        }
        let mut priv_key_array = [0u8; 3168];
        priv_key_array.copy_from_slice(private_key_bytes);
        let private_key = libcrux_ml_kem::MlKemPrivateKey::<3168>::from(priv_key_array);

        // Use the unpacked API to reconstruct the key pair from private key
        let mut key_pair_unpacked = libcrux_ml_kem::mlkem1024::portable::unpacked::init_key_pair();
        libcrux_ml_kem::mlkem1024::portable::unpacked::key_pair_from_private_mut(
            &private_key,
            &mut key_pair_unpacked,
        );

        // Extract the public key from the reconstructed key pair
        let public_key =
            libcrux_ml_kem::mlkem1024::portable::unpacked::key_pair_serialized_public_key(
                &key_pair_unpacked,
            );
        let reconstructed_private_key =
            libcrux_ml_kem::mlkem1024::portable::unpacked::key_pair_serialized_private_key(
                &key_pair_unpacked,
            );

        // Verify the reconstruction worked by checking the private key matches
        if reconstructed_private_key.as_slice() != private_key_bytes {
            return Err(crate::error::err_msg(
                crate::error::ErrorKind::InvalidState,
                "ML-KEM-1024 key reconstruction failed",
            ));
        }

        let mut public_key_bytes = [0u8; 1568];
        public_key_bytes.copy_from_slice(public_key.as_slice());

        // Store the actual private key bytes for proper decapsulation
        Ok(Self {
            public_key_bytes,
            private_key_bytes: Some(priv_key_array),
        })
    }

    /// Create from raw public key bytes
    pub fn from_public_key_bytes(public_key_bytes: [u8; 1568]) -> Self {
        Self {
            public_key_bytes,
            private_key_bytes: None,
        }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> &[u8; 1568] {
        &self.public_key_bytes
    }

    /// Get the private key bytes (for testing and benchmarking)
    pub fn get_private_key_bytes(&self) -> Option<&[u8; 3168]> {
        self.private_key_bytes.as_ref()
    }

    /// Get the libcrux public key (recreated from bytes)
    pub fn public_key(&self) -> libcrux_ml_kem::MlKemPublicKey<1568> {
        libcrux_ml_kem::MlKemPublicKey::<1568>::from(self.public_key_bytes)
    }

    /// Check if private key is available
    pub fn has_private_key(&self) -> bool {
        self.private_key_bytes.is_some()
    }

    /// Encapsulate a shared secret to the public key  
    pub fn encapsulate(
        public_key: &libcrux_ml_kem::MlKemPublicKey<1568>,
        randomness: [u8; 32],
    ) -> (libcrux_ml_kem::MlKemCiphertext<1568>, [u8; 32]) {
        libcrux_ml_kem::mlkem1024::encapsulate(public_key, randomness)
    }

    /// Decapsulate a shared secret from the ciphertext (requires private key)
    pub fn decapsulate(
        &self,
        ciphertext: &libcrux_ml_kem::MlKemCiphertext<1568>,
    ) -> Result<[u8; 32]> {
        match &self.private_key_bytes {
            Some(private_key_bytes) => {
                let private_key = libcrux_ml_kem::MlKemPrivateKey::<3168>::from(*private_key_bytes);
                Ok(libcrux_ml_kem::mlkem1024::decapsulate(
                    &private_key,
                    ciphertext,
                ))
            }
            None => Err(err_msg(
                ErrorKind::InvalidState,
                "Private key not available for decapsulation",
            )),
        }
    }
}

impl MlDsa65KeyPair {
    /// Generate a new ML-DSA-65 (Dilithium3) key pair with both keys
    pub fn generate() -> Self {
        let (public_key, secret_key) = pqcrypto_dilithium::dilithium3::keypair();
        Self {
            public_key,
            secret_key: Some(secret_key),
        }
    }

    /// Create from public key only (for DID document parsing)
    pub fn from_public_key(public_key: pqcrypto_dilithium::dilithium3::PublicKey) -> Self {
        Self {
            public_key,
            secret_key: None,
        }
    }

    /// Create from private key bytes (for secrets resolver)
    ///
    /// IMPORTANT: Since Dilithium/ML-DSA doesn't support deriving public keys from private keys,
    /// this function expects a combined format: [private_key_bytes][public_key_bytes]
    /// Total length should be 4032 + 1952 = 5984 bytes for ML-DSA-65
    pub fn from_private_key(combined_key_bytes: &[u8]) -> crate::error::Result<Self> {
        // Check if we have the expected combined format
        if combined_key_bytes.len() == 5984 {
            // 4032 + 1952
            // Extract private and public key parts
            let private_key_bytes = &combined_key_bytes[..4032];
            let public_key_bytes = &combined_key_bytes[4032..];

            let secret_key = pqcrypto_dilithium::dilithium3::SecretKey::from_bytes(
                private_key_bytes,
            )
            .map_err(|_| {
                crate::error::err_msg(
                    crate::error::ErrorKind::InvalidState,
                    "Invalid ML-DSA-65 private key format",
                )
            })?;

            let public_key = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(
                public_key_bytes,
            )
            .map_err(|_| {
                crate::error::err_msg(
                    crate::error::ErrorKind::InvalidState,
                    "Invalid ML-DSA-65 public key format",
                )
            })?;

            Ok(Self {
                public_key,
                secret_key: Some(secret_key),
            })
        } else if combined_key_bytes.len() == 4032 {
            // Legacy format - only private key provided
            // This is insecure as we can't properly derive the public key
            return Err(crate::error::err_msg(
                crate::error::ErrorKind::InvalidState,
                "ML-DSA-65 requires both private and public key material (5984 bytes total). Cannot derive public key from private key alone.",
            ));
        } else {
            return Err(crate::error::err_msg(
                crate::error::ErrorKind::InvalidState,
                "Invalid ML-DSA-65 key material length. Expected 5984 bytes (4032 private + 1952 public).",
            ));
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &pqcrypto_dilithium::dilithium3::PublicKey {
        &self.public_key
    }

    /// Get the secret key (if available)
    pub fn secret_key(&self) -> Option<&pqcrypto_dilithium::dilithium3::SecretKey> {
        self.secret_key.as_ref()
    }

    /// Get combined private+public key bytes for storage/transmission
    pub fn get_combined_key_bytes(&self) -> Option<Vec<u8>> {
        if let Some(secret_key) = &self.secret_key {
            let mut combined = Vec::with_capacity(5984); // 4032 + 1952
            combined.extend_from_slice(secret_key.as_bytes());
            combined.extend_from_slice(self.public_key.as_bytes());
            Some(combined)
        } else {
            None
        }
    }

    /// Sign a message (requires secret key)
    pub fn sign(&self, message: &[u8]) -> Result<pqcrypto_dilithium::dilithium3::SignedMessage> {
        match &self.secret_key {
            Some(secret_key) => Ok(pqcrypto_dilithium::dilithium3::sign(message, secret_key)),
            None => Err(err_msg(
                ErrorKind::InvalidState,
                "Secret key not available for signing",
            )),
        }
    }

    /// Verify a signature
    pub fn verify(
        signature: &pqcrypto_dilithium::dilithium3::SignedMessage,
        public_key: &pqcrypto_dilithium::dilithium3::PublicKey,
    ) -> Result<Vec<u8>> {
        pqcrypto_dilithium::dilithium3::open(signature, public_key).map_err(|_| {
            err_msg(
                ErrorKind::SignatureVerificationFailed,
                "ML-DSA-65 signature verification failed",
            )
        })
    }
}

impl MlDsa87KeyPair {
    /// Generate a new ML-DSA-87 (Dilithium5) key pair with both keys
    pub fn generate() -> Self {
        let (public_key, secret_key) = pqcrypto_dilithium::dilithium5::keypair();
        Self {
            public_key,
            secret_key: Some(secret_key),
        }
    }

    /// Create from public key only (for DID document parsing)
    pub fn from_public_key(public_key: pqcrypto_dilithium::dilithium5::PublicKey) -> Self {
        Self {
            public_key,
            secret_key: None,
        }
    }

    /// Create from private key bytes (for secrets resolver)
    ///
    /// IMPORTANT: Since Dilithium/ML-DSA doesn't support deriving public keys from private keys,
    /// this function expects a combined format: [private_key_bytes][public_key_bytes]
    /// Total length should be 4896 + 2592 = 7488 bytes for ML-DSA-87
    pub fn from_private_key(combined_key_bytes: &[u8]) -> crate::error::Result<Self> {
        // Check if we have the expected combined format (corrected size from our earlier test: 4896, not 4864)
        if combined_key_bytes.len() == 7488 {
            // 4896 + 2592
            // Extract private and public key parts
            let private_key_bytes = &combined_key_bytes[..4896];
            let public_key_bytes = &combined_key_bytes[4896..];

            let secret_key = pqcrypto_dilithium::dilithium5::SecretKey::from_bytes(
                private_key_bytes,
            )
            .map_err(|_| {
                crate::error::err_msg(
                    crate::error::ErrorKind::InvalidState,
                    "Invalid ML-DSA-87 private key format",
                )
            })?;

            let public_key = pqcrypto_dilithium::dilithium5::PublicKey::from_bytes(
                public_key_bytes,
            )
            .map_err(|_| {
                crate::error::err_msg(
                    crate::error::ErrorKind::InvalidState,
                    "Invalid ML-DSA-87 public key format",
                )
            })?;

            Ok(Self {
                public_key,
                secret_key: Some(secret_key),
            })
        } else if combined_key_bytes.len() == 4896 {
            // Legacy format - only private key provided
            // This is insecure as we can't properly derive the public key
            return Err(crate::error::err_msg(
                crate::error::ErrorKind::InvalidState,
                "ML-DSA-87 requires both private and public key material (7488 bytes total). Cannot derive public key from private key alone.",
            ));
        } else {
            return Err(crate::error::err_msg(
                crate::error::ErrorKind::InvalidState,
                "Invalid ML-DSA-87 key material length. Expected 7488 bytes (4896 private + 2592 public).",
            ));
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &pqcrypto_dilithium::dilithium5::PublicKey {
        &self.public_key
    }

    /// Get the secret key (if available)
    pub fn secret_key(&self) -> Option<&pqcrypto_dilithium::dilithium5::SecretKey> {
        self.secret_key.as_ref()
    }

    /// Get combined private+public key bytes for storage/transmission
    pub fn get_combined_key_bytes(&self) -> Option<Vec<u8>> {
        if let Some(secret_key) = &self.secret_key {
            let mut combined = Vec::with_capacity(7488); // 4896 + 2592
            combined.extend_from_slice(secret_key.as_bytes());
            combined.extend_from_slice(self.public_key.as_bytes());
            Some(combined)
        } else {
            None
        }
    }

    /// Sign a message (requires secret key)
    pub fn sign(&self, message: &[u8]) -> Result<pqcrypto_dilithium::dilithium5::SignedMessage> {
        match &self.secret_key {
            Some(secret_key) => Ok(pqcrypto_dilithium::dilithium5::sign(message, secret_key)),
            None => Err(err_msg(
                ErrorKind::InvalidState,
                "Secret key not available for signing",
            )),
        }
    }

    /// Verify a signature
    pub fn verify(
        signature: &pqcrypto_dilithium::dilithium5::SignedMessage,
        public_key: &pqcrypto_dilithium::dilithium5::PublicKey,
    ) -> Result<Vec<u8>> {
        pqcrypto_dilithium::dilithium5::open(signature, public_key).map_err(|_| {
            err_msg(
                ErrorKind::SignatureVerificationFailed,
                "ML-DSA-87 signature verification failed",
            )
        })
    }
}

/// Trait for working with PQC key pairs generically
pub trait AsPQCKeyPair {
    /// Get the algorithm type
    fn pqc_key_alg(&self) -> PQCKeyAlg;

    /// Convert to the generic key pair enum
    fn as_pqc_key_pair(&self) -> Result<PQCKeyPair>;

    /// Extract as ML-KEM-768 key pair
    fn as_ml_kem_768(&self) -> Result<&MlKem768KeyPair> {
        Err(err_msg(
            ErrorKind::InvalidState,
            "Not an ML-KEM-768 key pair",
        ))
    }

    /// Extract as ML-KEM-1024 key pair
    fn as_ml_kem_1024(&self) -> Result<&MlKem1024KeyPair> {
        Err(err_msg(
            ErrorKind::InvalidState,
            "Not an ML-KEM-1024 key pair",
        ))
    }

    /// Extract as ML-DSA-65 key pair
    fn as_ml_dsa_65(&self) -> Result<&MlDsa65KeyPair> {
        Err(err_msg(
            ErrorKind::InvalidState,
            "Not an ML-DSA-65 key pair",
        ))
    }

    /// Extract as ML-DSA-87 key pair  
    fn as_ml_dsa_87(&self) -> Result<&MlDsa87KeyPair> {
        Err(err_msg(
            ErrorKind::InvalidState,
            "Not an ML-DSA-87 key pair",
        ))
    }
}

impl PQCKeyPair {
    /// Get the algorithm type for this key pair
    pub fn algorithm(&self) -> PQCKeyAlg {
        match self {
            PQCKeyPair::MlKem768(_) => PQCKeyAlg::MlKem768,
            PQCKeyPair::MlKem1024(_) => PQCKeyAlg::MlKem1024,
            PQCKeyPair::MlDsa65(_) => PQCKeyAlg::MlDsa65,
            PQCKeyPair::MlDsa87(_) => PQCKeyAlg::MlDsa87,
        }
    }

    /// Check if this is a key encapsulation mechanism
    pub fn is_kem(&self) -> bool {
        matches!(self, PQCKeyPair::MlKem768(_) | PQCKeyPair::MlKem1024(_))
    }

    /// Check if this is a digital signature algorithm
    pub fn is_signature(&self) -> bool {
        matches!(self, PQCKeyPair::MlDsa65(_) | PQCKeyPair::MlDsa87(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

    #[test]
    fn test_ml_kem_768_keypair() {
        let randomness = [0u8; 64];
        let keypair = MlKem768KeyPair::generate(randomness);

        assert_eq!(keypair.public_key().as_slice().len(), 1184);
        assert!(keypair.has_private_key());

        // Test encapsulation/decapsulation
        let encaps_randomness = [0u8; 32];
        let public_key = keypair.public_key();
        let (ciphertext, shared_secret) =
            MlKem768KeyPair::encapsulate(&public_key, encaps_randomness);
        let decapsulated = keypair.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret, decapsulated);
        assert_eq!(ciphertext.as_slice().len(), 1088);
        assert_eq!(shared_secret.len(), 32);
    }

    #[test]
    fn test_ml_dsa_65_keypair() {
        let keypair = MlDsa65KeyPair::generate();

        assert_eq!(keypair.public_key().as_bytes().len(), 1952);
        assert_eq!(keypair.secret_key().unwrap().as_bytes().len(), 4032);

        // Test signing/verification
        let message = b"Hello, post-quantum world!";
        let signature = keypair.sign(message).unwrap();

        assert_eq!(signature.as_bytes().len(), 3335);

        let verified_message = MlDsa65KeyPair::verify(&signature, keypair.public_key()).unwrap();
        assert_eq!(verified_message, message);
    }

    #[test]
    fn test_pqc_keypair_enum() {
        let ml_kem_pair = MlKem768KeyPair::generate([0u8; 64]);
        let pqc_pair = PQCKeyPair::MlKem768(ml_kem_pair);

        assert_eq!(pqc_pair.algorithm(), PQCKeyAlg::MlKem768);
        assert!(pqc_pair.is_kem());
        assert!(!pqc_pair.is_signature());

        let ml_dsa_pair = MlDsa65KeyPair::generate();
        let pqc_pair = PQCKeyPair::MlDsa65(ml_dsa_pair);

        assert_eq!(pqc_pair.algorithm(), PQCKeyAlg::MlDsa65);
        assert!(!pqc_pair.is_kem());
        assert!(pqc_pair.is_signature());
    }
}
