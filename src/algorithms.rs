use serde::{Deserialize, Serialize};

/// Algorithms for anonymous encryption
#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[derive(Default)]
pub enum AnonCryptAlg {
    /// AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    A256cbcHs512EcdhEsA256kw,

    /// XChaCha20Poly1305 with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    #[default]
    Xc20pEcdhEsA256kw,

    /// A256GCM_ECDH_ES_A256KW: XChaCha20Poly1305 with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    A256gcmEcdhEsA256kw,
}


#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[derive(Default)]
/// Authentication encryption algorithms for DIDComm messages.
/// 
/// These algorithms provide both encryption and sender authentication,
/// ensuring that the recipient can verify the sender's identity while
/// maintaining message confidentiality.
pub enum AuthCryptAlg {
    /// AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-1PU key agreement with A256KW key wrapping
    #[default]
    A256cbcHs512Ecdh1puA256kw,
}


#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
/// Digital signature algorithms for DIDComm messages.
/// 
/// These algorithms are used to create and verify digital signatures
/// on DIDComm messages, providing non-repudiation and message integrity.
pub enum SignAlg {
    /// EdDSA signature algorithm using Ed25519 curve
    EdDSA,
    /// ECDSA signature algorithm using P-256 curve  
    ES256,
    /// ECDSA signature algorithm using secp256k1 curve
    ES256K,
}
