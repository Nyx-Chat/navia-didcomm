//! Post-Quantum JWS (JSON Web Signature) operations
//!
//! This module provides PQC-specific implementations for JSON Web Signature
//! using ML-DSA (Digital Signature Algorithm) from the Dilithium family.

use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    utils::pqc::{MlDsa65KeyPair, MlDsa87KeyPair},
};

use base64::prelude::*;
use pqcrypto_traits::sign::SignedMessage;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// PQC-specific JWS Algorithm enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
    #[serde(other)]
    Other,
}

/// PQC JWS Protected Header
#[derive(Debug, Serialize, Deserialize)]
pub struct ProtectedHeader<'a> {
    pub typ: Cow<'a, str>,
    pub alg: Algorithm,
}

/// PQC JWS Header
#[derive(Debug, Serialize, Deserialize)]
pub struct Header<'a> {
    pub kid: &'a str,
}

/// PQC JWS Signature
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature<'a> {
    pub header: Header<'a>,
    pub protected: &'a str,
    pub signature: &'a str,
}

/// PQC JWS structure (borrowed)
#[derive(Debug, Serialize, Deserialize)]
pub struct JWS<'a> {
    pub payload: &'a str,
    pub signatures: Vec<Signature<'a>>,
}

/// Owned PQC JWS structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWSOwned {
    pub payload: String,
    pub signatures: Vec<SignatureOwned>,
}

/// Owned PQC JWS Header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderOwned {
    pub kid: String,
}

/// Owned PQC JWS Signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureOwned {
    pub header: HeaderOwned,
    pub protected: String,
    pub signature: String,
}

/// Owned PQC JWS Protected Header
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtectedHeaderOwned {
    pub typ: String,
    pub alg: Algorithm,
}

/// Parsed PQC JWS
pub struct ParsedJWS {
    pub jws: JWSOwned,
    pub protected: Vec<ProtectedHeaderOwned>,
}

impl JWS<'_> {
    pub fn from_str(s: &str) -> Result<JWSOwned> {
        let jws: JWS<'_> = serde_json::from_str(s).map_err(move |e| {
            let msg = format!("Invalid JWS JSON: {e}");
            err_msg(ErrorKind::Malformed, msg)
        })?;

        // Convert borrowed JWS to owned
        Ok(JWSOwned {
            payload: jws.payload.to_string(),
            signatures: jws
                .signatures
                .into_iter()
                .map(|s| SignatureOwned {
                    header: HeaderOwned {
                        kid: s.header.kid.to_string(),
                    },
                    protected: s.protected.to_string(),
                    signature: s.signature.to_string(),
                })
                .collect(),
        })
    }

    #[allow(dead_code)]
    pub fn parse(&self, _buf: &mut [u8]) -> Result<ParsedJWS> {
        let mut protected = Vec::new();

        for signature in &self.signatures {
            let protected_bytes = BASE64_URL_SAFE_NO_PAD
                .decode(signature.protected)
                .kind(ErrorKind::Malformed, "Invalid base64 in protected header")?;

            let protected_header: ProtectedHeader<'_> = serde_json::from_slice(&protected_bytes)
                .kind(ErrorKind::Malformed, "Invalid protected header JSON")?;

            protected.push(ProtectedHeaderOwned {
                typ: protected_header.typ.to_string(),
                alg: protected_header.alg,
            });
        }

        // Convert to owned JWS
        let jws = JWSOwned {
            payload: self.payload.to_string(),
            signatures: self
                .signatures
                .iter()
                .map(|s| SignatureOwned {
                    header: HeaderOwned {
                        kid: s.header.kid.to_string(),
                    },
                    protected: s.protected.to_string(),
                    signature: s.signature.to_string(),
                })
                .collect(),
        };

        Ok(ParsedJWS { jws, protected })
    }
}

impl JWSOwned {
    #[allow(dead_code)]
    pub fn parse(&self, _buf: &mut [u8]) -> Result<ParsedJWS> {
        let mut protected = Vec::new();

        for signature in &self.signatures {
            let protected_bytes = BASE64_URL_SAFE_NO_PAD
                .decode(&signature.protected)
                .kind(ErrorKind::Malformed, "Invalid base64 in protected header")?;

            let protected_header: ProtectedHeader<'_> = serde_json::from_slice(&protected_bytes)
                .kind(ErrorKind::Malformed, "Invalid protected header JSON")?;

            protected.push(ProtectedHeaderOwned {
                typ: protected_header.typ.to_string(),
                alg: protected_header.alg,
            });
        }

        Ok(ParsedJWS {
            jws: self.clone(),
            protected,
        })
    }
}

/// Sign a message using ML-DSA-65 (Dilithium3)
pub(crate) fn sign_ml_dsa_65(
    payload: &[u8],
    kid: &str,
    key_pair: &MlDsa65KeyPair,
) -> Result<String> {
    sign_ml_dsa_65_with_typ(payload, kid, key_pair, "application/didcomm-signed+json")
}

/// Sign a message using ML-DSA-65 with custom typ parameter
pub(crate) fn sign_ml_dsa_65_with_typ(
    payload: &[u8],
    kid: &str,
    key_pair: &MlDsa65KeyPair,
    typ: &str,
) -> Result<String> {
    let protected = {
        let p = ProtectedHeader {
            typ: Cow::Borrowed(typ),
            alg: Algorithm::MlDsa65,
        };

        let p = serde_json::to_string(&p)
            .kind(ErrorKind::InvalidState, "Unable serialize protected header")?;

        BASE64_URL_SAFE_NO_PAD.encode(&p)
    };

    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(payload);

    let signature = {
        let sign_input = format!("{protected}.{payload_b64}");

        let signed_message = pqcrypto_dilithium::dilithium3::sign(
            sign_input.as_bytes(),
            key_pair.secret_key().unwrap(),
        );
        BASE64_URL_SAFE_NO_PAD.encode(signed_message.as_bytes())
    };

    let signature = Signature {
        header: Header { kid },
        protected: &protected,
        signature: &signature,
    };

    let jws = JWS {
        signatures: vec![signature],
        payload: &payload_b64,
    };

    serde_json::to_string(&jws).kind(ErrorKind::InvalidState, "Unable serialize JWS")
}

/// Sign a message using ML-DSA-87 (Dilithium5)
pub(crate) fn sign_ml_dsa_87(
    payload: &[u8],
    kid: &str,
    key_pair: &MlDsa87KeyPair,
) -> Result<String> {
    sign_ml_dsa_87_with_typ(payload, kid, key_pair, "application/didcomm-signed+json")
}

/// Sign a message using ML-DSA-87 with custom typ parameter
pub(crate) fn sign_ml_dsa_87_with_typ(
    payload: &[u8],
    kid: &str,
    key_pair: &MlDsa87KeyPair,
    typ: &str,
) -> Result<String> {
    let protected = {
        let p = ProtectedHeader {
            typ: Cow::Borrowed(typ),
            alg: Algorithm::MlDsa87,
        };

        let p = serde_json::to_string(&p)
            .kind(ErrorKind::InvalidState, "Unable serialize protected header")?;

        BASE64_URL_SAFE_NO_PAD.encode(&p)
    };

    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(payload);

    let signature = {
        let sign_input = format!("{protected}.{payload_b64}");

        let signed_message = pqcrypto_dilithium::dilithium5::sign(
            sign_input.as_bytes(),
            key_pair.secret_key().unwrap(),
        );
        BASE64_URL_SAFE_NO_PAD.encode(signed_message.as_bytes())
    };

    let signature = Signature {
        header: Header { kid },
        protected: &protected,
        signature: &signature,
    };

    let jws = JWS {
        signatures: vec![signature],
        payload: &payload_b64,
    };

    serde_json::to_string(&jws).kind(ErrorKind::InvalidState, "Unable serialize JWS")
}

/// Verify a ML-DSA-65 signature
pub(crate) fn verify_ml_dsa_65(
    signature: &[u8],
    message: &[u8],
    public_key: &pqcrypto_dilithium::dilithium3::PublicKey,
) -> Result<bool> {
    // Convert bytes to SignedMessage
    let signed_message = pqcrypto_dilithium::dilithium3::SignedMessage::from_bytes(signature)
        .map_err(|_| err_msg(ErrorKind::Malformed, "Invalid signature format"))?;
    match pqcrypto_dilithium::dilithium3::open(&signed_message, public_key) {
        Ok(verified_msg) => Ok(verified_msg == message),
        Err(_) => Ok(false),
    }
}

/// Verify a ML-DSA-87 signature
pub(crate) fn verify_ml_dsa_87(
    signature: &[u8],
    message: &[u8],
    public_key: &pqcrypto_dilithium::dilithium5::PublicKey,
) -> Result<bool> {
    // Convert bytes to SignedMessage
    let signed_message = pqcrypto_dilithium::dilithium5::SignedMessage::from_bytes(signature)
        .map_err(|_| err_msg(ErrorKind::Malformed, "Invalid signature format"))?;
    match pqcrypto_dilithium::dilithium5::open(&signed_message, public_key) {
        Ok(verified_msg) => Ok(verified_msg == message),
        Err(_) => Ok(false),
    }
}

/// Sign a message using ML-DSA-65 in compact format (for JWTs)
pub(crate) fn sign_ml_dsa_65_compact(
    payload: &[u8],
    key_pair: &MlDsa65KeyPair,
    typ: &str,
) -> Result<String> {
    let protected = {
        let p = ProtectedHeader {
            typ: Cow::Borrowed(typ),
            alg: Algorithm::MlDsa65,
        };

        let p = serde_json::to_string(&p)
            .kind(ErrorKind::InvalidState, "Unable serialize protected header")?;

        BASE64_URL_SAFE_NO_PAD.encode(&p)
    };

    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected}.{payload_b64}");

    let signature = pqcrypto_dilithium::dilithium3::sign(
        signing_input.as_bytes(),
        key_pair.secret_key().unwrap(),
    );
    let signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.as_bytes());

    Ok(format!("{protected}.{payload_b64}.{signature_b64}"))
}

/// Sign a message using ML-DSA-87 in compact format (for JWTs)
pub(crate) fn sign_ml_dsa_87_compact(
    payload: &[u8],
    key_pair: &MlDsa87KeyPair,
    typ: &str,
) -> Result<String> {
    let protected = {
        let p = ProtectedHeader {
            typ: Cow::Borrowed(typ),
            alg: Algorithm::MlDsa87,
        };

        let p = serde_json::to_string(&p)
            .kind(ErrorKind::InvalidState, "Unable serialize protected header")?;

        BASE64_URL_SAFE_NO_PAD.encode(&p)
    };

    let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected}.{payload_b64}");

    let signature = pqcrypto_dilithium::dilithium5::sign(
        signing_input.as_bytes(),
        key_pair.secret_key().unwrap(),
    );
    let signature_b64 = BASE64_URL_SAFE_NO_PAD.encode(signature.as_bytes());

    Ok(format!("{protected}.{payload_b64}.{signature_b64}"))
}

/// Parse compact JWS format (header.payload.signature)
pub(crate) fn parse_compact(compact_jws: &str) -> Result<(ProtectedHeaderOwned, String, String)> {
    let parts: Vec<&str> = compact_jws.split('.').collect();
    if parts.len() != 3 {
        return Err(err_msg(ErrorKind::Malformed, "Invalid compact JWS format"));
    }

    let protected_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(parts[0])
        .kind(ErrorKind::Malformed, "Invalid base64 in protected header")?;

    let protected_header: ProtectedHeader<'_> = serde_json::from_slice(&protected_bytes)
        .kind(ErrorKind::Malformed, "Invalid protected header JSON")?;

    let protected = ProtectedHeaderOwned {
        typ: protected_header.typ.to_string(),
        alg: protected_header.alg,
    };

    Ok((protected, parts[1].to_string(), parts[2].to_string()))
}
