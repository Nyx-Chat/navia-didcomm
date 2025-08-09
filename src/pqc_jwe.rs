//! Post-Quantum JWE (JSON Web Encryption) operations
//!
//! This module provides PQC-specific implementations for JSON Web Encryption
//! using ML-KEM (key encapsulation mechanism) instead of ECDH key agreement.

use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    utils::{
        crypto::KeyWrap,
        pqc::{MlKem1024KeyPair, MlKem768KeyPair},
    },
};

use askar_crypto::{
    alg::aes::{A256Kw, AesKey},
    buffer::SecretBytes,
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    random,
    repr::{KeyGen, KeySecretBytes, ToSecretBytes},
};

use base64::prelude::*;
use pqcrypto_traits::sign::SignedMessage;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Derive a key-wrapping key from ML-KEM shared secret using HKDF-like derivation
/// This follows the general pattern of deriving KEK (Key Encryption Key) from shared secret
fn derive_kek_from_shared_secret(
    shared_secret: &[u8; 32],
    alg: &str,
    apu: &[u8],
    apv: &[u8],
) -> Result<AesKey<A256Kw>> {
    use sha2::{Digest, Sha256};

    // Create key derivation context similar to JOSE Concat KDF
    let mut hasher = Sha256::new();

    // Add the shared secret as primary material
    hasher.update(shared_secret);

    // Add algorithm identifier
    hasher.update((alg.len() as u32).to_be_bytes());
    hasher.update(alg.as_bytes());

    // Add APU (Agreement PartyUInfo) - optional sender info
    hasher.update((apu.len() as u32).to_be_bytes());
    hasher.update(apu);

    // Add APV (Agreement PartyVInfo) - recipient info
    hasher.update((apv.len() as u32).to_be_bytes());
    hasher.update(apv);

    // Add key length for A256KW (256 bits = 32 bytes)
    hasher.update(32u32.to_be_bytes());

    // Derive KEK using SHA256 (produces exactly 32 bytes for AES-256)
    let kek_bytes = hasher.finalize();

    AesKey::<A256Kw>::from_secret_bytes(&kek_bytes).kind(
        ErrorKind::InvalidState,
        "Unable to create AES-256 key from derived KEK",
    )
}
use std::borrow::Cow;

/// PQC JWE Algorithm enum  
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "ML-KEM768")]
    MlKem768,
    #[serde(rename = "ML-KEM1024")]
    MlKem1024,
    #[serde(rename = "ML-KEM768+ML-DSA65")]
    MlKem768MlDsa65,
    #[serde(rename = "ML-KEM1024+ML-DSA87")]
    MlKem1024MlDsa87,
    #[serde(other)]
    Other,
}

impl Algorithm {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        match self {
            Algorithm::MlKem768 => "ML-KEM768",
            Algorithm::MlKem1024 => "ML-KEM1024",
            Algorithm::MlKem768MlDsa65 => "ML-KEM768+ML-DSA65",
            Algorithm::MlKem1024MlDsa87 => "ML-KEM1024+ML-DSA87",
            Algorithm::Other => "Other",
        }
    }
}

/// PQC JWE Encryption Algorithm enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncAlgorithm {
    #[serde(rename = "A256CBC-HS512")]
    A256cbcHs512,
    #[serde(rename = "XC20P")]
    Xc20P,
    #[serde(rename = "A256GCM")]
    A256Gcm,
    #[serde(other)]
    Other,
}

/// PQC JWE Protected Header
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProtectedHeader<'a> {
    pub typ: Option<Cow<'a, str>>,
    pub alg: Algorithm,
    pub enc: EncAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apu: Option<&'a str>,
    pub apv: &'a str,
    pub epk: Value,
}

/// PQC JWE Per-Recipient Header
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PerRecipientHeader<'a> {
    pub kid: &'a str,
}

/// PQC JWE Recipient
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Recipient<'a> {
    pub header: PerRecipientHeader<'a>,
    pub encrypted_key: &'a str,
}

/// PQC JWE structure (borrowed)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JWE<'a> {
    pub protected: &'a str,
    pub recipients: Vec<Recipient<'a>>,
    pub iv: &'a str,
    pub ciphertext: &'a str,
    pub tag: &'a str,
}

/// Owned PQC JWE structure
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JWEOwned {
    pub protected: String,
    pub recipients: Vec<RecipientOwned>,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

/// Owned PQC JWE Per-Recipient Header
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PerRecipientHeaderOwned {
    pub kid: String,
}

/// Owned PQC JWE Recipient
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RecipientOwned {
    pub header: PerRecipientHeaderOwned,
    pub encrypted_key: String,
}

/// Parsed PQC JWE
pub struct ParsedJWE {
    pub jwe: JWEOwned,
    pub protected: ProtectedHeaderOwned,
    pub apu: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub apv: Vec<u8>,
}

/// Owned version of ProtectedHeader to avoid lifetime issues
#[derive(Debug, Clone)]
pub struct ProtectedHeaderOwned {
    #[allow(dead_code)]
    pub typ: Option<String>,
    pub alg: Algorithm,
    pub enc: EncAlgorithm,
    #[allow(dead_code)]
    pub skid: Option<String>,
    pub apu: Option<String>,
    pub apv: String,
    #[allow(dead_code)]
    pub epk: serde_json::Value,
}

impl JWE<'_> {
    pub fn from_str(s: &str) -> Result<JWEOwned> {
        let jwe: JWE<'_> = serde_json::from_str(s).map_err(move |e| {
            let msg = format!("Invalid JWE JSON: {e}");
            err_msg(ErrorKind::Malformed, msg)
        })?;

        // Convert borrowed JWE to owned
        Ok(JWEOwned {
            protected: jwe.protected.to_string(),
            recipients: jwe
                .recipients
                .into_iter()
                .map(|r| RecipientOwned {
                    header: PerRecipientHeaderOwned {
                        kid: r.header.kid.to_string(),
                    },
                    encrypted_key: r.encrypted_key.to_string(),
                })
                .collect(),
            iv: jwe.iv.to_string(),
            ciphertext: jwe.ciphertext.to_string(),
            tag: jwe.tag.to_string(),
        })
    }

    #[allow(dead_code)]
    pub fn parse(&self, _buf: &mut [u8]) -> Result<ParsedJWE> {
        let protected_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(self.protected)
            .kind(ErrorKind::Malformed, "Invalid base64 in protected header")?;

        let protected_header: ProtectedHeader<'_> = serde_json::from_slice(&protected_bytes)
            .kind(ErrorKind::Malformed, "Invalid protected header JSON")?;

        let protected = ProtectedHeaderOwned {
            typ: protected_header.typ.map(|s| s.to_string()),
            alg: protected_header.alg,
            enc: protected_header.enc,
            skid: protected_header.skid.map(|s| s.to_string()),
            apu: protected_header.apu.map(|s| s.to_string()),
            apv: protected_header.apv.to_string(),
            epk: protected_header.epk,
        };

        let apu = protected
            .apu
            .as_ref()
            .map(|apu| {
                BASE64_URL_SAFE_NO_PAD
                    .decode(apu)
                    .kind(ErrorKind::Malformed, "Invalid base64 in apu")
            })
            .transpose()?;

        let apv = BASE64_URL_SAFE_NO_PAD
            .decode(&protected.apv)
            .kind(ErrorKind::Malformed, "Invalid base64 in apv")?;

        // Convert to owned JWE
        let jwe = JWEOwned {
            protected: self.protected.to_string(),
            recipients: self
                .recipients
                .iter()
                .map(|r| RecipientOwned {
                    header: PerRecipientHeaderOwned {
                        kid: r.header.kid.to_string(),
                    },
                    encrypted_key: r.encrypted_key.to_string(),
                })
                .collect(),
            iv: self.iv.to_string(),
            ciphertext: self.ciphertext.to_string(),
            tag: self.tag.to_string(),
        };

        Ok(ParsedJWE {
            jwe,
            protected,
            apu,
            apv,
        })
    }
}

impl JWEOwned {
    #[allow(dead_code)]
    pub fn parse(&self, _buf: &mut [u8]) -> Result<ParsedJWE> {
        let protected_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&self.protected)
            .kind(ErrorKind::Malformed, "Invalid base64 in protected header")?;

        let protected_header: ProtectedHeader<'_> = serde_json::from_slice(&protected_bytes)
            .kind(ErrorKind::Malformed, "Invalid protected header JSON")?;

        let protected = ProtectedHeaderOwned {
            typ: protected_header.typ.map(|s| s.to_string()),
            alg: protected_header.alg,
            enc: protected_header.enc,
            skid: protected_header.skid.map(|s| s.to_string()),
            apu: protected_header.apu.map(|s| s.to_string()),
            apv: protected_header.apv.to_string(),
            epk: protected_header.epk,
        };

        let apu = protected
            .apu
            .as_ref()
            .map(|apu| {
                BASE64_URL_SAFE_NO_PAD
                    .decode(apu)
                    .kind(ErrorKind::Malformed, "Invalid base64 in apu")
            })
            .transpose()?;

        let apv = BASE64_URL_SAFE_NO_PAD
            .decode(&protected.apv)
            .kind(ErrorKind::Malformed, "Invalid base64 in apv")?;

        Ok(ParsedJWE {
            jwe: self.clone(),
            protected,
            apu,
            apv,
        })
    }
}

impl ParsedJWE {
    /// Verify DIDComm-specific JWE requirements
    pub fn verify_didcomm(self) -> Result<ParsedJWE> {
        // Verify required DIDComm JWE fields
        if let Some(ref typ) = self.protected.typ {
            if typ != "application/didcomm-encrypted+json" {
                return Err(err_msg(
                    ErrorKind::Malformed,
                    "Invalid DIDComm JWE typ header",
                ));
            }
        }

        // Verify PQC algorithms are supported
        if !matches!(
            self.protected.alg,
            Algorithm::MlKem768
                | Algorithm::MlKem1024
                | Algorithm::MlKem768MlDsa65
                | Algorithm::MlKem1024MlDsa87
        ) {
            return Err(err_msg(ErrorKind::Unsupported, "Unsupported PQC algorithm"));
        }

        // Verify encryption algorithm is supported
        if !matches!(
            self.protected.enc,
            EncAlgorithm::A256cbcHs512 | EncAlgorithm::Xc20P | EncAlgorithm::A256Gcm
        ) {
            return Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported encryption algorithm",
            ));
        }

        Ok(self)
    }
}

/// ML-KEM-768 based JWE encryption for anonymous cryptography
pub(crate) fn encrypt_anon_ml_kem_768<CE>(
    plaintext: &[u8],
    enc: EncAlgorithm,
    recipients: &[(&str, &libcrux_ml_kem::MlKemPublicKey<1184>)], // (kid, public_key)
) -> Result<String>
where
    CE: KeyAeadInPlace + KeyAeadMeta + KeyGen + ToSecretBytes,
{
    let mut rng = random::default_rng();
    let cek = CE::generate(&mut rng).kind(ErrorKind::InvalidState, "Unable generate cek")?;

    let apv = {
        let mut kids = recipients.iter().map(|r| r.0).collect::<Vec<_>>();
        kids.sort();
        Sha256::digest(kids.join(".").as_bytes())
    };

    let protected = {
        let apv = BASE64_URL_SAFE_NO_PAD.encode(apv);

        let p = ProtectedHeader {
            typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
            alg: Algorithm::MlKem768,
            enc,
            skid: None,
            apu: None,
            apv: &apv,
            epk: serde_json::json!({}), // ML-KEM doesn't need EPK
        };

        let p = serde_json::to_string(&p)
            .kind(ErrorKind::InvalidState, "Unable serialize protected header")?;

        BASE64_URL_SAFE_NO_PAD.encode(&p)
    };

    let mut buf = {
        let mut buf = SecretBytes::with_capacity(plaintext.len() + cek.aead_params().tag_length);
        buf.extend_from_slice(plaintext);
        buf
    };

    let (ciphertext, tag, iv) = {
        let iv = CE::random_nonce();

        let ciphertext_len = cek
            .encrypt_in_place(&mut buf, &iv[..], protected.as_bytes())
            .kind(ErrorKind::InvalidState, "Unable encrypt content")?;

        let ciphertext = &buf.as_ref()[0..ciphertext_len];
        let tag_raw = &buf.as_ref()[ciphertext_len..];

        let ciphertext = BASE64_URL_SAFE_NO_PAD.encode(ciphertext);
        let tag = BASE64_URL_SAFE_NO_PAD.encode(tag_raw);
        let iv = BASE64_URL_SAFE_NO_PAD.encode(&iv);

        (ciphertext, tag, iv)
    };

    let encrypted_keys = {
        let mut encrypted_keys: Vec<(&str, String)> = Vec::with_capacity(recipients.len());

        for (kid, public_key) in recipients {
            // Use ML-KEM-768 encapsulation with proper randomness
            let mut randomness = [0u8; 32];
            random::fill_random(&mut randomness);
            let (kem_ciphertext, shared_secret) =
                libcrux_ml_kem::mlkem768::encapsulate(public_key, randomness);

            // Derive key-wrapping key from shared secret
            let kek = derive_kek_from_shared_secret(&shared_secret, "ML-KEM768+A256KW", &[], &apv)?;

            // Wrap the CEK using the derived key-wrapping key
            let wrapped_cek = kek.wrap_key(&cek)?;

            // Combine KEM ciphertext + wrapped CEK
            let mut encrypted_key_bytes = Vec::new();
            encrypted_key_bytes.extend_from_slice(kem_ciphertext.as_slice());
            encrypted_key_bytes.extend_from_slice(wrapped_cek.as_ref());

            let encrypted_key = BASE64_URL_SAFE_NO_PAD.encode(&encrypted_key_bytes);
            encrypted_keys.push((kid, encrypted_key));
        }

        encrypted_keys
    };

    let recipients: Vec<_> = encrypted_keys
        .iter()
        .map(|(kid, encrypted_key)| Recipient {
            header: PerRecipientHeader { kid },
            encrypted_key,
        })
        .collect();

    let jwe = JWE {
        protected: &protected,
        recipients,
        iv: &iv,
        ciphertext: &ciphertext,
        tag: &tag,
    };

    serde_json::to_string(&jwe).kind(ErrorKind::InvalidState, "Unable serialize jwe")
}

/// ML-KEM-1024 based JWE encryption for anonymous cryptography
pub(crate) fn encrypt_anon_ml_kem_1024<CE>(
    plaintext: &[u8],
    enc: EncAlgorithm,
    recipients: &[(&str, &libcrux_ml_kem::MlKemPublicKey<1568>)], // (kid, public_key)
) -> Result<String>
where
    CE: KeyAeadInPlace + KeyAeadMeta + KeyGen + ToSecretBytes,
{
    let mut rng = random::default_rng();
    let cek = CE::generate(&mut rng).kind(ErrorKind::InvalidState, "Unable generate cek")?;

    let apv = {
        let mut kids = recipients.iter().map(|r| r.0).collect::<Vec<_>>();
        kids.sort();
        Sha256::digest(kids.join(".").as_bytes())
    };

    let protected = {
        let apv = BASE64_URL_SAFE_NO_PAD.encode(apv);

        let p = ProtectedHeader {
            typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
            alg: Algorithm::MlKem1024,
            enc,
            skid: None,
            apu: None,
            apv: &apv,
            epk: serde_json::json!({}), // ML-KEM doesn't need EPK
        };

        let p = serde_json::to_string(&p)
            .kind(ErrorKind::InvalidState, "Unable serialize protected header")?;

        BASE64_URL_SAFE_NO_PAD.encode(&p)
    };

    let mut buf = {
        let mut buf = SecretBytes::with_capacity(plaintext.len() + cek.aead_params().tag_length);
        buf.extend_from_slice(plaintext);
        buf
    };

    let (ciphertext, tag, iv) = {
        let iv = CE::random_nonce();

        let ciphertext_len = cek
            .encrypt_in_place(&mut buf, &iv[..], protected.as_bytes())
            .kind(ErrorKind::InvalidState, "Unable encrypt content")?;

        let ciphertext = &buf.as_ref()[0..ciphertext_len];
        let tag_raw = &buf.as_ref()[ciphertext_len..];

        let ciphertext = BASE64_URL_SAFE_NO_PAD.encode(ciphertext);
        let tag = BASE64_URL_SAFE_NO_PAD.encode(tag_raw);
        let iv = BASE64_URL_SAFE_NO_PAD.encode(&iv);

        (ciphertext, tag, iv)
    };

    let encrypted_keys = {
        let mut encrypted_keys: Vec<(&str, String)> = Vec::with_capacity(recipients.len());

        for (kid, public_key) in recipients {
            // Use ML-KEM-1024 encapsulation with proper randomness
            let mut randomness = [0u8; 32];
            random::fill_random(&mut randomness);
            let (kem_ciphertext, shared_secret) =
                libcrux_ml_kem::mlkem1024::encapsulate(public_key, randomness);

            // Derive key-wrapping key from shared secret
            let kek =
                derive_kek_from_shared_secret(&shared_secret, "ML-KEM1024+A256KW", &[], &apv)?;

            // Wrap the CEK using the derived key-wrapping key
            let wrapped_cek = kek.wrap_key(&cek)?;

            // Combine KEM ciphertext + wrapped CEK
            let mut encrypted_key_bytes = Vec::new();
            encrypted_key_bytes.extend_from_slice(kem_ciphertext.as_slice());
            encrypted_key_bytes.extend_from_slice(wrapped_cek.as_ref());

            let encrypted_key = BASE64_URL_SAFE_NO_PAD.encode(&encrypted_key_bytes);
            encrypted_keys.push((kid, encrypted_key));
        }

        encrypted_keys
    };

    let recipients: Vec<_> = encrypted_keys
        .iter()
        .map(|(kid, encrypted_key)| Recipient {
            header: PerRecipientHeader { kid },
            encrypted_key,
        })
        .collect();

    let jwe = JWE {
        protected: &protected,
        recipients,
        iv: &iv,
        ciphertext: &ciphertext,
        tag: &tag,
    };

    serde_json::to_string(&jwe).kind(ErrorKind::InvalidState, "Unable serialize jwe")
}

// AnonCrypt Decrypt Functions

pub(crate) fn decrypt_anon_ml_kem_768<CE>(
    jwe_encrypted_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    protected: &str,
    _recipient_kid: &str,
    recipient_key: &MlKem768KeyPair,
) -> crate::error::Result<Vec<u8>>
where
    CE: KeyAeadInPlace + KeySecretBytes,
{
    // Parse protected header to get APV
    let protected_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(protected)
        .kind(ErrorKind::Malformed, "Invalid base64 in protected header")?;
    let protected_header: ProtectedHeader<'_> = serde_json::from_slice(&protected_bytes)
        .kind(ErrorKind::Malformed, "Invalid protected header JSON")?;
    let apv_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(protected_header.apv)
        .kind(ErrorKind::Malformed, "Invalid base64 in apv")?;

    // Split encrypted key into KEM ciphertext (1088 bytes) + wrapped CEK (rest)
    if jwe_encrypted_key.len() < 1088 {
        return Err(err_msg(
            ErrorKind::Malformed,
            "Encrypted key too short for ML-KEM-768",
        ));
    }

    let (kem_ciphertext_bytes, wrapped_cek_bytes) = jwe_encrypted_key.split_at(1088);

    // Decode the ML-KEM ciphertext
    let kem_ciphertext =
        libcrux_ml_kem::mlkem768::MlKem768Ciphertext::try_from(kem_ciphertext_bytes)
            .map_err(|_| err_msg(ErrorKind::Malformed, "Invalid ML-KEM-768 ciphertext"))?;

    // Decapsulate to get shared secret using the key pair's method
    let shared_secret = recipient_key.decapsulate(&kem_ciphertext)?;

    // Derive key-wrapping key from shared secret
    let kek = derive_kek_from_shared_secret(&shared_secret, "ML-KEM768+A256KW", &[], &apv_bytes)?;

    // Unwrap the CEK
    let cek: CE = kek.unwrap_key(wrapped_cek_bytes)?;

    // Decrypt the actual content using the unwrapped CEK
    let mut buf = SecretBytes::from_slice(ciphertext);
    buf.extend_from_slice(tag);

    cek.decrypt_in_place(&mut buf, iv, protected.as_bytes())
        .kind(ErrorKind::Malformed, "Unable to decrypt JWE content")?;

    // After decrypt_in_place, the buffer contains only the plaintext
    // The tag has been consumed/validated during decryption
    Ok(buf.as_ref().to_vec())
}

pub(crate) fn decrypt_anon_ml_kem_1024<CE>(
    jwe_encrypted_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    protected: &str,
    _recipient_kid: &str,
    recipient_key: &MlKem1024KeyPair,
) -> crate::error::Result<Vec<u8>>
where
    CE: KeyAeadInPlace + KeySecretBytes,
{
    // Parse protected header to get APV
    let protected_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(protected)
        .kind(ErrorKind::Malformed, "Invalid base64 in protected header")?;
    let protected_header: ProtectedHeader<'_> = serde_json::from_slice(&protected_bytes)
        .kind(ErrorKind::Malformed, "Invalid protected header JSON")?;
    let apv_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(protected_header.apv)
        .kind(ErrorKind::Malformed, "Invalid base64 in apv")?;

    // Split encrypted key into KEM ciphertext (1568 bytes) + wrapped CEK (rest)
    if jwe_encrypted_key.len() < 1568 {
        return Err(err_msg(
            ErrorKind::Malformed,
            "Encrypted key too short for ML-KEM-1024",
        ));
    }

    let (kem_ciphertext_bytes, wrapped_cek_bytes) = jwe_encrypted_key.split_at(1568);

    // Decode the ML-KEM ciphertext
    let kem_ciphertext =
        libcrux_ml_kem::mlkem1024::MlKem1024Ciphertext::try_from(kem_ciphertext_bytes)
            .map_err(|_| err_msg(ErrorKind::Malformed, "Invalid ML-KEM-1024 ciphertext"))?;

    // Decapsulate to get shared secret using the key pair's method
    let shared_secret = recipient_key.decapsulate(&kem_ciphertext)?;

    // Derive key-wrapping key from shared secret
    let kek = derive_kek_from_shared_secret(&shared_secret, "ML-KEM1024+A256KW", &[], &apv_bytes)?;

    // Unwrap the CEK
    let cek: CE = kek.unwrap_key(wrapped_cek_bytes)?;

    // Decrypt the actual content using the unwrapped CEK
    let mut buf = SecretBytes::from_slice(ciphertext);
    buf.extend_from_slice(tag);

    cek.decrypt_in_place(&mut buf, iv, protected.as_bytes())
        .kind(ErrorKind::Malformed, "Unable to decrypt JWE content")?;

    // After decrypt_in_place, the buffer contains only the plaintext
    // The tag has been consumed/validated during decryption
    Ok(buf.as_ref().to_vec())
}

// AuthCrypt Decrypt Functions

pub(crate) fn decrypt_auth_ml_kem_768_dsa_65<CE>(
    jwe_encrypted_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    protected: &str,
    sender_id: &str,
    _recipient_kid: &str,
    sender_public_key: &pqcrypto_dilithium::dilithium3::PublicKey,
    recipient_key: &MlKem768KeyPair,
) -> crate::error::Result<Vec<u8>>
where
    CE: KeyAeadInPlace + KeySecretBytes,
{
    use pqcrypto_traits::sign::SignedMessage;

    // Parse protected header to get APU and APV
    let protected_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(protected)
        .kind(ErrorKind::Malformed, "Invalid base64 in protected header")?;
    let protected_header: ProtectedHeader<'_> = serde_json::from_slice(&protected_bytes)
        .kind(ErrorKind::Malformed, "Invalid protected header JSON")?;

    let apu_bytes = if let Some(apu) = protected_header.apu {
        BASE64_URL_SAFE_NO_PAD
            .decode(apu)
            .kind(ErrorKind::Malformed, "Invalid base64 in apu")?
    } else {
        vec![]
    };

    let apv_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(protected_header.apv)
        .kind(ErrorKind::Malformed, "Invalid base64 in apv")?;

    // AuthCrypt format: [ML-KEM ciphertext] + [ML-DSA signature] + [wrapped CEK]
    // ML-KEM-768 ciphertext is 1088 bytes, wrapped CEK is 40 bytes (32-byte key + 8-byte auth tag)
    const KEM_CIPHERTEXT_LEN: usize = 1088;
    const WRAPPED_CEK_LEN: usize = 40; // AES-256 key (32 bytes) + AES-KW auth tag (8 bytes)

    if jwe_encrypted_key.len() < KEM_CIPHERTEXT_LEN + WRAPPED_CEK_LEN {
        return Err(err_msg(
            ErrorKind::Malformed,
            "Encrypted key too short for AuthCrypt ML-KEM-768+ML-DSA-65",
        ));
    }

    // Split the encrypted key into components (parse backwards from known fixed sizes)
    let (kem_ciphertext_bytes, rest) = jwe_encrypted_key.split_at(KEM_CIPHERTEXT_LEN);
    let signature_len = rest.len() - WRAPPED_CEK_LEN;
    let (signature_bytes, wrapped_cek_bytes) = rest.split_at(signature_len);

    // Decode the ML-KEM ciphertext
    let kem_ciphertext =
        libcrux_ml_kem::mlkem768::MlKem768Ciphertext::try_from(kem_ciphertext_bytes)
            .map_err(|_| err_msg(ErrorKind::Malformed, "Invalid ML-KEM-768 ciphertext"))?;

    // Decapsulate to get shared secret
    let shared_secret = recipient_key.decapsulate(&kem_ciphertext)?;

    // Create the signed message for verification (sender_id + recipient_id + shared_secret)
    // This must match what was signed during encryption: from_kid + "|" + recipient_kid + "|" + shared_secret
    let mut message_to_verify = Vec::new();
    message_to_verify.extend_from_slice(sender_id.as_bytes());
    message_to_verify.extend_from_slice(b"|"); // separator
    message_to_verify.extend_from_slice(_recipient_kid.as_bytes()); // recipient kid (not APV!)
    message_to_verify.extend_from_slice(b"|"); // separator
    message_to_verify.extend_from_slice(&shared_secret);

    // Create ML-DSA signed message object for verification
    let signed_message = pqcrypto_dilithium::dilithium3::SignedMessage::from_bytes(signature_bytes)
        .map_err(|_| err_msg(ErrorKind::Malformed, "Invalid ML-DSA-65 signature format"))?;

    // Verify the signature
    let verified_message = pqcrypto_dilithium::dilithium3::open(&signed_message, sender_public_key)
        .map_err(|_| {
            err_msg(
                ErrorKind::SignatureVerificationFailed,
                "ML-DSA-65 signature verification failed",
            )
        })?;

    // Ensure the verified message matches what we expect
    if verified_message != message_to_verify {
        return Err(err_msg(
            ErrorKind::SignatureVerificationFailed,
            "AuthCrypt message verification failed",
        ));
    }

    // Derive key-wrapping key from shared secret (include sender info for AuthCrypt)
    let kek = derive_kek_from_shared_secret(
        &shared_secret,
        "ML-KEM768+ML-DSA65+A256KW",
        &apu_bytes,
        &apv_bytes,
    )?;

    // Unwrap the CEK
    let cek: CE = kek.unwrap_key(wrapped_cek_bytes)?;

    // Decrypt the actual content using the unwrapped CEK
    // For AES-GCM with decrypt_in_place, we need to provide ciphertext + tag as input
    let mut buf = SecretBytes::from_slice(ciphertext);
    buf.extend_from_slice(tag);

    cek.decrypt_in_place(&mut buf, iv, protected.as_bytes())
        .kind(ErrorKind::Malformed, "Unable to decrypt JWE content")?;

    // After decrypt_in_place, the buffer contains only the plaintext
    // The tag has been consumed/validated during decryption
    let decrypted_result = buf.as_ref().to_vec();

    Ok(decrypted_result)
}

pub(crate) fn decrypt_auth_ml_kem_1024_dsa_87<CE>(
    jwe_encrypted_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    protected: &str,
    sender_id: &str,
    _recipient_kid: &str,
    sender_public_key: &pqcrypto_dilithium::dilithium5::PublicKey,
    recipient_key: &MlKem1024KeyPair,
) -> crate::error::Result<Vec<u8>>
where
    CE: KeyAeadInPlace + KeySecretBytes,
{
    use pqcrypto_traits::sign::SignedMessage;

    // Parse protected header to get APU and APV
    let protected_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(protected)
        .kind(ErrorKind::Malformed, "Invalid base64 in protected header")?;
    let protected_header: ProtectedHeader<'_> = serde_json::from_slice(&protected_bytes)
        .kind(ErrorKind::Malformed, "Invalid protected header JSON")?;

    let apu_bytes = if let Some(apu) = protected_header.apu {
        BASE64_URL_SAFE_NO_PAD
            .decode(apu)
            .kind(ErrorKind::Malformed, "Invalid base64 in apu")?
    } else {
        vec![]
    };

    let apv_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(protected_header.apv)
        .kind(ErrorKind::Malformed, "Invalid base64 in apv")?;

    // AuthCrypt format: [ML-KEM ciphertext] + [ML-DSA signature] + [wrapped CEK]
    // ML-KEM-1024 ciphertext is 1568 bytes, wrapped CEK is 40 bytes (32-byte key + 8-byte auth tag)
    const KEM_CIPHERTEXT_LEN: usize = 1568;
    const WRAPPED_CEK_LEN: usize = 40; // AES-256 key (32 bytes) + AES-KW auth tag (8 bytes)

    if jwe_encrypted_key.len() < KEM_CIPHERTEXT_LEN + WRAPPED_CEK_LEN {
        return Err(err_msg(
            ErrorKind::Malformed,
            "Encrypted key too short for AuthCrypt ML-KEM-1024+ML-DSA-87",
        ));
    }

    // Split the encrypted key into components using dynamic parsing
    // Format: [ML-KEM ciphertext] + [ML-DSA signature] + [wrapped CEK]
    // We know KEM ciphertext (1568) and wrapped CEK (40) lengths, signature is the remainder
    let (kem_ciphertext_bytes, rest) = jwe_encrypted_key.split_at(KEM_CIPHERTEXT_LEN);
    let signature_len = rest.len() - WRAPPED_CEK_LEN;
    let (signature_bytes, wrapped_cek_bytes) = rest.split_at(signature_len);

    // Decode the ML-KEM ciphertext
    let kem_ciphertext =
        libcrux_ml_kem::mlkem1024::MlKem1024Ciphertext::try_from(kem_ciphertext_bytes)
            .map_err(|_| err_msg(ErrorKind::Malformed, "Invalid ML-KEM-1024 ciphertext"))?;

    // Decapsulate to get shared secret
    let shared_secret = recipient_key.decapsulate(&kem_ciphertext)?;

    // Create the signed message for verification (sender_id + recipient_id + shared_secret)
    // This must match what was signed during encryption: from_kid + "|" + recipient_kid + "|" + shared_secret
    let mut message_to_verify = Vec::new();
    message_to_verify.extend_from_slice(sender_id.as_bytes());
    message_to_verify.extend_from_slice(b"|"); // separator
    message_to_verify.extend_from_slice(_recipient_kid.as_bytes()); // recipient kid (not APV!)
    message_to_verify.extend_from_slice(b"|"); // separator
    message_to_verify.extend_from_slice(&shared_secret);

    // Create ML-DSA signed message object for verification
    let signed_message = pqcrypto_dilithium::dilithium5::SignedMessage::from_bytes(signature_bytes)
        .map_err(|_| err_msg(ErrorKind::Malformed, "Invalid ML-DSA-87 signature format"))?;

    // Verify the signature
    let verified_message = pqcrypto_dilithium::dilithium5::open(&signed_message, sender_public_key)
        .map_err(|_| {
            err_msg(
                ErrorKind::SignatureVerificationFailed,
                "ML-DSA-87 signature verification failed",
            )
        })?;

    // Ensure the verified message matches what we expect
    if verified_message != message_to_verify {
        return Err(err_msg(
            ErrorKind::SignatureVerificationFailed,
            "AuthCrypt message verification failed",
        ));
    }

    // Derive key-wrapping key from shared secret (include sender info for AuthCrypt)
    let kek = derive_kek_from_shared_secret(
        &shared_secret,
        "ML-KEM1024+ML-DSA87+A256KW",
        &apu_bytes,
        &apv_bytes,
    )?;

    // Unwrap the CEK
    let cek: CE = kek.unwrap_key(wrapped_cek_bytes)?;

    // Decrypt the actual content using the unwrapped CEK
    // For AES-GCM with decrypt_in_place, we need to provide ciphertext + tag as input
    let mut buf = SecretBytes::from_slice(ciphertext);
    buf.extend_from_slice(tag);

    cek.decrypt_in_place(&mut buf, iv, protected.as_bytes())
        .kind(ErrorKind::Malformed, "Unable to decrypt JWE content")?;

    // After decrypt_in_place, the buffer contains only the plaintext
    // The tag has been consumed/validated during decryption
    Ok(buf.as_ref().to_vec())
}

// Missing encrypt functions for AuthCrypt

pub(crate) fn encrypt_auth_ml_kem_768_dsa_65<CE>(
    plaintext: &[u8],
    enc: EncAlgorithm,
    from_kid: &str,
    _sender_key_pair: &crate::utils::pqc::MlDsa65KeyPair,
    recipients: &[(&str, &libcrux_ml_kem::MlKemPublicKey<1184>)], // (kid, public_key)
) -> crate::error::Result<String>
where
    CE: KeyAeadInPlace + KeyAeadMeta + KeyGen + ToSecretBytes,
{
    let mut rng = random::default_rng();
    let cek = CE::generate(&mut rng).kind(ErrorKind::InvalidState, "Unable generate cek")?;

    let apu = BASE64_URL_SAFE_NO_PAD.encode(from_kid);
    let apv = {
        let mut kids = recipients.iter().map(|r| r.0).collect::<Vec<_>>();
        kids.sort();
        Sha256::digest(kids.join(".").as_bytes())
    };

    let protected = {
        let apv_b64 = BASE64_URL_SAFE_NO_PAD.encode(&apv[..]);

        let p = ProtectedHeader {
            typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
            alg: Algorithm::MlKem768MlDsa65,
            enc,
            skid: Some(from_kid),
            apu: Some(&apu),
            apv: &apv_b64,
            epk: serde_json::json!({}), // ML-KEM doesn't need EPK
        };

        let p = serde_json::to_string(&p)
            .kind(ErrorKind::InvalidState, "Unable serialize protected header")?;

        BASE64_URL_SAFE_NO_PAD.encode(&p)
    };

    let mut buf = {
        let mut buf = SecretBytes::with_capacity(plaintext.len() + cek.aead_params().tag_length);
        buf.extend_from_slice(plaintext);
        buf
    };

    let (ciphertext, tag, iv) = {
        let iv = CE::random_nonce();

        let ciphertext_len = cek
            .encrypt_in_place(&mut buf, &iv[..], protected.as_bytes())
            .kind(ErrorKind::InvalidState, "Unable encrypt content")?;

        let ciphertext = &buf.as_ref()[0..ciphertext_len];
        let tag_raw = &buf.as_ref()[ciphertext_len..];

        let ciphertext = BASE64_URL_SAFE_NO_PAD.encode(ciphertext);
        let tag = BASE64_URL_SAFE_NO_PAD.encode(tag_raw);
        let iv = BASE64_URL_SAFE_NO_PAD.encode(&iv);

        (ciphertext, tag, iv)
    };

    let encrypted_keys = {
        let mut encrypted_keys: Vec<(&str, String)> = Vec::with_capacity(recipients.len());

        for (kid, public_key) in recipients {
            // Use ML-KEM-768 encapsulation with proper randomness
            let mut randomness = [0u8; 32];
            random::fill_random(&mut randomness);
            let (kem_ciphertext, shared_secret) =
                libcrux_ml_kem::mlkem768::encapsulate(public_key, randomness);

            // Create message to sign for AuthCrypt (sender_id + recipient_id + shared_secret)
            let mut message_to_sign = Vec::new();
            message_to_sign.extend_from_slice(from_kid.as_bytes());
            message_to_sign.extend_from_slice(b"|"); // separator
            message_to_sign.extend_from_slice(kid.as_bytes()); // recipient kid
            message_to_sign.extend_from_slice(b"|"); // separator
            message_to_sign.extend_from_slice(&shared_secret);

            // Sign the message using sender's ML-DSA key
            let signature = _sender_key_pair.sign(&message_to_sign)?;

            // Derive key-wrapping key from shared secret (include sender info for AuthCrypt)
            let apu_decoded = BASE64_URL_SAFE_NO_PAD
                .decode(&apu)
                .kind(ErrorKind::Malformed, "Invalid APU base64")?;
            let apv_decoded = apv.to_vec();
            let kek = derive_kek_from_shared_secret(
                &shared_secret,
                "ML-KEM768+ML-DSA65+A256KW",
                &apu_decoded,
                &apv_decoded,
            )?;

            // Wrap the CEK using the derived key-wrapping key
            let wrapped_cek = kek.wrap_key(&cek)?;

            // AuthCrypt format: [ML-KEM ciphertext] + [ML-DSA signature] + [wrapped CEK]
            let mut encrypted_key_bytes = Vec::new();
            encrypted_key_bytes.extend_from_slice(kem_ciphertext.as_slice());
            encrypted_key_bytes.extend_from_slice(signature.as_bytes());
            encrypted_key_bytes.extend_from_slice(wrapped_cek.as_ref());

            let encrypted_key = BASE64_URL_SAFE_NO_PAD.encode(&encrypted_key_bytes);
            encrypted_keys.push((kid, encrypted_key));
        }

        encrypted_keys
    };

    let recipients: Vec<_> = encrypted_keys
        .iter()
        .map(|(kid, encrypted_key)| Recipient {
            header: PerRecipientHeader { kid },
            encrypted_key,
        })
        .collect();

    let jwe = JWE {
        protected: &protected,
        recipients,
        iv: &iv,
        ciphertext: &ciphertext,
        tag: &tag,
    };

    serde_json::to_string(&jwe).kind(ErrorKind::InvalidState, "Unable serialize jwe")
}

pub(crate) fn encrypt_auth_ml_kem_1024_dsa_87<CE>(
    plaintext: &[u8],
    enc: EncAlgorithm,
    from_kid: &str,
    _sender_key_pair: &crate::utils::pqc::MlDsa87KeyPair,
    recipients: &[(&str, &libcrux_ml_kem::MlKemPublicKey<1568>)], // (kid, public_key)
) -> crate::error::Result<String>
where
    CE: KeyAeadInPlace + KeyAeadMeta + KeyGen + ToSecretBytes,
{
    let mut rng = random::default_rng();
    let cek = CE::generate(&mut rng).kind(ErrorKind::InvalidState, "Unable generate cek")?;

    let apu = BASE64_URL_SAFE_NO_PAD.encode(from_kid);
    let apv = {
        let mut kids = recipients.iter().map(|r| r.0).collect::<Vec<_>>();
        kids.sort();
        Sha256::digest(kids.join(".").as_bytes())
    };

    let protected = {
        let apv_b64 = BASE64_URL_SAFE_NO_PAD.encode(&apv[..]);

        let p = ProtectedHeader {
            typ: Some(Cow::Borrowed("application/didcomm-encrypted+json")),
            alg: Algorithm::MlKem1024MlDsa87,
            enc,
            skid: Some(from_kid),
            apu: Some(&apu),
            apv: &apv_b64,
            epk: serde_json::json!({}), // ML-KEM doesn't need EPK
        };

        let p = serde_json::to_string(&p)
            .kind(ErrorKind::InvalidState, "Unable serialize protected header")?;

        BASE64_URL_SAFE_NO_PAD.encode(&p)
    };

    let mut buf = {
        let mut buf = SecretBytes::with_capacity(plaintext.len() + cek.aead_params().tag_length);
        buf.extend_from_slice(plaintext);
        buf
    };

    let (ciphertext, tag, iv) = {
        let iv = CE::random_nonce();

        let ciphertext_len = cek
            .encrypt_in_place(&mut buf, &iv[..], protected.as_bytes())
            .kind(ErrorKind::InvalidState, "Unable encrypt content")?;

        let ciphertext = &buf.as_ref()[0..ciphertext_len];
        let tag_raw = &buf.as_ref()[ciphertext_len..];

        let ciphertext = BASE64_URL_SAFE_NO_PAD.encode(ciphertext);
        let tag = BASE64_URL_SAFE_NO_PAD.encode(tag_raw);
        let iv = BASE64_URL_SAFE_NO_PAD.encode(&iv);

        (ciphertext, tag, iv)
    };

    let encrypted_keys = {
        let mut encrypted_keys: Vec<(&str, String)> = Vec::with_capacity(recipients.len());

        for (kid, public_key) in recipients {
            // Use ML-KEM-1024 encapsulation with proper randomness
            let mut randomness = [0u8; 32];
            random::fill_random(&mut randomness);
            let (kem_ciphertext, shared_secret) =
                libcrux_ml_kem::mlkem1024::encapsulate(public_key, randomness);

            // Create message to sign for AuthCrypt (sender_id + recipient_id + shared_secret)
            let mut message_to_sign = Vec::new();
            message_to_sign.extend_from_slice(from_kid.as_bytes());
            message_to_sign.extend_from_slice(b"|"); // separator
            message_to_sign.extend_from_slice(kid.as_bytes()); // recipient kid
            message_to_sign.extend_from_slice(b"|"); // separator
            message_to_sign.extend_from_slice(&shared_secret);

            // Sign the message using sender's ML-DSA key
            let signature = _sender_key_pair.sign(&message_to_sign)?;

            // Derive key-wrapping key from shared secret (include sender info for AuthCrypt)
            let apu_decoded = BASE64_URL_SAFE_NO_PAD
                .decode(&apu)
                .kind(ErrorKind::Malformed, "Invalid APU base64")?;
            let apv_decoded = apv.to_vec();
            let kek = derive_kek_from_shared_secret(
                &shared_secret,
                "ML-KEM1024+ML-DSA87+A256KW",
                &apu_decoded,
                &apv_decoded,
            )?;

            // Wrap the CEK using the derived key-wrapping key
            let wrapped_cek = kek.wrap_key(&cek)?;

            // AuthCrypt format: [ML-KEM ciphertext] + [ML-DSA signature] + [wrapped CEK]
            let mut encrypted_key_bytes = Vec::new();
            encrypted_key_bytes.extend_from_slice(kem_ciphertext.as_slice());
            encrypted_key_bytes.extend_from_slice(signature.as_bytes());
            encrypted_key_bytes.extend_from_slice(wrapped_cek.as_ref());

            let encrypted_key = BASE64_URL_SAFE_NO_PAD.encode(&encrypted_key_bytes);
            encrypted_keys.push((kid, encrypted_key));
        }

        encrypted_keys
    };

    let recipients: Vec<_> = encrypted_keys
        .iter()
        .map(|(kid, encrypted_key)| Recipient {
            header: PerRecipientHeader { kid },
            encrypted_key,
        })
        .collect();

    let jwe = JWE {
        protected: &protected,
        recipients,
        iv: &iv,
        ciphertext: &ciphertext,
        tag: &tag,
    };

    serde_json::to_string(&jwe).kind(ErrorKind::InvalidState, "Unable serialize jwe")
}
