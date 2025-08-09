use crate::{
    did::{did_doc::VerificationMethodType, VerificationMaterial, VerificationMethod},
    error::{err_msg, ErrorKind, Result, ResultExt},
    secrets::{Secret, SecretMaterial, SecretType},
    utils::crypto::{AsKnownKeyPair, KnownKeyAlg, KnownKeyPair},
};

pub(crate) fn is_did(did: &str) -> bool {
    let parts: Vec<_> = did.split(':').collect();
    parts.len() >= 3 && parts.first().unwrap() == &"did"
}

pub(crate) fn did_or_url(did_or_url: &str) -> (&str, Option<&str>) {
    match did_or_url.split_once("#") {
        Some((did, _)) => (did, Some(did_or_url)),
        None => (did_or_url, None),
    }
}

impl AsKnownKeyPair for VerificationMethod {
    fn key_alg(&self) -> KnownKeyAlg {
        match &self.type_ {
            VerificationMethodType::MlKem768KeyAgreementKey2025 => KnownKeyAlg::MlKem768,
            VerificationMethodType::MlKem1024KeyAgreementKey2025 => KnownKeyAlg::MlKem1024,
            VerificationMethodType::MlDsa65VerificationKey2025 => KnownKeyAlg::MlDsa65,
            VerificationMethodType::MlDsa87VerificationKey2025 => KnownKeyAlg::MlDsa87,
            // Legacy verification method types (not supported in PQC-only mode)
            VerificationMethodType::JsonWebKey2020 | VerificationMethodType::Other => {
                KnownKeyAlg::Unsupported
            }
        }
    }

    fn as_key_pair(&self) -> Result<KnownKeyPair> {
        match (&self.type_, &self.verification_material) {
            (
                VerificationMethodType::MlKem768KeyAgreementKey2025,
                VerificationMaterial::Multibase {
                    public_key_multibase: ref key_mb,
                },
            ) => {
                let key_bytes = multibase::decode(key_mb)
                    .kind(ErrorKind::Malformed, "Unable decode multibase key")?
                    .1;

                if key_bytes.len() != 1184 {
                    return Err(err_msg(
                        ErrorKind::Malformed,
                        "Invalid ML-KEM-768 key length",
                    ));
                }

                let mut key_array = [0u8; 1184];
                key_array.copy_from_slice(&key_bytes);
                let public_key = libcrux_ml_kem::MlKemPublicKey::<1184>::from(key_array);
                let keypair = crate::utils::pqc::MlKem768KeyPair::from_public_key(public_key);
                Ok(KnownKeyPair::MlKem768(keypair))
            }
            (
                VerificationMethodType::MlKem1024KeyAgreementKey2025,
                VerificationMaterial::Multibase {
                    public_key_multibase: ref key_mb,
                },
            ) => {
                let key_bytes = multibase::decode(key_mb)
                    .kind(ErrorKind::Malformed, "Unable decode multibase key")?
                    .1;

                if key_bytes.len() != 1568 {
                    return Err(err_msg(
                        ErrorKind::Malformed,
                        "Invalid ML-KEM-1024 key length",
                    ));
                }

                let mut key_array = [0u8; 1568];
                key_array.copy_from_slice(&key_bytes);
                let public_key = libcrux_ml_kem::MlKemPublicKey::<1568>::from(key_array);
                let keypair = crate::utils::pqc::MlKem1024KeyPair::from_public_key(public_key);
                Ok(KnownKeyPair::MlKem1024(keypair))
            }
            (
                VerificationMethodType::MlDsa65VerificationKey2025,
                VerificationMaterial::Multibase {
                    public_key_multibase: ref key_mb,
                },
            ) => {
                let key_bytes = multibase::decode(key_mb)
                    .kind(ErrorKind::Malformed, "Unable decode multibase key")?
                    .1;

                if key_bytes.len() != 1952 {
                    return Err(err_msg(
                        ErrorKind::Malformed,
                        "Invalid ML-DSA-65 key length",
                    ));
                }

                use pqcrypto_traits::sign::PublicKey;
                let public_key = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&key_bytes)
                    .map_err(|_| {
                        err_msg(ErrorKind::Malformed, "Invalid ML-DSA-65 public key format")
                    })?;
                let keypair = crate::utils::pqc::MlDsa65KeyPair::from_public_key(public_key);
                Ok(KnownKeyPair::MlDsa65(keypair))
            }
            (
                VerificationMethodType::MlDsa87VerificationKey2025,
                VerificationMaterial::Multibase {
                    public_key_multibase: ref key_mb,
                },
            ) => {
                let key_bytes = multibase::decode(key_mb)
                    .kind(ErrorKind::Malformed, "Unable decode multibase key")?
                    .1;

                if key_bytes.len() != 2592 {
                    return Err(err_msg(
                        ErrorKind::Malformed,
                        "Invalid ML-DSA-87 key length",
                    ));
                }

                use pqcrypto_traits::sign::PublicKey;
                let public_key = pqcrypto_dilithium::dilithium5::PublicKey::from_bytes(&key_bytes)
                    .map_err(|_| {
                        err_msg(ErrorKind::Malformed, "Invalid ML-DSA-87 public key format")
                    })?;
                let keypair = crate::utils::pqc::MlDsa87KeyPair::from_public_key(public_key);
                Ok(KnownKeyPair::MlDsa87(keypair))
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported verification method type",
            )),
        }
    }
}

impl AsKnownKeyPair for Secret {
    fn key_alg(&self) -> KnownKeyAlg {
        match &self.type_ {
            SecretType::MlKem768KeyAgreementKey2025 => KnownKeyAlg::MlKem768,
            SecretType::MlKem1024KeyAgreementKey2025 => KnownKeyAlg::MlKem1024,
            SecretType::MlDsa65VerificationKey2025 => KnownKeyAlg::MlDsa65,
            SecretType::MlDsa87VerificationKey2025 => KnownKeyAlg::MlDsa87,
            _ => KnownKeyAlg::Unsupported,
        }
    }

    fn as_key_pair(&self) -> Result<KnownKeyPair> {
        match (&self.type_, &self.secret_material) {
            (
                SecretType::MlKem768KeyAgreementKey2025,
                SecretMaterial::Multibase {
                    private_key_multibase: ref key_mb,
                },
            ) => {
                let key_bytes = multibase::decode(key_mb)
                    .kind(ErrorKind::Malformed, "Unable decode multibase private key")?
                    .1;

                let keypair = crate::utils::pqc::MlKem768KeyPair::from_private_key(&key_bytes)?;
                Ok(KnownKeyPair::MlKem768(keypair))
            }
            (
                SecretType::MlKem1024KeyAgreementKey2025,
                SecretMaterial::Multibase {
                    private_key_multibase: ref key_mb,
                },
            ) => {
                let key_bytes = multibase::decode(key_mb)
                    .kind(ErrorKind::Malformed, "Unable decode multibase private key")?
                    .1;

                let keypair = crate::utils::pqc::MlKem1024KeyPair::from_private_key(&key_bytes)?;
                Ok(KnownKeyPair::MlKem1024(keypair))
            }
            (
                SecretType::MlDsa65VerificationKey2025,
                SecretMaterial::Multibase {
                    private_key_multibase: ref key_mb,
                },
            ) => {
                let key_bytes = multibase::decode(key_mb)
                    .kind(ErrorKind::Malformed, "Unable decode multibase private key")?
                    .1;

                let keypair = crate::utils::pqc::MlDsa65KeyPair::from_private_key(&key_bytes)?;
                Ok(KnownKeyPair::MlDsa65(keypair))
            }
            (
                SecretType::MlDsa87VerificationKey2025,
                SecretMaterial::Multibase {
                    private_key_multibase: ref key_mb,
                },
            ) => {
                let key_bytes = multibase::decode(key_mb)
                    .kind(ErrorKind::Malformed, "Unable decode multibase private key")?
                    .1;

                let keypair = crate::utils::pqc::MlDsa87KeyPair::from_private_key(&key_bytes)?;
                Ok(KnownKeyPair::MlDsa87(keypair))
            }
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported secret type")),
        }
    }
}
