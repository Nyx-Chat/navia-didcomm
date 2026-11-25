//! Set of interfaces that allow access to DID Document secrets

pub mod resolvers;
pub(crate) mod wipe;

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;

/// Interface for secrets resolver.
/// Resolves secrets such as private keys to be used for signing and encryption.
///
/// This trait is `Send + Sync` to work with async runtimes and multi-threaded environments.
#[async_trait]
pub trait SecretsResolver: Send + Sync {
    /// Finds secret (usually private key) identified by the given key ID.
    ///
    /// # Parameters
    /// - `secret_id` the ID (in form of DID URL) identifying a secret
    ///
    /// # Returns
    /// A secret (usually private key) or None of there is no secret for the given ID
    ///
    /// # Errors
    /// - IOError
    /// - InvalidState
    async fn get_secret(&self, secret_id: &str) -> Result<Option<Secret>>;

    /// Find all secrets that have one of the given IDs.
    /// Return secrets only for key IDs for which a secret is present.
    ///
    /// # Parameters
    /// - `secret_ids` the IDs find secrets for
    ///
    /// # Returns
    /// possible empty list of all secrets that have one of the given IDs.
    async fn find_secrets<'a>(&self, secret_ids: &'a [&'a str]) -> Result<Vec<&'a str>>;
}

/// Represents secret.
///
/// `Debug` does not print the key material. The private key is wiped from memory when the
/// `Secret` is dropped (the copy that `Serialize` writes out is the caller's to protect).
#[derive(Clone, Deserialize, Serialize)]
pub struct Secret {
    /// A key ID identifying a secret (private key).
    pub id: String,

    /// Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
    #[serde(rename = "type")]
    pub type_: SecretType,

    /// Value of the secret (private key)
    #[serde(flatten)]
    pub secret_material: SecretMaterial,
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("id", &self.id)
            .field("type_", &self.type_)
            .field("secret_material", &self.secret_material)
            .finish()
    }
}

/// Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum SecretType {
    JsonWebKey2020,
    X25519KeyAgreementKey2019,
    X25519KeyAgreementKey2020,
    Ed25519VerificationKey2018,
    Ed25519VerificationKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Other,
}

/// Represents secret crypto material.
///
/// `Debug` does not print the key. The strings that hold it are wiped when the value is
/// dropped, which is also why the key cannot be moved out of a `SecretMaterial`: borrow it.
#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SecretMaterial {
    #[serde(rename_all = "camelCase")]
    JWK { private_key_jwk: Value },

    #[serde(rename_all = "camelCase")]
    Multibase { private_key_multibase: String },

    #[serde(rename_all = "camelCase")]
    Base58 { private_key_base58: String },
}

impl SecretMaterial {
    /// Wipes the private key held by this value.
    fn wipe(&mut self) {
        match self {
            SecretMaterial::JWK { private_key_jwk } => wipe::wipe_json(private_key_jwk),
            SecretMaterial::Multibase {
                private_key_multibase,
            } => wipe::wipe_string(private_key_multibase),
            SecretMaterial::Base58 { private_key_base58 } => wipe::wipe_string(private_key_base58),
        }
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Stands for the key in the output.
        struct Redacted;

        impl fmt::Debug for Redacted {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("<redacted>")
            }
        }

        match self {
            SecretMaterial::JWK { .. } => f
                .debug_struct("JWK")
                .field("private_key_jwk", &Redacted)
                .finish(),
            SecretMaterial::Multibase { .. } => f
                .debug_struct("Multibase")
                .field("private_key_multibase", &Redacted)
                .finish(),
            SecretMaterial::Base58 { .. } => f
                .debug_struct("Base58")
                .field("private_key_base58", &Redacted)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const PRIVATE: &str = "PRIVATE-KEY-MATERIAL";

    fn materials() -> Vec<SecretMaterial> {
        vec![
            SecretMaterial::JWK {
                private_key_jwk: json!({"kty": "OKP", "crv": "Ed25519", "d": PRIVATE}),
            },
            SecretMaterial::Multibase {
                private_key_multibase: PRIVATE.to_owned(),
            },
            SecretMaterial::Base58 {
                private_key_base58: PRIVATE.to_owned(),
            },
        ]
    }

    #[test]
    fn debug_of_a_secret_does_not_print_the_key() {
        for secret_material in materials() {
            let secret = Secret {
                id: "did:example:alice#key-1".to_owned(),
                type_: SecretType::JsonWebKey2020,
                secret_material,
            };

            let printed = format!("{secret:?} {:#?} {:?}", secret, secret.secret_material);

            assert!(!printed.contains(PRIVATE), "{printed}");
            assert!(printed.contains("<redacted>"), "{printed}");
            assert!(printed.contains("did:example:alice#key-1"), "{printed}");
        }
    }

    #[test]
    fn wipe_clears_the_private_key() {
        for mut secret_material in materials() {
            secret_material.wipe();

            let serialized = serde_json::to_string(&secret_material).unwrap();
            assert!(!serialized.contains(PRIVATE), "{serialized}");
        }
    }

    #[test]
    fn dropping_a_secret_wipes_the_private_key() {
        let before = wipe::WIPES.with(|wipes| wipes.get());

        let secret = Secret {
            id: "did:example:alice#key-1".to_owned(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({"d": PRIVATE}),
            },
        };
        let clone = secret.clone();
        drop(secret);
        drop(clone);

        // One wipe of the object and one of its string, for each of the two values.
        assert_eq!(wipe::WIPES.with(|wipes| wipes.get()), before + 4);
    }

    #[test]
    fn a_secret_keeps_its_wire_form() {
        let secret: Secret = serde_json::from_value(json!({
            "id": "did:example:alice#key-1",
            "type": "JsonWebKey2020",
            "privateKeyJwk": {"kty": "OKP", "crv": "Ed25519", "d": PRIVATE},
        }))
        .unwrap();

        assert_eq!(
            serde_json::to_value(&secret).unwrap(),
            json!({
                "id": "did:example:alice#key-1",
                "type": "JsonWebKey2020",
                "privateKeyJwk": {"kty": "OKP", "crv": "Ed25519", "d": PRIVATE},
            })
        );
    }
}
