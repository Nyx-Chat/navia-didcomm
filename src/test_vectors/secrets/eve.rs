use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::secrets::{Secret, SecretMaterial, SecretType};

lazy_static! {
    pub static ref EVE_SECRET_KEY_AGREEMENT_KEY_X25519: Secret = Secret {
        id: "did:example:eve#key-x25519-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
                "kty": "OKP",
                "crv": "X25519",
                "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
                "d": "f9WJeuQXEItkGM8shN4dqFr5fLQLBasHnWZ-8dPaSo0",
            })
        },
    };
    pub static ref EVE_SECRET_AUTH_KEY_ED25519: Secret = Secret {
        id: "did:example:eve#key-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "8MYqNztKREYadGvPBQ3RPfVRmQ5Zv2F3sRgcRJN1hKM",
                "d": "Y3NrOztKREYadGvPBQ3RPfVRmQ5Zv2F3sRgcRJN1hKM",
            })
        },
    };
    pub static ref EVE_SECRETS: Vec<Secret> = vec![
        EVE_SECRET_KEY_AGREEMENT_KEY_X25519.clone(),
        EVE_SECRET_AUTH_KEY_ED25519.clone(),
    ];
}
