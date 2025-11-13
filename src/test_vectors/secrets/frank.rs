use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::secrets::{Secret, SecretMaterial, SecretType};

lazy_static! {
    pub static ref FRANK_SECRET_KEY_AGREEMENT_KEY_X25519: Secret = Secret {
        id: "did:example:frank#key-x25519-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
                "kty": "OKP",
                "crv": "X25519",
                "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                "d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
            })
        },
    };
    pub static ref FRANK_SECRET_AUTH_KEY_ED25519: Secret = Secret {
        id: "did:example:frank#key-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "9PZrQytLWEZbdHxQBR4RPgXSmR6Zw3G4tShcSKO2iLN",
                "d": "Z4OsRytLWEZbdHxQBR4RPgXSmR6Zw3G4tShcSKO2iLN",
            })
        },
    };
    pub static ref FRANK_SECRETS: Vec<Secret> = vec![
        FRANK_SECRET_KEY_AGREEMENT_KEY_X25519.clone(),
        FRANK_SECRET_AUTH_KEY_ED25519.clone(),
    ];
}
