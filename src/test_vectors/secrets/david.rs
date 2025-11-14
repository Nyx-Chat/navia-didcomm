use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::secrets::{Secret, SecretMaterial, SecretType};

lazy_static! {
    pub static ref DAVID_SECRET_KEY_AGREEMENT_KEY_X25519: Secret = Secret {
        id: "did:example:david#key-x25519-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
                "kty": "OKP",
                "crv": "X25519",
                "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
            })
        },
    };
    pub static ref DAVID_SECRET_AUTH_KEY_ED25519: Secret = Secret {
        id: "did:example:david#key-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "6fioC1zcDPyPCAR3FP52T9DnX7fYR7UXJ3T6T3mzLwM",
                "d": "X1M-SjKHkqCGqKXdh0q5F6vDwq8VjGxKhXjLYnBjM1",
            })
        },
    };
    pub static ref DAVID_SECRETS: Vec<Secret> = vec![
        DAVID_SECRET_KEY_AGREEMENT_KEY_X25519.clone(),
        DAVID_SECRET_AUTH_KEY_ED25519.clone(),
    ];
}
