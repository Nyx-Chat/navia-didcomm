use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::secrets::{Secret, SecretMaterial, SecretType};

lazy_static! {
    pub static ref MEDIATOR4_SECRET_KEY_AGREEMENT_KEY_X25519_1: Secret = Secret {
        id: "did:example:mediator4#key-x25519-1".into(),
        type_: SecretType::JsonWebKey2020,
        secret_material: SecretMaterial::JWK {
            private_key_jwk: json!(
            {
                "kty": "OKP",
                "d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
                "crv": "X25519",
                "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
            })
        },
    };
    pub static ref MEDIATOR4_SECRETS: Vec<Secret> =
        vec![MEDIATOR4_SECRET_KEY_AGREEMENT_KEY_X25519_1.clone(),];
}
