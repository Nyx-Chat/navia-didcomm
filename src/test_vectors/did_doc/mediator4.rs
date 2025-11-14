use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::did::{
    DIDDoc, VerificationMaterial, VerificationMethod, VerificationMethodType,
};

lazy_static! {
    pub static ref MEDIATOR4_VERIFICATION_METHOD_KEY_AGREEM_X25519_1: VerificationMethod =
        VerificationMethod {
            id: "did:example:mediator4#key-x25519-1".into(),
            controller: "did:example:mediator4#key-x25519-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                public_key_jwk: json!(
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                })
            },
        };
    pub static ref MEDIATOR4_DID_DOC: DIDDoc = DIDDoc {
        id: "did:example:mediator4".into(),
        authentication: vec![],
        key_agreement: vec!["did:example:mediator4#key-x25519-1".into()],
        service: vec![],
        verification_method: vec![MEDIATOR4_VERIFICATION_METHOD_KEY_AGREEM_X25519_1.clone()],
    };
}
