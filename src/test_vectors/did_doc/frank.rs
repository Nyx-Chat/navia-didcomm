use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::did::{
    DIDCommMessagingService, DIDDoc, Service, ServiceKind, VerificationMaterial,
    VerificationMethod, VerificationMethodType,
};

lazy_static! {
    pub static ref FRANK_VERIFICATION_METHOD_KEY_AGREEM_X25519: VerificationMethod =
        VerificationMethod {
            id: "did:example:frank#key-x25519-1".into(),
            controller: "did:example:frank#key-x25519-1".into(),
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
    pub static ref FRANK_AUTH_METHOD_25519: VerificationMethod = VerificationMethod {
        id: "did:example:frank#key-1".into(),
        controller: "did:example:frank#key-1".into(),
        type_: VerificationMethodType::JsonWebKey2020,
        verification_material: VerificationMaterial::JWK {
            public_key_jwk: json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "9PZrQytLWEZbdHxQBR4RPgXSmR6Zw3G4tShcSKO2iLN",
            })
        },
    };
    pub static ref FRANK_DID_COMM_MESSAGING_SERVICE: DIDCommMessagingService =
        DIDCommMessagingService {
            uri: "http://example.com/frank".into(),
            accept: Some(vec!["didcomm/v2".into(), "didcomm/aip2;env=rfc587".into()]),
            routing_keys: vec![
                "did:example:mediator1#key-x25519-1".into(),
                "did:example:mediator3#key-x25519-1".into(),
                "did:example:mediator4#key-x25519-1".into(),
            ],
        };
    pub static ref FRANK_SERVICE: Service = Service {
        id: "did:example:frank#didcomm-1".into(),
        service_endpoint: ServiceKind::DIDCommMessaging {
            value: FRANK_DID_COMM_MESSAGING_SERVICE.clone()
        },
    };
    pub static ref FRANK_DID_DOC: DIDDoc = DIDDoc {
        id: "did:example:frank".into(),
        authentication: vec!["did:example:frank#key-1".into()],
        key_agreement: vec!["did:example:frank#key-x25519-1".into()],
        service: vec![FRANK_SERVICE.clone()],
        verification_method: vec![
            FRANK_VERIFICATION_METHOD_KEY_AGREEM_X25519.clone(),
            FRANK_AUTH_METHOD_25519.clone(),
        ],
    };
}
