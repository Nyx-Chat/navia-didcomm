use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::did::{
    DIDCommMessagingService, DIDDoc, Service, ServiceKind, VerificationMaterial,
    VerificationMethod, VerificationMethodType,
};

lazy_static! {
    pub static ref EVE_VERIFICATION_METHOD_KEY_AGREEM_X25519: VerificationMethod =
        VerificationMethod {
            id: "did:example:eve#key-x25519-1".into(),
            controller: "did:example:eve#key-x25519-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                public_key_jwk: json!(
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
                })
            },
        };
    pub static ref EVE_AUTH_METHOD_25519: VerificationMethod = VerificationMethod {
        id: "did:example:eve#key-1".into(),
        controller: "did:example:eve#key-1".into(),
        type_: VerificationMethodType::JsonWebKey2020,
        verification_material: VerificationMaterial::JWK {
            public_key_jwk: json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "8MYqNztKREYadGvPBQ3RPfVRmQ5Zv2F3sRgcRJN1hKM",
            })
        },
    };
    pub static ref EVE_DID_COMM_MESSAGING_SERVICE: DIDCommMessagingService =
        DIDCommMessagingService {
            uri: "http://example.com/eve".into(),
            accept: Some(vec!["didcomm/v2".into(), "didcomm/aip2;env=rfc587".into()]),
            routing_keys: vec![
                "did:example:mediator1#key-x25519-1".into(),
                "did:example:mediator2#key-x25519-1".into(),
                "did:example:mediator4#key-x25519-1".into(),
            ],
        };
    pub static ref EVE_SERVICE: Service = Service {
        id: "did:example:eve#didcomm-1".into(),
        service_endpoint: ServiceKind::DIDCommMessaging {
            value: EVE_DID_COMM_MESSAGING_SERVICE.clone()
        },
    };
    pub static ref EVE_DID_DOC: DIDDoc = DIDDoc {
        id: "did:example:eve".into(),
        authentication: vec!["did:example:eve#key-1".into()],
        key_agreement: vec!["did:example:eve#key-x25519-1".into()],
        service: vec![EVE_SERVICE.clone()],
        verification_method: vec![
            EVE_VERIFICATION_METHOD_KEY_AGREEM_X25519.clone(),
            EVE_AUTH_METHOD_25519.clone(),
        ],
    };
}
