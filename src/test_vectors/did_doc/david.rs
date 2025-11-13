use lazy_static::lazy_static;
use serde_json::json;

use crate::didcomm::did::{
    DIDCommMessagingService, DIDDoc, Service, ServiceKind, VerificationMaterial,
    VerificationMethod, VerificationMethodType,
};

lazy_static! {
    pub static ref DAVID_VERIFICATION_METHOD_KEY_AGREEM_X25519: VerificationMethod =
        VerificationMethod {
            id: "did:example:david#key-x25519-1".into(),
            controller: "did:example:david#key-x25519-1".into(),
            type_: VerificationMethodType::JsonWebKey2020,
            verification_material: VerificationMaterial::JWK {
                public_key_jwk: json!(
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                })
            },
        };
    pub static ref DAVID_AUTH_METHOD_25519: VerificationMethod = VerificationMethod {
        id: "did:example:david#key-1".into(),
        controller: "did:example:david#key-1".into(),
        type_: VerificationMethodType::JsonWebKey2020,
        verification_material: VerificationMaterial::JWK {
            public_key_jwk: json!(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "6fioC1zcDPyPCAR3FP52T9DnX7fYR7UXJ3T6T3mzLwM",
            })
        },
    };
    pub static ref DAVID_DID_COMM_MESSAGING_SERVICE: DIDCommMessagingService =
        DIDCommMessagingService {
            uri: "http://example.com/david".into(),
            accept: Some(vec!["didcomm/v2".into(), "didcomm/aip2;env=rfc587".into()]),
            routing_keys: vec![
                "did:example:mediator1#key-x25519-1".into(),
                "did:example:mediator2#key-x25519-1".into(),
                "did:example:mediator3#key-x25519-1".into(),
            ],
        };
    pub static ref DAVID_SERVICE: Service = Service {
        id: "did:example:david#didcomm-1".into(),
        service_endpoint: ServiceKind::DIDCommMessaging {
            value: DAVID_DID_COMM_MESSAGING_SERVICE.clone()
        },
    };
    pub static ref DAVID_DID_DOC: DIDDoc = DIDDoc {
        id: "did:example:david".into(),
        authentication: vec!["did:example:david#key-1".into()],
        key_agreement: vec!["did:example:david#key-x25519-1".into()],
        service: vec![DAVID_SERVICE.clone()],
        verification_method: vec![
            DAVID_VERIFICATION_METHOD_KEY_AGREEM_X25519.clone(),
            DAVID_AUTH_METHOD_25519.clone(),
        ],
    };
}
