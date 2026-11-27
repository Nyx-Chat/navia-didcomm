mod envelope;

mod parse;

mod sign;

mod verify;

pub(crate) use envelope::{Algorithm, JWS};
#[cfg(test)]
pub(crate) use envelope::{CompactHeader, Header, ProtectedHeader};

pub(crate) use sign::{sign, sign_compact};

#[cfg(test)]
pub(crate) use parse::parse;
pub(crate) use parse::{parse_compact, ParsedCompactJWS, ParsedJWS};

#[cfg(test)]
mod tests {
    use askar_crypto::{alg::ed25519::Ed25519KeyPair, jwk::FromJwk};

    use crate::jws::{self, Algorithm};

    #[test]
    fn demo_works() {
        let alice_kid = "did:example:alice#key-1";

        let alice_key = Ed25519KeyPair::from_jwk(
            r#"
            {
                "kty":"OKP",
                "d":"pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                "crv":"Ed25519",
                "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
            }
            "#,
        )
        .expect("Unable from_jwk");

        let alice_pkey = Ed25519KeyPair::from_jwk(
            r#"
            {
                "kty":"OKP",
                "crv":"Ed25519",
                "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
            }
            "#,
        )
        .expect("Unable from_jwk");

        let payload = "Hello World!";

        let msg = jws::sign(
            payload.as_bytes(),
            (alice_kid, &alice_key),
            Algorithm::EdDSA,
        )
        .expect("unable sign");

        let mut buf = vec![];
        let msg = jws::parse(&msg, &mut buf).expect("Unable parse");

        let valid = msg
            .verify((alice_kid, &alice_pkey))
            .expect("Unable verify.");

        assert!(valid);
    }
}
