// PQC-only - classical crypto imports removed
use askar_crypto::jwk::{FromJwk, ToJwk};

use serde_json::Value;

use crate::error::{ErrorKind, Result, ResultExt};

#[allow(dead_code)]
pub(crate) trait FromJwkValue: FromJwk {
    /// Import the key from a JWK string reference
    fn from_jwk_value(jwk: &Value) -> Result<Self> {
        let jwk = serde_json::to_string(jwk)
            .kind(ErrorKind::InvalidState, "Unable produce jwk string")?;

        Self::from_jwk(&jwk).kind(ErrorKind::Malformed, "Unable produce jwk")
    }
}

#[allow(dead_code)]
pub(crate) trait ToJwkValue: ToJwk {
    fn to_jwk_public_value(&self) -> Result<Value> {
        let jwk = self
            .to_jwk_public(None)
            .kind(ErrorKind::InvalidState, "Unable produce jwk string")?;

        let jwk: Value =
            serde_json::from_str(&jwk).kind(ErrorKind::InvalidState, "Unable produce jwk value")?;

        Ok(jwk)
    }
}

// PQC-only - classical crypto implementations and tests removed
