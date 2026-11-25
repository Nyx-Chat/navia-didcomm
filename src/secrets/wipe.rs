//! Wiping of private key material that this crate holds in strings and JSON values.
//!
//! `askar_crypto::buffer::SecretBytes` zeroizes its buffer (and the spare capacity) when it
//! is dropped, so moving a `String` into one and dropping it wipes the string without a
//! second copy of the key.

use std::ops::{Deref, DerefMut};

use askar_crypto::buffer::SecretBytes;
use serde_json::Value;

#[cfg(test)]
thread_local! {
    /// Counts the wipes that ran on this thread, so that a test can tell that a drop wiped.
    pub(crate) static WIPES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Wipes the buffer of `s` and leaves it empty.
pub(crate) fn wipe_string(s: &mut String) {
    drop(SecretBytes::from(std::mem::take(s)));
}

/// Wipes every string of `value`, keys of objects excepted: they name the fields and never
/// hold key material.
pub(crate) fn wipe_json(value: &mut Value) {
    #[cfg(test)]
    WIPES.with(|wipes| wipes.set(wipes.get() + 1));

    match value {
        Value::String(s) => wipe_string(s),
        Value::Array(items) => items.iter_mut().for_each(wipe_json),
        Value::Object(map) => map.values_mut().for_each(wipe_json),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// A JSON value that holds key material (a private JWK) and wipes its strings when dropped.
pub(crate) struct SecretJson(Value);

impl SecretJson {
    pub(crate) fn new(value: Value) -> Self {
        SecretJson(value)
    }
}

impl Deref for SecretJson {
    type Target = Value;

    fn deref(&self) -> &Value {
        &self.0
    }
}

impl DerefMut for SecretJson {
    fn deref_mut(&mut self) -> &mut Value {
        &mut self.0
    }
}

impl Drop for SecretJson {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn wipe_string_empties_the_string() {
        let mut s = String::from("private");
        wipe_string(&mut s);
        assert!(s.is_empty());
    }

    #[test]
    fn wipe_json_reaches_every_string_and_keeps_the_field_names() {
        let mut value = json!({"kty": "OKP", "d": "private", "nested": ["a", {"b": "c"}], "n": 1});
        wipe_json(&mut value);

        assert_eq!(
            value,
            json!({"kty": "", "d": "", "nested": ["", {"b": ""}], "n": 1})
        );
    }

    #[test]
    fn secret_json_wipes_when_dropped() {
        let before = WIPES.with(|wipes| wipes.get());
        drop(SecretJson::new(json!({"d": "private"})));

        // `wipe_json` runs once for the object and once for each of its values.
        assert_eq!(WIPES.with(|wipes| wipes.get()), before + 2);
    }
}
