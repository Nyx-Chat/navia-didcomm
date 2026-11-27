use askar_crypto::{
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    kdf::{FromKeyDerivation, KeyExchange},
    repr::{KeyGen, KeySecretBytes},
};
use base64::prelude::*;

use crate::{
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    jwe::ParsedJWE,
    jwk::{FromJwkValue, ToJwkValue},
    utils::crypto::{JoseKDF, KeyWrap},
};

impl<'a, 'b> ParsedJWE<'a, 'b> {
    pub(crate) fn decrypt<CE, KDF, KE, KW>(
        &self,
        sender: Option<(&str, &KE)>,
        recipient: (&str, &KE),
    ) -> Result<Vec<u8>>
    where
        CE: KeyAeadInPlace + KeySecretBytes,
        KDF: JoseKDF<KE, KW>,
        KE: KeyExchange + KeyGen + ToJwkValue + FromJwkValue,
        KW: KeyWrap + FromKeyDerivation,
    {
        let (skid, skey) = match sender {
            Some((skid, skey)) => (Some(skid), Some(skey)),
            None => (None, None),
        };

        let (kid, key) = recipient;

        if skid.map(str::as_bytes) != self.apu.as_deref() {
            Err(err_msg(ErrorKind::InvalidState, "Wrong skid used"))?;
        }

        let encrypted_key = {
            let encrypted_key = self
                .jwe
                .recipients
                .iter()
                .find(|r| r.header.kid == kid)
                .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Recipient not found"))?
                .encrypted_key;

            BASE64_URL_SAFE_NO_PAD
                .decode(encrypted_key)
                .kind(ErrorKind::Malformed, "Unable decode encrypted_key")?
        };

        let epk = KE::from_jwk_value(&self.protected.epk).context("Unable instantiate epk")?;

        let tag = BASE64_URL_SAFE_NO_PAD
            .decode(self.jwe.tag)
            .kind(ErrorKind::Malformed, "Unable decode tag")?;

        // ECDH-1PU feeds the tag into key derivation, which writes it after 8 bytes of
        // length fields into a 132-byte buffer, so a tag over 124 bytes fails there.
        // No supported content encryption produces a tag that long.
        if tag.len() > 124 {
            Err(err_msg(ErrorKind::Malformed, "Tag too long"))?;
        }

        let kw = KDF::derive_key(
            &epk,
            skey,
            key,
            self.protected.alg.as_str().as_bytes(),
            self.apu.as_deref().unwrap_or(&[]),
            &self.apv,
            &tag,
            true,
        )
        .kind(ErrorKind::InvalidState, "Unable derive kw")?;

        let cek: CE = kw
            .unwrap_key(&encrypted_key)
            .kind(ErrorKind::Malformed, "Unable unwrap cek")?;

        let ciphertext = BASE64_URL_SAFE_NO_PAD
            .decode(self.jwe.ciphertext)
            .kind(ErrorKind::Malformed, "Unable decode ciphertext")?;

        let iv = BASE64_URL_SAFE_NO_PAD
            .decode(self.jwe.iv)
            .kind(ErrorKind::Malformed, "Unable decode iv")?;

        let plaintext = {
            let mut buf = SecretBytes::with_capacity(ciphertext.len() + tag.len());
            buf.extend_from_slice(&ciphertext);
            buf.extend_from_slice(&tag);

            cek.decrypt_in_place(&mut buf, &iv, self.jwe.protected.as_bytes())
                .kind(ErrorKind::Malformed, "Unable decrypt content")?;

            buf.to_vec()
        };

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests;
