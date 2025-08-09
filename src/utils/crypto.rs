use askar_crypto::{
    alg::aes::{A128Kw, A256Kw, AesKey},
    buffer::SecretBytes,
    encrypt::KeyAeadInPlace,
    kdf::KeyExchange, // PQC-only - ECDH and FromKeyDerivation imports removed
    repr::{KeySecretBytes, ToSecretBytes},
};

use crate::error::{err_msg, ErrorKind, Result, ResultExt};

/// Note this trait is compatible with KW algorithms only
#[allow(dead_code)]
pub(crate) trait KeyWrap: KeyAeadInPlace {
    fn wrap_key<K: KeyAeadInPlace + ToSecretBytes>(&self, key: &K) -> Result<SecretBytes> {
        let params = self.aead_params();

        let key_len = key
            .secret_bytes_length()
            .kind(ErrorKind::InvalidState, "Unable get key len")?;

        let mut buf = SecretBytes::with_capacity(key_len + params.tag_length);

        key.write_secret_bytes(&mut buf)
            .kind(ErrorKind::InvalidState, "Unable encrypt")?;

        self.encrypt_in_place(&mut buf, &[], &[])
            .kind(ErrorKind::InvalidState, "Unable encrypt")?;

        Ok(buf)
    }

    fn unwrap_key<K: KeyAeadInPlace + KeySecretBytes>(&self, ciphertext: &[u8]) -> Result<K> {
        let mut buf = SecretBytes::from_slice(ciphertext);

        self.decrypt_in_place(&mut buf, &[], &[])
            .kind(ErrorKind::Malformed, "Unable decrypt key")?;

        let key =
            K::from_secret_bytes(buf.as_ref()).kind(ErrorKind::Malformed, "Unable create key")?;

        Ok(key)
    }
}

impl KeyWrap for AesKey<A256Kw> {}

impl KeyWrap for AesKey<A128Kw> {}

#[allow(dead_code)]
pub(crate) trait JoseKDF<Key: KeyExchange, KW: KeyWrap + Sized> {
    fn derive_key(
        ephem_key: &Key,
        send_key: Option<&Key>,
        recip_key: &Key,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        cc_tag: &[u8],
        receive: bool,
    ) -> Result<KW>;
}

// PQC-only - ECDH-1PU and ECDH-ES implementations removed

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KnownKeyAlg {
    // Post-Quantum algorithms only
    MlKem768,
    MlKem1024,
    MlDsa65,
    MlDsa87,
    Unsupported,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum KnownKeyPair {
    // Post-Quantum algorithms only
    MlKem768(crate::utils::pqc::MlKem768KeyPair),
    MlKem1024(crate::utils::pqc::MlKem1024KeyPair),
    MlDsa65(crate::utils::pqc::MlDsa65KeyPair),
    MlDsa87(crate::utils::pqc::MlDsa87KeyPair),
}

pub(crate) trait AsKnownKeyPair {
    fn key_alg(&self) -> KnownKeyAlg;
    fn as_key_pair(&self) -> Result<KnownKeyPair>;

    // Post-Quantum key extraction methods only
    fn as_ml_kem_768(&self) -> Result<crate::utils::pqc::MlKem768KeyPair> {
        if self.key_alg() != KnownKeyAlg::MlKem768 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::MlKem768(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }

    fn as_ml_kem_1024(&self) -> Result<crate::utils::pqc::MlKem1024KeyPair> {
        if self.key_alg() != KnownKeyAlg::MlKem1024 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::MlKem1024(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }

    fn as_ml_dsa_65(&self) -> Result<crate::utils::pqc::MlDsa65KeyPair> {
        if self.key_alg() != KnownKeyAlg::MlDsa65 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::MlDsa65(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }

    fn as_ml_dsa_87(&self) -> Result<crate::utils::pqc::MlDsa87KeyPair> {
        if self.key_alg() != KnownKeyAlg::MlDsa87 {
            Err(err_msg(ErrorKind::InvalidState, "Unexpected key alg"))?
        }

        match self.as_key_pair()? {
            KnownKeyPair::MlDsa87(k) => Ok(k),
            _ => Err(err_msg(ErrorKind::InvalidState, "Unexpected key pair type"))?,
        }
    }
}
