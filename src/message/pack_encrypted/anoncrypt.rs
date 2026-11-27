use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::ecdh_es::EcdhEs,
};

use crate::{
    algorithms::AnonCryptAlg,
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext},
    jwe,
    utils::crypto::{AsKnownKeyPair, KnownKeyAlg},
};

use super::recipients::{ensure_every_recipient_has_key, recipient_key_agreements};

pub(crate) async fn anoncrypt<'dr, 'sr>(
    to: &[&str],
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    msg: &[u8],
    enc_alg_anon: &AnonCryptAlg,
) -> Result<(String, Vec<String>)> /* (msg, to_kids) */ {
    let to_keys = recipient_key_agreements(to, did_resolver).await?;

    // The first supported key decides the key alg for all recipients.
    let key_alg = to_keys
        .iter()
        .filter(|key| key.key_alg() != KnownKeyAlg::Unsupported)
        .map(crate::utils::crypto::AsKnownKeyPair::key_alg)
        .next()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "No key agreement keys found for recipient",
            )
        })?;

    let to_keys: Vec<_> = to_keys
        .into_iter()
        .filter(|key| key.key_alg() == key_alg)
        .collect();

    if to_keys.is_empty() {
        Err(err_msg(
            ErrorKind::NoCompatibleCrypto,
            "No compatible keys found across all recipients",
        ))?;
    }

    ensure_every_recipient_has_key(to, &to_keys, &format!("of type {key_alg:?}"))?;

    let msg = match key_alg {
        KnownKeyAlg::X25519 => {
            let _to_keys = to_keys
                .iter()
                .map(|vm| vm.as_x25519().map(|k| (&vm.id, k)))
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = _to_keys
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            match enc_alg_anon {
                AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    EcdhEs<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                    Chacha20Key<XC20P>,
                    EcdhEs<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::Xc20P,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256Gcm>,
                    EcdhEs<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256Gcm,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
            }
        }
        KnownKeyAlg::P256 => {
            let _to_keys = to_keys
                .iter()
                .map(|vm| vm.as_p256().map(|k| (&vm.id, k)))
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = _to_keys
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            match enc_alg_anon {
                AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    EcdhEs<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                    Chacha20Key<XC20P>,
                    EcdhEs<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::Xc20P,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
                AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                    AesKey<A256Gcm>,
                    EcdhEs<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::EcdhEsA256kw,
                    jwe::EncAlgorithm::A256Gcm,
                    None,
                    &to_keys,
                )
                .context("Unable produce anoncrypt envelope")?,
            }
        }
        _ => Err(err_msg(
            ErrorKind::InvalidState,
            "Unsupported recipient key agreement alg",
        ))?,
    };

    let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id).collect();
    Ok((msg, to_kids))
}
