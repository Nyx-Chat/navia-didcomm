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
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyAlg},
        did::did_or_url,
        secure_cmp::secure_string_eq,
    },
};

pub(crate) async fn anoncrypt<'dr, 'sr>(
    to: &[&str],
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    msg: &[u8],
    enc_alg_anon: &AnonCryptAlg,
) -> Result<(String, Vec<String>)> /* (msg, to_kids) */ {
    // Collect keys from ALL recipient DIDs
    let mut all_to_keys = Vec::new();

    for recipient in to {
        let (to_did, to_kid) = did_or_url(recipient);

        // Note: DID resolution caching is now handled by CachingDIDResolver in pack_encrypted
        let to_ddoc = did_resolver
            .resolve(to_did)
            .await
            .context("Unable resolve recipient did")?
            .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Recipient did not found"))?;

        // Get key agreements for this recipient
        let to_kids: Vec<_> = to_ddoc
            .key_agreement
            .iter()
            .filter(|kid| to_kid.map(|to_kid| kid == &to_kid).unwrap_or(true))
            .map(|s| s.as_str())
            .collect();

        if to_kids.is_empty() {
            Err(err_msg(
                ErrorKind::DIDUrlNotFound,
                format!("No key agreements found for recipient {to_did}"),
            ))?
        }

        // Resolve materials for this recipient's keys
        let recipient_keys = to_kids
            .into_iter()
            .map(|kid| {
                to_ddoc
                    .verification_method
                    .iter()
                    .find(|vm| secure_string_eq(&vm.id, kid))
                    .cloned() // Clone to avoid lifetime issues
                    .ok_or_else(|| {
                        err_msg(
                            ErrorKind::Malformed,
                            format!(
                                "No verification material found for recipient key agreement {kid}"
                            ),
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;

        all_to_keys.extend(recipient_keys);
    }

    if all_to_keys.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No recipient key agreements found across all recipients",
        ))?
    }

    let to_keys = all_to_keys;

    // Looking for first supported key to determine what key alg to use
    let key_alg = to_keys
        .iter()
        .filter(|key| key.key_alg() != KnownKeyAlg::Unsupported)
        .map(|key| key.key_alg())
        .next()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "No key agreement keys found for recipient",
            )
        })?;

    // Keep only keys with determined key alg
    let to_keys: Vec<_> = to_keys
        .iter()
        .filter(|key| key.key_alg() == key_alg)
        .collect();

    if to_keys.is_empty() {
        Err(err_msg(
            ErrorKind::NoCompatibleCrypto,
            "No compatible keys found across all recipients",
        ))?
    }

    // Validate that ALL original recipients have at least one compatible key
    // This ensures we're not silently excluding recipients due to incompatibility
    for recipient in to {
        let (to_did, _) = did_or_url(recipient);
        let has_compatible_key = to_keys.iter().any(|key| {
            // Check if key.id belongs to this DID (either "did#key" or exact match)
            key.id == to_did || key.id.starts_with(&format!("{to_did}#"))
        });

        if !has_compatible_key {
            Err(err_msg(
                ErrorKind::NoCompatibleCrypto,
                format!(
                    "Recipient {to_did} has no keys of type {key_alg:?}. All recipients must have compatible key types for multi-recipient encryption."
                ),
            ))?
        }
    }

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

    let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id.clone()).collect();
    Ok((msg, to_kids))
}
