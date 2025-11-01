use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        p256::P256KeyPair,
        x25519::X25519KeyPair,
    },
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
};

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext},
    jwe,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyAlg},
        did::did_or_url,
        secure_cmp::secure_string_eq,
    },
};

pub(crate) async fn authcrypt<'dr, 'sr>(
    to: &[String],
    from: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    msg: &[u8],
    enc_alg_auth: &AuthCryptAlg,
    enc_alg_anon: &AnonCryptAlg,
    protect_sender: bool,
) -> Result<(String, String, Vec<String>)> /* (msg, from_kid, to_kids) */ {
    let (from_did, from_kid) = did_or_url(from);

    let from_ddoc = did_resolver
        .resolve(from_did)
        .await
        .context("Unable resolve sender did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Sender did not found"))?;

    // Initial list of sender keys is all key_agreements of sender did doc
    // or filtered to keep only provided key
    let from_kids: Vec<_> = from_ddoc
        .key_agreement
        .iter()
        .filter(|kid| from_kid.map(|from_kid| kid == &from_kid).unwrap_or(true))
        .map(|s| s.as_str())
        .collect();

    if from_kids.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No sender key agreements found",
        ))?
    }

    // Keep only sender keys present in the wallet
    let from_kids = secrets_resolver
        .find_secrets(&from_kids)
        .await
        .context("Unable find secrets")?;

    if from_kids.is_empty() {
        Err(err_msg(
            ErrorKind::SecretNotFound,
            "No sender secrets found",
        ))?
    }

    // Resolve materials for sender keys
    let from_keys = from_kids
        .into_iter()
        .map(|kid| {
            from_ddoc
                .verification_method
                .iter()
                .find(|vm| secure_string_eq(&vm.id, kid))
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::Malformed,
                        format!("No verification material found for sender key agreement {kid}"),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;

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
            .filter(|kid| to_kid.map_or(true, |to_kid| kid == &to_kid))
            .map(std::string::String::as_str)
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

    // Looking for first sender key that has supported crypto and intersects with recipient keys
    // by key alg
    let from_key = from_keys
        .iter()
        .filter(|key| key.key_alg() != KnownKeyAlg::Unsupported)
        .find(|from_key| {
            to_keys
                .iter()
                .any(|to_key| to_key.key_alg() == from_key.key_alg())
        })
        .copied()
        .ok_or_else(|| {
            err_msg(
                ErrorKind::NoCompatibleCrypto,
                "No common keys between sender and recipient found",
            )
        })?;

    // Resolve secret for found sender key
    let from_priv_key = secrets_resolver
        .get_secret(&from_key.id)
        .await
        .context("Unable resolve sender secret")?
        .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Sender secret not found"))?;

    let key_alg = from_key.key_alg();

    // Keep only recipient keys compatible with sender key
    let to_keys: Vec<_> = to_keys
        .into_iter()
        .filter(|key| key.key_alg() == key_alg)
        .collect();

    if to_keys.is_empty() {
        Err(err_msg(
            ErrorKind::NoCompatibleCrypto,
            "No compatible keys found across all recipients with sender's key type",
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
                    "Recipient {to_did} has no keys compatible with sender's key type ({key_alg:?}). All recipients must have compatible key types for multi-recipient encryption."
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

            let msg = match enc_alg_auth {
                AuthCryptAlg::A256cbcHs512Ecdh1puA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, X25519KeyPair>,
                    X25519KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::Ecdh1puA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    Some((&from_key.id, &from_priv_key.as_x25519()?)),
                    &to_keys,
                )
                .context("Unable produce authcrypt envelope")?,
            };

            if protect_sender {
                match enc_alg_anon {
                    AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::Xc20P,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, X25519KeyPair>,
                        X25519KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256Gcm,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                }
            } else {
                msg
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

            let msg = match enc_alg_auth {
                AuthCryptAlg::A256cbcHs512Ecdh1puA256kw => jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, P256KeyPair>,
                    P256KeyPair,
                    AesKey<A256Kw>,
                >(
                    msg,
                    jwe::Algorithm::Ecdh1puA256kw,
                    jwe::EncAlgorithm::A256cbcHs512,
                    Some((&from_key.id, &from_priv_key.as_p256()?)),
                    &to_keys,
                )
                .context("Unable produce authcrypt envelope")?,
            };

            if protect_sender {
                match enc_alg_anon {
                    AnonCryptAlg::A256cbcHs512EcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256CbcHs512>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256cbcHs512,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::Xc20pEcdhEsA256kw => jwe::encrypt::<
                        Chacha20Key<XC20P>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::Xc20P,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                    AnonCryptAlg::A256gcmEcdhEsA256kw => jwe::encrypt::<
                        AesKey<A256Gcm>,
                        EcdhEs<'_, P256KeyPair>,
                        P256KeyPair,
                        AesKey<A256Kw>,
                    >(
                        msg.as_bytes(),
                        jwe::Algorithm::EcdhEsA256kw,
                        jwe::EncAlgorithm::A256Gcm,
                        None,
                        &to_keys,
                    )
                    .context("Unable produce authcrypt envelope")?,
                }
            } else {
                msg
            }
        }
        _ => Err(err_msg(
            ErrorKind::Unsupported,
            "Unsupported recipient key agreement method",
        ))?,
    };

    let to_kids: Vec<_> = to_keys.into_iter().map(|vm| vm.id.clone()).collect();
    Ok((msg, from_key.id.clone(), to_kids))
}
