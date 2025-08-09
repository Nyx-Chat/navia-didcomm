use askar_crypto::alg::{
    aes::{A256Gcm, AesKey},
    chacha20::{Chacha20Key, XC20P},
};

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    pqc_jwe, pqc_jwe as jwe,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyAlg},
        did::did_or_url,
        secure_cmp::secure_string_eq,
    },
};

pub(crate) async fn authcrypt<'dr, 'sr>(
    to: &str,
    from: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    msg: &[u8],
    enc_alg_auth: &AuthCryptAlg,
    enc_alg_anon: &AnonCryptAlg,
    protect_sender: bool,
) -> Result<(String, String, Vec<String>)> /* (msg, from_kid, to_kids) */ {
    let (to_did, to_kid) = did_or_url(to);

    // Note: DID resolution caching is now handled by CachingDIDResolver in pack_encrypted
    let to_ddoc = did_resolver
        .resolve(to_did)
        .await
        .context("Unable resolve recipient did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Recipient did not found"))?;

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
        .filter(|kid| from_kid.map_or(true, |from_kid| kid == &from_kid))
        .map(std::string::String::as_str)
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

    // Initial list of recipient keys is all key_agreements of recipient did doc
    // or filtered to keep only provided key
    let to_kids: Vec<_> = to_ddoc
        .key_agreement
        .iter()
        .filter(|kid| to_kid.map_or(true, |to_kid| kid == &to_kid))
        .map(std::string::String::as_str)
        .collect();

    if to_kids.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No recipient key agreements found",
        ))?
    }

    // Resolve materials for recipient keys
    let to_keys = to_kids
        .into_iter()
        .map(|kid| {
            to_ddoc
                .verification_method
                .iter()
                .find(|vm| secure_string_eq(&vm.id, kid))
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::Malformed,
                        format!("No verification material found for recipient key agreement {kid}"),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;

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

    // Resolve secret for found sender key (ML-KEM for encryption)
    let _from_priv_key = secrets_resolver
        .get_secret(&from_key.id)
        .await
        .context("Unable resolve sender secret")?
        .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Sender secret not found"))?;

    // For AuthCrypt, we also need the sender's signing key (ML-DSA)
    // Find authentication key in sender DID document
    let auth_key_id = from_ddoc.authentication.first().ok_or_else(|| {
        err_msg(
            ErrorKind::DIDUrlNotFound,
            "No authentication key found in sender DID doc",
        )
    })?;

    let auth_secret = secrets_resolver
        .get_secret(auth_key_id)
        .await
        .context("Unable resolve sender authentication secret")?
        .ok_or_else(|| {
            err_msg(
                ErrorKind::InvalidState,
                "Sender authentication secret not found",
            )
        })?;

    let key_alg = from_key.key_alg();

    // Keep only recipient keys compatible with sender key
    let to_keys: Vec<_> = to_keys
        .into_iter()
        .filter(|key| key.key_alg() == key_alg)
        .collect();

    let msg = match key_alg {
        KnownKeyAlg::MlKem1024 => {
            let to_key_pairs = to_keys
                .iter()
                .map(|vm| vm.as_ml_kem_1024().map(|k| (&vm.id, k.public_key())))
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = to_key_pairs
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            let sender_key_pair = auth_secret.as_ml_dsa_87()?;

            let msg = match enc_alg_auth {
                AuthCryptAlg::MlKem1024A256cbcHs512 => {
                    pqc_jwe::encrypt_auth_ml_kem_1024_dsa_87::<AesKey<A256Gcm>>(
                        msg,
                        jwe::EncAlgorithm::A256Gcm,
                        &from_key.id,
                        &sender_key_pair,
                        &to_keys,
                    )
                    .kind(
                        ErrorKind::InvalidState,
                        "Unable produce ML-KEM-1024 + DSA-87 authcrypt envelope",
                    )?
                }

                AuthCryptAlg::MlKem768A256cbcHs512 => {
                    return Err(err_msg(
                        ErrorKind::NoCompatibleCrypto,
                        "ML-KEM-768 algorithm not supported with ML-KEM-1024 keys",
                    ))
                }
            };

            if protect_sender {
                match enc_alg_anon {
                    AnonCryptAlg::MlKem1024Xc20p => {
                        pqc_jwe::encrypt_anon_ml_kem_1024::<Chacha20Key<XC20P>>(
                            msg.as_bytes(),
                            jwe::EncAlgorithm::Xc20P,
                            &to_keys,
                        )
                        .kind(
                            ErrorKind::InvalidState,
                            "Unable produce ML-KEM-1024 + XC20P anoncrypt envelope",
                        )?
                    }

                    AnonCryptAlg::MlKem1024A256gcm => {
                        pqc_jwe::encrypt_anon_ml_kem_1024::<AesKey<A256Gcm>>(
                            msg.as_bytes(),
                            jwe::EncAlgorithm::A256Gcm,
                            &to_keys,
                        )
                        .kind(
                            ErrorKind::InvalidState,
                            "Unable produce ML-KEM-1024 + A256GCM anoncrypt envelope",
                        )?
                    }

                    _ => {
                        return Err(err_msg(
                            ErrorKind::InvalidState,
                            "Unsupported AuthCrypt algorithm",
                        ))
                    }
                }
            } else {
                msg
            }
        }
        KnownKeyAlg::MlKem768 => {
            let to_key_pairs = to_keys
                .iter()
                .map(|vm| vm.as_ml_kem_768().map(|k| (&vm.id, k.public_key())))
                .collect::<Result<Vec<_>>>()?;

            let to_keys: Vec<_> = to_key_pairs
                .iter()
                .map(|(id, key)| (id.as_str(), key))
                .collect();

            let sender_key_pair = auth_secret.as_ml_dsa_65()?;

            let msg = match enc_alg_auth {
                AuthCryptAlg::MlKem768A256cbcHs512 => {
                    pqc_jwe::encrypt_auth_ml_kem_768_dsa_65::<AesKey<A256Gcm>>(
                        msg,
                        jwe::EncAlgorithm::A256Gcm,
                        &from_key.id,
                        &sender_key_pair,
                        &to_keys,
                    )
                    .kind(
                        ErrorKind::InvalidState,
                        "Unable produce ML-KEM-768 + DSA-65 authcrypt envelope",
                    )?
                }

                AuthCryptAlg::MlKem1024A256cbcHs512 => {
                    return Err(err_msg(
                        ErrorKind::NoCompatibleCrypto,
                        "ML-KEM-1024 algorithm not supported with ML-KEM-768 keys",
                    ))
                }
            };

            if protect_sender {
                match enc_alg_anon {
                    AnonCryptAlg::MlKem768Xc20p => {
                        pqc_jwe::encrypt_anon_ml_kem_768::<Chacha20Key<XC20P>>(
                            msg.as_bytes(),
                            jwe::EncAlgorithm::Xc20P,
                            &to_keys,
                        )
                        .kind(
                            ErrorKind::InvalidState,
                            "Unable produce ML-KEM-768 + XC20P authcrypt envelope",
                        )?
                    }

                    AnonCryptAlg::MlKem768A256gcm => {
                        pqc_jwe::encrypt_anon_ml_kem_768::<AesKey<A256Gcm>>(
                            msg.as_bytes(),
                            jwe::EncAlgorithm::A256Gcm,
                            &to_keys,
                        )
                        .kind(
                            ErrorKind::InvalidState,
                            "Unable produce ML-KEM-768 + A256GCM authcrypt envelope",
                        )?
                    }

                    _ => {
                        return Err(err_msg(
                            ErrorKind::InvalidState,
                            "Unsupported AuthCrypt algorithm",
                        ))
                    }
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
