use askar_crypto::alg::{
    aes::{A256Gcm, AesKey},
    chacha20::{Chacha20Key, XC20P},
};

use crate::pqc_jwe;

use crate::{
    algorithms::AnonCryptAlg,
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext, ResultExt},
    pqc_jwe as jwe,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyAlg},
        did::did_or_url,
        secure_cmp::secure_string_eq,
    },
};

pub(crate) async fn anoncrypt<'dr, 'sr>(
    to: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    msg: &[u8],
    enc_alg_anon: &AnonCryptAlg,
) -> Result<(String, Vec<String>)> /* (msg, to_kids) */ {
    let (to_did, to_kid) = did_or_url(to);

    // Note: DID resolution caching is now handled by CachingDIDResolver in pack_encrypted
    let to_ddoc = did_resolver
        .resolve(to_did)
        .await
        .context("Unable resolve recipient did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Recipient did not found"))?;

    // Initial list of recipient key ids is all key_agreements of recipient did doc
    // or one key if url was explicitly provided
    let to_kids: Vec<_> = to_ddoc
        .key_agreement
        .iter()
        .filter(|kid| to_kid.map(|to_kid| kid == &to_kid).unwrap_or(true))
        .map(|s| s.as_str())
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

    let msg =
        match key_alg {
            KnownKeyAlg::MlKem768 => {
                let _to_keys = to_keys
                    .iter()
                    .map(|vm| vm.as_ml_kem_768().map(|k| (&vm.id, k.public_key())))
                    .collect::<Result<Vec<_>>>()?;

                let to_keys: Vec<_> = _to_keys
                    .iter()
                    .map(|(id, key)| (id.as_str(), key))
                    .collect();

                match enc_alg_anon {
                    AnonCryptAlg::MlKem768Xc20p => pqc_jwe::encrypt_anon_ml_kem_768::<
                        Chacha20Key<XC20P>,
                    >(
                        msg, jwe::EncAlgorithm::Xc20P, &to_keys
                    )
                    .context("Unable produce ML-KEM-768 + XC20P anoncrypt envelope")?,

                    AnonCryptAlg::MlKem768A256gcm => pqc_jwe::encrypt_anon_ml_kem_768::<
                        AesKey<A256Gcm>,
                    >(
                        msg, jwe::EncAlgorithm::A256Gcm, &to_keys
                    )
                    .context("Unable produce ML-KEM-768 + A256GCM anoncrypt envelope")?,

                    _ => {
                        return Err(err_msg(
                            ErrorKind::InvalidState,
                            "ML-KEM-768 keys require ML-KEM-768 compatible algorithms",
                        ));
                    }
                }
            }
            KnownKeyAlg::MlKem1024 => {
                let _to_keys = to_keys
                    .iter()
                    .map(|vm| vm.as_ml_kem_1024().map(|k| (&vm.id, k.public_key())))
                    .collect::<Result<Vec<_>>>()?;

                let to_keys: Vec<_> = _to_keys
                    .iter()
                    .map(|(id, key)| (id.as_str(), key))
                    .collect();

                match enc_alg_anon {
                    AnonCryptAlg::MlKem1024Xc20p => pqc_jwe::encrypt_anon_ml_kem_1024::<
                        Chacha20Key<XC20P>,
                    >(
                        msg, jwe::EncAlgorithm::Xc20P, &to_keys
                    )
                    .kind(
                        ErrorKind::InvalidState,
                        "Unable produce ML-KEM-1024 + XC20P anoncrypt envelope",
                    )?,

                    AnonCryptAlg::MlKem1024A256gcm => pqc_jwe::encrypt_anon_ml_kem_1024::<
                        AesKey<A256Gcm>,
                    >(
                        msg, jwe::EncAlgorithm::A256Gcm, &to_keys
                    )
                    .kind(
                        ErrorKind::InvalidState,
                        "Unable produce ML-KEM-1024 + A256GCM anoncrypt envelope",
                    )?,

                    _ => Err(err_msg(ErrorKind::InvalidState, "Unsupported algorithm"))?,
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
