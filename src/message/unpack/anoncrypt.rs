// PQC-only - classical algorithms removed

use crate::{
    algorithms::AnonCryptAlg,
    error::{err_msg, ErrorKind, Result, ResultExt},
    pqc_jwe as jwe,
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyPair},
        did::did_or_url,
    },
    UnpackMetadata, UnpackOptions,
};

pub(crate) async fn _try_unpack_anoncrypt<'sr>(
    msg: &str,
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    opts: &UnpackOptions,
    metadata: &mut UnpackMetadata,
) -> Result<Option<String>> {
    let jwe = match jwe::JWE::from_str(msg) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::Malformed => return Ok(None),
        Err(e) => Err(e)?,
    };

    let mut buf = vec![];
    let parsed_jwe = jwe.parse(&mut buf)?;

    // Only support PQC algorithms (ML-KEM) - reject classical crypto
    match parsed_jwe.protected.alg {
        jwe::Algorithm::MlKem768 | jwe::Algorithm::MlKem1024 => {
            // PQC anoncrypt - continue processing
        }
        _ => return Ok(None),
    }

    let parsed_jwe = parsed_jwe.verify_didcomm()?;

    let to_kids: Vec<&str> = parsed_jwe
        .jwe
        .recipients
        .iter()
        .map(|r| r.header.kid.as_str())
        .collect();

    let to_kid = to_kids
        .first()
        .copied()
        .ok_or_else(|| err_msg(ErrorKind::Malformed, "No recipient keys found"))?;

    let (to_did, _) = did_or_url(to_kid);

    if to_kids.iter().any(|k| {
        let (k_did, k_url) = did_or_url(k);
        (k_did != to_did) || (k_url.is_none())
    }) {
        Err(err_msg(
            ErrorKind::Malformed,
            "Recipient keys are outside of one did or can't be resolved to key agreement",
        ))?;
    }

    metadata.encrypted_to_kids = Some(to_kids.iter().map(|&k| k.to_owned()).collect());
    metadata.encrypted = true;
    metadata.anonymous_sender = true;

    let to_kids_found = secrets_resolver.find_secrets(&to_kids).await?;

    if to_kids_found.is_empty() {
        Err(err_msg(
            ErrorKind::SecretNotFound,
            "No recipient secrets found",
        ))?;
    }

    let mut payload: Option<Vec<u8>> = None;

    for to_kid in to_kids_found {
        let to_key = secrets_resolver
            .get_secret(to_kid)
            .await?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::InvalidState,
                    "Recipient secret not found after existence checking",
                )
            })?
            .as_key_pair()?;

        let payload_bytes = match (to_key, &parsed_jwe.protected.enc) {
            (KnownKeyPair::MlKem768(ref to_key), jwe::EncAlgorithm::A256Gcm) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::MlKem768A256gcm);

                use crate::pqc_jwe::decrypt_anon_ml_kem_768;
                use askar_crypto::alg::aes::{A256Gcm, AesKey};
                use base64::prelude::*;

                let recipient = parsed_jwe
                    .jwe
                    .recipients
                    .iter()
                    .find(|r| r.header.kid == to_kid)
                    .ok_or_else(|| err_msg(ErrorKind::Malformed, "Recipient not found"))?;

                let encrypted_key = BASE64_URL_SAFE_NO_PAD
                    .decode(&recipient.encrypted_key)
                    .kind(ErrorKind::Malformed, "Invalid base64 in encrypted_key")?;
                let iv = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.iv)
                    .kind(ErrorKind::Malformed, "Invalid base64 in iv")?;
                let ciphertext = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.ciphertext)
                    .kind(ErrorKind::Malformed, "Invalid base64 in ciphertext")?;
                let tag = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.tag)
                    .kind(ErrorKind::Malformed, "Invalid base64 in tag")?;

                decrypt_anon_ml_kem_768::<AesKey<A256Gcm>>(
                    &encrypted_key,
                    &iv,
                    &ciphertext,
                    &tag,
                    &parsed_jwe.jwe.protected,
                    &recipient.header.kid,
                    to_key,
                )?
            }
            (KnownKeyPair::MlKem768(ref to_key), jwe::EncAlgorithm::Xc20P) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::MlKem768Xc20p);

                use crate::pqc_jwe::decrypt_anon_ml_kem_768;
                use askar_crypto::alg::chacha20::{Chacha20Key, XC20P};
                use base64::prelude::*;

                let recipient = parsed_jwe
                    .jwe
                    .recipients
                    .iter()
                    .find(|r| r.header.kid == to_kid)
                    .ok_or_else(|| err_msg(ErrorKind::Malformed, "Recipient not found"))?;

                let encrypted_key = BASE64_URL_SAFE_NO_PAD
                    .decode(&recipient.encrypted_key)
                    .kind(ErrorKind::Malformed, "Invalid base64 in encrypted_key")?;
                let iv = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.iv)
                    .kind(ErrorKind::Malformed, "Invalid base64 in iv")?;
                let ciphertext = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.ciphertext)
                    .kind(ErrorKind::Malformed, "Invalid base64 in ciphertext")?;
                let tag = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.tag)
                    .kind(ErrorKind::Malformed, "Invalid base64 in tag")?;

                decrypt_anon_ml_kem_768::<Chacha20Key<XC20P>>(
                    &encrypted_key,
                    &iv,
                    &ciphertext,
                    &tag,
                    &parsed_jwe.jwe.protected,
                    &recipient.header.kid,
                    to_key,
                )?
            }
            (KnownKeyPair::MlKem1024(ref to_key), jwe::EncAlgorithm::A256Gcm) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::MlKem1024A256gcm);

                use crate::pqc_jwe::decrypt_anon_ml_kem_1024;
                use askar_crypto::alg::aes::{A256Gcm, AesKey};
                use base64::prelude::*;

                let recipient = parsed_jwe
                    .jwe
                    .recipients
                    .iter()
                    .find(|r| r.header.kid == to_kid)
                    .ok_or_else(|| err_msg(ErrorKind::Malformed, "Recipient not found"))?;

                let encrypted_key = BASE64_URL_SAFE_NO_PAD
                    .decode(&recipient.encrypted_key)
                    .kind(ErrorKind::Malformed, "Invalid base64 in encrypted_key")?;
                let iv = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.iv)
                    .kind(ErrorKind::Malformed, "Invalid base64 in iv")?;
                let ciphertext = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.ciphertext)
                    .kind(ErrorKind::Malformed, "Invalid base64 in ciphertext")?;
                let tag = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.tag)
                    .kind(ErrorKind::Malformed, "Invalid base64 in tag")?;

                decrypt_anon_ml_kem_1024::<AesKey<A256Gcm>>(
                    &encrypted_key,
                    &iv,
                    &ciphertext,
                    &tag,
                    &parsed_jwe.jwe.protected,
                    &recipient.header.kid,
                    to_key,
                )?
            }
            (KnownKeyPair::MlKem1024(ref to_key), jwe::EncAlgorithm::Xc20P) => {
                metadata.enc_alg_anon = Some(AnonCryptAlg::MlKem1024Xc20p);

                use crate::pqc_jwe::decrypt_anon_ml_kem_1024;
                use askar_crypto::alg::chacha20::{Chacha20Key, XC20P};
                use base64::prelude::*;

                let recipient = parsed_jwe
                    .jwe
                    .recipients
                    .iter()
                    .find(|r| r.header.kid == to_kid)
                    .ok_or_else(|| err_msg(ErrorKind::Malformed, "Recipient not found"))?;

                let encrypted_key = BASE64_URL_SAFE_NO_PAD
                    .decode(&recipient.encrypted_key)
                    .kind(ErrorKind::Malformed, "Invalid base64 in encrypted_key")?;
                let iv = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.iv)
                    .kind(ErrorKind::Malformed, "Invalid base64 in iv")?;
                let ciphertext = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.ciphertext)
                    .kind(ErrorKind::Malformed, "Invalid base64 in ciphertext")?;
                let tag = BASE64_URL_SAFE_NO_PAD
                    .decode(&parsed_jwe.jwe.tag)
                    .kind(ErrorKind::Malformed, "Invalid base64 in tag")?;

                decrypt_anon_ml_kem_1024::<Chacha20Key<XC20P>>(
                    &encrypted_key,
                    &iv,
                    &ciphertext,
                    &tag,
                    &parsed_jwe.jwe.protected,
                    &recipient.header.kid,
                    to_key,
                )?
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported recipient key agreement method",
            ))?,
        };

        payload = Some(payload_bytes);

        if !opts.expect_decrypt_by_all_keys {
            break;
        }
    }

    let payload = payload.ok_or_else(|| err_msg(ErrorKind::InvalidState, "Payload is none"))?;

    let payload = String::from_utf8(payload)
        .kind(ErrorKind::Malformed, "Anoncrypt payload is invalid utf8")?;

    Ok(Some(payload))
}
