use crate::pqc_jwe::{Algorithm as JweAlgorithm, EncAlgorithm, JWE};
use crate::{
    algorithms::AuthCryptAlg,
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultExt},
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyPair},
        did::did_or_url,
    },
    UnpackMetadata, UnpackOptions,
};

pub(crate) async fn _try_unpack_authcrypt<'dr, 'sr>(
    msg: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    opts: &UnpackOptions,
    metadata: &mut UnpackMetadata,
) -> Result<Option<String>> {
    let jwe = match JWE::from_str(msg) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::Malformed => return Ok(None),
        Err(e) => Err(e)?,
    };

    let mut buf = vec![];
    let parsed_jwe = jwe.parse(&mut buf)?;

    // Only support PQC algorithms (ML-KEM + ML-DSA) - reject classical crypto
    match parsed_jwe.protected.alg {
        JweAlgorithm::MlKem768MlDsa65 | JweAlgorithm::MlKem1024MlDsa87 => {
            // PQC authcrypt - continue processing
        }
        _ => return Ok(None),
    }

    let parsed_jwe = parsed_jwe.verify_didcomm()?;

    let from_kid = std::str::from_utf8(
        parsed_jwe
            .apu
            .as_deref()
            .ok_or_else(|| err_msg(ErrorKind::Malformed, "No apu presented for authcrypt"))?,
    )
    .kind(ErrorKind::Malformed, "apu is invalid utf8")?;

    let (from_did, from_url) = did_or_url(from_kid);

    if from_url.is_none() {
        Err(err_msg(
            ErrorKind::Malformed,
            "Sender key can't be resolved to key agreement",
        ))?;
    }

    let from_ddoc = did_resolver
        .resolve(from_did)
        .await
        .kind(ErrorKind::InvalidState, "Unable resolve sender did")?
        .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Sender did not found"))?;

    // For AuthCrypt, the from_kid in APU is the sender's key agreement key
    // But we need the sender's authentication (signing) key for verification
    let _from_kem_kid = from_ddoc
        .key_agreement
        .iter()
        .find(|&k| k.as_str() == from_kid)
        .ok_or_else(|| err_msg(ErrorKind::DIDUrlNotFound, "Sender KEM kid not found in did"))?;

    // Get the sender's authentication (ML-DSA signing) key
    let from_auth_kid = from_ddoc.authentication.first().ok_or_else(|| {
        err_msg(
            ErrorKind::DIDUrlNotFound,
            "No authentication key found in sender DID doc",
        )
    })?;

    let from_key = from_ddoc
        .verification_method
        .iter()
        .find(|&vm| &vm.id == from_auth_kid)
        .ok_or_else(|| {
            err_msg(
                ErrorKind::DIDUrlNotFound,
                "Sender authentication verification method not found in did",
            )
        })?
        .as_key_pair()?;

    let to_kids: Vec<&str> = parsed_jwe
        .jwe
        .recipients
        .iter()
        .map(|r| &*r.header.kid)
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

    if metadata.encrypted_to_kids.is_none() {
        metadata.encrypted_to_kids = Some(to_kids.iter().map(|&k| k.to_owned()).collect());
    } else {
        // Verify that same keys used for authcrypt as for anoncrypt envelope
        let existing_kids: std::collections::HashSet<&str> = metadata
            .encrypted_to_kids
            .as_ref()
            .unwrap()
            .iter()
            .map(|s| s.as_str())
            .collect();
        let new_kids: std::collections::HashSet<&str> = to_kids.iter().copied().collect();
        if existing_kids != new_kids {
            return Err(err_msg(
                ErrorKind::InvalidState,
                "Key mismatch between anoncrypt and authcrypt envelopes",
            ));
        }
    }

    metadata.authenticated = true;
    metadata.encrypted = true;
    metadata.encrypted_from_kid = Some(from_kid.into());

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

        let _payload = match (&from_key, &to_key, &parsed_jwe.protected.enc) {
            (
                KnownKeyPair::MlDsa65(ref from_dsa_key),
                KnownKeyPair::MlKem768(ref to_key),
                EncAlgorithm::A256Gcm,
            ) => {
                metadata.enc_alg_auth = Some(AuthCryptAlg::MlKem768A256cbcHs512);

                use crate::pqc_jwe::decrypt_auth_ml_kem_768_dsa_65;
                use askar_crypto::alg::aes::{A256Gcm, AesKey};
                use base64::prelude::*;

                let recipient = parsed_jwe
                    .jwe
                    .recipients
                    .iter()
                    .find(|r| &*r.header.kid == to_kid)
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

                decrypt_auth_ml_kem_768_dsa_65::<AesKey<A256Gcm>>(
                    &encrypted_key,
                    &iv,
                    &ciphertext,
                    &tag,
                    &parsed_jwe.jwe.protected,
                    from_kid, // This is the sender's KEM kid from APU (used in signing)
                    to_kid,
                    from_dsa_key.public_key(), // This is the sender's DSA public key
                    to_key,
                )?
            }
            (
                KnownKeyPair::MlDsa87(ref from_dsa_key),
                KnownKeyPair::MlKem1024(ref to_key),
                EncAlgorithm::A256Gcm,
            ) => {
                metadata.enc_alg_auth = Some(AuthCryptAlg::MlKem1024A256cbcHs512);

                use crate::pqc_jwe::decrypt_auth_ml_kem_1024_dsa_87;
                use askar_crypto::alg::aes::{A256Gcm, AesKey};
                use base64::prelude::*;

                let recipient = parsed_jwe
                    .jwe
                    .recipients
                    .iter()
                    .find(|r| &*r.header.kid == to_kid)
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

                decrypt_auth_ml_kem_1024_dsa_87::<AesKey<A256Gcm>>(
                    &encrypted_key,
                    &iv,
                    &ciphertext,
                    &tag,
                    &parsed_jwe.jwe.protected,
                    from_kid, // This is the sender's KEM kid from APU (used in signing)
                    to_kid,
                    from_dsa_key.public_key(), // This is the sender's DSA public key
                    to_key,
                )?
            }
            _ => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported key agreement method",
            ))?,
        };

        payload = Some(_payload);

        if !opts.expect_decrypt_by_all_keys {
            break;
        }
    }

    let payload = payload.ok_or_else(|| err_msg(ErrorKind::InvalidState, "Payload is none"))?;

    let payload = String::from_utf8(payload)
        .kind(ErrorKind::Malformed, "Authcrypt payload is invalid utf8")?;

    Ok(Some(payload))
}
