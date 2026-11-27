use crate::{
    did::{DIDResolver, VerificationMethod},
    error::{err_msg, ErrorKind, Result, ResultContext},
    utils::{did::did_or_url, secure_cmp::secure_string_eq},
};

/// Key agreement methods of every recipient, narrowed to one key where the recipient is a key ID.
pub(super) async fn recipient_key_agreements(
    to: &[&str],
    did_resolver: &(dyn DIDResolver + '_),
) -> Result<Vec<VerificationMethod>> {
    let mut all_to_keys = Vec::new();

    for recipient in to {
        let (to_did, to_kid) = did_or_url(recipient);

        let to_ddoc = did_resolver
            .resolve(to_did)
            .await
            .context("Unable resolve recipient did")?
            .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Recipient did not found"))?;

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
            ))?;
        }

        for kid in to_kids {
            let method = to_ddoc
                .verification_method
                .iter()
                .find(|vm| secure_string_eq(&vm.id, kid))
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::Malformed,
                        format!("No verification material found for recipient key agreement {kid}"),
                    )
                })?;
            all_to_keys.push(method.clone());
        }
    }

    if all_to_keys.is_empty() {
        Err(err_msg(
            ErrorKind::DIDUrlNotFound,
            "No recipient key agreements found across all recipients",
        ))?;
    }

    Ok(all_to_keys)
}

/// Fails unless every recipient owns at least one of `to_keys`, so that narrowing the keys to
/// one algorithm never silently drops a recipient. `requirement` completes "has no keys ...".
pub(super) fn ensure_every_recipient_has_key(
    to: &[&str],
    to_keys: &[VerificationMethod],
    requirement: &str,
) -> Result<()> {
    for recipient in to {
        let (to_did, _) = did_or_url(recipient);
        let has_compatible_key = to_keys
            .iter()
            .any(|key| key.id == to_did || key.id.starts_with(&format!("{to_did}#")));

        if !has_compatible_key {
            Err(err_msg(
                ErrorKind::NoCompatibleCrypto,
                format!(
                    "Recipient {to_did} has no keys {requirement}. All recipients must have compatible key types for multi-recipient encryption."
                ),
            ))?;
        }
    }
    Ok(())
}
