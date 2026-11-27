use crate::{
    error::{err_msg, ErrorKind, Result},
    secrets::SecretsResolver,
    utils::did::did_or_url,
};

/// The key IDs among `all_to_kids` that the secrets resolver holds a secret for. They must be
/// key agreement URLs of a single DID.
pub(super) async fn own_recipient_kids<'a>(
    all_to_kids: &'a [&'a str],
    secrets_resolver: &(dyn SecretsResolver + '_),
) -> Result<Vec<&'a str>> {
    let to_kids = secrets_resolver.find_secrets(all_to_kids).await?;

    let Some(first) = to_kids.first() else {
        return Err(err_msg(
            ErrorKind::SecretNotFound,
            "No recipient secrets found for current DID",
        ));
    };
    let (to_did, _) = did_or_url(first);

    if to_kids.iter().any(|k| {
        let (k_did, k_url) = did_or_url(k);
        (k_did != to_did) || (k_url.is_none())
    }) {
        return Err(err_msg(
            ErrorKind::Malformed,
            "Recipient keys for current DID are malformed or can't be resolved to key agreement",
        ));
    }

    Ok(to_kids)
}
