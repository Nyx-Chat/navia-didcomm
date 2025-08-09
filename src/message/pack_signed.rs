use serde::Serialize;

use crate::{
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext},
    secrets::SecretsResolver,
    utils::{
        crypto::{AsKnownKeyPair, KnownKeyPair},
        did::{did_or_url, is_did},
    },
    Message,
};

impl Message {
    /// Produces `DIDComm Signed Message`
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-message.
    ///
    /// Signed messages are not necessary to provide message integrity (tamper evidence),
    /// or to prove the sender to the recipient. Both of these guarantees automatically occur
    /// with the authenticated encryption in DIDComm encrypted messages. Signed messages are only
    /// necessary when the origin of plaintext must be provable to third parties,
    /// or when the sender can't be proven to the recipient by authenticated encryption because
    /// the recipient is not known in advance (e.g., in a broadcast scenario).
    /// We therefore expect signed messages to be used in a few cases, but not as a matter of course.
    ///
    /// # Parameters
    /// - `sign_by` a DID or key ID the sender uses for signing
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    ///
    /// # Returns
    /// Tuple (signed_message, metadata)
    /// - `signed_message` a DIDComm signed message as JSON string
    /// - `metadata` additional metadata about this `encrypt` execution like used keys identifiers and algorithms.
    ///
    /// # Errors
    /// - `DIDNotResolved` Sender DID not found.
    /// - `DIDUrlNotFound` DID doesn't contain mentioned DID URLs (key IDs).
    /// - `SecretNotFound` Sender secret is not found.
    /// - `InvalidState` PQC signature creation failed or unsupported algorithm.
    /// - `SignatureCreationFailed` ML-DSA signature generation failed.
    /// - `IOError` IO error during DID or secrets resolving.
    pub async fn pack_signed<'dr, 'sr>(
        &self,
        sign_by: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    ) -> Result<(String, PackSignedMetadata)> {
        self._validate_pack_signed(sign_by)?;

        let (did, key_id) = did_or_url(sign_by);

        let did_doc = did_resolver
            .resolve(did)
            .await
            .context("Unable resolve signer did")?
            .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Signer did not found"))?;

        let authentications: Vec<_> = if let Some(key_id) = key_id {
            did_doc
                .authentication
                .iter()
                .find(|a| *a == key_id)
                .ok_or_else(|| {
                    err_msg(
                        ErrorKind::DIDUrlNotFound,
                        "Signer key id not found in did doc",
                    )
                })?;

            vec![key_id]
        } else {
            did_doc.authentication.iter().map(|s| s.as_str()).collect()
        };

        let key_id = *secrets_resolver
            .find_secrets(&authentications)
            .await
            .context("Unable find secrets")?
            .first()
            .ok_or_else(|| err_msg(ErrorKind::SecretNotFound, "No signer secrets found"))?;

        let secret = secrets_resolver
            .get_secret(key_id)
            .await
            .context("Unable get secret")?
            .ok_or_else(|| err_msg(ErrorKind::SecretNotFound, "Signer secret not found"))?;

        let sign_key = secret
            .as_key_pair()
            .context("Unable instantiate sign key")?;

        let payload = self.pack_plaintext(did_resolver).await?;

        let msg = match sign_key {
            KnownKeyPair::MlDsa65(ref key) => {
                crate::pqc_jws::sign_ml_dsa_65(payload.as_bytes(), key_id, key)
            }
            KnownKeyPair::MlDsa87(ref key) => {
                crate::pqc_jws::sign_ml_dsa_87(payload.as_bytes(), key_id, key)
            }

            // Post-Quantum Cryptography signing only
            _ => Err(err_msg(ErrorKind::Unsupported, "Unsupported signature alg"))?,
        }
        .context("Unable produce signature")?;

        let metadata = PackSignedMetadata {
            sign_by_kid: key_id.to_owned(),
        };

        Ok((msg, metadata))
    }

    fn _validate_pack_signed(&self, sign_by: &str) -> Result<()> {
        if !is_did(sign_by) {
            Err(err_msg(
                ErrorKind::IllegalArgument,
                "`sign_from` value is not a valid DID or DID URL",
            ))?;
        }

        Ok(())
    }
}

/// Additional metadata about this `pack` method execution like used key identifiers.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct PackSignedMetadata {
    /// Identifier (DID URL) of sign key.
    pub sign_by_kid: String,
}
