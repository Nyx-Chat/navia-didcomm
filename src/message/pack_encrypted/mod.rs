mod anoncrypt;
mod authcrypt;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::{CachingDIDResolver, DIDResolver},
    error::{err_msg, ErrorKind, Result, ResultContext},
    protocols::routing::wrap_in_forward_if_needed,
    secrets::SecretsResolver,
    utils::did::{did_or_url, is_did},
    Message, PackSignedMetadata,
};

pub(crate) use self::anoncrypt::anoncrypt;

use self::authcrypt::authcrypt;

impl Message {
    /// Produces `DIDComm Encrypted Message`
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-message.
    ///
    /// A DIDComm encrypted message is an encrypted JWM (JSON Web Messages) and
    /// hides its content from all but authorized recipients, discloses (optionally) and proves
    /// the sender to exactly and only those recipients, and provides integrity guarantees.
    /// It is important in privacy-preserving routing. It is what normally moves over network
    /// transports in DIDComm applications, and is the safest format for storing DIDComm data at rest.
    ///
    /// Encryption is done as following:
    ///  - Encryption is done via the keys from the `keyAgreement` verification relationship in the DID Doc
    ///  - if `to` is a DID, then multiplex encryption is done for all keys from the
    ///    receiver's `keyAgreement` verification relationship
    ///    which are compatible the sender's key.
    ///  - if `to` is a key ID, then encryption is done for the receiver's `keyAgreement`
    ///    verification method identified by the given key ID.
    ///  - if `from` is a DID, then sender `keyAgreement` will be negotiated based on recipient preference and
    ///    sender-recipient crypto compatibility.
    ///  - if `from` is a key ID, then the sender's `keyAgreement` verification method
    ///    identified by the given key ID is used.
    ///  - if `from` is None, then anonymous encryption is done and there will be no sender authentication property.
    ///
    /// It's possible to add non-repudiation by providing `sign_by` parameter.
    ///
    /// # Params
    /// - `to` recipient DID or key ID the sender uses encryption.
    /// - `from` a sender DID or key ID. If set message will be repudiable authenticated or anonymous otherwise.
    ///   Must match `from` header in Plaintext if the header is set.
    /// - `sign_by` if `Some` message will be additionally signed to provide additional non-repudiable authentication
    ///   by provided DID/Key. Signed messages are only necessary when the origin of plaintext must be provable
    ///   to third parties, or when the sender can't be proven to the recipient by authenticated encryption because
    ///   the recipient is not known in advance (e.g., in a broadcast scenario).
    ///   Adding a signature when one is not needed can degrade rather than enhance security because
    ///   it relinquishes the sender's ability to speak off the record.
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs.
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets.
    /// - `options` allow fine configuration of packing process and have implemented `Default`.
    ///
    /// # Returns
    /// Tuple `(encrypted_message, metadata)`.
    /// - `encrypted_message` A DIDComm encrypted message as a JSON string.
    /// - `metadata` additional metadata about this `pack` execution like used keys identifiers,
    ///   used messaging service.
    ///
    /// # Errors
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotFound` DID doesn't contain mentioned DID URLs (key IDs).
    /// - `SecretNotFound` Sender secret is not found.
    /// - `NoCompatibleCrypto` No compatible PQC keys found between sender and recipient.
    /// - `InvalidState` Library error or unsupported PQC algorithm configuration.
    /// - `IllegalArgument` Invalid input parameters (empty DIDs, malformed data).
    /// - `Malformed` Invalid key format or structure.
    /// - `EncryptionFailed` PQC encryption operation failed.
    /// - `IOError` IO error during DID or secrets resolving.
    pub async fn pack_encrypted<'dr, 'sr>(
        &self,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &PackEncryptedOptions,
    ) -> Result<(String, PackEncryptedMetadata)> {
        self._validate_pack_encrypted(to, from, sign_by)?;

        // Use caching resolver to avoid duplicate DID resolutions
        let caching_resolver = CachingDIDResolver::new(did_resolver);

        // Extract JWE-related steps to a separate method for better modularity
        let (msg, from_kid, to_kids, sign_by_kid) = self
            ._pack_jwe_envelope(
                to,
                from,
                sign_by,
                &caching_resolver,
                secrets_resolver,
                options,
            )
            .await?;

        let (msg, messaging_service) =
            match wrap_in_forward_if_needed(&msg, to, &caching_resolver, options).await? {
                Some((forward_msg, messaging_service)) => (forward_msg, Some(messaging_service)),
                None => (msg, None),
            };

        let metadata = PackEncryptedMetadata {
            messaging_service,
            from_kid,
            sign_by_kid,
            to_kids,
        };

        Ok((msg, metadata))
    }

    fn _validate_pack_encrypted(
        &self,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
    ) -> Result<()> {
        if !is_did(to) {
            Err(err_msg(
                ErrorKind::IllegalArgument,
                "`to` value is not a valid DID or DID URL",
            ))?;
        }

        match from {
            Some(from) if !is_did(from) => Err(err_msg(
                ErrorKind::IllegalArgument,
                "`from` value is not a valid DID or DID URL",
            ))?,
            _ => {}
        }

        match sign_by {
            Some(sign_by) if !is_did(sign_by) => Err(err_msg(
                ErrorKind::IllegalArgument,
                "`sign_from` value is not a valid DID or DID URL",
            ))?,
            _ => {}
        }

        let (to_did, _) = did_or_url(to);

        match self.to {
            Some(ref sto) if !sto.contains(&to_did.into()) => {
                Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "`message.to` value does not contain `to` value's DID",
                ))?;
            }
            _ => {}
        }

        match (from, &self.from) {
            (Some(from), Some(ref sfrom)) if did_or_url(from).0 != sfrom => Err(err_msg(
                ErrorKind::IllegalArgument,
                "`message.from` value is not equal to `from` value's DID",
            ))?,
            _ => {}
        }

        Ok(())
    }

    /// Internal method that handles JWE envelope creation (signing + encryption)
    /// This method is separated from pack_encrypted to allow reuse in routing protocols
    async fn _pack_jwe_envelope<'dr, 'sr>(
        &self,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &PackEncryptedOptions,
    ) -> Result<(String, Option<String>, Vec<String>, Option<String>)> {
        // Step 1: Create signed message if sign_by is provided, otherwise use plaintext
        let (msg, sign_by_kid) = if let Some(sign_by) = sign_by {
            let (msg, PackSignedMetadata { sign_by_kid }) = self
                .pack_signed(sign_by, did_resolver, secrets_resolver)
                .await
                .context("Unable produce sign envelope")?;
            (msg, Some(sign_by_kid))
        } else {
            let msg = self
                .pack_plaintext(did_resolver)
                .await
                .context("Unable produce plaintext")?;
            (msg, None)
        };

        // Step 2: Apply encryption (authcrypt if from is provided, anoncrypt otherwise)
        let (msg, from_kid, to_kids) = if let Some(from) = from {
            let (msg, from_kid, to_kids) = authcrypt(
                to,
                from,
                did_resolver,
                secrets_resolver,
                msg.as_bytes(),
                &options.enc_alg_auth,
                &options.enc_alg_anon,
                options.protect_sender,
            )
            .await?;
            (msg, Some(from_kid), to_kids)
        } else {
            let (msg, to_kids) =
                anoncrypt(to, did_resolver, msg.as_bytes(), &options.enc_alg_anon).await?;
            (msg, None, to_kids)
        };

        Ok((msg, from_kid, to_kids, sign_by_kid))
    }
}

/// Allow fine configuration of packing process.
#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
pub struct PackEncryptedOptions {
    /// If `true` and message is authenticated than information about sender will be protected from mediators, but
    /// additional re-encryption will be required. For anonymous messages this property will be ignored.
    #[serde(default)]
    pub protect_sender: bool,

    /// Whether the encrypted messages need to be wrapped into `Forward` messages to be sent to Mediators
    /// as defined by the `Forward` protocol.
    #[serde(default = "crate::utils::serde::_true")]
    pub forward: bool,

    /// if forward is enabled these optional headers can be passed to the wrapping `Forward` messages.
    /// If forward is disabled this property will be ignored.
    pub forward_headers: Option<HashMap<String, Value>>,

    /// Identifier (DID URL) of messaging service (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
    /// If DID doc contains multiple messaging services it allows specify what service to use.
    /// If not present first service will be used.
    pub messaging_service: Option<String>,

    /// Algorithm used for authenticated encryption
    #[serde(default)]
    pub enc_alg_auth: AuthCryptAlg,

    /// Algorithm used for anonymous encryption
    #[serde(default)]
    pub enc_alg_anon: AnonCryptAlg,
}

impl Default for PackEncryptedOptions {
    fn default() -> Self {
        PackEncryptedOptions {
            protect_sender: false,
            forward: true,
            forward_headers: None,
            messaging_service: None,
            enc_alg_auth: AuthCryptAlg::default(),
            enc_alg_anon: AnonCryptAlg::default(),
        }
    }
}

/// Additional metadata about this `encrypt` method execution like used keys identifiers,
/// used messaging service.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct PackEncryptedMetadata {
    /// Information about messaging service used for message preparation.
    /// Practically `service_endpoint` field can be used to transport the message.
    pub messaging_service: Option<MessagingServiceMetadata>,

    /// Identifier (DID URL) of sender key used for message encryption.
    pub from_kid: Option<String>,

    /// Identifier (DID URL) of sender key used for message sign.
    pub sign_by_kid: Option<String>,

    /// Identifiers (DID URLs) of recipient keys used for message encryption.
    pub to_kids: Vec<String>,
}

/// Information about messaging service used for message preparation.
/// Practically `service_endpoint` field can be used to transport the message.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct MessagingServiceMetadata {
    /// Identifier (DID URL) of used messaging service.
    pub id: String,

    /// Service endpoint of used messaging service.
    pub service_endpoint: String,
}
