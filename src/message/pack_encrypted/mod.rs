mod anoncrypt;
mod authcrypt;
mod recipients;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::{CachingDIDResolver, DIDResolver},
    error::{err_msg, ErrorKind, Result, ResultContext},
    message::padding,
    protocols::routing::{
        tree::{analyze_routing_paths, group_by_common_routes},
        wrap::wrap_with_routing_tree,
    },
    secrets::SecretsResolver,
    utils::did::{did_or_url, is_did},
    Message, PackSignedMetadata, PadFloor,
};

pub(crate) use self::anoncrypt::anoncrypt;

use self::authcrypt::authcrypt;

#[cfg(test)]
pub(crate) use self::authcrypt::authcrypt as authcrypt_raw;

impl Message {
    /// Produces `DIDComm Encrypted Message`
    /// <https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-message>.
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
    /// - `to` slice of recipient DIDs or key IDs for encryption. All recipients will share the same encrypted content
    ///   but each will receive their own encrypted key. All recipients must have compatible key types.
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
    /// Vector of tuples `(encrypted_message, metadata)`.
    /// - When forwarding is disabled or no routing is needed, returns a Vec with a single element.
    /// - When multiple recipients have different routing paths, returns multiple messages
    ///   (one per routing path) for optimal delivery.
    /// - `encrypted_message` A DIDComm encrypted message as a JSON string.
    /// - `metadata` additional metadata about this `pack` execution like used keys identifiers,
    ///   used messaging service.
    ///
    /// # Multi-Recipient Optimization
    /// When encrypting for multiple recipients, the library:
    /// - Uses a single shared Content Encryption Key (CEK) for all recipients (per DIDComm v2 spec)
    /// - Automatically deduplicates recipient DIDs if the same DID appears multiple times
    /// - Analyzes mediator routing chains to minimize message count:
    ///   - Recipients with identical routing paths share a single message
    ///   - Recipients sharing common final mediators are grouped optimally
    ///   - Example: 3 recipients through same 2 mediators = 1 message instead of 3 (66% reduction)
    /// - Validates all recipients have compatible key types before encryption
    ///
    /// **Performance**: For N recipients, this performs N key encapsulations but only 1 content encryption,
    /// significantly faster than encrypting N separate messages.
    ///
    /// # Errors
    /// - `IllegalArgument` `from` is set and the message lacks `created_time` or `expires_time`,
    ///   which a recipient needs to accept a message from a named sender.
    /// - `IllegalArgument` The message has a `pad` header, which `options.pad` adds and
    ///   `Message::unpack` removes.
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotFound` DID doesn't contain mentioned DID Urls (for ex., key id)
    /// - `SecretNotFound` Sender secret is not found.
    /// - `NoCompatibleCrypto` No compatible keys are found between sender and recipient.
    /// - `Unsupported` Used crypto or method is unsupported.
    /// - `InvalidState` Indicates library error.
    /// - `IOError` IO error during DID or secrets resolving
    pub async fn pack_encrypted<'dr, 'sr>(
        &self,
        to: &[&str],
        from: Option<&str>,
        sign_by: Option<&str>,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &PackEncryptedOptions,
    ) -> Result<Vec<(String, PackEncryptedMetadata)>> {
        self._validate_pack_encrypted(to, from, sign_by)?;

        let unique_to: Vec<&str> = {
            let mut seen = std::collections::HashSet::new();
            to.iter().filter(|did| seen.insert(*did)).copied().collect()
        };

        let caching_resolver = CachingDIDResolver::new(did_resolver);

        // The padded clone is only for the plaintext that is encrypted: the metadata
        // below describes `self`.
        let padded = options
            .pad
            .map(|floor| padding::pad(self, floor))
            .transpose()?;

        let (msg, from_kid, to_kids, sign_by_kid) = padded
            .as_ref()
            .unwrap_or(self)
            ._pack_jwe_envelope(
                &unique_to,
                from,
                sign_by,
                &caching_resolver,
                secrets_resolver,
                options,
            )
            .await?;

        let routing_tree = if options.forward {
            let routing_paths = analyze_routing_paths(
                &unique_to,
                options.messaging_service.as_deref(),
                &caching_resolver,
            )
            .await?;
            Some(group_by_common_routes(routing_paths)).filter(|tree| tree.needs_forwarding())
        } else {
            None
        };

        let Some(routing_tree) = routing_tree else {
            return Ok(vec![(
                msg,
                PackEncryptedMetadata {
                    messaging_service: None,
                    from_kid,
                    sign_by_kid,
                    to_kids,
                    message_ids: vec![self.id.clone()],
                },
            )]);
        };

        let wrapped_messages = wrap_with_routing_tree(
            &msg,
            &routing_tree,
            options.forward_headers.as_ref(),
            &options.enc_alg_anon,
            &caching_resolver,
            options.use_routing_multi,
        )
        .await?;

        Ok(wrapped_messages
            .into_iter()
            .map(|wrapped| {
                // Outermost forward first, the message itself last, as `unpack` lists them.
                let mut message_ids = wrapped.forward_ids;
                message_ids.push(self.id.clone());

                let metadata = PackEncryptedMetadata {
                    messaging_service: Some(MessagingServiceMetadata {
                        id: wrapped.service_id,
                        service_endpoint: wrapped.service_endpoint,
                    }),
                    from_kid: from_kid.clone(),
                    sign_by_kid: sign_by_kid.clone(),
                    to_kids: to_kids.clone(),
                    message_ids,
                };
                (wrapped.message, metadata)
            })
            .collect())
    }

    fn _validate_pack_encrypted(
        &self,
        to: &[&str],
        from: Option<&str>,
        sign_by: Option<&str>,
    ) -> Result<()> {
        padding::ensure_unpadded(self)?;

        if to.is_empty() {
            Err(err_msg(
                ErrorKind::IllegalArgument,
                "`to` array must contain at least one recipient",
            ))?;
        }

        for recipient in to {
            if !is_did(recipient) {
                Err(err_msg(
                    ErrorKind::IllegalArgument,
                    "All `to` values must be valid DIDs or DID URLs",
                ))?;
            }

            let (to_did, _) = did_or_url(recipient);

            match self.to {
                Some(ref sto) if !sto.contains(&to_did.into()) => {
                    Err(err_msg(
                        ErrorKind::IllegalArgument,
                        "`message.to` value does not contain all recipient DIDs",
                    ))?;
                }
                _ => {}
            }
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

        // A message from a named sender is checked for freshness by its recipient, who
        // refuses one without both time fields.
        if from.is_some() && (self.created_time.is_none() || self.expires_time.is_none()) {
            Err(err_msg(
                ErrorKind::IllegalArgument,
                "`message.created_time` and `message.expires_time` are required when `from` is set",
            ))?;
        }

        // A frame whose `from` is missing is refused by its recipient.
        match (from, &self.from) {
            (Some(from), Some(ref sfrom)) if did_or_url(from).0 != sfrom => Err(err_msg(
                ErrorKind::IllegalArgument,
                "`message.from` value is not equal to `from` value's DID",
            ))?,
            (Some(_), None) => Err(err_msg(
                ErrorKind::IllegalArgument,
                "`message.from` is required when `from` is set",
            ))?,
            _ => {}
        }

        Ok(())
    }

    /// Signs when `sign_by` is set, then encrypts: authcrypt when `from` is set, anoncrypt otherwise.
    async fn _pack_jwe_envelope<'dr, 'sr>(
        &self,
        to: &[&str],
        from: Option<&str>,
        sign_by: Option<&str>,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &PackEncryptedOptions,
    ) -> Result<(String, Option<String>, Vec<String>, Option<String>)> {
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

    /// Whether to use routing-multi protocol for optimized multi-recipient forwarding.
    /// If `true`, uses the routing-multi/1.0 protocol which allows multiple attachments
    /// and more efficient routing. If `false`, falls back to standard DIDComm 2.0 routing.
    #[serde(default = "crate::utils::serde::_true")]
    pub use_routing_multi: bool,

    /// Identifier (DID URL) of messaging service (<https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint>).
    /// If DID doc contains multiple messaging services it allows specify what service to use.
    /// If not present first service will be used.
    pub messaging_service: Option<String>,

    /// Algorithm used for authenticated encryption
    #[serde(default)]
    pub enc_alg_auth: AuthCryptAlg,

    /// Algorithm used for anonymous encryption
    #[serde(default)]
    pub enc_alg_anon: AnonCryptAlg,

    /// Pads the plaintext with a `pad` header to the next size on the ladder of 2 048,
    /// 4 096, 16 384 and 65 536 bytes and then every 32 768 bytes, and at least to the
    /// floor, so that the size of the frame does not tell the length of the message.
    /// `None` (the default) does not pad. `Message::unpack` removes the header, and refuses
    /// an off-ladder message from a proven sender when `UnpackOptions::pad` is `Required`.
    #[serde(default)]
    pub pad: Option<PadFloor>,
}

impl Default for PackEncryptedOptions {
    fn default() -> Self {
        PackEncryptedOptions {
            protect_sender: false,
            forward: true,
            forward_headers: None,
            use_routing_multi: true,
            messaging_service: None,
            enc_alg_auth: AuthCryptAlg::default(),
            enc_alg_anon: AnonCryptAlg::default(),
            pad: None,
        }
    }
}

impl PackEncryptedOptions {
    pub fn no_forward() -> Self {
        PackEncryptedOptions {
            protect_sender: false,
            forward: false,
            forward_headers: None,
            use_routing_multi: true,
            messaging_service: None,
            enc_alg_auth: AuthCryptAlg::default(),
            enc_alg_anon: AnonCryptAlg::default(),
            pad: None,
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

    /// List of message IDs in the order `Message::unpack` lists them: the forward messages
    /// that wrap the message (the outermost, which the first mediator opens, first), then
    /// the original message ID last. If routing is not used, this contains only the original
    /// message ID. For a routing-multi message only its outermost forward is listed.
    pub message_ids: Vec<String>,
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

#[cfg(test)]
mod tests;
