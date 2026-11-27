use serde::{Deserialize, Serialize};

use anoncrypt::_try_unpack_anoncrypt;
use authcrypt::_try_unpack_authcrypt;
use sign::_try_unpack_sign;

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg, SignAlg},
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultExt},
    message::{
        padding::{self, PadRequirement},
        unpack::plaintext::_try_unpack_plaintext,
    },
    protocols::routing::try_parse_forward,
    secrets::SecretsResolver,
    utils::did::did_or_url,
    FromPrior, Message,
};

mod anoncrypt;
mod authcrypt;
mod plaintext;
mod sender;
mod sign;

#[cfg(test)]
mod wire_tests;

impl Message {
    /// Unpacks the packed message by doing decryption and verifying the signatures, and proves
    /// who sent it.
    /// This method supports all DID Comm message types (encrypted, signed, plaintext), but
    /// only an encrypted message can have a sender.
    ///
    /// # Sender
    /// The sender of a message is proven only by an authcrypt layer: `from` is present, equals
    /// the DID of the authcrypt sender key and, if the message is also signed, the DID of the
    /// signer key. A signature alone never proves the sender, because anyone who holds a signed
    /// message can encrypt it again. A plaintext message, a bare JWS and a message that is
    /// only anoncrypted have no proven sender.
    /// - With `UnpackOptions::sender` = `SenderRequirement::Proven` (the default) a message
    ///   without a proven sender is refused.
    /// - With `SenderRequirement::AllowAnonymous` such a message is returned with `from` and
    ///   `from_prior` removed and `UnpackMetadata::sender_proven` = `false`, so that nothing
    ///   the sender claimed can be mistaken for a fact. This is for mediators and for
    ///   anonymous protocols, which must not read the sender.
    /// - In both modes a message whose `from` contradicts its authcrypt or signer key is refused.
    ///
    /// # Padding
    /// A message that `Message::pack_encrypted` padded carries a `pad` header, which unpack
    /// always removes. With `UnpackOptions::pad` = `PadRequirement::Required` a message with a
    /// proven sender whose plaintext length is not on the size ladder is refused, so that a
    /// packer that forgot to pad is an error and not a leak. A forward and any other message
    /// without a proven sender is never checked.
    ///
    /// # Time
    /// A message with a proven sender must carry `created_time` and `expires_time`. They are
    /// compared with `UnpackOptions::now` (the system clock if it is not set): the message is
    /// refused once `expires_time <= now`, or when `created_time` is more than
    /// `UnpackOptions::future_skew_secs` ahead. Without a proven sender the fields are checked
    /// only when they are present. `from_prior` `exp` and `nbf` are checked the same way.
    ///
    /// If unpack options expect a particular property (for example that a message is encrypted)
    /// and the packed message doesn't meet the criteria (it's not encrypted), then a MessageUntrusted
    /// error will be returned.
    ///
    /// # Params
    /// - `packed_msg` the message as JSON string to be unpacked
    /// - `did_resolver` instance of `DIDResolver` to resolve DIDs
    /// - `secrets_resolver` instance of SecretsResolver` to resolve sender DID keys secrets
    /// - `options` allow fine configuration of unpacking process and imposing additional restrictions
    /// to message to be trusted.
    ///
    /// # Returns
    /// Tuple `(message, metadata)`.
    /// - `message` plain message instance
    /// - `metadata` additional metadata about this `unpack` execution like used keys identifiers,
    ///   trust context, algorithms and etc.
    ///
    /// # Errors
    /// - `SenderNotProven` The sender is not proven and `options.sender` is `Proven`, or the
    ///   message is not encrypted at all (in both modes), or `from` is missing from an authcrypt
    ///   message or is not the DID of the authcrypt sender key or of the signer key (in both
    ///   modes).
    /// - `Expired` `expires_time` or `from_prior` `exp` has passed.
    /// - `NotYetValid` `created_time` or `from_prior` `nbf` is further ahead than
    ///   `options.future_skew_secs`. Unlike `Expired` it clears as the receiver's clock
    ///   catches up, or when the sender's clock is corrected.
    /// - `Malformed` Message is not a valid JWE, JWS or JWM (including empty or truncated JSON)
    ///   or has invalid encryption or signatures. This also covers an anoncrypt envelope that
    ///   carries `apu` or is addressed to other keys than the authcrypt inside it, a signature
    ///   `alg` that doesn't match the signer key type, and key material (sender, signer or
    ///   recipient secret) that can't be decoded or parsed, including a multicodec prefix
    ///   that can't be read. It also covers a message with a proven sender that lacks
    ///   `created_time` or `expires_time`, and a `from_prior` whose `iss` is not the DID of
    ///   its signing key, whose `sub` is not the message `from`, or that comes without `from`.
    ///   With `PadRequirement::Required` it also covers a message with a proven sender whose
    ///   plaintext is not a padded size; the sender and time checks come first.
    /// - `IllegalArgument` Multibase key material (sender, signer or recipient secret) without
    ///   the `z` prefix, or with an unknown or wrong multicodec prefix.
    /// - `SecretNotFound` No recipient secrets found, or a recipient secret was removed while
    ///   unpacking.
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotFound` DID doesn't contain mentioned DID Urls (for ex., key id)
    /// - `Unsupported` Used crypto or method is unsupported, including a sender or signer key
    ///   of a type this crate doesn't support.
    /// - `IoError` IO error during DID or secrets resolving.
    /// - Errors returned by `did_resolver` or `secrets_resolver` keep their kind.
    /// - `InvalidState` Indicates library error, or `options.now` is `None` on `wasm32`, which
    ///   has no system clock.
    pub async fn unpack<'dr, 'sr>(
        msg: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &UnpackOptions,
    ) -> Result<(Self, UnpackMetadata)> {
        let (mut msg, mut metadata, plaintext_len) =
            Self::unpack_layers(msg, did_resolver, secrets_resolver, options).await?;

        msg.extra_headers.remove(padding::PAD_HEADER);

        sender::bind(&mut msg, &mut metadata, options)?;

        if options.pad == PadRequirement::Required
            && metadata.sender_proven
            && !padding::on_ladder(plaintext_len)
        {
            Err(err_msg(
                ErrorKind::Malformed,
                "Plaintext of a message with a proven sender is not a padded size",
            ))?;
        }

        Ok((msg, metadata))
    }

    /// Opens the envelopes and parses the plaintext, without deciding who the sender is.
    /// Returns the length in bytes of the plaintext that the message was parsed from.
    async fn unpack_layers<'dr, 'sr>(
        msg: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &UnpackOptions,
    ) -> Result<(Self, UnpackMetadata, usize)> {
        let mut metadata = UnpackMetadata {
            encrypted: false,
            sender_proven: false,
            anonymous_sender: false,
            re_wrapped_in_forward: false,
            encrypted_from_kid: None,
            encrypted_to_kids: None,
            sign_from: None,
            from_prior_issuer_kid: None,
            enc_alg_auth: None,
            enc_alg_anon: None,
            sign_alg: None,
            signed_message: None,
            from_prior: None,
            message_ids: Vec::new(),
        };

        let mut msg: &str = msg;
        let mut anoncrypted: Option<String>;
        let mut forwarded_msg: String;

        loop {
            anoncrypted =
                _try_unpack_anoncrypt(msg, secrets_resolver, options, &mut metadata).await?;

            if options.unwrap_re_wrapping_forward && anoncrypted.is_some() {
                let forwarded_msg_opt = Self::_try_unwrap_forwarded_message(
                    anoncrypted.as_deref().unwrap(),
                    did_resolver,
                    secrets_resolver,
                )
                .await?;

                if let Some((unwrapped_msg, forward_msg_id)) = forwarded_msg_opt {
                    metadata.message_ids.push(forward_msg_id);
                    forwarded_msg = unwrapped_msg;
                    msg = &forwarded_msg;

                    metadata.re_wrapped_in_forward = true;

                    continue;
                }
            }

            break;
        }

        let msg = anoncrypted.as_deref().unwrap_or(msg);

        let authcrypted =
            _try_unpack_authcrypt(msg, did_resolver, secrets_resolver, options, &mut metadata)
                .await?;
        let msg = authcrypted.as_deref().unwrap_or(msg);

        let signed = _try_unpack_sign(msg, did_resolver, options, &mut metadata).await?;
        let msg = signed.as_deref().unwrap_or(msg);
        let plaintext_len = msg.len();

        let msg = _try_unpack_plaintext(msg, did_resolver, &mut metadata)
            .await?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::Malformed,
                    "Message is not a valid JWE, JWS or JWM",
                )
            })?;

        // Add the final message ID to the list
        metadata.message_ids.push(msg.id.clone());

        Ok((msg, metadata, plaintext_len))
    }

    async fn _try_unwrap_forwarded_message<'dr, 'sr>(
        msg: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    ) -> Result<Option<(String, String)>> {
        let plaintext = match Message::from_str(msg) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::Malformed => return Ok(None),
            Err(e) => Err(e)?,
        };

        if let Some(forward_msg) = try_parse_forward(&plaintext) {
            if has_key_agreement_secret(&forward_msg.next, did_resolver, secrets_resolver).await? {
                // TODO: Think how to avoid extra serialization of forwarded_msg here.
                // (This serializtion is a double work because forwarded_msg will then
                // be deserialized in _try_unpack_anoncrypt.)
                let forwarded_msg = serde_json::to_string(&forward_msg.forwarded_msg).kind(
                    ErrorKind::InvalidState,
                    "Unable serialize forwarded message",
                )?;

                return Ok(Some((forwarded_msg, plaintext.id.clone())));
            }
        }

        Ok(None)
    }
}

/// Allows fine customization of unpacking process
#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
pub struct UnpackOptions {
    /// Whether the plaintext must be decryptable by all keys resolved by the secrets resolver. False by default.
    #[serde(default)]
    pub expect_decrypt_by_all_keys: bool,

    /// If `true` and the packed message is a `Forward`
    /// wrapping a plaintext packed for the given recipient, then both Forward and packed plaintext are unpacked automatically,
    /// and the unpacked plaintext will be returned instead of unpacked Forward.
    /// False by default.
    #[serde(default)]
    pub unwrap_re_wrapping_forward: bool,

    /// Whether a message without a proven sender is refused (`Proven`, the default) or
    /// returned with its sender claims removed (`AllowAnonymous`).
    #[serde(default)]
    pub sender: SenderRequirement,

    /// The current time in seconds since the Unix epoch, against which `created_time`,
    /// `expires_time` and `from_prior` `exp` and `nbf` are checked. `None` reads the system
    /// clock. On `wasm32` there is no system clock and `None` is an `InvalidState` error
    /// whenever a time check is due, so set it there.
    #[serde(default)]
    pub now: Option<u64>,

    /// How many seconds ahead of `now` a `created_time` or `from_prior` `nbf` may be before
    /// the message counts as expired (clock skew of the sender). 86 400 (24 hours) by default.
    #[serde(default = "default_future_skew_secs")]
    pub future_skew_secs: u64,

    /// Whether a message with a proven sender whose plaintext is not a padded size is
    /// refused (`Required`) or accepted (`Ignore`, the default). A message without a proven
    /// sender, such as a forward, is never checked. The `pad` header that
    /// `PackEncryptedOptions::pad` adds is removed in both modes.
    #[serde(default)]
    pub pad: PadRequirement,
}

fn default_future_skew_secs() -> u64 {
    DEFAULT_FUTURE_SKEW_SECS
}

/// Default for `UnpackOptions::future_skew_secs`: 24 hours.
pub const DEFAULT_FUTURE_SKEW_SECS: u64 = 86_400;

/// Whether `Message::unpack` accepts a message whose sender it cannot prove.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum SenderRequirement {
    /// Refuse a message unless its sender is proven by authcrypt (the default).
    #[default]
    Proven,

    /// Also accept a message without a proven sender. It comes back with `from` and
    /// `from_prior` removed and `UnpackMetadata::sender_proven` = `false`.
    AllowAnonymous,
}

impl Default for UnpackOptions {
    fn default() -> Self {
        UnpackOptions {
            expect_decrypt_by_all_keys: false,
            unwrap_re_wrapping_forward: true,
            sender: SenderRequirement::default(),
            now: None,
            future_skew_secs: DEFAULT_FUTURE_SKEW_SECS,
            pad: PadRequirement::default(),
        }
    }
}

/// Additional metadata about this `unpack` method execution like trust predicates
/// and used keys identifiers.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct UnpackMetadata {
    /// Whether the plaintext has been encrypted
    pub encrypted: bool,

    /// Whether the sender is proven: an authcrypt layer whose sender key belongs to `from`
    /// (and to the signer, if the message is signed). `false` only for a message that
    /// `SenderRequirement::AllowAnonymous` let through, which then has no `from`.
    pub sender_proven: bool,

    /// Whether the sender ID was hidden or protected
    pub anonymous_sender: bool,

    /// Whether the plaintext was re-wrapped in a forward message by a mediator
    pub re_wrapped_in_forward: bool,

    /// Key ID of the sender used for authentication encryption if the plaintext has been authenticated and encrypted
    pub encrypted_from_kid: Option<String>,

    /// Target key IDS for encryption if the plaintext has been encrypted
    pub encrypted_to_kids: Option<Vec<String>>,

    /// Key ID used for signature if the plaintext has been signed. A signature alone does
    /// not prove the sender, see `sender_proven`.
    pub sign_from: Option<String>,

    /// Key ID used for from_prior header signature if from_prior header is present and the
    /// sender is proven
    pub from_prior_issuer_kid: Option<String>,

    /// Algorithm used for authenticated encryption
    pub enc_alg_auth: Option<AuthCryptAlg>,

    /// Algorithm used for anonymous encryption
    pub enc_alg_anon: Option<AnonCryptAlg>,

    /// Algorithm used for message signing
    pub sign_alg: Option<SignAlg>,

    /// If the plaintext has been signed, the JWS is returned for non-repudiation purposes
    pub signed_message: Option<String>,

    /// If plaintext contains from_prior header and the sender is proven, its unpacked value
    /// is returned
    pub from_prior: Option<FromPrior>,

    /// List of message IDs in the order they were unpacked (outer layer to inner layer).
    /// First elements are Forward message IDs (if any), last element is the final message ID.
    pub message_ids: Vec<String>,
}

async fn has_key_agreement_secret<'dr, 'sr>(
    did_or_kid: &str,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
) -> Result<bool> {
    let kids = match did_or_url(did_or_kid) {
        (_, Some(kid)) => {
            vec![kid.to_owned()]
        }
        (did, None) => {
            let did_doc = did_resolver
                .resolve(did)
                .await?
                .ok_or_else(|| err_msg(ErrorKind::DIDNotResolved, "Next DID doc not found"))?;
            did_doc.key_agreement
        }
    };

    let kids = kids.iter().map(|k| k as &str).collect::<Vec<_>>();

    let secrets_ids = secrets_resolver.find_secrets(&kids[..]).await?;

    Ok(!secrets_ids.is_empty())
}

#[cfg(test)]
mod test;
