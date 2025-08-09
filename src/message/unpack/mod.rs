use serde::{Deserialize, Serialize};

use anoncrypt::_try_unpack_anoncrypt;
use authcrypt::_try_unpack_authcrypt;
use sign::_try_unpack_sign;

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg, SignAlg},
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultExt},
    message::unpack::plaintext::_try_unpack_plaintext,
    protocols::routing::try_parse_forward,
    secrets::SecretsResolver,
    utils::did::did_or_url,
    FromPrior, Message,
};

mod anoncrypt;
mod authcrypt;
mod plaintext;
mod sign;

impl Message {
    /// Unpacks the packed message by doing decryption and verifying the signatures.
    /// This method supports all DID Comm message types (encrypted, signed, plaintext).
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
    /// - `DIDNotResolved` Sender or recipient DID not found.
    /// - `DIDUrlNotFound` DID doesn't contain mentioned DID URLs (key IDs).
    /// - `Malformed` Message doesn't correspond to DIDComm format or has invalid structure.
    /// - `SecretNotFound` No recipient secrets found.
    /// - `DecryptionFailed` PQC decryption operation failed.
    /// - `SignatureVerificationFailed` ML-DSA signature verification failed.
    /// - `InvalidState` Library error or unsupported PQC algorithm.
    /// - `IOError` IO error during DID or secrets resolving.
    pub async fn unpack<'dr, 'sr>(
        msg: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
        options: &UnpackOptions,
    ) -> Result<(Self, UnpackMetadata)> {
        let mut metadata = UnpackMetadata {
            encrypted: false,
            authenticated: false,
            non_repudiation: false,
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

                if forwarded_msg_opt.is_some() {
                    forwarded_msg = forwarded_msg_opt.unwrap();
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

        let msg = _try_unpack_plaintext(msg, did_resolver, &mut metadata)
            .await?
            .ok_or_else(|| {
                err_msg(
                    ErrorKind::Malformed,
                    "Message is not a valid JWE, JWS or JWM",
                )
            })?;

        Ok((msg, metadata))
    }

    async fn _try_unwrap_forwarded_message<'dr, 'sr>(
        msg: &str,
        did_resolver: &'dr (dyn DIDResolver + 'dr),
        secrets_resolver: &'sr (dyn SecretsResolver + 'sr),
    ) -> Result<Option<String>> {
        let plaintext = match Message::from_str(msg) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::Malformed => return Ok(None),
            Err(e) => Err(e)?,
        };

        if let Some(forward_msg) = try_parse_forward(&plaintext) {
            if has_key_agreement_secret(&forward_msg.next, did_resolver, secrets_resolver).await? {
                // Optimize: Pass Value directly to avoid unnecessary serialization/deserialization
                // The forwarded message is already a JSON Value, no need to serialize then deserialize
                let forwarded_msg = serde_json::to_string(&forward_msg.forwarded_msg).kind(
                    ErrorKind::InvalidState,
                    "Unable serialize forwarded message",
                )?;

                return Ok(Some(forwarded_msg));
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
}

impl Default for UnpackOptions {
    fn default() -> Self {
        UnpackOptions {
            expect_decrypt_by_all_keys: false,
            unwrap_re_wrapping_forward: true,
        }
    }
}

/// Additional metadata about this `unpack` method execution like trust predicates
/// and used keys identifiers.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct UnpackMetadata {
    /// Whether the plaintext has been encrypted
    pub encrypted: bool,

    /// Whether the plaintext has been authenticated
    pub authenticated: bool,

    /// Whether the plaintext has been signed
    pub non_repudiation: bool,

    /// Whether the sender ID was hidden or protected
    pub anonymous_sender: bool,

    /// Whether the plaintext was re-wrapped in a forward message by a mediator
    pub re_wrapped_in_forward: bool,

    /// Key ID of the sender used for authentication encryption if the plaintext has been authenticated and encrypted
    pub encrypted_from_kid: Option<String>,

    /// Target key IDS for encryption if the plaintext has been encrypted
    pub encrypted_to_kids: Option<Vec<String>>,

    /// Key ID used for signature if the plaintext has been signed
    pub sign_from: Option<String>,

    /// Key ID used for from_prior header signature if from_prior header is present
    pub from_prior_issuer_kid: Option<String>,

    /// Algorithm used for authenticated encryption
    pub enc_alg_auth: Option<AuthCryptAlg>,

    /// Algorithm used for anonymous encryption
    pub enc_alg_anon: Option<AnonCryptAlg>,

    /// Algorithm used for message signing
    pub sign_alg: Option<SignAlg>,

    /// If the plaintext has been signed, the JWS is returned for non-repudiation purposes
    pub signed_message: Option<String>,

    /// If plaintext contains from_prior header, its unpacked value is returned
    pub from_prior: Option<FromPrior>,
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
