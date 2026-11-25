//! The last step of `Message::unpack`: decide who the sender is and whether the message is
//! still valid.

use crate::{
    error::{err_msg, ErrorKind, Result},
    utils::did::did_or_url,
    Message, SenderRequirement, UnpackMetadata, UnpackOptions,
};

/// Binds `from` to the keys that opened the message, strips what is not proven, and checks
/// the time fields. See `Message::unpack` for the rules.
pub(super) fn bind(
    msg: &mut Message,
    metadata: &mut UnpackMetadata,
    options: &UnpackOptions,
) -> Result<()> {
    let proven = prove_sender(msg, metadata)?;

    if !proven {
        if options.sender == SenderRequirement::Proven {
            Err(err_msg(
                ErrorKind::SenderNotProven,
                "Message has no authcrypt layer, so its sender is not proven",
            ))?;
        }

        // Nothing the sender claimed is a fact: neither `from` nor the rotation that
        // names it.
        msg.from = None;
        msg.from_prior = None;
        metadata.from_prior = None;
        metadata.from_prior_issuer_kid = None;
    }

    metadata.sender_proven = proven;

    check_times(msg, metadata, proven, options)
}

/// Whether `from` is proven by the authcrypt layer. A message that contradicts itself is
/// an error whatever the options say.
fn prove_sender(msg: &Message, metadata: &UnpackMetadata) -> Result<bool> {
    if !metadata.encrypted {
        Err(err_msg(
            ErrorKind::SenderNotProven,
            "Message is not encrypted, so its sender is not proven",
        ))?;
    }

    if let (Some(from), Some(sign_from)) = (msg.from.as_deref(), metadata.sign_from.as_deref()) {
        if did_or_url(sign_from).0 != from {
            Err(err_msg(
                ErrorKind::SenderNotProven,
                "`from` is not the DID of the signer key",
            ))?;
        }
    }

    let Some(encrypted_from_kid) = metadata.encrypted_from_kid.as_deref() else {
        return Ok(false);
    };

    let from = msg.from.as_deref().ok_or_else(|| {
        err_msg(
            ErrorKind::SenderNotProven,
            "Authcrypt message has no `from`",
        )
    })?;

    if did_or_url(encrypted_from_kid).0 != from {
        Err(err_msg(
            ErrorKind::SenderNotProven,
            "`from` is not the DID of the authcrypt sender key",
        ))?;
    }

    if let Some(sign_from) = metadata.sign_from.as_deref() {
        if did_or_url(sign_from).0 != from {
            Err(err_msg(
                ErrorKind::SenderNotProven,
                "Authcrypt sender key and signer key belong to different DIDs",
            ))?;
        }
    }

    Ok(true)
}

fn check_times(
    msg: &Message,
    metadata: &UnpackMetadata,
    proven: bool,
    options: &UnpackOptions,
) -> Result<()> {
    let has_times = msg.created_time.is_some() || msg.expires_time.is_some();

    if !proven && !has_times {
        return Ok(());
    }

    let now = now(options)?;

    if proven {
        msg.check_times(now, options.future_skew_secs)?;

        if let Some(from_prior) = &metadata.from_prior {
            from_prior.check_times(now, options.future_skew_secs)?;
        }
    } else {
        msg.check_times_if_present(now, options.future_skew_secs)?;
    }

    Ok(())
}

/// `options.now`, or the system clock.
fn now(options: &UnpackOptions) -> Result<u64> {
    if let Some(now) = options.now {
        return Ok(now);
    }

    system_now()
}

#[cfg(not(target_arch = "wasm32"))]
fn system_now() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::error::ResultExt;

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .kind(
            ErrorKind::InvalidState,
            "System clock is before the Unix epoch",
        )
}

#[cfg(target_arch = "wasm32")]
fn system_now() -> Result<u64> {
    Err(err_msg(
        ErrorKind::InvalidState,
        "`UnpackOptions::now` is not set and wasm32 has no system clock",
    ))
}
