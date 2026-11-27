//! Size padding of the plaintext that `Message::pack_encrypted` encrypts.
//!
//! A padded message carries one extra top-level member, `pad`, a string of `0`, so that
//! the length of its serialization is exactly a value on a fixed ladder. Whoever sees only
//! the size of an encrypted frame learns the rung, not the length of the message. The
//! member sits inside the encryption: `Message::unpack` removes it, and refuses a message
//! with a proven sender whose plaintext is off the ladder when it is told to
//! (`PadRequirement::Required`).
//!
//! The ladder is 2 048, 4 096, 16 384 and 65 536 bytes, then 32 768 bytes further for
//! each step.

use serde::Deserialize;
use serde_json::Value;

use crate::{
    error::{err_msg, ErrorKind, Result, ResultExt},
    Message,
};

/// The member that carries the padding. `Message::pack_encrypted` refuses a message that
/// already has it and `Message::unpack` always removes it.
pub(crate) const PAD_HEADER: &str = "pad";

/// What the `pad` member adds to a serialization besides its zeros: `,"pad":""`.
const PAD_OVERHEAD: usize = PAD_HEADER.len() + 6;

/// The rungs below the first fixed step.
const RUNGS: [usize; 4] = [2_048, 4_096, 16_384, 65_536];

/// The distance between the rungs above the last entry of `RUNGS`.
const STEP: usize = 32_768;

/// The smallest plaintext that `Message::pack_encrypted` produces when it pads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum PadFloor {
    /// 4 096 bytes: a message to a peer, which holds every usual chat control message.
    Peer,

    /// 2 048 bytes: a control message to a mediator or a bare message to a peer.
    Control,
}

impl PadFloor {
    /// The floor in bytes.
    pub const fn bytes(self) -> usize {
        match self {
            PadFloor::Peer => 4_096,
            PadFloor::Control => 2_048,
        }
    }
}

/// Whether `Message::unpack` refuses a message with a proven sender whose plaintext is off
/// the size ladder.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum PadRequirement {
    /// Accept any plaintext length (the default). The `pad` member is removed in both modes.
    #[default]
    Ignore,

    /// Refuse a message whose sender is proven and whose plaintext length is not on the
    /// ladder with `Malformed`. A message without a proven sender, such as a forward, is
    /// not checked. This turns a packer that forgot to pad into an error instead of a leak.
    Required,
}

/// The smallest ladder value that is at least `len` and at least `floor`, or `None` if it
/// does not fit in a `usize`.
pub(crate) fn target(len: usize, floor: PadFloor) -> Option<usize> {
    let len = len.max(floor.bytes());

    if let Some(rung) = RUNGS.iter().copied().find(|rung| *rung >= len) {
        return Some(rung);
    }

    let top = RUNGS[RUNGS.len() - 1];
    let steps = (len - top).checked_add(STEP - 1)? / STEP;

    steps.checked_mul(STEP)?.checked_add(top)
}

/// Whether `len` is a ladder value.
pub(crate) fn on_ladder(len: usize) -> bool {
    let top = RUNGS[RUNGS.len() - 1];

    if len > top {
        (len - top) % STEP == 0
    } else {
        RUNGS.contains(&len)
    }
}

/// `msg` with a `pad` member that brings its serialization to the next ladder value.
///
/// `msg` must not have a `pad` member (see `ensure_unpadded`), which `pack_encrypted`
/// checks first.
///
/// # Errors
/// - `InvalidState` The padded serialization is not exactly the ladder value.
pub(crate) fn pad(msg: &Message, floor: PadFloor) -> Result<Message> {
    let len = serialized_len(msg)?;

    let want = len
        .checked_add(PAD_OVERHEAD)
        .and_then(|needed| target(needed, floor))
        .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Message is too large to pad"))?;

    let mut padded = msg.clone();
    padded.extra_headers.insert(
        PAD_HEADER.to_owned(),
        Value::String("0".repeat(want - len - PAD_OVERHEAD)),
    );

    if serialized_len(&padded)? != want {
        Err(err_msg(
            ErrorKind::InvalidState,
            "Padded message is not the length of the ladder value",
        ))?;
    }

    Ok(padded)
}

/// Refuses a message that has a `pad` member of its own, which `Message::unpack` would
/// remove.
pub(crate) fn ensure_unpadded(msg: &Message) -> Result<()> {
    if msg.extra_headers.contains_key(PAD_HEADER) {
        Err(err_msg(
            ErrorKind::IllegalArgument,
            "`message` must not have a `pad` header: `pack_encrypted` adds it and `unpack` removes it",
        ))?;
    }

    Ok(())
}

fn serialized_len(msg: &Message) -> Result<usize> {
    serde_json::to_string(msg)
        .map(|json| json.len())
        .kind(ErrorKind::InvalidState, "Unable to serialize message")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOORS: [PadFloor; 2] = [PadFloor::Peer, PadFloor::Control];

    #[test]
    fn floors_are_on_the_ladder() {
        assert_eq!(PadFloor::Peer.bytes(), 4_096);
        assert_eq!(PadFloor::Control.bytes(), 2_048);

        for floor in FLOORS {
            assert!(on_ladder(floor.bytes()));
        }
    }

    #[test]
    fn target_is_the_smallest_rung_at_or_above_the_length_and_the_floor() {
        let cases = [
            (0, PadFloor::Control, 2_048),
            (2_048, PadFloor::Control, 2_048),
            (2_049, PadFloor::Control, 4_096),
            (0, PadFloor::Peer, 4_096),
            (2_049, PadFloor::Peer, 4_096),
            (4_096, PadFloor::Peer, 4_096),
            (4_097, PadFloor::Peer, 16_384),
            (16_384, PadFloor::Control, 16_384),
            (16_385, PadFloor::Control, 65_536),
            (65_536, PadFloor::Peer, 65_536),
            (65_537, PadFloor::Peer, 98_304),
            (98_304, PadFloor::Peer, 98_304),
            (98_305, PadFloor::Peer, 131_072),
            (300_000, PadFloor::Control, 327_680),
        ];

        for (len, floor, want) in cases {
            assert_eq!(target(len, floor), Some(want), "{len} {floor:?}");
        }
    }

    #[test]
    fn target_gives_up_instead_of_overflowing() {
        for floor in FLOORS {
            assert_eq!(target(usize::MAX, floor), None);

            let largest = target(usize::MAX - STEP, floor).expect("fits");
            assert!(on_ladder(largest));
            assert!(largest > usize::MAX - 2 * STEP);
        }
    }

    #[test]
    fn on_ladder_holds_exactly_the_rungs_and_the_steps_above_them() {
        let ladder: Vec<usize> = (0..=400_000).filter(|len| on_ladder(*len)).collect();

        assert_eq!(
            ladder,
            [
                2_048, 4_096, 16_384, 65_536, 98_304, 131_072, 163_840, 196_608, 229_376, 262_144,
                294_912, 327_680, 360_448, 393_216
            ]
        );
    }

    #[test]
    fn every_target_is_on_the_ladder() {
        for floor in FLOORS {
            for len in (0..400_000).step_by(7) {
                let want = target(len, floor).expect("fits");

                assert!(on_ladder(want), "{len} {floor:?}");
                assert!(want >= len.max(floor.bytes()), "{len} {floor:?}");
            }
        }
    }
}
