//! `Message::unpack` as the one place that proves the sender (`from`), checks the time
//! fields and binds `from_prior`.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::{
    algorithms::{AnonCryptAlg, AuthCryptAlg},
    did::resolvers::ExampleDIDResolver,
    error::{Error, ErrorKind},
    jws,
    message::authcrypt_raw,
    secrets::resolvers::ExampleSecretsResolver,
    test_vectors::{
        ALICE_DID, ALICE_DID_DOC, ALICE_SECRETS, BOB_DID, BOB_DID_DOC, BOB_SECRETS, CHARLIE_DID,
        CHARLIE_DID_DOC, CHARLIE_SECRETS, CHARLIE_SECRET_AUTH_KEY_ED25519, MEDIATOR1_DID_DOC,
        PLAINTEXT_MSG_SIMPLE, SIGNED_MSG_ALICE_KEY_1,
    },
    utils::crypto::{AsKnownKeyPair, KnownKeyPair},
    Message, MessageBuilder, PackEncryptedOptions, SenderRequirement, UnpackMetadata,
    UnpackOptions,
};

const CREATED: u64 = 1_516_269_022;
const EXPIRES: u64 = 1_516_385_931;
const NOW: u64 = CREATED + 100;
const SKEW: u64 = 86_400;

const BOTH_MODES: [SenderRequirement; 2] =
    [SenderRequirement::Proven, SenderRequirement::AllowAnonymous];

fn options(sender: SenderRequirement) -> UnpackOptions {
    UnpackOptions {
        sender,
        now: Some(NOW),
        ..UnpackOptions::default()
    }
}

fn did_resolver() -> ExampleDIDResolver {
    ExampleDIDResolver::new(vec![
        ALICE_DID_DOC.clone(),
        BOB_DID_DOC.clone(),
        CHARLIE_DID_DOC.clone(),
        MEDIATOR1_DID_DOC.clone(),
    ])
}

/// Secrets of the senders: Alice, and Charlie for the frames signed by someone else.
fn sender_secrets() -> ExampleSecretsResolver {
    let mut secrets = ALICE_SECRETS.clone();
    secrets.extend(CHARLIE_SECRETS.clone());
    ExampleSecretsResolver::new(secrets)
}

fn builder() -> MessageBuilder {
    Message::build(
        "wire-1".into(),
        "https://example.com/wire/1.0/ping".into(),
        json!({"n": 1}),
    )
    .to(BOB_DID.into())
}

fn timed(builder: MessageBuilder) -> MessageBuilder {
    builder.created_time(CREATED).expires_time(EXPIRES)
}

fn from_alice() -> MessageBuilder {
    timed(builder()).from(ALICE_DID.into())
}

async fn pack(
    msg: &Message,
    from: Option<&str>,
    sign_by: Option<&str>,
    protect_sender: bool,
) -> String {
    let options = PackEncryptedOptions {
        protect_sender,
        ..PackEncryptedOptions::no_forward()
    };

    msg.pack_encrypted(
        &[BOB_DID],
        from,
        sign_by,
        &did_resolver(),
        &sender_secrets(),
        &options,
    )
    .await
    .expect("pack is ok")
    .into_iter()
    .next()
    .expect("one message")
    .0
}

/// Authcrypts `plaintext` as is, which `pack_encrypted` would refuse for the frames
/// that these tests need to be hostile.
async fn authcrypt_plaintext(plaintext: &str, from: &str) -> String {
    authcrypt_raw(
        &[BOB_DID],
        from,
        &did_resolver(),
        &sender_secrets(),
        plaintext.as_bytes(),
        &AuthCryptAlg::default(),
        &AnonCryptAlg::default(),
        false,
    )
    .await
    .expect("authcrypt is ok")
    .0
}

async fn authcrypt_message(msg: &Message, from: &str) -> String {
    authcrypt_plaintext(&serde_json::to_string(msg).unwrap(), from).await
}

async fn unpack(packed: &str, options: &UnpackOptions) -> Result<(Message, UnpackMetadata), Error> {
    Message::unpack(
        packed,
        &did_resolver(),
        &ExampleSecretsResolver::new(BOB_SECRETS.clone()),
        options,
    )
    .await
}

async fn unpack_err(packed: &str, options: &UnpackOptions) -> Error {
    unpack(packed, options)
        .await
        .expect_err("unpack must refuse the frame")
}

// W1: sender proof

#[tokio::test]
async fn plaintext_is_not_a_proven_sender_in_either_mode() {
    for sender in BOTH_MODES {
        let err = unpack_err(PLAINTEXT_MSG_SIMPLE, &options(sender)).await;
        assert_eq!(err.kind(), ErrorKind::SenderNotProven, "{sender:?}");
    }
}

#[tokio::test]
async fn bare_jws_is_not_a_proven_sender_in_either_mode() {
    for sender in BOTH_MODES {
        let err = unpack_err(SIGNED_MSG_ALICE_KEY_1, &options(sender)).await;
        assert_eq!(err.kind(), ErrorKind::SenderNotProven, "{sender:?}");
    }
}

#[tokio::test]
async fn anoncrypt_of_plaintext_with_from_is_not_proven() {
    let msg = from_alice().finalize();
    let packed = pack(&msg, None, None, false).await;

    let err = unpack_err(&packed, &options(SenderRequirement::Proven)).await;
    assert_eq!(err.kind(), ErrorKind::SenderNotProven);

    let (unpacked, metadata) = unpack(&packed, &options(SenderRequirement::AllowAnonymous))
        .await
        .expect("anonymous frame is accepted");

    assert_eq!(unpacked.from, None);
    assert_eq!(unpacked.id, msg.id);
    assert!(!metadata.sender_proven);
    assert!(metadata.encrypted);
    assert!(metadata.anonymous_sender);
    assert_eq!(metadata.encrypted_from_kid, None);
}

#[tokio::test]
async fn authcrypt_with_the_senders_from_is_proven() {
    let msg = from_alice().finalize();
    let packed = pack(&msg, Some(ALICE_DID), None, false).await;

    for sender in BOTH_MODES {
        let (unpacked, metadata) = unpack(&packed, &options(sender))
            .await
            .expect("authcrypt is proven");

        assert_eq!(unpacked, msg, "{sender:?}");
        assert!(metadata.sender_proven, "{sender:?}");
        assert!(!metadata.anonymous_sender, "{sender:?}");
        assert!(metadata
            .encrypted_from_kid
            .as_deref()
            .is_some_and(|kid| kid.starts_with(ALICE_DID)));
    }
}

#[tokio::test]
async fn anoncrypt_of_authcrypt_is_proven() {
    let msg = from_alice().finalize();
    let packed = pack(&msg, Some(ALICE_DID), None, true).await;

    for sender in BOTH_MODES {
        let (unpacked, metadata) = unpack(&packed, &options(sender))
            .await
            .expect("sealed sender is proven");

        assert_eq!(unpacked.from.as_deref(), Some(ALICE_DID), "{sender:?}");
        assert!(metadata.sender_proven, "{sender:?}");
        assert!(metadata.anonymous_sender, "{sender:?}");
        assert!(metadata.encrypted_from_kid.is_some(), "{sender:?}");
    }
}

#[tokio::test]
async fn authcrypt_from_one_did_with_from_of_another_is_refused_in_both_modes() {
    // `pack_encrypted` refuses a `from` that disagrees with the sender, so the forged
    // frame is authcrypted as is.
    let forged = timed(builder()).from(CHARLIE_DID.into()).finalize();
    let packed = authcrypt_message(&forged, ALICE_DID).await;

    for sender in BOTH_MODES {
        let err = unpack_err(&packed, &options(sender)).await;
        assert_eq!(err.kind(), ErrorKind::SenderNotProven, "{sender:?}");
    }
}

#[tokio::test]
async fn authcrypt_without_from_is_refused_in_both_modes() {
    // `pack_encrypted` refuses a message without `from` for a named sender, so the
    // frame is authcrypted as is.
    let msg = timed(builder()).finalize();
    let packed = authcrypt_message(&msg, ALICE_DID).await;

    for sender in BOTH_MODES {
        let err = unpack_err(&packed, &options(sender)).await;
        assert_eq!(err.kind(), ErrorKind::SenderNotProven, "{sender:?}");
    }
}

#[tokio::test]
async fn pack_refuses_a_sender_for_a_message_without_from() {
    let msg = timed(builder()).finalize();

    let err = msg
        .pack_encrypted(
            &[BOB_DID],
            Some(ALICE_DID),
            None,
            &did_resolver(),
            &sender_secrets(),
            &PackEncryptedOptions::no_forward(),
        )
        .await
        .expect_err("pack must refuse the message");

    assert_eq!(err.kind(), ErrorKind::IllegalArgument);
}

#[tokio::test]
async fn authcrypt_signed_by_another_did_is_refused_in_both_modes() {
    let msg = from_alice().finalize();
    let packed = pack(
        &msg,
        Some(ALICE_DID),
        Some(&CHARLIE_SECRET_AUTH_KEY_ED25519.id),
        false,
    )
    .await;

    for sender in BOTH_MODES {
        let err = unpack_err(&packed, &options(sender)).await;
        assert_eq!(err.kind(), ErrorKind::SenderNotProven, "{sender:?}");
    }
}

#[tokio::test]
async fn authcrypt_signed_by_the_sender_is_proven_and_keeps_the_signature() {
    let msg = from_alice().finalize();
    let packed = pack(&msg, Some(ALICE_DID), Some(ALICE_DID), false).await;

    let (unpacked, metadata) = unpack(&packed, &options(SenderRequirement::Proven))
        .await
        .expect("authcrypt signed by the sender is proven");

    assert_eq!(unpacked, msg);
    assert!(metadata.sender_proven);
    assert!(metadata
        .sign_from
        .as_deref()
        .is_some_and(|kid| kid.starts_with(ALICE_DID)));
    assert!(metadata.signed_message.is_some());
}

#[tokio::test]
async fn anoncrypt_of_a_signature_is_not_proven() {
    // The C2 case: a signed JWS from a group member, encrypted again by anyone.
    let msg = from_alice().finalize();
    let packed = pack(&msg, None, Some(ALICE_DID), false).await;

    let err = unpack_err(&packed, &options(SenderRequirement::Proven)).await;
    assert_eq!(err.kind(), ErrorKind::SenderNotProven);

    let (unpacked, metadata) = unpack(&packed, &options(SenderRequirement::AllowAnonymous))
        .await
        .expect("anonymous frame is accepted");

    assert_eq!(unpacked.from, None);
    assert!(!metadata.sender_proven);
    assert!(metadata.sign_from.is_some());
}

// W2: time fields

fn at(created: Option<u64>, expires: Option<u64>) -> Message {
    let mut builder = builder().from(ALICE_DID.into());
    if let Some(created) = created {
        builder = builder.created_time(created);
    }
    if let Some(expires) = expires {
        builder = builder.expires_time(expires);
    }
    builder.finalize()
}

async fn proven_with_times(created: u64, expires: u64) -> String {
    pack(
        &at(Some(created), Some(expires)),
        Some(ALICE_DID),
        None,
        false,
    )
    .await
}

#[tokio::test]
async fn proven_frame_expires_at_expires_time() {
    let opts = options(SenderRequirement::Proven);

    let err = unpack_err(&proven_with_times(CREATED, NOW).await, &opts).await;
    assert_eq!(err.kind(), ErrorKind::Expired);

    let err = unpack_err(&proven_with_times(CREATED, NOW - 1).await, &opts).await;
    assert_eq!(err.kind(), ErrorKind::Expired);

    unpack(&proven_with_times(CREATED, NOW + 1).await, &opts)
        .await
        .expect("a frame that expires one second from now is accepted");
}

#[tokio::test]
async fn proven_frame_may_be_created_up_to_the_skew_ahead() {
    let opts = options(SenderRequirement::Proven);
    let expires = NOW + SKEW + 10;

    unpack(&proven_with_times(NOW + SKEW, expires).await, &opts)
        .await
        .expect("a frame created exactly the skew ahead is accepted");

    let err = unpack_err(&proven_with_times(NOW + SKEW + 1, expires).await, &opts).await;
    assert_eq!(err.kind(), ErrorKind::NotYetValid);

    let strict = UnpackOptions {
        future_skew_secs: 0,
        ..opts
    };
    unpack(&proven_with_times(NOW, expires).await, &strict)
        .await
        .expect("a frame created now is accepted without skew");

    let err = unpack_err(&proven_with_times(NOW + 1, expires).await, &strict).await;
    assert_eq!(err.kind(), ErrorKind::NotYetValid);
}

#[tokio::test]
async fn expiry_wins_over_a_creation_time_too_far_ahead() {
    // `expires_time` is checked first, so a frame that is both is the permanent kind.
    let opts = options(SenderRequirement::Proven);

    let err = unpack_err(&proven_with_times(NOW + SKEW + 1, NOW).await, &opts).await;
    assert_eq!(err.kind(), ErrorKind::Expired);
}

#[tokio::test]
async fn proven_frame_may_be_created_long_ago() {
    unpack(
        &proven_with_times(1, NOW + 1).await,
        &options(SenderRequirement::Proven),
    )
    .await
    .expect("there is no lower bound on created_time");
}

#[tokio::test]
async fn proven_frame_needs_both_time_fields() {
    for (created, expires) in [(None, Some(EXPIRES)), (Some(CREATED), None), (None, None)] {
        let plaintext = serde_json::to_string(&at(created, expires)).unwrap();
        let packed = authcrypt_plaintext(&plaintext, ALICE_DID).await;

        for sender in BOTH_MODES {
            let err = unpack_err(&packed, &options(sender)).await;
            assert_eq!(
                err.kind(),
                ErrorKind::Malformed,
                "{sender:?} created {created:?} expires {expires:?}"
            );
        }
    }
}

#[tokio::test]
async fn pack_encrypted_with_from_needs_both_time_fields() {
    for (created, expires) in [(None, Some(EXPIRES)), (Some(CREATED), None), (None, None)] {
        let err = at(created, expires)
            .pack_encrypted(
                &[BOB_DID],
                Some(ALICE_DID),
                None,
                &did_resolver(),
                &sender_secrets(),
                &PackEncryptedOptions::no_forward(),
            )
            .await
            .expect_err("pack must refuse a message without both time fields");

        assert_eq!(
            err.kind(),
            ErrorKind::IllegalArgument,
            "created {created:?} expires {expires:?}"
        );
    }
}

#[tokio::test]
async fn pack_encrypted_without_from_needs_no_time_fields() {
    pack(&at(None, None), None, None, false).await;
}

#[tokio::test]
async fn unproven_frame_without_times_is_accepted() {
    let packed = pack(&at(None, None), None, None, false).await;

    let (unpacked, metadata) = unpack(&packed, &options(SenderRequirement::AllowAnonymous))
        .await
        .expect("a frame without times is accepted when the sender is not proven");

    assert!(!metadata.sender_proven);
    assert_eq!(unpacked.created_time, None);
}

#[tokio::test]
async fn unproven_frame_with_times_is_checked() {
    let opts = options(SenderRequirement::AllowAnonymous);

    let expired = pack(&at(None, Some(NOW)), None, None, false).await;
    assert_eq!(unpack_err(&expired, &opts).await.kind(), ErrorKind::Expired);

    let future = pack(&at(Some(NOW + SKEW + 1), None), None, None, false).await;
    assert_eq!(
        unpack_err(&future, &opts).await.kind(),
        ErrorKind::NotYetValid
    );

    let fresh = pack(&at(Some(NOW), Some(NOW + 1)), None, None, false).await;
    unpack(&fresh, &opts)
        .await
        .expect("fresh frame is accepted");
}

#[tokio::test]
async fn forward_without_times_unpacks_for_the_mediator() {
    // The mediator side of a sealed-sender frame: anoncrypt(forward) with no times,
    // no `from`, opened with the mediator's keys only.
    let msg = from_alice().finalize();
    let packed = msg
        .pack_encrypted(
            &[BOB_DID],
            Some(ALICE_DID),
            None,
            &did_resolver(),
            &sender_secrets(),
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("pack is ok")
        .into_iter()
        .next()
        .expect("one message")
        .0;

    let mediator = ExampleSecretsResolver::new(crate::test_vectors::MEDIATOR1_SECRETS.clone());
    let (forward, metadata) = Message::unpack(
        &packed,
        &did_resolver(),
        &mediator,
        &options(SenderRequirement::AllowAnonymous),
    )
    .await
    .expect("the mediator opens the forward");

    assert!(crate::protocols::routing::try_parse_forward(&forward).is_some());
    assert_eq!(forward.created_time, None);
    assert_eq!(forward.expires_time, None);
    assert!(!metadata.sender_proven);

    let err = Message::unpack(
        &packed,
        &did_resolver(),
        &mediator,
        &options(SenderRequirement::Proven),
    )
    .await
    .expect_err("a forward has no proven sender");
    assert_eq!(err.kind(), ErrorKind::SenderNotProven);
}

fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_secs()
}

#[tokio::test]
async fn unpack_reads_the_system_clock_when_now_is_not_set() {
    let opts = UnpackOptions {
        now: None,
        ..options(SenderRequirement::Proven)
    };

    let now = system_now();
    let fresh = proven_with_times(now, now + 3600).await;
    unpack(&fresh, &opts)
        .await
        .expect("a frame created now is accepted");

    let err = unpack_err(&proven_with_times(CREATED, EXPIRES).await, &opts).await;
    assert_eq!(err.kind(), ErrorKind::Expired);
}

#[test]
fn check_times_is_strict_about_missing_fields_and_exact_at_the_boundaries() {
    let ok = at(Some(NOW), Some(NOW + 1));
    ok.check_times(NOW, SKEW).expect("fresh message");

    for (msg, kind) in [
        (at(None, Some(NOW + 1)), ErrorKind::Malformed),
        (at(Some(NOW), None), ErrorKind::Malformed),
        (at(Some(NOW), Some(NOW)), ErrorKind::Expired),
        (
            at(Some(NOW + SKEW + 1), Some(NOW + SKEW + 2)),
            ErrorKind::NotYetValid,
        ),
    ] {
        let err = msg.check_times(NOW, SKEW).expect_err("must be refused");
        assert_eq!(err.kind(), kind);
    }

    at(Some(NOW + SKEW), Some(NOW + SKEW + 1))
        .check_times(NOW, SKEW)
        .expect("created exactly the skew ahead");
}

// W3: from_prior

fn from_prior_jwt(iss: &str, sub: &str, exp: Option<u64>, nbf: Option<u64>) -> String {
    let mut payload = json!({"iss": iss, "sub": sub});
    if let Some(exp) = exp {
        payload["exp"] = Value::from(exp);
    }
    if let Some(nbf) = nbf {
        payload["nbf"] = Value::from(nbf);
    }

    let KnownKeyPair::Ed25519(key) = CHARLIE_SECRET_AUTH_KEY_ED25519
        .as_key_pair()
        .expect("charlie key")
    else {
        panic!("charlie key is Ed25519");
    };

    jws::sign_compact(
        payload.to_string().as_bytes(),
        (&CHARLIE_SECRET_AUTH_KEY_ED25519.id, &key),
        "JWT",
        jws::Algorithm::EdDSA,
    )
    .expect("sign from_prior")
}

async fn with_from_prior(jwt: String) -> String {
    let msg = from_alice().from_prior(jwt).finalize();
    authcrypt_message(&msg, ALICE_DID).await
}

#[tokio::test]
async fn from_prior_bound_to_the_sender_is_accepted() {
    let jwt = from_prior_jwt(CHARLIE_DID, ALICE_DID, Some(NOW + 1), Some(NOW));
    let packed = with_from_prior(jwt).await;

    let (_, metadata) = unpack(&packed, &options(SenderRequirement::Proven))
        .await
        .expect("bound from_prior is accepted");

    let from_prior = metadata.from_prior.expect("from_prior is unpacked");
    assert_eq!(from_prior.iss, CHARLIE_DID);
    assert_eq!(from_prior.sub, ALICE_DID);
    assert_eq!(
        metadata.from_prior_issuer_kid.as_deref(),
        Some(CHARLIE_SECRET_AUTH_KEY_ED25519.id.as_str())
    );
}

#[tokio::test]
async fn from_prior_iss_must_be_the_did_of_the_signing_key() {
    // Signed with Charlie's key, but claims Alice as the issuer.
    let jwt = from_prior_jwt(ALICE_DID, ALICE_DID, None, None);
    let packed = with_from_prior(jwt).await;

    for sender in BOTH_MODES {
        let err = unpack_err(&packed, &options(sender)).await;
        assert_eq!(err.kind(), ErrorKind::Malformed, "{sender:?}");
    }
}

#[tokio::test]
async fn from_prior_sub_must_be_the_message_from() {
    let jwt = from_prior_jwt(CHARLIE_DID, BOB_DID, None, None);
    let packed = with_from_prior(jwt).await;

    for sender in BOTH_MODES {
        let err = unpack_err(&packed, &options(sender)).await;
        assert_eq!(err.kind(), ErrorKind::Malformed, "{sender:?}");
    }
}

#[tokio::test]
async fn from_prior_exp_is_checked_against_now() {
    let opts = options(SenderRequirement::Proven);

    for exp in [NOW - 1, NOW] {
        let packed = with_from_prior(from_prior_jwt(CHARLIE_DID, ALICE_DID, Some(exp), None)).await;
        let err = unpack_err(&packed, &opts).await;
        assert_eq!(err.kind(), ErrorKind::Expired, "exp {exp}");
    }

    let packed = with_from_prior(from_prior_jwt(CHARLIE_DID, ALICE_DID, Some(NOW + 1), None)).await;
    unpack(&packed, &opts)
        .await
        .expect("from_prior that expires in a second is accepted");
}

#[tokio::test]
async fn from_prior_nbf_is_checked_against_now_with_the_skew() {
    let opts = options(SenderRequirement::Proven);

    let packed = with_from_prior(from_prior_jwt(
        CHARLIE_DID,
        ALICE_DID,
        None,
        Some(NOW + SKEW),
    ))
    .await;
    unpack(&packed, &opts)
        .await
        .expect("nbf exactly the skew ahead is accepted");

    let packed = with_from_prior(from_prior_jwt(
        CHARLIE_DID,
        ALICE_DID,
        None,
        Some(NOW + SKEW + 1),
    ))
    .await;
    let err = unpack_err(&packed, &opts).await;
    assert_eq!(err.kind(), ErrorKind::NotYetValid);
}

#[tokio::test]
async fn unproven_frame_carries_no_from_prior() {
    let jwt = from_prior_jwt(CHARLIE_DID, ALICE_DID, None, None);
    let msg = from_alice().from_prior(jwt).finalize();
    let plaintext = serde_json::to_string(&msg).unwrap();
    let packed = crate::message::anoncrypt(
        &[BOB_DID],
        &did_resolver(),
        plaintext.as_bytes(),
        &AnonCryptAlg::default(),
    )
    .await
    .expect("anoncrypt is ok")
    .0;

    let (unpacked, metadata) = unpack(&packed, &options(SenderRequirement::AllowAnonymous))
        .await
        .expect("anonymous frame is accepted");

    assert_eq!(unpacked.from, None);
    assert_eq!(unpacked.from_prior, None);
    assert_eq!(metadata.from_prior, None);
    assert_eq!(metadata.from_prior_issuer_kid, None);
}
