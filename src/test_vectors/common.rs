use base64::prelude::*;
use serde_json::{Map, Value};

pub const ALICE_DID: &str = "did:example:alice";
pub const BOB_DID: &str = "did:example:bob";
pub const CHARLIE_DID: &str = "did:example:charlie";
pub const DAVID_DID: &str = "did:example:david";
pub const EVE_DID: &str = "did:example:eve";
pub const FRANK_DID: &str = "did:example:frank";

/// A moment inside the time window of the fixtures: they were created at 1516269022 and
/// expire at 1516385931.
pub const FIXTURE_NOW: u64 = 1_516_269_122;

/// Unpack options for the fixtures: the clock is pinned in their time window, and a message
/// without a proven sender comes back anonymous instead of failing.
pub fn fixture_unpack_options() -> crate::didcomm::UnpackOptions {
    crate::didcomm::UnpackOptions {
        sender: crate::didcomm::SenderRequirement::AllowAnonymous,
        now: Some(FIXTURE_NOW),
        ..crate::didcomm::UnpackOptions::default()
    }
}

/// What `Message::unpack` returns for `msg`: it keeps `from` only when the sender is proven.
pub fn unpacked_message(
    msg: &crate::didcomm::Message,
    sender_proven: bool,
) -> crate::didcomm::Message {
    crate::didcomm::Message {
        from: msg.from.clone().filter(|_| sender_proven),
        ..msg.clone()
    }
}

pub fn update_field(msg: &str, field: &str, value: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();
    msg_dict.insert(String::from(field), value.into());
    serde_json::to_string(&msg_dict).unwrap()
}

pub fn remove_field(msg: &str, field: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();
    msg_dict.remove(field);
    serde_json::to_string(&msg_dict).unwrap()
}

pub fn update_protected_field(msg: &str, field: &str, value: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();

    let mut buffer = Vec::<u8>::new();
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(msg_dict.get("protected").unwrap().as_str().unwrap())
        .unwrap();
    buffer.clear();
    buffer.extend_from_slice(&decoded);
    let parsed_protected: Value = serde_json::from_slice(&buffer).unwrap();
    let mut protected_dict: Map<String, Value> = parsed_protected.as_object().unwrap().clone();
    protected_dict.insert(String::from(field), value.into());
    let protected_str = serde_json::to_string(&protected_dict).unwrap();
    println!("{}", protected_str);
    let protected_str_base64 = BASE64_URL_SAFE_NO_PAD.encode(protected_str);
    msg_dict.insert(String::from("protected"), protected_str_base64.into());
    serde_json::to_string(&msg_dict).unwrap()
}

pub fn remove_protected_field(msg: &str, field: &str) -> String {
    let parsed: Value = serde_json::from_str(msg).unwrap();
    let mut msg_dict: Map<String, Value> = parsed.as_object().unwrap().clone();

    let mut buffer = Vec::<u8>::new();
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(msg_dict.get("protected").unwrap().as_str().unwrap())
        .unwrap();
    buffer.clear();
    buffer.extend_from_slice(&decoded);
    let parsed_protected: Value = serde_json::from_slice(&buffer).unwrap();
    let mut protected_dict: Map<String, Value> = parsed_protected.as_object().unwrap().clone();
    protected_dict.remove(field);
    let protected_str = serde_json::to_string(&protected_dict).unwrap();
    let protected_str_base64 = BASE64_URL_SAFE_NO_PAD.encode(protected_str);

    msg_dict.insert(String::from("protected"), protected_str_base64.into());
    serde_json::to_string(&msg_dict).unwrap()
}
