use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Message;

/// Utility structure providing convinient access to Forward plaintext message fields.
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct ParsedForward<'a> {
    pub msg: &'a Message,
    pub next: String,
    pub forwarded_msg: Value,
}

/// Represents a group of destinations that share the same attachment in routing-multi protocol.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct NextDestination {
    /// List of DIDs or DID URLs that should receive this attachment
    pub to: Vec<String>,

    /// The attachment ID that contains the message for these destinations
    pub attachment_id: String,
}

/// Utility structure for routing-multi forward messages.
/// This is an extension of DIDComm 2.0 that allows multiple next destinations
/// with different attachments, enabling better optimization for multi-recipient routing.
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct ParsedForwardMulti<'a> {
    pub msg: &'a Message,
    pub next: Vec<NextDestination>,
}
