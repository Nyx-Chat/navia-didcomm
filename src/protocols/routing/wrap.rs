//! Optimized forward message wrapping for multi-recipient routing.
//!
//! This module implements the actual message wrapping logic that uses the routing tree
//! to create optimally wrapped forward messages.

use serde_json::Value;
use std::collections::HashMap;

use crate::{
    algorithms::AnonCryptAlg,
    did::DIDResolver,
    error::{Result, ResultContext},
};

use super::{
    anoncrypt, build_forward_message,
    tree::{RouteGroup, RoutingTree},
};

/// Represents a wrapped message ready to be sent.
#[derive(Debug, Clone)]
pub struct WrappedMessage {
    /// The encrypted and wrapped message content
    pub message: String,

    /// The endpoint to send this message to
    pub service_endpoint: String,

    /// The service ID
    pub service_id: String,

    /// The recipient DIDs that will ultimately receive this message
    pub final_recipients: Vec<String>,
}

/// Wraps a multi-recipient encrypted message using the routing tree for optimal delivery.
///
/// This function takes an already-encrypted message (encrypted for all recipients) and
/// wraps it in forward messages according to the routing tree optimization.
///
/// # Returns
///
/// A vector of `WrappedMessage` objects, each representing a message that needs to be sent
/// to a specific endpoint. The number of messages returned is typically much less than the
/// number of recipients due to optimization.
pub async fn wrap_with_routing_tree<'dr>(
    encrypted_msg: &str,
    tree: &RoutingTree,
    headers: Option<&HashMap<String, Value>>,
    enc_alg_anon: &AnonCryptAlg,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<Vec<WrappedMessage>> {
    let mut wrapped_messages = Vec::new();

    // Handle direct recipients (no forwarding needed)
    if !tree.direct_recipients.is_empty() {
        // For direct recipients, use the first one's endpoint
        // (in a real scenario, you might send to multiple endpoints)
        let first = &tree.direct_recipients[0];
        wrapped_messages.push(WrappedMessage {
            message: encrypted_msg.to_owned(),
            service_endpoint: first.service_endpoint.clone(),
            service_id: first.service_id.clone(),
            final_recipients: tree
                .direct_recipients
                .iter()
                .map(|p| p.recipient_did.clone())
                .collect(),
        });
    }

    // Handle routed groups
    for group in &tree.routed_groups {
        let group_messages =
            wrap_route_group(encrypted_msg, group, headers, enc_alg_anon, did_resolver).await?;

        wrapped_messages.extend(group_messages);
    }

    Ok(wrapped_messages)
}

/// Wraps a message for a single route group.
///
/// This implements the core optimization logic:
/// 1. Wrap the message for common suffix mediators
/// 2. Branch out for individual paths
async fn wrap_route_group<'dr>(
    encrypted_msg: &str,
    group: &RouteGroup,
    headers: Option<&HashMap<String, Value>>,
    enc_alg_anon: &AnonCryptAlg,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<Vec<WrappedMessage>> {
    // If all recipients have identical routes, simple case
    if group.has_identical_routes() {
        let wrapped = wrap_for_mediator_chain(
            encrypted_msg,
            &group.recipients,
            &group.common_suffix,
            headers,
            enc_alg_anon,
            did_resolver,
        )
        .await?;

        return Ok(vec![WrappedMessage {
            message: wrapped,
            service_endpoint: group.service_endpoint.clone(),
            service_id: group.service_id.clone(),
            final_recipients: group.recipients.clone(),
        }]);
    }

    // Complex case: recipients have divergent paths
    // 1. First, wrap for the common suffix
    let common_wrapped = if !group.common_suffix.is_empty() {
        wrap_for_mediator_chain(
            encrypted_msg,
            &group.recipients,
            &group.common_suffix,
            headers,
            enc_alg_anon,
            did_resolver,
        )
        .await?
    } else {
        encrypted_msg.to_owned()
    };

    // 2. Group recipients by their individual path prefix
    let mut path_groups: HashMap<Vec<String>, Vec<String>> = HashMap::new();
    for (recipient, path) in &group.individual_paths {
        path_groups
            .entry(path.clone())
            .or_default()
            .push(recipient.clone());
    }

    // 3. For each unique path prefix, wrap the common message
    let mut result = Vec::new();
    for (path_prefix, recipients) in path_groups {
        if path_prefix.is_empty() {
            // No additional wrapping needed for these recipients
            // They go directly through the common path
            result.push(WrappedMessage {
                message: common_wrapped.clone(),
                service_endpoint: group.service_endpoint.clone(),
                service_id: group.service_id.clone(),
                final_recipients: recipients,
            });
        } else {
            // Wrap the common message with this path's prefix
            let branch_wrapped = wrap_for_mediator_chain(
                &common_wrapped,
                &recipients,
                &path_prefix,
                headers,
                enc_alg_anon,
                did_resolver,
            )
            .await?;

            // The endpoint for this branch is determined by the first mediator in the prefix
            // For now, use the group's endpoint (this could be optimized further)
            result.push(WrappedMessage {
                message: branch_wrapped,
                service_endpoint: group.service_endpoint.clone(),
                service_id: group.service_id.clone(),
                final_recipients: recipients,
            });
        }
    }

    Ok(result)
}

/// Wraps a message for a chain of mediators.
///
/// Takes a message and wraps it in forward messages for each mediator in the chain,
/// working from last to first (inside-out wrapping).
async fn wrap_for_mediator_chain<'dr>(
    msg: &str,
    recipients: &[String],
    mediators: &[String],
    headers: Option<&HashMap<String, Value>>,
    enc_alg_anon: &AnonCryptAlg,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<String> {
    if mediators.is_empty() {
        return Ok(msg.to_owned());
    }

    let mut current_msg = msg.to_owned();
    let mut next_hop = recipients.first().unwrap().clone(); // The ultimate destination

    // Work backwards through the mediator chain (last to first)
    // This creates nested forward messages
    for mediator in mediators.iter().rev() {
        // Build forward message pointing to the next hop
        current_msg = build_forward_message(&current_msg, &next_hop, headers)
            .context("Failed to build forward message")?
            .0; // Take only the message, ignore message_id

        // Encrypt for this mediator
        current_msg = anoncrypt(
            std::slice::from_ref(mediator),
            did_resolver,
            current_msg.as_bytes(),
            enc_alg_anon,
        )
        .await
        .context(format!("Failed to encrypt for mediator {mediator}"))?
        .0;

        // The next iteration wraps for the previous mediator, pointing to this one
        next_hop = mediator.clone();
    }

    Ok(current_msg)
}

#[cfg(test)]
mod tests {
    // Note: Full integration tests would require mock DID resolver and secrets
    // These tests verify the structure and logic

    #[test]
    fn test_route_group_identical_routes() {
        use crate::protocols::routing::tree::RouteGroup;
        use std::collections::HashMap;

        let mut individual_paths = HashMap::new();
        individual_paths.insert("did:example:alice".to_owned(), vec![]);
        individual_paths.insert("did:example:bob".to_owned(), vec![]);

        let group = RouteGroup {
            recipients: vec!["did:example:alice".to_owned(), "did:example:bob".to_owned()],
            common_suffix: vec!["did:example:med1".to_owned()],
            individual_paths,
            service_endpoint: "https://mediator1.example".to_owned(),
            service_id: "service-1".to_owned(),
        };

        assert!(group.has_identical_routes());
    }

    #[test]
    fn test_route_group_divergent_routes() {
        use crate::protocols::routing::tree::RouteGroup;
        use std::collections::HashMap;

        let mut individual_paths = HashMap::new();
        individual_paths.insert(
            "did:example:alice".to_owned(),
            vec!["did:example:med1".to_owned()],
        );
        individual_paths.insert(
            "did:example:bob".to_owned(),
            vec!["did:example:med2".to_owned()],
        );

        let group = RouteGroup {
            recipients: vec!["did:example:alice".to_owned(), "did:example:bob".to_owned()],
            common_suffix: vec!["did:example:med3".to_owned()],
            individual_paths,
            service_endpoint: "https://mediator3.example".to_owned(),
            service_id: "service-1".to_owned(),
        };

        assert!(!group.has_identical_routes());
    }
}
