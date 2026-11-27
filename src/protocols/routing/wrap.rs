//! Optimized forward message wrapping for multi-recipient routing.
//!
//! This module implements the actual message wrapping logic that uses the routing tree
//! to create optimally wrapped forward messages.

use serde_json::Value;
use std::collections::HashMap;

use crate::{
    algorithms::AnonCryptAlg,
    did::DIDResolver,
    error::{err_msg, ErrorKind, Result, ResultContext},
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

    /// IDs of the forward messages that wrap the message, outermost (the one the first
    /// mediator opens) first. Empty when the message is not wrapped. For a routing-multi
    /// message only the outermost forward is listed.
    pub forward_ids: Vec<String>,
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
    use_routing_multi: bool,
) -> Result<Vec<WrappedMessage>> {
    let mut wrapped_messages = Vec::new();

    if !tree.direct_recipients.is_empty() {
        // All direct recipients share the first one's endpoint, even when theirs differ.
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
            forward_ids: Vec::new(),
        });
    }

    for group in &tree.routed_groups {
        let group_messages = wrap_route_group(
            encrypted_msg,
            group,
            headers,
            enc_alg_anon,
            did_resolver,
            use_routing_multi,
        )
        .await?;

        wrapped_messages.extend(group_messages);
    }

    Ok(wrapped_messages)
}

/// Wraps a message for a single route group.
///
/// This implements the core optimization logic:
/// - For suffix-based: Wrap for common suffix, then branch for individual prefixes
/// - For prefix-based: Wrap once for common prefix with multi-next destinations
async fn wrap_route_group<'dr>(
    encrypted_msg: &str,
    group: &RouteGroup,
    headers: Option<&HashMap<String, Value>>,
    enc_alg_anon: &AnonCryptAlg,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    use_routing_multi: bool,
) -> Result<Vec<WrappedMessage>> {
    if group.has_identical_routes() {
        let (wrapped, forward_ids) = wrap_for_mediator_chain(
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
            forward_ids,
        }]);
    }

    // Recipients that share their first hops, e.g. both go through mediator1.
    if group.is_prefix_based {
        return wrap_prefix_based_group(
            encrypted_msg,
            group,
            headers,
            enc_alg_anon,
            did_resolver,
            use_routing_multi,
        )
        .await;
    }

    // Recipients with divergent paths: wrap for the shared suffix, then branch per prefix.
    let (common_wrapped, common_forward_ids) = if !group.common_suffix.is_empty() {
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
        (encrypted_msg.to_owned(), Vec::new())
    };

    let mut path_groups: HashMap<Vec<String>, Vec<String>> = HashMap::new();
    for (recipient, path) in &group.individual_paths {
        path_groups
            .entry(path.clone())
            .or_default()
            .push(recipient.clone());
    }

    let mut result = Vec::new();
    for (path_prefix, recipients) in path_groups {
        if path_prefix.is_empty() {
            // These recipients go straight through the common path.
            result.push(WrappedMessage {
                message: common_wrapped.clone(),
                service_endpoint: group.service_endpoint.clone(),
                service_id: group.service_id.clone(),
                final_recipients: recipients,
                forward_ids: common_forward_ids.clone(),
            });
        } else {
            let (branch_wrapped, mut forward_ids) = wrap_for_mediator_chain(
                &common_wrapped,
                &recipients,
                &path_prefix,
                headers,
                enc_alg_anon,
                did_resolver,
            )
            .await?;
            forward_ids.extend(common_forward_ids.iter().cloned());

            // Uses the group's endpoint, not the branch's first mediator.
            result.push(WrappedMessage {
                message: branch_wrapped,
                service_endpoint: group.service_endpoint.clone(),
                service_id: group.service_id.clone(),
                final_recipients: recipients,
                forward_ids,
            });
        }
    }

    Ok(result)
}

/// Wraps a message for a prefix-based group (shared first hops).
///
/// When `use_routing_multi` is true:
/// - Uses routing-multi/1.0 protocol with multiple attachments for optimization
/// - Example: F,G,H through med1 → ONE message with 2 attachments (for med2 and med3)
///
/// When `use_routing_multi` is false:
/// - Falls back to standard DIDComm 2.0 with separate messages
/// - Example: F,G,H through med1 → TWO separate messages
async fn wrap_prefix_based_group<'dr>(
    encrypted_msg: &str,
    group: &RouteGroup,
    headers: Option<&HashMap<String, Value>>,
    enc_alg_anon: &AnonCryptAlg,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    use_routing_multi: bool,
) -> Result<Vec<WrappedMessage>> {
    use super::{build_forward_message, build_forward_message_multi, NextDestination};

    let first_mediator = group
        .common_suffix
        .first()
        .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Prefix group has no common prefix"))?;

    let mut next_hop_groups: HashMap<String, Vec<String>> = HashMap::new();
    for (recipient, path) in &group.individual_paths {
        if let Some(next_hop) = path.first() {
            next_hop_groups
                .entry(next_hop.clone())
                .or_default()
                .push(recipient.clone());
        }
    }

    let unique_next_hops: Vec<String> = next_hop_groups.keys().cloned().collect();
    let has_optimization_benefit = unique_next_hops.len() > 1;

    // routing-multi only pays off when the next hops differ.
    if use_routing_multi && has_optimization_benefit {
        let mut encrypted_attachments = HashMap::new();
        let mut next_destinations = Vec::new();

        for (next_hop, recipients_for_hop) in &next_hop_groups {
            let remaining_paths: Vec<(String, Vec<String>)> = recipients_for_hop
                .iter()
                .filter_map(|recipient| {
                    group.individual_paths.get(recipient).map(|path| {
                        let remaining = if !path.is_empty() {
                            path[1..].to_vec() // Skip the first element (next_hop)
                        } else {
                            vec![]
                        };
                        (recipient.clone(), remaining)
                    })
                })
                .collect();

            let all_same = remaining_paths.windows(2).all(|w| w[0].1 == w[1].1);

            let wrapped_for_path = if all_same && !remaining_paths.is_empty() {
                let remaining_path = &remaining_paths[0].1;
                wrap_for_mediator_chain(
                    encrypted_msg,
                    recipients_for_hop,
                    remaining_path,
                    headers,
                    enc_alg_anon,
                    did_resolver,
                )
                .await?
                .0
            } else if !remaining_paths.is_empty() {
                wrap_divergent_paths(
                    encrypted_msg,
                    &remaining_paths,
                    headers,
                    enc_alg_anon,
                    did_resolver,
                    use_routing_multi,
                )
                .await?
            } else {
                encrypted_msg.to_owned()
            };

            let forward_to = if all_same && !remaining_paths.is_empty() {
                remaining_paths[0]
                    .1
                    .first()
                    .unwrap_or(&recipients_for_hop[0])
            } else {
                // The wrapped message already is a routing structure that next_hop resolves.
                next_hop
            };

            let (inner_fwd, inner_fwd_id) =
                build_forward_message(&wrapped_for_path, forward_to, headers)
                    .context("Failed to build inner forward message")?;

            let encrypted_for_next = anoncrypt(
                &[next_hop.as_str()],
                did_resolver,
                inner_fwd.as_bytes(),
                enc_alg_anon,
            )
            .await
            .context(format!("Failed to encrypt for next hop {next_hop}"))?
            .0;

            let attachment_id = format!("att-{inner_fwd_id}");

            encrypted_attachments.insert(attachment_id.clone(), encrypted_for_next);

            next_destinations.push(NextDestination {
                to: vec![next_hop.clone()],
                attachment_id,
            });
        }

        let (fwd_mod_msg, fwd_mod_id) =
            build_forward_message_multi(next_destinations, encrypted_attachments, headers)
                .context("Failed to build routing-multi forward message")?;

        let encrypted_fwd = anoncrypt(
            &[first_mediator.as_str()],
            did_resolver,
            fwd_mod_msg.as_bytes(),
            enc_alg_anon,
        )
        .await
        .context(format!(
            "Failed to encrypt routing-multi message for mediator {first_mediator}"
        ))?
        .0;

        return Ok(vec![WrappedMessage {
            message: encrypted_fwd,
            service_endpoint: group.service_endpoint.clone(),
            service_id: group.service_id.clone(),
            final_recipients: group.recipients.clone(),
            forward_ids: vec![fwd_mod_id],
        }]);
    }

    // Standard DIDComm 2.0: one forward message per next hop.
    let mut result = Vec::new();

    for (next_hop, recipients_for_hop) in next_hop_groups {
        let remaining_path: Vec<String> = group
            .individual_paths
            .get(&recipients_for_hop[0])
            .map(|path| path[1..].to_vec())
            .unwrap_or_default();

        let (wrapped_for_path, inner_forward_ids) = wrap_for_mediator_chain(
            encrypted_msg,
            &recipients_for_hop,
            &remaining_path,
            headers,
            enc_alg_anon,
            did_resolver,
        )
        .await?;

        let forward_to = remaining_path.first().unwrap_or(&recipients_for_hop[0]);

        let (fwd_msg, fwd_id) = build_forward_message(&wrapped_for_path, forward_to, headers)
            .context("Failed to build forward message")?;
        let forward_ids = std::iter::once(fwd_id)
            .chain(inner_forward_ids)
            .collect::<Vec<_>>();

        let encrypted_fwd = anoncrypt(
            &[next_hop.as_str()],
            did_resolver,
            fwd_msg.as_bytes(),
            enc_alg_anon,
        )
        .await
        .context(format!("Failed to encrypt for next hop {next_hop}"))?
        .0;

        result.push(WrappedMessage {
            message: encrypted_fwd,
            service_endpoint: group.service_endpoint.clone(),
            service_id: group.service_id.clone(),
            final_recipients: recipients_for_hop,
            forward_ids,
        });
    }

    Ok(result)
}

/// Wraps a message when recipients have divergent remaining paths.
///
/// This handles the case where recipients share a next hop but then diverge.
/// For example, David and Eve both go through mediator2, but then David goes to
/// mediator3 while Eve goes to mediator4.
///
/// This function creates a routing-multi message with separate attachments for each
/// divergent path, allowing optimal routing at each hop level.
async fn wrap_divergent_paths<'dr>(
    encrypted_msg: &str,
    remaining_paths: &[(String, Vec<String>)], // (recipient, remaining_path)
    headers: Option<&HashMap<String, Value>>,
    enc_alg_anon: &AnonCryptAlg,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
    use_routing_multi: bool,
) -> Result<String> {
    use super::{build_forward_message_multi, NextDestination};

    let mut next_hop_groups: HashMap<String, Vec<String>> = HashMap::new();
    let mut next_hop_remaining: HashMap<String, Vec<String>> = HashMap::new();

    for (recipient, remaining_path) in remaining_paths {
        if let Some(next_hop) = remaining_path.first() {
            next_hop_groups
                .entry(next_hop.clone())
                .or_default()
                .push(recipient.clone());

            if !next_hop_remaining.contains_key(next_hop) {
                let remaining = if remaining_path.len() > 1 {
                    remaining_path[1..].to_vec()
                } else {
                    vec![]
                };
                next_hop_remaining.insert(next_hop.clone(), remaining);
            }
        }
    }

    if use_routing_multi && next_hop_groups.len() > 1 {
        let mut encrypted_attachments = HashMap::new();
        let mut next_destinations = Vec::new();

        for (next_hop, recipients) in &next_hop_groups {
            let remaining = next_hop_remaining.get(next_hop).unwrap();

            let wrapped = wrap_for_mediator_chain(
                encrypted_msg,
                recipients,
                remaining,
                headers,
                enc_alg_anon,
                did_resolver,
            )
            .await?
            .0;

            let forward_to = remaining.first().unwrap_or(&recipients[0]);

            let (fwd_msg, fwd_id) = build_forward_message(&wrapped, forward_to, headers)
                .context("Failed to build forward message for divergent path")?;

            let encrypted = anoncrypt(
                &[next_hop.as_str()],
                did_resolver,
                fwd_msg.as_bytes(),
                enc_alg_anon,
            )
            .await
            .context(format!("Failed to encrypt for next hop {next_hop}"))?
            .0;

            let attachment_id = format!("att-{fwd_id}");
            encrypted_attachments.insert(attachment_id.clone(), encrypted);

            next_destinations.push(NextDestination {
                to: vec![next_hop.clone()],
                attachment_id,
            });
        }

        let (routing_multi_msg, _) =
            build_forward_message_multi(next_destinations, encrypted_attachments, headers)
                .context("Failed to build routing-multi message for divergent paths")?;

        Ok(routing_multi_msg)
    } else {
        // With a single next hop (or routing-multi off) only the first recipient's path is wrapped.
        let (recipient, remaining_path) = &remaining_paths[0];
        Ok(wrap_for_mediator_chain(
            encrypted_msg,
            std::slice::from_ref(recipient),
            remaining_path,
            headers,
            enc_alg_anon,
            did_resolver,
        )
        .await?
        .0)
    }
}

/// Wraps a message for a chain of mediators.
///
/// Takes a message and wraps it in forward messages for each mediator in the chain,
/// working from last to first (inside-out wrapping).
///
/// Returns the wrapped message and the IDs of its forward messages, outermost first.
async fn wrap_for_mediator_chain<'dr>(
    msg: &str,
    recipients: &[String],
    mediators: &[String],
    headers: Option<&HashMap<String, Value>>,
    enc_alg_anon: &AnonCryptAlg,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<(String, Vec<String>)> {
    if mediators.is_empty() {
        return Ok((msg.to_owned(), Vec::new()));
    }

    let mut current_msg = msg.to_owned();
    let mut next_hop = recipients.first().unwrap().clone(); // The ultimate destination
    let mut forward_ids = Vec::with_capacity(mediators.len());

    for mediator in mediators.iter().rev() {
        let (forward_msg, forward_id) = build_forward_message(&current_msg, &next_hop, headers)
            .context("Failed to build forward message")?;
        forward_ids.push(forward_id);

        current_msg = anoncrypt(
            &[mediator.as_str()],
            did_resolver,
            forward_msg.as_bytes(),
            enc_alg_anon,
        )
        .await
        .context(format!("Failed to encrypt for mediator {mediator}"))?
        .0;

        // The next iteration wraps for the previous mediator, pointing to this one
        next_hop = mediator.clone();
    }

    // The loop built the innermost forward first.
    forward_ids.reverse();

    Ok((current_msg, forward_ids))
}

#[cfg(test)]
mod tests {
    #[test]
    fn identical_routes_are_detected() {
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
            is_prefix_based: false,
        };

        assert!(group.has_identical_routes());
    }

    #[test]
    fn divergent_routes_are_not_identical() {
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
            is_prefix_based: false,
        };

        assert!(!group.has_identical_routes());
    }
}
