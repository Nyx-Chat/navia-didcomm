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

    // PREFIX-BASED OPTIMIZATION (new)
    // When recipients share common first hops (e.g., David and Eve both through mediator1)
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

    // SUFFIX-BASED (original algorithm)
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

    // Get the first common mediator (where we send the message)
    let first_mediator = group
        .common_suffix
        .first()
        .ok_or_else(|| err_msg(ErrorKind::InvalidState, "Prefix group has no common prefix"))?;

    // Group recipients by their next hop (after the common prefix)
    let mut next_hop_groups: HashMap<String, Vec<String>> = HashMap::new();
    for (recipient, path) in &group.individual_paths {
        if let Some(next_hop) = path.first() {
            next_hop_groups
                .entry(next_hop.clone())
                .or_default()
                .push(recipient.clone());
        }
    }

    // Check if optimization provides benefit (multiple different next hops)
    let unique_next_hops: Vec<String> = next_hop_groups.keys().cloned().collect();
    let has_optimization_benefit = unique_next_hops.len() > 1;

    // USE ROUTING-MULTI: When flag is true AND optimization provides benefit
    if use_routing_multi && has_optimization_benefit {
        // For each next hop group, create a wrapped message for the remaining path
        let mut encrypted_attachments = HashMap::new();
        let mut next_destinations = Vec::new();

        for (next_hop, recipients_for_hop) in &next_hop_groups {
            // Get remaining paths for all recipients in this group
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

            // Check if all recipients have the same remaining path
            let all_same = remaining_paths.windows(2).all(|w| w[0].1 == w[1].1);

            let wrapped_for_path = if all_same && !remaining_paths.is_empty() {
                // Simple case: all recipients have same remaining path
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
            } else if !remaining_paths.is_empty() {
                // Complex case: recipients have divergent remaining paths
                // We need to recursively create a routing structure for the next level
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
                // No remaining path, just use the encrypted message
                encrypted_msg.to_owned()
            };

            // Build a forward message for this path that will be decrypted by next_hop
            // Determine where it should go AFTER next_hop decrypts it
            let forward_to = if all_same && !remaining_paths.is_empty() {
                // Use the first recipient's remaining path
                let remaining = &remaining_paths[0].1;
                if remaining.is_empty() {
                    // No more mediators after next_hop, point to final recipient
                    &recipients_for_hop[0]
                } else {
                    // Point to the next mediator in the chain
                    &remaining[0]
                }
            } else {
                // Divergent paths - the wrapped message is already a routing structure
                // Point to next_hop since it will handle the routing
                next_hop
            };

            let (inner_fwd, inner_fwd_id) =
                build_forward_message(&wrapped_for_path, forward_to, headers)
                    .context("Failed to build inner forward message")?;

            // Encrypt for the next hop
            let encrypted_for_next = anoncrypt(
                &[next_hop.as_str()],
                did_resolver,
                inner_fwd.as_bytes(),
                enc_alg_anon,
            )
            .await
            .context(format!("Failed to encrypt for next hop {next_hop}"))?
            .0;

            // Generate attachment ID
            let attachment_id = format!("att-{}", inner_fwd_id);

            // Add to attachments map
            encrypted_attachments.insert(attachment_id.clone(), encrypted_for_next);

            // Create NextDestination entry
            next_destinations.push(NextDestination {
                to: vec![next_hop.clone()],
                attachment_id,
            });
        }

        // Build the routing-multi forward message with all attachments
        let (fwd_mod_msg, _) =
            build_forward_message_multi(next_destinations, encrypted_attachments, headers)
                .context("Failed to build routing-multi forward message")?;

        // Encrypt for the first common mediator
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

        // Return single optimized wrapped message
        return Ok(vec![WrappedMessage {
            message: encrypted_fwd,
            service_endpoint: group.service_endpoint.clone(),
            service_id: group.service_id.clone(),
            final_recipients: group.recipients.clone(),
        }]);
    }

    // FALLBACK TO STANDARD DIDCOMM 2.0: When flag is false OR no optimization benefit
    // Create separate forward messages for each next hop
    let mut result = Vec::new();

    for (next_hop, recipients_for_hop) in next_hop_groups {
        // Get the remaining path after this next hop
        let remaining_path: Vec<String> = group
            .individual_paths
            .get(&recipients_for_hop[0])
            .map(|path| path[1..].to_vec())
            .unwrap_or_default();

        // Wrap the encrypted message for the remaining path
        let wrapped_for_path = wrap_for_mediator_chain(
            encrypted_msg,
            &recipients_for_hop,
            &remaining_path,
            headers,
            enc_alg_anon,
            did_resolver,
        )
        .await?;

        // Determine where the forward message should point to AFTER next_hop decrypts
        let forward_to = if remaining_path.is_empty() {
            // No more mediators, point to the final recipient
            &recipients_for_hop[0]
        } else {
            // Point to the next mediator in the remaining path
            &remaining_path[0]
        };

        // Build standard forward message pointing to where it goes after next_hop decrypts
        let (fwd_msg, _) = build_forward_message(&wrapped_for_path, forward_to, headers)
            .context("Failed to build forward message")?;

        // Encrypt for the next hop mediator (who will decrypt and forward)
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

    // Group recipients by their next hop
    let mut next_hop_groups: HashMap<String, Vec<String>> = HashMap::new();
    let mut next_hop_remaining: HashMap<String, Vec<String>> = HashMap::new();

    for (recipient, remaining_path) in remaining_paths {
        if let Some(next_hop) = remaining_path.first() {
            next_hop_groups
                .entry(next_hop.clone())
                .or_default()
                .push(recipient.clone());

            // Store the remaining path after this next hop
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

    // If we can use routing-multi and have multiple next hops, create a routing-multi message
    if use_routing_multi && next_hop_groups.len() > 1 {
        let mut encrypted_attachments = HashMap::new();
        let mut next_destinations = Vec::new();

        for (next_hop, recipients) in &next_hop_groups {
            let remaining = next_hop_remaining.get(next_hop).unwrap();

            // Recursively wrap for the remaining path
            let wrapped = wrap_for_mediator_chain(
                encrypted_msg,
                recipients,
                remaining,
                headers,
                enc_alg_anon,
                did_resolver,
            )
            .await?;

            // Build forward message pointing to where it should go AFTER next_hop decrypts
            // If there are more mediators in the remaining path, point to the first one
            // Otherwise, point to the final recipient
            let forward_to = if remaining.is_empty() {
                // No more mediators, point to the final recipient
                &recipients[0]
            } else {
                // Point to the next mediator in the remaining path
                &remaining[0]
            };

            let (fwd_msg, fwd_id) = build_forward_message(&wrapped, forward_to, headers)
                .context("Failed to build forward message for divergent path")?;

            // Encrypt for the next hop
            let encrypted = anoncrypt(
                &[next_hop.as_str()],
                did_resolver,
                fwd_msg.as_bytes(),
                enc_alg_anon,
            )
            .await
            .context(format!("Failed to encrypt for next hop {next_hop}"))?
            .0;

            // Add to attachments
            let attachment_id = format!("att-{}", fwd_id);
            encrypted_attachments.insert(attachment_id.clone(), encrypted);

            // Add destination
            next_destinations.push(NextDestination {
                to: vec![next_hop.clone()],
                attachment_id,
            });
        }

        // Build routing-multi message with all attachments
        let (routing_multi_msg, _) =
            build_forward_message_multi(next_destinations, encrypted_attachments, headers)
                .context("Failed to build routing-multi message for divergent paths")?;

        Ok(routing_multi_msg)
    } else {
        // Fallback: just wrap for the first recipient's path
        // This shouldn't happen often, but provides a safe fallback
        let (recipient, remaining_path) = &remaining_paths[0];
        wrap_for_mediator_chain(
            encrypted_msg,
            std::slice::from_ref(recipient),
            remaining_path,
            headers,
            enc_alg_anon,
            did_resolver,
        )
        .await
    }
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
            &[mediator.as_str()],
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
            is_prefix_based: false,
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
            is_prefix_based: false,
        };

        assert!(!group.has_identical_routes());
    }
}
