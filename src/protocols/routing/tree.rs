//! Routing tree optimization for multi-recipient DIDComm messages.
//!
//! This module implements intelligent routing optimization for messages sent to multiple
//! recipients that may have different mediator chains. The key insight is that when multiple
//! recipients share common mediators in their routing paths, we can optimize by:
//! 1. Encrypting the message once for all recipients
//! 2. Identifying common mediator suffixes in routing paths
//! 3. Creating optimized forward message trees
//!
//! Example scenario:
//! - Recipient 1: R1 → med1 → med2
//! - Recipient 2: R2 → med3 → med2
//! - Recipient 3: R3 → med3 → med2
//!
//! Optimization:
//! - Encrypt once for [R1, R2, R3]
//! - Wrap for med2 (common final mediator)
//! - Create two branches: one for med1, one for med3
//! - Result: 2 messages instead of 3

use std::collections::HashMap;

use crate::{did::DIDResolver, error::Result};

use super::resolve_did_comm_services_chain;

/// Represents the complete routing path for a single recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPath {
    /// The final recipient DID or DID URL (can include key ID like "did:example:bob#key-1")
    pub recipient_did: String,

    /// Ordered list of mediators from first to last.
    /// Empty if recipient has direct delivery (no mediators).
    /// Example: ["did:med1", "did:med2"] means message goes med1 → med2 → recipient
    pub mediators: Vec<String>,

    /// The final service endpoint to send to (either first mediator or direct endpoint)
    pub service_endpoint: String,

    /// Service ID used for routing
    pub service_id: String,
}

impl RoutingPath {
    /// Returns true if this recipient requires routing through mediators
    pub fn needs_forwarding(&self) -> bool {
        !self.mediators.is_empty()
    }

    /// Returns the first mediator in the chain (the one we send to)
    pub fn first_mediator(&self) -> Option<&str> {
        self.mediators.first().map(std::string::String::as_str)
    }

    /// Returns the last mediator in the chain (closest to recipient)
    pub fn last_mediator(&self) -> Option<&str> {
        self.mediators.last().map(std::string::String::as_str)
    }

    /// Returns the length of the mediator chain
    pub fn mediator_count(&self) -> usize {
        self.mediators.len()
    }
}

/// A group of recipients that share routing characteristics and can be optimized together.
#[derive(Debug, Clone)]
pub struct RouteGroup {
    /// Recipients in this group
    pub recipients: Vec<String>,

    /// Mediators shared by all recipients in this group, ordered from first to last.
    /// With `is_prefix_based` (what `group_by_common_routes` builds) these are the common
    /// first hops: R1→`[med1,med2]` and R2→`[med1,med3]` share `["med1"]`. Otherwise they are the
    /// common last hops: R1→`[med1,med2]` and R2→`[med3,med2]` share `["med2"]`.
    pub common_suffix: Vec<String>,

    /// Maps each recipient DID to the mediators of its chain that are not in `common_suffix`.
    pub individual_paths: HashMap<String, Vec<String>>,

    /// The service endpoint to send to for this group
    pub service_endpoint: String,

    /// Service ID for this group
    pub service_id: String,

    /// Whether this group is based on common prefix (true) or suffix (false)
    pub is_prefix_based: bool,
}

impl RouteGroup {
    /// Returns true if all recipients in this group share the entire routing path
    pub fn has_identical_routes(&self) -> bool {
        self.individual_paths.values().all(std::vec::Vec::is_empty)
    }

    /// Returns the total depth of routing (common + individual)
    pub fn total_depth(&self) -> usize {
        let max_individual = self
            .individual_paths
            .values()
            .map(std::vec::Vec::len)
            .max()
            .unwrap_or(0);
        self.common_suffix.len() + max_individual
    }
}

/// The complete routing tree for all recipients, optimized for minimal message sends.
#[derive(Debug, Clone)]
pub struct RoutingTree {
    /// Recipients that need no forwarding (direct delivery)
    pub direct_recipients: Vec<RoutingPath>,

    /// Groups of recipients organized by shared routing paths
    pub routed_groups: Vec<RouteGroup>,
}

impl Default for RoutingTree {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTree {
    /// Create a new empty routing tree
    pub fn new() -> Self {
        Self {
            direct_recipients: Vec::new(),
            routed_groups: Vec::new(),
        }
    }

    /// Returns the total number of recipients in this tree
    pub fn recipient_count(&self) -> usize {
        self.direct_recipients.len()
            + self
                .routed_groups
                .iter()
                .map(|g| g.recipients.len())
                .sum::<usize>()
    }

    /// Returns the number of messages that will need to be sent
    pub fn message_count(&self) -> usize {
        // All direct recipients share one message.
        let direct_count = if self.direct_recipients.is_empty() {
            0
        } else {
            1
        };

        // Each routed group is one message.
        let routed_count = self.routed_groups.len();

        direct_count + routed_count
    }

    /// Returns true if any recipient needs forwarding
    pub fn needs_forwarding(&self) -> bool {
        !self.routed_groups.is_empty()
    }
}

/// Analyzes recipient DIDs and builds their routing paths.
pub async fn analyze_routing_paths<'dr>(
    recipients: &[&str],
    service_id: Option<&str>,
    did_resolver: &'dr (dyn DIDResolver + 'dr),
) -> Result<Vec<RoutingPath>> {
    let mut paths = Vec::new();

    for recipient in recipients {
        let services_chain =
            resolve_did_comm_services_chain(recipient, service_id, did_resolver).await?;

        let path = if services_chain.is_empty() {
            // No services found: direct delivery.
            RoutingPath {
                recipient_did: recipient.to_string(),
                mediators: Vec::new(),
                service_endpoint: String::new(), // No endpoint needed for direct delivery
                service_id: String::new(),
            }
        } else {
            let mut mediators = Vec::new();

            // Services are ordered from outermost to innermost
            // services_chain[0] is the final recipient's service
            // services_chain[1..] are mediators (if any)
            if services_chain.len() > 1 {
                for service in &services_chain[1..] {
                    mediators.push(service.1.uri.clone());
                }
            }

            // The last service is the one closest to the recipient.
            mediators.extend(services_chain.last().unwrap().1.routing_keys.clone());

            let service_endpoint = services_chain.first().unwrap().1.uri.clone();
            let service_id = services_chain.last().unwrap().0.clone();

            RoutingPath {
                recipient_did: recipient.to_string(),
                mediators,
                service_endpoint,
                service_id,
            }
        };

        paths.push(path);
    }

    Ok(paths)
}

/// Finds the longest common prefix between two mediator chains.
/// Returns the common prefix and the remaining suffixes for each chain.
fn find_common_prefix(
    path1: &[String],
    path2: &[String],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut common = Vec::new();
    let min_len = path1.len().min(path2.len());

    for i in 0..min_len {
        if path1[i] == path2[i] {
            common.push(path1[i].clone());
        } else {
            break;
        }
    }

    let suffix1 = path1[common.len()..].to_vec();
    let suffix2 = path2[common.len()..].to_vec();

    (common, suffix1, suffix2)
}

/// Groups routing paths that share their first mediators. Paths without a shared first hop
/// are not grouped; direct recipients are kept apart in `direct_recipients`.
pub fn group_by_common_routes(paths: Vec<RoutingPath>) -> RoutingTree {
    let mut tree = RoutingTree::new();

    let (direct, mut routed): (Vec<_>, Vec<_>) =
        paths.into_iter().partition(|p| !p.needs_forwarding());

    tree.direct_recipients = direct;

    if routed.is_empty() {
        return tree;
    }

    while !routed.is_empty() {
        let first = routed.remove(0);
        let mut group_recipients = vec![first.recipient_did.clone()];
        let mut individual_paths = HashMap::new();
        let mut common_prefix = first.mediators.clone();
        let service_endpoint = first.service_endpoint.clone();
        let service_id = first.service_id.clone();

        // Initially, first recipient has no suffix (all of its path is "common prefix")
        individual_paths.insert(first.recipient_did.clone(), Vec::new());

        let mut i = 0;
        while i < routed.len() {
            let (new_common, suffix1, suffix2) =
                find_common_prefix(&common_prefix, &routed[i].mediators);

            // Only group if they share at least one mediator at the start
            if !new_common.is_empty() {
                common_prefix = new_common;

                // Update all existing recipients' suffixes by prepending suffix1
                // (the part that was removed from common_prefix)
                // suffix1 must come BEFORE the current suffix because it represents
                // the earlier part of the routing path
                if !suffix1.is_empty() {
                    for recipient_did in &group_recipients {
                        let current_suffix = individual_paths
                            .get(recipient_did)
                            .cloned()
                            .unwrap_or_default();
                        let mut extended_suffix = suffix1.clone();
                        extended_suffix.extend_from_slice(&current_suffix);
                        individual_paths.insert(recipient_did.clone(), extended_suffix);
                    }
                }

                let recipient = routed.remove(i);
                group_recipients.push(recipient.recipient_did.clone());
                individual_paths.insert(recipient.recipient_did, suffix2);
            } else {
                i += 1;
            }
        }

        tree.routed_groups.push(RouteGroup {
            recipients: group_recipients,
            // Holds the common prefix for prefix-based groups.
            common_suffix: common_prefix,
            individual_paths,
            service_endpoint,
            service_id,
            is_prefix_based: true,
        });
    }

    tree
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(mediators: &[&str]) -> Vec<String> {
        mediators.iter().map(|m| (*m).to_owned()).collect()
    }

    #[test]
    fn common_prefix_splits_the_chains() {
        type Chains = &'static [&'static str];
        // (path1, path2, common prefix, rest of path1, rest of path2)
        let cases: [(Chains, Chains, Chains, Chains, Chains); 5] = [
            (
                &["med1", "med2"],
                &["med1", "med3"],
                &["med1"],
                &["med2"],
                &["med3"],
            ),
            (
                &["med1", "med2"],
                &["med3", "med4"],
                &[],
                &["med1", "med2"],
                &["med3", "med4"],
            ),
            (
                &["med1", "med2"],
                &["med1", "med2"],
                &["med1", "med2"],
                &[],
                &[],
            ),
            (&["med1"], &["med1", "med2"], &["med1"], &[], &["med2"]),
            (
                &["med1", "med2", "med3"],
                &["med1"],
                &["med1"],
                &["med2", "med3"],
                &[],
            ),
        ];

        for (path1, path2, common, rest1, rest2) in cases {
            let (actual_common, actual_rest1, actual_rest2) =
                find_common_prefix(&chain(path1), &chain(path2));

            assert_eq!(actual_common, chain(common));
            assert_eq!(actual_rest1, chain(rest1));
            assert_eq!(actual_rest2, chain(rest2));
        }
    }
}
