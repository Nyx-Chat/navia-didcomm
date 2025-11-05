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

use crate::{did::DIDResolver, error::Result, utils::did::did_or_url};

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
        self.mediators.first().map(|s| s.as_str())
    }

    /// Returns the last mediator in the chain (closest to recipient)
    pub fn last_mediator(&self) -> Option<&str> {
        self.mediators.last().map(|s| s.as_str())
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

    /// Common mediator path suffix shared by all recipients in this group.
    /// Ordered from first common mediator to last.
    /// Example: If R1→[med1,med2] and R2→[med3,med2], common_suffix is ["med2"]
    pub common_suffix: Vec<String>,

    /// Individual paths for each recipient in this group, showing the divergent part.
    /// Maps recipient DID to their unique mediator prefix.
    pub individual_paths: HashMap<String, Vec<String>>,

    /// The service endpoint to send to for this group
    pub service_endpoint: String,

    /// Service ID for this group
    pub service_id: String,
}

impl RouteGroup {
    /// Returns true if all recipients in this group share the entire routing path
    pub fn has_identical_routes(&self) -> bool {
        self.individual_paths.values().all(|path| path.is_empty())
    }

    /// Returns the total depth of routing (common + individual)
    pub fn total_depth(&self) -> usize {
        let max_individual = self
            .individual_paths
            .values()
            .map(|p| p.len())
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
        // One message per direct recipient
        let direct_count = if self.direct_recipients.is_empty() {
            0
        } else {
            1
        };

        // For routed groups, count the number of distinct first mediators
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
        let (_recipient_did, _) = did_or_url(recipient);

        // Resolve the service chain for this recipient
        let services_chain =
            resolve_did_comm_services_chain(recipient, service_id, did_resolver).await?;

        let path = if services_chain.is_empty() {
            // No services found - treat as direct delivery (no routing)
            RoutingPath {
                recipient_did: recipient.to_string(),
                mediators: Vec::new(),
                service_endpoint: String::new(), // No endpoint needed for direct delivery
                service_id: String::new(),
            }
        } else {
            // Extract mediators from the service chain
            let mut mediators = Vec::new();

            // Services are ordered from outermost to innermost
            // services_chain[0] is the final recipient's service
            // services_chain[1..] are mediators (if any)
            if services_chain.len() > 1 {
                // Add mediator URIs
                for service in &services_chain[1..] {
                    mediators.push(service.1.uri.clone());
                }
            }

            // Also add routing_keys from the last service (closest to recipient)
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

/// Finds the longest common suffix between two mediator chains.
/// Returns the common suffix and the remaining prefixes for each chain.
fn find_common_suffix(
    path1: &[String],
    path2: &[String],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut common = Vec::new();
    let mut i = path1.len();
    let mut j = path2.len();

    // Work backwards from the end
    while i > 0 && j > 0 {
        if path1[i - 1] == path2[j - 1] {
            common.push(path1[i - 1].clone());
            i -= 1;
            j -= 1;
        } else {
            break;
        }
    }

    // Reverse common to get correct order (first to last)
    common.reverse();

    let prefix1 = path1[..i].to_vec();
    let prefix2 = path2[..j].to_vec();

    (common, prefix1, prefix2)
}

/// Groups routing paths by their common suffixes to enable optimization.
pub fn group_by_common_routes(paths: Vec<RoutingPath>) -> RoutingTree {
    let mut tree = RoutingTree::new();

    // Separate direct recipients
    let (direct, mut routed): (Vec<_>, Vec<_>) =
        paths.into_iter().partition(|p| !p.needs_forwarding());

    tree.direct_recipients = direct;

    if routed.is_empty() {
        return tree;
    }

    // Group routed recipients by finding common suffixes
    while !routed.is_empty() {
        let first = routed.remove(0);
        let mut group_recipients = vec![first.recipient_did.clone()];
        let mut individual_paths = HashMap::new();
        let mut common_suffix = first.mediators.clone();
        let service_endpoint = first.service_endpoint.clone();
        let service_id = first.service_id.clone();

        // Initially, first recipient has no prefix (all of its path is "common")
        individual_paths.insert(first.recipient_did.clone(), Vec::new());

        // Find others with compatible routes
        let mut i = 0;
        while i < routed.len() {
            let (new_common, prefix1, prefix2) =
                find_common_suffix(&common_suffix, &routed[i].mediators);

            // Only group if they share at least one mediator
            if !new_common.is_empty() {
                // Update the common suffix
                common_suffix = new_common;

                // Update all existing recipients' prefixes by extending them with prefix1
                // (the part that was removed from common_suffix)
                if !prefix1.is_empty() {
                    for recipient_did in &group_recipients {
                        let current_prefix = individual_paths
                            .get(recipient_did)
                            .cloned()
                            .unwrap_or_default();
                        let mut extended_prefix = current_prefix;
                        extended_prefix.extend_from_slice(&prefix1);
                        individual_paths.insert(recipient_did.clone(), extended_prefix);
                    }
                }

                // Add this recipient to the group
                let recipient = routed.remove(i);
                group_recipients.push(recipient.recipient_did.clone());
                individual_paths.insert(recipient.recipient_did, prefix2);
            } else {
                i += 1;
            }
        }

        tree.routed_groups.push(RouteGroup {
            recipients: group_recipients,
            common_suffix,
            individual_paths,
            service_endpoint,
            service_id,
        });
    }

    tree
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_common_suffix() {
        let path1 = vec!["med1".to_owned(), "med2".to_owned()];
        let path2 = vec!["med3".to_owned(), "med2".to_owned()];

        let (common, prefix1, prefix2) = find_common_suffix(&path1, &path2);

        assert_eq!(common, vec!["med2"]);
        assert_eq!(prefix1, vec!["med1"]);
        assert_eq!(prefix2, vec!["med3"]);
    }

    #[test]
    fn test_find_common_suffix_no_common() {
        let path1 = vec!["med1".to_owned(), "med2".to_owned()];
        let path2 = vec!["med3".to_owned(), "med4".to_owned()];

        let (common, prefix1, prefix2) = find_common_suffix(&path1, &path2);

        assert!(common.is_empty());
        assert_eq!(prefix1, path1);
        assert_eq!(prefix2, path2);
    }

    #[test]
    fn test_find_common_suffix_identical() {
        let path1 = vec!["med1".to_owned(), "med2".to_owned()];
        let path2 = vec!["med1".to_owned(), "med2".to_owned()];

        let (common, prefix1, prefix2) = find_common_suffix(&path1, &path2);

        assert_eq!(common, vec!["med1", "med2"]);
        assert!(prefix1.is_empty());
        assert!(prefix2.is_empty());
    }
}
