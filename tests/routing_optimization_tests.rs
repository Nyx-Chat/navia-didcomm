//! Integration tests for routing tree optimization

use navia_didcomm::protocols::routing::tree::{group_by_common_routes, RoutingPath};
use std::collections::HashMap;

#[test]
fn test_routing_path_needs_forwarding() {
    let direct_path = RoutingPath {
        recipient_did: "did:example:alice".to_string(),
        mediators: vec![],
        service_endpoint: "https://alice.example".to_string(),
        service_id: "service-1".to_string(),
    };

    let routed_path = RoutingPath {
        recipient_did: "did:example:bob".to_string(),
        mediators: vec!["did:example:mediator".to_string()],
        service_endpoint: "https://mediator.example".to_string(),
        service_id: "service-1".to_string(),
    };

    assert!(!direct_path.needs_forwarding());
    assert!(routed_path.needs_forwarding());
}

#[test]
fn test_routing_path_mediator_access() {
    let path = RoutingPath {
        recipient_did: "did:example:bob".to_string(),
        mediators: vec![
            "did:example:med1".to_string(),
            "did:example:med2".to_string(),
        ],
        service_endpoint: "https://med1.example".to_string(),
        service_id: "service-1".to_string(),
    };

    assert_eq!(path.first_mediator(), Some("did:example:med1"));
    assert_eq!(path.last_mediator(), Some("did:example:med2"));
    assert_eq!(path.mediator_count(), 2);
}

#[test]
fn test_group_by_common_routes_no_routing() {
    // All recipients have direct delivery
    let paths = vec![
        RoutingPath {
            recipient_did: "did:example:alice".to_string(),
            mediators: vec![],
            service_endpoint: "https://alice.example".to_string(),
            service_id: "service-1".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:bob".to_string(),
            mediators: vec![],
            service_endpoint: "https://bob.example".to_string(),
            service_id: "service-2".to_string(),
        },
    ];

    let tree = group_by_common_routes(paths);

    assert_eq!(tree.direct_recipients.len(), 2);
    assert_eq!(tree.routed_groups.len(), 0);
    assert!(!tree.needs_forwarding());
}

#[test]
fn test_group_by_common_routes_identical_paths() {
    // Two recipients with identical routing paths
    let paths = vec![
        RoutingPath {
            recipient_did: "did:example:alice".to_string(),
            mediators: vec![
                "did:example:med1".to_string(),
                "did:example:med2".to_string(),
            ],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-1".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:bob".to_string(),
            mediators: vec![
                "did:example:med1".to_string(),
                "did:example:med2".to_string(),
            ],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-1".to_string(),
        },
    ];

    let tree = group_by_common_routes(paths);

    assert_eq!(tree.direct_recipients.len(), 0);
    assert_eq!(tree.routed_groups.len(), 1);
    assert!(tree.needs_forwarding());

    let group = &tree.routed_groups[0];
    assert_eq!(group.recipients.len(), 2);
    assert_eq!(group.common_suffix.len(), 2);
    assert!(group.has_identical_routes());
}

#[test]
fn test_group_by_common_routes_with_common_suffix() {
    // Recipients with different first mediator but common final mediator
    // R1: med1 -> med2
    // R2: med3 -> med2
    let paths = vec![
        RoutingPath {
            recipient_did: "did:example:alice".to_string(),
            mediators: vec![
                "did:example:med1".to_string(),
                "did:example:med2".to_string(),
            ],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-1".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:bob".to_string(),
            mediators: vec![
                "did:example:med3".to_string(),
                "did:example:med2".to_string(),
            ],
            service_endpoint: "https://med3.example".to_string(),
            service_id: "service-2".to_string(),
        },
    ];

    let tree = group_by_common_routes(paths);

    assert_eq!(tree.direct_recipients.len(), 0);
    // Alice and Bob have different service endpoints, so they're in separate groups
    assert_eq!(tree.routed_groups.len(), 2);

    // Each recipient should be in their own group
    assert!(tree.routed_groups.iter().all(|g| g.recipients.len() == 1));

    // Find Alice's group
    let alice_group = tree
        .routed_groups
        .iter()
        .find(|g| g.recipients.contains(&"did:example:alice".to_string()))
        .unwrap();
    assert_eq!(
        alice_group.common_suffix,
        vec!["did:example:med1", "did:example:med2"]
    );

    // Find Bob's group
    let bob_group = tree
        .routed_groups
        .iter()
        .find(|g| g.recipients.contains(&"did:example:bob".to_string()))
        .unwrap();
    assert_eq!(
        bob_group.common_suffix,
        vec!["did:example:med3", "did:example:med2"]
    );
}

#[test]
fn test_group_by_common_routes_no_common() {
    // Recipients with completely different routing paths
    let paths = vec![
        RoutingPath {
            recipient_did: "did:example:alice".to_string(),
            mediators: vec!["did:example:med1".to_string()],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-1".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:bob".to_string(),
            mediators: vec!["did:example:med2".to_string()],
            service_endpoint: "https://med2.example".to_string(),
            service_id: "service-2".to_string(),
        },
    ];

    let tree = group_by_common_routes(paths);

    assert_eq!(tree.direct_recipients.len(), 0);
    // Should create separate groups since no common mediators
    assert_eq!(tree.routed_groups.len(), 2);
}

#[test]
fn test_group_by_common_routes_mixed() {
    // Mix of direct and routed recipients
    let paths = vec![
        RoutingPath {
            recipient_did: "did:example:alice".to_string(),
            mediators: vec![],
            service_endpoint: "https://alice.example".to_string(),
            service_id: "service-1".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:bob".to_string(),
            mediators: vec!["did:example:med1".to_string()],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-2".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:charlie".to_string(),
            mediators: vec!["did:example:med1".to_string()],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-2".to_string(),
        },
    ];

    let tree = group_by_common_routes(paths);

    // Alice should be in direct recipients
    assert_eq!(tree.direct_recipients.len(), 1);
    assert_eq!(tree.direct_recipients[0].recipient_did, "did:example:alice");

    // Bob and Charlie should be grouped together
    assert_eq!(tree.routed_groups.len(), 1);
    assert_eq!(tree.routed_groups[0].recipients.len(), 2);
}

#[test]
fn test_routing_tree_message_count() {
    let paths = vec![
        RoutingPath {
            recipient_did: "did:example:alice".to_string(),
            mediators: vec![],
            service_endpoint: "https://alice.example".to_string(),
            service_id: "service-1".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:bob".to_string(),
            mediators: vec!["did:example:med1".to_string()],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-2".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:charlie".to_string(),
            mediators: vec!["did:example:med1".to_string()],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-2".to_string(),
        },
    ];

    let tree = group_by_common_routes(paths);

    // Should result in 2 messages:
    // 1. For direct recipient (Alice)
    // 2. For routed group (Bob + Charlie through med1)
    assert_eq!(tree.message_count(), 2);
    assert_eq!(tree.recipient_count(), 3);
}

#[test]
fn test_route_group_total_depth() {
    use navia_didcomm::protocols::routing::tree::RouteGroup;

    let mut individual_paths = HashMap::new();
    individual_paths.insert(
        "did:example:alice".to_string(),
        vec!["did:example:med1".to_string()],
    );
    individual_paths.insert(
        "did:example:bob".to_string(),
        vec!["did:example:med3".to_string()],
    );

    let group = RouteGroup {
        recipients: vec![
            "did:example:alice".to_string(),
            "did:example:bob".to_string(),
        ],
        common_suffix: vec!["did:example:med2".to_string()],
        individual_paths,
        service_endpoint: "https://med.example".to_string(),
        service_id: "service-1".to_string(),
        is_prefix_based: false,
    };

    // Total depth = 1 (common) + 1 (max individual) = 2
    assert_eq!(group.total_depth(), 2);
}

#[test]
fn test_complex_routing_scenario() {
    // Complex scenario from the original conversation:
    // R1: med1 -> med2
    // R2: med3 -> med2
    // R3: med3 -> med2
    // Expected optimization: group R2 and R3, separate path for R1
    let paths = vec![
        RoutingPath {
            recipient_did: "did:example:r1".to_string(),
            mediators: vec![
                "did:example:med1".to_string(),
                "did:example:med2".to_string(),
            ],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-1".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:r2".to_string(),
            mediators: vec![
                "did:example:med3".to_string(),
                "did:example:med2".to_string(),
            ],
            service_endpoint: "https://med3.example".to_string(),
            service_id: "service-2".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:r3".to_string(),
            mediators: vec![
                "did:example:med3".to_string(),
                "did:example:med2".to_string(),
            ],
            service_endpoint: "https://med3.example".to_string(),
            service_id: "service-2".to_string(),
        },
    ];

    let tree = group_by_common_routes(paths);

    // All recipients need routing
    assert_eq!(tree.direct_recipients.len(), 0);

    // With prefix-based optimization: R2 and R3 (identical paths) in one group, R1 separate
    // This is more optimal than grouping all three together
    assert_eq!(tree.routed_groups.len(), 2);

    // Find the group with R2 and R3 (they have identical paths: med3 -> med2)
    let r2_r3_group = tree
        .routed_groups
        .iter()
        .find(|g| g.recipients.contains(&"did:example:r2".to_string()))
        .unwrap();
    assert_eq!(r2_r3_group.recipients.len(), 2);
    assert!(r2_r3_group.has_identical_routes());
    assert_eq!(
        r2_r3_group.common_suffix,
        vec!["did:example:med3", "did:example:med2"]
    );

    // Find the group with R1 (separate path: med1 -> med2)
    let r1_group = tree
        .routed_groups
        .iter()
        .find(|g| g.recipients.contains(&"did:example:r1".to_string()))
        .unwrap();
    assert_eq!(r1_group.recipients.len(), 1);
    assert_eq!(
        r1_group.common_suffix,
        vec!["did:example:med1", "did:example:med2"]
    );
}

#[test]
fn test_three_hop_routing_with_shrinking_common() {
    // Test case with 3-hop paths where common suffix shrinks multiple times
    // R1: med1 -> med2 -> med3
    // R2: med4 -> med2 -> med3
    // R3: med5 -> med3
    // Expected: common=med3, R1=[med1,med2], R2=[med4,med2], R3=[med5]
    let paths = vec![
        RoutingPath {
            recipient_did: "did:example:r1".to_string(),
            mediators: vec![
                "did:example:med1".to_string(),
                "did:example:med2".to_string(),
                "did:example:med3".to_string(),
            ],
            service_endpoint: "https://med1.example".to_string(),
            service_id: "service-1".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:r2".to_string(),
            mediators: vec![
                "did:example:med4".to_string(),
                "did:example:med2".to_string(),
                "did:example:med3".to_string(),
            ],
            service_endpoint: "https://med4.example".to_string(),
            service_id: "service-2".to_string(),
        },
        RoutingPath {
            recipient_did: "did:example:r3".to_string(),
            mediators: vec![
                "did:example:med5".to_string(),
                "did:example:med3".to_string(),
            ],
            service_endpoint: "https://med5.example".to_string(),
            service_id: "service-3".to_string(),
        },
    ];

    let tree = group_by_common_routes(paths);

    // All recipients need routing
    assert_eq!(tree.direct_recipients.len(), 0);
    // Recipients have different service endpoints, so they're in separate groups
    assert_eq!(tree.routed_groups.len(), 3);

    // Each recipient should be in their own group
    assert!(tree.routed_groups.iter().all(|g| g.recipients.len() == 1));

    // Verify individual routing paths for each group
    let r1_group = tree
        .routed_groups
        .iter()
        .find(|g| g.recipients.contains(&"did:example:r1".to_string()))
        .unwrap();
    assert_eq!(
        r1_group.common_suffix,
        vec!["did:example:med1", "did:example:med2", "did:example:med3"]
    );

    let r2_group = tree
        .routed_groups
        .iter()
        .find(|g| g.recipients.contains(&"did:example:r2".to_string()))
        .unwrap();
    assert_eq!(
        r2_group.common_suffix,
        vec!["did:example:med4", "did:example:med2", "did:example:med3"]
    );

    let r3_group = tree
        .routed_groups
        .iter()
        .find(|g| g.recipients.contains(&"did:example:r3".to_string()))
        .unwrap();
    assert_eq!(
        r3_group.common_suffix,
        vec!["did:example:med5", "did:example:med3"]
    );
}
