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
    assert_eq!(tree.routed_groups.len(), 1);

    let group = &tree.routed_groups[0];
    assert_eq!(group.recipients.len(), 2);
    assert_eq!(group.common_suffix, vec!["did:example:med2"]);
    assert!(!group.has_identical_routes());

    // Check individual paths
    let alice_path = group.individual_paths.get("did:example:alice").unwrap();
    let bob_path = group.individual_paths.get("did:example:bob").unwrap();

    // One should have med1, other should have med3 as their unique prefix
    assert!(
        (alice_path == &vec!["did:example:med1".to_string()]
            && bob_path == &vec!["did:example:med3".to_string()])
            || (alice_path == &vec!["did:example:med3".to_string()]
                && bob_path == &vec!["did:example:med1".to_string()])
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

    // Should create one group with all three recipients sharing med2 as common suffix
    assert_eq!(tree.routed_groups.len(), 1);

    let group = &tree.routed_groups[0];
    assert_eq!(group.recipients.len(), 3);
    assert_eq!(group.common_suffix, vec!["did:example:med2"]);

    // R2 and R3 should have the same individual path (med3)
    // R1 should have different path (med1)
    let r1_path = group.individual_paths.get("did:example:r1").unwrap();
    let r2_path = group.individual_paths.get("did:example:r2").unwrap();
    let r3_path = group.individual_paths.get("did:example:r3").unwrap();

    assert_eq!(r1_path, &vec!["did:example:med1".to_string()]);
    assert_eq!(r2_path, &vec!["did:example:med3".to_string()]);
    assert_eq!(r3_path, &vec!["did:example:med3".to_string()]);
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

    // All recipients should be grouped
    assert_eq!(tree.direct_recipients.len(), 0);
    assert_eq!(tree.routed_groups.len(), 1);

    let group = &tree.routed_groups[0];
    assert_eq!(group.recipients.len(), 3);
    assert_eq!(group.common_suffix, vec!["did:example:med3"]);

    // Verify individual paths - this is the critical test for the bug fix
    let r1_path = group.individual_paths.get("did:example:r1").unwrap();
    let r2_path = group.individual_paths.get("did:example:r2").unwrap();
    let r3_path = group.individual_paths.get("did:example:r3").unwrap();

    assert_eq!(
        r1_path,
        &vec![
            "did:example:med1".to_string(),
            "did:example:med2".to_string()
        ],
        "R1 should have full prefix [med1, med2], not just [med2]"
    );
    assert_eq!(
        r2_path,
        &vec![
            "did:example:med4".to_string(),
            "did:example:med2".to_string()
        ],
        "R2 should have full prefix [med4, med2], not just [med2]"
    );
    assert_eq!(
        r3_path,
        &vec!["did:example:med5".to_string()],
        "R3 should have prefix [med5]"
    );
}
