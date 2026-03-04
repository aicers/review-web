use async_graphql::Result;

use super::is_member;

/// Extracts the customer ID for node-level CRUD authorization.
///
/// Uses `profile.customer_id` if available and falls back to
/// `profile_draft.customer_id` for draft-only nodes.
#[must_use]
fn node_customer_id(node: &review_database::Node) -> Option<u32> {
    node.profile
        .as_ref()
        .map(|profile| profile.customer_id)
        .or_else(|| {
            node.profile_draft
                .as_ref()
                .map(|profile| profile.customer_id)
        })
}

/// Checks whether the requester can access the given node.
///
/// Returns `true` if:
/// - The requester is admin (`users_customers` is `None`), or
/// - The node has a customer ID (from `profile` or `profile_draft`) in the requester's scope.
#[must_use]
pub(crate) fn can_access_node(
    users_customers: Option<&[u32]>,
    node: &review_database::Node,
) -> bool {
    match users_customers {
        None => true,
        Some(users_customers) => node_customer_id(node)
            .is_some_and(|customer_id| is_member(Some(users_customers), customer_id)),
    }
}

/// Checks whether the requester can access the given node.
///
/// Returns `Ok(())` if:
/// - The requester is admin (`users_customers` is `None`), or
/// - The node has a customer ID (from `profile` or `profile_draft`) in the requester's scope.
///
/// # Errors
///
/// Returns `Forbidden` if the requester is not allowed to access the node.
pub(crate) fn check_node_access(
    users_customers: Option<&[u32]>,
    node: &review_database::Node,
) -> Result<()> {
    if can_access_node(users_customers, node) {
        Ok(())
    } else {
        Err("Forbidden".into())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    #[test]
    fn test_can_access_node_profile_draft_allowed() {
        let node = review_database::Node {
            id: u32::MAX,
            name: "draft-only".to_string(),
            name_draft: Some("draft-only".to_string()),
            profile: None,
            profile_draft: Some(review_database::NodeProfile {
                customer_id: 7,
                description: String::new(),
                hostname: "host-draft".to_string(),
            }),
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };

        assert!(can_access_node(Some(&[7]), &node));
    }

    #[test]
    fn test_can_access_node_profile_draft_forbidden() {
        let node = review_database::Node {
            id: u32::MAX,
            name: "draft-only".to_string(),
            name_draft: Some("draft-only".to_string()),
            profile: None,
            profile_draft: Some(review_database::NodeProfile {
                customer_id: 7,
                description: String::new(),
                hostname: "host-draft".to_string(),
            }),
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };

        assert!(!can_access_node(Some(&[1]), &node));
    }

    #[test]
    fn test_check_node_access_profile_draft_allowed() {
        let node = review_database::Node {
            id: u32::MAX,
            name: "draft-only".to_string(),
            name_draft: Some("draft-only".to_string()),
            profile: None,
            profile_draft: Some(review_database::NodeProfile {
                customer_id: 7,
                description: String::new(),
                hostname: "host-draft".to_string(),
            }),
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };

        assert!(check_node_access(Some(&[7]), &node).is_ok());
    }

    #[test]
    fn test_check_node_access_profile_draft_forbidden() {
        let node = review_database::Node {
            id: u32::MAX,
            name: "draft-only".to_string(),
            name_draft: Some("draft-only".to_string()),
            profile: None,
            profile_draft: Some(review_database::NodeProfile {
                customer_id: 7,
                description: String::new(),
                hostname: "host-draft".to_string(),
            }),
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };

        let err = check_node_access(Some(&[1]), &node).unwrap_err();
        assert_eq!(err.message, "Forbidden");
    }
}
