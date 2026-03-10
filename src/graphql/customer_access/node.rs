use async_graphql::{Context, Result, types::ID};

use super::{is_member, users_customers};

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

/// Loads the given node and checks whether the requester can access it.
///
/// Returns the node if:
/// - The node exists, and
/// - The requester is admin, or
/// - The node has a customer ID (from `profile` or `profile_draft`) in the requester's scope.
///
/// # Errors
///
/// Returns an error if the GraphQL context is missing required authorization data or the store
/// cannot be read.
///
/// Returns `no such node` if the node does not exist.
///
/// Returns `Forbidden` if the requester is not allowed to access the node.
pub(crate) fn load_accessible_node(
    ctx: &Context<'_>,
    node_id: &ID,
) -> Result<review_database::Node> {
    let users_customers = users_customers(ctx)?;
    let node_id = node_id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
    let store = crate::graphql::get_store(ctx)?;
    let map = store.node_map();
    let Some((node, _, _)) = map.get_by_id(node_id)? else {
        return Err("no such node".into());
    };
    if can_access_node(users_customers.as_deref(), &node) {
        Ok(node)
    } else {
        Err("Forbidden".into())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
    use chrono::Utc;
    use review_database::{Role, Store, types};

    use super::*;

    fn test_node(customer_id: u32) -> review_database::Node {
        review_database::Node {
            id: u32::MAX,
            name: "draft-only".to_string(),
            name_draft: Some("draft-only".to_string()),
            profile: None,
            profile_draft: Some(review_database::NodeProfile {
                customer_id,
                description: String::new(),
                hostname: "host-draft".to_string(),
            }),
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        }
    }

    #[derive(Default)]
    struct QueryRoot;

    #[Object]
    impl QueryRoot {
        async fn load_accessible_node(&self, ctx: &Context<'_>, customer_id: u32) -> Result<bool> {
            let store = crate::graphql::get_store(ctx)?;
            let node_id = store.node_map().put(&test_node(customer_id))?;
            let node = super::load_accessible_node(ctx, &ID(node_id.to_string()))?;
            assert_eq!(
                node.profile_draft
                    .as_ref()
                    .map(|profile| profile.customer_id),
                Some(customer_id)
            );
            Ok(true)
        }

        async fn load_missing_node(&self, ctx: &Context<'_>, node_id: ID) -> Result<bool> {
            super::load_accessible_node(ctx, &node_id)?;
            Ok(true)
        }
    }

    struct TestContext {
        _dir: tempfile::TempDir,
        _backup_dir: tempfile::TempDir,
        schema: Schema<QueryRoot, EmptyMutation, EmptySubscription>,
    }

    impl TestContext {
        fn new(username: &str, customer_ids: Option<Vec<u32>>) -> Self {
            let db_dir = tempfile::tempdir().expect("create data dir");
            let backup_dir = tempfile::tempdir().expect("create backup dir");
            let store = Store::new(db_dir.path(), backup_dir.path()).expect("create store");
            let account = types::Account::new(
                username,
                "password",
                Role::SecurityMonitor,
                "Test User".to_string(),
                "Testing".to_string(),
                None,
                None,
                None,
                None,
                customer_ids,
            )
            .expect("create account");
            store
                .account_map()
                .insert(&account)
                .expect("insert account");
            let schema = Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
                .data(Arc::new(RwLock::new(store)))
                .data(username.to_string())
                .finish();
            Self {
                _dir: db_dir,
                _backup_dir: backup_dir,
                schema,
            }
        }

        async fn execute_load_accessible_node(&self, customer_id: u32) -> async_graphql::Response {
            self.schema
                .execute(format!(
                    "{{ loadAccessibleNode(customerId: {customer_id}) }}"
                ))
                .await
        }

        async fn execute_load_missing_node(&self, node_id: &str) -> async_graphql::Response {
            self.schema
                .execute(format!("{{ loadMissingNode(nodeId: \"{node_id}\") }}"))
                .await
        }
    }

    #[test]
    fn test_can_access_node_profile_draft_allowed() {
        let node = test_node(7);

        assert!(can_access_node(Some(&[7]), &node));
    }

    #[test]
    fn test_can_access_node_profile_draft_forbidden() {
        let node = test_node(7);

        assert!(!can_access_node(Some(&[1]), &node));
    }

    #[test]
    fn test_can_access_node_profile_allowed() {
        let node = review_database::Node {
            id: u32::MAX,
            name: "node-with-profile".to_string(),
            name_draft: Some("node-with-profile".to_string()),
            profile: Some(review_database::NodeProfile {
                customer_id: 7,
                description: String::new(),
                hostname: "host-profile".to_string(),
            }),
            profile_draft: Some(review_database::NodeProfile {
                customer_id: 999,
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
    fn test_can_access_node_profile_forbidden() {
        let node = review_database::Node {
            id: u32::MAX,
            name: "node-with-profile".to_string(),
            name_draft: Some("node-with-profile".to_string()),
            profile: Some(review_database::NodeProfile {
                customer_id: 7,
                description: String::new(),
                hostname: "host-profile".to_string(),
            }),
            profile_draft: Some(review_database::NodeProfile {
                customer_id: 999,
                description: String::new(),
                hostname: "host-draft".to_string(),
            }),
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };

        assert!(!can_access_node(Some(&[1]), &node));
    }

    #[tokio::test]
    async fn test_load_accessible_node_scoped_user_allowed() {
        let test_ctx = TestContext::new("scoped_user", Some(vec![7]));
        let response = test_ctx.execute_load_accessible_node(7).await;

        assert!(
            response.errors.is_empty(),
            "unexpected errors: {:?}",
            response.errors
        );
    }

    #[tokio::test]
    async fn test_load_accessible_node_scoped_user_forbidden() {
        let test_ctx = TestContext::new("scoped_user", Some(vec![1]));
        let response = test_ctx.execute_load_accessible_node(7).await;

        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_load_accessible_node_admin_allowed() {
        let test_ctx = TestContext::new("admin_user", None);
        let response = test_ctx.execute_load_accessible_node(7).await;

        assert!(
            response.errors.is_empty(),
            "unexpected errors: {:?}",
            response.errors
        );
    }

    #[tokio::test]
    async fn test_load_accessible_node_missing_node() {
        let test_ctx = TestContext::new("scoped_user", Some(vec![7]));
        let response = test_ctx.execute_load_missing_node("1").await;

        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].message, "no such node");
    }
}
