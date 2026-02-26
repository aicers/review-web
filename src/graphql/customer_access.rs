//! Customer-scoping utilities for GraphQL authorization.
//!
//! This module provides helpers to centralize customer-scoping logic:
//! - Administrator semantics: when `customer_ids` is `None`, the user is treated
//!   as an admin with access to all resources.
//! - Membership checks for single customer IDs.
//! - Membership checks for sets of customer IDs.
//! - Context-based lookup of the current user's customer scope.

use async_graphql::{Context, Result};
use review_database::{Role, Store, event::Direction};

/// Checks if a user is a member of a specific customer.
///
/// Returns `true` if:
/// - The user is an admin (`users_customers` is `None`), or
/// - The user's `customer_ids` list contains the specified `customer_id`.
///
/// Returns `false` otherwise, including when `users_customers` is an empty slice.
#[must_use]
pub(crate) fn is_member(users_customers: Option<&[u32]>, customer_id: u32) -> bool {
    match users_customers {
        None => true, // Admin has access to all customers
        Some(users_customers) => users_customers.contains(&customer_id),
    }
}

/// Checks whether the user has membership for the provided customer IDs.
///
/// Returns `true` if:
/// - The user is an admin (`users_customers` is `None`), or
/// - Any `customer_ids` entry exists in the user's customer list.
#[must_use]
#[allow(dead_code)] // Will be used by other sub-issues of #756
pub(crate) fn has_membership(users_customers: Option<&[u32]>, customer_ids: &[u32]) -> bool {
    match users_customers {
        None => true, // Admin has access to all customers
        Some(users_customers) => customer_ids.iter().any(|id| users_customers.contains(id)),
    }
}

/// Retrieves the current user's customer ID list from the GraphQL context.
///
/// Returns `Ok(None)` for administrators (full access), or `Ok(Some(Vec<u32>))` for
/// scoped users.
///
/// The function first checks for an explicit `CustomerIds` in the context
/// (set by mTLS auth). If not present, it looks up the user's account by
/// username to determine their customer scope.
///
/// # Errors
///
/// Returns an error if required context data is missing (e.g., username),
/// the store cannot be accessed, account lookup fails, or the user account
/// does not exist.
pub(crate) fn users_customers(ctx: &Context<'_>) -> Result<Option<Vec<u32>>> {
    // Check if CustomerIds is explicitly set in context (mTLS path)
    if let Some(cids) = ctx.data_opt::<crate::graphql::CustomerIds>() {
        return Ok(cids.0.clone());
    }

    // System administrators (and local auth bypass) are always unscoped.
    // This also keeps test schemas (which may not populate account data) aligned
    // with production behavior where system admins have full access.
    if let Some(guard) = ctx.data_opt::<crate::graphql::RoleGuard>() {
        match guard {
            crate::graphql::RoleGuard::Role(Role::SystemAdministrator)
            | crate::graphql::RoleGuard::Local => {
                return Ok(None);
            }
            crate::graphql::RoleGuard::Role(_) => {}
        }
    }

    // Fall back to account lookup (JWT path)
    let username = ctx.data::<String>()?;
    let store = crate::graphql::get_store(ctx)?;
    let account_map = store.account_map();
    let user = account_map
        .get(username)?
        .ok_or_else::<async_graphql::Error, _>(|| "User not found".into())?;
    Ok(user.customer_ids)
}

/// Derives the customer ID from a node hostname.
///
/// Returns:
/// - `Ok(Some(customer_id))` if a node with matching hostname exists.
/// - `Ok(None)` if no matching node exists.
///
/// # Errors
///
/// Returns an error if node iteration fails.
pub(crate) fn derive_customer_id_from_hostname(
    store: &Store,
    hostname: &str,
) -> Result<Option<u32>> {
    let node_map = store.node_map();
    for entry in node_map.iter(Direction::Forward, None) {
        let node = entry.map_err(|_| "invalid value in database")?;
        if let Some(profile) = node.profile.as_ref()
            && profile.hostname == hostname
        {
            return Ok(Some(profile.customer_id));
        }
    }
    Ok(None)
}

/// Checks whether the requester can access a node identified by hostname.
///
/// Returns `Ok(true)` if:
/// - The requester is an admin (`users_customers` is `None`), or
/// - A node with the given hostname exists and its customer is in the requester's scope.
///
/// Returns `Ok(false)` otherwise.
///
/// # Errors
///
/// Returns an error if context data is missing or node iteration fails.
pub(crate) fn can_access_hostname(ctx: &Context<'_>, hostname: &str) -> Result<bool> {
    let users_customers = users_customers(ctx)?;
    let Some(users_customers) = users_customers.as_deref() else {
        // Admin is unscoped.
        return Ok(true);
    };

    let store = crate::graphql::get_store(ctx)?;
    let customer_id = derive_customer_id_from_hostname(&store, hostname)?;
    Ok(customer_id.is_some_and(|customer_id| is_member(Some(users_customers), customer_id)))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
    use chrono::Utc;
    use review_database::{Role, Store, types};
    use serde_json::json;

    use super::*;

    #[test]
    fn test_is_member_admin() {
        assert!(is_member(None, 1));
        assert!(is_member(None, 999));
    }

    #[test]
    fn test_is_member_with_allowed_customers() {
        let users_customers = vec![1, 2, 3];
        assert!(is_member(Some(&users_customers), 1));
        assert!(is_member(Some(&users_customers), 3));
        assert!(!is_member(Some(&users_customers), 4));
    }

    #[test]
    fn test_is_member_empty_customers() {
        let users_customers = Vec::<u32>::new();
        assert!(!is_member(Some(&users_customers), 1));
    }

    #[test]
    fn test_has_membership_admin() {
        let customer_ids = vec![1, 2, 3];
        assert!(has_membership(None, &customer_ids));
    }

    #[test]
    fn test_has_membership_with_match() {
        let users_customers = vec![1, 3, 5];
        let customer_ids = vec![2, 3, 4];
        assert!(has_membership(Some(&users_customers), &customer_ids));
    }

    #[test]
    fn test_has_membership_no_match() {
        let users_customers = vec![10, 20, 30];
        let customer_ids = vec![1, 2, 3];
        assert!(!has_membership(Some(&users_customers), &customer_ids));
    }

    fn create_store_with_node(
        hostname: &str,
        customer_id: u32,
    ) -> (tempfile::TempDir, tempfile::TempDir, Store) {
        let db_dir = tempfile::tempdir().expect("create data dir");
        let backup_dir = tempfile::tempdir().expect("create backup dir");
        let store = Store::new(db_dir.path(), backup_dir.path()).expect("create store");
        let node = review_database::Node {
            id: u32::MAX,
            name: hostname.to_string(),
            name_draft: Some(hostname.to_string()),
            profile: Some(review_database::NodeProfile {
                customer_id,
                description: String::new(),
                hostname: hostname.to_string(),
            }),
            profile_draft: None,
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };
        store.node_map().put(&node).expect("insert node");
        (db_dir, backup_dir, store)
    }

    #[test]
    fn test_derive_customer_id_single_match() {
        let (_dir, _bdir, store) = create_store_with_node("host-a", 42);
        let customer_id = derive_customer_id_from_hostname(&store, "host-a")
            .expect("derive customer id should succeed");
        assert_eq!(customer_id, Some(42));
    }

    #[test]
    fn test_derive_customer_id_no_match() {
        let (_dir, _bdir, store) = create_store_with_node("host-a", 42);
        let customer_id = derive_customer_id_from_hostname(&store, "host-missing")
            .expect("derive customer id should succeed");
        assert_eq!(customer_id, None);
    }

    #[test]
    fn test_derive_customer_id_ignores_profile_draft() {
        let db_dir = tempfile::tempdir().expect("create data dir");
        let backup_dir = tempfile::tempdir().expect("create backup dir");
        let store = Store::new(db_dir.path(), backup_dir.path()).expect("create store");
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
        store.node_map().put(&node).expect("insert node");

        let customer_id = derive_customer_id_from_hostname(&store, "host-draft")
            .expect("derive customer id should succeed");
        assert_eq!(customer_id, None);
    }

    #[derive(Default)]
    struct QueryRoot;

    #[Object]
    impl QueryRoot {
        async fn users_customers(&self, ctx: &Context<'_>) -> Result<Option<Vec<u32>>> {
            super::users_customers(ctx)
        }
    }

    struct TestContext {
        _dir: tempfile::TempDir,
        _backup_dir: tempfile::TempDir,
        schema: Schema<QueryRoot, EmptyMutation, EmptySubscription>,
    }

    impl TestContext {
        fn new_with_account(username: &str, customer_ids: Option<Vec<u32>>) -> Self {
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
            let store = Arc::new(RwLock::new(store));
            let schema = Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
                .data(store)
                .data(username.to_string())
                .finish();
            Self {
                _dir: db_dir,
                _backup_dir: backup_dir,
                schema,
            }
        }

        fn new_without_account(username: &str) -> Self {
            let db_dir = tempfile::tempdir().expect("create data dir");
            let backup_dir = tempfile::tempdir().expect("create backup dir");
            let store = Store::new(db_dir.path(), backup_dir.path()).expect("create store");
            let store = Arc::new(RwLock::new(store));
            let schema = Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
                .data(store)
                .data(username.to_string())
                .finish();
            Self {
                _dir: db_dir,
                _backup_dir: backup_dir,
                schema,
            }
        }

        fn new_without_username() -> Self {
            let db_dir = tempfile::tempdir().expect("create data dir");
            let backup_dir = tempfile::tempdir().expect("create backup dir");
            let store = Store::new(db_dir.path(), backup_dir.path()).expect("create store");
            let store = Arc::new(RwLock::new(store));
            let schema = Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
                .data(store)
                .finish();
            Self {
                _dir: db_dir,
                _backup_dir: backup_dir,
                schema,
            }
        }

        async fn execute(&self, query: &str) -> async_graphql::Response {
            self.schema.execute(query).await
        }
    }

    #[tokio::test]
    async fn test_users_customers_scoped_user() {
        let test_ctx = TestContext::new_with_account("scoped_user", Some(vec![1, 2, 3]));
        let res = test_ctx.execute("{ usersCustomers }").await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({"usersCustomers": [1, 2, 3]})
        );
    }

    #[tokio::test]
    async fn test_users_customers_admin_user() {
        let test_ctx = TestContext::new_with_account("admin_user", None);
        let res = test_ctx.execute("{ usersCustomers }").await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({"usersCustomers": null})
        );
    }

    #[tokio::test]
    async fn test_users_customers_missing_user() {
        let test_ctx = TestContext::new_without_account("missing_user");
        let res = test_ctx.execute("{ usersCustomers }").await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "User not found");
    }

    #[tokio::test]
    async fn test_users_customers_missing_username_context() {
        let test_ctx = TestContext::new_without_username();
        let res = test_ctx.execute("{ usersCustomers }").await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(
            res.errors[0].message,
            "Data `alloc::string::String` does not exist."
        );
    }
}
