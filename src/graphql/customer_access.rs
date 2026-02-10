//! Customer-scoping utilities for GraphQL authorization.
//!
//! This module provides helpers to centralize customer-scoping logic:
//! - Administrator semantics: when `customer_ids` is `None`, the user is treated
//!   as an admin with access to all resources.
//! - Membership checks for single customer IDs.
//! - Membership checks for sets of customer IDs.
//! - Context-based lookup of the current user's customer scope.
//! - Hostname-to-customer derivation via node profile mapping.

use std::collections::HashMap;

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

/// Checks whether the user has membership for all provided customer IDs.
///
/// Returns `true` if:
/// - The user is an admin (`users_customers` is `None`), or
/// - Every entry in `customer_ids` exists in the user's customer list.
#[must_use]
#[allow(dead_code)]
pub(crate) fn has_all_membership(users_customers: Option<&[u32]>, customer_ids: &[u32]) -> bool {
    match users_customers {
        None => true, // Admin has access to all customers
        Some(users_customers) => customer_ids.iter().all(|id| users_customers.contains(id)),
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

/// Derives the customer ID from a sensor hostname by looking up the node
/// whose `profile.hostname` matches.
///
/// The database enforces hostname uniqueness, so at most one node will match.
///
/// Returns:
/// - `Ok(Some(customer_id))` if a node with a matching hostname is found.
/// - `Ok(None)` if no node has a profile with a matching hostname.
///
/// # Errors
///
/// Returns an error if a database iteration error occurs.
pub(crate) fn derive_customer_id_from_hostname(
    store: &Store,
    hostname: &str,
) -> Result<Option<u32>> {
    let map = store.node_map();

    for entry in map.iter(Direction::Forward, None) {
        let node = entry
            .map_err(|e| async_graphql::Error::new(format!("failed to iterate nodes: {e}")))?;
        if let Some(profile) = node.profile.as_ref()
            && profile.hostname == hostname
        {
            return Ok(Some(profile.customer_id));
        }
    }

    Ok(None)
}

/// Builds a hostname-to-customer map from the node profiles.
///
/// The map includes only active profiles (excluding drafts).
///
/// This helper exists primarily for performance: callers that need to
/// resolve many sensors/hostnames (e.g., while iterating triage responses)
/// can build this map once and then do O(1) lookups instead of repeatedly
/// scanning the node map.
///
/// # Errors
///
/// Returns an error if a database iteration error occurs.
pub(crate) fn hostname_customer_id_map(store: &Store) -> Result<HashMap<String, u32>> {
    let map = store.node_map();
    let mut hostname_map = HashMap::<String, u32>::new();

    for entry in map.iter(Direction::Forward, None) {
        let node = entry
            .map_err(|e| async_graphql::Error::new(format!("failed to iterate nodes: {e}")))?;
        if let Some(profile) = node.profile.as_ref() {
            hostname_map.insert(profile.hostname.clone(), profile.customer_id);
        }
    }

    Ok(hostname_map)
}

/// Extracts the sensor hostname from a `TriageResponse` key.
///
/// The key is a composite of `sensor_bytes + 8_byte_timestamp`. This
/// function strips the trailing 8 bytes and interprets the rest as UTF-8.
///
/// # Errors
///
/// Returns an error if the key is too short or contains invalid UTF-8.
pub(crate) fn sensor_from_key(key: &[u8]) -> Result<String> {
    const TIMESTAMP_LEN: usize = 8;
    if key.len() <= TIMESTAMP_LEN {
        return Err("TriageResponse key too short to extract sensor".into());
    }
    std::str::from_utf8(&key[..key.len() - TIMESTAMP_LEN])
        .map(str::to_owned)
        .map_err(|_| "TriageResponse key contains invalid UTF-8 sensor".into())
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
    fn test_has_all_membership_admin() {
        let customer_ids = vec![1, 2, 3];
        assert!(has_all_membership(None, &customer_ids));
    }

    #[test]
    fn test_has_all_membership_with_full_match() {
        let users_customers = vec![1, 2, 3, 4, 5];
        let customer_ids = vec![2, 3, 4];
        assert!(has_all_membership(Some(&users_customers), &customer_ids));
    }

    #[test]
    fn test_has_all_membership_partial_match() {
        let users_customers = vec![1, 3, 5];
        let customer_ids = vec![2, 3, 4];
        assert!(!has_all_membership(Some(&users_customers), &customer_ids));
    }

    #[test]
    fn test_has_all_membership_no_match() {
        let users_customers = vec![10, 20, 30];
        let customer_ids = vec![1, 2, 3];
        assert!(!has_all_membership(Some(&users_customers), &customer_ids));
    }

    #[test]
    fn test_has_all_membership_empty_required() {
        let users_customers = vec![1, 2, 3];
        assert!(has_all_membership(Some(&users_customers), &[]));
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
        let map = store.node_map();
        map.put(&node).expect("insert node");
        (db_dir, backup_dir, store)
    }

    #[test]
    fn test_derive_customer_id_single_match() {
        let (_dir, _bdir, store) = create_store_with_node("host-a", 42);
        let result = derive_customer_id_from_hostname(&store, "host-a");
        assert_eq!(result.unwrap(), Some(42));
    }

    #[test]
    fn test_derive_customer_id_no_match() {
        let (_dir, _bdir, store) = create_store_with_node("host-a", 42);
        let result = derive_customer_id_from_hostname(&store, "host-unknown");
        assert_eq!(result.unwrap(), None);
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

        let result = derive_customer_id_from_hostname(&store, "host-draft").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_hostname_customer_id_map_ignores_profile_draft() {
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

        let hostname_map = hostname_customer_id_map(&store).unwrap();
        assert!(!hostname_map.contains_key("host-draft"));
    }

    #[test]
    fn test_derive_customer_id_duplicate_hostname_rejected_by_db() {
        let db_dir = tempfile::tempdir().expect("create data dir");
        let backup_dir = tempfile::tempdir().expect("create backup dir");
        let store = Store::new(db_dir.path(), backup_dir.path()).expect("create store");
        let node1 = review_database::Node {
            id: u32::MAX,
            name: "node1".to_string(),
            name_draft: Some("node1".to_string()),
            profile: Some(review_database::NodeProfile {
                customer_id: 1,
                description: String::new(),
                hostname: "dup-host".to_string(),
            }),
            profile_draft: None,
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };
        let node2 = review_database::Node {
            id: u32::MAX,
            name: "node2".to_string(),
            name_draft: Some("node2".to_string()),
            profile: Some(review_database::NodeProfile {
                customer_id: 2,
                description: String::new(),
                hostname: "dup-host".to_string(),
            }),
            profile_draft: None,
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };
        let map = store.node_map();
        map.put(&node1).expect("insert node1");
        // The database enforces hostname uniqueness
        assert!(map.put(&node2).is_err());
    }

    #[test]
    fn test_sensor_from_key_valid() {
        // "sensor1" = [115, 101, 110, 115, 111, 114, 49]
        // + 8 bytes timestamp
        let key = b"sensor1\x17\x43\xB8\xA0\x91\x4B\xDD\xB2";
        assert_eq!(sensor_from_key(key).unwrap(), "sensor1".to_string());
    }

    #[test]
    fn test_sensor_from_key_too_short() {
        let key = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        assert!(sensor_from_key(key).is_err());
    }
}
