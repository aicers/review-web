use std::collections::HashMap;

use async_graphql::{Context, Result};
use review_database::{Store, event::Direction};

use super::{is_member, users_customers};

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

/// Checks whether the requester can access a node identified by hostname.
///
/// Returns `Ok(())` if:
/// - The requester is an admin (`users_customers` is `None`), or
/// - A node with the given hostname exists and its customer is in the requester's scope.
///
/// # Errors
///
/// Returns an error if:
/// - Context data is missing.
/// - Node iteration fails.
/// - The requester is not allowed to access the hostname.
pub(crate) fn check_hostname_access(ctx: &Context<'_>, hostname: &str) -> Result<()> {
    let users_customers = users_customers(ctx)?;
    let Some(users_customers) = users_customers.as_deref() else {
        return Ok(());
    };

    let store = crate::graphql::get_store(ctx)?;
    let customer_id = derive_customer_id_from_hostname(&store, hostname)?;
    if customer_id.is_some_and(|customer_id| is_member(Some(users_customers), customer_id)) {
        Ok(())
    } else {
        Err("Forbidden".into())
    }
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

    use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Result, Schema};
    use chrono::Utc;
    use review_database::{Role, Store, types};

    use super::*;

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

    #[derive(Default)]
    struct QueryRoot;

    #[Object]
    impl QueryRoot {
        async fn check_hostname_access(&self, ctx: &Context<'_>, hostname: String) -> Result<bool> {
            super::check_hostname_access(ctx, &hostname)?;
            Ok(true)
        }
    }

    struct TestContext {
        _dir: tempfile::TempDir,
        _backup_dir: tempfile::TempDir,
        schema: Schema<QueryRoot, EmptyMutation, EmptySubscription>,
    }

    impl TestContext {
        fn new(username: &str, customer_ids: Option<Vec<u32>>, nodes: &[(&str, u32)]) -> Self {
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

            let node_map = store.node_map();
            for (hostname, customer_id) in nodes {
                let node = review_database::Node {
                    id: u32::MAX,
                    name: (*hostname).to_string(),
                    name_draft: Some((*hostname).to_string()),
                    profile: Some(review_database::NodeProfile {
                        customer_id: *customer_id,
                        description: String::new(),
                        hostname: (*hostname).to_string(),
                    }),
                    profile_draft: None,
                    agents: vec![],
                    external_services: vec![],
                    creation_time: Utc::now(),
                };
                node_map.put(&node).expect("insert node");
            }

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

        async fn execute_check_hostname_access(&self, hostname: &str) -> async_graphql::Response {
            self.schema
                .execute(format!(
                    "{{ checkHostnameAccess(hostname: \"{hostname}\") }}"
                ))
                .await
        }
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
        // The database enforces hostname uniqueness.
        assert!(map.put(&node2).is_err());
    }

    #[tokio::test]
    async fn test_check_hostname_access_scoped_user_allowed() {
        let test_ctx = TestContext::new("scoped_user", Some(vec![42]), &[("host-a", 42)]);

        let response = test_ctx.execute_check_hostname_access("host-a").await;

        assert!(
            response.errors.is_empty(),
            "unexpected errors: {:?}",
            response.errors
        );
    }

    #[tokio::test]
    async fn test_check_hostname_access_scoped_user_forbidden() {
        let test_ctx = TestContext::new("scoped_user", Some(vec![7]), &[("host-a", 42)]);

        let response = test_ctx.execute_check_hostname_access("host-a").await;

        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_check_hostname_access_unknown_hostname_forbidden() {
        let test_ctx = TestContext::new("scoped_user", Some(vec![42]), &[("host-a", 42)]);

        let response = test_ctx.execute_check_hostname_access("host-missing").await;

        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_check_hostname_access_admin_bypasses_lookup() {
        let test_ctx = TestContext::new("admin_user", None, &[]);

        let response = test_ctx.execute_check_hostname_access("host-missing").await;

        assert!(
            response.errors.is_empty(),
            "unexpected errors: {:?}",
            response.errors
        );
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
