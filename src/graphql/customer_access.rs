//! Customer-scoping utilities for GraphQL authorization.
//!
//! This module provides helpers to centralize customer-scoping logic:
//! - Administrator semantics: when `customer_ids` is `None`, the user is treated
//!   as an admin with access to all resources.
//! - Membership checks for single customer IDs.
//! - Membership checks for sets of customer IDs.
//! - Context-based lookup of the current user's customer scope.

use async_graphql::{Context, Result};

/// Checks if a user is a member of a specific customer.
///
/// Returns `true` if:
/// - The user is an admin (`users_customers` is `None`), or
/// - The user's `customer_ids` list contains the specified `customer_id`.
///
/// Returns `false` otherwise, including when `users_customers` is an empty slice.
#[must_use]
#[allow(dead_code)] // It will be used in the sub-issues of #756
fn is_member(users_customers: Option<&[u32]>, customer_id: u32) -> bool {
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
#[allow(dead_code)] // It will be used in the sub-issues of #756
fn has_membership(users_customers: Option<&[u32]>, customer_ids: &[u32]) -> bool {
    match users_customers {
        None => true, // Admin has access to all customers
        Some(users_customers) => customer_ids.iter().any(|id| users_customers.contains(id)),
    }
}

/// Retrieves the current user's customer ID list from the GraphQL context.
///
/// Returns `None` for administrators (full access), or `Some(Vec<u32>)` for
/// scoped users.
#[allow(dead_code)] // It will be used in the sub-issues of #756
fn users_customers(ctx: &Context<'_>) -> Result<Option<Vec<u32>>> {
    let store = crate::graphql::get_store(ctx)?;
    let username = ctx.data::<String>()?;
    let account_map = store.account_map();
    let user = account_map
        .get(username)?
        .ok_or_else::<async_graphql::Error, _>(|| "User not found".into())?;
    Ok(user.customer_ids)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
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
