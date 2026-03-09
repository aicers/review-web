// Temporary for shared utilities used across sub-issues of #756.
// Remove this allow when the last #756 sub-issue is completed.
#![allow(dead_code)]

use async_graphql::{Context, Result, types::ID};
use review_database::Role;

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

/// Checks whether the user has membership for any provided customer IDs.
///
/// Returns `true` if:
/// - The user is an admin (`users_customers` is `None`), or
/// - Any entry in `customer_ids` exists in the user's customer list.
#[must_use]
pub(crate) fn has_any_membership(users_customers: Option<&[u32]>, customer_ids: &[u32]) -> bool {
    match users_customers {
        None => true, // Admin has access to all customers
        Some(users_customers) => customer_ids.iter().any(|id| users_customers.contains(id)),
    }
}

/// Checks whether the user has membership for all provided customer IDs.
///
/// Returns `true` if:
/// - The user is an admin (`users_customers` is `None`), or
/// - Every entry in `customer_ids` exists in the user's customer list.
#[must_use]
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
/// The function treats system administrators and local auth as unscoped first.
/// Otherwise, it checks an explicit `CustomerIds` in the context (mTLS auth),
/// then falls back to account lookup by username (JWT auth).
///
/// # Errors
///
/// Returns an error if required context data is missing (e.g., username),
/// the store cannot be accessed, account lookup fails, or the user account
/// does not exist.
pub(crate) fn users_customers(ctx: &Context<'_>) -> Result<Option<Vec<u32>>> {
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

    // Check if CustomerIds is explicitly set in context (mTLS path)
    if let Some(cids) = ctx.data_opt::<crate::graphql::CustomerIds>() {
        return Ok(cids.0.clone());
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

/// Checks whether the current user can access the given customer ID.
///
/// Returns `Ok(())` if the current user is unscoped or belongs to the given customer.
///
/// # Errors
///
/// Returns an error if required context data is missing, the customer ID is invalid,
/// or the current user is not allowed to access the customer.
pub(crate) fn check_customer_membership(ctx: &Context<'_>, customer_id: &ID) -> Result<()> {
    let users_customers = users_customers(ctx)?;
    let customer_id = customer_id
        .as_str()
        .parse::<u32>()
        .map_err(|_| "invalid customer ID")?;
    if is_member(users_customers.as_deref(), customer_id) {
        Ok(())
    } else {
        Err("Forbidden".into())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use async_graphql::{
        Context, EmptyMutation, EmptySubscription, Object, Request, Result, Schema,
    };
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
    fn test_has_any_membership_admin() {
        let customer_ids = vec![1, 2, 3];
        assert!(has_any_membership(None, &customer_ids));
    }

    #[test]
    fn test_has_any_membership_with_match() {
        let users_customers = vec![1, 2, 3, 4, 5];
        let customer_ids = vec![2, 3, 4];
        assert!(has_any_membership(Some(&users_customers), &customer_ids));
    }

    #[test]
    fn test_has_any_membership_partial_match() {
        let users_customers = vec![1, 3, 5];
        let customer_ids = vec![2, 3, 4];
        assert!(has_any_membership(Some(&users_customers), &customer_ids));
    }

    #[test]
    fn test_has_any_membership_no_match() {
        let users_customers = vec![10, 20, 30];
        let customer_ids = vec![1, 2, 3];
        assert!(!has_any_membership(Some(&users_customers), &customer_ids));
    }

    #[test]
    fn test_has_any_membership_empty_required() {
        let users_customers = vec![1, 2, 3];
        assert!(!has_any_membership(Some(&users_customers), &[]));
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
        let customer_ids = vec![1, 2];
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

    #[test]
    fn test_has_all_membership_empty_users() {
        let users_customers = Vec::<u32>::new();
        assert!(!has_all_membership(Some(&users_customers), &[1]));
    }

    #[derive(Default)]
    struct QueryRoot;

    #[Object]
    impl QueryRoot {
        async fn users_customers(&self, ctx: &Context<'_>) -> Result<Option<Vec<u32>>> {
            super::users_customers(ctx)
        }

        async fn check_customer_membership(
            &self,
            ctx: &Context<'_>,
            customer_id: ID,
        ) -> Result<bool> {
            super::check_customer_membership(ctx, &customer_id)?;
            Ok(true)
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

        async fn execute_with_guard_and_customer_ids(
            &self,
            query: &str,
            guard: crate::graphql::RoleGuard,
            customer_ids: Option<Vec<u32>>,
        ) -> async_graphql::Response {
            let request = Request::new(query)
                .data(guard)
                .data(crate::graphql::CustomerIds(customer_ids));
            self.schema.execute(request).await
        }

        async fn execute_check_customer_membership(
            &self,
            customer_id: &str,
        ) -> async_graphql::Response {
            self.schema
                .execute(format!(
                    "{{ checkCustomerMembership(customerId: \"{customer_id}\") }}"
                ))
                .await
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
    async fn test_users_customers_system_admin_ignores_customer_ids_context() {
        let test_ctx = TestContext::new_without_account("admin_user");
        let res = test_ctx
            .execute_with_guard_and_customer_ids(
                "{ usersCustomers }",
                crate::graphql::RoleGuard::Role(crate::graphql::Role::SystemAdministrator),
                Some(vec![1, 2, 3]),
            )
            .await;
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
    async fn test_check_customer_membership_scoped_user_allowed() {
        let test_ctx = TestContext::new_with_account("scoped_user", Some(vec![1, 2, 3]));
        let res = test_ctx.execute_check_customer_membership("2").await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
    }

    #[tokio::test]
    async fn test_check_customer_membership_scoped_user_forbidden() {
        let test_ctx = TestContext::new_with_account("scoped_user", Some(vec![1]));
        let res = test_ctx.execute_check_customer_membership("2").await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_check_customer_membership_invalid_customer_id() {
        let test_ctx = TestContext::new_with_account("scoped_user", Some(vec![1]));
        let res = test_ctx.execute_check_customer_membership("abc").await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "invalid customer ID");
    }

    #[tokio::test]
    async fn test_check_customer_membership_admin_allowed() {
        let test_ctx = TestContext::new_with_account("admin_user", None);
        let res = test_ctx.execute_check_customer_membership("999").await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
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
