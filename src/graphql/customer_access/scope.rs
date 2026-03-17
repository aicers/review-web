use async_graphql::{Context, Result};
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
#[allow(dead_code)] // Shared helper for upcoming customer-scoping sub-issues of #756.
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
#[allow(dead_code)] // Shared helper for upcoming customer-scoping sub-issues of #756.
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

    users_customers_by_feature(ctx)
}

#[cfg(feature = "auth-jwt")]
fn users_customers_by_feature(ctx: &Context<'_>) -> Result<Option<Vec<u32>>> {
    let username = ctx.data::<String>()?;
    let store = crate::graphql::get_store(ctx)?;
    let account_map = store.account_map();
    let user = account_map
        .get(username)?
        .ok_or_else::<async_graphql::Error, _>(|| "User not found".into())?;
    Ok(user.customer_ids)
}

#[cfg(feature = "auth-mtls")]
fn users_customers_by_feature(ctx: &Context<'_>) -> Result<Option<Vec<u32>>> {
    let customer_ids = ctx.data::<crate::graphql::CustomerIds>()?;
    Ok(customer_ids.0.clone())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use async_graphql::{
        Context, EmptyMutation, EmptySubscription, Object, Request, Result, Schema,
    };
    #[cfg(feature = "auth-jwt")]
    use review_database::Role;
    use review_database::Store;
    #[cfg(feature = "auth-jwt")]
    use review_database::types;
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
    }

    struct TestContext {
        _dir: tempfile::TempDir,
        _backup_dir: tempfile::TempDir,
        schema: Schema<QueryRoot, EmptyMutation, EmptySubscription>,
    }

    impl TestContext {
        #[cfg(feature = "auth-jwt")]
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

        #[cfg(feature = "auth-jwt")]
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

        #[cfg(feature = "auth-jwt")]
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

        #[cfg(feature = "auth-mtls")]
        async fn execute_with_guard(
            &self,
            query: &str,
            guard: crate::graphql::RoleGuard,
        ) -> async_graphql::Response {
            let request = Request::new(query).data(guard);
            self.schema.execute(request).await
        }
    }

    #[cfg(feature = "auth-jwt")]
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

    #[cfg(feature = "auth-jwt")]
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

    #[cfg(feature = "auth-jwt")]
    #[tokio::test]
    async fn test_users_customers_missing_user() {
        let test_ctx = TestContext::new_without_account("missing_user");
        let res = test_ctx.execute("{ usersCustomers }").await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "User not found");
    }

    #[cfg(feature = "auth-jwt")]
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

    #[cfg(feature = "auth-mtls")]
    #[tokio::test]
    async fn test_users_customers_mtls_scoped_user() {
        let test_ctx = TestContext::new_without_account("scoped_user");
        let res = test_ctx
            .execute_with_guard_and_customer_ids(
                "{ usersCustomers }",
                crate::graphql::RoleGuard::Role(crate::graphql::Role::SecurityAdministrator),
                Some(vec![1, 2, 3]),
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({"usersCustomers": [1, 2, 3]})
        );
    }

    #[cfg(feature = "auth-mtls")]
    #[tokio::test]
    async fn test_users_customers_missing_customer_ids_context() {
        let test_ctx = TestContext::new_without_account("scoped_user");
        let res = test_ctx
            .execute_with_guard(
                "{ usersCustomers }",
                crate::graphql::RoleGuard::Role(crate::graphql::Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(
            res.errors[0].message,
            "Data `review_web::graphql::CustomerIds` does not exist."
        );
    }
}
