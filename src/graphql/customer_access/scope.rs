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

/// Retrieves the current user's customer ID list from the GraphQL context.
///
/// Returns `Ok(None)` for administrators (full access), or `Ok(Some(Vec<u32>))` for
/// scoped users.
///
/// A system administrator's `RoleGuard` is treated as unscoped. Otherwise, the
/// function returns the `CustomerIds` the request carries.
///
/// # Errors
///
/// Returns an error if the request carries no `CustomerIds` and its role is not
/// system administrator.
pub(crate) fn users_customers(ctx: &Context<'_>) -> Result<Option<Vec<u32>>> {
    // System administrators are always unscoped. This also keeps test schemas
    // (which may not populate `CustomerIds`) aligned with production behavior
    // where system admins have full access.
    if ctx.data_opt::<crate::graphql::RoleGuard>()
        == Some(&crate::graphql::RoleGuard::Role(Role::SystemAdministrator))
    {
        return Ok(None);
    }

    let customer_ids = ctx.data::<crate::graphql::CustomerIds>()?;
    Ok(customer_ids.0.clone())
}

/// Returns whether the request is made by a System Administrator.
///
/// A System Administrator is unscoped (see [`users_customers`]) and is the
/// only role some decisions are reserved for, such as a cross-customer clone
/// or an address override.
#[must_use]
pub(crate) fn is_system_admin(ctx: &Context<'_>) -> bool {
    ctx.data_opt::<crate::graphql::RoleGuard>()
        == Some(&crate::graphql::RoleGuard::Role(Role::SystemAdministrator))
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
    use review_database::Store;
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
        fn new_without_account(username: &str) -> Self {
            let db_dir = tempfile::tempdir().expect("create data dir");
            let backup_dir = tempfile::tempdir().expect("create backup dir");
            let store = Store::new(db_dir.path(), backup_dir.path(), None).expect("create store");
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

        async fn execute_with_guard(
            &self,
            query: &str,
            guard: crate::graphql::RoleGuard,
        ) -> async_graphql::Response {
            let request = Request::new(query).data(guard);
            self.schema.execute(request).await
        }
    }

    #[tokio::test]
    async fn test_users_customers_scoped_user() {
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

    #[tokio::test]
    async fn test_users_customers_admin_user() {
        let test_ctx = TestContext::new_without_account("admin_user");
        let res = test_ctx
            .execute_with_guard_and_customer_ids(
                "{ usersCustomers }",
                crate::graphql::RoleGuard::Role(crate::graphql::Role::SystemAdministrator),
                None,
            )
            .await;
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

    #[tokio::test]
    async fn test_check_customer_membership_scoped_user_allowed() {
        let test_ctx = TestContext::new_without_account("scoped_user");
        let request = Request::new(r#"{ checkCustomerMembership(customerId: "2") }"#)
            .data(crate::graphql::RoleGuard::Role(
                crate::graphql::Role::SecurityMonitor,
            ))
            .data(crate::graphql::CustomerIds(Some(vec![1, 2, 3])));
        let res = test_ctx.schema.execute(request).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
    }

    #[tokio::test]
    async fn test_check_customer_membership_scoped_user_forbidden() {
        let test_ctx = TestContext::new_without_account("scoped_user");
        let request = Request::new(r#"{ checkCustomerMembership(customerId: "2") }"#)
            .data(crate::graphql::RoleGuard::Role(
                crate::graphql::Role::SecurityMonitor,
            ))
            .data(crate::graphql::CustomerIds(Some(vec![1])));
        let res = test_ctx.schema.execute(request).await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_check_customer_membership_invalid_customer_id() {
        let test_ctx = TestContext::new_without_account("scoped_user");
        let request = Request::new(r#"{ checkCustomerMembership(customerId: "abc") }"#)
            .data(crate::graphql::RoleGuard::Role(
                crate::graphql::Role::SecurityMonitor,
            ))
            .data(crate::graphql::CustomerIds(Some(vec![1])));
        let res = test_ctx.schema.execute(request).await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "invalid customer ID");
    }

    #[tokio::test]
    async fn test_check_customer_membership_admin_allowed() {
        let test_ctx = TestContext::new_without_account("admin_user");
        let request = Request::new(r#"{ checkCustomerMembership(customerId: "999") }"#).data(
            crate::graphql::RoleGuard::Role(crate::graphql::Role::SystemAdministrator),
        );
        let res = test_ctx.schema.execute(request).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
    }
}
