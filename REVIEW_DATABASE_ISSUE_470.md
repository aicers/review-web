# Issue: Add Method to Reset `last_signin_time` in Account Struct

## Background

This issue is required to implement the feature described in [aicers/review-web#470](https://github.com/aicers/review-web/issues/470): "Force Password Change After Admin Reset".

## Problem

The `review-web` application needs to force users to change their password after an administrator resets it. The current mechanism for forcing password changes relies on checking if `last_signin_time` is `None`:

```rust
fn validate_last_signin_time(account: &types::Account, username: &str) -> Result<()> {
    if account.last_signin_time().is_none() {
        info!("Password change is required to proceed for {username}");
        return Err("a password change is required to proceed".into());
    }
    Ok(())
}
```

When `last_signin_time` is `None`, the user is directed to use the `signInWithNewPassword` mutation instead of the regular `signIn` mutation.

## Current API Limitation

The `review_database::types::Account` struct currently provides only two methods for `last_signin_time`:

1. **`last_signin_time()`** - Returns `Option<DateTime<Utc>>` (getter)
2. **`update_last_signin_time()`** - Sets `last_signin_time` to `Some(Utc::now())`

The `last_signin_time` field itself is `pub(crate)`, preventing direct access from outside the crate.

**There is no way to reset `last_signin_time` to `None`** from the `review-web` crate.

## Required Change

Add a new public method to the `Account` struct in `review-database` that resets `last_signin_time` to `None`:

```rust
impl Account {
    /// Resets the last signin time to `None`.
    ///
    /// This is typically used when an administrator resets a user's password,
    /// forcing the user to change their password upon next sign-in.
    pub fn reset_last_signin_time(&mut self) {
        self.last_signin_time = None;
    }
}
```

## Use Cases

This method will be used in `review-web` in two scenarios:

### 1. `resetAdminPassword` Mutation

When a system administrator's password is reset via the `resetAdminPassword` mutation (accessed locally only):

```rust
async fn reset_admin_password(
    &self,
    ctx: &Context<'_>,
    username: String,
    password: String,
) -> Result<String> {
    let normalized_username = username.to_lowercase();
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.account_map();

    if let Some(mut account) = map.get(&normalized_username)? {
        if account.role == review_database::Role::SystemAdministrator {
            // Update password
            map.update(normalized_username.as_bytes(), &Some(password), ...)?;

            // Reset last_signin_time to force password change
            account.reset_last_signin_time();  // ← NEW METHOD NEEDED
            map.put(&account)?;

            return Ok(normalized_username);
        }
    }
    Err("reset failed".into())
}
```

### 2. `updateAccount` Mutation

When a system administrator changes another user's password via the `updateAccount` mutation:

```rust
async fn update_account(
    &self,
    ctx: &Context<'_>,
    username: String,
    password: Option<String>,
    // ... other fields
) -> Result<String> {
    let normalized_username = username.to_lowercase();
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.account_map();

    // Update account fields
    map.update(normalized_username.as_bytes(), &password, ...)?;

    // If password was changed, reset last_signin_time
    if password.is_some() {
        if let Some(mut account) = map.get(&normalized_username)? {
            account.reset_last_signin_time();  // ← NEW METHOD NEEDED
            map.put(&account)?;
        }
    }

    Ok(normalized_username)
}
```

## Benefits

1. **Security**: Ensures users must change administrator-reset passwords
2. **Consistency**: Maintains the existing password-change-forcing mechanism
3. **API Completeness**: Provides setter methods for both states (`Some(now)` via `update_last_signin_time()` and `None` via `reset_last_signin_time()`)
4. **Clear Intent**: The method name explicitly documents its purpose

## Alternative Considered

We considered making `last_signin_time` a `pub` field instead of `pub(crate)`, but:
- This would expose internal implementation details
- It would allow arbitrary timestamp manipulation
- The method-based approach is more encapsulated and safer

## Priority

This is a **blocking issue** for implementing the forced password change feature in `review-web`. The feature cannot be completed without this change to `review-database`.

## Related Issues

- aicers/review-web#470 - Force Password Change After Admin Reset (blocked by this issue)
