mod username_validation;

use std::{
    env,
    net::{IpAddr, SocketAddr},
};

use anyhow::anyhow;
use async_graphql::{
    Context, Enum, ID, InputObject, Object, Result, ServerError, SimpleObject,
    connection::{Connection, EmptyFields, OpaqueCursor},
};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use review_database::{
    self as database, Iterable, Store, Table,
    event::Direction,
    types::{self},
};
use serde::Serialize;
use tracing::info;

use self::username_validation::validate_and_normalize_username;
use super::{IpAddress, RoleGuard, cluster::try_id_args_into_ints};
use crate::graphql::query_with_constraints;
use crate::{
    auth::{
        create_aimer_token, create_token, decode_token, insert_token, revoke_token,
        update_jwt_expires_in, validate_token,
    },
    info_with_username,
};

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Serialize, SimpleObject)]
pub struct SignedInAccount {
    username: String,
    expire_times: Vec<DateTime<Utc>>,
    signin_times: Vec<DateTime<Utc>>,
    durations: Vec<i64>,
    name: String,
    department: String,
    role: Role,
    customer_ids: Option<Vec<ID>>,
}

/// GraphQL type for the current user's account information, including expiration times.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, SimpleObject)]
pub struct MyAccount {
    username: String,
    role: Role,
    name: String,
    department: String,
    language: Option<String>,
    theme: Option<String>,
    creation_time: DateTime<Utc>,
    last_signin_time: Option<DateTime<Utc>>,
    allow_access_from: Option<Vec<String>>,
    max_parallel_sessions: Option<u8>,
    customer_ids: Option<Vec<ID>>,
    expire_times: Vec<DateTime<Utc>>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Serialize, SimpleObject)]
pub struct ComprehensiveUserAccount {
    username: String,
    name: String,
    department: String,
    role: Role,
    creation_time: DateTime<Utc>,
    last_signin_time: Option<DateTime<Utc>>,
    is_locked: bool,
    is_suspended: bool,
    max_parallel_sessions: Option<u8>,
    allow_access_from: Option<Vec<String>>,
}

const REVIEW_ADMIN: &str = "REVIEW_ADMIN";
const MAX_FAILED_LOGIN_ATTEMPTS_BEFORE_LOCKOUT: u8 = 5; // Account lockout constants
const ACCOUNT_LOCKOUT_DURATION: chrono::Duration = chrono::Duration::minutes(30);
const AIMER_TOKEN_ERROR_MESSAGE: &str = "Failed to issue aimer token";

#[derive(Default)]
pub(super) struct AccountQuery;

#[Object]
impl AccountQuery {
    /// Looks up an account by the given username.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn account(&self, ctx: &Context<'_>, username: String) -> Result<Account> {
        // Normalize the username for lookup (convert to lowercase)
        let normalized_username = username.to_lowercase();

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        let inner = map
            .get(&normalized_username)?
            .ok_or_else::<async_graphql::Error, _>(|| "User not found".into())?;

        Ok(Account { inner })
    }

    /// Retrieves the current user's account information.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn my_account(&self, ctx: &Context<'_>) -> Result<MyAccount> {
        let store = crate::graphql::get_store(ctx).await?;
        let username = ctx.data::<String>()?;
        let account_map = store.account_map();
        let access_token_map = store.access_token_map();

        let inner = account_map
            .get(username)?
            .ok_or_else::<async_graphql::Error, _>(|| "User not found".into())?;

        // Get expire times for the current user's active tokens
        let expire_times = access_token_map
            .tokens(username)
            .filter_map(|e| {
                let e = e.ok()?;
                let decoded_token = decode_token(&e.token).ok()?;
                let exp_time = Utc.timestamp_nanos(decoded_token.exp * 1_000_000_000);
                if Utc::now() < exp_time {
                    Some(exp_time)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(MyAccount {
            username: inner.username.clone(),
            role: inner.role.into(),
            name: inner.name.clone(),
            department: inner.department.clone(),
            language: inner.language.clone(),
            theme: inner.theme.clone(),
            creation_time: inner.creation_time(),
            last_signin_time: inner.last_signin_time(),
            allow_access_from: inner
                .allow_access_from
                .as_ref()
                .map(|ips| ips.iter().map(ToString::to_string).collect::<Vec<String>>()),
            max_parallel_sessions: inner.max_parallel_sessions,
            customer_ids: inner
                .customer_ids
                .as_ref()
                .map(|ids| ids.iter().map(|id| ID(id.to_string())).collect()),
            expire_times,
        })
    }

    /// A list of accounts.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn account_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Account, AccountTotalCount, EmptyFields>> {
        info_with_username!(ctx, "Account list requested");
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// Returns the list of accounts who have signed in.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn signed_in_account_list(&self, ctx: &Context<'_>) -> Result<Vec<SignedInAccount>> {
        use std::collections::HashMap;

        use review_database::Iterable;

        let store = crate::graphql::get_store(ctx).await?;
        let access_token_map = store.access_token_map();
        let account_map = store.account_map();

        // Get the current expiration time for calculating session durations
        let jwt_expires_in = expiration_time(&store)? as i64;

        let signed = access_token_map
            .iter(Direction::Forward, None)
            .filter_map(|e| {
                let e = e.ok()?;
                let username = e.username;
                let decoded_token = decode_token(&e.token).ok()?;
                let exp_time = Utc.timestamp_nanos(decoded_token.exp * 1_000_000_000);
                if Utc::now() < exp_time {
                    // Calculate sign-in time from expiration time
                    let signin_time = exp_time - chrono::Duration::seconds(jwt_expires_in);
                    // Calculate session duration in seconds
                    let duration = (Utc::now() - signin_time).num_seconds();
                    Some((username, exp_time, signin_time, duration))
                } else {
                    None
                }
            })
            .fold(
                HashMap::new(),
                |mut res: HashMap<_, (Vec<_>, Vec<_>, Vec<_>)>,
                 (username, exp_time, signin_time, duration)| {
                    let (expire_times, signin_times, durations) = res.entry(username).or_default();
                    expire_times.push(exp_time);
                    signin_times.push(signin_time);
                    durations.push(duration);
                    res
                },
            )
            .into_iter()
            .filter_map(|(username, (expire_times, signin_times, durations))| {
                // Get account details for additional fields
                let account = account_map.get(&username).ok()??;
                Some(SignedInAccount {
                    username,
                    expire_times,
                    signin_times,
                    durations,
                    name: account.name.clone(),
                    department: account.department.clone(),
                    role: account.role.into(),
                    customer_ids: account
                        .customer_ids
                        .as_ref()
                        .map(|ids| ids.iter().map(|id| ID(id.to_string())).collect()),
                })
            })
            .collect::<Vec<_>>();

        info_with_username!(ctx, "Account connection status retrieved");
        Ok(signed)
    }

    /// Returns a comprehensive list of all user accounts with security status.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)")]
    async fn comprehensive_user_list(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Vec<ComprehensiveUserAccount>> {
        use review_database::Iterable;

        let store = crate::graphql::get_store(ctx).await?;
        let account_map = store.account_map();

        let users = account_map
            .iter(Direction::Forward, None)
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let account = entry;

                Some(ComprehensiveUserAccount {
                    username: account.username.clone(),
                    name: account.name.clone(),
                    department: account.department.clone(),
                    role: account.role.into(),
                    creation_time: account.creation_time(),
                    last_signin_time: account.last_signin_time(),
                    is_locked: false,
                    is_suspended: false,
                    max_parallel_sessions: account.max_parallel_sessions,
                    allow_access_from: account
                        .allow_access_from
                        .as_ref()
                        .map(|ips| ips.iter().map(ToString::to_string).collect()),
                })
            })
            .collect();

        Ok(users)
    }

    /// Returns how long signing in lasts in seconds
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn expiration_time(&self, ctx: &Context<'_>) -> Result<i64> {
        let store = crate::graphql::get_store(ctx).await?;

        info_with_username!(ctx, "Account session expiration settings retrieved");
        expiration_time(&store)
    }
}

#[derive(Default)]
pub(super) struct AccountMutation;

#[Object]
impl AccountMutation {
    /// Creates a new account
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)")]
    async fn insert_account(
        &self,
        ctx: &Context<'_>,
        username: String,
        password: String,
        role: Role,
        name: String,
        department: String,
        language: Option<String>,
        theme: Option<String>,
        allow_access_from: Option<Vec<IpAddress>>,
        max_parallel_sessions: Option<u8>,
        customer_ids: Option<Vec<ID>>,
    ) -> Result<String> {
        // Validate and normalize the username
        let normalized_username = validate_and_normalize_username(&username)
            .map_err(|e| format!("Invalid username: {e}"))?;

        let customer_ids = try_id_args_into_ints::<u32>(customer_ids)?;
        let store = crate::graphql::get_store(ctx).await?;
        let table = store.account_map();
        if table.contains(&normalized_username)? {
            info_with_username!(ctx, "Account creation skipped: username already exists");
            return Err("account already exists".into());
        }
        if customer_ids.is_none() && role != Role::SystemAdministrator {
            return Err("You are not allowed to access all customers.".into());
        }
        let allow_access_from = if let Some(ip_addrs) = allow_access_from {
            let ip_addrs = to_ip_addr(&ip_addrs);
            Some(ip_addrs)
        } else {
            None
        };
        let account = types::Account::new(
            &normalized_username,
            &password,
            database::Role::from(role),
            name,
            department,
            language,
            theme,
            allow_access_from,
            max_parallel_sessions,
            customer_ids,
        )?;
        table.put(&account)?;
        info_with_username!(ctx, "Created a new user {normalized_username}");
        Ok(normalized_username)
    }

    /// Resets system admin `password` for `username`.
    ///
    /// # Errors
    ///
    /// Returns an error if `username` is invalid,
    /// or if the `account.role != Role::SystemAdministrator`.
    #[graphql(guard = "RoleGuard::Local")]
    async fn reset_admin_password(
        &self,
        ctx: &Context<'_>,
        username: String,
        password: String,
    ) -> Result<String> {
        // Normalize the username for lookup (convert to lowercase)
        let normalized_username = username.to_lowercase();

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        if let Some(account) = map.get(&normalized_username)? {
            if account.role == review_database::Role::SystemAdministrator {
                // Validate that the new password is different from the current password
                if account.verify_password(&password) {
                    return Err("new password cannot be the same as the current password".into());
                }

                map.update(
                    normalized_username.as_bytes(),
                    &Some(password),
                    None,
                    &None,
                    &None,
                    &None,
                    &None,
                    &None,
                    &None,
                    &None,
                )?;
                info_with_username!(
                    ctx,
                    "System administrator {normalized_username}'s password has been changed"
                );
                return Ok(normalized_username);
            }
            return Err(
                format!("reset failed due to invalid access for {normalized_username}").into(),
            );
        }

        Err("reset failed due to invalid username".into())
    }

    /// Removes accounts using normalized usernames, returning the usernames that no longer exist.
    /// This is the main API for account removal that handles usernames according to current
    /// username validation rules.
    ///
    /// On error, some usernames may have been removed.
    ///
    /// # Errors
    ///
    /// Returns an error if a user attempts to delete themselves.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)")]
    async fn remove_accounts(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] usernames: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        let current_username = ctx.data::<String>()?;

        // Normalize usernames for lookup and validate them
        let mut normalized_usernames = Vec::with_capacity(usernames.len());
        for username in usernames {
            // Normalize the username using the same validation as account creation
            let normalized_username =
                self::username_validation::validate_and_normalize_username(&username)
                    .map_err(|e| format!("Invalid username '{username}': {e}"))?;
            normalized_usernames.push(normalized_username);
        }

        // Check if the current user is trying to delete themselves
        if normalized_usernames.contains(&current_username.to_lowercase()) {
            info_with_username!(
                ctx,
                "Account deletion skipped: users cannot delete themselves"
            );
            return Err("Users cannot delete themselves".into());
        }

        // Proceed with deletion if validation passes
        let mut removed = Vec::with_capacity(normalized_usernames.len());
        for username in normalized_usernames {
            map.delete(&username)?;
            removed.push(username);
        }
        Ok(removed)
    }

    /// Removes accounts using exact usernames without normalization, returning the usernames that no longer exist.
    /// This is a secondary API for backward compatibility with accounts created before strict validation.
    ///
    /// On error, some usernames may have been removed.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)")]
    async fn remove_accounts_exact(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] usernames: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        let mut removed = Vec::with_capacity(usernames.len());
        for username in usernames {
            // Use exact username without normalization for legacy accounts
            map.delete(&username)?;
            info_with_username!(ctx, "Deleted user {username}");
            removed.push(username);
        }
        Ok(removed)
    }

    /// Updates an existing account.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)")]
    async fn update_account(
        &self,
        ctx: &Context<'_>,
        username: String,
        password: Option<String>,
        role: Option<UpdateRole>,
        name: Option<UpdateName>,
        department: Option<UpdateDepartment>,
        language: Option<UpdateLanguage>,
        theme: Option<UpdateTheme>,
        allow_access_from: Option<UpdateAllowAccessFrom>,
        max_parallel_sessions: Option<UpdateMaxParallelSessions>,
        customer_ids: Option<UpdateCustomerIds>,
    ) -> Result<String> {
        if password.is_none()
            && role.is_none()
            && name.is_none()
            && department.is_none()
            && language.is_none()
            && allow_access_from.is_none()
            && max_parallel_sessions.is_none()
            && customer_ids.is_none()
        {
            return Err("At lease one of the optional fields must be provided to update.".into());
        }

        // Disallow update to SystemAdministrator
        if role.as_ref().is_some_and(|role| {
            (role.old == Role::SystemAdministrator) ^ (role.new == Role::SystemAdministrator)
        }) {
            return Err("Role not allowed.".into());
        }

        let customer_ids = customer_ids
            .map(|ids| {
                let old = try_id_args_into_ints::<u32>(ids.old)?;
                let new = try_id_args_into_ints::<u32>(ids.new)?;
                Ok::<_, async_graphql::Error>((old, new))
            })
            .transpose()?;
        // Normalize the username for lookup (convert to lowercase)
        let normalized_username = username.to_lowercase();

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();

        // Validate password change if provided
        if let Some(ref new_password) = password {
            let Ok(Some(account)) = map.get(&username) else {
                return Err("invalid username".into());
            };

            // Validate that the new password is different from the current password
            if account.verify_password(new_password) {
                return Err("new password cannot be the same as the current password".into());
            }
            info_with_username!(ctx, "Password change requested");
        }

        // Ensure that the `customer_ids` is set correctly for the account role
        if role.is_some() || customer_ids.is_some() {
            let Ok(Some(account)) = map.get(&normalized_username) else {
                return Err("invalid username".into());
            };
            let role_to_check = role.as_ref().map_or(account.role, |update_role| {
                database::Role::from(update_role.new)
            });
            let customer_ids_to_check = customer_ids
                .as_ref()
                .map_or(&account.customer_ids, |update_customer_ids| {
                    &update_customer_ids.1
                });

            if customer_ids_to_check.is_none()
                && role_to_check != database::Role::SystemAdministrator
            {
                return Err("You are not allowed to access all customers.".into());
            }
        }

        let password_new = password;
        let role = role.map(|r| (database::Role::from(r.old), database::Role::from(r.new)));
        let name = name.map(|n| (n.old, n.new));
        let dept = department.map(|d| (d.old, d.new));
        let language = language.map(|d| (d.old, d.new));
        let theme = theme.map(|d| (d.old, d.new));
        let allow_access_from = if let Some(ip_addrs) = allow_access_from {
            let old = ip_addrs.old.map(|old| to_ip_addr(&old));
            let new = ip_addrs.new.map(|new| to_ip_addr(&new));
            Some((old, new))
        } else {
            None
        };
        let max_parallel_sessions = max_parallel_sessions.map(|m| (m.old, m.new));

        map.update(
            normalized_username.as_bytes(),
            &password_new,
            role,
            &name,
            &dept,
            &language,
            &theme,
            &allow_access_from,
            &max_parallel_sessions,
            &customer_ids,
        )?;
        info_with_username!(
            ctx,
            "Updated profile information for user {normalized_username}"
        );
        Ok(normalized_username)
    }

    /// Authenticates with the given username and password.
    ///
    /// If the `lastSigninTime` value of the `account` is `None`, the operation will fail, and
    /// it should be guided to call `signInWithNewPassword` GraphQL API.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the password is invalid, this is the first sign-in attempt, the access
    /// doesn't originate from a permitted IP address, or the number of sessions exceeds the
    /// maximum limit.
    async fn sign_in(
        &self,
        ctx: &Context<'_>,
        username: String,
        password: String,
    ) -> Result<AuthPayload> {
        // Normalize the username for lookup (convert to lowercase)
        let normalized_username = username.to_lowercase();

        let store = crate::graphql::get_store(ctx).await?;
        let account_map = store.account_map();
        let client_ip = get_client_ip(ctx);

        if let Some(mut account) = account_map.get(&normalized_username)? {
            check_account_lockout_status(&mut account, &account_map, &normalized_username)?;
            validate_password(&mut account, &account_map, &normalized_username, &password)?;
            validate_last_signin_time(&account, &normalized_username)?;
            validate_allow_access_from(&account, client_ip, &normalized_username)?;
            validate_max_parallel_sessions(&account, &store, &normalized_username)?;

            sign_in_actions(
                ctx,
                &mut account,
                &store,
                &account_map,
                client_ip,
                &normalized_username,
            )
        } else {
            info!("{normalized_username} is not a valid username");
            Err("incorrect username or password".into())
        }
    }

    /// Authenticates with the given username and password, then updates to the new password.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the password or the new password are invalid, the access
    /// doesn't originate from a permitted IP address, or the number of sessions exceeds the
    /// maximum limit.
    async fn sign_in_with_new_password(
        &self,
        ctx: &Context<'_>,
        username: String,
        password: String,
        new_password: String,
    ) -> Result<AuthPayload> {
        // Normalize the username for lookup (convert to lowercase)
        let normalized_username = username.to_lowercase();

        let store = crate::graphql::get_store(ctx).await?;
        let account_map = store.account_map();
        let client_ip = get_client_ip(ctx);

        if let Some(mut account) = account_map.get(&normalized_username)? {
            check_account_lockout_status(&mut account, &account_map, &normalized_username)?;
            validate_password(&mut account, &account_map, &normalized_username, &password)?;
            validate_allow_access_from(&account, client_ip, &normalized_username)?;
            validate_max_parallel_sessions(&account, &store, &normalized_username)?;
            validate_update_new_password(&password, &new_password, &normalized_username)?;

            account.update_password(&new_password)?;

            sign_in_actions(
                ctx,
                &mut account,
                &store,
                &account_map,
                client_ip,
                &normalized_username,
            )
        } else {
            info!("{normalized_username} is not a valid username");
            Err("incorrect username or password".into())
        }
    }

    /// Revokes the given access token
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn sign_out(&self, ctx: &Context<'_>, token: String) -> Result<String> {
        let store = crate::graphql::get_store(ctx).await?;
        revoke_token(&store, &token)?;
        info_with_username!(ctx, "Signed out");
        Ok(token)
    }

    /// Forcefully terminates all sessions for a specific user. Only system administrators
    /// and security administrators can perform this operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the username is invalid or if the operation fails.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn force_sign_out(
        &self,
        ctx: &Context<'_>,
        username: String,
    ) -> Result<ForceSignOutResult> {
        // Normalize the username for lookup (convert to lowercase)
        let normalized_username = username.to_lowercase();

        let store = crate::graphql::get_store(ctx).await?;
        let account_map = store.account_map();

        // Verify the target user exists
        if !account_map.contains(&normalized_username)? {
            info_with_username!(
                ctx,
                "Force sign-out skipped: user '{normalized_username}' not found"
            );
            return Err(format!("User '{normalized_username}' not found").into());
        }

        let access_token_map = store.access_token_map();
        let mut revoked_sessions = Vec::new();
        let mut failed_revocations = Vec::new();

        // Find all active sessions for the user
        let user_sessions: Vec<_> = access_token_map
            .iter(Direction::Forward, Some(normalized_username.as_bytes()))
            .filter_map(|res| {
                if let Ok(access_token) = res
                    && access_token.username == normalized_username
                {
                    // Verify the token hasn't expired
                    if let Ok(decoded_token) = decode_token(&access_token.token) {
                        let exp_time = Utc.timestamp_nanos(decoded_token.exp * 1_000_000_000);
                        if Utc::now() < exp_time {
                            return Some(access_token.token);
                        }
                    }
                }
                None
            })
            .collect();

        // Revoke all active sessions
        for token in user_sessions {
            match revoke_token(&store, &token) {
                Ok(()) => {
                    revoked_sessions.push(token);
                }
                Err(e) => {
                    failed_revocations.push(format!("Failed to revoke token: {e}"));
                }
            }
        }

        if revoked_sessions.is_empty() && failed_revocations.is_empty() {
            info_with_username!(
                ctx,
                "Attempted to forcefully sign out {normalized_username}, but no active sessions found"
            );
        } else {
            info_with_username!(
                ctx,
                "Forcefully signed out {normalized_username} ({} sessions terminated)",
                revoked_sessions.len()
            );
        }

        Ok(ForceSignOutResult {
            username: normalized_username,
            sessions_terminated: i32::try_from(revoked_sessions.len())
                .map_err(|_| "Too many sessions terminated")?,
            errors: if failed_revocations.is_empty() {
                None
            } else {
                Some(failed_revocations)
            },
        })
    }

    /// Obtains a new access token with renewed expiration time. The given
    /// access token will be revoked.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn refresh_token(&self, ctx: &Context<'_>, token: String) -> Result<AuthPayload> {
        let store = crate::graphql::get_store(ctx).await?;
        let decoded_token = decode_token(&token)?;
        let username = decoded_token.sub;
        let (review_token, expiration_time) = create_token(username.clone(), decoded_token.role)?;

        let exp_timestamp = expiration_time.and_utc().timestamp();
        let aimer_token = generate_aimer_token(ctx, exp_timestamp);

        insert_token(&store, &review_token, &username)?;
        let rt = revoke_token(&store, &token);
        if let Err(e) = rt {
            revoke_token(&store, &review_token)?;
            Err(e.into())
        } else {
            info_with_username!(ctx, "Login session extended");
            Ok(AuthPayload {
                review_token,
                aimer_token,
                expiration_time,
            })
        }
    }

    /// Issues a new Aimer token for an existing session represented by a review token.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided review token is invalid or if an Aimer token cannot be generated.
    async fn issue_aimer_token(
        &self,
        ctx: &Context<'_>,
        review_token: String,
    ) -> Result<AimerTokenPayload> {
        let store = crate::graphql::get_store(ctx).await?;
        validate_token(&store, &review_token)
            .map_err(|err| async_graphql::Error::new(err.to_string()))?;

        let claims = decode_token(&review_token)?;
        let exp_timestamp = claims.exp;
        let expiration_time = DateTime::<Utc>::from_timestamp(exp_timestamp, 0)
            .ok_or_else(|| async_graphql::Error::new("invalid expiration timestamp"))?
            .naive_utc();

        let aimer_token = create_aimer_token(exp_timestamp).map_err(|err| {
            tracing::error!(error = %err, "Failed to create aimer_token");
            async_graphql::Error::new(format!("{AIMER_TOKEN_ERROR_MESSAGE}: {err}"))
        })?;

        Ok(AimerTokenPayload {
            aimer_token,
            expiration_time,
        })
    }

    /// Updates the expiration time for signing in, specifying the duration in
    /// seconds. The `time` parameter specifies the new expiration time in
    /// seconds and must be a positive integer.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn update_expiration_time(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(minimum = 1))] time: i32,
    ) -> Result<i32> {
        let Ok(expires_in) = u32::try_from(time) else {
            unreachable!("`time` is a positive integer")
        };
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_policy_map();
        map.update_expiry_period(expires_in)?;
        info_with_username!(
            ctx,
            "Account session expiration settings have been modified"
        );

        update_jwt_expires_in(expires_in)?;
        Ok(time)
    }

    /// Updates only the user's language setting.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn update_language(
        &self,
        ctx: &Context<'_>,
        language: UpdateLanguage,
    ) -> Result<Option<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();

        let username = ctx.data::<String>()?;
        let new_language = language.new.clone();

        map.update(
            username.as_bytes(),
            &None,
            None,
            &None,
            &None,
            &Some((language.old, language.new)),
            &None,
            &None,
            &None,
            &None,
        )?;

        Ok(new_language)
    }

    /// Updates only the user's screen color theme selection.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
   .or(RoleGuard::new(super::Role::SecurityAdministrator))
   .or(RoleGuard::new(super::Role::SecurityManager))
   .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn update_theme(&self, ctx: &Context<'_>, theme: UpdateTheme) -> Result<Option<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();

        let username = ctx.data::<String>()?;
        let new_theme = theme.new.clone();

        map.update(
            username.as_bytes(),
            &None,
            None,
            &None,
            &None,
            &None,
            &Some((theme.old, theme.new)),
            &None,
            &None,
            &None,
        )?;

        Ok(new_theme)
    }

    /// Updates the current user's own account information.
    #[allow(clippy::too_many_arguments)]
    async fn update_my_account(
        &self,
        ctx: &Context<'_>,
        password: Option<UpdatePassword>,
        name: Option<UpdateName>,
        department: Option<UpdateDepartment>,
        language: Option<UpdateLanguage>,
        theme: Option<UpdateTheme>,
    ) -> Result<String> {
        if password.is_none()
            && name.is_none()
            && department.is_none()
            && language.is_none()
            && theme.is_none()
        {
            return Err("At least one of the optional fields must be provided to update.".into());
        }

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        let username = ctx.data::<String>()?;

        // Validate password change if provided
        if let Some(ref password_update) = password {
            let Ok(Some(account)) = map.get(username) else {
                return Err("invalid username".into());
            };

            // Verify the old password is correct
            if !account.verify_password(&password_update.old) {
                return Err("incorrect current password".into());
            }

            // Validate that the new password is different from the old password
            if password_update.old == password_update.new {
                return Err("new password cannot be the same as the current password".into());
            }
        }

        // Validate username exists
        let Ok(Some(_)) = map.get(username) else {
            return Err("invalid username".into());
        };

        let password_new = password.map(|p| p.new);
        let name_update = name.map(|n| (n.old, n.new));
        let dept_update = department.map(|d| (d.old, d.new));
        let language_update = language.map(|l| (l.old, l.new));
        let theme_update = theme.map(|t| (t.old, t.new));

        map.update(
            username.as_bytes(),
            &password_new,
            None,
            &name_update,
            &dept_update,
            &language_update,
            &theme_update,
            &None,
            &None,
            &None,
        )?;
        Ok(username.clone())
    }
}

fn validate_password(
    account: &mut types::Account,
    account_map: &Table<types::Account>,
    username: &str,
    password: &str,
) -> Result<()> {
    if !account.verify_password(password) {
        info!("wrong password for {username}");

        // Increment failed login attempts
        account.failed_login_attempts += 1;

        // Check if we've reached the lockout threshold
        if account.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS_BEFORE_LOCKOUT {
            let lockout_until = Utc::now() + ACCOUNT_LOCKOUT_DURATION;
            account.locked_out_until = Some(lockout_until);

            // Persist changes to database
            account_map.put(account)?;

            info!(
                "{username} has been locked until {lockout_until} due to multiple failed login attempts"
            );
            return Err(format!(
                "{username} has been locked due to multiple failed login attempts. It will remain locked until {lockout_until}"
            ).into());
        }

        // Persist the incremented failed login attempts
        account_map.put(account)?;
        return Err("incorrect username or password".into());
    }

    // Reset failed attempts on successful password validation
    account.failed_login_attempts = 0;
    account_map.put(account)?;
    Ok(())
}

fn validate_last_signin_time(account: &types::Account, username: &str) -> Result<()> {
    if account.last_signin_time().is_none() {
        info!("Password change is required to proceed for {username}");
        return Err("a password change is required to proceed".into());
    }
    Ok(())
}

fn check_account_lockout_status(
    account: &mut types::Account,
    account_map: &Table<types::Account>,
    username: &str,
) -> Result<()> {
    // Check if the account has lockout fields - this will help us determine if the feature is supported
    // Try to access the fields directly
    if let Some(locked_until) = &account.locked_out_until {
        if *locked_until > Utc::now() {
            info!("{username} is locked until {locked_until}");
            return Err(format!("{username} is locked until {locked_until}").into());
        }
        // Lockout period has expired, reset the fields
        account.locked_out_until = None;
        account.failed_login_attempts = 0;

        // Persist changes to database
        account_map.put(account)?;
    }
    Ok(())
}

fn validate_allow_access_from(
    account: &types::Account,
    client_ip: Option<SocketAddr>,
    username: &str,
) -> Result<()> {
    if let Some(allow_access_from) = account.allow_access_from.as_ref() {
        if let Some(socket) = client_ip {
            let ip = socket.ip();
            if !allow_access_from.contains(&ip) {
                info!("Access denied for {username} from IP: {ip}");
                return Err("access denied from this IP".into());
            }
        } else {
            info!("Unable to retrieve client IP for {username}");
            return Err("unable to retrieve client IP".into());
        }
    }
    Ok(())
}

fn validate_max_parallel_sessions(
    account: &types::Account,
    store: &Store,
    username: &str,
) -> Result<()> {
    let expiry_cutoff = Utc::now().timestamp();
    if let Some(max_parallel_sessions) = account.max_parallel_sessions {
        let access_token_map = store.access_token_map();
        let count = access_token_map
            .iter(Direction::Forward, Some(username.as_bytes()))
            .filter_map(Result::ok)
            .filter(|access_token| {
                access_token.username == username
                    && decode_token(&access_token.token)
                        .is_ok_and(|claims| claims.exp > expiry_cutoff)
            })
            .count();
        if count >= max_parallel_sessions as usize {
            info!("Maximum parallel sessions exceeded for {username}");
            return Err("maximum parallel sessions exceeded".into());
        }
    }
    Ok(())
}

fn validate_update_new_password(password: &str, new_password: &str, username: &str) -> Result<()> {
    if password.eq(new_password) {
        info!("Password is the same as the previous one for {username}");
        return Err("password is the same as the previous one".into());
    }
    Ok(())
}

fn generate_aimer_token(ctx: &Context<'_>, exp_timestamp: i64) -> Option<String> {
    match create_aimer_token(exp_timestamp) {
        Ok(token) => Some(token),
        Err(err) => {
            tracing::error!(error = %err, "Failed to create aimer_token");
            let server_error = ctx.set_error_path(ServerError::new(
                format!("{AIMER_TOKEN_ERROR_MESSAGE}: {err}"),
                None,
            ));
            ctx.add_error(server_error);
            None
        }
    }
}

fn sign_in_actions(
    ctx: &Context<'_>,
    account: &mut types::Account,
    store: &Store,
    account_map: &Table<types::Account>,
    client_ip: Option<SocketAddr>,
    username: &str,
) -> Result<AuthPayload> {
    let (review_token, expiration_time) =
        create_token(account.username.clone(), account.role.to_string())?;

    let exp_timestamp = expiration_time.and_utc().timestamp();
    let aimer_token = generate_aimer_token(ctx, exp_timestamp);

    account.update_last_signin_time();
    account_map.put(account)?;

    insert_token(store, &review_token, username)?;

    if let Some(socket) = client_ip {
        info_with_username!(username: username, "Signed in from IP: {}", socket.ip());
    } else {
        info_with_username!(username: username, "Signed in");
    }
    Ok(AuthPayload {
        review_token,
        aimer_token,
        expiration_time,
    })
}

/// Returns the expiration time according to the account policy.
///
/// # Errors
///
/// Returns an error if the account policy is not found or the value is
/// corrupted.
pub fn expiration_time(store: &Store) -> Result<i64> {
    let map = store.account_policy_map();

    map.current_expiry_period()?
        .map(i64::from)
        .ok_or("expiration time uninitialized".into())
}

/// Initializes the account policy with the given expiration time.
///
/// # Errors
///
/// Returns an error if the value cannot be serialized or the underlying store
/// fails to put the value.
pub fn init_expiration_time(store: &Store, time: u32) -> anyhow::Result<()> {
    let map = store.account_policy_map();
    map.init_expiry_period(time)?;
    Ok(())
}

fn get_client_ip(ctx: &Context<'_>) -> Option<SocketAddr> {
    ctx.data_opt::<SocketAddr>().copied()
}

struct Account {
    inner: types::Account,
}

#[Object]
impl Account {
    async fn username(&self) -> &str {
        &self.inner.username
    }

    async fn role(&self) -> Role {
        self.inner.role.into()
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn department(&self) -> &str {
        &self.inner.department
    }

    async fn language(&self) -> Option<String> {
        self.inner.language.clone()
    }

    async fn theme(&self) -> Option<String> {
        self.inner.theme.clone()
    }

    async fn creation_time(&self) -> DateTime<Utc> {
        self.inner.creation_time()
    }

    async fn last_signin_time(&self) -> Option<DateTime<Utc>> {
        self.inner.last_signin_time()
    }

    async fn allow_access_from(&self) -> Option<Vec<String>> {
        self.inner
            .allow_access_from
            .as_ref()
            .map(|ips| ips.iter().map(ToString::to_string).collect::<Vec<String>>())
    }

    /// The max sessions that can be run in parallel within the
    /// representable range of `u8`.
    async fn max_parallel_sessions(&self) -> Option<u8> {
        self.inner.max_parallel_sessions
    }

    async fn customer_ids(&self) -> Option<Vec<ID>> {
        self.inner
            .customer_ids
            .as_ref()
            .map(|ids| ids.iter().map(|id| ID(id.to_string())).collect())
    }
}

impl From<types::Account> for Account {
    fn from(account: types::Account) -> Self {
        Self { inner: account }
    }
}

fn to_ip_addr(ip_addrs: &[IpAddress]) -> Vec<IpAddr> {
    let mut ip_addrs = ip_addrs
        .iter()
        .map(|ip_addr| ip_addr.0)
        .collect::<Vec<IpAddr>>();
    ip_addrs.sort_unstable();
    ip_addrs.dedup();
    ip_addrs
}

#[derive(SimpleObject)]
struct AuthPayload {
    review_token: String,
    aimer_token: Option<String>,
    expiration_time: NaiveDateTime,
}

#[derive(SimpleObject)]
struct AimerTokenPayload {
    aimer_token: String,
    expiration_time: NaiveDateTime,
}

#[derive(SimpleObject)]
struct ForceSignOutResult {
    username: String,
    sessions_terminated: i32,
    errors: Option<Vec<String>>,
}

#[derive(Clone, Copy, Enum, Eq, PartialEq, Serialize)]
#[graphql(remote = "database::Role")]
enum Role {
    SystemAdministrator,
    SecurityAdministrator,
    SecurityManager,
    SecurityMonitor,
}

/// The old and new values of `password` to update.
#[derive(InputObject)]
struct UpdatePassword {
    old: String,
    new: String,
}

/// The old and new values of `role` to update.
#[derive(InputObject)]
struct UpdateRole {
    old: Role,
    new: Role,
}

/// The old and new values of `name` to update.
#[derive(InputObject)]
struct UpdateName {
    old: String,
    new: String,
}

/// The old and new values of `department` to update.
#[derive(InputObject)]
struct UpdateDepartment {
    old: String,
    new: String,
}

#[derive(InputObject)]
struct UpdateLanguage {
    old: Option<String>,
    new: Option<String>,
}

#[derive(InputObject)]
struct UpdateTheme {
    old: Option<String>,
    new: Option<String>,
}

/// The old and new values of `allowAccessFrom` to update.
#[derive(InputObject)]
struct UpdateAllowAccessFrom {
    old: Option<Vec<IpAddress>>,
    new: Option<Vec<IpAddress>>,
}

/// The old and new values of `maxParallelSessions` to update,
/// and the values must be in the range of `u8`.
#[derive(InputObject)]
struct UpdateMaxParallelSessions {
    old: Option<u8>,
    new: Option<u8>,
}

/// The old and new values of `customer_ids` to update.
#[derive(InputObject)]
struct UpdateCustomerIds {
    old: Option<Vec<ID>>,
    new: Option<Vec<ID>>,
}

struct AccountTotalCount;

#[Object]
impl AccountTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        use database::Iterable;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        let count = map.iter(Direction::Forward, None).count();
        Ok(count)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Account, AccountTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let table = store.account_map();
    super::load_edges(&table, after, before, first, last, AccountTotalCount)
}

/// Sets the initial administrator password.
///
/// The credentials are obtained from the `REVIEW_ADMIN` environment variable,
/// which should be set in the format "username:password".
///
/// This function is called only once when the database is opened.
///
/// # Errors
///
/// This function returns an error if it fails to obtain the administrator credentials from the `REVIEW_ADMIN` environment variable,
/// or if the initial administrator password is already set, or if it
/// fails to generate random bytes for password.
pub fn set_initial_admin_password(store: &Store) -> anyhow::Result<()> {
    let map = store.account_map();
    let account = initial_credential()?;
    map.insert(&account)
}

/// Returns the initial administrator username and salted password.
///
/// # Errors
///
/// This function returns an error if it fails to generate random bytes for password.
fn initial_credential() -> anyhow::Result<types::Account> {
    let (username, password) = read_review_admin()?;

    let initial_account = types::Account::new(
        &username,
        &password,
        database::Role::SystemAdministrator,
        "System Administrator".to_owned(),
        String::new(),
        None,
        None,
        None,
        None,
        None,
    )?;

    Ok(initial_account)
}

/// Reads the `REVIEW_ADMIN` environment variable and parses it into a tuple of (username, password).
///
/// # Returns
///
/// - `Ok((String, String))`: If the `REVIEW_ADMIN` environment variable is successfully read and parsed
///   with the format "username:password".
/// - `Err(anyhow::Error)`: If the `REVIEW_ADMIN` environment variable is not set or its format is invalid.
fn read_review_admin() -> anyhow::Result<(String, String)> {
    match env::var(REVIEW_ADMIN) {
        Ok(admin) => {
            let admin_parts: Vec<&str> = admin.split(':').collect();
            if admin_parts.len() == 2 {
                let username = admin_parts[0].to_string();
                let password = admin_parts[1].to_string();
                Ok((username, password))
            } else {
                Err(anyhow!(
                    "Invalid format for {REVIEW_ADMIN} environment variable"
                ))
            }
        }
        Err(_) => Err(anyhow!("{REVIEW_ADMIN} environment variable not found")),
    }
}

#[cfg(test)]
mod tests {
    use std::{env, net::SocketAddr};

    use assert_json_diff::assert_json_eq;
    use async_graphql::Value;
    use review_database::Role;
    use serde_json::json;
    use serial_test::serial;

    use crate::graphql::{
        BoxedAgentManager, MockAgentManager, RoleGuard, TestSchema,
        account::{REVIEW_ADMIN, read_review_admin},
    };

    async fn update_account_last_signin_time(schema: &TestSchema, name: &str) {
        let store = schema.store().await;
        let map = store.account_map();
        let mut account = map.get(name).unwrap().unwrap();
        account.update_last_signin_time();
        let _ = map.put(&account).is_ok();
    }

    #[tokio::test]
    #[serial]
    async fn pagination() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let schema = TestSchema::new().await;
        let res = schema.execute(r"{accountList{totalCount}}").await;
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(account_list)) = retval.get("accountList") else {
            panic!("unexpected response: {retval:?}");
        };
        let Some(Value::Number(total_count)) = account_list.get("totalCount") else {
            panic!("unexpected response: {account_list:?}");
        };
        assert_eq!(total_count.as_u64(), Some(1)); // By default, there is only one account, "admin".

        // Insert 4 more accounts.
        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "user1",
                    password: "pw1",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "User One",
                    department: "Test"
                    customerIds: [0]
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user1"}"#);
        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "user2",
                    password: "pw2",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "User Two",
                    department: "Test"
                    customerIds: [0]
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user2"}"#);
        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "user3",
                    password: "pw3",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "User Three",
                    department: "Test"
                    customerIds: [0]
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user3"}"#);
        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "user4",
                    password: "pw4",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "User Four",
                    department: "Test"
                    customerIds: [0]
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user4"}"#);

        // Retrieve the first page.
        let res = schema
            .execute(
                r"query {
                    accountList(first: 2) {
                        edges {
                            node {
                                username
                            }
                            cursor
                        }
                        pageInfo {
                            hasNextPage
                            startCursor
                            endCursor
                        }
                    }
                }",
            )
            .await;

        // Check if `first` works.
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(account_list)) = retval.get("accountList") else {
            panic!("unexpected response: {retval:?}");
        };
        let Some(Value::List(edges)) = account_list.get("edges") else {
            panic!("unexpected response: {account_list:?}");
        };
        assert_eq!(edges.len(), 2);
        let Some(Value::Object(page_info)) = account_list.get("pageInfo") else {
            panic!("unexpected response: {account_list:?}");
        };
        let Some(Value::Boolean(has_next_page)) = page_info.get("hasNextPage") else {
            panic!("unexpected response: {page_info:?}");
        };
        assert!(*has_next_page);
        let Some(Value::String(end_cursor)) = page_info.get("endCursor") else {
            panic!("unexpected response: {page_info:?}");
        };

        // The first edge should be "admin".
        let Some(Value::Object(edge)) = edges.first() else {
            panic!("unexpected response: {edges:?}");
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {edge:?}");
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {node:?}");
        };
        assert_eq!(username, "admin");

        // The last edge should be "user1".
        let Some(Value::Object(edge)) = edges.get(1) else {
            panic!("unexpected response: {edges:?}");
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {edge:?}");
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {node:?}");
        };
        assert_eq!(username, "user1");
        let Some(Value::String(cursor)) = edge.get("cursor") else {
            panic!("unexpected response: {edge:?}");
        };
        assert_eq!(cursor, end_cursor);

        // Retrieve the second page, with the cursor from the first page.
        let res = schema
            .execute(&format!(
                "query {{
                    accountList(first: 4, after: \"{end_cursor}\") {{
                        edges {{
                            node {{
                                username
                            }}
                            cursor
                        }}
                        pageInfo {{
                            hasNextPage
                            startCursor
                            endCursor
                        }}
                    }}
                }}"
            ))
            .await;
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(account_list)) = retval.get("accountList") else {
            panic!("unexpected response: {retval:?}");
        };
        let Some(Value::List(edges)) = account_list.get("edges") else {
            panic!("unexpected response: {account_list:?}");
        };
        assert_eq!(edges.len(), 3); // The number of remaining accounts.
        let Some(Value::Object(page_info)) = account_list.get("pageInfo") else {
            panic!("unexpected response: {account_list:?}");
        };
        let Some(Value::Boolean(has_next_page)) = page_info.get("hasNextPage") else {
            panic!("unexpected response: {page_info:?}");
        };
        assert!(!(*has_next_page));

        // The first edge should be "user2".
        let Some(Value::Object(edge)) = edges.first() else {
            panic!("unexpected response: {edges:?}");
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {edge:?}");
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {node:?}");
        };
        assert_eq!(username, "user2");

        // The last edge should be "user4".
        let Some(Value::Object(edge)) = edges.get(2) else {
            panic!("unexpected response: {edges:?}");
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {edge:?}");
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {node:?}");
        };
        assert_eq!(username, "user4");

        // Record the cursor of the last edge.
        let Some(Value::String(cursor)) = edge.get("cursor") else {
            panic!("unexpected response: {edge:?}");
        };

        // Retrieve backward.
        let res = schema
            .execute(&format!(
                "query {{
                            accountList(last: 3, before: \"{cursor}\") {{
                                edges {{
                                    node {{
                                        username
                                    }}
                                }}
                                pageInfo {{
                                    hasPreviousPage
                                    startCursor
                                    endCursor
                                }}
                            }}
                        }}"
            ))
            .await;

        // Check if `last` works.
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(account_list)) = retval.get("accountList") else {
            panic!("unexpected response: {retval:?}");
        };
        let Some(Value::List(edges)) = account_list.get("edges") else {
            panic!("unexpected response: {account_list:?}");
        };
        assert_eq!(edges.len(), 3);
        let Some(Value::Object(page_info)) = account_list.get("pageInfo") else {
            panic!("unexpected response: {account_list:?}");
        };
        let Some(Value::Boolean(has_previous_page)) = page_info.get("hasPreviousPage") else {
            panic!("unexpected response: {page_info:?}");
        };
        assert!(*has_previous_page);

        // The first edge should be "user1".
        let Some(Value::Object(edge)) = edges.first() else {
            panic!("unexpected response: {edges:?}");
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {edge:?}");
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {node:?}");
        };
        assert_eq!(username, "user1");

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    async fn my_account() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "username").await;

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "username",
                        password: "password",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security",
                        language: "en-US"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{insertAccount: "username"}"#);

        let res = schema
            .execute(
                r"query {
                    myAccount {
                        username
                        role
                        name
                        department
                        language
                        customerIds
                    }
                }",
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!(
                {
                    "myAccount": {
                        "username": "username",
                        "role": "SECURITY_ADMINISTRATOR",
                        "name": "John Doe",
                        "department": "Security",
                        "language": "en-US",
                        "customerIds": ["0"]
                    }
            })
        );
    }

    #[tokio::test]
    #[serial]
    async fn remove_accounts() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "admin").await;
        let res = schema.execute(r"{accountList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{accountList: {totalCount: 1}}");

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "user1",
                        password: "Ahh9booH",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user1"}"#);

        let res = schema
            .execute(r"{accountList{edges{node{username}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{accountList: {edges: [{node: {username: "admin"}}, {node: {username: "user1"}}], totalCount: 2}}"#
        );

        // A non-existent username is considered removed.
        let res = schema
            .execute(r#"mutation { removeAccounts(usernames: ["none"]) }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeAccounts: ["none"]}"#);

        let res = schema
            .execute(r#"mutation { removeAccounts(usernames: ["user1"]) }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeAccounts: ["user1"]}"#);

        let res = schema.execute(r"{accountList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{accountList: {totalCount: 1}}");

        // Test that users cannot delete themselves
        let res = schema
            .execute(r#"mutation { removeAccounts(usernames: ["admin"]) }"#)
            .await;
        assert!(!res.errors.is_empty());
        assert!(
            res.errors[0]
                .message
                .contains("Users cannot delete themselves")
        );

        // Verify admin account still exists
        let res = schema.execute(r"{accountList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{accountList: {totalCount: 1}}");

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn prevent_admin_self_deletion() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "admin").await;

        // Start with default admin account (SystemAdministrator)
        let res = schema.execute(r"{accountList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{accountList: {totalCount: 1}}");

        // Try to delete self - should fail
        let res = schema
            .execute(r#"mutation { removeAccounts(usernames: ["admin"]) }"#)
            .await;
        assert!(!res.errors.is_empty());
        assert!(
            res.errors[0]
                .message
                .contains("Users cannot delete themselves")
        );

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    async fn prevent_user_self_deletion() {
        let schema = TestSchema::new_with_params(Box::new(MockAgentManager {}), None, "user").await;

        // Try to delete self - should fail
        let res = schema
            .execute(r#"mutation { removeAccounts(usernames: ["user"]) }"#)
            .await;
        assert!(!res.errors.is_empty());
        assert!(
            res.errors[0]
                .message
                .contains("Users cannot delete themselves")
        );
    }

    #[tokio::test]
    #[serial]
    async fn remove_accounts_with_normalization() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let schema = TestSchema::new().await;

        // Insert an account with a username that will be normalized
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "TestUser1",
                        password: "Ahh9booH",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User",
                        department: "Security"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        // Should be normalized to "testuser1"
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser1"}"#);

        // Test removing with uppercase - should normalize and find the account
        let res = schema
            .execute(r#"mutation { removeAccounts(usernames: ["TestUser1"]) }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeAccounts: ["testuser1"]}"#);

        let res = schema.execute(r"{accountList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{accountList: {totalCount: 1}}");

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn remove_accounts_exact() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let schema = TestSchema::new().await;

        // Insert an account using GraphQL - this will be normalized
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "testuser2",
                        password: "Ahh9booH",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User 2",
                        department: "Security"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser2"}"#);

        // Verify the account exists
        let res = schema.execute(r"{accountList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{accountList: {totalCount: 2}}");

        // Test exact removal API - should work with normalized username
        let res = schema
            .execute(r#"mutation { removeAccountsExact(usernames: ["testuser2"]) }"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{removeAccountsExact: ["testuser2"]}"#
        );

        let res = schema.execute(r"{accountList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{accountList: {totalCount: 1}}");

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn default_account() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let schema = TestSchema::new().await;
        let store = schema.store().await;
        super::init_expiration_time(&store, 3600).unwrap();
        update_account_last_signin_time(&schema, "admin").await;
        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "admin", password: "admin") {
                        reviewToken
                        aimerToken
                    }
                }"#,
            )
            .await;

        // should return "{signIn { reviewToken: ..., aimerToken: ... }}"
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        assert_eq!(retval.len(), 1);
        let Value::Object(map) = retval.get("signIn").unwrap() else {
            panic!("unexpected response: {retval:?}");
        };
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("reviewToken"));
        assert!(map.contains_key("aimerToken"));

        let res = schema
            .execute(
                r"query {
                    signedInAccountList {
                        username
                        name
                        department
                        role
                        signinTimes
                        durations
                        expireTimes
                    }
                }",
            )
            .await;

        // Verify the response contains the enhanced fields
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::List(signed_in_list)) = retval.get("signedInAccountList") else {
            panic!("unexpected response: {retval:?}");
        };
        assert_eq!(signed_in_list.len(), 1);

        let Some(Value::Object(account)) = signed_in_list.first() else {
            panic!("unexpected response: {signed_in_list:?}");
        };

        // Verify all required fields are present
        assert!(account.contains_key("username"));
        assert!(account.contains_key("name"));
        assert!(account.contains_key("department"));
        assert!(account.contains_key("role"));
        assert!(account.contains_key("signinTimes"));
        assert!(account.contains_key("durations"));
        assert!(account.contains_key("expireTimes"));

        // Verify specific values
        assert_eq!(
            account.get("username").unwrap(),
            &Value::String("admin".to_string())
        );
        assert_eq!(
            account.get("name").unwrap(),
            &Value::String("System Administrator".to_string())
        );
        assert_eq!(
            account.get("role").unwrap(),
            &Value::Enum(async_graphql::Name::new("SYSTEM_ADMINISTRATOR"))
        );

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn refresh_token_returns_dual_tokens() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let schema = TestSchema::new().await;
        let store = schema.store().await;
        super::init_expiration_time(&store, 3600).unwrap();
        drop(store);
        update_account_last_signin_time(&schema, "admin").await;

        let sign_in_res = schema
            .execute(
                r#"mutation {
                    signIn(username: "admin", password: "admin") {
                        reviewToken
                        aimerToken
                    }
                }"#,
            )
            .await;
        assert!(
            sign_in_res.errors.is_empty(),
            "errors: {:?}",
            sign_in_res.errors
        );
        let Value::Object(sign_in_root) = sign_in_res.data else {
            panic!("unexpected response: {sign_in_res:?}");
        };
        let Some(Value::Object(sign_in_payload)) = sign_in_root.get("signIn") else {
            panic!("unexpected response: {sign_in_root:?}");
        };
        let Some(Value::String(review_token)) = sign_in_payload.get("reviewToken") else {
            panic!("missing reviewToken: {sign_in_payload:?}");
        };
        assert!(!review_token.is_empty());
        let Some(Value::String(aimer_token)) = sign_in_payload.get("aimerToken") else {
            panic!("missing aimerToken: {sign_in_payload:?}");
        };
        assert!(!aimer_token.is_empty());

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let refresh_query = format!(
            r#"mutation {{
                refreshToken(token: "{review_token}") {{
                    reviewToken
                    aimerToken
                    expirationTime
                }}
            }}"#
        );
        let refresh_res = schema.execute(&refresh_query).await;
        assert!(
            refresh_res.errors.is_empty(),
            "errors: {:?}",
            refresh_res.errors
        );
        let Value::Object(refresh_root) = refresh_res.data else {
            panic!("unexpected response: {refresh_res:?}");
        };
        let Some(Value::Object(refresh_payload)) = refresh_root.get("refreshToken") else {
            panic!("unexpected response: {refresh_root:?}");
        };
        let Some(Value::String(new_review_token)) = refresh_payload.get("reviewToken") else {
            panic!("missing reviewToken: {refresh_payload:?}");
        };
        assert!(!new_review_token.is_empty());
        let Some(Value::String(new_aimer_token)) = refresh_payload.get("aimerToken") else {
            panic!("missing aimerToken: {refresh_payload:?}");
        };
        assert!(!new_aimer_token.is_empty());
        assert!(refresh_payload.contains_key("expirationTime"));

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn issue_aimer_token_success() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let schema = TestSchema::new().await;
        let store = schema.store().await;
        super::init_expiration_time(&store, 3600).unwrap();
        drop(store);
        update_account_last_signin_time(&schema, "admin").await;

        let sign_in_res = schema
            .execute(
                r#"mutation {
                    signIn(username: "admin", password: "admin") {
                        reviewToken
                    }
                }"#,
            )
            .await;
        assert!(
            sign_in_res.errors.is_empty(),
            "errors: {:?}",
            sign_in_res.errors
        );
        let Value::Object(sign_in_root) = sign_in_res.data else {
            panic!("unexpected response: {sign_in_res:?}");
        };
        let Some(Value::Object(sign_in_payload)) = sign_in_root.get("signIn") else {
            panic!("unexpected response: {sign_in_root:?}");
        };
        let Some(Value::String(review_token)) = sign_in_payload.get("reviewToken") else {
            panic!("missing reviewToken: {sign_in_payload:?}");
        };

        let mutation = format!(
            r#"mutation {{
                issueAimerToken(reviewToken: "{review_token}") {{
                    aimerToken
                    expirationTime
                }}
            }}"#
        );
        let res = schema.execute(&mutation).await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let Value::Object(root) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(payload)) = root.get("issueAimerToken") else {
            panic!("unexpected response: {root:?}");
        };
        let Some(Value::String(aimer_token)) = payload.get("aimerToken") else {
            panic!("missing aimerToken: {payload:?}");
        };
        assert!(!aimer_token.is_empty());
        assert!(payload.contains_key("expirationTime"));

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn sign_in_reports_aimer_token_signing_failure() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let schema = TestSchema::new().await;
        let store = schema.store().await;
        super::init_expiration_time(&store, 3600).unwrap();
        drop(store);

        update_account_last_signin_time(&schema, "admin").await;

        let _force_failure = crate::auth::ForceAimerTokenFailureGuard::new();

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "admin", password: "admin") {
                        reviewToken
                        aimerToken
                    }
                }"#,
            )
            .await;

        assert!(
            res.errors
                .iter()
                .any(|err| err.message.contains("Failed to issue aimer token")),
            "expected aimer token failure, got {:?}",
            res.errors
        );

        let Value::Object(root) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(payload)) = root.get("signIn") else {
            panic!("unexpected response: {root:?}");
        };
        let Some(Value::String(review_token)) = payload.get("reviewToken") else {
            panic!("missing reviewToken: {payload:?}");
        };
        assert!(!review_token.is_empty());
        assert!(matches!(payload.get("aimerToken"), Some(Value::Null)));
        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn issue_aimer_token_invalid_review_token_fails() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let schema = TestSchema::new().await;
        let store = schema.store().await;
        super::init_expiration_time(&store, 3600).unwrap();
        drop(store);

        let res = schema
            .execute(
                r#"mutation {
                    issueAimerToken(reviewToken: "not-a-valid-token") {
                        aimerToken
                        expirationTime
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors
                .iter()
                .any(|err| err.message.contains("InvalidToken")),
            "expected invalid token error, got {:?}",
            res.errors
        );
        assert!(matches!(res.data, Value::Null));

        restore_review_admin(original_review_admin);
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial]
    async fn test_read_review_admin() {
        let original_review_admin = backup_and_set_review_admin();

        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let result = read_review_admin();
        assert_eq!(result.unwrap(), ("admin".to_string(), "admin".to_string()));

        // Set the temporary `REVIEW_ADMIN` with invalid format
        unsafe {
            env::set_var(REVIEW_ADMIN, "adminadmin");
        }

        assert_eq!(env::var(REVIEW_ADMIN), Ok("adminadmin".to_string()));

        let result = read_review_admin();
        assert!(result.is_err());

        // Unset the `REVIEW_ADMIN`
        unsafe {
            env::remove_var(REVIEW_ADMIN);
        }

        assert!(env::var(REVIEW_ADMIN).is_err());

        let result = read_review_admin();
        assert!(result.is_err());

        restore_review_admin(original_review_admin);
    }

    fn backup_and_set_review_admin() -> Option<String> {
        let original_review_admin = env::var(REVIEW_ADMIN).ok();
        unsafe {
            env::set_var(REVIEW_ADMIN, "admin:admin");
        }
        original_review_admin
    }

    fn restore_review_admin(original_review_admin: Option<String>) {
        if let Some(value) = original_review_admin {
            unsafe {
                env::set_var(REVIEW_ADMIN, value);
            }
        } else {
            unsafe {
                env::remove_var(REVIEW_ADMIN);
            }
        }
    }

    #[tokio::test]
    async fn expiration_time() {
        let schema = TestSchema::new().await;

        let store = schema.store().await;
        assert!(super::init_expiration_time(&store, 12).is_ok());

        let res = schema
            .execute(
                r"query {
                    expirationTime
                }",
            )
            .await;
        assert_eq!(res.data.to_string(), r"{expirationTime: 12}");

        let res = schema
            .execute(
                r"mutation {
                    updateExpirationTime(time: 120)
                }",
            )
            .await;
        assert_eq!(res.data.to_string(), r"{updateExpirationTime: 120}");

        let res = schema
            .execute(
                r"query {
                    expirationTime
                }",
            )
            .await;
        assert_eq!(res.data.to_string(), r"{expirationTime: 120}");
    }

    #[tokio::test]
    async fn reset_admin_password_security_administrator() {
        let schema = TestSchema::new().await;

        // given
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "user1",
                        password: "Ahh9booH",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security",
                        language: "en-US"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user1"}"#);

        // when
        let res = schema
            .execute_with_guard(
                r#"mutation {
                resetAdminPassword(username: "user1", password: "not admin")
            }"#,
                RoleGuard::Local,
            )
            .await;

        // then
        assert_eq!(res.data.to_string(), r"null");
    }

    #[tokio::test]
    #[serial]
    async fn reset_admin_password_system_administrator() {
        // given
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));
        let schema = TestSchema::new().await;

        // when
        // : Change password in local
        let res = schema
            .execute_with_guard(
                r#"mutation {
                resetAdminPassword(username: "admin", password: "Reset-password1!")
            }"#,
                RoleGuard::Local,
            )
            .await;

        // then
        assert_eq!(res.data.to_string(), r#"{resetAdminPassword: "admin"}"#);

        // when
        // : Change passowrd not in local
        let res = schema
            .execute_with_guard(
                r#"mutation {
                resetAdminPassword(username: "admin", password: "not local")
            }"#,
                RoleGuard::Role(Role::SystemAdministrator),
            )
            .await;

        // then
        assert_eq!(res.data.to_string(), r"null");
        assert!(!res.errors.is_empty());

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    async fn reset_admin_password_unregistered_person() {
        let schema = TestSchema::new().await;

        // when
        let res = schema
            .execute_with_guard(
                r#"mutation {
            resetAdminPassword(username: "user", password: "user not existed")
        }"#,
                RoleGuard::Local,
            )
            .await;

        // then
        assert_eq!(res.data.to_string(), r"null");
        assert!(!res.errors.is_empty());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn insert_account() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "sysadmin2",
                        password: "password",
                        role: "SYSTEM_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security",
                        language: "en-US",
                        allowAccessFrom: ["127.0.0.1"]
                        theme: "dark"
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{insertAccount: "sysadmin2"}"#);
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "secadmin1",
                        password: "password",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security",
                        language: "en-US",
                        allowAccessFrom: ["127.0.0.1"]
                        theme: "dark"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{insertAccount: "secadmin1"}"#);

        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "secadmin2",
                    password: "password",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "John Doe",
                    department: "Security",
                    language: "en-US",
                    allowAccessFrom: ["127.0.0.1"]
                    theme: "dark"
                )
            }"#,
            )
            .await;

        assert_eq!(
            res.errors.first().unwrap().message,
            "You are not allowed to access all customers."
        );

        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "secmgr1",
                    password: "password",
                    role: "SECURITY_MANAGER",
                    name: "John Doe",
                    department: "Security",
                    language: "en-US",
                    allowAccessFrom: ["127.0.0.1"]
                    theme: "dark"
                    customerIds: [0]
                )
            }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{insertAccount: "secmgr1"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "secmgr2",
                        password: "password",
                        role: "SECURITY_MANAGER",
                        name: "John Doe",
                        department: "Security",
                        language: "en-US",
                        allowAccessFrom: ["127.0.0.1"]
                        theme: "dark"
                    )
                }"#,
            )
            .await;
        assert_eq!(
            res.errors.first().unwrap().message,
            "You are not allowed to access all customers."
        );

        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "secmon1",
                    password: "password",
                    role: "SECURITY_MONITOR",
                    name: "John Doe",
                    department: "Security",
                    language: "en-US",
                    allowAccessFrom: ["127.0.0.1"]
                    theme: "dark"
                    customerIds: [0]
                )
            }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{insertAccount: "secmon1"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "secmon2",
                        password: "password",
                        role: "SECURITY_MONITOR",
                        name: "John Doe",
                        department: "Security",
                        language: "en-US",
                        allowAccessFrom: ["127.0.0.1"]
                        theme: "dark"
                    )
                }"#,
            )
            .await;
        assert_eq!(
            res.errors.first().unwrap().message,
            "You are not allowed to access all customers."
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn update_account() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "username",
                        password: "password",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security Admin",
                        language: "en-US",
                        allowAccessFrom: ["127.0.0.1"]
                        theme: "dark"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{insertAccount: "username"}"#);

        let res = schema
            .execute(
                r#"
                query {
                     account(username: "username") {
                        username
                        role
                        name
                        department
                        language
                        theme
                    }
                }"#,
            )
            .await;

        assert_eq!(
            res.data.to_string(),
            r#"{account: {username: "username", role: SECURITY_ADMINISTRATOR, name: "John Doe", department: "Security Admin", language: "en-US", theme: "dark"}}"#
        );

        let res = schema
            .execute(
                r#"
                mutation {
                    updateAccount(
                        username: "username",
                        password: "newpassword",
                        role: {
                            old: "SECURITY_ADMINISTRATOR",
                            new: "SECURITY_MONITOR"
                        },
                        name: {
                            old: "John Doe",
                            new: "Loren Ipsum"
                        },
                        department: {
                            old: "Security Admin",
                            new: "Security Monitor"
                        },
                        language: {
                            old: "en-US",
                            new: "ko-KR"
                        },
                        allowAccessFrom: {
                            old: "127.0.0.1",
                            new: "127.0.0.2"
                        },
                        theme: {
                            old: "dark",
                            new: "light"
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateAccount: "username"}"#);

        let res = schema
            .execute(
                r#"
                query {
                     account(username: "username") {
                        username
                        role
                        name
                        department
                        language
                        allowAccessFrom
                        theme
                    }
                }"#,
            )
            .await;

        assert_eq!(
            res.data.to_string(),
            r#"{account: {username: "username", role: SECURITY_MONITOR, name: "Loren Ipsum", department: "Security Monitor", language: "ko-KR", allowAccessFrom: ["127.0.0.2"], theme: "light"}}"#
        );

        let res = schema
            .execute(
                r#"
                mutation {
                    updateAccount(
                        username: "username",
                        password: "anotherpassword",
                        role: {
                            old: "SECURITY_MONITOR",
                            new: "SECURITY_MANAGER"
                        },
                        name: {
                            old: "John Doe",
                            new: "Loren Ipsum"
                        },
                        department: {
                            old: "Security Monitor",
                            new: "Security Manager"
                        },
                        language: {
                            old: "en-US",
                            new: "ko-KR"
                        },
                        allowAccessFrom: {
                            old: "127.0.0.2",
                            new: "127.0.0.x"
                        },
                        theme: {
                            old: "dark",
                            new: "light"
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(
            res.errors.first().unwrap().message.to_string(),
            "Failed to parse \"IpAddress\": Invalid IP address: 127.0.0.x (occurred while \
            parsing \"[IpAddress!]\") (occurred while parsing \"UpdateAllowAccessFrom\")"
                .to_string()
        );

        // Failure Case 1 Related to customer id: Update `customer_ids` to `None` while the current
        // account's `role` is set to a value other than `SYSTEM_ADMINISTRATOR`.
        let res = schema
            .execute(
                r#"
                mutation {
                    updateAccount(
                        username: "username",
                        customerIds: {
                            old: [0]
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(
            res.errors.first().unwrap().message,
            "You are not allowed to access all customers."
        );

        // Failure Case 2 Related to customer id: Update `role` to a value other than
        // `SYSTEM_ADMINISTRATOR` and `customer_ids` to `None`.
        let res = schema
            .execute(
                r#"
                    mutation {
                        updateAccount(
                            username: "username",
                            role: {
                                old: "SECURITY_MONITOR",
                                new: "SECURITY_MANAGER"
                            },
                            customerIds: {
                                old: [0]
                            }
                        )
                    }"#,
            )
            .await;

        assert_eq!(
            res.errors.first().unwrap().message,
            "You are not allowed to access all customers."
        );
    }

    #[tokio::test]
    #[serial]
    async fn update_account_case_system_administrator() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));
        let schema = TestSchema::new().await;

        // Failure Case 3 Related to customer id: Update `role` to a value other than
        // `SYSTEM_ADMINISTRATOR` while the current account's `customer_ids` is set to `None`.
        let res = schema
            .execute(
                r#"
                mutation {
                    updateAccount(
                        username: "admin",
                        role: {
                            old: "SYSTEM_ADMINISTRATOR",
                            new: "SECURITY_ADMINISTRATOR"
                        },
                    )
                }"#,
            )
            .await;

        assert_eq!(res.errors.first().unwrap().message, "Role not allowed.");
        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    async fn max_parallel_sessions() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        super::init_expiration_time(&store, 3600).unwrap();
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "user1",
                        password: "pw1",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "User One",
                        department: "Test",
                        maxParallelSessions: 2
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user1"}"#);

        update_account_last_signin_time(&schema, "user1").await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "user1", password: "pw1") {
                        reviewToken
                    }
                }"#,
            )
            .await;

        assert!(res.data.to_string().contains("reviewToken"));

        let res = schema
            .execute(
                r"query {
                    signedInAccountList {
                        username
                    }
                }",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{signedInAccountList: [{username: "user1"}]}"#
        );

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "user1", password: "pw1") {
                        reviewToken
                    }
                }"#,
            )
            .await;
        assert!(res.data.to_string().contains("reviewToken"));

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "user1", password: "pw1") {
                        reviewToken
                    }
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r"null");
    }

    #[tokio::test]
    async fn allow_access_from() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let test_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let schema = TestSchema::new_with_params(agent_manager, Some(test_addr), "user1").await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "user1",
                        password: "pw1",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "User One",
                        department: "Test",
                        allowAccessFrom: ["127.0.0.1"]
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user1"}"#);

        update_account_last_signin_time(&schema, "user1").await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "user1", password: "pw1") {
                        reviewToken
                    }
                }"#,
            )
            .await;

        assert!(res.data.to_string().contains("reviewToken"));
    }

    #[tokio::test]
    async fn not_allow_access_from() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let test_addr: SocketAddr = "127.0.0.2:8080".parse().unwrap();

        let schema = TestSchema::new_with_params(agent_manager, Some(test_addr), "user1").await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "user1",
                        password: "pw1",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "User One",
                        department: "Test",
                        allowAccessFrom: ["127.0.0.1"]
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user1"}"#);

        update_account_last_signin_time(&schema, "user1").await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "user1", password: "pw1") {
                        reviewToken
                    }
                }"#,
            )
            .await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn invalid_ip_allow_access_from() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let test_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        let schema = TestSchema::new_with_params(agent_manager, Some(test_addr), "user1").await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "user1",
                        password: "pw1",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "User One",
                        department: "Test",
                        allowAccessFrom: ["127.0.0.x"]
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(
            res.errors.first().unwrap().message.to_string(),
            "Failed to parse \"IpAddress\": Invalid IP address: 127.0.0.x (occurred while \
            parsing \"[IpAddress!]\")"
                .to_string()
        );
    }

    #[tokio::test]
    async fn update_language() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "username").await;

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "username",
                        password: "password",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security",
                        language: "en-US"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{insertAccount: "username"}"#);

        let res = schema
            .execute(
                r#"
                query {
                     account(username: "username") {
                        username
                        role
                        name
                        department
                        language
                    }
                }"#,
            )
            .await;

        assert_eq!(
            res.data.to_string(),
            r#"{account: {username: "username", role: SECURITY_ADMINISTRATOR, name: "John Doe", department: "Security", language: "en-US"}}"#
        );

        let res = schema
            .execute(
                r#"
                mutation {
                    updateLanguage(
                        language: {
                            old: "en-US",
                            new: "ko-KR"
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateLanguage: "ko-KR"}"#);

        let res = schema
            .execute(
                r#"
                query {
                     account(username: "username") {
                        username
                        role
                        name
                        department
                        language
                    }
                }"#,
            )
            .await;

        assert_eq!(
            res.data.to_string(),
            r#"{account: {username: "username", role: SECURITY_ADMINISTRATOR, name: "John Doe", department: "Security", language: "ko-KR"}}"#
        );
    }

    #[tokio::test]
    async fn password_required_proceed() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "user2",
                        password: "pw2",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "User One",
                        department: "Test",
                        maxParallelSessions: 2
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user2"}"#);

        let query = r#"mutation {
                    signIn(username: "user2", password: "pw2") {
                        reviewToken
                    }
              }"#;
        let res = schema.execute(query).await;

        assert_eq!(
            res.errors.first().unwrap().message.to_string(),
            "a password change is required to proceed".to_string()
        );

        update_account_last_signin_time(&schema, "user2").await;

        let res = schema.execute(query).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn sign_in_with_new_password_proceed() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "user3",
                        password: "pw3",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "User One",
                        department: "Test",
                        maxParallelSessions: 2
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user3"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "user3", password: "pw3") {
                        reviewToken
                    }
                }"#,
            )
            .await;

        assert_eq!(
            res.errors.first().unwrap().message.to_string(),
            "a password change is required to proceed".to_string()
        );

        let res = schema
            .execute(
                r#"mutation {
                    signInWithNewPassword(username: "user3", password: "pw3") {
                        reviewToken
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.errors.first().unwrap().message.to_string(),
            "Field \"signInWithNewPassword\" argument \"newPassword\" of type \"Mutation\" is \
            required but not provided"
                .to_string()
        );

        let query = r#"mutation {
                    signInWithNewPassword(username: "user1", password: "pw1", newPassword: "pw2") {
                        reviewToken
                    }
              }"#;
        let res = schema.execute(query).await;
        assert_eq!(
            res.errors.first().unwrap().message.to_string(),
            "incorrect username or password".to_string()
        );

        let res = schema
            .execute(
                r#"mutation {
                    signInWithNewPassword(username: "user3", password: "pw3", newPassword: "pw3") {
                        reviewToken
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.errors.first().unwrap().message.to_string(),
            "password is the same as the previous one".to_string()
        );

        let res = schema
            .execute(
                r#"mutation {
                    signInWithNewPassword(username: "user3", password: "pw3", newPassword: "pw4") {
                        reviewToken
                    }
                }"#,
            )
            .await;
        assert!(res.is_ok());

        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("user3").unwrap().unwrap();
        assert!(account.verify_password("pw4"));
    }

    #[tokio::test]
    async fn password_validate_proceed() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "user2",
                        password: "pw2",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "User One",
                        department: "Test",
                        maxParallelSessions: 2
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "user2"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "user2", password: "pw3") {
                        reviewToken
                    }
                }"#,
            )
            .await;

        assert_eq!(
            res.errors.first().unwrap().message.to_string(),
            "incorrect username or password".to_string()
        );
    }

    #[tokio::test]
    async fn update_theme() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "username").await;

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "username",
                        password: "password",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security",
                        language: "en-US",
                        theme: "dark"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{insertAccount: "username"}"#);

        let res = schema
            .execute(
                r#"
                query {
                     account(username: "username") {
                        username
                        role
                        name
                        department
                        language
                        theme
                    }
                }"#,
            )
            .await;

        assert_eq!(
            res.data.to_string(),
            r#"{account: {username: "username", role: SECURITY_ADMINISTRATOR, name: "John Doe", department: "Security", language: "en-US", theme: "dark"}}"#
        );

        let res = schema
            .execute(
                r#"
                mutation {
                    updateTheme(
                        theme: {
                            old: "dark",
                            new: "light"
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateTheme: "light"}"#);

        let res = schema
            .execute(
                r#"
                query {
                     account(username: "username") {
                        username
                        role
                        name
                        department
                        language
                        theme
                    }
                }"#,
            )
            .await;

        assert_eq!(
            res.data.to_string(),
            r#"{account: {username: "username", role: SECURITY_ADMINISTRATOR, name: "John Doe", department: "Security", language: "en-US", theme: "light"}}"#
        );
    }

    #[tokio::test]
    async fn prevent_password_reuse_update_account() {
        let schema = TestSchema::new().await;

        // Create a test account
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "oldpassword",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User",
                        department: "Security",
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser"}"#);

        // Try to update password with the same password (should fail)
        let res = schema
            .execute(
                r#"mutation {
                    updateAccount(
                        username: "testuser",
                        password: "oldpassword"
                    )
                }"#,
            )
            .await;

        assert!(!res.errors.is_empty());
        assert_eq!(
            res.errors.first().unwrap().message,
            "new password cannot be the same as the current password"
        );

        // Update password without requiring old password (should succeed)
        let res = schema
            .execute(
                r#"mutation {
                    updateAccount(
                        username: "testuser",
                        password: "newpassword"
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateAccount: "testuser"}"#);

        // Update password with a different new password (should succeed)
        let res = schema
            .execute(
                r#"mutation {
                    updateAccount(
                        username: "testuser",
                        password: "differentpassword"
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateAccount: "testuser"}"#);

        // Verify the password was actually changed
        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("testuser").unwrap().unwrap();
        assert!(account.verify_password("differentpassword"));
        assert!(!account.verify_password("oldpassword"));
    }

    #[tokio::test]
    #[serial]
    async fn prevent_password_reuse_reset_admin_password() {
        let original_review_admin = backup_and_set_review_admin();
        let schema = TestSchema::new().await;

        // Try to reset admin password with the same password (should fail)
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    resetAdminPassword(username: "admin", password: "admin")
                }"#,
                RoleGuard::Local,
            )
            .await;

        assert!(!res.errors.is_empty());
        assert_eq!(
            res.errors.first().unwrap().message,
            "new password cannot be the same as the current password"
        );

        // Try to reset admin password with different password (should succeed)
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    resetAdminPassword(username: "admin", password: "newadminpassword")
                }"#,
                RoleGuard::Local,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{resetAdminPassword: "admin"}"#);

        // Verify the password was actually changed
        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("admin").unwrap().unwrap();
        assert!(account.verify_password("newadminpassword"));
        assert!(!account.verify_password("adminpassword"));

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    async fn update_my_account_success() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // Create a test account
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "initialpassword",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Initial Name",
                        department: "Initial Department",
                        language: "en-US",
                        theme: "dark",
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser"}"#);

        // Update all fields
        let res = schema
            .execute(
                r#"mutation {
                    updateMyAccount(
                        password: {
                            old: "initialpassword",
                            new: "newpassword"
                        },
                        name: {
                            old: "Initial Name",
                            new: "Updated Name"
                        },
                        department: {
                            old: "Initial Department",
                            new: "Updated Department"
                        },
                        language: {
                            old: "en-US",
                            new: "ko-KR"
                        },
                        theme: {
                            old: "dark",
                            new: "light"
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateMyAccount: "testuser"}"#);

        // Verify all changes were applied
        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("testuser").unwrap().unwrap();
        assert!(account.verify_password("newpassword"));
        assert_eq!(account.name, "Updated Name");
        assert_eq!(account.department, "Updated Department");
        assert_eq!(account.language, Some("ko-KR".to_string()));
        assert_eq!(account.theme, Some("light".to_string()));
    }

    #[tokio::test]
    async fn update_my_account_partial_updates() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // Create a test account
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "password",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User",
                        department: "Security",
                        language: "en-US",
                        theme: "dark",
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser"}"#);

        // Update only name and department
        let res = schema
            .execute(
                r#"mutation {
                    updateMyAccount(
                        name: {
                            old: "Test User",
                            new: "New Name"
                        },
                        department: {
                            old: "Security",
                            new: "Engineering"
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateMyAccount: "testuser"}"#);

        // Verify only specified fields were changed
        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("testuser").unwrap().unwrap();
        assert!(account.verify_password("password")); // Password unchanged
        assert_eq!(account.name, "New Name");
        assert_eq!(account.department, "Engineering");
        assert_eq!(account.language, Some("en-US".to_string())); // Language unchanged
        assert_eq!(account.theme, Some("dark".to_string())); // Theme unchanged
    }

    #[tokio::test]
    async fn update_my_account_no_fields_provided() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // Create a test account
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "password",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User",
                        department: "Security",
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser"}"#);

        // Try to update without providing any fields
        let res = schema
            .execute(
                r"mutation {
                    updateMyAccount
                }",
            )
            .await;

        assert!(!res.errors.is_empty());
        assert_eq!(
            res.errors.first().unwrap().message,
            "At least one of the optional fields must be provided to update."
        );
    }

    #[tokio::test]
    async fn update_my_account_wrong_old_password() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // Create a test account
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "correctpassword",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User",
                        department: "Security",
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser"}"#);

        // Try to update password with wrong old password
        let res = schema
            .execute(
                r#"mutation {
                    updateMyAccount(
                        password: {
                            old: "wrongpassword",
                            new: "newpassword"
                        }
                    )
                }"#,
            )
            .await;

        assert!(!res.errors.is_empty());
        assert_eq!(
            res.errors.first().unwrap().message,
            "incorrect current password"
        );
    }

    #[tokio::test]
    async fn update_my_account_same_old_new_password() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // Create a test account
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "samepassword",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User",
                        department: "Security",
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser"}"#);

        // Try to update password with same old and new password
        let res = schema
            .execute(
                r#"mutation {
                    updateMyAccount(
                        password: {
                            old: "samepassword",
                            new: "samepassword"
                        }
                    )
                }"#,
            )
            .await;

        assert!(!res.errors.is_empty());
        assert_eq!(
            res.errors.first().unwrap().message,
            "new password cannot be the same as the current password"
        );
    }

    #[tokio::test]
    async fn update_my_account_language_theme_null_values() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // Create a test account with null language and theme
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "password",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User",
                        department: "Security",
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser"}"#);

        // Update from null to values
        let res = schema
            .execute(
                r#"mutation {
                    updateMyAccount(
                        language: {
                            old: null,
                            new: "en-US"
                        },
                        theme: {
                            old: null,
                            new: "dark"
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateMyAccount: "testuser"}"#);

        // Verify values were set
        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("testuser").unwrap().unwrap();
        assert_eq!(account.language, Some("en-US".to_string()));
        assert_eq!(account.theme, Some("dark".to_string()));

        // Update from values back to null
        let res = schema
            .execute(
                r#"mutation {
                    updateMyAccount(
                        language: {
                            old: "en-US",
                            new: null
                        },
                        theme: {
                            old: "dark",
                            new: null
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateMyAccount: "testuser"}"#);

        // Verify values were cleared
        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("testuser").unwrap().unwrap();
        assert_eq!(account.language, None);
        assert_eq!(account.theme, None);
    }

    #[tokio::test]
    #[serial]
    async fn force_sign_out() {
        let original_review_admin = backup_and_set_review_admin();

        let schema = TestSchema::new().await;
        let store = schema.store().await;
        super::init_expiration_time(&store, 3600).unwrap();

        // Create a test user
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "password123",
                        role: "SECURITY_MANAGER",
                        name: "Test User",
                        department: "Testing",
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser"}"#);

        // Sign in the test user to create an active session
        update_account_last_signin_time(&schema, "testuser").await;
        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "testuser", password: "password123") {
                        reviewToken
                    }
                }"#,
            )
            .await;
        assert!(res.data.to_string().contains("reviewToken"));

        // Verify the user has an active session
        let res = schema
            .execute(
                r"query {
                    signedInAccountList {
                        username
                    }
                }",
            )
            .await;
        assert!(res.data.to_string().contains("testuser"));

        // Force sign out the user as admin
        let res = schema
            .execute(
                r#"mutation {
                    forceSignOut(username: "testuser") {
                        username
                        sessionsTerminated
                        errors
                    }
                }"#,
            )
            .await;

        // Verify the force sign out was successful
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(force_sign_out)) = retval.get("forceSignOut") else {
            panic!("unexpected response: {retval:?}");
        };

        assert_eq!(
            force_sign_out.get("username"),
            Some(&Value::String("testuser".to_string()))
        );
        assert_eq!(
            force_sign_out.get("sessionsTerminated"),
            Some(&Value::Number(serde_json::Number::from(1)))
        );
        assert_eq!(force_sign_out.get("errors"), Some(&Value::Null));

        // Verify the user no longer has active sessions
        let res = schema
            .execute(
                r"query {
                    signedInAccountList {
                        username
                    }
                }",
            )
            .await;
        assert!(!res.data.to_string().contains("testuser"));

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    async fn force_sign_out_nonexistent_user() {
        let schema = TestSchema::new().await;

        // Try to force sign out a non-existent user
        let res = schema
            .execute(
                r#"mutation {
                    forceSignOut(username: "nonexistent") {
                        username
                        sessionsTerminated
                        errors
                    }
                }"#,
            )
            .await;

        // Should return an error
        assert!(!res.errors.is_empty());
        assert!(res.errors.first().unwrap().message.contains("not found"));
    }

    #[tokio::test]
    async fn force_sign_out_no_active_sessions() {
        let schema = TestSchema::new().await;

        // Create a test user but don't sign them in
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "inactiveuser",
                        password: "password123",
                        role: "SECURITY_MONITOR",
                        name: "Inactive User",
                        department: "Testing",
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "inactiveuser"}"#);

        // Force sign out the user (who has no active sessions)
        let res = schema
            .execute(
                r#"mutation {
                    forceSignOut(username: "inactiveuser") {
                        username
                        sessionsTerminated
                        errors
                    }
                }"#,
            )
            .await;

        // Should succeed but terminate 0 sessions
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        let Some(Value::Object(force_sign_out)) = retval.get("forceSignOut") else {
            panic!("unexpected response: {retval:?}");
        };

        assert_eq!(
            force_sign_out.get("username"),
            Some(&Value::String("inactiveuser".to_string()))
        );
        assert_eq!(
            force_sign_out.get("sessionsTerminated"),
            Some(&Value::Number(serde_json::Number::from(0)))
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn comprehensive_user_list() {
        let schema = TestSchema::new().await;

        // Create several test users
        let mutations = [
            r#"mutation {
                insertAccount(
                    username: "user1",
                    password: "password123",
                    role: "SECURITY_MONITOR",
                    name: "User One",
                    department: "Security",
                    customerIds: [0]
                )
            }"#,
            r#"mutation {
                insertAccount(
                    username: "user2",
                    password: "password456",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "User Two",
                    department: "Admin",
                    customerIds: [0]
                )
            }"#,
        ];

        for mutation in &mutations {
            let res = schema.execute(mutation).await;
            assert!(res.errors.is_empty());
        }

        // Query comprehensive user list
        let res = schema
            .execute(
                r"query {
                    comprehensiveUserList {
                        username
                        name
                        department
                        role
                        isLocked
                        isSuspended
                        maxParallelSessions
                        allowAccessFrom
                        creationTime
                        lastSigninTime
                    }
                }",
            )
            .await;

        assert!(res.errors.is_empty());

        let Value::Object(data) = res.data else {
            panic!("unexpected response: {res:?}");
        };

        let Some(Value::List(users)) = data.get("comprehensiveUserList") else {
            panic!("expected comprehensiveUserList array");
        };

        // Should include at least our created users
        assert!(users.len() >= 2);

        // Check that created users are present with expected security status
        let usernames: Vec<String> = users
            .iter()
            .filter_map(|user| {
                if let Value::Object(user_obj) = user {
                    if let Some(Value::String(username)) = user_obj.get("username") {
                        Some(username.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        assert!(usernames.contains(&"user1".to_string()));
        assert!(usernames.contains(&"user2".to_string()));

        // Verify security status fields are present and false (no locking implemented yet)
        for user in users {
            if let Value::Object(user_obj) = user {
                assert_eq!(user_obj.get("isLocked"), Some(&Value::Boolean(false)));
                assert_eq!(user_obj.get("isSuspended"), Some(&Value::Boolean(false)));
                assert!(user_obj.contains_key("creationTime"));
            }
        }
    }

    #[tokio::test]
    async fn insert_account_requires_system_administrator() {
        let schema = TestSchema::new().await;

        // Test that SecurityAdministrator can no longer create accounts
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "password123",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User",
                        department: "Test"
                        customerIds: [0]
                    )
                }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(!res.errors.is_empty());
        assert_eq!(res.errors[0].message, "Forbidden");

        // Test that SystemAdministrator can create accounts
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    insertAccount(
                        username: "testuser",
                        password: "password123",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Test User",
                        department: "Test"
                        customerIds: [0]
                    )
                }"#,
                RoleGuard::Role(Role::SystemAdministrator),
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "testuser"}"#);
    }

    #[tokio::test]
    async fn insert_account_can_create_system_administrator() {
        let schema = TestSchema::new().await;

        // Test that SystemAdministrator can now create SystemAdministrator accounts
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    insertAccount(
                        username: "newsysadmin",
                        password: "password123",
                        role: "SYSTEM_ADMINISTRATOR",
                        name: "New System Admin",
                        department: "IT"
                    )
                }"#,
                RoleGuard::Role(Role::SystemAdministrator),
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "newsysadmin"}"#);
    }

    #[tokio::test]
    async fn remove_accounts_requires_system_administrator() {
        let schema = TestSchema::new().await;

        // First create a test account to remove
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    insertAccount(
                        username: "toremove",
                        password: "password123",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "To Remove",
                        department: "Test"
                        customerIds: [0]
                    )
                }"#,
                RoleGuard::Role(Role::SystemAdministrator),
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "toremove"}"#);

        // Test that SecurityAdministrator can no longer remove accounts
        let res = schema
            .execute_with_guard(
                r#"mutation { removeAccounts(usernames: ["toremove"]) }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(!res.errors.is_empty());
        assert_eq!(res.errors[0].message, "Forbidden");

        // Test that SystemAdministrator can remove accounts
        let res = schema
            .execute_with_guard(
                r#"mutation { removeAccounts(usernames: ["toremove"]) }"#,
                RoleGuard::Role(Role::SystemAdministrator),
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeAccounts: ["toremove"]}"#);
    }

    #[tokio::test]
    async fn remove_accounts_exact_requires_system_administrator() {
        let schema = TestSchema::new().await;

        // First create a test account to remove
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    insertAccount(
                        username: "exactremove",
                        password: "password123",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "Exact Remove",
                        department: "Test"
                        customerIds: [0]
                    )
                }"#,
                RoleGuard::Role(Role::SystemAdministrator),
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "exactremove"}"#);

        // Test that SecurityAdministrator can no longer use removeAccountsExact
        let res = schema
            .execute_with_guard(
                r#"mutation { removeAccountsExact(usernames: ["exactremove"]) }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(!res.errors.is_empty());
        assert_eq!(res.errors[0].message, "Forbidden");

        // Test that SystemAdministrator can use removeAccountsExact
        let res = schema
            .execute_with_guard(
                r#"mutation { removeAccountsExact(usernames: ["exactremove"]) }"#,
                RoleGuard::Role(Role::SystemAdministrator),
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{removeAccountsExact: ["exactremove"]}"#
        );
    }
}
