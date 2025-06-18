use std::{
    env,
    net::{IpAddr, SocketAddr},
};

use anyhow::anyhow;
use async_graphql::{
    Context, Enum, ID, InputObject, Object, Result, SimpleObject,
    connection::{Connection, EmptyFields, OpaqueCursor},
};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use review_database::{
    self as database, Direction, Iterable, Store, Table,
    types::{self},
};
use serde::Serialize;
use tracing::info;

use super::{IpAddress, RoleGuard, cluster::try_id_args_into_ints};
use crate::auth::{create_token, decode_token, insert_token, revoke_token, update_jwt_expires_in};
use crate::graphql::query_with_constraints;

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Serialize, SimpleObject)]
pub struct SignedInAccount {
    username: String,
    expire_times: Vec<DateTime<Utc>>,
}

const REVIEW_ADMIN: &str = "REVIEW_ADMIN";

#[derive(Default)]
pub(super) struct AccountQuery;

#[Object]
impl AccountQuery {
    /// Looks up an account by the given username.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn account(&self, ctx: &Context<'_>, username: String) -> Result<Account> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        let inner = map
            .get(&username)?
            .ok_or_else::<async_graphql::Error, _>(|| "User not found".into())?;

        Ok(Account { inner })
    }

    /// Retrieves the current user's account information.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn my_account(&self, ctx: &Context<'_>) -> Result<Account> {
        let store = crate::graphql::get_store(ctx).await?;
        let username = ctx.data::<String>()?;
        let map = store.account_map();
        let inner = map
            .get(username)?
            .ok_or_else::<async_graphql::Error, _>(|| "User not found".into())?;

        Ok(Account { inner })
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
        let map = store.access_token_map();

        let signed = map
            .iter(Direction::Forward, None)
            .filter_map(|e| {
                let e = e.ok()?;
                let username = e.username;
                let exp_time = decode_token(&e.token)
                    .ok()
                    .map(|t| Utc.timestamp_nanos(t.exp * 1_000_000_000))?;
                if Utc::now() < exp_time {
                    Some((username, exp_time))
                } else {
                    None
                }
            })
            .fold(
                HashMap::new(),
                |mut res: HashMap<_, Vec<_>>, (username, time)| {
                    let e = res.entry(username).or_default();
                    e.push(time);
                    res
                },
            )
            .into_iter()
            .map(|(username, expire_times)| SignedInAccount {
                username,
                expire_times,
            })
            .collect::<Vec<_>>();

        Ok(signed)
    }

    /// Returns how long signing in lasts in seconds
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn expiration_time(&self, ctx: &Context<'_>) -> Result<i64> {
        let store = crate::graphql::get_store(ctx).await?;

        expiration_time(&store)
    }
}

#[derive(Default)]
pub(super) struct AccountMutation;

#[Object]
impl AccountMutation {
    /// Creates a new account
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
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
        let customer_ids = try_id_args_into_ints::<u32>(customer_ids)?;
        let store = crate::graphql::get_store(ctx).await?;
        let table = store.account_map();
        if table.contains(&username)? {
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
            &username,
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
        Ok(username)
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        if let Some(account) = map.get(&username)? {
            if account.role == review_database::Role::SystemAdministrator {
                // Validate that the new password is different from the current password
                if account.verify_password(&password) {
                    return Err("new password cannot be the same as the current password".into());
                }

                map.update(
                    username.as_bytes(),
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
                return Ok(username);
            }
            return Err(format!("reset failed due to invalid access for {username}").into());
        }

        Err("reset failed due to invalid username".into())
    }

    /// Removes accounts, returning the usernames that no longer exist.
    ///
    /// On error, some usernames may have been removed.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn remove_accounts(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] usernames: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        let mut removed = Vec::with_capacity(usernames.len());
        for username in usernames {
            map.delete(&username)?;
            removed.push(username);
        }
        Ok(removed)
    }

    /// Updates an existing account.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn update_account(
        &self,
        ctx: &Context<'_>,
        username: String,
        password: Option<UpdatePassword>,
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

        let customer_ids = customer_ids
            .map(|ids| {
                let old = try_id_args_into_ints::<u32>(ids.old)?;
                let new = try_id_args_into_ints::<u32>(ids.new)?;
                Ok::<_, async_graphql::Error>((old, new))
            })
            .transpose()?;
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();

        // Validate password change if provided
        if let Some(ref password_update) = password {
            let Ok(Some(account)) = map.get(&username) else {
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

        // Ensure that the `customer_ids` is set correctly for the account role
        if role.is_some() || customer_ids.is_some() {
            let Ok(Some(account)) = map.get(&username) else {
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

        let password_new = password.map(|p| p.new);
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
            username.as_bytes(),
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
        Ok(username)
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
        let store = crate::graphql::get_store(ctx).await?;
        let account_map = store.account_map();
        let client_ip = get_client_ip(ctx);

        if let Some(mut account) = account_map.get(&username)? {
            validate_password(&account, &username, &password)?;
            validate_last_signin_time(&account, &username)?;
            validate_allow_access_from(&account, client_ip, &username)?;
            validate_max_parallel_sessions(&account, &store, &username)?;

            sign_in_actions(&mut account, &store, &account_map, client_ip, &username)
        } else {
            info!("{username} is not a valid username");
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
        let store = crate::graphql::get_store(ctx).await?;
        let account_map = store.account_map();
        let client_ip = get_client_ip(ctx);

        if let Some(mut account) = account_map.get(&username)? {
            validate_password(&account, &username, &password)?;
            validate_allow_access_from(&account, client_ip, &username)?;
            validate_max_parallel_sessions(&account, &store, &username)?;
            validate_update_new_password(&password, &new_password, &username)?;

            account.update_password(&new_password)?;

            sign_in_actions(&mut account, &store, &account_map, client_ip, &username)
        } else {
            info!("{username} is not a valid username");
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
        let decoded_token = decode_token(&token)?;
        let username = decoded_token.sub;
        info!("{username} signed out");
        Ok(token)
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
        let (new_token, expiration_time) = create_token(username.clone(), decoded_token.role)?;
        insert_token(&store, &new_token, &username)?;
        let rt = revoke_token(&store, &token);
        if let Err(e) = rt {
            revoke_token(&store, &new_token)?;
            Err(e.into())
        } else {
            Ok(AuthPayload {
                token: new_token,
                expiration_time,
            })
        }
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
}

fn validate_password(account: &types::Account, username: &str, password: &str) -> Result<()> {
    if !account.verify_password(password) {
        info!("wrong password for {username}");
        return Err("incorrect username or password".into());
    }
    Ok(())
}

fn validate_last_signin_time(account: &types::Account, username: &str) -> Result<()> {
    if account.last_signin_time().is_none() {
        info!("a password change is required to proceed for {username}");
        return Err("a password change is required to proceed".into());
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
                info!("access denied for {username} from IP: {ip}");
                return Err("access denied from this IP".into());
            }
        } else {
            info!("unable to retrieve client IP for {username}");
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
    if let Some(max_parallel_sessions) = account.max_parallel_sessions {
        let access_token_map = store.access_token_map();
        let count = access_token_map
            .iter(Direction::Forward, Some(username.as_bytes()))
            .filter_map(|res| {
                if let Ok(access_token) = res {
                    if access_token.username == username {
                        Some(access_token)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .count();
        if count >= max_parallel_sessions as usize {
            info!("maximum parallel sessions exceeded for {username}");
            return Err("maximum parallel sessions exceeded".into());
        }
    }
    Ok(())
}

fn validate_update_new_password(password: &str, new_password: &str, username: &str) -> Result<()> {
    if password.eq(new_password) {
        info!("password is the same as the previous one for {username}");
        return Err("password is the same as the previous one".into());
    }
    Ok(())
}

fn sign_in_actions(
    account: &mut types::Account,
    store: &Store,
    account_map: &Table<types::Account>,
    client_ip: Option<SocketAddr>,
    username: &str,
) -> Result<AuthPayload> {
    let (token, expiration_time) =
        create_token(account.username.clone(), account.role.to_string())?;
    account.update_last_signin_time();
    account_map.put(account)?;

    insert_token(store, &token, username)?;

    if let Some(socket) = client_ip {
        info!("{username} signed in from IP: {}", socket.ip());
    } else {
        info!("{username} signed in");
    }
    Ok(AuthPayload {
        token,
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
    token: String,
    expiration_time: NaiveDateTime,
}

#[derive(Clone, Copy, Enum, Eq, PartialEq)]
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
                    username: "u1",
                    password: "pw1",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "User One",
                    department: "Test"
                    customerIds: [0]
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u1"}"#);
        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "u2",
                    password: "pw2",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "User Two",
                    department: "Test"
                    customerIds: [0]
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u2"}"#);
        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "u3",
                    password: "pw3",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "User Three",
                    department: "Test"
                    customerIds: [0]
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u3"}"#);
        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "u4",
                    password: "pw4",
                    role: "SECURITY_ADMINISTRATOR",
                    name: "User Four",
                    department: "Test"
                    customerIds: [0]
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u4"}"#);

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

        // The last edge should be "u1".
        let Some(Value::Object(edge)) = edges.get(1) else {
            panic!("unexpected response: {edges:?}");
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {edge:?}");
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {node:?}");
        };
        assert_eq!(username, "u1");
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

        // The first edge should be "u2".
        let Some(Value::Object(edge)) = edges.first() else {
            panic!("unexpected response: {edges:?}");
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {edge:?}");
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {node:?}");
        };
        assert_eq!(username, "u2");

        // The last edge should be "u4".
        let Some(Value::Object(edge)) = edges.get(2) else {
            panic!("unexpected response: {edges:?}");
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {edge:?}");
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {node:?}");
        };
        assert_eq!(username, "u4");

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

        // The first edge should be "u1".
        let Some(Value::Object(edge)) = edges.first() else {
            panic!("unexpected response: {edges:?}");
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {edge:?}");
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {node:?}");
        };
        assert_eq!(username, "u1");

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

        let schema = TestSchema::new().await;
        let res = schema.execute(r"{accountList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{accountList: {totalCount: 1}}");

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "u1",
                        password: "Ahh9booH",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security"
                        customerIds: [0]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u1"}"#);

        let res = schema
            .execute(r"{accountList{edges{node{username}}totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{accountList: {edges: [{node: {username: "admin"}}, {node: {username: "u1"}}], totalCount: 2}}"#
        );

        // A non-existent username is considered removed.
        let res = schema
            .execute(r#"mutation { removeAccounts(usernames: ["none"]) }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeAccounts: ["none"]}"#);

        let res = schema
            .execute(r#"mutation { removeAccounts(usernames: ["u1"]) }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeAccounts: ["u1"]}"#);

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
        update_account_last_signin_time(&schema, "admin").await;
        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "admin", password: "admin") {
                        token
                    }
                }"#,
            )
            .await;

        // should return "{signIn { token: ... }}"
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {res:?}");
        };
        assert_eq!(retval.len(), 1);
        let Value::Object(map) = retval.get("signIn").unwrap() else {
            panic!("unexpected response: {retval:?}");
        };
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("token"));

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
            r#"{signedInAccountList: [{username: "admin"}]}"#
        );

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
    async fn reset_admin_password() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "u1",
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
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u1"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "u2",
                        password: "Ahh9booH",
                        role: "SYSTEM_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Admin",
                        language: "en-US"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u2"}"#);

        let res = schema
            .execute_with_guard(
                r#"mutation {
                resetAdminPassword(username: "u1", password: "not admin")
            }"#,
                RoleGuard::Local,
            )
            .await;
        assert_eq!(res.data.to_string(), r"null");

        let res = schema
            .execute_with_guard(
                r#"mutation {
                resetAdminPassword(username: "u3", password: "user not existed")
            }"#,
                RoleGuard::Local,
            )
            .await;
        assert_eq!(res.data.to_string(), r"null");

        let res = schema
            .execute_with_guard(
                r#"mutation {
                resetAdminPassword(username: "u2", password: "admin")
            }"#,
                RoleGuard::Local,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{resetAdminPassword: "u2"}"#);

        let res = schema
            .execute_with_guard(
                r#"mutation {
                resetAdminPassword(username: "u2", password: "not local")
            }"#,
                RoleGuard::Role(Role::SystemAdministrator),
            )
            .await;
        assert_eq!(res.data.to_string(), r"null");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn insert_account() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "system administrator1",
                        password: "password",
                        role: "SYSTEM_ADMINISTRATOR",
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

        assert_eq!(
            res.data.to_string(),
            r#"{insertAccount: "system administrator1"}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "system administrator2",
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

        assert_eq!(
            res.data.to_string(),
            r#"{insertAccount: "system administrator2"}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "security administrator1",
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

        assert_eq!(
            res.data.to_string(),
            r#"{insertAccount: "security administrator1"}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                insertAccount(
                    username: "security administrator2",
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
                    username: "security manager1",
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

        assert_eq!(
            res.data.to_string(),
            r#"{insertAccount: "security manager1"}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "security manager2",
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
                    username: "security monitor1",
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

        assert_eq!(
            res.data.to_string(),
            r#"{insertAccount: "security monitor1"}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "security monitor2",
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
                        password: {
                            old: "password",
                            new: "newpassword"
                        },
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
                        password: {
                            old: "newpassword", 
                            new: "anotherpassword"
                        },
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

        // Failure Case 3 Related to customer id: Update `role` to a value other than
        // `SYSTEM_ADMINISTRATOR` while the current account's `customer_ids` is set to `None`.
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "username2",
                        password: "password",
                        role: "SYSTEM_ADMINISTRATOR",
                        name: "John Doe",
                        department: "System Admin",
                        language: "en-US",
                        allowAccessFrom: ["127.0.0.1"]
                        theme: "dark"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "username2"}"#);

        let res = schema
            .execute(
                r#"
                mutation {
                    updateAccount(
                        username: "username2",
                        role: {
                            old: "SYSTEM_ADMINISTRATOR",
                            new: "SECURITY_ADMINISTRATOR"
                        },
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
    async fn max_parallel_sessions() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "u1",
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
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u1"}"#);

        update_account_last_signin_time(&schema, "u1").await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "u1", password: "pw1") {
                        token
                    }
                }"#,
            )
            .await;

        assert!(res.data.to_string().contains("token"));

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
            r#"{signedInAccountList: [{username: "u1"}]}"#
        );

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "u1", password: "pw1") {
                        token
                    }
                }"#,
            )
            .await;
        assert!(res.data.to_string().contains("token"));

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "u1", password: "pw1") {
                        token
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

        let schema = TestSchema::new_with_params(agent_manager, Some(test_addr), "u1").await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "u1",
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
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u1"}"#);

        update_account_last_signin_time(&schema, "u1").await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "u1", password: "pw1") {
                        token
                    }
                }"#,
            )
            .await;

        assert!(res.data.to_string().contains("token"));
    }

    #[tokio::test]
    async fn not_allow_access_from() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let test_addr: SocketAddr = "127.0.0.2:8080".parse().unwrap();

        let schema = TestSchema::new_with_params(agent_manager, Some(test_addr), "u1").await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "u1",
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
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u1"}"#);

        update_account_last_signin_time(&schema, "u1").await;

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "u1", password: "pw1") {
                        token
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

        let schema = TestSchema::new_with_params(agent_manager, Some(test_addr), "u1").await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "u1",
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
                        username: "u2",
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
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u2"}"#);

        let query = r#"mutation {
                    signIn(username: "u2", password: "pw2") {
                        token
                    }
              }"#;
        let res = schema.execute(query).await;

        assert_eq!(
            res.errors.first().unwrap().message.to_string(),
            "a password change is required to proceed".to_string()
        );

        update_account_last_signin_time(&schema, "u2").await;

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
                        username: "u3",
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
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u3"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "u3", password: "pw3") {
                        token
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
                    signInWithNewPassword(username: "u3", password: "pw3") {
                        token
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
                    signInWithNewPassword(username: "u1", password: "pw1", newPassword: "pw2") {
                        token
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
                    signInWithNewPassword(username: "u3", password: "pw3", newPassword: "pw3") {
                        token
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
                    signInWithNewPassword(username: "u3", password: "pw3", newPassword: "pw4") {
                        token
                    }
                }"#,
            )
            .await;
        assert!(res.is_ok());

        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("u3").unwrap().unwrap();
        assert!(account.verify_password("pw4"));
    }

    #[tokio::test]
    async fn password_validate_proceed() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "u2",
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
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u2"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    signIn(username: "u2", password: "pw3") {
                        token
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
                        password: {
                            old: "oldpassword",
                            new: "oldpassword"
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

        // Try to update password with wrong old password (should fail)
        let res = schema
            .execute(
                r#"mutation {
                    updateAccount(
                        username: "testuser",
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

        // Try to update password with different new password (should succeed)
        let res = schema
            .execute(
                r#"mutation {
                    updateAccount(
                        username: "testuser",
                        password: {
                            old: "oldpassword",
                            new: "newpassword"
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateAccount: "testuser"}"#);

        // Verify the password was actually changed
        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("testuser").unwrap().unwrap();
        assert!(account.verify_password("newpassword"));
        assert!(!account.verify_password("oldpassword"));
    }

    #[tokio::test]
    async fn prevent_password_reuse_reset_admin_password() {
        let schema = TestSchema::new().await;

        // Create a system admin account
        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "admin_user",
                        password: "adminpassword",
                        role: "SYSTEM_ADMINISTRATOR",
                        name: "Admin User",
                        department: "Admin"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "admin_user"}"#);

        // Try to reset admin password with the same password (should fail)
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    resetAdminPassword(username: "admin_user", password: "adminpassword")
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
                    resetAdminPassword(username: "admin_user", password: "newadminpassword")
                }"#,
                RoleGuard::Local,
            )
            .await;

        assert_eq!(
            res.data.to_string(),
            r#"{resetAdminPassword: "admin_user"}"#
        );

        // Verify the password was actually changed
        let store = schema.store().await;
        let map = store.account_map();
        let account = map.get("admin_user").unwrap().unwrap();
        assert!(account.verify_password("newadminpassword"));
        assert!(!account.verify_password("adminpassword"));
    }
}
