use super::RoleGuard;
use crate::auth::{create_token, decode_token, insert_token, revoke_token, update_jwt_expires_in};
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, Enum, InputObject, Object, Result, SimpleObject,
};
use bincode::Options;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use review_database::{
    self as database,
    types::PasswordHashAlgorithm,
    types::{self, SaltedPassword},
    IterableMap, MapIterator, Store, Table,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::{AddrParseError, IpAddr},
    sync::Arc,
};

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Serialize, SimpleObject)]
pub struct SignedInAccount {
    username: String,
    expire_times: Vec<DateTime<Utc>>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Deserialize, Serialize)]
pub struct AccountPolicy {
    pub expiration_time: i64,
}

const ACCOUNT_POLICY_KEY: &[u8] = b"account policy key";

#[derive(Default)]
pub(super) struct AccountQuery;

#[Object]
impl AccountQuery {
    /// Looks up an account by the given username.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn account(&self, ctx: &Context<'_>, username: String) -> Result<Account> {
        let map = ctx.data::<Arc<Store>>()?.account_map();
        let inner = map
            .get(&username)?
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
    ) -> Result<Connection<String, Account, AccountTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last) },
        )
        .await
    }

    /// Returns the list of accounts who have signed in.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn signed_in_account_list(&self, ctx: &Context<'_>) -> Result<Vec<SignedInAccount>> {
        let map = ctx.data::<Arc<Store>>()?.access_token_map();

        let signed = map
            .iter_forward()?
            .filter_map(|(key, value)| {
                bincode::DefaultOptions::new()
                    .deserialize::<HashSet<String>>(&value)
                    .ok()
                    .map(|tokens| SignedInAccount {
                        username: String::from_utf8_lossy(&key).into_owned(),
                        expire_times: tokens
                            .iter()
                            .filter_map(|token| {
                                decode_token(token).ok().and_then(|decoded| {
                                    let time = Utc.timestamp_nanos(decoded.exp * 1_000_000_000);
                                    if Utc::now() < time {
                                        Some(time)
                                    } else {
                                        None
                                    }
                                })
                            })
                            .collect::<Vec<DateTime<Utc>>>(),
                    })
            })
            .collect::<Vec<SignedInAccount>>();

        Ok(signed)
    }

    /// Returns how long signing in lasts in seconds
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn expiration_time(&self, ctx: &Context<'_>) -> Result<i64> {
        let store = ctx.data::<Arc<Store>>()?;
        expiration_time(store)
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
        allow_access_from: Option<Vec<String>>,
        max_parallel_sessions: Option<u32>,
    ) -> Result<String> {
        let table = ctx.data::<Arc<Store>>()?.account_map();
        if table.contains(&username)? {
            return Err("account already exists".into());
        }
        let salted_password = SaltedPassword::new(&password)?;
        let allow_access_from = if let Some(ipaddrs) = allow_access_from {
            let ipaddrs = strings_to_ipaddrs(&ipaddrs)?;
            Some(ipaddrs)
        } else {
            None
        };
        let account = types::Account {
            username: username.clone(),
            password: salted_password,
            role: database::Role::from(role),
            name,
            department,
            creation_time: Utc::now(),
            last_signin_time: None as Option<DateTime<Utc>>,
            allow_access_from,
            max_parallel_sessions,
            password_hash_algorithm: PasswordHashAlgorithm::Pbkdf2HmacSha512,
        };
        table.put(&account)?;
        Ok(username)
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
        let map = ctx.data::<Arc<Store>>()?.account_map();
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
        password: Option<String>,
        role: Option<UpdateRole>,
        name: Option<UpdateName>,
        department: Option<UpdateDepartment>,
        allow_access_from: Option<UpdateAllowAccessFrom>,
        max_parallel_sessions: Option<UpdateMaxParallelSessions>,
    ) -> Result<String> {
        if password.is_none()
            && role.is_none()
            && name.is_none()
            && department.is_none()
            && allow_access_from.is_none()
            && max_parallel_sessions.is_none()
        {
            return Err("At lease one of the optional fields must be provided to update.".into());
        }

        let role = role.map(|r| (database::Role::from(r.old), database::Role::from(r.new)));
        let name = name.map(|n| (n.old, n.new));
        let dept = department.map(|d| (d.old, d.new));
        let allow_access_from = if let Some(ipaddrs) = allow_access_from {
            let old = if let Some(old) = ipaddrs.old {
                Some(strings_to_ipaddrs(&old)?)
            } else {
                None
            };
            let new = if let Some(new) = ipaddrs.new {
                Some(strings_to_ipaddrs(&new)?)
            } else {
                None
            };
            Some((old, new))
        } else {
            None
        };
        let max_parallel_sessions = max_parallel_sessions.map(|m| (m.old, m.new));

        let map = ctx.data::<Arc<Store>>()?.account_map();
        map.update(
            username.as_bytes(),
            &password,
            role,
            &name,
            &dept,
            &allow_access_from,
            &max_parallel_sessions,
        )?;
        Ok(username)
    }

    /// Authenticates with the given username and password
    async fn sign_in(
        &self,
        ctx: &Context<'_>,
        username: String,
        password: String,
    ) -> Result<AuthPayload> {
        let store = ctx.data::<Arc<Store>>()?;
        let account_map = store.account_map();
        let mut account = account_map
            .get(&username)?
            .ok_or_else::<async_graphql::Error, _>(|| "incorrect username or password".into())?;

        if account.password.is_match(&password) {
            let (token, expiration_time) =
                create_token(account.username.clone(), account.role.to_string())?;
            account.last_signin_time = Some(Utc::now());
            account_map.put(&account)?;
            insert_token(store, &token, &username)?;

            Ok(AuthPayload {
                token,
                expiration_time,
            })
        } else {
            Err("incorrect username or password".into())
        }
    }

    /// Revokes the given access token
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn sign_out(&self, ctx: &Context<'_>, token: String) -> Result<String> {
        let store = ctx.data::<Arc<Store>>()?;
        revoke_token(store, &token)?;
        Ok(token)
    }

    /// Obtains a new access token with renewed expiration time. The given
    /// access token will be revoked.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))
        .or(RoleGuard::new(super::Role::SecurityManager))
        .or(RoleGuard::new(super::Role::SecurityMonitor))")]
    async fn refresh_token(&self, ctx: &Context<'_>, token: String) -> Result<AuthPayload> {
        let store = ctx.data::<Arc<Store>>()?;
        let decoded_token = decode_token(&token)?;
        let username = decoded_token.sub;
        let (new_token, expiration_time) = create_token(username.clone(), decoded_token.role)?;
        insert_token(store, &new_token, &username)?;
        if let Err(e) = revoke_token(store, &token) {
            revoke_token(store, &new_token)?;
            Err(e.into())
        } else {
            Ok(AuthPayload {
                token: new_token,
                expiration_time,
            })
        }
    }

    /// Updates how long signing in lasts in seconds
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn update_expiration_time(&self, ctx: &Context<'_>, time: i64) -> Result<i64> {
        let store = ctx.data::<Arc<Store>>()?;
        let map = store.account_policy_map();
        if let Some(value) = map.get(ACCOUNT_POLICY_KEY)? {
            let codec = bincode::DefaultOptions::new();
            let mut policy = codec.deserialize::<AccountPolicy>(value.as_ref())?;
            policy.expiration_time = time;
            let new_value = codec.serialize(&policy)?;
            map.update(
                (ACCOUNT_POLICY_KEY, value.as_ref()),
                (ACCOUNT_POLICY_KEY, &new_value),
            )?;
        } else {
            init_expiration_time(store, time)?;
        }
        update_jwt_expires_in(time)?;
        Ok(time)
    }
}

/// Returns the expiration time according to the account policy.
///
/// # Errors
///
/// Returns an error if the account policy is not found or the value is
/// corrupted.
pub fn expiration_time(store: &Arc<Store>) -> Result<i64> {
    let map = store.account_policy_map();
    let value = map
        .get(ACCOUNT_POLICY_KEY)?
        .ok_or_else::<async_graphql::Error, _>(|| "incorrect account policy key".into())?;
    let exp = bincode::DefaultOptions::new()
        .deserialize::<AccountPolicy>(value.as_ref())?
        .expiration_time;
    Ok(exp)
}

/// Initializes the account policy with the given expiration time.
///
/// # Errors
///
/// Returns an error if the value cannot be serialized or the underlaying store
/// fails to put the value.
pub fn init_expiration_time(store: &Arc<Store>, time: i64) -> anyhow::Result<()> {
    let map = store.account_policy_map();
    let policy = AccountPolicy {
        expiration_time: time,
    };
    let value = bincode::DefaultOptions::new().serialize(&policy)?;
    map.put(ACCOUNT_POLICY_KEY, &value)?;
    Ok(())
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

    async fn creation_time(&self) -> DateTime<Utc> {
        self.inner.creation_time
    }

    async fn last_signin_time(&self) -> Option<DateTime<Utc>> {
        self.inner.last_signin_time
    }

    async fn allow_access_from(&self) -> Option<Vec<String>> {
        self.inner
            .allow_access_from
            .as_ref()
            .map(|ips| ips.iter().map(ToString::to_string).collect::<Vec<String>>())
    }

    async fn max_parallel_sessions(&self) -> Option<u32> {
        self.inner.max_parallel_sessions
    }
}

impl From<types::Account> for Account {
    fn from(account: types::Account) -> Self {
        Self { inner: account }
    }
}

fn strings_to_ipaddrs(ipaddrs: &[String]) -> Result<Vec<IpAddr>, AddrParseError> {
    let mut ipaddrs = ipaddrs
        .iter()
        .map(|ipaddr| ipaddr.parse::<IpAddr>())
        .collect::<Result<Vec<_>, _>>()?;
    ipaddrs.sort();
    Ok(ipaddrs)
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

/// The old and new values of `allowAccessFrom` to update.
#[derive(InputObject)]
struct UpdateAllowAccessFrom {
    old: Option<Vec<String>>,
    new: Option<Vec<String>>,
}

/// The old and new values of `maxParallelSessions` to update.
#[derive(InputObject)]
struct UpdateMaxParallelSessions {
    old: Option<u32>,
    new: Option<u32>,
}

struct AccountTotalCount;

#[Object]
impl AccountTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let map = ctx.data::<Arc<Store>>()?.account_map();
        let count = map.iter_forward()?.count();
        Ok(count)
    }
}

fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Account, AccountTotalCount, EmptyFields>> {
    let map = ctx.data::<Arc<Store>>()?.account_map();
    super::load::<'_, Table<types::Account>, MapIterator, Account, types::Account, AccountTotalCount>(
        &map,
        after,
        before,
        first,
        last,
        AccountTotalCount,
    )
}

/// Sets the initial administrator password.
///
/// This function is called only once when the database is opened.
///
/// # Errors
///
/// This function returns an error if the initial administrator password is already set, or if it
/// fails to generate random bytes for password.
pub fn set_initial_admin_password(store: &Store) -> anyhow::Result<()> {
    let map = store.account_map();
    let account = initial_credential()?;
    map.insert(&account)
}

/// Resets the administrator password to the initial value.
///
/// # Errors
///
/// This function returns an error if it fails to generate random bytes for password.
pub fn reset_admin_password(store: &Store) -> anyhow::Result<()> {
    let map = store.account_map();
    let account = initial_credential()?;
    map.put(&account)
}

/// Returns the initial administrator username and salted password.
///
/// # Errors
///
/// This function returns an error if it fails to generate random bytes for password.
fn initial_credential() -> anyhow::Result<types::Account> {
    const INITIAL_ADMINISTRATOR_ID: &str = "admin";
    const INITIAL_ADMINISTRATOR_PASSWORD: &str = "admin";

    let salted_password = SaltedPassword::new(INITIAL_ADMINISTRATOR_PASSWORD)?;

    let initial_account = review_database::types::Account {
        username: INITIAL_ADMINISTRATOR_ID.to_string(),
        password: salted_password,
        role: database::Role::SystemAdministrator,
        name: "System Administrator".to_owned(),
        department: String::new(),
        creation_time: Utc::now(),
        last_signin_time: None,
        allow_access_from: None,
        max_parallel_sessions: None,
        password_hash_algorithm: review_database::types::PasswordHashAlgorithm::default(),
    };

    Ok(initial_account)
}

#[cfg(test)]
mod tests {
    use async_graphql::Value;

    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn remove_accounts() {
        let schema = TestSchema::new().await;
        let res = schema.execute(r#"{accountList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{accountList: {totalCount: 1}}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertAccount(
                        username: "u1",
                        password: "Ahh9booH",
                        role: "SECURITY_ADMINISTRATOR",
                        name: "John Doe",
                        department: "Security"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u1"}"#);

        let res = schema
            .execute(r#"{accountList{edges{node{username}}totalCount}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{accountList: {edges: [{node: {username: "admin"}},{node: {username: "u1"}}],totalCount: 2}}"#
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

        let res = schema.execute(r#"{accountList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{accountList: {totalCount: 1}}"#);
    }

    #[tokio::test]
    async fn default_account() {
        let schema = TestSchema::new().await;
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
            panic!("unexpected response: {:?}", res);
        };
        assert_eq!(retval.len(), 1);
        let Value::Object(map) = retval.get("signIn").unwrap() else {
            panic!("unexpected response: {:?}", retval);
        };
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("token"));

        let res = schema
            .execute(
                r#"query {
                    signedInAccountList {
                        username
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{signedInAccountList: [{username: "admin"}]}"#
        );
    }

    #[tokio::test]
    async fn expiration_time() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                r#"mutation {
                    updateExpirationTime(time: 120)
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateExpirationTime: 120}"#);

        let res = schema
            .execute(
                r#"query {
                    expirationTime
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{expirationTime: 120}"#);
    }
}
