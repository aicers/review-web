use super::RoleGuard;
use crate::auth::{create_token, decode_token, insert_token, revoke_token, update_jwt_expires_in};
use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, Enum, InputObject, Object, Result, SimpleObject,
};
use bincode::Options;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use review_database::{
    self as database,
    types::{self},
    Direction, Iterable, Store,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    net::{AddrParseError, IpAddr},
};
use tracing::info;

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
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// Returns the list of accounts who have signed in.
    #[graphql(guard = "RoleGuard::new(super::Role::SystemAdministrator)
        .or(RoleGuard::new(super::Role::SecurityAdministrator))")]
    async fn signed_in_account_list(&self, ctx: &Context<'_>) -> Result<Vec<SignedInAccount>> {
        use review_database::Iterable;
        use std::collections::HashMap;

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
        allow_access_from: Option<Vec<String>>,
        max_parallel_sessions: Option<u32>,
    ) -> Result<String> {
        let store = crate::graphql::get_store(ctx).await?;
        let table = store.account_map();
        if table.contains(&username)? {
            return Err("account already exists".into());
        }
        let allow_access_from = if let Some(ipaddrs) = allow_access_from {
            let ipaddrs = strings_to_ipaddrs(&ipaddrs)?;
            Some(ipaddrs)
        } else {
            None
        };
        let account = types::Account::new(
            &username,
            &password,
            database::Role::from(role),
            name,
            department,
            allow_access_from,
            max_parallel_sessions,
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
                map.update(
                    username.as_bytes(),
                    &Some(password),
                    None,
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

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
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
        let store = crate::graphql::get_store(ctx).await?;
        let account_map = store.account_map();

        if let Some(mut account) = account_map.get(&username)? {
            if account.verify_password(&password) {
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
                let (token, expiration_time) =
                    create_token(account.username.clone(), account.role.to_string())?;
                account.update_last_signin_time();
                account_map.put(&account)?;

                insert_token(&store, &token, &username)?;

                info!("{} signed in", username);
                Ok(AuthPayload {
                    token,
                    expiration_time,
                })
            } else {
                info!("wrong password for {username}");
                Err("incorrect username or password".into())
            }
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
        if let Err(e) = revoke_token(&store, &token) {
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
        if let Some(value) = map.get(ACCOUNT_POLICY_KEY)? {
            let codec = bincode::DefaultOptions::new();
            let mut policy = codec.deserialize::<AccountPolicy>(value.as_ref())?;
            policy.expiration_time = expires_in.into();
            let new_value = codec.serialize(&policy)?;
            map.update(
                (ACCOUNT_POLICY_KEY, value.as_ref()),
                (ACCOUNT_POLICY_KEY, &new_value),
            )?;
        } else {
            init_expiration_time(&store, expires_in)?;
        }
        update_jwt_expires_in(expires_in)?;
        Ok(time)
    }
}

/// Returns the expiration time according to the account policy.
///
/// # Errors
///
/// Returns an error if the account policy is not found or the value is
/// corrupted.
pub fn expiration_time(store: &Store) -> Result<i64> {
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
pub fn init_expiration_time(store: &Store, time: u32) -> anyhow::Result<()> {
    let map = store.account_policy_map();
    let policy = AccountPolicy {
        expiration_time: time.into(),
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
        use database::Iterable;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.account_map();
        let count = map.iter(Direction::Forward, None).count();
        Ok(count)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Account, AccountTotalCount, EmptyFields>> {
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
    let (username, password) = read_review_admin()?;

    let initial_account = review_database::types::Account::new(
        &username,
        &password,
        database::Role::SystemAdministrator,
        "System Administrator".to_owned(),
        String::new(),
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
    use crate::graphql::{
        account::{read_review_admin, REVIEW_ADMIN},
        RoleGuard, TestSchema,
    };
    use async_graphql::Value;
    use review_database::Role;
    use serial_test::serial;
    use std::env;

    #[tokio::test]
    #[serial]
    async fn pagination() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let schema = TestSchema::new().await;
        let res = schema.execute(r#"{accountList{totalCount}}"#).await;
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {:?}", res);
        };
        let Some(Value::Object(account_list)) = retval.get("accountList") else {
            panic!("unexpected response: {:?}", retval);
        };
        let Some(Value::Number(total_count)) = account_list.get("totalCount") else {
            panic!("unexpected response: {:?}", account_list);
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
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u4"}"#);

        // Retrieve the first page.
        let res = schema
            .execute(
                r#"query {
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
                }"#,
            )
            .await;

        // Check if `first` works.
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {:?}", res);
        };
        let Some(Value::Object(account_list)) = retval.get("accountList") else {
            panic!("unexpected response: {:?}", retval);
        };
        let Some(Value::List(edges)) = account_list.get("edges") else {
            panic!("unexpected response: {:?}", account_list);
        };
        assert_eq!(edges.len(), 2);
        let Some(Value::Object(page_info)) = account_list.get("pageInfo") else {
            panic!("unexpected response: {:?}", account_list);
        };
        let Some(Value::Boolean(has_next_page)) = page_info.get("hasNextPage") else {
            panic!("unexpected response: {:?}", page_info);
        };
        assert_eq!(*has_next_page, true);
        let Some(Value::String(end_cursor)) = page_info.get("endCursor") else {
            panic!("unexpected response: {:?}", page_info);
        };

        // The first edge should be "admin".
        let Some(Value::Object(edge)) = edges.get(0) else {
            panic!("unexpected response: {:?}", edges);
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {:?}", edge);
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {:?}", node);
        };
        assert_eq!(username, "admin");

        // The last edge should be "u1".
        let Some(Value::Object(edge)) = edges.get(1) else {
            panic!("unexpected response: {:?}", edges);
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {:?}", edge);
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {:?}", node);
        };
        assert_eq!(username, "u1");
        let Some(Value::String(cursor)) = edge.get("cursor") else {
            panic!("unexpected response: {:?}", edge);
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
            panic!("unexpected response: {:?}", res);
        };
        let Some(Value::Object(account_list)) = retval.get("accountList") else {
            panic!("unexpected response: {:?}", retval);
        };
        let Some(Value::List(edges)) = account_list.get("edges") else {
            panic!("unexpected response: {:?}", account_list);
        };
        assert_eq!(edges.len(), 3); // The number of remaining accounts.
        let Some(Value::Object(page_info)) = account_list.get("pageInfo") else {
            panic!("unexpected response: {:?}", account_list);
        };
        let Some(Value::Boolean(has_next_page)) = page_info.get("hasNextPage") else {
            panic!("unexpected response: {:?}", page_info);
        };
        assert_eq!(*has_next_page, false);

        // The first edge should be "u2".
        let Some(Value::Object(edge)) = edges.get(0) else {
            panic!("unexpected response: {:?}", edges);
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {:?}", edge);
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {:?}", node);
        };
        assert_eq!(username, "u2");

        // The last edge should be "u4".
        let Some(Value::Object(edge)) = edges.get(2) else {
            panic!("unexpected response: {:?}", edges);
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {:?}", edge);
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {:?}", node);
        };
        assert_eq!(username, "u4");

        // Record the cursor of the last edge.
        let Some(Value::String(cursor)) = edge.get("cursor") else {
            panic!("unexpected response: {:?}", edge);
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
            panic!("unexpected response: {:?}", res);
        };
        let Some(Value::Object(account_list)) = retval.get("accountList") else {
            panic!("unexpected response: {:?}", retval);
        };
        let Some(Value::List(edges)) = account_list.get("edges") else {
            panic!("unexpected response: {:?}", account_list);
        };
        assert_eq!(edges.len(), 3);
        let Some(Value::Object(page_info)) = account_list.get("pageInfo") else {
            panic!("unexpected response: {:?}", account_list);
        };
        let Some(Value::Boolean(has_previous_page)) = page_info.get("hasPreviousPage") else {
            panic!("unexpected response: {:?}", page_info);
        };
        assert_eq!(*has_previous_page, true);

        // The first edge should be "u1".
        let Some(Value::Object(edge)) = edges.get(0) else {
            panic!("unexpected response: {:?}", edges);
        };
        let Some(Value::Object(node)) = edge.get("node") else {
            panic!("unexpected response: {:?}", edge);
        };
        let Some(Value::String(username)) = node.get("username") else {
            panic!("unexpected response: {:?}", node);
        };
        assert_eq!(username, "u1");

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn remove_accounts() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

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

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn default_account() {
        let original_review_admin = backup_and_set_review_admin();
        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

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

        restore_review_admin(original_review_admin);
    }

    #[tokio::test]
    #[serial]
    async fn test_read_review_admin() {
        let original_review_admin = backup_and_set_review_admin();

        assert_eq!(env::var(REVIEW_ADMIN), Ok("admin:admin".to_string()));

        let result = read_review_admin();
        assert_eq!(result.unwrap(), ("admin".to_string(), "admin".to_string()));

        // Set the temporary `REVIEW_ADMIN` with invalid format
        env::set_var(REVIEW_ADMIN, "adminadmin");

        assert_eq!(env::var(REVIEW_ADMIN), Ok("adminadmin".to_string()));

        let result = read_review_admin();
        assert!(result.is_err());

        // Unset the `REVIEW_ADMIN`
        env::remove_var(REVIEW_ADMIN);

        assert!(env::var(REVIEW_ADMIN).is_err());

        let result = read_review_admin();
        assert!(result.is_err());

        restore_review_admin(original_review_admin);
    }

    fn backup_and_set_review_admin() -> Option<String> {
        let original_review_admin = env::var(REVIEW_ADMIN).ok();
        env::set_var(REVIEW_ADMIN, "admin:admin");
        original_review_admin
    }

    fn restore_review_admin(original_review_admin: Option<String>) {
        if let Some(value) = original_review_admin {
            env::set_var(REVIEW_ADMIN, value);
        } else {
            env::remove_var(REVIEW_ADMIN);
        }
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
                        department: "Security"
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
                        department: "Admin"
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
        assert_eq!(res.data.to_string(), r#"null"#);

        let res = schema
            .execute_with_guard(
                r#"mutation {
                resetAdminPassword(username: "u3", password: "user not existed")
            }"#,
                RoleGuard::Local,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"null"#);

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
        assert_eq!(res.data.to_string(), r#"null"#);
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
                        department: "Test"
                        maxParallelSessions: 2
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertAccount: "u1"}"#);

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
                r#"query {
                    signedInAccountList {
                        username
                    }
                }"#,
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
        assert_eq!(res.data.to_string(), r#"null"#);
    }
}
