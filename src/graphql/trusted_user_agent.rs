use super::{BoxedAgentManager, Role, RoleGuard};
use anyhow::Context as _;
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, Object, Result, SimpleObject,
};
use bincode::Options;
use chrono::{DateTime, Utc};
use database::types::FromKeyValue;
use review_database::{self as database, IterableMap, Store};
use std::sync::Arc;

#[derive(Default)]
pub(super) struct UserAgentQuery;

#[Object]
impl UserAgentQuery {
    /// A list of trusted user agent list.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn trusted_user_agent_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, TrustedUserAgent, TrustedUserAgentTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last) },
        )
        .await
    }
}

#[derive(Default)]
pub(super) struct UserAgentMutation;

#[Object]
impl UserAgentMutation {
    /// Inserts a new trusted user agents, Returns true if the insertion was successful.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_trusted_user_agents(
        &self,
        ctx: &Context<'_>,
        user_agents: Vec<String>,
    ) -> Result<bool> {
        let map = ctx.data::<Arc<Store>>()?.trusted_user_agent_map();
        for user_agent in user_agents {
            map.put(user_agent.as_bytes(), Utc::now().to_string().as_bytes())?;
        }
        Ok(true)
    }

    /// Removes a trusted user agents, Returns true if the deletion was successful.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_trusted_user_agents(
        &self,
        ctx: &Context<'_>,
        user_agents: Vec<String>,
    ) -> Result<bool> {
        let map = ctx.data::<Arc<Store>>()?.trusted_user_agent_map();
        for user_agent in user_agents {
            map.delete(user_agent.as_bytes())?;
        }
        Ok(true)
    }

    /// Updates the given trusted user agent.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_trusted_user_agent(
        &self,
        ctx: &Context<'_>,
        old: String,
        new: String,
    ) -> Result<bool> {
        let map = ctx.data::<Arc<Store>>()?.trusted_user_agent_map();
        let old_timestamp = map.get(old.as_bytes())?.unwrap();
        let new_timestamp = Utc::now().to_string();
        map.update(
            (old.as_bytes(), old_timestamp.as_ref()),
            (new.as_bytes(), new_timestamp.as_bytes()),
        )?;
        Ok(true)
    }

    /// Broadcast the trusted user agent list to all Hogs.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_trusted_user_agent(&self, ctx: &Context<'_>) -> Result<bool> {
        let db = ctx.data::<Arc<Store>>()?;
        let list = get_trusted_user_agent_list(db)?;
        let serialized_user_agent = bincode::DefaultOptions::new().serialize(&list)?;
        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        agent_manager
            .broadcast_trusted_user_agent_list(&serialized_user_agent)
            .await?;
        Ok(true)
    }
}

#[derive(SimpleObject)]
struct TrustedUserAgent {
    user_agent: String,
    updated_at: DateTime<Utc>,
}

impl FromKeyValue for TrustedUserAgent {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self, anyhow::Error> {
        let user_agent =
            String::from_utf8(key.to_vec()).context("invalid user-agent in database")?;
        let updated_at = String::from_utf8(value.to_vec())
            .context("invalid timestamp in database")?
            .parse()
            .context("invalid timestamp in database")?;
        Ok(TrustedUserAgent {
            user_agent,
            updated_at,
        })
    }
}

struct TrustedUserAgentTotalCount;

#[Object]
impl TrustedUserAgentTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let map = ctx.data::<Arc<Store>>()?.trusted_user_agent_map();
        let count = map.iter_forward()?.count();
        Ok(count)
    }
}

/// Returns the trusted user agent list.
///
/// # Errors
///
/// Returns an error if the user agent list database could not be retrieved.
pub fn get_trusted_user_agent_list(db: &Arc<Store>) -> Result<Vec<String>> {
    let map = db.trusted_user_agent_map();
    let mut user_agent_list = vec![];
    for (key, _value) in map.iter_forward()? {
        let user_agent = String::from_utf8(key.to_vec())?;
        user_agent_list.push(user_agent);
    }
    Ok(user_agent_list)
}

fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, TrustedUserAgent, TrustedUserAgentTotalCount, EmptyFields>> {
    let map = ctx.data::<Arc<Store>>()?.trusted_user_agent_map();
    super::load(&map, after, before, first, last, TrustedUserAgentTotalCount)
}
