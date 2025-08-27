use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Object, Result, SimpleObject,
    connection::{Connection, EmptyFields},
};
use chrono::{DateTime, Utc};
use database::{Iterable, event::Direction};
use review_database::{self as database, Store};

use super::{BoxedAgentManager, Role, RoleGuard};
use crate::graphql::query_with_constraints;

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
    ) -> Result<
        Connection<
            OpaqueCursor<Vec<u8>>,
            TrustedUserAgent,
            TrustedUserAgentTotalCount,
            EmptyFields,
        >,
    > {
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.trusted_user_agent_map();
        for user_agent in user_agents {
            let entry = database::TrustedUserAgent {
                user_agent,
                updated_at: Utc::now(),
            };
            map.put(&entry)?;
        }

        apply_trusted_user_agent_list(&store, ctx).await?;
        Ok(true)
    }

    /// Removes trusted user agents, returning the list of successfully removed user agents.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_trusted_user_agents(
        &self,
        ctx: &Context<'_>,
        user_agents: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.trusted_user_agent_map();

        let count = user_agents.len();
        let removed = user_agents
            .into_iter()
            .try_fold(Vec::with_capacity(count), |mut removed, user_agent| {
                if map.remove(&user_agent).is_ok() {
                    removed.push(user_agent);
                    Ok(removed)
                } else {
                    Err(removed)
                }
            })
            .unwrap_or_else(|r| r);

        if removed.is_empty() {
            return Err("None of the specified trusted user agents was removed.".into());
        }

        apply_trusted_user_agent_list(&store, ctx).await?;

        if removed.len() < count {
            return Err("Some trusted user agents were removed, but not all.".into());
        }

        Ok(removed)
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.trusted_user_agent_map();
        let new = database::TrustedUserAgent {
            user_agent: new,
            updated_at: Utc::now(),
        };
        map.update(&old, &new)?;

        apply_trusted_user_agent_list(&store, ctx).await?;
        Ok(true)
    }
}

#[derive(SimpleObject)]
struct TrustedUserAgent {
    user_agent: String,
    updated_at: DateTime<Utc>,
}

impl From<database::TrustedUserAgent> for TrustedUserAgent {
    fn from(input: database::TrustedUserAgent) -> Self {
        Self {
            user_agent: input.user_agent,
            updated_at: input.updated_at,
        }
    }
}

struct TrustedUserAgentTotalCount;

#[Object]
impl TrustedUserAgentTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.trusted_user_agent_map();

        Ok(map.iter(Direction::Forward, None).count())
    }
}

/// Returns the trusted user agent list.
///
/// # Errors
///
/// Returns an error if the user agent list database could not be retrieved.
fn get_trusted_user_agent_list(db: &Store) -> Result<Vec<String>> {
    let map = db.trusted_user_agent_map();
    Ok(map
        .iter(Direction::Forward, None)
        .map(|res| res.map(|entry| entry.user_agent))
        .collect::<Result<Vec<_>, anyhow::Error>>()?)
}

async fn apply_trusted_user_agent_list(store: &Store, ctx: &Context<'_>) -> Result<()> {
    let list = get_trusted_user_agent_list(store)?;
    let agent_manager = ctx.data::<BoxedAgentManager>()?;
    agent_manager
        .broadcast_trusted_user_agent_list(&list)
        .await
        .map_err(Into::into)
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<
    Connection<OpaqueCursor<Vec<u8>>, TrustedUserAgent, TrustedUserAgentTotalCount, EmptyFields>,
> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.trusted_user_agent_map();
    super::load_edges(&map, after, before, first, last, TrustedUserAgentTotalCount)
}
