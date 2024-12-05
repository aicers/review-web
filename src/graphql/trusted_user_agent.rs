use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    connection::{Connection, EmptyFields},
    Context, Object, Result, SimpleObject,
};
use bincode::Options;
use chrono::{DateTime, Utc};
use database::{Direction, Iterable};
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
            let entry = review_database::TrustedUserAgent {
                user_agent,
                updated_at: Utc::now(),
            };
            map.put(&entry)?;
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.trusted_user_agent_map();
        for user_agent in user_agents {
            map.remove(&user_agent)?;
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.trusted_user_agent_map();
        let new = review_database::TrustedUserAgent {
            user_agent: new,
            updated_at: Utc::now(),
        };

        map.update(&old, &new)?;
        Ok(true)
    }

    /// Broadcast the trusted user agent list to all Hogs.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_trusted_user_agent(&self, ctx: &Context<'_>) -> Result<bool> {
        let store = crate::graphql::get_store(ctx).await?;
        let list = get_trusted_user_agent_list(&store)?;
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

impl From<review_database::TrustedUserAgent> for TrustedUserAgent {
    fn from(input: review_database::TrustedUserAgent) -> Self {
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
pub fn get_trusted_user_agent_list(db: &Store) -> Result<Vec<String>> {
    let map = db.trusted_user_agent_map();
    Ok(map
        .iter(Direction::Forward, None)
        .map(|res| res.map(|entry| entry.user_agent))
        .collect::<Result<Vec<_>, anyhow::Error>>()?)
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
