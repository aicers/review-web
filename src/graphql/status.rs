use std::sync::Arc;
use std::sync::RwLock;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Object, Result, StringNumber,
    connection::{Connection, EmptyFields},
    types::ID,
};
use database::Store;
use review_database::{self as database};

use super::{Role, RoleGuard};
use crate::graphql::query_with_constraints;

#[derive(Default)]
pub(super) struct StatusQuery;

#[Object]
impl StatusQuery {
    /// A list of statuses.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn statuses(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Status, StatusTotalCount, EmptyFields>> {
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
pub(super) struct StatusMutation;

#[Object]
impl StatusMutation {
    /// Adds a new status.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn add_status(&self, ctx: &Context<'_>, description: String) -> Result<ID> {
        let db = ctx
            .data::<Arc<RwLock<Store>>>()?
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        let map = db.status_map();
        Ok(ID(map.insert(&description)?.to_string()))
    }

    /// Updates the given status's description.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_status(&self, ctx: &Context<'_>, id: ID, description: String) -> Result<ID> {
        let db = ctx
            .data::<Arc<RwLock<Store>>>()?
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        let mut map = db.status_map();
        let id: u32 = id.as_str().parse()?;
        let Some(old) = map.get_by_id(id)? else {
            return Err("no such status".into());
        };
        map.update(id, &old.description, &description)?;
        Ok(ID(id.to_string()))
    }
}

pub(super) struct Status {
    inner: database::Status,
}

#[Object]
impl Status {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }
}

impl From<database::Status> for Status {
    fn from(inner: database::Status) -> Self {
        Self { inner }
    }
}

struct StatusTotalCount;

#[Object]
impl StatusTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let db = ctx
            .data::<Arc<RwLock<Store>>>()?
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        let map = db.status_map();
        Ok(StringNumber(map.count()?))
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Status, StatusTotalCount, EmptyFields>> {
    let store = super::get_store(ctx)?;
    let table = store.status_map();
    super::load_edges(&table, after, before, first, last, StatusTotalCount)
}
