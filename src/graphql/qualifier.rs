use std::sync::Arc;

use async_graphql::{
    connection::{query, Connection, EmptyFields},
    types::ID,
    Context, Object, Result,
};
use database::Store;
use review_database::{self as database};
use tokio::sync::RwLock;

use super::{Role, RoleGuard};

#[derive(Default)]
pub(super) struct QualifierQuery;

#[Object]
impl QualifierQuery {
    /// A list of qualifiers.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn qualifiers(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Qualifier, QualifierTotalCount, EmptyFields>> {
        query(
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
pub(super) struct QualifierMutation;

#[Object]
impl QualifierMutation {
    /// Adds a new qualifier.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn add_qualifier(&self, ctx: &Context<'_>, description: String) -> Result<ID> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.qualifier_map();
        Ok(ID(map.insert(&description)?.to_string()))
    }

    /// Updates the given qualifier's description.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_qualifier(&self, ctx: &Context<'_>, id: ID, description: String) -> Result<ID> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let mut map = db.qualifier_map();
        let id: u32 = id.as_str().parse()?;
        let Some(old) = map.get_by_id(id)? else {
            return Err("no such qualifier".into());
        };
        map.update(id, &old.description, &description)?;
        Ok(ID(id.to_string()))
    }
}

pub(super) struct Qualifier {
    inner: database::Qualifier,
}

#[Object]
impl Qualifier {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }
}

impl From<database::Qualifier> for Qualifier {
    fn from(inner: database::Qualifier) -> Self {
        Self { inner }
    }
}

struct QualifierTotalCount;

#[Object]
impl QualifierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.qualifier_map();
        Ok(i64::try_from(map.count()?)?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Qualifier, QualifierTotalCount, EmptyFields>> {
    let store = super::get_store(ctx).await?;
    let table = store.qualifier_map();
    super::load_edges(&table, after, before, first, last, QualifierTotalCount)
}
