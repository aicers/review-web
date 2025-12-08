use std::sync::Arc;
use std::sync::RwLock;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Object, Result,
    connection::{Connection, EmptyFields},
    types::ID,
};
use database::Store;
use review_database::{self as database};

use super::{Role, RoleGuard};
use crate::graphql::query_with_constraints;

#[derive(Default)]
pub(super) struct CategoryQuery;

#[Object]
impl CategoryQuery {
    /// A list of available alert categories.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn categories(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Category, CategoryTotalCount, EmptyFields>> {
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
pub(super) struct CategoryMutation;

#[Object]
impl CategoryMutation {
    /// Adds a new category.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn add_category(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let db = ctx
            .data::<Arc<RwLock<Store>>>()?
            .read()
            .expect("the Store is always readable due to controlled write access");
        let map = db.category_map();
        let id = map.insert(&name)?;
        Ok(ID(id.to_string()))
    }

    /// Updates the given category's name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_category(&self, ctx: &Context<'_>, id: ID, name: String) -> Result<ID> {
        let db = ctx
            .data::<Arc<RwLock<Store>>>()?
            .read()
            .expect("the Store is always readable due to controlled write access");
        let mut map = db.category_map();
        let id: u32 = id.as_str().parse()?;
        let Some(old) = map.get_by_id(id)? else {
            return Err("no such category".into());
        };
        map.update(id, &old.name, &name)?;
        Ok(ID(id.to_string()))
    }
}

/// A category for a cluster.
pub(super) struct Category {
    inner: database::Category,
}

#[Object]
impl Category {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }
}

impl From<database::Category> for Category {
    fn from(inner: database::Category) -> Self {
        Self { inner }
    }
}

struct CategoryTotalCount;

#[Object]
impl CategoryTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        let db = ctx
            .data::<Arc<RwLock<Store>>>()?
            .read()
            .expect("the Store is always readable due to controlled write access");
        let map = db.category_map();

        Ok(i64::try_from(map.count()?)?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Category, CategoryTotalCount, EmptyFields>> {
    let store = super::get_store(ctx)?;
    let table = store.category_map();
    super::load_edges(&table, after, before, first, last, CategoryTotalCount)
}
