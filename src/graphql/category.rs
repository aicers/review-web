use super::{slicing, Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    types::ID,
    Context, Object, Result,
};
use database::Store;
use review_database::{self as database};
use std::sync::Arc;
use tokio::sync::RwLock;

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
    ) -> Result<Connection<String, Category, CategoryTotalCount, EmptyFields>> {
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
pub(super) struct CategoryMutation;

#[Object]
impl CategoryMutation {
    /// Adds a new category.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn add_category(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.category_map();
        let id = map.insert(&name)?;
        Ok(ID(id.to_string()))
    }

    /// Updates the given category's name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_category(&self, ctx: &Context<'_>, id: ID, name: String) -> Result<ID> {
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let mut map = db.category_map();
        let id: u32 = id.as_str().parse()?;
        let old = map.get(id)?;
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
        let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
        let map = db.category_map();

        Ok(i64::try_from(map.count()?)?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Category, CategoryTotalCount, EmptyFields>> {
    let after = slicing::decode_cursor(&after)?.map(|(id, name)| {
        let id = u32::try_from(id).expect("id out of range");
        review_database::Category { id, name }
    });
    let before = slicing::decode_cursor(&before)?.map(|(id, name)| {
        let id = u32::try_from(id).expect("id out of range");
        review_database::Category { id, name }
    });
    let is_first = first.is_some();
    let limit = slicing::limit(first, last)?;
    let db = ctx.data::<Arc<RwLock<Store>>>()?.read().await;
    let map = db.category_map();
    let rows = map.get_range(after, before, is_first, limit + 1)?;

    let (rows, has_previous, has_next) = slicing::page_info(is_first, limit, rows);
    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, CategoryTotalCount);
    connection.edges.extend(rows.into_iter().map(|row| {
        let cursor =
            slicing::encode_cursor(i32::try_from(row.id).expect("id out of range"), &row.name);
        Edge::new(cursor, row.into())
    }));
    Ok(connection)
}
