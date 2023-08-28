use super::{Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    types::ID,
    Context, Enum, InputObject, Object, Result,
};
use review_database::{
    self as database, Indexed, IndexedMap, IndexedMapIterator, IndexedMapUpdate,
};

#[derive(Default)]
pub(super) struct DataSourceQuery;

#[Object]
impl DataSourceQuery {
    /// A list of data sources.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn data_source_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DataSource, DataSourceTotalCount, EmptyFields>> {
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

#[derive(InputObject)]
pub(super) struct DataSourceInsertInput {
    name: String,
    server_name: Option<String>,
    address: Option<String>,
    data_type: DataType,
    source: Option<String>,
    kind: Option<String>,
    description: String,
}

impl DataSourceInsertInput {
    const DEFAULT_DATA_SOURCE_ADDRESS: &str = "127.0.0.1:38371";
    const DEFAULT_SERVER_NAME: &str = "localhost";
}

impl TryFrom<DataSourceInsertInput> for database::DataSource {
    type Error = String;

    fn try_from(input: DataSourceInsertInput) -> Result<Self, Self::Error> {
        let data_type = database::DataType::from(input.data_type);
        let server_name = input
            .server_name
            .unwrap_or(DataSourceInsertInput::DEFAULT_SERVER_NAME.to_string());
        let address = input
            .address
            .as_ref()
            .map_or(DataSourceInsertInput::DEFAULT_DATA_SOURCE_ADDRESS, |s| {
                s.as_str()
            })
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("Invalid giganto address ({:?}): {e}", &input.address))?;
        if data_type != database::DataType::TimeSeries && input.kind.is_none() {
            return Err(format!("For {data_type:?} data, `kind` is required."));
        }

        Ok(database::DataSource {
            id: u32::MAX,
            name: input.name,
            server_name,
            address,
            data_type,
            source: input.source.unwrap_or(String::new()),
            kind: input.kind,
            description: input.description,
        })
    }
}

#[derive(Default)]
pub(super) struct DataSourceMutation;

#[Object]
impl DataSourceMutation {
    /// Inserts a new data source, returning the ID of the new data source.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn insert_data_source(
        &self,
        ctx: &Context<'_>,
        input: DataSourceInsertInput,
    ) -> Result<ID> {
        let value: database::DataSource = input.try_into()?;

        validate_policy(ctx, &value.source, value.data_type).await?;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.data_source_map();

        let id = map.insert(value)?;
        Ok(ID(id.to_string()))
    }

    /// Removes a data source, returning the name of the removed data source if
    /// it existed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn remove_data_source(&self, ctx: &Context<'_>, id: ID) -> Result<String> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.data_source_map();

        let key = map.remove(i)?;
        match String::from_utf8(key) {
            Ok(key) => Ok(key),
            Err(e) => Ok(String::from_utf8_lossy(e.as_bytes()).into()),
        }
    }

    /// Updates the given data source.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn update_data_source(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: DataSourceUpdateInput,
        new: DataSourceUpdateInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.data_source_map();

        map.update(i, &old, &new)?;
        Ok(id)
    }
}

pub(super) struct DataSource {
    inner: database::DataSource,
}

#[Object]
impl DataSource {
    /// The ID of the data source.
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    /// The name of the data source.
    async fn name(&self) -> &str {
        &self.inner.name
    }

    /// The server_name of the data source.
    async fn server_name(&self) -> &str {
        &self.inner.server_name
    }

    /// The socket address of the data source.
    async fn address(&self) -> String {
        self.inner.address.to_string()
    }

    /// The source for the data source in giganto.
    async fn data_type(&self) -> DataType {
        self.inner.data_type.into()
    }

    /// The policy of the data source.
    async fn policy(&self) -> Option<ID> {
        if DataType::TimeSeries == self.inner.data_type.into() {
            Some(ID(self.inner.source.clone()))
        } else {
            None
        }
    }

    /// The source for the data source in giganto.
    async fn source(&self) -> &str {
        &self.inner.source
    }

    /// The description of the data source.
    async fn description(&self) -> &str {
        &self.inner.description
    }

    /// The kind of the data source.
    async fn kind(&self) -> Option<&str> {
        self.inner.kind.as_deref()
    }
}

impl From<database::DataSource> for DataSource {
    fn from(inner: database::DataSource) -> Self {
        Self { inner }
    }
}

#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::DataType")]
enum DataType {
    /// comma-separated values
    Csv,
    /// line-based text data
    Log,
    /// time series data
    TimeSeries,
}

#[derive(InputObject)]
struct DataSourceUpdateInput {
    name: Option<String>,
    server_name: Option<String>,
    address: Option<String>,
    data_type: Option<DataType>,
    source: Option<String>,
    kind: Option<String>,
    description: Option<String>,
}

impl IndexedMapUpdate for DataSourceUpdateInput {
    type Entry = database::DataSource;

    fn key(&self) -> Option<&[u8]> {
        self.name.as_deref().map(str::as_bytes)
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(v) = self.name.as_deref() {
            value.name.clear();
            value.name.push_str(v);
        }

        if let Some(v) = self.server_name.as_deref() {
            value.server_name.clear();
            value.server_name.push_str(v);
        }
        if let Some(v) = self.address.as_deref() {
            let addr = v.parse()?;
            value.address = addr;
        }

        if let Some(v) = self.data_type {
            value.data_type = v.into();
        }

        if let Some(v) = self.source.as_deref() {
            value.source.clear();
            value.source.push_str(v);
        }
        if let Some(v) = self.kind.as_deref() {
            if value.data_type != database::DataType::TimeSeries {
                if let Some(s) = value.kind.as_mut() {
                    s.clear();
                    s.push_str(v);
                }
            }
        }

        if let Some(v) = self.description.as_deref() {
            value.description.clear();
            value.description.push_str(v);
        }

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if let Some(v) = self.name.as_deref() {
            if value.name != v {
                return false;
            }
        }
        if let Some(v) = self.server_name.as_deref() {
            if value.server_name != v {
                return false;
            }
        }
        if let Some(v) = self.address.as_deref() {
            if let Ok(v) = v.parse() {
                if value.address != v {
                    return false;
                }
            } else {
                return false;
            }
        }
        if let Some(v) = self.data_type {
            if value.data_type != v.into() {
                return false;
            }
        }

        if let Some(v) = self.source.as_deref() {
            if value.source != v {
                return false;
            }
        }
        if value.kind.as_deref() != self.kind.as_deref() {
            return false;
        }
        if let Some(v) = self.description.as_deref() {
            if value.description != v {
                return false;
            }
        }
        true
    }
}

struct DataSourceTotalCount;

#[Object]
impl DataSourceTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.data_source_map();

        Ok(map.count()?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, DataSource, DataSourceTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.data_source_map();

    super::load::<
        '_,
        IndexedMap,
        IndexedMapIterator,
        DataSource,
        database::DataSource,
        DataSourceTotalCount,
    >(&map, after, before, first, last, DataSourceTotalCount)
}

async fn validate_policy(ctx: &Context<'_>, policy: &str, kind: database::DataType) -> Result<()> {
    match kind {
        database::DataType::TimeSeries => {
            let policy = policy.parse::<u32>()?;
            let store = crate::graphql::get_store(ctx).await?;
            let map = store.sampling_policy_map();
            let Some(_value) = map.get_by_id(policy)? else {
                return Err("no such sampling policy".into());
            };
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn remove_data_source() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r#"{dataSourceList{edges{node{name}}}}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{dataSourceList: {edges: []}}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertDataSource(input: { name: "d1", dataType: "LOG", source: "test", kind: "Dns", description: "" })
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{insertDataSource: "0"}"#);
        let res = schema
            .execute(r#"{dataSourceList{edges{node{name}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{dataSourceList: {edges: [{node: {name: "d1"}}]}}"#
        );

        let res = schema
            .execute(r#"mutation { removeDataSource(id: "0") }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeDataSource: "d1"}"#);
        let res = schema
            .execute(r#"{dataSourceList{edges{node{name}}}}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{dataSourceList: {edges: []}}"#);
    }
}
