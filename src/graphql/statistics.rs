use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Object, OutputType, Result, StringNumber,
    connection::{Connection, ConnectionNameType, Edge, EdgeNameType, EmptyFields},
    types::ID,
};
use chrono::{DateTime, NaiveDateTime};
use num_traits::ToPrimitive;
use review_database::BatchInfo;
use serde_json::Value as JsonValue;

use super::{Role, RoleGuard, slicing};
use crate::graphql::{query, query_with_constraints};

#[derive(Default)]
pub(super) struct StatisticsQuery;

#[Object]
impl StatisticsQuery {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn column_statistics(
        &self,
        ctx: &Context<'_>,
        model: ID,
        cluster: ID,
        time: Vec<NaiveDateTime>,
    ) -> Result<JsonValue> {
        let cluster = cluster.as_str().parse()?;
        let model = model.as_str().parse()?;
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.column_stats_map();
        let result = map.get_column_statistics(model, cluster, time)?;
        Ok(serde_json::to_value(result)?)
    }

    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn rounds_by_cluster(
        &self,
        ctx: &Context<'_>,
        model: ID,
        cluster: ID,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<
        Connection<
            OpaqueCursor<(u32, i64)>,
            Round,
            TotalCountByCluster,
            EmptyFields,
            RoundByCluster,
            RoundByClusterEdge,
        >,
    > {
        let cluster = cluster.as_str().parse()?;
        let model = model.as_str().parse()?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_rounds_by_cluster(ctx, model, cluster, after, before, first, last).await
            },
        )
        .await
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn rounds_by_model(
        &self,
        ctx: &Context<'_>,
        model: ID,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<
        Connection<OpaqueCursor<Vec<u8>>, Round, TotalCountByModel, EmptyFields, RoundByModel>,
    > {
        let model = model.as_str().parse()?;

        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_rounds_by_model(ctx, model, after, before, first, last).await
            },
        )
        .await
    }
}

struct TotalCountByCluster {
    model: u32,
    cluster: u32,
}

#[Object]
impl TotalCountByCluster {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.column_stats_map();
        Ok(map.count_rounds_by_cluster(i32::try_from(self.model)?, self.cluster)?)
    }
}

struct TotalCountByModel {
    model: u32,
}

#[Object]
impl TotalCountByModel {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        use num_traits::ToPrimitive;
        let store = super::get_store(ctx).await?;
        let map = store.batch_info_map();
        Ok(map
            .count(self.model)
            .map(|c| c.to_i64().unwrap_or_default())?)
    }
}

struct Round {
    inner: BatchInfo,
}

#[Object]
impl Round {
    async fn time(&self) -> NaiveDateTime {
        i64_to_naive_date_time(self.inner.inner.id)
    }

    /// The first event id in the round within a string represantable by a
    ///  `i64`.
    async fn first_event_id(&self) -> StringNumber<i64> {
        StringNumber(self.inner.inner.earliest)
    }

    /// The last event id in the round within a string represantable by a
    /// `i64`.
    async fn last_event_id(&self) -> StringNumber<i64> {
        StringNumber(self.inner.inner.latest)
    }
}

impl From<BatchInfo> for Round {
    fn from(inner: BatchInfo) -> Self {
        Self { inner }
    }
}

struct RoundByClusterEdge;

impl EdgeNameType for RoundByClusterEdge {
    fn type_name<T: OutputType>() -> String {
        "RoundByClusterEdge".to_string()
    }
}

async fn load_rounds_by_cluster(
    ctx: &Context<'_>,
    model: u32,
    cluster: u32,
    after: Option<OpaqueCursor<(u32, i64)>>,
    before: Option<OpaqueCursor<(u32, i64)>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<
    Connection<
        OpaqueCursor<(u32, i64)>,
        Round,
        TotalCountByCluster,
        EmptyFields,
        RoundByCluster,
        RoundByClusterEdge,
    >,
> {
    let is_first = first.is_some();
    let limit = slicing::len(first, last)?;
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.column_stats_map();
    let (_, batches) = map.load_rounds_by_cluster(
        model,
        cluster,
        &after.map(|k| i64_to_naive_date_time(k.0.1)),
        &before.map(|k| i64_to_naive_date_time(k.0.1)),
        is_first,
        limit + 1,
    )?;

    let (batches, has_previous, has_next) = slicing::page_info(is_first, limit, batches);
    let batch_infos: Vec<_> = {
        let store = super::get_store(ctx).await?;
        let map = store.batch_info_map();
        batches
            .into_iter()
            .take(limit)
            .filter_map(|t| t.and_utc().timestamp_nanos_opt())
            .filter_map(|t| {
                if let Ok(Some(b)) = map.get(model, t) {
                    Some(b)
                } else {
                    None
                }
            })
            .collect()
    };

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        TotalCountByCluster { model, cluster },
    );
    connection.edges.extend(
        batch_infos
            .into_iter()
            .map(|row| Edge::new(OpaqueCursor((cluster, row.inner.id)), row.into())),
    );
    Ok(connection)
}

async fn load_rounds_by_model(
    ctx: &Context<'_>,
    model: u32,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Round, TotalCountByModel, EmptyFields, RoundByModel>>
{
    let store = super::get_store(ctx).await?;
    let table = store.batch_info_map();
    super::load_edges(
        &table,
        after,
        before,
        first,
        last,
        TotalCountByModel { model },
    )
}

pub(super) fn i64_to_naive_date_time(t: i64) -> NaiveDateTime {
    const A_BILLION: i64 = 1_000_000_000;
    DateTime::from_timestamp(t / A_BILLION, (t % A_BILLION).to_u32().unwrap_or_default())
        .unwrap_or_default()
        .naive_utc()
}

struct RoundByCluster;

impl ConnectionNameType for RoundByCluster {
    fn type_name<T: crate::graphql::OutputType>() -> String {
        "RoundByClusterConnection".to_string()
    }
}

struct RoundByModel;

impl ConnectionNameType for RoundByModel {
    fn type_name<T: crate::graphql::OutputType>() -> String {
        "RoundByModelConnection".to_string()
    }
}
