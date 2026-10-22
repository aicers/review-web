use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Object, OutputType, Result, StringNumber,
    connection::{Connection, ConnectionNameType, Edge, EdgeNameType, EmptyFields},
    types::ID,
};
use chrono::{DateTime, NaiveDateTime};
use num_traits::ToPrimitive;
use review_database::{BatchInfo, UniqueKey};
use serde_json::Value as JsonValue;

use super::{Role, RoleGuard, customer_access, slicing, training_result};
use crate::graphql::{query, query_with_constraints};

#[derive(Default)]
pub(super) struct StatisticsQuery;

#[Object]
impl StatisticsQuery {
    /// The column statistics of a cluster.
    ///
    /// With `previous`, those of the model's previous training result.
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
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
        #[graphql(default_with = "Some(false)")] previous: Option<bool>,
    ) -> Result<JsonValue> {
        let previous = previous.unwrap_or_default();
        let cluster = cluster.as_str().parse()?;
        let model = model.as_str().parse()?;
        customer_access::load_accessible_model(ctx, "model", model)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = training_result::column_stats_map(&store, previous);
        let result = map.get_column_statistics(model, cluster, time)?;
        Ok(serde_json::to_value(result)?)
    }

    /// The rounds of a cluster.
    ///
    /// With `previous`, those of the model's previous training result.
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
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
        #[graphql(default_with = "Some(false)")] previous: Option<bool>,
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
        let previous = previous.unwrap_or_default();
        let cluster = cluster.as_str().parse()?;
        let model = model.as_str().parse()?;
        customer_access::load_accessible_model(ctx, "model", model)?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_rounds_by_cluster(ctx, model, cluster, previous, after, before, first, last)
                    .await
            },
        )
        .await
    }

    /// The rounds of a model.
    ///
    /// With `previous`, those of the model's previous training result.
    /// An unknown model is refused with `extensions.code` `NOT_FOUND`, and a
    /// model of none of the caller's customers with `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    // Each argument is an argument of the GraphQL field.
    #[allow(clippy::too_many_arguments)]
    async fn rounds_by_model(
        &self,
        ctx: &Context<'_>,
        model: ID,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
        #[graphql(default_with = "Some(false)")] previous: Option<bool>,
    ) -> Result<
        Connection<OpaqueCursor<Vec<u8>>, Round, TotalCountByModel, EmptyFields, RoundByModel>,
    > {
        let previous = previous.unwrap_or_default();
        let model = model.as_str().parse()?;
        customer_access::load_accessible_model(ctx, "model", model)?;

        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_rounds_by_model(ctx, model, previous, after, before, first, last).await
            },
        )
        .await
    }
}

struct TotalCountByCluster {
    model: u32,
    cluster: u32,
    previous: bool,
}

#[Object]
impl TotalCountByCluster {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<i64>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = training_result::column_stats_map(&store, self.previous);
        Ok(StringNumber(
            map.count_rounds_by_cluster(self.model, self.cluster)?,
        ))
    }
}

struct TotalCountByModel {
    model: u32,
    previous: bool,
}

#[Object]
impl TotalCountByModel {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = super::get_store(ctx)?;
        let map = training_result::batch_info_map(&store, self.previous);
        Ok(StringNumber(map.count(self.model)?))
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

#[allow(clippy::too_many_arguments)]
async fn load_rounds_by_cluster(
    ctx: &Context<'_>,
    model: u32,
    cluster: u32,
    previous: bool,
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
    let store = crate::graphql::get_store(ctx)?;
    let map = training_result::column_stats_map(&store, previous);
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
        let map = training_result::batch_info_map(&store, previous);
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
        TotalCountByCluster {
            model,
            cluster,
            previous,
        },
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
    previous: bool,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Round, TotalCountByModel, EmptyFields, RoundByModel>>
{
    let store = super::get_store(ctx)?;
    let table = training_result::batch_info_map(&store, previous);
    // The model id's big-endian bytes lead every key of its rounds, so the
    // scan stays within the model's rows whatever the cursor.
    let (rows, has_previous, has_next) = super::load_edges_interim(
        &table,
        after,
        before,
        first,
        last,
        Some(&model.to_be_bytes()),
    )?;
    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        TotalCountByModel { model, previous },
    );
    connection.edges.extend(rows.into_iter().map(|row| {
        let key: Vec<u8> = row.unique_key();
        Edge::new(OpaqueCursor(key), row.into())
    }));
    Ok(connection)
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

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::graphql::model_test_support::{TestModel, data};
    use crate::graphql::{Role, TestSchema};

    const CUSTOMER_A: u32 = 1;
    const CUSTOMER_B: u32 = 2;

    /// The first event ids of the nodes of a `roundsByModel` response, with
    /// its page info and total count.
    struct Page {
        rounds: Vec<i64>,
        has_next: bool,
        has_previous: bool,
        start: Option<String>,
        end: Option<String>,
        total: String,
    }

    async fn page(schema: &TestSchema, model: u32, previous: bool, arguments: &str) -> Page {
        let query = format!(
            "{{ roundsByModel(model: {model}, previous: {previous}{arguments}) {{
                totalCount nodes {{ firstEventId }}
                pageInfo {{ hasNextPage hasPreviousPage startCursor endCursor }} }} }}"
        );
        let res = schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![CUSTOMER_A]))
            .await;
        let json = data(res);
        let connection = &json["roundsByModel"];
        let cursor = |name: &str| connection["pageInfo"][name].as_str().map(str::to_string);
        Page {
            rounds: connection["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|node| node["firstEventId"].as_str().unwrap().parse().unwrap())
                .collect(),
            has_next: connection["pageInfo"]["hasNextPage"] == Value::Bool(true),
            has_previous: connection["pageInfo"]["hasPreviousPage"] == Value::Bool(true),
            start: cursor("startCursor"),
            end: cursor("endCursor"),
            total: connection["totalCount"].as_str().unwrap().to_string(),
        }
    }

    /// Returns a cursor of a round of `model`, read by a System Administrator.
    async fn foreign_cursor(schema: &TestSchema, model: u32, previous: bool) -> String {
        let query = format!(
            "{{ roundsByModel(model: {model}, previous: {previous}, first: 1) {{
                pageInfo {{ endCursor }} }} }}"
        );
        let json = data(schema.execute_as_system_admin(&query).await);
        json["roundsByModel"]["pageInfo"]["endCursor"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn rounds_by_model_pages_only_the_model_rounds() {
        let schema = TestSchema::new().await;
        // Models whose ids sort before and after A's, each with rounds in the
        // current and the previous result.
        let (before, model_a, after) = {
            let store = schema.store();
            let mut ids = Vec::new();
            for (name, customer_id, offset) in [
                ("before", CUSTOMER_B, 0),
                ("model-a", CUSTOMER_A, 1_000),
                ("after", CUSTOMER_B, 2_000),
            ] {
                let previous: Vec<i64> = (1..=5).map(|i| offset + i).collect();
                let current: Vec<i64> = (11..=14).map(|i| offset + i).collect();
                let id = TestModel {
                    rounds: &previous,
                    ..TestModel::new(name, customer_id)
                }
                .replace(&store);
                TestModel {
                    rounds: &current,
                    ..TestModel::new(name, customer_id)
                }
                .replace(&store);
                ids.push(id);
            }
            (ids[0], ids[1], ids[2])
        };
        assert!(before < model_a && model_a < after);

        for (previous, expected) in [
            (false, vec![1_011, 1_012, 1_013, 1_014]),
            (true, vec![1_001, 1_002, 1_003, 1_004, 1_005]),
        ] {
            let total = expected.len().to_string();

            let first = page(&schema, model_a, previous, ", first: 2").await;
            assert_eq!(first.rounds, expected[..2]);
            assert!(first.has_next && !first.has_previous);
            assert_eq!(first.total, total);
            let mut forward = first.rounds;
            let mut cursor = first.end;
            loop {
                let arguments = format!(", first: 2, after: \"{}\"", cursor.unwrap());
                let next = page(&schema, model_a, previous, &arguments).await;
                assert_eq!(next.total, total);
                forward.extend(next.rounds);
                if !next.has_next {
                    break;
                }
                cursor = next.end;
            }
            assert_eq!(forward, expected, "previous: {previous}");

            let last = page(&schema, model_a, previous, ", last: 2").await;
            assert_eq!(last.rounds, expected[expected.len() - 2..]);
            assert!(last.has_previous && !last.has_next);
            let mut backward = last.rounds;
            let mut cursor = last.start;
            loop {
                let arguments = format!(", last: 2, before: \"{}\"", cursor.unwrap());
                let next = page(&schema, model_a, previous, &arguments).await;
                assert_eq!(next.total, total);
                let mut rounds = next.rounds;
                rounds.extend(backward);
                backward = rounds;
                if !next.has_previous {
                    break;
                }
                cursor = next.start;
            }
            assert_eq!(backward, expected, "previous: {previous}");

            for (other, arguments) in [(before, "first: 10, after"), (after, "last: 10, before")] {
                let cursor = foreign_cursor(&schema, other, previous).await;
                let arguments = format!(", {arguments}: \"{cursor}\"");
                let foreign = page(&schema, model_a, previous, &arguments).await;
                assert!(
                    foreign.rounds.iter().all(|round| expected.contains(round)),
                    "{:?}",
                    foreign.rounds
                );
                assert_eq!(foreign.total, total);
            }
        }
    }
}
