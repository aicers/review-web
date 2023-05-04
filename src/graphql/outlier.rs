use std::sync::Arc;

use super::{model::Model, slicing, Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    types::ID,
    ComplexObject, Context, InputObject, Object, Result, SimpleObject,
};
use bincode::Options;
use chrono::{offset::LocalResult, DateTime, NaiveDateTime, TimeZone, Utc};
use num_traits::ToPrimitive;
use review_database::{types::FromKeyValue, Database, Store};

#[derive(Default)]
pub(super) struct OutlierMutation;

#[Object]
impl OutlierMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn preserve_outliers(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] input: Vec<PreserveOutliersInput>,
    ) -> Result<usize> {
        use bincode::Options;

        let map = ctx.data::<Arc<Store>>()?.outlier_map();
        let mut updated = vec![];
        for outlier_key in input {
            let outlier_id = (outlier_key.id, outlier_key.source.clone());
            let key: RankedOutlierKey = outlier_key.into();
            let key = bincode::DefaultOptions::new().serialize(&key)?;
            if let Some(old) = map.get(&key)? {
                let (distance, saved): RankedOutlierValue =
                    bincode::DefaultOptions::new().deserialize(old.as_ref())?;
                if !saved {
                    let new = bincode::DefaultOptions::new().serialize(&(distance, true))?;
                    map.update((&key, old.as_ref()), (&key, &new))?;
                    updated.push(outlier_id);
                }
            }
        }

        Ok(updated.len())
    }
}

#[derive(Default)]
pub(super) struct OutlierQuery;

#[Object]
impl OutlierQuery {
    /// A list of outliers.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn outliers(
        &self,
        ctx: &Context<'_>,
        model: ID,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Outlier, OutlierTotalCount, EmptyFields>> {
        let model = model.as_str().parse()?;
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(ctx, model, after, before, first, last).await
            },
        )
        .await
    }

    /// A list of saved outliers, grouped by clustering time. Within each group,
    /// the outliers are sorted by their distance to the cluster centers.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
     .or(RoleGuard::new(Role::SecurityAdministrator))
     .or(RoleGuard::new(Role::SecurityManager))
     .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)]
    async fn saved_outliers(
        &self,
        ctx: &Context<'_>,
        model_id: ID,
        time: Option<NaiveDateTime>,
        after: Option<String>,
        before: Option<String>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
        let filter = |node: RankedOutlier| if node.saved { Some(node) } else { None };
        load_outliers(ctx, model_id, time, after, before, first, last, filter).await
    }

    /// A list of outliers, grouped by clustering time. Within each group,
    /// the outliers are sorted by their distance to the cluster centers.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
     .or(RoleGuard::new(Role::SecurityAdministrator))
     .or(RoleGuard::new(Role::SecurityManager))
     .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)]
    async fn ranked_outliers(
        &self,
        ctx: &Context<'_>,
        model_id: ID,
        time: Option<NaiveDateTime>,
        after: Option<String>,
        before: Option<String>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
        let filter = Some;
        load_outliers(ctx, model_id, time, after, before, first, last, filter).await
    }
}

#[allow(clippy::too_many_arguments)]
async fn load_outliers(
    ctx: &Context<'_>,
    model_id: ID,
    time: Option<NaiveDateTime>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    filter: fn(RankedOutlier) -> Option<RankedOutlier>,
) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
    let model_id: i32 = model_id.as_str().parse()?;
    let timestamp = time.map(|t| t.timestamp_nanos());

    let prefix = if let Some(timestamp) = timestamp {
        bincode::DefaultOptions::new().serialize(&(model_id, timestamp))?
    } else {
        bincode::DefaultOptions::new().serialize(&model_id)?
    };

    let map = ctx
        .data::<Arc<Store>>()?
        .outlier_map()
        .into_prefix_map(&prefix);

    super::load_with_filter(
        &map,
        filter,
        after,
        before,
        first,
        last,
        RankedOutlierTotalCount {
            model_id,
            timestamp,
        },
    )
}

#[derive(Debug, SimpleObject)]
pub(super) struct RankedOutlier {
    id: i64,
    model_id: i32,
    timestamp: i64,
    rank: i64,
    source: String,
    distance: f64,
    saved: bool,
}

impl FromKeyValue for RankedOutlier {
    fn from_key_value(key: &[u8], value: &[u8]) -> anyhow::Result<Self> {
        let (model_id, timestamp, rank, id, source) =
            bincode::DefaultOptions::new().deserialize(key)?;
        let (distance, saved) = bincode::DefaultOptions::new().deserialize(value)?;
        Ok(Self {
            id,
            model_id,
            timestamp,
            rank,
            source,
            distance,
            saved,
        })
    }
}

#[derive(Debug, InputObject)]
struct PreserveOutliersInput {
    id: i64,
    model_id: i32,
    timestamp: i64,
    rank: i64,
    source: String,
}

type RankedOutlierKey = (i32, i64, i64, i64, String);
type RankedOutlierValue = (f64, bool);
impl From<PreserveOutliersInput> for RankedOutlierKey {
    fn from(input: PreserveOutliersInput) -> Self {
        (
            input.model_id,
            input.timestamp,
            input.rank,
            input.id,
            input.source,
        )
    }
}

struct RankedOutlierTotalCount {
    model_id: i32,
    timestamp: Option<i64>,
}

#[Object]
impl RankedOutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        use review_database::IterableMap;
        let prefix = if let Some(timestamp) = self.timestamp {
            bincode::DefaultOptions::new().serialize(&(self.model_id, timestamp))?
        } else {
            bincode::DefaultOptions::new().serialize(&self.model_id)?
        };
        let map = ctx
            .data::<Arc<Store>>()?
            .outlier_map()
            .into_prefix_map(&prefix);

        let count = map
            .iter_forward()?
            .filter(|(_k, v)| {
                let (_, saved): RankedOutlierValue = bincode::DefaultOptions::new()
                    .deserialize(v)
                    .unwrap_or_default();
                saved
            })
            .count();
        Ok(count)
    }
}

#[derive(Debug, SimpleObject)]
#[graphql(complex)]
pub(super) struct Outlier {
    #[graphql(skip)]
    pub(super) id: i32,
    // pub(super) raw_event: Vec<u8>,
    #[graphql(skip)]
    pub(super) events: Vec<i64>,
    pub(super) size: i64,
    #[graphql(skip)]
    pub(super) model_id: i32,
}

#[ComplexObject]
impl Outlier {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn events(&self, _ctx: &Context<'_>) -> Result<Vec<DateTime<Utc>>> {
        Ok(self
            .events
            .iter()
            .filter_map(|e| datetime_from_ts_nano(*e))
            .collect::<Vec<_>>())
    }

    async fn model(&self, ctx: &Context<'_>) -> Result<Model> {
        let db = ctx.data::<Database>()?;
        Ok(db.load_model(self.model_id).await?.into())
    }
}

struct OutlierTotalCount {
    model_id: i32,
}

#[Object]
impl OutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        let db = ctx.data::<Database>()?;
        Ok(db.count_outliers(self.model_id).await?)
    }
}

async fn load(
    ctx: &Context<'_>,
    model: i32,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Outlier, OutlierTotalCount, EmptyFields>> {
    let after = slicing::decode_cursor(&after)?;
    let before = slicing::decode_cursor(&before)?;
    let is_first = first.is_some();
    let limit = slicing::limit(first, last)?;
    let db = ctx.data::<Database>()?;
    let rows = db
        .load_outliers(model, &after, &before, is_first, limit)
        .await?;

    let (rows, has_previous, has_next) = slicing::page_info(is_first, limit, rows);
    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        OutlierTotalCount { model_id: model },
    );
    connection.edges.extend(rows.into_iter().map(|o| {
        let cursor = slicing::encode_cursor(o.id, o.size);
        Edge::new(
            cursor,
            Outlier {
                id: o.id,
                events: o.event_ids,
                size: o.size,
                model_id: o.model_id,
            },
        )
    }));
    Ok(connection)
}

pub(crate) fn datetime_from_ts_nano(time: i64) -> Option<DateTime<Utc>> {
    let sec = time / 1_000_000_000;
    let Some(nano) = (time - sec * 1_000_000_000).to_u32() else {
        return None;
    };
    if let LocalResult::Single(time) = Utc.timestamp_opt(sec, nano) {
        Some(time)
    } else {
        None
    }
}
