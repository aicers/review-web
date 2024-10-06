use std::{collections::HashMap, sync::Arc};

use async_graphql::{
    connection::{Connection, Edge, EmptyFields},
    types::ID,
    ComplexObject, Context, InputObject, Object, Result, SimpleObject, StringNumber, Subscription,
};
use bincode::Options;
use chrono::{offset::LocalResult, DateTime, NaiveDateTime, TimeZone, Utc};
use futures::channel::mpsc::{unbounded, UnboundedSender};
use futures_util::stream::Stream;
use num_traits::ToPrimitive;
use review_database::{Database, Direction, Store, UniqueKey};
use serde::Deserialize;
use serde::Serialize;
use tokio::{sync::RwLock, time};
use tracing::error;

use super::{encode_cursor, model::ModelDigest, query, Role, RoleGuard};

const DEFAULT_OUTLIER_SIZE: usize = 50;
const DISTANCE_EPSILON: f64 = 0.1;
const DEFAULT_RANKED_OUTLIER_FETCH_TIME: u64 = 60;
const MAX_MODEL_LIST_SIZE: usize = 100;

#[derive(Default)]
pub(super) struct OutlierStream;

#[Subscription]
impl OutlierStream {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn ranked_outlier_stream(
        &self,
        ctx: &Context<'_>,
        start: DateTime<Utc>,
        fetch_interval: Option<u64>,
    ) -> Result<impl Stream<Item = RankedOutlier>> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?.clone();
        let db = ctx.data::<Database>()?.clone();
        let fetch_time = fetch_interval.unwrap_or(DEFAULT_RANKED_OUTLIER_FETCH_TIME);
        let (tx, rx) = unbounded();
        tokio::spawn(async move {
            if let Err(e) = fetch_ranked_outliers(
                db,
                store,
                start.timestamp_nanos_opt().unwrap_or_default(),
                tx,
                fetch_time,
            )
            .await
            {
                error!("{e:?}");
            }
        });
        Ok(rx)
    }
}

#[allow(clippy::too_many_lines)]
async fn fetch_ranked_outliers(
    db: Database,
    store: Arc<RwLock<Store>>,
    start_time: i64,
    tx: UnboundedSender<RankedOutlier>,
    fetch_time: u64,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(fetch_time));
    let mut latest_fetched_key: HashMap<i32, Vec<u8>> = HashMap::new();

    loop {
        itv.tick().await;

        // Read current model's ids
        let rows = db
            .load_models(&None, &None, true, MAX_MODEL_LIST_SIZE)
            .await?;
        let model_ids: Vec<i32> = rows.iter().map(|row| row.id).collect();

        // Search for ranked outliers by model.
        for model_id in model_ids {
            let store = store.read().await;
            let map = store.outlier_map();

            let (iter, is_first_fetch) = if let Some(cursor) = latest_fetched_key.get(&model_id) {
                (
                    map.get(model_id, None, Direction::Forward, Some(cursor)),
                    false,
                )
            } else {
                (map.get(model_id, None, Direction::Forward, None), true)
            };

            let mut model_cursor = Vec::new();
            for res in iter {
                let entry = res?;
                if is_first_fetch && entry.timestamp < start_time {
                    continue;
                }
                model_cursor = entry.unique_key();
                tx.unbounded_send(entry.into())?;
            }
            if !model_cursor.is_empty() {
                model_cursor.push(0);
                latest_fetched_key.insert(model_id, model_cursor);
            }
        }
    }
}

#[derive(Default)]
pub(super) struct OutlierMutation;

#[Object]
impl OutlierMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn preserve_outliers(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] input: Vec<PreserveOutliersInput>,
    ) -> Result<Vec<PreserveOutliersOutput>> {
        let store = super::get_store(ctx).await?;
        let map = store.outlier_map();
        let mut outdated_items: Vec<PreserveOutliersOutput> = vec![];
        for outlier_key in input {
            let preserve: PreserveOutliersInput = outlier_key.clone();
            let key: review_database::OutlierInfoKey = outlier_key.into();
            if !(map.update_is_saved(&key)?) {
                outdated_items.push(PreserveOutliersOutput::from(preserve));
            }
        }

        Ok(outdated_items)
    }
}

#[derive(Default)]
pub(super) struct OutlierQuery;

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct OutlierTimeRange {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}

#[allow(clippy::module_name_repetitions)]
#[derive(InputObject, Serialize)]
pub struct OutlierDistanceRange {
    start: Option<f64>,
    end: Option<f64>,
}

#[derive(InputObject, Serialize)]
pub struct SearchFilterInput {
    pub time: Option<OutlierTimeRange>,
    distance: Option<OutlierDistanceRange>,
    tag: Option<String>,
    remark: Option<String>,
}

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
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
        let filter = |node: RankedOutlier| if node.saved { Some(node) } else { None };
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_outliers(ctx, model_id, time, after, before, first, last, filter).await
            },
        )
        .await
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
        first: Option<i32>,
        last: Option<i32>,
        filter: Option<SearchFilterInput>,
    ) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_ranked_outliers_with_filter(
                    ctx, model_id, time, after, before, first, last, filter,
                )
                .await
            },
        )
        .await
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
    let timestamp = time.map(|t| t.and_utc().timestamp_nanos_opt().unwrap_or_default());

    let prefix = {
        let mut buf = model_id.to_be_bytes().to_vec();
        if let Some(ts) = timestamp {
            buf.extend(ts.to_be_bytes());
        }
        buf
    };

    let store = crate::graphql::get_store(ctx).await?;
    let map = store.outlier_map();

    let (nodes, has_previous, has_next) =
        super::load_edges_interim(&map, after, before, first, last, Some(&prefix))?;

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        RankedOutlierTotalCount {
            model_id,
            timestamp,
            check_saved: true,
        },
    );
    connection.edges.extend(nodes.into_iter().filter_map(|n| {
        let cursor = encode_cursor(&n.unique_key());
        let n: RankedOutlier = n.into();
        filter(n).map(|n| Edge::new(cursor, n))
    }));
    Ok(connection)
}

#[derive(Debug, SimpleObject)]
#[graphql(complex)]
pub(super) struct RankedOutlier {
    #[graphql(skip)]
    id: i64,
    model_id: i32,
    timestamp: i64,
    rank: i64,
    source: String,
    distance: f64,
    saved: bool,
}

impl From<review_database::OutlierInfo> for RankedOutlier {
    fn from(input: review_database::OutlierInfo) -> Self {
        Self {
            id: input.id,
            model_id: input.model_id,
            timestamp: input.timestamp,
            rank: input.rank,
            source: input.source,
            distance: input.distance,
            saved: input.is_saved,
        }
    }
}

#[ComplexObject]
impl RankedOutlier {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }
}

#[derive(Debug, Clone, InputObject)]
struct PreserveOutliersInput {
    id: i64,
    model_id: i32,
    timestamp: i64,
    rank: i64,
    source: String,
}

impl From<PreserveOutliersInput> for review_database::OutlierInfoKey {
    fn from(input: PreserveOutliersInput) -> Self {
        Self {
            model_id: input.model_id,
            timestamp: input.timestamp,
            rank: input.rank,
            id: input.id,
            source: input.source,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PreserveOutliersOutput {
    id: i64,
    model_id: i32,
    timestamp: i64,
    source: String,
}

impl From<PreserveOutliersInput> for PreserveOutliersOutput {
    fn from(input: PreserveOutliersInput) -> Self {
        Self {
            model_id: input.model_id,
            timestamp: input.timestamp,
            id: input.id,
            source: input.source,
        }
    }
}

#[Object]
impl PreserveOutliersOutput {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn model_id(&self) -> i32 {
        self.model_id
    }

    async fn timestamp(&self) -> StringNumber<i64> {
        StringNumber(self.timestamp)
    }

    async fn source(&self) -> String {
        self.source.to_string()
    }
}

struct RankedOutlierTotalCount {
    model_id: i32,
    timestamp: Option<i64>,
    check_saved: bool,
}

#[Object]
impl RankedOutlierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.outlier_map();

        let iter = map.get(self.model_id, self.timestamp, Direction::Forward, None);
        let count = if self.check_saved {
            iter.filter(|res| {
                if let Ok(entry) = res {
                    entry.is_saved
                } else {
                    false
                }
            })
            .count()
        } else {
            iter.count()
        };
        Ok(count)
    }
}

#[derive(Debug, Deserialize, SimpleObject)]
#[graphql(complex)]
pub(super) struct Outlier {
    #[graphql(skip)]
    pub(super) id: i64, //timestamp
    #[graphql(skip)]
    pub(super) events: Vec<i64>,
    pub(super) size: i64,
    pub(super) model_id: i32,
}

#[ComplexObject]
impl Outlier {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn events(&self) -> Result<Vec<DateTime<Utc>>> {
        Ok(self
            .events
            .iter()
            .filter_map(|e| datetime_from_ts_nano(*e))
            .collect::<Vec<_>>())
    }

    async fn model(&self, ctx: &Context<'_>) -> Result<ModelDigest> {
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
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        use std::collections::HashSet;
        let store = crate::graphql::get_store(ctx).await?;
        let table = store.outlier_map();
        let iter = table.get(self.model_id, None, Direction::Forward, None);

        Ok(iter
            .map(|res| res.map(|entry| entry.timestamp).map_err(Into::into))
            .collect::<Result<HashSet<_>>>()?
            .len())
    }
}

async fn load(
    ctx: &Context<'_>,
    model_id: i32,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Outlier, OutlierTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let table = store.outlier_map();
    let (after, before) = super::decode_cursor_pair(after, before)?;
    let decoded_after = after
        .as_deref()
        .map(|input| bincode::DefaultOptions::new().deserialize(input))
        .transpose()?
        .map(|(_, from): (&[u8], &[u8])| from);
    let decoded_before = before
        .as_deref()
        .map(|input| bincode::DefaultOptions::new().deserialize(input))
        .transpose()?
        .map(|(from, _): (&[u8], &[u8])| from);
    let (direction, count, from, to) = if let Some(first) = first {
        (Direction::Forward, first, decoded_after, decoded_before)
    } else if let Some(last) = last {
        (Direction::Reverse, last, decoded_before, decoded_after)
    } else {
        unreachable!();
    };

    let iter = table.get(model_id, None, direction, from);

    let mut batches = HashMap::new();
    let mut has_more = false;
    for res in iter {
        let entry = res?;
        if !batches.contains_key(&entry.timestamp) && batches.len() >= count {
            has_more = true;
            break;
        }
        let key = entry.unique_key();
        if let Some(to) = to {
            if key == to {
                break;
            }
        }

        let batch = batches.entry(entry.timestamp).or_insert((
            key.clone(),
            vec![],
            Outlier {
                model_id,
                events: vec![],
                id: entry.timestamp,
                size: 0,
            },
        ));
        batch.1 = key;
        batch.2.size += 1;
        if batch.2.events.len() < DEFAULT_OUTLIER_SIZE {
            batch.2.events.push(entry.id);
        }
    }

    let (has_previous, has_next) = if first.is_some() {
        (false, has_more)
    } else {
        (has_more, false)
    };
    let edges = batches.into_values().filter_map(|(from, to, mut ev)| {
        let cursor = bincode::DefaultOptions::new().serialize(&(from, to)).ok()?;
        let encoded = super::encode_cursor(&cursor);
        ev.events.sort_unstable();
        Some(Edge::new(encoded, ev))
    });
    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, OutlierTotalCount { model_id });
    connection.edges.extend(edges);
    Ok(connection)
}

pub(crate) fn datetime_from_ts_nano(time: i64) -> Option<DateTime<Utc>> {
    let sec = time / 1_000_000_000;
    let nano = (time - sec * 1_000_000_000).to_u32()?;
    if let LocalResult::Single(time) = Utc.timestamp_opt(sec, nano) {
        Some(time)
    } else {
        None
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn load_ranked_outliers_with_filter(
    ctx: &Context<'_>,
    model_id: ID,
    time: Option<NaiveDateTime>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    filter: Option<SearchFilterInput>,
) -> Result<Connection<String, RankedOutlier, RankedOutlierTotalCount, EmptyFields>> {
    let model_id: i32 = model_id.as_str().parse()?;
    let timestamp = time.map(|t| t.and_utc().timestamp_nanos_opt().unwrap_or_default());
    let (after, before) = super::decode_cursor_pair(after, before)?;
    let (direction, count, from, to) = if let Some(first) = first {
        (
            Direction::Forward,
            first,
            after.as_deref(),
            before.as_deref(),
        )
    } else if let Some(last) = last {
        (
            Direction::Reverse,
            last,
            before.as_deref(),
            after.as_deref(),
        )
    } else {
        unreachable!();
    };

    let store = crate::graphql::get_store(ctx).await?;
    let table = store.outlier_map();

    let remarks_map = store.triage_response_map();
    let tags_map = store.event_tag_set()?;

    let mut has_more = false;
    let mut nodes = vec![];
    let additional = RankedOutlierTotalCount {
        model_id,
        timestamp,
        check_saved: false,
    };

    let tag_id_list = if let Some(filter) = &filter {
        if let Some(pattern) = &filter.tag {
            let tag_ids = tags_map
                .tags()
                .filter_map(|tag| {
                    if tag.name.contains(pattern) {
                        Some(tag.id)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            if tag_ids.is_empty() {
                return Ok(Connection::with_additional_fields(false, false, additional));
            }
            Some(tag_ids)
        } else {
            None
        }
    } else {
        None
    };

    for res in table.get(model_id, timestamp, direction, from) {
        let node = res?;
        let key = node.unique_key();

        if let Some(to) = to {
            if to == key {
                continue;
            }
        }
        if nodes.len() >= count {
            has_more = true;
            continue;
        }
        let encoded_key = encode_cursor(&key);

        if let Some(filter) = &filter {
            if filter.remark.is_some() || tag_id_list.is_some() {
                if let Some(value) = remarks_map.get(&node.source, &Utc.timestamp_nanos(node.id))? {
                    if let Some(remark) = &filter.remark {
                        if !value.remarks.contains(remark) {
                            continue;
                        }
                    }
                    if let Some(tag_ids) = &tag_id_list {
                        if !tag_ids.iter().any(|tag| value.tag_ids().contains(tag)) {
                            continue;
                        }
                    }
                } else {
                    continue;
                }
            }
            if let Some(time) = &filter.time {
                if let Some(start) = time.start {
                    if let Some(end) = time.end {
                        if node.timestamp < start.timestamp_nanos_opt().unwrap_or_default()
                            || node.timestamp > end.timestamp_nanos_opt().unwrap_or_default()
                        {
                            continue;
                        }
                    } else if node.timestamp < start.timestamp_nanos_opt().unwrap_or_default() {
                        continue;
                    }
                } else if let Some(end) = time.end {
                    if node.timestamp > end.timestamp_nanos_opt().unwrap_or_default() {
                        continue;
                    }
                }
            }

            if let Some(distance) = &filter.distance {
                if let Some(start) = distance.start {
                    if let Some(end) = distance.end {
                        if node.distance < start || node.distance > end {
                            continue;
                        }
                    } else if (node.distance - start).abs() > DISTANCE_EPSILON {
                        continue;
                    }
                }
            }
        }
        nodes.push((encoded_key, node));
    }

    let (has_previous, has_next) = if first.is_some() {
        (false, has_more)
    } else {
        (has_more, false)
    };

    let mut connection = Connection::with_additional_fields(has_previous, has_next, additional);
    connection
        .edges
        .extend(nodes.into_iter().map(|(k, ev)| Edge::new(k, ev.into())));
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use async_graphql::Value;
    use chrono::{DateTime, Utc};
    use review_database::OutlierInfo;

    use crate::graphql::TestSchema;

    fn time_str(t: &DateTime<Utc>) -> String {
        t.format("%FT%T%.9f").to_string()
    }

    fn samples(model_id: i32, timestamp: i64, start: i64, total: i64) -> Vec<OutlierInfo> {
        (start..start + total)
            .into_iter()
            .map(|id| {
                let rank = id;
                let distance = id as f64;
                let is_saved = id % 2 == 0;
                OutlierInfo {
                    model_id,
                    timestamp,
                    rank,
                    id,
                    source: "test".to_string(),
                    distance,
                    is_saved,
                }
            })
            .collect()
    }

    #[tokio::test]
    async fn outliers() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let map = store.outlier_map();
        let model = 3;
        let t1 = chrono::Utc::now();
        let outliers = samples(model, t1.timestamp_nanos_opt().unwrap(), 0, 2);
        for outlier in &outliers {
            assert!(map.insert(&outlier).is_ok());
        }
        let res = schema
            .execute(
                r#"query {
                outliers(model: 3) {
                    nodes {id, events, size},
                    totalCount
                }
            }"#,
            )
            .await;
        let e0 = DateTime::from_timestamp(0, 0).unwrap().to_rfc3339();
        let e1 = DateTime::from_timestamp(0, 1).unwrap().to_rfc3339();
        assert_eq!(
            res.data.to_string(),
            format!("{{outliers: {{nodes: [{{id: \"{}\", events: [\"{e0}\", \"{e1}\"], size: 2}}], totalCount: {}}}}}", t1.timestamp_nanos_opt().unwrap(), 1)
        );

        let t2 = t1 + chrono::TimeDelta::hours(1);
        let start = 3;
        let total = 4;

        let outliers = samples(model, t2.timestamp_nanos_opt().unwrap(), start, total);
        for outlier in &outliers {
            assert!(map.insert(&outlier).is_ok());
        }

        let res = schema
            .execute(
                r#"query {
                    outliers(model: 3) {
                        totalCount
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{outliers: {{totalCount: {}}}}}", 2)
        );
    }

    #[tokio::test]
    async fn ranked_outliers() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let map = store.outlier_map();
        let model = 3;
        let t1 = chrono::Utc::now();
        let outliers = samples(model, t1.timestamp_nanos_opt().unwrap(), 0, 2);
        for outlier in &outliers {
            assert!(map.insert(&outlier).is_ok());
        }

        let res = schema
            .execute(
                r#"query {
                    rankedOutliers(modelId: 3) {
                        totalCount
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{totalCount: {}}}}}", outliers.len())
        );

        let t2 = t1 + chrono::TimeDelta::hours(1);
        let t2_str = time_str(&t2);
        let start = 3;
        let total = 4;
        let last = start + total - 1;

        let outliers = samples(model, t2.timestamp_nanos_opt().unwrap(), start, total);
        for outlier in &outliers {
            assert!(map.insert(&outlier).is_ok());
        }

        let res = schema
            .execute(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{}\", first: 1) {{ nodes {{ id }} }} }}",
                &t2_str
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{nodes: [{{id: \"{}\"}}]}}}}", 3)
        );

        let res = schema
            .execute(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{}\", first: 3) {{ pageInfo {{
                hasNextPage,
                startCursor,
                endCursor
            }} }} }}",
                &t2_str
            ))
            .await;
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {:?}", res);
        };
        let Some(Value::Object(ranked_outliers)) = retval.get("rankedOutliers") else {
            panic!("unexpected response: {:?}", retval);
        };
        let Some(Value::Object(page_info)) = ranked_outliers.get("pageInfo") else {
            panic!("unexpected response: {:?}", ranked_outliers);
        };
        let Some(Value::Boolean(has_next_page)) = page_info.get("hasNextPage") else {
            panic!("unexpected response: {:?}", page_info);
        };
        assert_eq!(*has_next_page, true);
        let Some(Value::String(cursor)) = page_info.get("endCursor") else {
            panic!("unexpected response: {:?}", page_info);
        };

        let res = schema
            .execute(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{}\", after: \"{cursor}\", first: 1) {{ nodes {{ id }} }} }}",
                &t2_str
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{nodes: [{{id: \"{}\"}}]}}}}", last - 1,)
        );

        let res = schema
            .execute(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{}\", last: 2) {{ nodes {{ id }} }} }}",
                &t2_str
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!(
                "{{rankedOutliers: {{nodes: [{{id: \"{}\"}}, {{id: \"{}\"}}]}}}}",
                last,
                last - 1
            )
        );

        let res = schema
            .execute(&format!(
                "query {{rankedOutliers(modelId: 3, time: \"{}\", last: 3) {{ pageInfo {{
            hasPreviousPage,
            startCursor,
            endCursor
        }} }} }}",
                &t2_str
            ))
            .await;
        let Value::Object(retval) = res.data else {
            panic!("unexpected response: {:?}", res);
        };
        let Some(Value::Object(ranked_outliers)) = retval.get("rankedOutliers") else {
            panic!("unexpected response: {:?}", retval);
        };
        let Some(Value::Object(page_info)) = ranked_outliers.get("pageInfo") else {
            panic!("unexpected response: {:?}", ranked_outliers);
        };
        let Some(Value::Boolean(has_previous_page)) = page_info.get("hasPreviousPage") else {
            panic!("unexpected response: {:?}", page_info);
        };
        assert_eq!(*has_previous_page, true);
        let Some(Value::String(cursor)) = page_info.get("endCursor") else {
            panic!("unexpected response: {:?}", page_info);
        };

        let res = schema
        .execute(&format!(
            "query {{rankedOutliers(modelId: 3, time: \"{}\", before: \"{cursor}\", last: 1) {{ nodes {{ id }} }} }}",
            &t2_str
        ))
        .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{rankedOutliers: {{nodes: [{{id: \"{}\"}}]}}}}", start + 1,)
        );
    }

    #[tokio::test]
    async fn saved_outliers() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let map = store.outlier_map();

        let t = chrono::Utc::now();
        let t_str = time_str(&t);
        let outliers = samples(0, t.timestamp_nanos_opt().unwrap(), 0, 2);
        for outlier in &outliers {
            assert!(map.insert(&outlier).is_ok());
        }

        let model = 3;

        let start = 3;
        let total = 4;

        let outliers = samples(model, t.timestamp_nanos_opt().unwrap(), start, total);
        for outlier in &outliers {
            assert!(map.insert(&outlier).is_ok());
        }

        let res = schema
            .execute(&format!(
                "query {{savedOutliers(modelId: {model}, time: \"{}\") {{ totalCount }} }}",
                &t_str
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{savedOutliers: {{totalCount: {}}}}}", total / 2)
        );
    }

    #[tokio::test]
    async fn preserved_outliers() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let map = store.outlier_map();

        let t = chrono::Utc::now();
        let t_str = time_str(&t);

        let model = 3;

        let start = 3;
        let total = 4;

        let outliers = samples(model, t.timestamp_nanos_opt().unwrap(), start, total);
        for outlier in &outliers {
            assert!(map.insert(&outlier).is_ok());
        }

        let res = schema
            .execute(&format!(
                "query {{savedOutliers(modelId: {model}, time: \"{}\") {{ totalCount }} }}",
                &t_str
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!("{{savedOutliers: {{totalCount: {}}}}}", total / 2)
        );

        let to_save = start;
        let to_preserve = format!("[{{id: {to_save}, modelId: {model}, timestamp: {}, rank: {to_save}, source: \"test\"}}]", t.timestamp_nanos_opt().unwrap());
        let res = schema
            .execute(&format!(
                "mutation {{
                    preserveOutliers(input: {to_preserve}) {{
                        id
                        modelId
                        timestamp
                        source
                    }}
                }}"
            ))
            .await;
        let expect = format!("{{preserveOutliers: []}}");
        assert_eq!(res.data.to_string(), expect);

        let saved = start + 1;
        let to_preserve = format!(
            "[{{id: {saved}, modelId: {model}, timestamp: {}, rank: {saved}, source: \"test\"}}]",
            t.timestamp_nanos_opt().unwrap()
        );
        let res = schema
            .execute(&format!(
                "mutation {{
                    preserveOutliers(input: {to_preserve}) {{
                        id
                        modelId
                        timestamp
                        source
                    }}
                }}"
            ))
            .await;
        let expect = format!("{{preserveOutliers: [{{id: \"{saved}\", modelId: {model}, timestamp: \"{}\", source: \"test\"}}]}}", t.timestamp_nanos_opt().unwrap());
        assert_eq!(res.data.to_string(), expect);
    }
}
