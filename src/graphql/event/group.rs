use std::collections::HashMap;

use async_graphql::{Context, Object, OutputType, Result, SimpleObject, resolver_utils::EnumType};
use num_traits::ToPrimitive;
use review_database::event::{Direction, EventFilter};
use review_database::{IndexedTable, Iterable, StoredDetectionEvent};

use super::{
    EventListFilterInput, earliest, empty_time_range, from_filter_input, latest, readable_event,
    timestamp_nanos,
};
use crate::graphql::{Role, RoleGuard, filter::DetectionModel};

const MAX_EVENT_FREQUENCY_SERIES_BUCKETS: usize = 10_000;

#[derive(Default)]
pub(in crate::graphql) struct EventGroupQuery;

#[Object]
impl EventGroupQuery {
    /// The number of events for each category, with timestamp on or after
    /// `start` and before `end`. An uncategorized event is counted in a bucket
    /// whose value is `null`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_category(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<Option<u8>>> {
        let (values, counts) =
            count_events(ctx, &filter, StoredDetectionEvent::count_category, first).await?;
        let values = values
            .into_iter()
            .map(|category| category.and_then(|value| value.to_u8()))
            .collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each country code recorded on them, with
    /// timestamp on or after `start` and before `end`. The `"ZZ"` bucket holds
    /// events whose country could not be determined, and the `"XX"` bucket
    /// holds events recorded without country information. Both bucket values
    /// can be used in `countries` filters.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_country(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) =
            count_events(ctx, &filter, StoredDetectionEvent::count_country, first).await?;
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each IP address, with timestamp on or after
    /// `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_ip_address(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) =
            count_events(ctx, &filter, StoredDetectionEvent::count_ip_address, first).await?;
        let values = values.into_iter().map(|v| v.to_string()).collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each originator and responder IP address pair,
    /// with timestamp on or after `start` and before `end`. Each entry in
    /// `values` is a string representation of the originator and responder IP
    /// address pair. For example, originator IP address 10.0.0.1 and responder IP
    /// address 10.0.0.2 become "10.0.0.1-10.0.0.2".
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_ip_address_pair(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) = count_events(
            ctx,
            &filter,
            StoredDetectionEvent::count_ip_address_pair,
            first,
        )
        .await?;
        let values = values
            .into_iter()
            .map(|(src, dst)| {
                let mut value = src.to_string();
                value.push('-');
                value.push_str(&dst.to_string());
                value
            })
            .collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each originator and responder IP address pair
    /// and detection model, with timestamp on or after `start` and before
    /// `end`. Each entry in `values` is the originator address, the responder
    /// address and the `DetectionModel` value, joined by `-`. For example, a
    /// DNS covert channel event with originator IP address 10.0.0.1 and
    /// responder IP address 10.0.0.2 becomes
    /// "10.0.0.1-10.0.0.2-DNS_COVERT_CHANNEL".
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_ip_address_pair_and_detection_model(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) = count_events(
            ctx,
            &filter,
            StoredDetectionEvent::count_ip_address_pair_and_detection_model,
            first,
        )
        .await?;
        let values = values
            .into_iter()
            .map(|(src, dst, model)| format!("{src}-{dst}-{}", detection_model_name(model.into())))
            .collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each originator IP address, with timestamp on or
    /// after `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_originator_ip_address(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) = count_events(
            ctx,
            &filter,
            StoredDetectionEvent::count_originator_ip_address,
            first,
        )
        .await?;
        let values = values.into_iter().map(|v| v.to_string()).collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each responder IP address, with timestamp on
    /// or after `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_responder_ip_address(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) = count_events(
            ctx,
            &filter,
            StoredDetectionEvent::count_responder_ip_address,
            first,
        )
        .await?;
        let values = values.into_iter().map(|v| v.to_string()).collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each detection model, with timestamp on or
    /// after `start` and before `end`. Every detection model has its own
    /// bucket, and each value can be passed back in `detectionModels` to
    /// select the events counted under it.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_detection_model(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<DetectionModel>> {
        let (values, counts) = count_events(
            ctx,
            &filter,
            StoredDetectionEvent::count_detection_model,
            first,
        )
        .await?;
        let values = values.into_iter().map(Into::into).collect();
        Ok(EventCounts { values, counts })
    }

    /// The number of events for each network, with timestamp on or after
    /// `start` and before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_counts_by_network(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] first: i32,
    ) -> Result<EventCounts<String>> {
        let (values, counts) = count_events_by_network(ctx, &filter, first).await?;
        Ok(EventCounts { values, counts })
    }

    /// A dense time series for `[start, end)`, aligned to `start`, with a
    /// positive `slotSize` in seconds. Both `filter.start` and `filter.end` must
    /// be explicitly provided and non-null; omitted bounds no longer default
    /// to the Unix epoch or an unbounded end. Timestamps must fit signed i64
    /// nanoseconds. Valid ranges with `start >= end` return an empty list.
    /// Returns `ceil((end - start) / slotSize)` buckets, including zeros and a
    /// partial final bucket. Events exactly at `end` are excluded. At most
    /// 10,000 buckets are allowed; larger requests return an error before
    /// event iteration. Provide both bounds for missing-bound errors, or
    /// increase `slotSize` or narrow the time range for bucket-limit errors.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_frequency_series(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        #[graphql(validator(minimum = 1))] slot_size: i64,
    ) -> Result<Vec<usize>> {
        let store = crate::graphql::get_store(ctx)?;
        let event_filter = from_filter_input(ctx, &store, &filter)?;
        let start: jiff::Timestamp = filter
            .start
            .ok_or("eventFrequencySeries requires non-null filter.start")?
            .into();
        let end: jiff::Timestamp = filter
            .end
            .ok_or("eventFrequencySeries requires non-null filter.end")?
            .into();
        let start_nanos = i128::from(timestamp_nanos(start)?);
        let end_nanos = i128::from(timestamp_nanos(end)?);
        let slot_size_nanos = i128::from(slot_size)
            .checked_mul(1_000_000_000)
            .filter(|&value| value > 0)
            .ok_or("eventFrequencySeries slotSize must be positive seconds")?;
        if start_nanos >= end_nanos {
            return Ok(Vec::new());
        }

        // Work in nanoseconds rather than shifted event keys: the full signed
        // i64 timestamp span and even an i64::MAX-second slot size fit in i128.
        let span = end_nanos
            .checked_sub(start_nanos)
            .ok_or("eventFrequencySeries time span overflow")?;
        let bucket_count = span
            .checked_add(slot_size_nanos - 1)
            .ok_or("eventFrequencySeries bucket count overflow")?
            / slot_size_nanos;
        if bucket_count > i128::try_from(MAX_EVENT_FREQUENCY_SERIES_BUCKETS)? {
            return Err(format!(
                "eventFrequencySeries would produce {bucket_count} buckets; the maximum is \
                 {MAX_EVENT_FREQUENCY_SERIES_BUCKETS}. Increase slotSize or narrow the time range."
            )
            .into());
        }
        let mut series = vec![0; usize::try_from(bucket_count)?];
        let db = store.events();
        for item in db.iter_from(earliest(Some(start))?, Direction::Forward) {
            let Some((key, event)) = readable_event(ctx, item)? else {
                continue;
            };
            let event_nanos = key >> 64;
            if event_nanos >= end_nanos {
                break;
            }
            if event.matches(&event_filter)?.0 {
                let offset = event_nanos
                    .checked_sub(start_nanos)
                    .ok_or("eventFrequencySeries bucket offset overflow")?;
                let index = usize::try_from(offset / slot_size_nanos)?;
                let frequency = series
                    .get_mut(index)
                    .ok_or("eventFrequencySeries event outside bucket range")?;
                *frequency += 1;
            }
        }
        Ok(series)
    }
}

#[derive(SimpleObject)]
#[graphql(concrete(name = "StringEventCounter", params(String)))]
#[graphql(concrete(name = "U8EventCounter", params("Option<u8>")))]
#[graphql(concrete(name = "DetectionModelEventCounter", params(DetectionModel)))]
struct EventCounts<T: OutputType> {
    values: Vec<T>,
    counts: Vec<usize>,
}

type EventCountFn<T> =
    fn(&StoredDetectionEvent, &mut HashMap<T, usize>, &EventFilter) -> anyhow::Result<()>;

/// Returns the `DetectionModel` GraphQL enum value of `model`.
fn detection_model_name(model: DetectionModel) -> &'static str {
    DetectionModel::items()
        .iter()
        .find(|item| item.value == model)
        .map_or("", |item| item.name)
}

async fn count_events<T>(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    count: EventCountFn<T>,
    first: i32,
) -> Result<(Vec<T>, Vec<usize>)> {
    let start = filter.start.map(Into::into);
    let end = filter.end.map(Into::into);
    let store = crate::graphql::get_store(ctx)?;
    let filter = from_filter_input(ctx, &store, filter)?;
    if empty_time_range(start, end)? {
        return Ok((Vec::new(), Vec::new()));
    }

    let start = earliest(start)?;
    let end = latest(end)?;
    let db = store.events();
    let mut counter = HashMap::new();
    for item in db.iter_from(start, Direction::Forward) {
        let Some((key, event)) = readable_event(ctx, item)? else {
            continue;
        };
        if key > end {
            break;
        }
        count(&event, &mut counter, &filter)?;
    }

    let mut counter = counter.into_iter().collect::<Vec<_>>();
    counter.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
    counter.truncate(usize::try_from(first).unwrap_or(counter.len()));
    let (values, counts) = counter.into_iter().fold(
        (Vec::new(), Vec::new()),
        |(mut values, mut counts), (k, v)| {
            values.push(k);
            counts.push(v);
            (values, counts)
        },
    );
    Ok((values, counts))
}

async fn count_events_by_network(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    first: i32,
) -> Result<(Vec<String>, Vec<usize>)> {
    let start = filter.start.map(Into::into);
    let end = filter.end.map(Into::into);
    let store = crate::graphql::get_store(ctx)?;
    let filter = from_filter_input(ctx, &store, filter)?;
    if empty_time_range(start, end)? {
        return Ok((Vec::new(), Vec::new()));
    }
    let network_map = store.network_map();
    let networks = load_networks(&network_map)?;

    let start = earliest(start)?;
    let end = latest(end)?;
    let db = store.events();
    let mut counter = HashMap::new();
    for item in db.iter_from(start, Direction::Forward) {
        let Some((key, event)) = readable_event(ctx, item)? else {
            continue;
        };
        if key > end {
            break;
        }
        event.count_network(&mut counter, &networks, &filter)?;
    }

    let mut counter = counter.into_iter().collect::<Vec<_>>();
    counter.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
    counter.truncate(usize::try_from(first).unwrap_or(counter.len()));
    let (values, counts) = counter.into_iter().fold(
        (Vec::new(), Vec::new()),
        |(mut values, mut counts), (k, v)| {
            values.push(k.to_string());
            counts.push(v);
            (values, counts)
        },
    );
    Ok((values, counts))
}

fn load_networks(
    map: &IndexedTable<review_database::Network>,
) -> anyhow::Result<Vec<review_database::Network>> {
    let mut networks = Vec::new();
    for entry in map.iter(Direction::Forward, None) {
        let network = entry?;
        networks.push(network);
    }
    Ok(networks)
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use std::net::Ipv4Addr;

    use jiff::{SignedDuration, Timestamp};
    use review_protocol::types::{
        Detail, DetectionEvent, EndpointRole, EventCategory, ExternalDdosDetail,
        MultiHostPortScanDetail, PrimarySubject, ThreatRole,
    };

    use super::super::tests::{
        event_country_locator, schema_with_country_filter_events, utc_micro,
    };
    use crate::graphql::{
        TestSchema,
        event_test_support::{PutEvent, dns_event, related, subject_event},
    };

    /// Creates an event at `timestamp` with the given source and
    /// destination `IPv4` addresses.
    fn event_message_at(timestamp: Timestamp, src: u32, dst: u32) -> DetectionEvent {
        event_message_with_category(timestamp, src, dst, Some(EventCategory::CommandAndControl))
    }

    fn event_message_with_category(
        timestamp: Timestamp,
        src: u32,
        dst: u32,
        category: Option<EventCategory>,
    ) -> DetectionEvent {
        dns_event(
            timestamp,
            Ipv4Addr::from(src).into(),
            Ipv4Addr::from(dst).into(),
            category,
            "sensor1",
        )
    }

    #[tokio::test]
    async fn event_counts_by_category_preserves_uncategorized_bucket() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);

        for offset in 0..3 {
            db.put_event(&event_message_with_category(
                ts + SignedDuration::from_secs(offset),
                1,
                2,
                None,
            ))
            .unwrap();
        }
        for offset in 3..5 {
            db.put_event(&event_message_with_category(
                ts + SignedDuration::from_secs(offset),
                3,
                4,
                Some(EventCategory::InitialAccess),
            ))
            .unwrap();
        }
        drop(store);

        let res = schema
            .execute_as_system_admin(
                r"{
                    all: eventCountsByCategory(filter: {}, first: 10) {
                        values
                        counts
                    }
                    uncategorized: eventCountsByCategory(
                        filter: { categories: [null] }
                        first: 10
                    ) {
                        values
                        counts
                    }
                    categorized: eventCountsByCategory(
                        filter: { categories: [2] }
                        first: 10
                    ) {
                        values
                        counts
                    }
                    mixed: eventCountsByCategory(
                        filter: { categories: [2, null] }
                        first: 10
                    ) {
                        values
                        counts
                    }
                    limited: eventCountsByCategory(filter: {}, first: 1) {
                        values
                        counts
                    }
                    noMatches: eventCountsByCategory(
                        filter: { categories: [3] }
                        first: 10
                    ) {
                        values
                        counts
                    }
                }",
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            "{all: {values: [null, 2], counts: [3, 2]}, uncategorized: {values: [null], counts: [3]}, categorized: {values: [2], counts: [2]}, mixed: {values: [null, 2], counts: [3, 2]}, limited: {values: [null], counts: [3]}, noMatches: {values: [], counts: []}}"
        );
    }

    #[tokio::test]
    async fn event_frequency_series_requires_explicit_start() {
        let schema = TestSchema::new().await;
        let epoch = Timestamp::UNIX_EPOCH;
        let store = schema.store();
        let db = store.events();
        db.put_event(&event_message_at(epoch, 1, 2)).unwrap();
        db.put_event(&event_message_at(
            epoch + SignedDuration::from_secs(1),
            3,
            4,
        ))
        .unwrap();
        drop(store);
        let end = epoch + SignedDuration::from_secs(2);

        let output = schema
            .execute_as_system_admin(&format!(
                r#"{{ eventFrequencySeries(filter: {{ end: "{end}" }}, slotSize: 1) }}"#
            ))
            .await;

        assert_eq!(output.errors.len(), 1);
        assert!(
            output.errors[0]
                .message
                .contains("requires non-null filter.start")
        );
    }

    async fn frequency_series(
        schema: &TestSchema,
        start: i64,
        end: i64,
        slot_size: i64,
        extra_filter: &str,
    ) -> Vec<usize> {
        let start = jiff::Timestamp::from_nanosecond(i128::from(start)).unwrap();
        let end = jiff::Timestamp::from_nanosecond(i128::from(end)).unwrap();
        let output = schema
            .execute_as_system_admin(&format!(
                r#"{{ eventFrequencySeries(filter: {{ start: "{start}", end: "{end}", {extra_filter} }}, slotSize: {slot_size}) }}"#
            ))
            .await;
        assert!(output.errors.is_empty(), "{:?}", output.errors);
        serde_json::from_value(output.data.into_json().unwrap()["eventFrequencySeries"].clone())
            .unwrap()
    }

    #[tokio::test]
    async fn event_frequency_series_bucket_limit() {
        let schema = TestSchema::new().await;
        // Run the same boundary checks with an empty DB and with only a late
        // event, which previously grew the series while advancing buckets.
        for populated in [false, true] {
            if populated {
                let store = schema.store();
                store
                    .events()
                    .put_event(&event_message_at(
                        Timestamp::from_second(9_999).unwrap(),
                        1,
                        2,
                    ))
                    .unwrap();
            }
            let series = frequency_series(&schema, 0, 10_000_000_000_000, 1, "").await;
            assert_eq!(series.len(), 10_000);
            assert!(series[..9_999].iter().all(|&count| count == 0));
            assert_eq!(series[9_999], usize::from(populated));
            // A partial bucket just below the limit is accepted too.
            assert_eq!(
                frequency_series(&schema, 0, 9_999_000_000_001, 1, "").await,
                series
            );
            for end in [10_000_000_000_001, 10_001_000_000_000] {
                let end = jiff::Timestamp::from_nanosecond(end).unwrap();
                let output = schema.execute_as_system_admin(&format!(
                    r#"{{ eventFrequencySeries(filter: {{ start: "1970-01-01T00:00:00Z", end: "{end}" }}, slotSize: 1) }}"#
                )).await;
                assert_eq!(output.errors.len(), 1);
                assert_eq!(
                    output.errors[0].message,
                    "eventFrequencySeries would produce 10001 buckets; the maximum is 10000. Increase slotSize or narrow the time range."
                );
            }
        }
        let output = schema.execute_as_system_admin(
            r#"{ eventFrequencySeries(filter: { start: "1970-01-01T00:00:00Z", end: "2026-01-01T00:00:00Z", source: "192.0.2.1" }, slotSize: 1) }"#
        ).await;
        assert_eq!(output.errors.len(), 1);
        assert!(output.errors[0].message.contains("maximum is 10000"));
    }

    #[tokio::test]
    async fn event_frequency_series_start_aligned_exclusive_buckets() {
        let schema = TestSchema::new().await;
        // Fractional start crossing the epoch; cover start, an internal
        // boundary, immediately before end, and the excluded end itself.
        {
            let store = schema.store();
            for nanos in [-1_500_000_000, -500_000_000, 1_499_999_999, 1_500_000_000] {
                store
                    .events()
                    .put_event(&event_message_at(
                        Timestamp::from_nanosecond(i128::from(nanos)).unwrap(),
                        1,
                        2,
                    ))
                    .unwrap();
            }
        }
        assert_eq!(
            frequency_series(&schema, -1_500_000_000, 1_500_000_000, 1, "").await,
            [1, 1, 1]
        );
        assert_eq!(
            frequency_series(&schema, -1_500_000_000, 1_500_000_001, 1, "").await,
            [1, 1, 1, 1]
        );
        assert_eq!(
            frequency_series(&schema, -1_500_000_000, 4_500_000_001, 1, "").await,
            [1, 1, 1, 1, 0, 0, 0]
        );
        assert_eq!(
            frequency_series(
                &schema,
                -1_500_000_000,
                1_500_000_001,
                1,
                r#"source: "192.0.2.1""#
            )
            .await,
            [0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn event_frequency_series_counts_events_sharing_timestamps() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            for (seconds, count) in [(0, 2), (1, 3), (2, 2)] {
                for _ in 0..count {
                    store
                        .events()
                        .put_event(&event_message_at(
                            Timestamp::from_second(seconds).unwrap(),
                            1,
                            2,
                        ))
                        .unwrap();
                }
            }
        }
        assert_eq!(
            frequency_series(&schema, 0, 2_000_000_000, 1, "").await,
            [2, 3]
        );
    }

    #[tokio::test]
    async fn event_frequency_series_extreme_ranges_and_slot_sizes() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            for nanos in [i64::MIN, i64::MIN + 1, -1, 0, i64::MAX - 1, i64::MAX] {
                store
                    .events()
                    .put_event(&event_message_at(
                        Timestamp::from_nanosecond(i128::from(nanos)).unwrap(),
                        1,
                        2,
                    ))
                    .unwrap();
            }
        }
        assert_eq!(
            frequency_series(&schema, i64::MIN, i64::MIN + 2, 1, "").await,
            [2]
        );
        assert_eq!(
            frequency_series(&schema, i64::MAX - 2, i64::MAX, 1, "").await,
            [1]
        );
        assert_eq!(
            frequency_series(&schema, i64::MIN, i64::MAX, i64::MAX, "").await,
            [5]
        );
        // The span exceeds i64 nanoseconds; the slot size's shifted key would
        // overflow i128, but the actual bounded result is valid.
        let series = frequency_series(&schema, i64::MIN, i64::MAX, 2_592_000, "").await;
        let mut expected = vec![0; 7_117];
        expected[0] = 2;
        expected[3_558] = 2;
        expected[7_116] = 1;
        assert_eq!(series, expected);
        assert_eq!(frequency_series(&schema, 0, 1, i64::MAX, "").await, [1]);
        assert_eq!(
            frequency_series(&schema, 0, 0, 1, "").await,
            Vec::<usize>::new()
        );
        assert_eq!(
            frequency_series(&schema, 1, 0, 1, "").await,
            Vec::<usize>::new()
        );
    }

    #[tokio::test]
    async fn event_frequency_series_refuses_the_former_period_argument() {
        let schema = TestSchema::new().await;
        let filter = r#"{ start: "1970-01-01T00:00:00Z", end: "1970-01-01T00:00:02Z" }"#;
        for arguments in ["period: 1", "slotSize: 1, period: 1"] {
            let output = schema
                .execute_as_system_admin(&format!(
                    "{{ eventFrequencySeries(filter: {filter}, {arguments}) }}"
                ))
                .await;
            assert_eq!(output.data, async_graphql::Value::Null, "{arguments}");
            assert!(
                output
                    .errors
                    .iter()
                    .any(|error| error.message.contains("Unknown argument \"period\"")),
                "{arguments}: {:?}",
                output.errors
            );
        }
    }

    #[tokio::test]
    async fn event_frequency_series_validation_errors() {
        let schema = TestSchema::new().await;
        for (filter, slot_size, message) in [
            ("{}", 1, "requires non-null filter.start"),
            (
                r#"{ end: "1970-01-01T00:00:00Z" }"#,
                1,
                "requires non-null filter.start",
            ),
            (
                r#"{ start: null, end: "1970-01-01T00:00:00Z" }"#,
                1,
                "requires non-null filter.start",
            ),
            (
                r#"{ start: "1970-01-01T00:00:00Z" }"#,
                1,
                "requires non-null filter.end",
            ),
            (
                r#"{ start: "1970-01-01T00:00:00Z", end: null }"#,
                1,
                "requires non-null filter.end",
            ),
            (
                r#"{ start: "1970-01-01T00:00:00Z", end: "1970-01-01T00:00:00Z" }"#,
                0,
                "must be greater than or equal to 1",
            ),
            (
                r#"{ start: "1970-01-01T00:00:00Z", end: "1969-01-01T00:00:00Z" }"#,
                -1,
                "must be greater than or equal to 1",
            ),
            (
                r#"{ start: "2262-04-11T23:47:16.854775808Z", end: "1970-01-01T00:00:00Z" }"#,
                1,
                "outside the supported nanosecond range",
            ),
            (
                r#"{ start: "1677-09-21T00:12:43.145224191Z", end: "1677-09-21T00:12:43.145224191Z" }"#,
                1,
                "outside the supported nanosecond range",
            ),
            (
                r#"{ start: "1970-01-01T00:00:00Z", end: "2262-04-11T23:47:16.854775808Z" }"#,
                1,
                "outside the supported nanosecond range",
            ),
            (
                r#"{ start: "1970-01-01T00:00:00Z", end: "1970-01-01T00:00:00Z", destination: "bad" }"#,
                1,
                "invalid destination IP address",
            ),
            (
                r#"{ start: "1970-01-01T00:00:00Z", end: "1969-01-01T00:00:00Z", countries: ["USA"] }"#,
                1,
                "invalid country code",
            ),
        ] {
            let output = schema
                .execute_as_system_admin(&format!(
                    "{{ eventFrequencySeries(filter: {filter}, slotSize: {slot_size}) }}"
                ))
                .await;
            assert_eq!(
                output.errors.len(),
                1,
                "filter: {filter}, slotSize: {slot_size}"
            );
            assert!(
                output.errors[0].message.contains(message),
                "{:?}",
                output.errors
            );
        }
    }

    #[tokio::test]
    async fn count_events_by_network() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let ts1 = utc_micro(2018, 1, 26, 18, 30, 9, 453_829);
        db.put_event(&event_message_at(ts1, 1, 2)).unwrap();
        let ts2 = utc_micro(2018, 1, 27, 18, 30, 9, 453_829);
        db.put_event(&event_message_at(ts2, 3, 4)).unwrap();
        let ts3 = utc_micro(2018, 1, 28, 18, 30, 9, 453_829);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(
                        name: "n0",
                        description: "",
                        networks: {
                            hosts: ["0.0.0.4"],
                            networks: [],
                            ranges: []
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);
        let query = format!(
            "{{ \
                eventCountsByNetwork(
                    filter: {{ start:\"{ts1}\", end:\"{ts3}\" }},
                    first: 10
                ) {{
                    values
                    counts
                }}
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventCountsByNetwork: {values: ["0"], counts: [1]}}"#
        );
    }

    #[tokio::test]
    async fn event_counts_by_endpoint_ip_address_use_matching_direction() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
        db.put_event(&event_message_at(
            ts,
            u32::from(Ipv4Addr::new(1, 0, 0, 1)),
            u32::from(Ipv4Addr::new(2, 0, 0, 1)),
        ))
        .unwrap();
        drop(store);

        // Distinct originator and responder addresses pin each aggregation to
        // its own endpoint, so swapping the two helpers fails here.
        let res = schema
            .execute_as_system_admin(
                r"{
                    originator: eventCountsByOriginatorIpAddress(filter: {}, first: 10) {
                        values
                        counts
                    }
                    responder: eventCountsByResponderIpAddress(filter: {}, first: 10) {
                        values
                        counts
                    }
                }",
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{originator: {values: ["1.0.0.1"], counts: [1]}, responder: {values: ["2.0.0.1"], counts: [1]}}"#
        );
    }

    #[tokio::test]
    async fn event_counts_by_ip_address_and_address_pair() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            let db = store.events();
            let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
            for (offset, src, dst) in [
                (0, [1, 0, 0, 1], [2, 0, 0, 1]),
                (1, [1, 0, 0, 1], [2, 0, 0, 1]),
                (2, [1, 0, 0, 3], [2, 0, 0, 1]),
            ] {
                db.put_event(&event_message_at(
                    ts + SignedDuration::from_secs(offset),
                    u32::from(Ipv4Addr::from(src)),
                    u32::from(Ipv4Addr::from(dst)),
                ))
                .unwrap();
            }
        }

        let res = schema
            .execute_as_system_admin(
                r"{
                    byIp: eventCountsByIpAddress(filter: {}, first: 10) {
                        values
                        counts
                    }
                    byPair: eventCountsByIpAddressPair(filter: {}, first: 10) {
                        values
                        counts
                    }
                    firstPair: eventCountsByIpAddressPair(filter: {}, first: 1) {
                        values
                        counts
                    }
                }",
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        // An event counts once for each of its distinct addresses, and a
        // pair is written as the originator, a hyphen, then the responder.
        assert_eq!(
            res.data.into_json().unwrap(),
            serde_json::json!({
                "byIp": {
                    "values": ["2.0.0.1", "1.0.0.1", "1.0.0.3"],
                    "counts": [3, 2, 1],
                },
                "byPair": {
                    "values": ["1.0.0.1-2.0.0.1", "1.0.0.3-2.0.0.1"],
                    "counts": [2, 1],
                },
                "firstPair": { "values": ["1.0.0.1-2.0.0.1"], "counts": [2] },
            })
        );
    }

    #[tokio::test]
    async fn event_counts_by_country_uses_stored_codes_without_locator() {
        let (_locator_dir, locator) = event_country_locator();
        let schema = TestSchema::new_with_event_country_locator(locator).await;
        let store = schema.store();
        let db = store.events();
        let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);

        // The first event contributes US and KR. The second contributes US
        // once because its originator and responder have the same code. The
        // third starts with US on both sides, so KR must come from a later
        // responder. Repeated codes within and across sides count only once.
        db.put_event(&event_message_at(
            ts,
            u32::from(Ipv4Addr::new(1, 0, 0, 1)),
            u32::from(Ipv4Addr::new(2, 0, 0, 1)),
        ))
        .unwrap();
        db.put_event(&event_message_at(
            ts + SignedDuration::from_secs(1),
            u32::from(Ipv4Addr::new(1, 0, 0, 2)),
            u32::from(Ipv4Addr::new(1, 0, 0, 3)),
        ))
        .unwrap();
        let mut multi_host = subject_event(
            ts + SignedDuration::from_secs(2),
            Some("sensor1"),
            PrimarySubject::Host {
                ip: Ipv4Addr::new(1, 0, 0, 4).into(),
                role: ThreatRole::Actor,
            },
            vec![
                related("1.0.0.5", EndpointRole::Destination),
                related("2.0.0.2", EndpointRole::Destination),
                related("2.0.0.3", EndpointRole::Destination),
            ],
            Detail::MultiHostPortScan(MultiHostPortScanDetail {
                resp_port: 443,
                proto: 6,
                truncated_related_ips: 0,
            }),
        );
        multi_host.category = Some(EventCategory::CommandAndControl);
        db.put_event(&multi_host).unwrap();
        drop(store);

        let res = schema
            .execute_as_system_admin(
                r"{
                    eventCountsByCountry(filter: {}, first: 10) {
                        values
                        counts
                    }
                }",
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{eventCountsByCountry: {values: ["US", "KR"], counts: [3, 2]}}"#
        );
    }

    #[tokio::test]
    async fn event_counts_by_country_includes_later_originators() {
        let (_locator_dir, locator) = event_country_locator();
        let schema = TestSchema::new_with_event_country_locator(locator).await;
        let store = schema.store();
        let db = store.events();
        let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);

        // Both first endpoints are US. Only later originators carry KR, and
        // the repeated KR and the US on both sides must each count once.
        let mut ddos = subject_event(
            ts,
            Some("sensor1"),
            PrimarySubject::Host {
                ip: Ipv4Addr::new(1, 0, 0, 2).into(),
                role: ThreatRole::Target,
            },
            vec![
                related("1.0.0.1", EndpointRole::Source),
                related("2.0.0.1", EndpointRole::Source),
                related("2.0.0.2", EndpointRole::Source),
            ],
            Detail::ExternalDdos(ExternalDdosDetail {
                proto: 17,
                truncated_related_ips: 0,
            }),
        );
        ddos.category = Some(EventCategory::Impact);
        db.put_event(&ddos).unwrap();
        db.put_event(&event_message_at(
            ts + SignedDuration::from_secs(1),
            u32::from(Ipv4Addr::new(1, 0, 0, 3)),
            u32::from(Ipv4Addr::new(1, 0, 0, 4)),
        ))
        .unwrap();
        drop(store);

        let res = schema
            .execute_as_system_admin(
                r#"{
                    all: eventCountsByCountry(filter: {}, first: 10) {
                        values
                        counts
                    }
                    matchingLaterOriginator: eventCountsByCountry(
                        filter: { countries: ["KR"] }, first: 10
                    ) {
                        counts
                    }
                    limited: eventCountsByCountry(filter: {}, first: 1) {
                        values
                        counts
                    }
                    noMatches: eventCountsByCountry(
                        filter: { countries: ["JP"] }, first: 10
                    ) {
                        values
                        counts
                    }
                }"#,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        // The filtered event contributes two equally sized buckets. Checking
        // only their counts avoids imposing an order on tied country names.
        assert_eq!(
            res.data.to_string(),
            r#"{all: {values: ["US", "KR"], counts: [2, 1]}, matchingLaterOriginator: {counts: [1, 1]}, limited: {values: ["US"], counts: [2]}, noMatches: {values: [], counts: []}}"#
        );
    }

    #[tokio::test]
    async fn event_frequency_series_country_filter_uses_stored_codes_without_locator() {
        let start = utc_micro(2026, 1, 1, 0, 0, 0, 0);
        let end = start + SignedDuration::from_mins(2);
        let (_locator_dir, schema) = schema_with_country_filter_events(
            start + SignedDuration::from_secs(10),
            start + SignedDuration::from_secs(20),
        )
        .await;

        // The first bucket contains one US event and one KR-only event. The
        // second bucket contains only a KR-only event.
        let store = schema.store();
        let db = store.events();
        db.put_event(&event_message_at(
            start + SignedDuration::from_secs(70),
            u32::from(Ipv4Addr::new(2, 0, 0, 4)),
            u32::from(Ipv4Addr::new(2, 0, 0, 5)),
        ))
        .unwrap();
        drop(store);

        let res = schema
            .execute_as_system_admin(&format!(
                r#"{{
                    eventFrequencySeries(
                        filter: {{ start: "{start}", end: "{end}", countries: ["US"] }}
                        slotSize: 60
                    )
                }}"#
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r"{eventFrequencySeries: [1, 0]}");
    }

    #[tokio::test]
    async fn event_counts_by_network_country_filter_uses_stored_codes_without_locator() {
        let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
        let (_locator_dir, schema) =
            schema_with_country_filter_events(ts, ts + SignedDuration::from_secs(1)).await;

        // Both events belong to the same configured network, but only the
        // first contains a stored US endpoint code.
        let insert_res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(
                        name: "country-filter-network"
                        description: ""
                        networks: {
                            hosts: ["2.0.0.1", "2.0.0.3"]
                            networks: []
                            ranges: []
                        }
                    )
                }"#,
            )
            .await;
        assert!(
            insert_res.errors.is_empty(),
            "unexpected errors: {:?}",
            insert_res.errors
        );

        let res = schema
            .execute_as_system_admin(
                r#"{
                    withoutCountryFilter: eventCountsByNetwork(filter: {}, first: 10) {
                        values
                        counts
                    }
                    withCountryFilter: eventCountsByNetwork(
                        filter: { countries: ["US"] }
                        first: 10
                    ) {
                        values
                        counts
                    }
                }"#,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{withoutCountryFilter: {values: ["0"], counts: [2]}, withCountryFilter: {values: ["0"], counts: [1]}}"#
        );
    }

    #[tokio::test]
    async fn event_counts_by_detection_model_and_address_pair_and_detection_model() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            let db = store.events();
            let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
            for (offset, detail, src, dst) in [
                (0, Detail::DnsCovertChannel, [10, 0, 0, 1], [10, 0, 0, 2]),
                (1, Detail::DnsCovertChannel, [10, 0, 0, 1], [10, 0, 0, 2]),
                (2, Detail::DnsCovertChannel, [10, 0, 0, 3], [10, 0, 0, 2]),
                (3, Detail::LockyRansomware, [10, 0, 0, 1], [10, 0, 0, 2]),
            ] {
                let mut event = event_message_at(
                    ts + SignedDuration::from_secs(offset),
                    u32::from(Ipv4Addr::from(src)),
                    u32::from(Ipv4Addr::from(dst)),
                );
                event.detection_model = detail.detection_model();
                event.detail = detail;
                db.put_event(&event).unwrap();
            }
        }

        let res = schema
            .execute_as_system_admin(
                r"{
                    byModel: eventCountsByDetectionModel(filter: {}, first: 10) {
                        values
                        counts
                    }
                    selected: eventCountsByDetectionModel(
                        filter: { detectionModels: [LOCKY_RANSOMWARE] }
                        first: 10
                    ) {
                        values
                        counts
                    }
                    byPair: eventCountsByIpAddressPairAndDetectionModel(filter: {}, first: 10) {
                        values
                        counts
                    }
                }",
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(
            data["byModel"],
            serde_json::json!({
                "values": ["DNS_COVERT_CHANNEL", "LOCKY_RANSOMWARE"],
                "counts": [3, 1],
            })
        );
        assert_eq!(
            data["selected"],
            serde_json::json!({ "values": ["LOCKY_RANSOMWARE"], "counts": [1] })
        );
        assert_eq!(data["byPair"]["counts"][0], 2);
        assert_eq!(
            data["byPair"]["values"][0],
            "10.0.0.1-10.0.0.2-DNS_COVERT_CHANNEL"
        );
        let mut rest: Vec<_> = data["byPair"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .skip(1)
            .map(|value| value.as_str().unwrap())
            .collect();
        rest.sort_unstable();
        assert_eq!(
            rest,
            [
                "10.0.0.1-10.0.0.2-LOCKY_RANSOMWARE",
                "10.0.0.3-10.0.0.2-DNS_COVERT_CHANNEL",
            ]
        );

        // Each value of `eventCountsByDetectionModel` selects its events
        // when passed back.
        for (value, count) in [("DNS_COVERT_CHANNEL", "3"), ("LOCKY_RANSOMWARE", "1")] {
            let res = schema
                .execute_as_system_admin(&format!(
                    "{{ eventList(filter: {{ detectionModels: [{value}] }}) {{ totalCount }} }}"
                ))
                .await;
            assert_eq!(
                res.data.into_json().unwrap()["eventList"]["totalCount"],
                count
            );
        }

        for removed in [
            "{ eventCountsByKind(filter: {}, first: 10) { counts } }",
            "{ eventCountsByLevel(filter: {}, first: 10) { counts } }",
            "{ eventCountsByIpAddressPairAndKind(filter: {}, first: 10) { counts } }",
        ] {
            let res = schema.execute_as_system_admin(removed).await;
            assert!(!res.errors.is_empty(), "{removed}");
        }
    }
}
