use std::{net::Ipv4Addr, sync::Arc};

use futures_util::StreamExt;
use jiff::{SignedDuration, Timestamp};
use review_protocol::types::{Detail, DetectionEvent, EventCategory};

use crate::graphql::{
    Role, RoleGuard, TestSchema,
    event_test_support::{PutEvent, dns_event},
};

#[test]
fn undecodable_event_records_are_skippable() {
    use review_database::event::{EventDb, InvalidEvent};

    let dir = tempfile::tempdir().unwrap();
    let raw = rocksdb::OptimisticTransactionDB::open_default(dir.path()).unwrap();
    let events = EventDb::new(&raw);
    let keys: Vec<_> = (0..3)
        .map(|second| {
            events
                .put_event(&event_message_at_timestamp(
                    Timestamp::from_second(second).unwrap(),
                    1,
                    2,
                    Some(EventCategory::CommandAndControl),
                    "sensor1",
                ))
                .unwrap()
        })
        .collect();
    raw.put(keys[1].to_be_bytes(), [0xff]).unwrap();
    let mut iter = events.iter_forward();
    assert!(matches!(iter.next(), Some(Ok((key, _))) if key == keys[0]));
    let error = iter.next().unwrap().err().unwrap();
    assert!(matches!(&error, InvalidEvent::Value(_)));
    assert!(!super::is_event_read_failure(&error));
    assert!(matches!(iter.next(), Some(Ok((key, _))) if key == keys[2]));
    assert!(iter.next().is_none());
    drop(iter);

    raw.put([0xff], [0xff]).unwrap();
    let error = events.iter_forward().find_map(Result::err).unwrap();
    assert!(matches!(&error, InvalidEvent::Key(_)));
    assert!(!super::is_event_read_failure(&error));
}

fn sst_files(dir: &std::path::Path) -> std::collections::HashSet<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sst"))
        .collect()
}

async fn corrupted_event_store() -> (TestSchema, Vec<i128>, i128, i128) {
    use std::io::{Seek, SeekFrom, Write};

    use review_database::event::InvalidEvent;

    let schema = TestSchema::new().await;
    let db_dir = schema.dir.path().join("states.db");
    let existing = sst_files(&db_dir);
    let keys = {
        let store = schema.store();
        let events = store.events();
        (0..20_000)
            .map(|second| {
                events
                    .put_event(&event_message_at_timestamp(
                        Timestamp::from_second(second).unwrap(),
                        1,
                        2,
                        Some(EventCategory::CommandAndControl),
                        "sensor1",
                    ))
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    review_database::backup::create(&schema.store, true, 1).unwrap();
    let new_files = sst_files(&db_dir);
    // The flush writes every column family holding unflushed data; the
    // events, by far the most of it, are in the largest new file.
    let created = new_files
        .difference(&existing)
        .max_by_key(|path| std::fs::metadata(path).unwrap().len())
        .expect("the flush writes the events");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(created)
        .unwrap();
    file.seek(SeekFrom::Start(file.metadata().unwrap().len() / 3))
        .unwrap();
    file.write_all(&[0; 64]).unwrap();
    file.sync_all().unwrap();

    let (last_good, first_bad) = {
        let store = schema.store();
        let events = store.events();
        let mut last_good = None;
        let mut failure = None;
        for (index, item) in events.iter_forward().enumerate() {
            match item {
                Ok((key, _)) => last_good = Some(key),
                Err(error) => {
                    assert!(matches!(&error, InvalidEvent::Iteration(error)
                        if error.kind() == rocksdb::ErrorKind::Corruption));
                    assert!(super::is_event_read_failure(&error));
                    failure = Some((last_good.unwrap(), keys[index]));
                    break;
                }
            }
        }
        failure.expect("the damaged SST block must produce an iteration failure")
    };
    (schema, keys, last_good, first_bad)
}

#[tokio::test]
async fn corrupted_event_store_returns_field_errors() {
    let (schema, keys, last_good, first_bad) = corrupted_event_store().await;
    let after_bad = keys.iter().copied().find(|key| *key > first_bad).unwrap();
    let cases = [
        ("eventList(filter: {}) { totalCount }".to_string(), serde_json::json!({"eventList": null}), vec!["eventList", "totalCount"]),
        ("eventListWithTriage(filter: {}) { totalCount }".to_string(), serde_json::json!({"eventListWithTriage": null}), vec!["eventListWithTriage", "totalCount"]),
        (format!("eventList(filter: {{}}, after: \"{last_good}\", first: 100) {{ edges {{ cursor }} }}"), serde_json::Value::Null, vec!["eventList"]),
        (format!("eventListWithTriage(filter: {{}}, after: \"{last_good}\", first: 100) {{ edges {{ cursor }} }}"), serde_json::Value::Null, vec!["eventListWithTriage"]),
        (format!("eventList(filter: {{}}, before: \"{after_bad}\", last: 100) {{ edges {{ cursor }} }}"), serde_json::Value::Null, vec!["eventList"]),
        (format!("event(id: \"{first_bad}\") {{ __typename }}"), serde_json::Value::Null, vec!["event"]),
        ("eventCountsByDetectionModel(filter: {}, first: 10) { counts }".to_string(), serde_json::Value::Null, vec!["eventCountsByDetectionModel"]),
        ("eventCountsByNetwork(filter: {}, first: 10) { counts }".to_string(), serde_json::Value::Null, vec!["eventCountsByNetwork"]),
        (r#"eventFrequencySeries(filter: {start: "1970-01-01T00:00:00Z", end: "1970-01-01T05:33:20Z"}, period: 20000)"#.to_string(), serde_json::Value::Null, vec!["eventFrequencySeries"]),
    ];
    for (query, data, path) in cases {
        let response = schema
            .execute_as_system_admin(&format!("{{ {query} }}"))
            .await;
        assert_eq!(response.data.into_json().unwrap(), data, "{query}");
        assert_eq!(response.errors.len(), 1, "{query}: {:?}", response.errors);
        let error = response.errors.first().unwrap();
        assert_eq!(error.message, "failed to read events", "{query}");
        assert_eq!(
            serde_json::to_value(&error.path).unwrap(),
            serde_json::json!(path),
            "{query}"
        );
        if let Some(source) = &error.source {
            if let Some(source) = source.downcast_ref::<anyhow::Error>() {
                assert_eq!(source.chain().count(), 1);
                assert_eq!(format!("{source:#}"), "failed to read events");
            } else {
                assert_eq!(
                    source.downcast_ref::<String>().unwrap(),
                    "failed to read events"
                );
            }
        }
    }

    // An independently resolved sibling can still read an unaffected range.
    let response = schema
        .execute_as_system_admin(&format!(
            "{{ eventList(filter: {{}}) {{ totalCount }} event(id: \"{}\") {{ __typename }} }}",
            keys[0]
        ))
        .await;
    assert_eq!(response.errors.len(), 1);
    assert!(!response.data.into_json().unwrap()["event"].is_null());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn subscription_task_logs_the_starting_connection() {
    use crate::graphql::logging_test_support::{CapturedEvents, identity};
    use crate::graphql::{CustomerIds, RoleGuard, TestSchema};

    let schema = TestSchema::new().await;
    let time = "2025-01-01T00:00:00Z".parse::<Timestamp>().unwrap();
    schema
        .store()
        .events()
        .put_event(&event_message_at(time, 1, 2))
        .unwrap();
    let (events, _guard) = CapturedEvents::start();
    // The task must retain these values after the request context is dropped.
    let request = async_graphql::Request::new(r#"subscription { eventStream(start: "2025-01-01T00:00:00Z", fetchInterval: 1) { __typename } }"#)
        .data(identity("subscription"))
        .data(RoleGuard::Role(Role::SecurityMonitor))
        .data(CustomerIds(None));
    let mut stream = schema.schema.execute_stream(request);
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap();
    assert!(response.errors.is_empty(), "{response:?}");
    // Drop the subscription context, then force a send to its closed receiver.
    drop(stream);
    schema
        .store()
        .events()
        .put_event(&event_message_at(time + SignedDuration::from_secs(1), 3, 4))
        .unwrap();
    events.wait_for("Failed to fetch events:").await;
    events.assert_fields(
        "Failed to fetch events:",
        "subscription.web-app.node-01.customer.internal",
        Some("SecurityMonitor"),
    );
}

/// Selects the query of a DNS raw event body.
const DNS_QUERY: &str = "target { ... on RawEventTarget { body { ... on DnsBody { query } } } }";

/// Selects the originator address of a DNS raw event body.
const DNS_ORIG_ADDR: &str =
    "target { ... on RawEventTarget { body { ... on DnsBody { origAddr } } } }";

/// The `Event.sensor` of events emitted by the test node whose hostname is
/// `sensor1`.
const SENSOR1_EVENT_SENSOR: &str = "piglet.sensor1";

/// Creates an event message at `timestamp` emitted by the `sensor1` test
/// node.
fn sensor1_event_at(timestamp: Timestamp, src: u32, dst: u32) -> DetectionEvent {
    event_message_with_category(
        timestamp,
        src,
        dst,
        Some(EventCategory::CommandAndControl),
        SENSOR1_EVENT_SENSOR,
    )
}

async fn connection_page(schema: &TestSchema, field: &str, arguments: &str) -> serde_json::Value {
    let output = schema
        .execute_as_system_admin(&format!(
            r"{{ {field}({arguments}) {{
                edges {{ cursor node {{
                    ... on DetectionEvent {{ time triageScores {{ policyId }} }}
                }} }}
                pageInfo {{ hasNextPage hasPreviousPage }}
                totalCount
            }} }}"
        ))
        .await;
    assert!(output.errors.is_empty(), "{:?}", output.errors);
    output.data.into_json().expect("valid GraphQL JSON")[field].clone()
}

/// Creates an event message at `timestamp` with the given sensor and
/// destination `IPv4` addresses.
fn event_message_at(timestamp: Timestamp, src: u32, dst: u32) -> DetectionEvent {
    event_message_at_timestamp(
        timestamp,
        src,
        dst,
        Some(EventCategory::CommandAndControl),
        "sensor1",
    )
}

fn event_message_with_category(
    timestamp: Timestamp,
    src: u32,
    dst: u32,
    category: Option<EventCategory>,
    sensor: &str,
) -> DetectionEvent {
    event_message_at_timestamp(timestamp, src, dst, category, sensor)
}

fn event_message_at_timestamp(
    timestamp: Timestamp,
    src: u32,
    dst: u32,
    category: Option<EventCategory>,
    sensor: &str,
) -> DetectionEvent {
    dns_event(
        timestamp,
        Ipv4Addr::from(src).into(),
        Ipv4Addr::from(dst).into(),
        category,
        sensor,
    )
}

/// Returns the UTC time of the given date and time of day.
pub(super) fn utc_micro(
    year: i16,
    month: i8,
    day: i8,
    hour: i8,
    minute: i8,
    second: i8,
    microsecond: i32,
) -> Timestamp {
    jiff::tz::Offset::UTC
        .to_timestamp(jiff::civil::date(year, month, day).at(
            hour,
            minute,
            second,
            microsecond * 1_000,
        ))
        .expect("a test time is representable")
}

#[tokio::test]
async fn event_stream_fetch_interval_range() {
    let schema = TestSchema::new().await;
    for (interval, range) in [
        (0, "must be greater than or equal to 1"),
        (86_401, "must be less than or equal to 86400"),
    ] {
        let query = format!(
            r#"subscription {{ eventStream(start: "2018-01-28T00:00:00Z", fetchInterval: {interval}) {{ __typename }} }}"#
        );
        let mut stream = schema.execute_stream(&query).await;
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.errors.len(), 1, "{response:?}");
        let error = response.errors.first().unwrap();
        assert!(error.message.contains(range), "{error:?}");
        // Identify fetchInterval by the reported argument value location.
        let column = query.find("fetchInterval: ").unwrap() + "fetchInterval: ".len() + 1;
        assert_eq!(
            error.locations,
            vec![async_graphql::Pos { line: 1, column }]
        );
    }
}

#[tokio::test]
async fn event_timestamps_preserve_rfc3339_io_and_datetime_schema() {
    let schema = TestSchema::new().await;
    let cases = [
        (-1, "1969-12-31T23:59:59.999999999Z"),
        (0, "1970-01-01T00:00:00Z"),
        (1_123_456_789, "1970-01-01T00:00:01.123456789Z"),
        (i64::MIN, "1677-09-21T00:12:43.145224192Z"),
        (i64::MAX, "2262-04-11T23:47:16.854775807Z"),
    ];

    for (nanos, expected) in cases {
        let timestamp = Timestamp::from_nanosecond(i128::from(nanos))
            .expect("i64 nanoseconds must fit in jiff");
        assert_eq!(timestamp.to_string(), expected);

        let key = {
            let store = schema.store();
            store
                .events()
                .put_event(&event_message_at_timestamp(
                    timestamp,
                    1,
                    2,
                    Some(EventCategory::CommandAndControl),
                    "sensor1",
                ))
                .expect("event timestamp must be stored")
        };
        let output = schema
            .execute_as_system_admin(&format!(
                "{{ event(id: \"{key}\") {{ ... on DetectionEvent {{ time }} }} }}"
            ))
            .await;
        assert!(output.errors.is_empty(), "{:?}", output.errors);
        assert_eq!(
            output.data.to_string(),
            format!(r#"{{event: {{time: "{expected}"}}}}"#)
        );

        let input = schema
            .execute_as_system_admin(&format!(
                "{{ eventList(filter: {{ start: \"{expected}\", end: \"{expected}\" }}, first: 1) {{ totalCount }} }}"
            ))
            .await;
        assert!(input.errors.is_empty(), "{:?}", input.errors);
        assert_eq!(input.data.to_string(), r#"{eventList: {totalCount: "0"}}"#);
    }

    let compatible_offset = schema
        .execute_as_system_admin(
            r#"{ eventList(filter: { start: "1970-01-01T00:00:00+00:00", end: "1970-01-01T00:00:00+00:00" }, first: 1) { totalCount } }"#,
        )
        .await;
    assert!(
        compatible_offset.errors.is_empty(),
        "{:?}",
        compatible_offset.errors
    );
    assert_eq!(
        compatible_offset.data.to_string(),
        r#"{eventList: {totalCount: "0"}}"#
    );

    let out_of_range = schema
        .execute_as_system_admin(
            r#"{ eventList(filter: { start: "2262-04-11T23:47:16.854775808Z" }, first: 1) { totalCount } }"#,
        )
        .await;
    assert_eq!(out_of_range.errors.len(), 1);
    assert!(
        out_of_range.errors[0]
            .message
            .contains("outside the supported nanosecond range")
    );

    let introspection = schema
        .execute_as_system_admin(
            r#"{ __type(name: "EventListFilterInput") {
                inputFields { name type { kind name ofType { kind name } } }
            } }"#,
        )
        .await;
    assert!(
        introspection.errors.is_empty(),
        "{:?}",
        introspection.errors
    );
    let data = introspection.data.to_string();
    assert!(data.contains(r#"name: "start""#));
    assert!(data.contains(r#"kind: SCALAR, name: "DateTime""#));
}

#[tokio::test]
async fn empty_time_range_does_not_skip_filter_validation() {
    let schema = TestSchema::new().await;
    let queries = [
        r#"{
            eventList(
                filter: {
                    start: "2026-01-01T00:00:00Z"
                    end: "2026-01-01T00:00:00Z"
                    source: "invalid"
                }
                first: 1
            ) { edges { cursor } }
        }"#,
        r#"{
            eventListWithTriage(
                filter: {
                    start: "2026-01-01T00:00:00Z"
                    end: "2026-01-01T00:00:00Z"
                    source: "invalid"
                }
                first: 1
            ) { edges { cursor } }
        }"#,
        r#"{
            eventCountsByCategory(
                filter: {
                    start: "2026-01-01T00:00:00Z"
                    end: "2026-01-01T00:00:00Z"
                    source: "invalid"
                }
                first: 1
            ) { counts }
        }"#,
        r#"{
            eventCountsByNetwork(
                filter: {
                    start: "2026-01-01T00:00:00Z"
                    end: "2026-01-01T00:00:00Z"
                    source: "invalid"
                }
                first: 1
            ) { counts }
        }"#,
        r#"{
            eventFrequencySeries(
                filter: {
                    start: "2026-01-01T00:00:00Z"
                    end: "2026-01-01T00:00:00Z"
                    source: "invalid"
                }
                period: 1
            )
        }"#,
    ];

    for query in queries {
        let output = schema.execute_as_system_admin(query).await;
        assert_eq!(output.errors.len(), 1, "query: {query}");
        assert_eq!(output.errors[0].message, "invalid source IP address");
    }
}

#[test]
fn event_end_boundaries_are_exclusive() {
    let epoch = Timestamp::UNIX_EPOCH;
    let negative = Timestamp::from_nanosecond(-1).expect("valid timestamp");
    let positive = Timestamp::from_nanosecond(1).expect("valid timestamp");
    let minimum =
        Timestamp::from_nanosecond(i128::from(i64::MIN)).expect("i64 nanoseconds must fit in jiff");

    assert_eq!(super::latest(Some(epoch)).unwrap(), -1);
    assert_eq!(super::latest(Some(minimum)).unwrap(), i128::MIN);
    assert_eq!(super::latest(None).unwrap(), i128::MAX);
    assert_eq!(
        super::latest(Some(negative)).unwrap(),
        -((1_i128 << 64) + 1)
    );
    assert_eq!(super::latest(Some(positive)).unwrap(), (1_i128 << 64) - 1);
}

#[test]
fn event_cursor_bounds_cover_the_signed_key_range() {
    assert_eq!(super::earliest(None).unwrap(), i128::MIN);
    assert_eq!(super::earliest_after("-1").unwrap(), Some(0));
    assert_eq!(super::earliest_after(&i128::MAX.to_string()).unwrap(), None);
    assert_eq!(super::latest_before("1").unwrap(), Some(0));
    assert_eq!(super::latest_before("0").unwrap(), Some(-1));
    assert_eq!(super::latest_before(&i128::MIN.to_string()).unwrap(), None);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn unbounded_event_list_paginates_across_the_unix_epoch() {
    let schema = TestSchema::new().await;
    let before_epoch = Timestamp::from_nanosecond(-1).expect("valid timestamp");
    let epoch = Timestamp::UNIX_EPOCH;
    let after_epoch = Timestamp::from_nanosecond(1).expect("valid timestamp");
    let store = schema.store();
    let events = store.events();
    let mut keys = Vec::new();
    for (timestamp, source, destination) in [
        (before_epoch, 1, 2),
        (before_epoch, 7, 8),
        (epoch, 3, 4),
        (epoch, 9, 10),
        (after_epoch, 5, 6),
        (after_epoch, 11, 12),
    ] {
        keys.push(
            events
                .put_event(&event_message_at_timestamp(
                    timestamp,
                    source,
                    destination,
                    Some(EventCategory::CommandAndControl),
                    "sensor1",
                ))
                .expect("event timestamp must be stored"),
        );
    }
    drop(store);

    keys.sort_unstable();
    let expected: Vec<String> = keys.iter().map(ToString::to_string).collect();
    let mut after = None;
    let mut forward = Vec::new();
    for (index, expected_cursor) in expected.iter().enumerate() {
        let cursor_argument = after
            .as_ref()
            .map_or_else(String::new, |cursor| format!(r#", after: "{cursor}""#));
        let page = connection_page(
            &schema,
            "eventList",
            &format!("filter: {{}}, first: 1{cursor_argument}"),
        )
        .await;
        assert_eq!(page["totalCount"], "6");
        assert_eq!(page["pageInfo"]["hasNextPage"], index < expected.len() - 1);
        assert_eq!(page["pageInfo"]["hasPreviousPage"], false);
        let cursor = page["edges"][0]["cursor"]
            .as_str()
            .expect("page must contain a cursor")
            .to_string();
        assert_eq!(&cursor, expected_cursor);
        forward.push(cursor.clone());
        after = Some(cursor);
    }
    assert_eq!(forward, expected);

    let mut before = None;
    let mut backward = Vec::new();
    for (index, expected_cursor) in expected.iter().rev().enumerate() {
        let cursor_argument = before
            .as_ref()
            .map_or_else(String::new, |cursor| format!(r#", before: "{cursor}""#));
        let page = connection_page(
            &schema,
            "eventList",
            &format!("filter: {{}}, last: 1{cursor_argument}"),
        )
        .await;
        assert_eq!(page["totalCount"], "6");
        assert_eq!(page["pageInfo"]["hasNextPage"], false);
        assert_eq!(
            page["pageInfo"]["hasPreviousPage"],
            index < expected.len() - 1
        );
        let cursor = page["edges"][0]["cursor"]
            .as_str()
            .expect("page must contain a cursor")
            .to_string();
        assert_eq!(&cursor, expected_cursor);
        backward.push(cursor.clone());
        before = Some(cursor);
    }
    backward.reverse();
    assert_eq!(backward, expected);

    let triage = r#"triage: {
        policies: [{
            id: 7
            packetAttr: []
            score: [{
                threatCategory: COMMAND_AND_CONTROL
                detectionModel: DNS_COVERT_CHANNEL
                score: 0.0
                weight: 1.0
            }]
            response: [{ minimumScore: 0.0, kind: MANUAL }]
        }]
        exclusions: [{
            ipAddress: { hosts: ["0.0.0.4"], networks: [], ranges: [] }
        }]
    }"#;
    // The exclusion would have removed the event from 0.0.0.3 to 0.0.0.4,
    // but exclusions no longer remove events.
    let expected_with_triage = expected.clone();
    let mut after = None;
    let mut with_triage = Vec::new();
    for (index, expected_cursor) in expected_with_triage.iter().enumerate() {
        let cursor_argument = after
            .as_ref()
            .map_or_else(String::new, |cursor| format!(r#", after: "{cursor}""#));
        let page = connection_page(
            &schema,
            "eventListWithTriage",
            &format!("filter: {{}}, {triage}, first: 1{cursor_argument}"),
        )
        .await;
        assert_eq!(page["totalCount"], "6");
        assert_eq!(
            page["pageInfo"]["hasNextPage"],
            index < expected_with_triage.len() - 1
        );
        assert_eq!(page["pageInfo"]["hasPreviousPage"], false);
        assert_eq!(page["edges"][0]["node"]["triageScores"][0]["policyId"], "7");
        let cursor = page["edges"][0]["cursor"]
            .as_str()
            .expect("page must contain a cursor")
            .to_string();
        assert_eq!(&cursor, expected_cursor);
        with_triage.push(cursor.clone());
        after = Some(cursor);
    }
    assert_eq!(with_triage, expected_with_triage);

    let mut before = None;
    let mut with_triage_backward = Vec::new();
    for (index, expected_cursor) in expected_with_triage.iter().rev().enumerate() {
        let cursor_argument = before
            .as_ref()
            .map_or_else(String::new, |cursor| format!(r#", before: "{cursor}""#));
        let page = connection_page(
            &schema,
            "eventListWithTriage",
            &format!("filter: {{}}, {triage}, last: 1{cursor_argument}"),
        )
        .await;
        assert_eq!(page["totalCount"], "6");
        assert_eq!(page["pageInfo"]["hasNextPage"], false);
        assert_eq!(
            page["pageInfo"]["hasPreviousPage"],
            index < expected_with_triage.len() - 1
        );
        assert_eq!(page["edges"][0]["node"]["triageScores"][0]["policyId"], "7");
        let cursor = page["edges"][0]["cursor"]
            .as_str()
            .expect("page must contain a cursor")
            .to_string();
        assert_eq!(&cursor, expected_cursor);
        with_triage_backward.push(cursor.clone());
        before = Some(cursor);
    }
    with_triage_backward.reverse();
    assert_eq!(with_triage_backward, expected_with_triage);

    for (arguments, field, total_count) in [
        (
            format!(r#"filter: {{}}, after: "{}", first: 1"#, i128::MAX),
            "eventList",
            "6",
        ),
        (
            format!(r#"filter: {{}}, before: "{}", last: 1"#, i128::MIN),
            "eventList",
            "6",
        ),
        (
            format!(
                r#"filter: {{}}, {triage}, after: "{}", first: 1"#,
                i128::MAX
            ),
            "eventListWithTriage",
            "6",
        ),
        (
            format!(
                r#"filter: {{}}, {triage}, before: "{}", last: 1"#,
                i128::MIN
            ),
            "eventListWithTriage",
            "6",
        ),
    ] {
        let page = connection_page(&schema, field, &arguments).await;
        assert_eq!(page["edges"], serde_json::json!([]));
        assert_eq!(page["totalCount"], total_count);
        assert_eq!(page["pageInfo"]["hasNextPage"], false);
        assert_eq!(page["pageInfo"]["hasPreviousPage"], false);
    }

    for (field, triage_argument, total_count) in
        [("eventList", "", "6"), ("eventListWithTriage", triage, "6")]
    {
        let page = connection_page(
            &schema,
            field,
            &format!(r#"filter: {{}}, {triage_argument} before: "0", last: 1"#),
        )
        .await;
        assert_eq!(page["edges"][0]["cursor"], expected[1]);
        assert_eq!(page["totalCount"], total_count);
    }

    let range = format!(r#"{{ start: "{epoch}", end: "{after_epoch}" }}"#);
    for (cursor, argument, expected_cursors) in [
        (&expected[1], "after", vec![&expected[2], &expected[3]]),
        (&expected[4], "after", vec![]),
        (&expected[2], "before", vec![]),
        (&expected[5], "before", vec![&expected[2], &expected[3]]),
    ] {
        let page = connection_page(
            &schema,
            "eventList",
            &format!(r#"filter: {range}, {argument}: "{cursor}", first: 10"#),
        )
        .await;
        let cursors = page["edges"]
            .as_array()
            .expect("connection edges must be an array")
            .iter()
            .map(|edge| {
                edge["cursor"]
                    .as_str()
                    .expect("edge cursor must be a string")
            })
            .collect::<Vec<_>>();
        assert_eq!(cursors, expected_cursors);
        assert_eq!(page["totalCount"], "2");
    }
}

#[tokio::test]
async fn minimum_end_is_an_empty_event_range() {
    let schema = TestSchema::new().await;
    let minimum =
        Timestamp::from_nanosecond(i128::from(i64::MIN)).expect("i64 nanoseconds must fit in jiff");
    let before_epoch = Timestamp::from_nanosecond(-1).expect("valid timestamp");
    let store = schema.store();
    let events = store.events();
    let minimum_key = events
        .put_event(&event_message_at_timestamp(
            minimum,
            1,
            2,
            Some(EventCategory::CommandAndControl),
            "sensor1",
        ))
        .expect("event timestamp must be stored");
    // The key holds the time in its upper 64 bits, then the detection model.
    assert_eq!(minimum_key >> 64, i128::from(i64::MIN));
    let before_epoch_key = events
        .put_event(&event_message_at_timestamp(
            before_epoch,
            1,
            2,
            Some(EventCategory::CommandAndControl),
            "sensor1",
        ))
        .expect("event timestamp must be stored");
    assert_eq!(before_epoch_key >> 64, -1);
    drop(store);

    let output = schema
        .execute_as_system_admin(&format!(
            r#"{{
                eventList(filter: {{ end: "{minimum}" }}) {{ edges {{ cursor }} totalCount }}
                eventCountsByCategory(filter: {{ end: "{minimum}" }}, first: 10) {{ counts }}
                eventFrequencySeries(filter: {{ start: "{minimum}", end: "{minimum}" }}, period: 1)
                beforeMinimum: eventList(
                    filter: {{}}
                    before: "{}"
                    last: 10
                ) {{ edges {{ cursor }} totalCount }}
            }}"#,
            i128::MIN
        ))
        .await;
    assert!(output.errors.is_empty(), "{:?}", output.errors);
    assert_eq!(
        output.data.to_string(),
        r#"{eventList: {edges: [], totalCount: "0"}, eventCountsByCategory: {counts: []}, eventFrequencySeries: [], beforeMinimum: {edges: [], totalCount: "2"}}"#
    );

    let epoch_output = schema
        .execute_as_system_admin(&format!(
            r#"{{ eventList(filter: {{ start: "{before_epoch}", end: "1970-01-01T00:00:00Z" }}) {{ edges {{ cursor }} totalCount }} }}"#
        ))
        .await;
    assert!(epoch_output.errors.is_empty(), "{:?}", epoch_output.errors);
    assert_eq!(
        epoch_output.data.to_string(),
        format!(r#"{{eventList: {{edges: [{{cursor: "{before_epoch_key}"}}], totalCount: "1"}}}}"#)
    );
}

#[tokio::test]
async fn negative_end_is_exclusive_across_event_queries() {
    let schema = TestSchema::new().await;
    let start = Timestamp::from_nanosecond(-2).expect("valid timestamp");
    let end = Timestamp::from_nanosecond(-1).expect("valid timestamp");
    let store = schema.store();
    let events = store.events();
    events
        .put_event(&event_message_at_timestamp(
            start,
            1,
            2,
            Some(EventCategory::CommandAndControl),
            "sensor1",
        ))
        .expect("event at start must be stored");
    events
        .put_event(&event_message_at_timestamp(
            end,
            1,
            2,
            Some(EventCategory::CommandAndControl),
            "sensor1",
        ))
        .expect("event at end must be stored");
    drop(store);

    let network = schema
        .execute_as_system_admin(
            r#"mutation {
                insertNetwork(
                    name: "negative-time-range"
                    description: ""
                    networks: { hosts: ["0.0.0.2"], networks: [], ranges: [] }
                )
            }"#,
        )
        .await;
    assert!(network.errors.is_empty(), "{:?}", network.errors);

    let output = schema
        .execute_as_system_admin(&format!(
            r#"{{
                eventListWithTriage(
                    filter: {{ start: "{start}", end: "{end}" }}
                    triage: {{
                        policies: [{{
                            id: 0
                            packetAttr: []
                            score: [{{
                                threatCategory: COMMAND_AND_CONTROL
                                detectionModel: DNS_COVERT_CHANNEL
                                score: 0.0
                                weight: 1.0
                            }}]
                            response: [{{ minimumScore: 0.5, kind: MANUAL }}]
                        }}]
                    }}
                    first: 10
                ) {{
                    edges {{
                        node {{ ... on DetectionEvent {{ time triageScores {{ policyId }} }} }}
                    }}
                }}
                eventCountsByCategory(
                    filter: {{ start: "{start}", end: "{end}" }}
                    first: 10
                ) {{ counts }}
                eventCountsByNetwork(
                    filter: {{ start: "{start}", end: "{end}" }}
                    first: 10
                ) {{ values counts }}
                eventFrequencySeries(
                    filter: {{ start: "{start}", end: "{end}" }}
                    period: 1
                )
            }}"#
        ))
        .await;
    assert!(output.errors.is_empty(), "{:?}", output.errors);
    assert_eq!(
        output.data.to_string(),
        r#"{eventListWithTriage: {edges: [{node: {time: "1969-12-31T23:59:59.999999998Z", triageScores: [{policyId: "0"}]}}]}, eventCountsByCategory: {counts: [1]}, eventCountsByNetwork: {values: ["0"], counts: [1]}, eventFrequencySeries: [1]}"#
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn grouped_event_queries_cross_the_unix_epoch() {
    let schema = TestSchema::new().await;
    let start = Timestamp::from_nanosecond(-2_000_000_000).unwrap();
    let epoch = Timestamp::UNIX_EPOCH;
    let positive = Timestamp::from_nanosecond(2_000_000_000).unwrap();
    let end = Timestamp::from_nanosecond(4_000_000_000).unwrap();
    let store = schema.store();
    let events = store.events();
    for (time, detail, category, source) in [
        (
            start,
            Detail::DnsCovertChannel,
            EventCategory::CommandAndControl,
            1,
        ),
        (
            epoch,
            Detail::LockyRansomware,
            EventCategory::CommandAndControl,
            3,
        ),
        (
            positive,
            Detail::DnsCovertChannel,
            EventCategory::InitialAccess,
            5,
        ),
        (
            end,
            Detail::DnsCovertChannel,
            EventCategory::InitialAccess,
            7,
        ),
    ] {
        let mut message = event_message_at_timestamp(time, source, 2, Some(category), "sensor1");
        message.detection_model = detail.detection_model();
        message.detail = detail;
        events.put_event(&message).expect("event must be stored");
    }
    drop(store);

    let network = schema
        .execute_as_system_admin(
            r#"mutation {
                insertNetwork(
                    name: "cross-epoch"
                    description: ""
                    networks: { hosts: ["0.0.0.2"], networks: [], ranges: [] }
                )
            }"#,
        )
        .await;
    assert!(network.errors.is_empty(), "{:?}", network.errors);

    let output = schema
        .execute_as_system_admin(&format!(
            r#"{{
                eventListWithTriage(
                    filter: {{ start: "{start}", end: "{end}" }}
                    triage: {{
                        policies: [{{
                            id: 0
                            packetAttr: []
                            score: [
                                {{
                                    threatCategory: COMMAND_AND_CONTROL
                                    detectionModel: DNS_COVERT_CHANNEL
                                    score: 0.0
                                    weight: 0.9
                                }}
                                {{
                                    threatCategory: COMMAND_AND_CONTROL
                                    detectionModel: LOCKY_RANSOMWARE
                                    score: 0.0
                                    weight: 0.9
                                }}
                                {{
                                    threatCategory: INITIAL_ACCESS
                                    detectionModel: DNS_COVERT_CHANNEL
                                    score: 0.0
                                    weight: 0.5
                                }}
                            ]
                            response: [{{ minimumScore: 0.3, kind: MANUAL }}]
                        }}]
                    }}
                    first: 10
                ) {{
                    edges {{
                        node {{
                            detectionModel time triageScores {{ score }}
                        }}
                    }}
                }}
                eventCountsByCategory(
                    filter: {{ start: "{start}", end: "{end}" }}
                    first: 10
                ) {{ counts }}
                eventCountsByNetwork(
                    filter: {{ start: "{start}", end: "{end}" }}
                    first: 10
                ) {{ values counts }}
                eventFrequencySeries(
                    filter: {{ start: "{start}", end: "{end}" }}
                    period: 1
                )
            }}"#
        ))
        .await;
    assert!(output.errors.is_empty(), "{:?}", output.errors);
    let data = output.data.into_json().expect("valid GraphQL JSON");
    let triage = data["eventListWithTriage"]["edges"]
        .as_array()
        .expect("triage edges must be an array")
        .iter()
        .map(|edge| &edge["node"])
        .collect::<Vec<_>>();
    assert_eq!(triage.len(), 3);
    assert!(triage.iter().all(|node| !node["triageScores"].is_null()));
    assert_eq!(triage[0]["detectionModel"], "DNS_COVERT_CHANNEL");
    assert_eq!(triage[0]["time"], start.to_string());
    assert_eq!(triage[1]["detectionModel"], "LOCKY_RANSOMWARE");
    assert_eq!(triage[1]["time"], epoch.to_string());
    assert_eq!(triage[2]["detectionModel"], "DNS_COVERT_CHANNEL");
    assert_eq!(triage[2]["time"], positive.to_string());
    assert_eq!(
        triage[0]["triageScores"][0]["score"],
        triage[1]["triageScores"][0]["score"]
    );
    assert!(
        triage[1]["triageScores"][0]["score"].as_f64().unwrap()
            > triage[2]["triageScores"][0]["score"].as_f64().unwrap()
    );
    assert_eq!(
        data["eventCountsByCategory"]["counts"],
        serde_json::json!([2, 1])
    );
    assert_eq!(
        data["eventCountsByNetwork"]["values"],
        serde_json::json!(["0"])
    );
    assert_eq!(
        data["eventCountsByNetwork"]["counts"],
        serde_json::json!([3])
    );
    assert_eq!(
        data["eventFrequencySeries"],
        serde_json::json!([1, 0, 1, 0, 1, 0])
    );
}

const IP2LOCATION_HEADER_LEN: usize = 35;
const IP2LOCATION_ROW_LEN: usize = 8;

fn write_fixture_u32(bytes: &mut [u8], offset: usize, value: u32) {
    let end = offset
        .checked_add(size_of::<u32>())
        .expect("fixture offset must fit in usize");
    bytes
        .get_mut(offset..end)
        .expect("fixture offset must be within the buffer")
        .copy_from_slice(&value.to_le_bytes());
}

fn append_fixture_country(bytes: &mut Vec<u8>, code: [u8; 2], name: &str) -> u32 {
    let pointer = u32::try_from(bytes.len()).expect("test fixture must fit in u32");
    bytes.push(u8::try_from(code.len()).expect("country code length must fit in u8"));
    bytes.extend_from_slice(&code);
    bytes.push(u8::try_from(name.len()).expect("country name length must fit in u8"));
    bytes.extend_from_slice(name.as_bytes());
    pointer
}

fn write_fixture_row(bytes: &mut [u8], row: usize, ip_from: Ipv4Addr, country_pointer: u32) {
    let offset = IP2LOCATION_HEADER_LEN + row * IP2LOCATION_ROW_LEN;
    write_fixture_u32(bytes, offset, u32::from(ip_from));
    write_fixture_u32(bytes, offset + size_of::<u32>(), country_pointer);
}

/// Creates a minimal DB1 file mapping `1.0.0.0/8` to US and
/// `2.0.0.0/8` to KR for deterministic ingestion-time country resolution.
pub(super) fn event_country_locator() -> (tempfile::TempDir, Arc<ip2location::DB>) {
    let locator_dir = tempfile::tempdir().unwrap();
    let locator_path = locator_dir.path().join("event-countries.bin");

    // DB1 has a 35-byte header, two 8-byte data rows, and one boundary row.
    let mut bytes = vec![
        1, 2, 26, 8, 27, // DB type, columns, and creation date.
        1, 0, 0, 0, // Last searchable IPv4 row index.
        36, 0, 0, 0, // One-based IPv4 row address.
        0, 0, 0, 0, // IPv6 row count.
        0, 0, 0, 0, // IPv6 row address.
        0, 0, 0, 0, // IPv4 index address.
        0, 0, 0, 0, // IPv6 index address.
        1, 0, // Product and license codes.
        0, 0, 0, 0, // Database size, populated below.
    ];
    bytes.resize(IP2LOCATION_HEADER_LEN + 3 * IP2LOCATION_ROW_LEN, 0);

    let us_pointer = append_fixture_country(&mut bytes, *b"US", "United States");
    let kr_pointer = append_fixture_country(&mut bytes, *b"KR", "South Korea");
    write_fixture_row(&mut bytes, 0, Ipv4Addr::new(1, 0, 0, 0), us_pointer);
    write_fixture_row(&mut bytes, 1, Ipv4Addr::new(2, 0, 0, 0), kr_pointer);
    write_fixture_row(&mut bytes, 2, Ipv4Addr::new(3, 0, 0, 0), 0);
    let database_size = u32::try_from(bytes.len()).expect("test fixture must fit in u32");
    write_fixture_u32(&mut bytes, 31, database_size);

    std::fs::write(&locator_path, bytes).unwrap();
    let locator = ip2location::DB::from_file(locator_path).unwrap();
    (locator_dir, Arc::new(locator))
}

/// Creates a schema with one US-to-KR event and one KR-only event while
/// keeping the ingestion-time country locator out of the GraphQL context.
pub(super) async fn schema_with_country_filter_events(
    us_event_time: Timestamp,
    kr_event_time: Timestamp,
) -> (tempfile::TempDir, TestSchema) {
    let (locator_dir, locator) = event_country_locator();
    let schema = TestSchema::new_with_event_country_locator(locator).await;
    let store = schema.store();
    let db = store.events();
    db.put_event(&event_message_at(
        us_event_time,
        u32::from(Ipv4Addr::new(1, 0, 0, 1)),
        u32::from(Ipv4Addr::new(2, 0, 0, 1)),
    ))
    .unwrap();
    db.put_event(&event_message_at(
        kr_event_time,
        u32::from(Ipv4Addr::new(2, 0, 0, 2)),
        u32::from(Ipv4Addr::new(2, 0, 0, 3)),
    ))
    .unwrap();
    drop(store);
    (locator_dir, schema)
}

#[test]
fn country_code_converts_stored_bytes() {
    assert_eq!(super::detection::country_code(b"KR"), "KR");
    assert_eq!(super::detection::country_code(b"ZZ"), "ZZ");
    assert_eq!(super::detection::country_code(b"XX"), "XX");
    assert_eq!(super::detection::country_code(&[0xff, b'X']), "ZZ");
}

#[tokio::test]
async fn event_lookup_by_id_returns_matching_event() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    let ts = utc_micro(2018, 1, 26, 18, 30, 9, 453_829);
    let key = db.put_event(&event_message_at(ts, 1, 2)).unwrap();
    drop(store);

    let query = format!("{{ event(id: \"{key}\") {{ id time {DNS_QUERY} }} }}");
    let res = schema.execute_as_system_admin(&query).await;
    assert_eq!(
        res.data.to_string(),
        format!(
            r#"{{event: {{id: "{key}", time: "2018-01-26T18:30:09.453829Z", target: {{body: {{query: "domain"}}}}}}}}"#
        )
    );
}

#[tokio::test]
async fn single_endpoint_event_countries_use_stored_codes_without_locator() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
    let key = db.put_event(&event_message_at(ts, 1, 2)).unwrap();
    drop(store);

    let query = format!(
        "{{ event(id: \"{key}\") {{ \
            endpointCountries {{ ip country }} \
        }} }}"
    );
    let res = schema.execute_as_system_admin(&query).await;

    assert_eq!(
        res.data.to_string(),
        r#"{event: {endpointCountries: [{ip: "0.0.0.1", country: "XX"}, {ip: "0.0.0.2", country: "XX"}]}}"#
    );
}

#[tokio::test]
async fn event_country_filter_uses_stored_endpoint_codes_without_locator() {
    let (_locator_dir, locator) = event_country_locator();
    let schema = TestSchema::new_with_event_country_locator(locator).await;
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

    // The schema has no IP2Location value in its request context. Both
    // endpoint filters therefore depend exclusively on the stored codes.
    let res = schema
        .execute_as_system_admin(
            r#"{
                byOrigin: eventList(filter: { countries: ["US"] }) {
                    edges { node { endpointCountries { country } } }
                    totalCount
                }
                byResponder: eventList(filter: { countries: ["KR"] }) {
                    edges { node { endpointCountries { country } } }
                    totalCount
                }
                noMatch: eventList(filter: { countries: ["JP"] }) {
                    edges { node { endpointCountries { country } } }
                    totalCount
                }
            }"#,
        )
        .await;

    assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
    assert_eq!(
        res.data.to_string(),
        r#"{byOrigin: {edges: [{node: {endpointCountries: [{country: "US"}, {country: "KR"}]}}], totalCount: "1"}, byResponder: {edges: [{node: {endpointCountries: [{country: "US"}, {country: "KR"}]}}], totalCount: "1"}, noMatch: {edges: [], totalCount: "0"}}"#
    );
}

#[tokio::test]
async fn country_filter_with_no_locator_selects_xx() {
    // The store is created without a locator, so the event is written with
    // the unresolved country code.
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

    let res = schema
        .execute_as_system_admin(
            r#"{
                unfiltered: eventList(filter: {}) { totalCount }
                byUnresolved: eventList(filter: { countries: ["XX"] }) { totalCount }
                byUnknown: eventList(filter: { countries: ["ZZ"] }) { totalCount }
                byCountry: eventList(filter: { countries: ["US"] }) { totalCount }
            }"#,
        )
        .await;

    assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
    assert_eq!(
        res.data.to_string(),
        r#"{unfiltered: {totalCount: "1"}, byUnresolved: {totalCount: "1"}, byUnknown: {totalCount: "0"}, byCountry: {totalCount: "0"}}"#
    );
}

#[tokio::test]
async fn failed_country_lookup_stores_zz_and_filter_selects_it() {
    let (_locator_dir, locator) = event_country_locator();
    let schema = TestSchema::new_with_event_country_locator(locator).await;
    let store = schema.store();
    let db = store.events();
    let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
    let key = db
        .put_event(&event_message_at(
            ts,
            u32::from(Ipv4Addr::new(4, 0, 0, 1)),
            u32::from(Ipv4Addr::new(5, 0, 0, 1)),
        ))
        .unwrap();
    drop(store);

    let res = schema
        .execute_as_system_admin(&format!(
            r#"{{
                event(id: "{key}") {{
                    endpointCountries {{ country }}
                }}
                byUnknown: eventList(filter: {{ countries: ["ZZ"] }}) {{ totalCount }}
                byUnresolved: eventList(filter: {{ countries: ["XX"] }}) {{ totalCount }}
                byCountry: eventList(filter: {{ countries: ["US"] }}) {{ totalCount }}
            }}"#
        ))
        .await;

    assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
    assert_eq!(
        res.data.to_string(),
        r#"{event: {endpointCountries: [{country: "ZZ"}, {country: "ZZ"}]}, byUnknown: {totalCount: "1"}, byUnresolved: {totalCount: "0"}, byCountry: {totalCount: "0"}}"#
    );
}

#[tokio::test]
async fn country_aggregation_placeholder_buckets_round_trip_to_filters() {
    let unresolved_schema = TestSchema::new().await;
    let (_locator_dir, locator) = event_country_locator();
    let unknown_schema = TestSchema::new_with_event_country_locator(locator).await;

    for (schema, code, address) in [
        (unresolved_schema, "XX", Ipv4Addr::new(1, 0, 0, 1)),
        (unknown_schema, "ZZ", Ipv4Addr::new(4, 0, 0, 1)),
    ] {
        let store = schema.store();
        let db = store.events();
        let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
        for offset in 0..2 {
            db.put_event(&event_message_at(
                ts + SignedDuration::from_secs(offset),
                u32::from(address),
                u32::from(address),
            ))
            .unwrap();
        }
        drop(store);

        let aggregation = schema
            .execute_as_system_admin(
                r"{
                    eventCountsByCountry(filter: {}, first: 100) {
                        values
                        counts
                    }
                }",
            )
            .await;
        assert!(
            aggregation.errors.is_empty(),
            "unexpected errors for {code}: {:?}",
            aggregation.errors
        );
        let aggregation = aggregation.data.into_json().unwrap();
        let buckets = aggregation
            .get("eventCountsByCountry")
            .expect("country aggregation must be present");
        let values = buckets
            .get("values")
            .and_then(serde_json::Value::as_array)
            .expect("country aggregation values must be an array");
        let counts = buckets
            .get("counts")
            .and_then(serde_json::Value::as_array)
            .expect("country aggregation counts must be an array");
        let index = values
            .iter()
            .position(|value| value.as_str() == Some(code))
            .expect("placeholder aggregation bucket must be present");
        let bucket_code = values
            .get(index)
            .and_then(serde_json::Value::as_str)
            .expect("placeholder aggregation bucket must be a string");
        let count = counts
            .get(index)
            .and_then(serde_json::Value::as_u64)
            .expect("placeholder aggregation count must be an integer");

        let filtered = schema
            .execute_as_system_admin(&format!(
                r#"{{ eventList(filter: {{ countries: ["{bucket_code}"] }}) {{ totalCount }} }}"#
            ))
            .await;
        assert!(
            filtered.errors.is_empty(),
            "unexpected errors for {code}: {:?}",
            filtered.errors
        );
        let filtered = filtered.data.into_json().unwrap();
        let expected_count = count.to_string();
        assert_eq!(
            filtered
                .get("eventList")
                .and_then(|event_list| event_list.get("totalCount"))
                .and_then(serde_json::Value::as_str),
            Some(expected_count.as_str())
        );
    }
}

#[tokio::test]
async fn event_list_with_triage_country_filter_uses_stored_codes_without_locator() {
    let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
    let (_locator_dir, schema) =
        schema_with_country_filter_events(ts, ts + SignedDuration::from_secs(1)).await;

    // Omitting inline triage still exercises the dedicated
    // eventListWithTriage matching and pagination path.
    let res = schema
        .execute_as_system_admin(
            r#"{
                eventListWithTriage(filter: { countries: ["US"] }, first: 10) {
                    edges { node { target { ... on RawEventTarget { body { ... on DnsBody { origAddr } } } } } }
                    totalCount
                }
            }"#,
        )
        .await;

    assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
    assert_eq!(
        res.data.to_string(),
        r#"{eventListWithTriage: {edges: [{node: {target: {body: {origAddr: "1.0.0.1"}}}}], totalCount: "1"}}"#
    );
}

#[tokio::test]
async fn event_lookup_unknown_id_returns_null() {
    let schema = TestSchema::new().await;
    let res = schema
        .execute_as_system_admin("{ event(id: \"0\") { id } }")
        .await;
    assert_eq!(res.data.to_string(), r"{event: null}");
}

#[tokio::test]
async fn event_lookup_invalid_id_errors() {
    let schema = TestSchema::new().await;
    let res = schema
        .execute_as_system_admin("{ event(id: \"not-a-number\") { id } }")
        .await;
    assert_ne!(res.errors, Vec::new());
}

#[tokio::test]
async fn event_lookup_id_matches_event_list_cursor() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    let ts = utc_micro(2018, 1, 26, 18, 30, 9, 453_829);
    db.put_event(&event_message_at(ts, 1, 2)).unwrap();
    drop(store);

    let res = schema
        .execute_as_system_admin("{ eventList(filter: {}) { edges { cursor, node { id } } } }")
        .await;
    let s = res.data.to_string();
    let cursor_pos = s.find("cursor: \"").expect("cursor present");
    let cursor_start = cursor_pos + "cursor: \"".len();
    let cursor_end = cursor_start + s[cursor_start..].find('"').unwrap();
    let cursor = &s[cursor_start..cursor_end];
    let id_pos = s.find("id: \"").expect("id present");
    let id_start = id_pos + "id: \"".len();
    let id_end = id_start + s[id_start..].find('"').unwrap();
    let id = &s[id_start..id_end];
    assert_eq!(cursor, id);
}

#[tokio::test]
async fn event_lookup_respects_tenant_scope() {
    let schema = TestSchema::new().await;

    let res = schema
        .execute_as_system_admin(
            r#"mutation {
                insertNode(
                    name: "sensor1",
                    customerId: 0,
                    description: "This is the sensor node",
                    hostname: "sensor1",
                    agents: [{
                        key: "sensor"
                        kind: SENSOR
                        status: ENABLED
                    }],
                    externalServices: [],
                )
            }"#,
        )
        .await;
    assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);
    let _ = schema
        .execute_as_system_admin(
            r#"mutation {
                applyNode(
                    id: "0"
                    node: {
                        name: "sensor1",
                        nameDraft: "sensor1",
                        profile: null,
                        profileDraft: {
                            customerId: 0,
                            description: "This is the sensor node",
                            hostname: "sensor1",
                        }
                        agents: [
                            {
                                key: "sensor",
                                kind: "SENSOR",
                                status: "ENABLED"
                            }
                        ],
                        externalServices: []
                    }
                )
            }"#,
        )
        .await;

    let store = schema.store();
    let db = store.events();
    let ts = utc_micro(2018, 1, 26, 18, 30, 9, 453_829);
    let key = db.put_event(&sensor1_event_at(ts, 1, 2)).unwrap();
    drop(store);

    let query = format!("{{ event(id: \"{key}\") {{ ... on DetectionEvent {{ sensor }} }} }}");

    // Scoped user assigned to customer 0 (which owns sensor1) can see it.
    let res = schema
        .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![0]))
        .await;
    assert_eq!(
        res.data.to_string(),
        format!(r#"{{event: {{sensor: "{SENSOR1_EVENT_SENSOR}"}}}}"#)
    );

    // Scoped user assigned to customer 1 (not owning sensor1) cannot.
    let res = schema
        .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![1]))
        .await;
    assert_eq!(res.data.to_string(), r"{event: null}");
}

#[tokio::test]
async fn event_list() {
    let schema = TestSchema::new().await;
    let res = schema
        .execute_as_system_admin("{eventList(filter: {}){edges{node{time}}totalCount}}")
        .await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventList: {edges: [], totalCount: "0"}}"#
    );

    let store = schema.store();
    let db = store.events();
    let ts1 = utc_micro(2018, 1, 26, 18, 30, 9, 453_829);
    db.put_event(&event_message_at(ts1, 1, 2)).unwrap();
    let ts2 = utc_micro(2018, 1, 27, 18, 30, 9, 453_829);
    db.put_event(&event_message_at(ts2, 3, 4)).unwrap();
    let ts3 = utc_micro(2018, 1, 28, 18, 30, 9, 453_829);
    db.put_event(&event_message_at(ts3, 5, 6)).unwrap();
    let query = format!(
        "{{ \
            eventList(filter: {{ start:\"{ts2}\", end:\"{ts3}\" }}) {{ \
                edges {{ node {{... on DetectionEvent {{ time }} }} }} \
                totalCount \
            }} \
        }}"
    );
    let res = schema.execute_as_system_admin(&query).await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829Z"}}], totalCount: "1"}}"#
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn filter_by_categories_and_sensors() {
    let schema = TestSchema::new().await;
    let res = schema
        .execute_as_system_admin("{eventList(filter: {}){edges{node{time}}totalCount}}")
        .await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventList: {edges: [], totalCount: "0"}}"#
    );

    let res = schema
        .execute_as_system_admin(
            r#"mutation {
                insertNode(
                    name: "sensor1",
                    customerId: 0,
                    description: "This is the sensor node",
                    hostname: "sensor1",
                    agents: [{
                        key: "sensor"
                        kind: SENSOR
                        status: ENABLED
                    }],
                    externalServices: [],
                )
            }"#,
        )
        .await;
    assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);
    let _ = schema
        .execute_as_system_admin(
            r#"mutation {
                applyNode(
                    id: "0"
                    node: {
                        name: "sensor1",
                        nameDraft: "sensor1",
                        profile: null,
                        profileDraft: {
                            customerId: 0,
                            description: "This is the sensor node",
                            hostname: "sensor1",
                        }
                        agents: [
                            {
                                key: "sensor",
                                kind: "SENSOR",
                                status: "ENABLED"
                            }
                        ],
                        externalServices: []
                    }
                )
            }"#,
        )
        .await;

    let store = schema.store();
    let db = store.events();
    let ts1 = utc_micro(2018, 1, 26, 18, 30, 9, 453_829);
    db.put_event(&sensor1_event_at(ts1, 1, 2)).unwrap();
    let ts2 = utc_micro(2018, 1, 27, 18, 30, 9, 453_829);
    db.put_event(&sensor1_event_at(ts2, 3, 4)).unwrap();
    let ts3 = utc_micro(2018, 1, 28, 18, 30, 9, 453_829);
    db.put_event(&sensor1_event_at(ts3, 5, 6)).unwrap();

    let query = format!(
        "{{ \
            eventList( \
                filter: {{ \
                    start:\"{ts2}\", end:\"{ts3}\", \
                    categories: 7, \
                    sensors: [0], \
                }}, \
            ) {{ \
                edges {{ node {{... on DetectionEvent {{ time, sensor }} }} }} \
                totalCount \
            }} \
        }}"
    );
    let res = schema.execute_as_system_admin(&query).await;
    assert_eq!(
        res.data.to_string(),
        format!(
            r#"{{eventList: {{edges: [{{node: {{time: "2018-01-27T18:30:09.453829Z", sensor: "{SENSOR1_EVENT_SENSOR}"}}}}], totalCount: "1"}}}}"#
        )
    );
}

#[tokio::test]
async fn explicit_sensors_outside_scope_returns_forbidden() {
    let schema = TestSchema::new().await;

    // Insert and apply a sensor node owned by customer 0.
    let _ = schema
        .execute_as_system_admin(
            r#"mutation {
                insertNode(
                    name: "sensor1",
                    customerId: 0,
                    description: "",
                    hostname: "sensor1",
                    agents: [{
                        key: "sensor"
                        kind: SENSOR
                        status: ENABLED
                    }],
                    externalServices: [],
                )
            }"#,
        )
        .await;
    let _ = schema
        .execute_as_system_admin(
            r#"mutation {
                applyNode(
                    id: "0"
                    node: {
                        name: "sensor1",
                        nameDraft: "sensor1",
                        profile: null,
                        profileDraft: {
                            customerId: 0,
                            description: "",
                            hostname: "sensor1",
                        }
                        agents: [
                            {
                                key: "sensor",
                                kind: "SENSOR",
                                status: "ENABLED"
                            }
                        ],
                        externalServices: []
                    }
                )
            }"#,
        )
        .await;

    // Caller scoped to customer 1 (out of scope for sensor node 0) must be
    // rejected when supplying `sensors: [0]`.
    let res = schema
        .execute_as_scoped_user(
            "{ eventList(filter: { sensors: [0] }) { edges { node { ... on DetectionEvent { sensor } } } totalCount } }",
            Role::SecurityMonitor,
            Some(vec![1]),
        )
        .await;
    assert_eq!(res.errors.len(), 1, "errors: {:?}", res.errors);
    assert!(
        res.errors[0].message.contains("Forbidden"),
        "message: {}",
        res.errors[0].message
    );

    // Caller scoped to customer 0 (in scope) succeeds.
    let res = schema
        .execute_as_scoped_user(
            "{ eventList(filter: { sensors: [0] }) { totalCount } }",
            Role::SecurityMonitor,
            Some(vec![0]),
        )
        .await;
    assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
}

#[tokio::test]
async fn total_count() {
    let timestamps: Vec<_> = [
        (2018, 1, 26, 18, 30, 9, 453_829),
        (2018, 1, 27, 18, 30, 9, 453_829),
        (2018, 1, 28, 18, 30, 9, 453_829),
    ]
    .into_iter()
    .map(|(y, m, d, h, min, s, micro)| utc_micro(y, m, d, h, min, s, micro))
    .collect();
    let src_dst: Vec<_> = vec![(1, 2), (3, 1), (2, 3)];
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    timestamps
        .iter()
        .zip(src_dst.into_iter())
        .for_each(|(ts, (src, dst))| {
            db.put_event(&event_message_at(*ts, src, dst)).unwrap();
        });

    let query = format!(
        "{{ \
                    eventList(filter: {{ start:\"{}\", end:\"{}\" }}) {{ \
                        edges {{ node {{... on DetectionEvent {{ time }} }} }} \
                        totalCount \
                    }} \
                }}",
        timestamps[0], timestamps[2]
    );
    let res = schema.execute_as_system_admin(&query).await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventList: {edges: [{node: {time: "2018-01-26T18:30:09.453829Z"}}, {node: {time: "2018-01-27T18:30:09.453829Z"}}], totalCount: "2"}}"#
    );
    let query = format!(
        "{{ \
                eventList(filter: {{ start:\"{}\", end:\"{}\" }}) {{ \
                    edges {{ node {{... on DetectionEvent {{ time }} }} }} \
                    totalCount \
                }} \
            }}",
        timestamps[1], timestamps[2]
    );
    let res = schema.execute_as_system_admin(&query).await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829Z"}}], totalCount: "1"}}"#
    );
}

#[tokio::test]
async fn filter_by_network() {
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
            eventList(filter: {{
                start:\"{ts1}\",
                end:\"{ts3}\",
                endpoints: [{{predefined: \"0\"}}]
            }}) {{ \
                edges {{ node {{ {DNS_ORIG_ADDR} }} }} \
            }} \
        }}"
    );
    let res = schema.execute_as_system_admin(&query).await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventList: {edges: [{node: {target: {body: {origAddr: "0.0.0.3"}}}}]}}"#
    );
}

#[tokio::test]
async fn filter_by_unknown_category() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();

    let ts1 = utc_micro(2024, 1, 1, 0, 0, 0, 0);
    db.put_event(&event_message_with_category(
        ts1,
        1,
        2,
        Some(EventCategory::InitialAccess), //category = 2
        "s1",
    ))
    .unwrap();

    let ts2 = utc_micro(2024, 1, 1, 0, 0, 1, 0);
    db.put_event(&event_message_with_category(ts2, 3, 4, None, "s2"))
        .unwrap();

    // 1. Filter by unknown category
    let query = r"{ eventList(filter: { categories: [null] }) { edges { node { ... on DetectionEvent { sensor } } } totalCount } }";
    let res = schema.execute_as_system_admin(query).await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventList: {edges: [{node: {sensor: "s2"}}], totalCount: "1"}}"#
    );

    // 2. Filter by a specific category (InitialAccess = 2)
    let query = r"{ eventList(filter: { categories: [2] }) { edges { node { ... on DetectionEvent { sensor } } } totalCount } }";
    let res = schema.execute_as_system_admin(query).await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventList: {edges: [{node: {sensor: "s1"}}], totalCount: "1"}}"#
    );

    // 3. Filter by both specific and unknown categories
    let query = r"{ eventList(filter: { categories: [2, null] }) { edges { node { ... on DetectionEvent { sensor } } } totalCount } }";
    let res = schema.execute_as_system_admin(query).await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventList: {edges: [{node: {sensor: "s1"}}, {node: {sensor: "s2"}}], totalCount: "2"}}"#
    );
}

#[tokio::test]
async fn event_stream() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    let ts1 = utc_micro(2018, 1, 26, 18, 30, 9, 453_829);
    db.put_event(&event_message_at(ts1, 1, 2)).unwrap();
    let ts2 = utc_micro(2018, 1, 27, 18, 30, 9, 453_829);
    db.put_event(&event_message_at(ts2, 3, 4)).unwrap();
    let ts3 = utc_micro(2018, 1, 28, 18, 30, 9, 453_829);
    db.put_event(&event_message_at(ts3, 5, 6)).unwrap();
    for argument in [
        "",
        ", fetchInterval: null",
        ", fetchInterval: 1",
        ", fetchInterval: 86400",
    ] {
        let query = format!(
            r#"
            subscription {{
                eventStream(start: "2018-01-28T00:00:00.000000000Z"{argument}) {{
                    __typename
                    detectionModel
                    {DNS_ORIG_ADDR}
                }}
            }}
        "#
        );
        let mut stream = schema.execute_stream(&query).await;
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap();
        assert!(response.errors.is_empty(), "{response:?}");
        assert_eq!(
            response.data.to_string(),
            r#"{eventStream: {__typename: "DetectionEvent", detectionModel: DNS_COVERT_CHANNEL, target: {body: {origAddr: "0.0.0.5"}}}}"#
        );
    }
}

#[tokio::test]
async fn event_list_with_triage_matches_event_list_cursor_semantics() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    let timestamps: Vec<_> = (0i8..5)
        .map(|i| utc_micro(2026, 1, 1, 0, 0, i, 0))
        .collect();
    for (i, ts) in timestamps.iter().enumerate() {
        let src = u32::try_from(i + 1).unwrap();
        db.put_event(&event_message_at(*ts, src, src + 100))
            .unwrap();
    }
    let start_ts = timestamps[0];

    let event_list_query = format!(
        "{{ eventList(filter: {{ start:\"{start_ts}\" }}, first: 3) {{ \
            edges {{ cursor node {{... on DetectionEvent {{ time }} }} }} \
            pageInfo {{ hasNextPage hasPreviousPage }} \
        }} }}",
    );
    let event_list_res = schema.execute_as_system_admin(&event_list_query).await;
    let event_list_data = event_list_res.data.to_string();

    let with_triage_query = format!(
        "{{ eventListWithTriage(filter: {{ start:\"{start_ts}\" }}, first: 3) {{ \
            edges {{ cursor node {{... on DetectionEvent {{ time }} }} }} \
            pageInfo {{ hasNextPage hasPreviousPage }} \
        }} }}",
    );
    let with_triage_res = schema.execute_as_system_admin(&with_triage_query).await;
    let with_triage_data = with_triage_res.data.to_string();

    let normalized_event_list = event_list_data.replacen("eventList", "eventListWithTriage", 1);
    assert_eq!(normalized_event_list, with_triage_data);
}

#[tokio::test]
async fn event_list_with_triage_rejects_negative_policy_id() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
    db.put_event(&event_message_at(ts, 1, 2)).unwrap();

    let query = format!(
        "{{ eventListWithTriage( \
            filter: {{ start:\"{ts}\" }}, \
            triage: {{ \
                policies: [{{ \
                    id: -1, \
                    packetAttr: [], \
                    score: [], \
                    response: [] \
                }}] \
            }} \
        ) {{ totalCount }} }}",
    );
    let res = schema.execute_as_system_admin(&query).await;
    assert!(
        !res.errors.is_empty(),
        "expected error for negative policy id"
    );
    assert!(
        res.errors
            .iter()
            .any(|e| e.message.contains("non-negative")),
        "expected non-negative error, got {:?}",
        res.errors,
    );
}

#[tokio::test]
async fn event_list_with_triage_policy_non_match_preserves_event() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
    db.put_event(&event_message_at(ts, 1, 2)).unwrap();

    // Policy with very high minimum_score so the event scores nothing.
    let query = format!(
        "{{ eventListWithTriage( \
            filter: {{ start:\"{ts}\" }}, \
            triage: {{ \
                policies: [{{ \
                    id: 7, \
                    packetAttr: [], \
                    score: [], \
                    response: [{{ minimumScore: 999.0, kind: MANUAL }}] \
                }}] \
            }} \
        ) {{ \
            edges {{ node {{... on DetectionEvent {{ triageScores {{ policyId }} }} }} }} \
            totalCount \
        }} }}",
    );
    let res = schema.execute_as_system_admin(&query).await;
    assert_eq!(
        res.data.to_string(),
        r#"{eventListWithTriage: {edges: [{node: {triageScores: null}}], totalCount: "1"}}"#
    );
}

#[tokio::test]
async fn event_list_with_triage_rejects_oversized_domain_exclusion() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    store
        .events()
        .put_event(&event_message_at(jiff::Timestamp::now(), 1, 2))
        .unwrap();
    let domains: Vec<_> = (0..5_000)
        .map(|index| format!("host{index:06}.sub.example-domain.com"))
        .collect();
    let domains = serde_json::to_string(&domains).unwrap();
    let query = format!(
        "{{ eventListWithTriage( \
            filter: {{}}, \
            triage: {{ exclusions: [{{ domain: {domains} }}] }} \
        ) {{ edges {{ cursor }} totalCount }} }}",
    );

    let res = schema.execute_as_system_admin(&query).await;
    assert_eq!(res.data, async_graphql::Value::Null);
    let error = res.errors.first().expect("expected an exclusion error");
    assert!(
        error.message.contains("triage.exclusions[0].domain"),
        "{error:?}"
    );
    assert!(error.message.contains("size limit"), "{error:?}");
}

#[tokio::test]
async fn event_list_with_triage_rejects_unbuildable_ip_address_exclusion() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    store
        .events()
        .put_event(&event_message_at(jiff::Timestamp::now(), 1, 2))
        .unwrap();
    // A buildable exclusion before the invalid one must not hide the failure.
    let query = r#"{ eventListWithTriage(
        filter: {},
        triage: { exclusions: [
            { domain: ["domain"] },
            { ipAddress: { hosts: [], networks: [], ranges: [
                { start: "192.0.2.1", end: "2001:db8::1" }
            ] } }
        ] }
    ) { edges { cursor } totalCount } }"#;

    let res = schema.execute_as_system_admin(query).await;
    assert_eq!(res.data, async_graphql::Value::Null);
    let error = res.errors.first().expect("expected an exclusion error");
    assert!(
        error.message.contains("triage.exclusions[1].ipAddress"),
        "{error:?}",
    );
    assert!(
        error
            .message
            .contains("building IP triage exclusion filter"),
        "{error:?}",
    );
    assert!(
        error.message.contains("Invalid ip address format"),
        "{error:?}"
    );
}

#[tokio::test]
async fn event_list_with_triage_schema_rejects_filter_triage_policies() {
    let schema = TestSchema::new().await;
    let res = schema
        .execute_as_system_admin(
            r#"{ eventListWithTriage(filter: { triagePolicies: ["1"] }) { totalCount } }"#,
        )
        .await;
    assert!(!res.errors.is_empty(), "expected schema validation error");
}

#[tokio::test]
async fn event_list_filter_rejects_triage_policies() {
    let schema = TestSchema::new().await;
    for query in [
        r#"{ eventList(filter: { triagePolicies: ["0"] }, first: 1) { totalCount } }"#,
        r#"{ eventCountsByCategory(filter: { triagePolicies: ["0"] }, first: 1) { counts } }"#,
    ] {
        let res = schema.execute_as_system_admin(query).await;
        assert!(!res.errors.is_empty(), "expected an error for {query}");
        assert_eq!(res.data, async_graphql::Value::Null, "{query}");
    }

    // Sending the field as `null` is rejected too.
    let request = async_graphql::Request::new(
        "query($filter: EventListFilterInput!) { eventList(filter: $filter) { totalCount } }",
    )
    .variables(async_graphql::Variables::from_json(
        serde_json::json!({ "filter": { "triagePolicies": null } }),
    ));
    let request =
        schema.request_with_context(request, RoleGuard::Role(Role::SystemAdministrator), None);
    let res = schema.schema.execute(request).await;
    assert!(!res.errors.is_empty(), "expected a variables error");
    assert_eq!(res.data, async_graphql::Value::Null);
}

#[tokio::test]
async fn event_list_with_triage_exclusion_flattens_and_rejects_empty() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    let ts = utc_micro(2026, 1, 1, 0, 0, 0, 0);
    db.put_event(&event_message_at(ts, 1, 2)).unwrap();

    // Single multi-field exclusion: ipAddress (no match) + domain (would have
    // matched). Exclusions are validated but remove no event.
    let query_combined = format!(
        "{{ eventListWithTriage( \
            filter: {{ start:\"{ts}\" }}, \
            triage: {{ exclusions: [{{ \
                ipAddress: {{ hosts: [\"99.99.99.99\"], networks: [], ranges: [] }}, \
                domain: [\"domain\"] \
            }}] }} \
        ) {{ totalCount }} }}",
    );
    let res_combined = schema.execute_as_system_admin(&query_combined).await;
    assert!(res_combined.errors.is_empty(), "{:?}", res_combined.errors);
    assert_eq!(
        res_combined.data.to_string(),
        r#"{eventListWithTriage: {totalCount: "1"}}"#
    );

    // Equivalent two-element list.
    let query_split = format!(
        "{{ eventListWithTriage( \
            filter: {{ start:\"{ts}\" }}, \
            triage: {{ exclusions: [ \
                {{ ipAddress: {{ hosts: [\"99.99.99.99\"], networks: [], ranges: [] }} }}, \
                {{ domain: [\"domain\"] }} \
            ] }} \
        ) {{ totalCount }} }}",
    );
    let res_split = schema.execute_as_system_admin(&query_split).await;
    assert!(res_split.errors.is_empty(), "{:?}", res_split.errors);
    assert_eq!(
        res_split.data.to_string(),
        r#"{eventListWithTriage: {totalCount: "1"}}"#
    );

    // Empty exclusion is rejected.
    let query_empty = format!(
        "{{ eventListWithTriage( \
            filter: {{ start:\"{ts}\" }}, \
            triage: {{ exclusions: [{{}}] }} \
        ) {{ totalCount }} }}",
    );
    let res_empty = schema.execute_as_system_admin(&query_empty).await;
    assert!(
        !res_empty.errors.is_empty(),
        "expected error for empty exclusion"
    );

    // An ipAddress group with all sub-fields empty is also treated as no
    // populated field and rejected.
    let query_empty_group = format!(
        "{{ eventListWithTriage( \
            filter: {{ start:\"{ts}\" }}, \
            triage: {{ exclusions: [{{ \
                ipAddress: {{ hosts: [], networks: [], ranges: [] }} \
            }}] }} \
        ) {{ totalCount }} }}",
    );
    let res_empty_group = schema.execute_as_system_admin(&query_empty_group).await;
    assert!(
        !res_empty_group.errors.is_empty(),
        "expected error for exclusion with empty ipAddress group"
    );
}

#[tokio::test]
async fn event_list_with_triage_exclusions_remove_no_event() {
    let schema = TestSchema::new().await;
    let store = schema.store();
    let db = store.events();
    let ts = |seconds: i8| utc_micro(2026, 1, 1, 0, 0, seconds, 0);
    // The default test event has the DNS query "domain", which each of these
    // exclusions would have matched before exclusions stopped removing
    // events.
    for second in 0..4 {
        let index = u32::try_from(second).unwrap();
        db.put_event(&event_message_at(ts(second), index + 1, index + 100))
            .unwrap();
    }
    drop(store);
    let start = ts(0);

    let page = |triage: &str, first: u32| {
        format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{start}\" }}, \
                {triage} \
                first: {first} \
            ) {{ \
                edges {{ cursor node {{ time }} }} \
                pageInfo {{ hasNextPage }} \
                totalCount \
            }} }}",
        )
    };
    for first in [1, 100] {
        let without = schema.execute_as_system_admin(&page("", first)).await;
        assert!(without.errors.is_empty(), "{:?}", without.errors);
        for exclusion in [
            r#"{ domain: ["domain"] }"#,
            r#"{ hostname: ["domain"] }"#,
            r#"{ uri: ["/domain"] }"#,
            r#"{ ipAddress: { hosts: ["0.0.0.1"], networks: [], ranges: [] } }"#,
        ] {
            let with = schema
                .execute_as_system_admin(&page(
                    &format!("triage: {{ exclusions: [{exclusion}] }},"),
                    first,
                ))
                .await;
            assert!(with.errors.is_empty(), "{exclusion}: {:?}", with.errors);
            assert_eq!(with.data, without.data, "{exclusion}");
        }
        let data = without.data.into_json().unwrap();
        assert_eq!(data["eventListWithTriage"]["totalCount"], "4");
        assert_eq!(
            data["eventListWithTriage"]["edges"]
                .as_array()
                .unwrap()
                .len(),
            usize::try_from(first.min(4)).unwrap()
        );
    }
}

mod event_sensor_names {
    use review_database::{Agent, AgentKind, AgentStatus, Lifecycle, Node, NodeProfile, Store};
    use serde_json::{Value, json};

    use super::*;

    const SENSOR_A: &str = "piglet.a.example.com";
    const SENSOR_B: &str = "piglet.b.example.com";
    const STALE_SENSOR: &str = "piglet.removed.example.com";

    struct Fixture {
        node_a: u32,
        node_b: u32,
        hog_only: u32,
        event_a: i128,
        event_b: i128,
        event_stale: i128,
    }

    fn agent(kind: AgentKind, key: &str) -> Agent {
        Agent {
            node_id: u32::MAX,
            key: key.to_string(),
            kind,
            status: AgentStatus::Enabled,
            config: Some(String::new().try_into().expect("empty TOML is valid")),
            draft: None,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::NotInstalled,
            bound_addrs: vec![],
            instance: None,
            run_as_root: false,
            run_as_root_draft: None,
            privilege_profile: None,
        }
    }

    fn insert_node(store: &Store, customer_id: u32, hostname: &str, agents: Vec<Agent>) -> u32 {
        let node = Node {
            id: u32::MAX,
            name: hostname.to_string(),
            name_draft: Some(hostname.to_string()),
            profile: Some(NodeProfile {
                customer_id,
                description: String::new(),
                hostname: hostname.to_string(),
            }),
            profile_draft: None,
            agents,
            external_services: vec![],
            creation_time: jiff::Timestamp::now(),
        };
        store.node_map().put(&node).expect("insert node")
    }

    /// Seeds two customers, each with one sensor node, a customer-1 node
    /// without a sensor, and events of both sensors, of a removed node's
    /// sensor, and one carrying a bare node hostname.
    fn seed(schema: &TestSchema) -> Fixture {
        let store = schema.store();
        let node_a = insert_node(
            &store,
            1,
            "a.example.com",
            vec![
                agent(AgentKind::Sensor, "001.piglet"),
                agent(AgentKind::SemiSupervised, "001.hog"),
            ],
        );
        let node_b = insert_node(
            &store,
            2,
            "b.example.com",
            vec![agent(AgentKind::Sensor, "001.piglet")],
        );
        let hog_only = insert_node(
            &store,
            1,
            "hog.example.com",
            vec![agent(AgentKind::SemiSupervised, "001.hog")],
        );

        let db = store.events();
        let ts = |day| utc_micro(2018, 1, day, 0, 0, 0, 0);
        let put = |day, sensor| {
            db.put_event(&event_message_with_category(
                ts(day),
                1,
                2,
                Some(EventCategory::CommandAndControl),
                sensor,
            ))
            .unwrap()
        };
        let event_a = put(1, SENSOR_A);
        let event_b = put(2, SENSOR_B);
        let event_stale = put(3, STALE_SENSOR);
        // A bare hostname is not a name events carry under bootroot, and
        // must never match a node.
        put(4, "a.example.com");

        Fixture {
            node_a,
            node_b,
            hog_only,
            event_a,
            event_b,
            event_stale,
        }
    }

    fn sensors_of(res: async_graphql::Response) -> Vec<String> {
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        data["eventList"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["node"]["sensor"].as_str().unwrap().to_string())
            .collect()
    }

    fn event_list_query(filter: &str) -> String {
        format!(
            "{{ eventList(filter: {{ {filter} }}) {{ \
                edges {{ node {{ ... on DetectionEvent {{ sensor }} }} }} \
            }} }}"
        )
    }

    #[tokio::test]
    async fn sensors_filter_matches_service_fqdn() {
        let schema = TestSchema::new().await;
        let fixture = seed(&schema);

        let res = schema
            .execute_as_system_admin(&event_list_query(&format!(
                "sensors: [\"{}\"]",
                fixture.node_a
            )))
            .await;
        assert_eq!(sensors_of(res), vec![SENSOR_A]);

        let res = schema
            .execute_as_scoped_user(
                &event_list_query(&format!("sensors: [\"{}\"]", fixture.node_b)),
                Role::SecurityMonitor,
                Some(vec![2]),
            )
            .await;
        assert_eq!(sensors_of(res), vec![SENSOR_B]);

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ eventCountsByCategory(filter: {{ sensors: [\"{}\"] }}, first: 10) \
                    {{ counts }} }}",
                fixture.node_a
            ))
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["eventCountsByCategory"]["counts"], json!([1]));
    }

    #[tokio::test]
    async fn sensors_filter_on_node_without_sensor_matches_nothing() {
        let schema = TestSchema::new().await;
        let fixture = seed(&schema);

        let res = schema
            .execute_as_system_admin(&event_list_query(&format!(
                "sensors: [\"{}\"]",
                fixture.hog_only
            )))
            .await;
        assert_eq!(sensors_of(res), Vec::<String>::new());
    }

    #[tokio::test]
    async fn sensors_filter_outside_scope_is_forbidden() {
        let schema = TestSchema::new().await;
        let fixture = seed(&schema);

        let res = schema
            .execute_as_scoped_user(
                &event_list_query(&format!("sensors: [\"{}\"]", fixture.node_b)),
                Role::SecurityMonitor,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1, "errors: {:?}", res.errors);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn scoped_caller_without_sensors_sees_only_its_customers() {
        let schema = TestSchema::new().await;
        seed(&schema);
        let query = event_list_query("");

        let res = schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![1]))
            .await;
        assert_eq!(sensors_of(res), vec![SENSOR_A]);

        let res = schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![2]))
            .await;
        assert_eq!(sensors_of(res), vec![SENSOR_B]);

        let res = schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![]))
            .await;
        assert_eq!(sensors_of(res), Vec::<String>::new());

        let res = schema
            .execute_as_scoped_user(
                "{ eventCountsByCategory(filter: {}, first: 10) { counts } }",
                Role::SecurityMonitor,
                Some(vec![2]),
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["eventCountsByCategory"]["counts"], json!([1]));
    }

    #[tokio::test]
    async fn administrator_without_sensors_sees_every_sensor() {
        let schema = TestSchema::new().await;
        seed(&schema);

        let res = schema.execute_as_system_admin(&event_list_query("")).await;
        assert_eq!(
            sensors_of(res),
            vec![SENSOR_A, SENSOR_B, STALE_SENSOR, "a.example.com"]
        );
    }

    #[tokio::test]
    async fn event_lookup_uses_event_sensor_names() {
        let schema = TestSchema::new().await;
        let fixture = seed(&schema);
        let lookup = |key: i128| {
            format!("{{ event(id: \"{key}\") {{ ... on DetectionEvent {{ sensor }} }} }}")
        };
        let sensor = |res: async_graphql::Response| -> Value {
            assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
            res.data.into_json().unwrap()["event"].clone()
        };

        let res = schema
            .execute_as_scoped_user(
                &lookup(fixture.event_a),
                Role::SecurityMonitor,
                Some(vec![1]),
            )
            .await;
        assert_eq!(sensor(res), json!({ "sensor": SENSOR_A }));

        for key in [fixture.event_b, fixture.event_stale] {
            let res = schema
                .execute_as_scoped_user(&lookup(key), Role::SecurityMonitor, Some(vec![1]))
                .await;
            assert_eq!(sensor(res), Value::Null);
        }

        let res = schema
            .execute_as_system_admin(&lookup(fixture.event_stale))
            .await;
        assert_eq!(sensor(res), json!({ "sensor": STALE_SENSOR }));
    }
}

/// The `directions` filter, which tests each event against the networks
/// of its own customer.
mod directions_by_customer {
    use review_database::{
        Agent, AgentKind, AgentStatus, HostNetworkGroup, Lifecycle, Node, NodeProfile,
        OwnedNetwork, Store, event::NetworkType,
    };

    use super::*;

    const SENSOR_A: &str = "piglet.a.example.com";
    const SENSOR_B: &str = "piglet.b.example.com";
    const SENSOR_C: &str = "piglet.c.example.com";
    const UNMAPPED_SENSOR: &str = "piglet.unmapped.example.com";

    fn insert_sensor_node(store: &Store, customer_id: u32, hostname: &str) {
        let node = Node {
            id: u32::MAX,
            name: hostname.to_string(),
            name_draft: Some(hostname.to_string()),
            profile: Some(NodeProfile {
                customer_id,
                description: String::new(),
                hostname: hostname.to_string(),
            }),
            profile_draft: None,
            agents: vec![Agent {
                node_id: u32::MAX,
                key: "001.piglet".to_string(),
                kind: AgentKind::Sensor,
                status: AgentStatus::Enabled,
                config: None,
                draft: None,
                installed_version: None,
                installed_commit: None,
                lifecycle: Lifecycle::NotInstalled,
                bound_addrs: vec![],
                instance: None,
                run_as_root: false,
                run_as_root_draft: None,
                privilege_profile: None,
            }],
            external_services: vec![],
            creation_time: jiff::Timestamp::now(),
        };
        store.node_map().put(&node).expect("insert node");
    }

    fn owned(name: &str, network_type: NetworkType, cidr: &str) -> OwnedNetwork {
        OwnedNetwork {
            name: name.to_string(),
            network_type,
            group: HostNetworkGroup::new(vec![], vec![cidr.parse().unwrap()], vec![]),
        }
    }

    fn put_event(store: &Store, day: i8, sensor: &str, src: &str, dst: &str) {
        let timestamp = utc_micro(2018, 1, day, 0, 0, 0, 0);
        let src: Ipv4Addr = src.parse().unwrap();
        let dst: Ipv4Addr = dst.parse().unwrap();
        store
            .events()
            .put_event(&event_message_with_category(
                timestamp,
                src.into(),
                dst.into(),
                Some(EventCategory::CommandAndControl),
                sensor,
            ))
            .unwrap();
    }

    /// Seeds customer 1 (sensor A) owning Intranet `10.0.0.0/8` and
    /// Extranet `8.0.0.0/8`, customer 2 (sensor B) owning nothing, and
    /// customer 0 (sensor C) with no customer networks row; and one
    /// `10.1.1.1 -> 8.8.8.8` event on each of them and on a sensor that
    /// maps to no node.
    fn seed(schema: &TestSchema) {
        let store = schema.store();
        insert_sensor_node(&store, 1, "a.example.com");
        insert_sensor_node(&store, 2, "b.example.com");
        insert_sensor_node(&store, 0, "c.example.com");
        let table = store.customer_networks_map();
        table
            .replace(
                1,
                1,
                vec![
                    owned("office", NetworkType::Intranet, "10.0.0.0/8"),
                    owned("partner", NetworkType::Extranet, "8.0.0.0/8"),
                ],
            )
            .unwrap();
        put_event(&store, 1, SENSOR_A, "10.1.1.1", "8.8.8.8");
        put_event(&store, 2, SENSOR_B, "10.1.1.1", "8.8.8.8");
        put_event(&store, 3, SENSOR_C, "10.1.1.1", "8.8.8.8");
        put_event(&store, 4, UNMAPPED_SENSOR, "10.1.1.1", "8.8.8.8");
    }

    async fn sensors_matching(schema: &TestSchema, directions: &str) -> Vec<String> {
        let res = schema
            .execute_as_system_admin(&format!(
                "{{ eventList(filter: {{ directions: [{directions}] }}) {{ \
                    edges {{ node {{ ... on DetectionEvent {{ sensor }} }} }} \
                }} }}"
            ))
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        data["eventList"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["node"]["sensor"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn event_is_classified_by_its_own_customer() {
        let schema = TestSchema::new().await;
        seed(&schema);

        assert_eq!(sensors_matching(&schema, "OUTBOUND").await, vec![SENSOR_A]);
        assert_eq!(
            sensors_matching(&schema, "INBOUND").await,
            Vec::<String>::new()
        );
        assert_eq!(
            sensors_matching(&schema, "INTERNAL").await,
            Vec::<String>::new()
        );
        assert_eq!(
            sensors_matching(&schema, "OUTBOUND, INBOUND, INTERNAL").await,
            vec![SENSOR_A]
        );
    }

    #[tokio::test]
    async fn internal_and_inbound_follow_the_owner() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        insert_sensor_node(&store, 1, "a.example.com");
        insert_sensor_node(&store, 2, "b.example.com");
        let table = store.customer_networks_map();
        table
            .replace(
                1,
                0,
                vec![
                    owned("office", NetworkType::Intranet, "10.0.0.0/8"),
                    owned("edge", NetworkType::Gateway, "192.168.0.0/16"),
                ],
            )
            .unwrap();
        table
            .replace(2, 0, vec![owned("lab", NetworkType::Intranet, "8.0.0.0/8")])
            .unwrap();
        // Internal for customer 1: both sides are in its networks.
        put_event(&store, 1, SENSOR_A, "10.1.1.1", "192.168.1.1");
        // Inbound for customer 2: only the responder is its own.
        put_event(&store, 2, SENSOR_B, "10.1.1.1", "8.8.8.8");
        drop(store);

        assert_eq!(sensors_matching(&schema, "INTERNAL").await, vec![SENSOR_A]);
        assert_eq!(sensors_matching(&schema, "INBOUND").await, vec![SENSOR_B]);
        assert_eq!(
            sensors_matching(&schema, "OUTBOUND").await,
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn extranet_only_customer_has_no_internal_side() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        insert_sensor_node(&store, 1, "a.example.com");
        store
            .customer_networks_map()
            .replace(
                1,
                0,
                vec![owned("partner", NetworkType::Extranet, "10.0.0.0/8")],
            )
            .unwrap();
        put_event(&store, 1, SENSOR_A, "10.1.1.1", "8.8.8.8");
        drop(store);

        assert_eq!(
            sensors_matching(&schema, "OUTBOUND, INBOUND, INTERNAL").await,
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn nested_extranet_network_is_not_internal() {
        use review_protocol::types::{RawEventBody, RawEventKind};

        use crate::graphql::event_test_support::{conn_body, raw_event};

        let put_conn = |store: &Store, day: i8, sensor: &str, orig: &str, resp: &str| {
            store
                .events()
                .put_event(&raw_event(
                    utc_micro(2018, 1, day, 0, 0, 0, 0),
                    sensor,
                    RawEventKind::Conn,
                    RawEventBody::Conn(conn_body(orig.parse().unwrap(), resp.parse().unwrap())),
                    Detail::TorExitNode,
                ))
                .unwrap();
        };
        let schema = TestSchema::new().await;
        let store = schema.store();
        insert_sensor_node(&store, 1, "a.example.com");
        store
            .customer_networks_map()
            .replace(
                1,
                0,
                vec![
                    owned("office", NetworkType::Intranet, "10.0.0.0/8"),
                    owned("partner", NetworkType::Extranet, "10.200.0.0/16"),
                ],
            )
            .unwrap();
        // The narrowest network holding the responder is the Extranet one,
        // so only the originator is internal.
        put_conn(&store, 1, SENSOR_A, "10.1.0.1", "10.200.0.1");
        // Neither side is internal.
        put_conn(&store, 2, SENSOR_A, "10.200.0.1", "10.200.0.2");
        drop(store);

        assert_eq!(sensors_matching(&schema, "OUTBOUND").await, vec![SENSOR_A]);
        assert_eq!(
            sensors_matching(&schema, "INTERNAL").await,
            Vec::<String>::new()
        );
        assert_eq!(
            sensors_matching(&schema, "INBOUND").await,
            Vec::<String>::new()
        );
        // Only the first conn matches any direction.
        assert_eq!(
            sensors_matching(&schema, "OUTBOUND, INBOUND, INTERNAL").await,
            vec![SENSOR_A]
        );
    }
}

/// Inserts and applies node `sensor1`, whose sensor's events have the sensor
/// [`SENSOR1_EVENT_SENSOR`], for customer 0.
async fn insert_sensor1_node(schema: &TestSchema) {
    let res = schema
        .execute_as_system_admin(
            r#"mutation {
                insertNode(
                    name: "sensor1",
                    customerId: 0,
                    description: "This is the sensor node",
                    hostname: "sensor1",
                    agents: [{ key: "sensor", kind: SENSOR, status: ENABLED }],
                    externalServices: [],
                )
            }"#,
        )
        .await;
    assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);
    let res = schema
        .execute_as_system_admin(
            r#"mutation {
                applyNode(
                    id: "0"
                    node: {
                        name: "sensor1",
                        nameDraft: "sensor1",
                        profile: null,
                        profileDraft: {
                            customerId: 0,
                            description: "This is the sensor node",
                            hostname: "sensor1",
                        }
                        agents: [{ key: "sensor", kind: "SENSOR", status: "ENABLED" }],
                        externalServices: []
                    }
                )
            }"#,
        )
        .await;
    assert!(res.errors.is_empty(), "{:?}", res.errors);
}

/// The contract of the detection event type: the union member names clients
/// fragment on, and the shape of every stored value.
mod detection_event {
    use std::net::IpAddr;

    use review_database::DetectionEventStamp;
    use review_protocol::types::{
        DetectionModel, EndpointRole, LdapBruteForceDetail, PrimarySubject, RawEventBody,
        RawEventKind, ThreatRole, UnusualDestinationPatternDetail, WatchlistMatchDetail, raw_event,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::graphql::event_test_support::{conn_body, raw_event, related, stamp, subject_event};

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("a test address")
    }

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(1_700_000_000 + second).expect("a test time")
    }

    /// Returns the `data` of `query`, run as a system administrator, as JSON.
    async fn data(schema: &TestSchema, query: &str) -> Value {
        let res = schema.execute_as_system_admin(query).await;
        assert!(res.errors.is_empty(), "{query}: {:?}", res.errors);
        res.data.into_json().unwrap()
    }

    /// Returns the nodes `eventList(filter: {})` returns, each with `fields`.
    async fn nodes(schema: &TestSchema, fields: &str) -> Vec<Value> {
        let data = data(
            schema,
            &format!("{{ eventList(filter: {{}}) {{ edges {{ node {{ {fields} }} }} }} }}"),
        )
        .await;
        data["eventList"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["node"].clone())
            .collect()
    }

    /// Returns the possible types of the union `name`, in schema order.
    async fn union_members(schema: &TestSchema, name: &str) -> Vec<String> {
        let data = data(
            schema,
            &format!(r#"{{ __type(name: "{name}") {{ kind possibleTypes {{ name }} }} }}"#),
        )
        .await;
        assert_eq!(data["__type"]["kind"], "UNION", "{name}");
        data["__type"]["possibleTypes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn unions_have_the_fixed_member_names() {
        let schema = TestSchema::new().await;
        let mut target = union_members(&schema, "Target").await;
        target.sort_unstable();
        assert_eq!(target, ["RawEventTarget", "SubjectTarget"]);

        let mut primary = union_members(&schema, "PrimarySubject").await;
        primary.sort_unstable();
        assert_eq!(
            primary,
            [
                "ClusterSubject",
                "HostSubject",
                "NetworkSubject",
                "SensorSubject"
            ]
        );

        let mut bodies = union_members(&schema, "RawEventBody").await;
        bodies.sort_unstable();
        let mut expected: Vec<String> = [
            "Conn",
            "Dns",
            "Http",
            "Rdp",
            "Smtp",
            "Ntlm",
            "Kerberos",
            "Ssh",
            "DceRpc",
            "Ftp",
            "Mqtt",
            "Ldap",
            "Tls",
            "Smb",
            "Nfs",
            "Bootp",
            "Dhcp",
            "Radius",
            "MalformedDns",
            "Icmp",
            "ProcessCreate",
            "FileCreateTime",
            "NetworkConnect",
            "ProcessTerminate",
            "ImageLoad",
            "FileCreate",
            "RegistryValueSet",
            "RegistryKeyRename",
            "FileCreateStreamHash",
            "PipeEvent",
            "DnsQuery",
            "FileDelete",
            "ProcessTamper",
            "FileDeleteDetected",
            "Netflow5",
            "Netflow9",
        ]
        .iter()
        .map(|kind| format!("{kind}Body"))
        .collect();
        expected.sort_unstable();
        assert_eq!(bodies, expected);

        let mut details = union_members(&schema, "Detail").await;
        details.sort_unstable();
        let mut expected: Vec<String> = [
            "WatchlistMatch",
            "CryptocurrencyMiningPool",
            "LockyRansomware",
            "SuspiciousTlsTraffic",
            "PortScan",
            "MultiHostPortScan",
            "ExternalDdos",
            "RdpBruteForce",
            "FtpBruteForce",
            "LdapBruteForce",
            "RepeatedHttpSessions",
            "FtpPlainText",
            "LdapPlainText",
            "NonBrowser",
            "TorExitNode",
            "DomainGenerationAlgorithm",
            "DnsCovertChannel",
            "UnusualDestinationPattern",
            "LabelDbMatch",
            "FarOutlier",
            "WindowOutlier",
        ]
        .iter()
        .map(|model| format!("{model}Detail"))
        .collect();
        expected.sort_unstable();
        assert_eq!(details, expected);

        // A model whose detail carries nothing still has its own member,
        // whose only field is its detection model.
        for model in [
            "LockyRansomware",
            "SuspiciousTlsTraffic",
            "FtpPlainText",
            "LdapPlainText",
            "NonBrowser",
            "TorExitNode",
            "DomainGenerationAlgorithm",
            "DnsCovertChannel",
        ] {
            let data = data(
                &schema,
                &format!(
                    r#"{{ __type(name: "{model}Detail") {{ fields {{ name type {{ kind ofType {{ name }} }} }} }} }}"#
                ),
            )
            .await;
            assert_eq!(
                data["__type"]["fields"],
                json!([{
                    "name": "detectionModel",
                    "type": { "kind": "NON_NULL", "ofType": { "name": "DetectionModel" } },
                }]),
                "{model}"
            );
        }
    }

    fn bootp_body() -> raw_event::Bootp {
        raw_event::Bootp {
            orig_addr: addr("192.0.2.10"),
            orig_port: 68,
            resp_addr: addr("192.0.2.11"),
            resp_port: 67,
            proto: 17,
            start_time: 0,
            duration: 0,
            orig_pkts: 1,
            resp_pkts: 1,
            orig_l2_bytes: 300,
            resp_l2_bytes: 300,
            op: 1,
            htype: 1,
            hops: 0,
            // Above the signed 32-bit range.
            xid: (1 << 31) + 7,
            ciaddr: addr("0.0.0.0"),
            yiaddr: addr("192.0.2.50"),
            siaddr: addr("0.0.0.0"),
            giaddr: addr("0.0.0.0"),
            chaddr: vec![0x00, 0x1a, 0x2b, 0xff, 0x00, 0x01],
            sname: String::new(),
            file: String::new(),
        }
    }

    fn dce_rpc_body() -> raw_event::DceRpc {
        raw_event::DceRpc {
            orig_addr: addr("192.0.2.20"),
            orig_port: 50000,
            resp_addr: addr("192.0.2.21"),
            resp_port: 135,
            proto: 6,
            start_time: 0,
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            context: vec![raw_event::DceRpcContext {
                id: 1,
                // Above the unsigned 64-bit range.
                abstract_syntax: (1 << 64) + 3,
                abstract_major: 4,
                abstract_minor: 0,
                transfer_syntax: u128::MAX,
                transfer_major: 2,
                transfer_minor: 0,
                acceptance: 0,
                reason: 0,
            }],
            request: vec!["1:2".to_string()],
        }
    }

    fn dhcp_body() -> raw_event::Dhcp {
        raw_event::Dhcp {
            orig_addr: addr("192.0.2.30"),
            orig_port: 68,
            resp_addr: addr("192.0.2.31"),
            resp_port: 67,
            proto: 17,
            start_time: 0,
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            msg_type: 5,
            ciaddr: addr("0.0.0.0"),
            yiaddr: addr("192.0.2.60"),
            siaddr: addr("0.0.0.0"),
            giaddr: addr("0.0.0.0"),
            subnet_mask: addr("255.255.255.0"),
            router: vec![addr("192.0.2.1"), addr("192.0.2.2")],
            domain_name_server: vec![addr("192.0.2.53")],
            req_ip_addr: addr("192.0.2.60"),
            lease_time: 86_400,
            server_id: addr("192.0.2.31"),
            param_req_list: vec![1, 3, 6],
            message: String::new(),
            renewal_time: 43_200,
            rebinding_time: 75_600,
            class_id: vec![0x4d, 0x53],
            client_id_type: 1,
            client_id: vec![0xaa, 0xbb],
            options: vec![(90, vec![0x01, 0x02, 0xff]), (12, vec![]), (61, vec![0x00])],
        }
    }

    pub(super) fn process_create_body() -> raw_event::ProcessCreate {
        raw_event::ProcessCreate {
            agent_name: "agent".to_string(),
            agent_id: "agent-1".to_string(),
            process_guid: "{guid}".to_string(),
            process_id: u32::MAX,
            image: "C:\\Windows\\cmd.exe".to_string(),
            file_version: String::new(),
            description: String::new(),
            product: String::new(),
            company: String::new(),
            original_file_name: String::new(),
            command_line: "cmd.exe".to_string(),
            current_directory: String::new(),
            user: "user".to_string(),
            logon_guid: String::new(),
            logon_id: 0,
            terminal_session_id: 0,
            integrity_level: String::new(),
            hashes: vec!["SHA256=00".to_string(), "MD5=11".to_string()],
            parent_process_guid: String::new(),
            parent_process_id: 0,
            parent_image: String::new(),
            parent_command_line: String::new(),
            parent_user: String::new(),
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn raw_event_bodies_are_returned_exactly() {
        let schema = TestSchema::new().await;
        let mut conn = conn_body(addr("192.0.2.1"), addr("2001:db8::2"));
        // Below the signed 32-bit range.
        conn.duration = -(1 << 31) - 5;
        conn.orig_bytes = u64::MAX;
        let keys = {
            let store = schema.store();
            let events = store.events();
            [
                (RawEventKind::Conn, RawEventBody::Conn(conn)),
                (RawEventKind::Bootp, RawEventBody::Bootp(bootp_body())),
                (RawEventKind::DceRpc, RawEventBody::DceRpc(dce_rpc_body())),
                (RawEventKind::Dhcp, RawEventBody::Dhcp(dhcp_body())),
                (
                    RawEventKind::ProcessCreate,
                    RawEventBody::ProcessCreate(process_create_body()),
                ),
            ]
            .into_iter()
            .enumerate()
            .map(|(second, (kind, body))| {
                let second = i64::try_from(second).unwrap();
                events
                    .put_event(&raw_event(
                        at(second),
                        "sensor1",
                        kind,
                        body,
                        Detail::TorExitNode,
                    ))
                    .unwrap()
            })
            .collect::<Vec<_>>()
        };

        let fields = "id rawEventKind target { __typename ... on RawEventTarget { time body {
            __typename
            ... on ConnBody { origAddr respAddr proto duration origBytes connState }
            ... on BootpBody { xid chaddr yiaddr }
            ... on DceRpcBody {
                context { id abstractSyntax transferSyntax abstractMajor }
                request
            }
            ... on DhcpBody {
                options { code value } router classId leaseTime paramReqList
            }
            ... on ProcessCreateBody { processId image hashes }
        } } }
        endpointCountries { ip country }";
        let nodes = nodes(&schema, fields).await;
        let expected = [
            json!({
                "rawEventKind": "CONN",
                "target": { "__typename": "RawEventTarget", "time": at(0).to_string(), "body": {
                    "__typename": "ConnBody",
                    "origAddr": "192.0.2.1",
                    "respAddr": "2001:db8::2",
                    "proto": 6,
                    "duration": "-2147483653",
                    "origBytes": u64::MAX.to_string(),
                    "connState": "SF",
                } },
                "endpointCountries": [
                    { "ip": "192.0.2.1", "country": "XX" },
                    { "ip": "2001:db8::2", "country": "XX" },
                ],
            }),
            json!({
                "rawEventKind": "BOOTP",
                "target": { "__typename": "RawEventTarget", "time": at(1).to_string(), "body": {
                    "__typename": "BootpBody",
                    "xid": "2147483655",
                    "chaddr": [0, 26, 43, 255, 0, 1],
                    "yiaddr": "192.0.2.50",
                } },
                "endpointCountries": [
                    { "ip": "192.0.2.10", "country": "XX" },
                    { "ip": "192.0.2.11", "country": "XX" },
                ],
            }),
            json!({
                "rawEventKind": "DCE_RPC",
                "target": { "__typename": "RawEventTarget", "time": at(2).to_string(), "body": {
                    "__typename": "DceRpcBody",
                    "context": [{
                        "id": 1,
                        "abstractSyntax": "18446744073709551619",
                        "transferSyntax": u128::MAX.to_string(),
                        "abstractMajor": 4,
                    }],
                    "request": ["1:2"],
                } },
                "endpointCountries": [
                    { "ip": "192.0.2.20", "country": "XX" },
                    { "ip": "192.0.2.21", "country": "XX" },
                ],
            }),
            json!({
                "rawEventKind": "DHCP",
                "target": { "__typename": "RawEventTarget", "time": at(3).to_string(), "body": {
                    "__typename": "DhcpBody",
                    "options": [
                        { "code": 90, "value": [1, 2, 255] },
                        { "code": 12, "value": [] },
                        { "code": 61, "value": [0] },
                    ],
                    "router": ["192.0.2.1", "192.0.2.2"],
                    "classId": [77, 83],
                    "leaseTime": "86400",
                    "paramReqList": [1, 3, 6],
                } },
                "endpointCountries": [
                    { "ip": "192.0.2.30", "country": "XX" },
                    { "ip": "192.0.2.31", "country": "XX" },
                ],
            }),
            json!({
                "rawEventKind": "PROCESS_CREATE",
                "target": { "__typename": "RawEventTarget", "time": at(4).to_string(), "body": {
                    "__typename": "ProcessCreateBody",
                    "processId": u32::MAX.to_string(),
                    "image": "C:\\Windows\\cmd.exe",
                    "hashes": ["SHA256=00", "MD5=11"],
                } },
                // A Sysmon body has no endpoint address.
                "endpointCountries": [],
            }),
        ];
        assert_eq!(nodes.len(), expected.len());
        for ((node, mut expected), key) in nodes.into_iter().zip(expected).zip(&keys) {
            expected["id"] = json!(key.to_string());
            assert_eq!(node, expected);
        }

        // `event(id)` returns the same as the list.
        let data = data(
            &schema,
            &format!(
                r#"{{ event(id: "{}") {{ target {{ ... on RawEventTarget {{ body {{ ... on BootpBody {{ xid chaddr }} }} }} }} }} }}"#,
                keys[1]
            ),
        )
        .await;
        assert_eq!(
            data,
            json!({ "event": { "target": { "body": {
                "xid": "2147483655", "chaddr": [0, 26, 43, 255, 0, 1],
            } } } })
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn subjects_are_returned_with_their_related_ips_and_countries() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            let events = store.events();
            for event in [
                subject_event(
                    at(0),
                    Some("sensor1"),
                    PrimarySubject::Host {
                        ip: addr("192.0.2.9"),
                        role: ThreatRole::Target,
                    },
                    vec![
                        related("198.51.100.1", EndpointRole::Source),
                        related("198.51.100.2", EndpointRole::Destination),
                    ],
                    Detail::TorExitNode,
                ),
                subject_event(
                    at(1),
                    Some("sensor1"),
                    PrimarySubject::Sensor,
                    vec![related("198.51.100.3", EndpointRole::Destination)],
                    Detail::TorExitNode,
                ),
                subject_event(
                    at(2),
                    None,
                    PrimarySubject::Cluster {
                        clustering_model: 7,
                        cluster_id: u32::MAX,
                    },
                    Vec::new(),
                    Detail::TorExitNode,
                ),
                subject_event(
                    at(3),
                    Some("sensor1"),
                    PrimarySubject::Network {
                        customer: 3,
                        name: "office".to_string(),
                        role: ThreatRole::Actor,
                    },
                    vec![related("198.51.100.4", EndpointRole::Source)],
                    Detail::TorExitNode,
                ),
            ] {
                events.put_event(&event).unwrap();
            }
        }

        let fields = "sensor target { __typename ... on SubjectTarget {
            primary {
                __typename
                ... on HostSubject { ip role }
                ... on ClusterSubject { clusteringModel clusterId }
                ... on SensorSubject { sensor }
                ... on NetworkSubject { customer name role }
            }
            relatedIps { ip role }
            window { start end }
        } }
        endpointCountries { ip country }";
        let window = |second: i64| json!({ "start": at(second).to_string(), "end": at(second + 1).to_string() });
        assert_eq!(
            nodes(&schema, fields).await,
            [
                json!({
                    "sensor": "sensor1",
                    "target": {
                        "__typename": "SubjectTarget",
                        "primary": { "__typename": "HostSubject", "ip": "192.0.2.9", "role": "TARGET" },
                        "relatedIps": [
                            { "ip": "198.51.100.1", "role": "SOURCE" },
                            { "ip": "198.51.100.2", "role": "DESTINATION" },
                        ],
                        "window": window(0),
                    },
                    // The host IP comes first, then each related IP in order.
                    "endpointCountries": [
                        { "ip": "192.0.2.9", "country": "XX" },
                        { "ip": "198.51.100.1", "country": "XX" },
                        { "ip": "198.51.100.2", "country": "XX" },
                    ],
                }),
                json!({
                    "sensor": "sensor1",
                    "target": {
                        "__typename": "SubjectTarget",
                        "primary": { "__typename": "SensorSubject", "sensor": "sensor1" },
                        "relatedIps": [{ "ip": "198.51.100.3", "role": "DESTINATION" }],
                        "window": window(1),
                    },
                    // A sensor subject has only its related IPs.
                    "endpointCountries": [{ "ip": "198.51.100.3", "country": "XX" }],
                }),
                json!({
                    "sensor": null,
                    "target": {
                        "__typename": "SubjectTarget",
                        "primary": {
                            "__typename": "ClusterSubject",
                            "clusteringModel": "7",
                            "clusterId": u32::MAX.to_string(),
                        },
                        "relatedIps": [],
                        "window": window(2),
                    },
                    "endpointCountries": [],
                }),
                json!({
                    "sensor": "sensor1",
                    "target": {
                        "__typename": "SubjectTarget",
                        "primary": {
                            "__typename": "NetworkSubject",
                            "customer": "3",
                            "name": "office",
                            "role": "ACTOR",
                        },
                        "relatedIps": [{ "ip": "198.51.100.4", "role": "SOURCE" }],
                        "window": window(3),
                    },
                    "endpointCountries": [{ "ip": "198.51.100.4", "country": "XX" }],
                }),
            ]
        );
    }

    #[tokio::test]
    async fn details_are_returned_exactly() {
        // Above 2^53, where a JSON number would lose precision.
        const WIDE_ENTRY_ID: u64 = (1 << 53) + 1;

        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            let events = store.events();
            for (second, detail) in [
                Detail::WatchlistMatch(WatchlistMatchDetail {
                    entry_id: WIDE_ENTRY_ID,
                    matched_side: EndpointRole::Destination,
                    raw_event_count: 12,
                    truncated_related_ips: u64::MAX,
                    closed_early: true,
                }),
                Detail::LdapBruteForce(LdapBruteForceDetail {
                    resp_port: 389,
                    proto: 6,
                    user_pw_list: vec![
                        ("alice".to_string(), "secret-1".to_string()),
                        ("bob".to_string(), "secret-2".to_string()),
                    ],
                }),
                Detail::LockyRansomware,
                Detail::UnusualDestinationPattern(UnusualDestinationPatternDetail {
                    count: 40,
                    expected_mean: 2.5,
                    std_deviation: 0.5,
                    z_score: 75.0,
                    truncated_related_ips: 0,
                }),
            ]
            .into_iter()
            .enumerate()
            {
                let second = i64::try_from(second).unwrap();
                let event = subject_event(
                    at(second),
                    Some("sensor1"),
                    PrimarySubject::Sensor,
                    Vec::new(),
                    detail,
                );
                events.put_event(&event).unwrap();
            }
        }

        let fields = "detectionModel detail {
            __typename
            ... on WatchlistMatchDetail {
                entryId matchedSide rawEventCount truncatedRelatedIps closedEarly
            }
            ... on LdapBruteForceDetail { respPort proto userPwList { user password } }
            ... on LockyRansomwareDetail { detectionModel }
            ... on UnusualDestinationPatternDetail { count expectedMean stdDeviation zScore }
        }";
        assert_eq!(
            nodes(&schema, fields).await,
            [
                json!({ "detectionModel": "WATCHLIST_MATCH", "detail": {
                    "__typename": "WatchlistMatchDetail",
                    "entryId": WIDE_ENTRY_ID.to_string(),
                    "matchedSide": "DESTINATION",
                    "rawEventCount": "12",
                    "truncatedRelatedIps": u64::MAX.to_string(),
                    "closedEarly": true,
                } }),
                json!({ "detectionModel": "LDAP_BRUTE_FORCE", "detail": {
                    "__typename": "LdapBruteForceDetail",
                    "respPort": 389,
                    "proto": 6,
                    "userPwList": [
                        { "user": "alice", "password": "secret-1" },
                        { "user": "bob", "password": "secret-2" },
                    ],
                } }),
                json!({ "detectionModel": "LOCKY_RANSOMWARE", "detail": {
                    "__typename": "LockyRansomwareDetail",
                    "detectionModel": "LOCKY_RANSOMWARE",
                } }),
                json!({ "detectionModel": "UNUSUAL_DESTINATION_PATTERN", "detail": {
                    "__typename": "UnusualDestinationPatternDetail",
                    "count": "40",
                    "expectedMean": 2.5,
                    "stdDeviation": 0.5,
                    "zScore": 75.0,
                } }),
            ]
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn label_db_match_and_far_outlier_details_are_returned_exactly() {
        use review_protocol::types::{FarOutlierDetail, LabelDbMatchDetail};

        // Above 2^53, where a JSON number would lose precision.
        const WIDE: u64 = (1 << 53) + 1;
        const RULE_CONFIDENCE: f32 = 0.7;
        const MATCH_SCORE: f32 = 0.3;

        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            let events = store.events();
            for (second, detail) in [
                Detail::LabelDbMatch(LabelDbMatchDetail {
                    label_db: "web-rules".to_string(),
                    rule_id: u32::MAX,
                    rule_name: "admin path probe".to_string(),
                    matched_to: "GET /admin".to_string(),
                    cluster_id: u32::MAX - 1,
                    rule_confidence: Some(RULE_CONFIDENCE),
                    match_score: MATCH_SCORE,
                }),
                Detail::LabelDbMatch(LabelDbMatchDetail {
                    label_db: "url-rules".to_string(),
                    rule_id: 0,
                    rule_name: "exact".to_string(),
                    matched_to: "example.com/x".to_string(),
                    cluster_id: 3,
                    rule_confidence: None,
                    match_score: 1.0,
                }),
                Detail::FarOutlier(FarOutlierDetail::Prefix {
                    nearest_cluster_id: Some(u32::MAX),
                    nearest_signature: Some("GET /api".to_string()),
                    matched_tokens: 2,
                    prefix_len: u32::MAX,
                    diverged_token: Some("v9".to_string()),
                    pattern_count: WIDE,
                    truncated_in_pattern: u64::MAX,
                }),
                Detail::FarOutlier(FarOutlierDetail::Prefix {
                    nearest_cluster_id: None,
                    nearest_signature: None,
                    matched_tokens: 0,
                    prefix_len: 0,
                    diverged_token: None,
                    pattern_count: 1,
                    truncated_in_pattern: 0,
                }),
            ]
            .into_iter()
            .enumerate()
            {
                let second = i64::try_from(second).unwrap();
                let event = subject_event(
                    at(second),
                    Some("sensor1"),
                    PrimarySubject::Sensor,
                    Vec::new(),
                    detail,
                );
                events.put_event(&event).unwrap();
            }
        }

        let fields = "detectionModel detail {
            __typename
            ... on LabelDbMatchDetail {
                labelDb ruleId ruleName matchedTo clusterId ruleConfidence matchScore
            }
            ... on FarOutlierDetail {
                prefix {
                    nearestClusterId nearestSignature matchedTokens prefixLen divergedToken
                    patternCount truncatedInPattern
                }
            }
        }";
        assert_eq!(
            nodes(&schema, fields).await,
            [
                json!({ "detectionModel": "LABEL_DB_MATCH", "detail": {
                    "__typename": "LabelDbMatchDetail",
                    "labelDb": "web-rules",
                    "ruleId": u32::MAX.to_string(),
                    "ruleName": "admin path probe",
                    "matchedTo": "GET /admin",
                    "clusterId": (u32::MAX - 1).to_string(),
                    "ruleConfidence": f64::from(RULE_CONFIDENCE),
                    "matchScore": f64::from(MATCH_SCORE),
                } }),
                json!({ "detectionModel": "LABEL_DB_MATCH", "detail": {
                    "__typename": "LabelDbMatchDetail",
                    "labelDb": "url-rules",
                    "ruleId": "0",
                    "ruleName": "exact",
                    "matchedTo": "example.com/x",
                    "clusterId": "3",
                    "ruleConfidence": null,
                    "matchScore": 1.0,
                } }),
                json!({ "detectionModel": "FAR_OUTLIER", "detail": {
                    "__typename": "FarOutlierDetail",
                    "prefix": {
                        "nearestClusterId": u32::MAX.to_string(),
                        "nearestSignature": "GET /api",
                        "matchedTokens": "2",
                        "prefixLen": u32::MAX.to_string(),
                        "divergedToken": "v9",
                        "patternCount": WIDE.to_string(),
                        "truncatedInPattern": u64::MAX.to_string(),
                    },
                } }),
                json!({ "detectionModel": "FAR_OUTLIER", "detail": {
                    "__typename": "FarOutlierDetail",
                    "prefix": {
                        "nearestClusterId": null,
                        "nearestSignature": null,
                        "matchedTokens": "0",
                        "prefixLen": "0",
                        "divergedToken": null,
                        "patternCount": "1",
                        "truncatedInPattern": "0",
                    },
                } }),
            ]
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn every_other_detail_is_returned_as_its_own_member() {
        use review_protocol::types::{
            CryptocurrencyMiningPoolDetail, ExternalDdosDetail, FtpBruteForceDetail,
            MultiHostPortScanDetail, PortScanDetail, RdpBruteForceDetail,
            RepeatedHttpSessionsDetail,
        };

        // `details_are_returned_exactly` covers the other four details.
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            let events = store.events();
            for (second, detail) in [
                Detail::CryptocurrencyMiningPool(CryptocurrencyMiningPoolDetail {
                    coins: vec!["XMR".to_string(), "BTC".to_string()],
                }),
                Detail::SuspiciousTlsTraffic,
                Detail::PortScan(PortScanDetail {
                    resp_ports: vec![22, 80, 443],
                    proto: 6,
                }),
                Detail::MultiHostPortScan(MultiHostPortScanDetail {
                    resp_port: 445,
                    proto: 6,
                    truncated_related_ips: u64::MAX,
                }),
                Detail::ExternalDdos(ExternalDdosDetail {
                    proto: 17,
                    truncated_related_ips: 3,
                }),
                Detail::RdpBruteForce(RdpBruteForceDetail {
                    proto: 6,
                    truncated_related_ips: 0,
                }),
                Detail::FtpBruteForce(FtpBruteForceDetail {
                    resp_port: 21,
                    proto: 6,
                    user_list: vec!["admin".to_string(), "root".to_string()],
                    is_internal: true,
                }),
                Detail::RepeatedHttpSessions(RepeatedHttpSessionsDetail {
                    orig_port: 50000,
                    resp_port: 8080,
                    proto: 6,
                }),
                Detail::FtpPlainText,
                Detail::LdapPlainText,
                Detail::NonBrowser,
                Detail::TorExitNode,
                Detail::DomainGenerationAlgorithm,
                Detail::DnsCovertChannel,
            ]
            .into_iter()
            .enumerate()
            {
                let event = subject_event(
                    at(i64::try_from(second).unwrap()),
                    Some("sensor1"),
                    PrimarySubject::Sensor,
                    Vec::new(),
                    detail,
                );
                events.put_event(&event).unwrap();
            }
        }

        let fields = "detectionModel detail {
            __typename
            ... on CryptocurrencyMiningPoolDetail { coins }
            ... on SuspiciousTlsTrafficDetail { detectionModel }
            ... on PortScanDetail { respPorts proto }
            ... on MultiHostPortScanDetail { respPort proto truncatedRelatedIps }
            ... on ExternalDdosDetail { proto truncatedRelatedIps }
            ... on RdpBruteForceDetail { proto truncatedRelatedIps }
            ... on FtpBruteForceDetail { respPort proto userList isInternal }
            ... on RepeatedHttpSessionsDetail { origPort respPort proto }
            ... on FtpPlainTextDetail { detectionModel }
            ... on LdapPlainTextDetail { detectionModel }
            ... on NonBrowserDetail { detectionModel }
            ... on TorExitNodeDetail { detectionModel }
            ... on DomainGenerationAlgorithmDetail { detectionModel }
            ... on DnsCovertChannelDetail { detectionModel }
        }";
        // A detail that carries nothing reports the model of its own event.
        let empty = |model: &str, member: &str| {
            json!({ "detectionModel": model, "detail": {
                "__typename": member,
                "detectionModel": model,
            } })
        };
        assert_eq!(
            nodes(&schema, fields).await,
            [
                json!({ "detectionModel": "CRYPTOCURRENCY_MINING_POOL", "detail": {
                    "__typename": "CryptocurrencyMiningPoolDetail",
                    "coins": ["XMR", "BTC"],
                } }),
                empty("SUSPICIOUS_TLS_TRAFFIC", "SuspiciousTlsTrafficDetail"),
                json!({ "detectionModel": "PORT_SCAN", "detail": {
                    "__typename": "PortScanDetail",
                    "respPorts": [22, 80, 443],
                    "proto": 6,
                } }),
                json!({ "detectionModel": "MULTI_HOST_PORT_SCAN", "detail": {
                    "__typename": "MultiHostPortScanDetail",
                    "respPort": 445,
                    "proto": 6,
                    "truncatedRelatedIps": u64::MAX.to_string(),
                } }),
                json!({ "detectionModel": "EXTERNAL_DDOS", "detail": {
                    "__typename": "ExternalDdosDetail",
                    "proto": 17,
                    "truncatedRelatedIps": "3",
                } }),
                json!({ "detectionModel": "RDP_BRUTE_FORCE", "detail": {
                    "__typename": "RdpBruteForceDetail",
                    "proto": 6,
                    "truncatedRelatedIps": "0",
                } }),
                json!({ "detectionModel": "FTP_BRUTE_FORCE", "detail": {
                    "__typename": "FtpBruteForceDetail",
                    "respPort": 21,
                    "proto": 6,
                    "userList": ["admin", "root"],
                    "isInternal": true,
                } }),
                json!({ "detectionModel": "REPEATED_HTTP_SESSIONS", "detail": {
                    "__typename": "RepeatedHttpSessionsDetail",
                    "origPort": 50000,
                    "respPort": 8080,
                    "proto": 6,
                } }),
                empty("FTP_PLAIN_TEXT", "FtpPlainTextDetail"),
                empty("LDAP_PLAIN_TEXT", "LdapPlainTextDetail"),
                empty("NON_BROWSER", "NonBrowserDetail"),
                empty("TOR_EXIT_NODE", "TorExitNodeDetail"),
                empty(
                    "DOMAIN_GENERATION_ALGORITHM",
                    "DomainGenerationAlgorithmDetail"
                ),
                empty("DNS_COVERT_CHANNEL", "DnsCovertChannelDetail"),
            ]
        );
    }

    /// Returns a raw event body of type `T` with every field at its zero
    /// value: zero numbers, `false`, empty strings and lists, and `0.0.0.0`.
    ///
    /// The body is decoded from zero bytes with `bincode`, whose fixed-width
    /// encoding reads each of those values from all-zero input.
    fn zero_body<T: serde::de::DeserializeOwned>() -> T {
        bincode::deserialize(&[0; 1024]).expect("a body decodable from zero bytes")
    }

    #[tokio::test]
    async fn every_raw_event_body_is_returned_as_its_own_member() {
        // Each entry is a raw event kind, its GraphQL enum value, the union
        // member of its body, and a zero body of that kind.
        macro_rules! bodies {
            ($(($kind:ident, $name:literal)),* $(,)?) => {
                vec![$((
                    RawEventKind::$kind,
                    $name,
                    concat!(stringify!($kind), "Body"),
                    RawEventBody::$kind(zero_body()),
                )),*]
            };
        }

        let bodies = bodies![
            (Conn, "CONN"),
            (Dns, "DNS"),
            (Http, "HTTP"),
            (Rdp, "RDP"),
            (Smtp, "SMTP"),
            (Ntlm, "NTLM"),
            (Kerberos, "KERBEROS"),
            (Ssh, "SSH"),
            (DceRpc, "DCE_RPC"),
            (Ftp, "FTP"),
            (Mqtt, "MQTT"),
            (Ldap, "LDAP"),
            (Tls, "TLS"),
            (Smb, "SMB"),
            (Nfs, "NFS"),
            (Bootp, "BOOTP"),
            (Dhcp, "DHCP"),
            (Radius, "RADIUS"),
            (MalformedDns, "MALFORMED_DNS"),
            (Icmp, "ICMP"),
            (ProcessCreate, "PROCESS_CREATE"),
            (FileCreateTime, "FILE_CREATE_TIME"),
            (NetworkConnect, "NETWORK_CONNECT"),
            (ProcessTerminate, "PROCESS_TERMINATE"),
            (ImageLoad, "IMAGE_LOAD"),
            (FileCreate, "FILE_CREATE"),
            (RegistryValueSet, "REGISTRY_VALUE_SET"),
            (RegistryKeyRename, "REGISTRY_KEY_RENAME"),
            (FileCreateStreamHash, "FILE_CREATE_STREAM_HASH"),
            (PipeEvent, "PIPE_EVENT"),
            (DnsQuery, "DNS_QUERY"),
            (FileDelete, "FILE_DELETE"),
            (ProcessTamper, "PROCESS_TAMPER"),
            (FileDeleteDetected, "FILE_DELETE_DETECTED"),
            (Netflow5, "NETFLOW_5"),
            (Netflow9, "NETFLOW_9"),
        ];
        let schema = TestSchema::new().await;
        let expected: Vec<Value> = {
            let store = schema.store();
            let events = store.events();
            bodies
                .into_iter()
                .enumerate()
                .map(|(second, (kind, name, member, body))| {
                    let event = raw_event(
                        at(i64::try_from(second).unwrap()),
                        "sensor1",
                        kind,
                        body,
                        Detail::TorExitNode,
                    );
                    events.put_event(&event).unwrap();
                    json!({
                        "rawEventKind": name,
                        "target": { "body": { "__typename": member } },
                    })
                })
                .collect()
        };
        assert_eq!(expected.len(), 36);

        // The union has one member per raw event kind, and each body is
        // returned as the member of its own kind.
        let fields = "rawEventKind target { ... on RawEventTarget { body { __typename } } }";
        assert_eq!(nodes(&schema, fields).await, expected);

        // The fields come from the stored body: a zero body has
        // `0.0.0.0` addresses, an empty string and a zero number.
        let fields = "target { ... on RawEventTarget { body {
            ... on HttpBody { origAddr respAddr method statusCode }
            ... on NetworkConnectBody { sourceIp destinationIp }
            ... on Netflow9Body { origAddr respAddr }
        } } }";
        let bodies: Vec<Value> = nodes(&schema, fields)
            .await
            .into_iter()
            .map(|node| node["target"]["body"].clone())
            .filter(|body| body.as_object().is_some_and(|body| !body.is_empty()))
            .collect();
        assert_eq!(
            bodies,
            [
                json!({ "origAddr": "0.0.0.0", "respAddr": "0.0.0.0", "method": "", "statusCode": 0 }),
                json!({ "sourceIp": "0.0.0.0", "destinationIp": "0.0.0.0" }),
                json!({ "origAddr": "0.0.0.0", "respAddr": "0.0.0.0" }),
            ]
        );
    }

    #[tokio::test]
    async fn stamped_fields_are_read_verbatim() {
        let schema = TestSchema::new().await;
        let trained_at: Timestamp = "2026-03-15T15:00:04.123456789Z".parse().unwrap();
        let stamps = [
            stamp(),
            DetectionEventStamp {
                engine_instance: review_database::ModelInstance {
                    node_id: 9,
                    agent_key: "unsupervised".to_string(),
                },
                clustering_model_id: Some(u32::MAX),
                trained_at: Some(trained_at),
                installed_version: Some("1.2.3".to_string()),
                installed_commit: None,
                config_revision: Some(u64::MAX),
                clustering_model_type: None,
            },
            DetectionEventStamp {
                installed_commit: Some("0123abc".to_string()),
                config_revision: Some(0),
                ..stamp()
            },
        ];
        {
            let store = schema.store();
            let events = store.events();
            for (second, stamp) in stamps.iter().enumerate() {
                let event = dns_event(
                    at(i64::try_from(second).unwrap()),
                    addr("192.0.2.1"),
                    addr("192.0.2.2"),
                    None,
                    "sensor1",
                );
                events.put(&event, stamp).unwrap();
            }
        }

        let fields = "engineInstance { nodeId agentKey } clusteringModelId trainedAt
            engineVersion { version commit } configRevision";
        assert_eq!(
            nodes(&schema, fields).await,
            [
                json!({
                    "engineInstance": { "nodeId": "1", "agentKey": "semi-supervised" },
                    "clusteringModelId": null,
                    "trainedAt": null,
                    "engineVersion": null,
                    "configRevision": null,
                }),
                json!({
                    "engineInstance": { "nodeId": "9", "agentKey": "unsupervised" },
                    "clusteringModelId": u32::MAX.to_string(),
                    "trainedAt": "2026-03-15T15:00:04.123456789Z",
                    "engineVersion": { "version": "1.2.3", "commit": null },
                    "configRevision": u64::MAX.to_string(),
                }),
                json!({
                    "engineInstance": { "nodeId": "1", "agentKey": "semi-supervised" },
                    "clusteringModelId": null,
                    "trainedAt": null,
                    "engineVersion": { "version": null, "commit": "0123abc" },
                    "configRevision": "0",
                }),
            ]
        );
    }

    #[tokio::test]
    async fn the_clustering_model_type_is_read_from_the_stamp() {
        use crate::graphql::model_test_support::{TestModel, http_url};

        let schema = TestSchema::new().await;
        let retrain = |model_type| {
            TestModel {
                clustering_model_type: model_type,
                ..TestModel::new("url-model", 1)
            }
            .replace(&schema.store())
        };
        let model_id = retrain(http_url(1));
        let stamps = [
            DetectionEventStamp {
                clustering_model_id: Some(model_id),
                clustering_model_type: Some(http_url(1)),
                ..stamp()
            },
            DetectionEventStamp {
                clustering_model_type: Some(review_database::ClusteringModelTypeRef::Custom),
                ..stamp()
            },
            stamp(),
        ];
        {
            let store = schema.store();
            let events = store.events();
            for (second, stamp) in stamps.iter().enumerate() {
                let event = dns_event(
                    at(i64::try_from(second).unwrap()),
                    addr("192.0.2.1"),
                    addr("192.0.2.2"),
                    None,
                    "sensor1",
                );
                events.put(&event, stamp).unwrap();
            }
        }

        let expected = [
            json!({ "clusteringModelType": { "id": "http_url", "version": "1" } }),
            json!({ "clusteringModelType": { "id": "custom", "version": null } }),
            json!({ "clusteringModelType": null }),
        ];
        let fields = "clusteringModelType { id version }";
        assert_eq!(nodes(&schema, fields).await, expected);

        // A retrain of the model as another type does not change what its
        // earlier events recorded.
        assert_eq!(
            retrain(review_database::ClusteringModelTypeRef::Custom),
            model_id
        );
        assert_eq!(nodes(&schema, fields).await, expected);
    }

    #[tokio::test]
    async fn header_fields_are_returned() {
        let schema = TestSchema::new().await;
        {
            let mut event = dns_event(
                at(0),
                addr("192.0.2.1"),
                addr("192.0.2.2"),
                Some(EventCategory::CommandAndControl),
                "sensor1",
            );
            event.score = 0.25;
            schema.store().events().put_event(&event).unwrap();
            let mut event = subject_event(
                at(1),
                None,
                PrimarySubject::Sensor,
                Vec::new(),
                Detail::PortScan(review_protocol::types::PortScanDetail {
                    resp_ports: vec![22, 80, 443],
                    proto: 6,
                }),
            );
            event.detection_model = DetectionModel::PortScan;
            schema.store().events().put_event(&event).unwrap();
        }
        assert_eq!(
            nodes(
                &schema,
                "__typename time sensor detectionModel rawEventKind category score triageScores { policyId }"
            )
            .await,
            [
                json!({
                    "__typename": "DetectionEvent",
                    "time": at(0).to_string(),
                    "sensor": "sensor1",
                    "detectionModel": "DNS_COVERT_CHANNEL",
                    "rawEventKind": "DNS",
                    "category": "COMMAND_AND_CONTROL",
                    "score": 0.25,
                    "triageScores": null,
                }),
                json!({
                    "__typename": "DetectionEvent",
                    "time": at(1).to_string(),
                    "sensor": null,
                    "detectionModel": "PORT_SCAN",
                    "rawEventKind": "CONN",
                    "category": null,
                    "score": 0.8,
                    "triageScores": null,
                }),
            ]
        );
    }
}

/// The conditions of `EventListFilterInput` and `EventStandardFilterInput`.
mod filter_conditions {
    use std::collections::BTreeSet;

    use review_protocol::types::{
        DetectionModel, EndpointRole, PrimarySubject, RawEventBody, RawEventKind, ThreatRole,
    };

    use super::*;
    use crate::graphql::event_test_support::{raw_event, related, subject_event};

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(1_700_000_000 + second).expect("a test time")
    }

    /// Stores one event per row, at the row's second, labelled by its
    /// sensor so a test can tell which were selected.
    fn seed(schema: &TestSchema) {
        let store = schema.store();
        let events = store.events();
        let mut dns = dns_event(
            at(0),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            Some(EventCategory::CommandAndControl),
            "dns",
        );
        dns.score = 0.5;
        events.put_event(&dns).unwrap();

        let mut sysmon = raw_event(
            at(1),
            "sysmon",
            RawEventKind::ProcessCreate,
            RawEventBody::ProcessCreate(super::detection_event::process_create_body()),
            Detail::NonBrowser,
        );
        sysmon.score = 0.2;
        events.put_event(&sysmon).unwrap();

        let mut host = subject_event(
            at(2),
            Some("host"),
            PrimarySubject::Host {
                ip: "192.0.2.9".parse().unwrap(),
                role: ThreatRole::Actor,
            },
            Vec::new(),
            Detail::LockyRansomware,
        );
        host.score = 0.8;
        events.put_event(&host).unwrap();

        let mut sensor = subject_event(
            at(3),
            Some("sensor"),
            PrimarySubject::Sensor,
            vec![
                related("198.51.100.1", EndpointRole::Source),
                related("198.51.100.2", EndpointRole::Destination),
            ],
            Detail::TorExitNode,
        );
        sensor.score = 0.800_000_1;
        sensor.category = Some(EventCategory::Reconnaissance);
        events.put_event(&sensor).unwrap();
    }

    /// Returns the sensors of the events `filter` selects through
    /// `eventList` and `eventListWithTriage`, checking both agree and their
    /// `totalCount` matches.
    async fn selected(schema: &TestSchema, filter: &str) -> BTreeSet<String> {
        let mut results = Vec::new();
        for field in ["eventList", "eventListWithTriage"] {
            let res = schema
                .execute_as_system_admin(&format!(
                    "{{ {field}(filter: {{ {filter} }}) {{ edges {{ node {{ sensor }} }} totalCount }} }}"
                ))
                .await;
            assert!(res.errors.is_empty(), "{filter}: {:?}", res.errors);
            let data = res.data.into_json().unwrap();
            let sensors: BTreeSet<String> = data[field]["edges"]
                .as_array()
                .unwrap()
                .iter()
                .map(|edge| edge["node"]["sensor"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                data[field]["totalCount"],
                sensors.len().to_string(),
                "{field} {filter}"
            );
            results.push(sensors);
        }
        let with_triage = results.pop().unwrap();
        let list = results.pop().unwrap();
        assert_eq!(list, with_triage, "{filter}");
        list
    }

    fn set(sensors: &[&str]) -> BTreeSet<String> {
        sensors.iter().map(ToString::to_string).collect()
    }

    #[tokio::test]
    async fn detection_models_and_raw_event_kinds_select_exactly_the_listed_values() {
        let schema = TestSchema::new().await;
        seed(&schema);
        assert_eq!(selected(&schema, "detectionModels: []").await, set(&[]));
        assert_eq!(selected(&schema, "rawEventKinds: []").await, set(&[]));
        assert_eq!(
            selected(
                &schema,
                "detectionModels: [DNS_COVERT_CHANNEL, TOR_EXIT_NODE]"
            )
            .await,
            set(&["dns", "sensor"])
        );
        assert_eq!(
            selected(&schema, "rawEventKinds: [PROCESS_CREATE]").await,
            set(&["sysmon"])
        );
        // Subject events carry the raw event kind of their fixture, `CONN`.
        assert_eq!(
            selected(&schema, "rawEventKinds: [CONN, DNS]").await,
            set(&["dns", "host", "sensor"])
        );
        assert_eq!(
            selected(
                &schema,
                "detectionModels: [LOCKY_RANSOMWARE], rawEventKinds: [DNS]"
            )
            .await,
            set(&[])
        );
    }

    #[tokio::test]
    async fn score_bounds_are_inclusive() {
        let schema = TestSchema::new().await;
        seed(&schema);
        assert_eq!(
            selected(&schema, "scoreMin: 0.5, scoreMax: 0.8").await,
            set(&["dns", "host"])
        );
        assert_eq!(
            selected(&schema, "scoreMin: 0.8").await,
            set(&["host", "sensor"])
        );
        assert_eq!(selected(&schema, "scoreMax: 0.2").await, set(&["sysmon"]));
        assert_eq!(selected(&schema, "scoreMin: 0.9").await, set(&[]));
    }

    #[tokio::test]
    async fn categories_and_learning_methods() {
        let schema = TestSchema::new().await;
        seed(&schema);
        assert_eq!(
            selected(&schema, "categories: [null]").await,
            set(&["sysmon", "host"])
        );
        assert_eq!(
            selected(&schema, "categories: [1, null]").await,
            set(&["sysmon", "host", "sensor"])
        );
        // The seeded events are all of semi-supervised models in
        // review-database's property table.
        assert_eq!(
            selected(&schema, "learningMethods: [SEMI_SUPERVISED]").await,
            set(&["dns", "sysmon", "host", "sensor"])
        );
        assert_eq!(
            selected(&schema, "learningMethods: [UNSUPERVISED]").await,
            set(&[])
        );
        assert_eq!(selected(&schema, "learningMethods: []").await, set(&[]));
        for model in (0..=u32::from(u8::MAX)).filter_map(|n| DetectionModel::try_from(n).ok()) {
            let expected = if matches!(
                model,
                DetectionModel::LabelDbMatch
                    | DetectionModel::FarOutlier
                    | DetectionModel::WindowOutlier
            ) {
                review_database::event::LearningMethod::Unsupervised
            } else {
                review_database::event::LearningMethod::SemiSupervised
            };
            assert_eq!(
                review_database::properties(model).learning_method,
                expected,
                "{model:?}"
            );
        }
    }

    #[tokio::test]
    async fn address_conditions_use_the_originator_and_responder_sides() {
        let schema = TestSchema::new().await;
        seed(&schema);
        // A host subject's IP is on both sides.
        assert_eq!(
            selected(&schema, r#"source: "192.0.2.9""#).await,
            set(&["host"])
        );
        assert_eq!(
            selected(&schema, r#"destination: "192.0.2.9""#).await,
            set(&["host"])
        );
        // A sensor subject is matched only through its related IPs, each on
        // the side it was observed on.
        assert_eq!(
            selected(&schema, r#"source: "198.51.100.1""#).await,
            set(&["sensor"])
        );
        assert_eq!(
            selected(&schema, r#"destination: "198.51.100.1""#).await,
            set(&[])
        );
        assert_eq!(
            selected(&schema, r#"destination: "198.51.100.2""#).await,
            set(&["sensor"])
        );
        // A raw event body's addresses.
        assert_eq!(
            selected(&schema, r#"source: "192.0.2.1""#).await,
            set(&["dns"])
        );
        assert_eq!(
            selected(&schema, r#"destination: "192.0.2.1""#).await,
            set(&[])
        );
        for (direction, expected) in [
            ("FROM", set(&["host", "sensor"])),
            ("TO", set(&["host", "sensor"])),
        ] {
            let range = if direction == "FROM" {
                r#"{ start: "192.0.2.9", end: "198.51.100.1" }"#
            } else {
                r#"{ start: "192.0.2.9", end: "198.51.100.2" }"#
            };
            assert_eq!(
                selected(
                    &schema,
                    &format!(
                        "endpoints: [{{ direction: {direction}, custom: {{ hosts: [], networks: [], ranges: [{range}] }} }}]"
                    )
                )
                .await,
                expected,
                "{direction}"
            );
        }
        assert_eq!(
            selected(
                &schema,
                r#"endpoints: [{ direction: FROM, custom: { hosts: ["198.51.100.2"], networks: [], ranges: [] } }]"#
            )
            .await,
            set(&[])
        );
        // A Sysmon body has no address, so no address condition selects it.
        assert_eq!(
            selected(
                &schema,
                r#"endpoints: [{ custom: { hosts: [], networks: ["0.0.0.0/0"], ranges: [] } }]"#
            )
            .await,
            set(&["dns", "host", "sensor"])
        );
    }

    #[tokio::test]
    async fn a_scoped_caller_sees_no_event_without_a_sensor() {
        let schema = TestSchema::new().await;
        insert_sensor1_node(&schema).await;
        let (own, sensorless) = {
            let store = schema.store();
            let events = store.events();
            let own = events
                .put_event(&super::sensor1_event_at(at(0), 1, 2))
                .unwrap();
            let mut event = super::sensor1_event_at(at(1), 3, 4);
            event.sensor = None;
            let sensorless = events.put_event(&event).unwrap();
            (own, sensorless)
        };
        let query = format!(
            r#"{{
                eventList(filter: {{}}) {{ edges {{ cursor }} totalCount }}
                own: event(id: "{own}") {{ id }}
                sensorless: event(id: "{sensorless}") {{ id }}
            }}"#
        );
        let res = schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![0]))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            serde_json::json!({
                "eventList": { "edges": [{ "cursor": own.to_string() }], "totalCount": "1" },
                "own": { "id": own.to_string() },
                "sensorless": null,
            })
        );

        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(data["eventList"]["totalCount"], "2");
        assert_eq!(data["sensorless"]["id"], sensorless.to_string());
    }

    #[tokio::test]
    async fn removed_filter_fields_are_rejected() {
        let schema = TestSchema::new().await;
        for field in [
            "kinds: [DNS_COVERT_CHANNEL]",
            "levels: [LOW]",
            "confidenceMin: 0.1",
            "confidenceMax: 0.9",
        ] {
            for query in ["eventList", "eventListWithTriage"] {
                let res = schema
                    .execute_as_system_admin(&format!(
                        "{{ {query}(filter: {{ {field} }}) {{ totalCount }} }}"
                    ))
                    .await;
                assert!(!res.errors.is_empty(), "{query} {field}");
            }
        }
    }
}

/// The delivery of `eventStream`, per detection model.
mod stream_progress {
    use review_protocol::types::Detail;

    use super::*;
    use crate::graphql::event::StreamProgress;

    const START: i64 = 1_000;

    fn at(nanos: i64) -> Timestamp {
        Timestamp::from_nanosecond(i128::from(nanos)).unwrap()
    }

    fn event(nanos: i64, detail: Detail) -> DetectionEvent {
        let mut event = dns_event(
            at(nanos),
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            None,
            "sensor1",
        );
        event.detection_model = detail.detection_model();
        event.detail = detail;
        event
    }

    /// Stores `event` and returns its key.
    fn put(schema: &TestSchema, event: &DetectionEvent) -> i128 {
        schema.store().events().put_event(event).unwrap()
    }

    /// Polls once and returns the keys delivered.
    fn poll(schema: &TestSchema, progress: &mut StreamProgress) -> Vec<i128> {
        let mut delivered = Vec::new();
        progress
            .poll(&schema.store().events(), |key, _| {
                delivered.push(key);
                Ok(())
            })
            .unwrap();
        delivered
    }

    #[tokio::test]
    async fn records_of_two_models_at_the_same_time_are_both_delivered() {
        let schema = TestSchema::new().await;
        let mut progress = StreamProgress::new(START);
        let a = put(&schema, &event(START + 5, Detail::DnsCovertChannel));
        let b = put(&schema, &event(START + 5, Detail::LockyRansomware));
        let mut delivered = poll(&schema, &mut progress);
        delivered.sort_unstable();
        let mut expected = vec![a, b];
        expected.sort_unstable();
        assert_eq!(delivered, expected);
        assert_eq!(poll(&schema, &mut progress), Vec::<i128>::new());
    }

    #[tokio::test]
    async fn records_before_start_are_not_delivered() {
        let schema = TestSchema::new().await;
        let mut progress = StreamProgress::new(START);
        put(&schema, &event(START - 1, Detail::DnsCovertChannel));
        let at_start = put(&schema, &event(START, Detail::DnsCovertChannel));
        assert_eq!(poll(&schema, &mut progress), [at_start]);
    }

    #[tokio::test]
    async fn a_late_record_of_another_model_is_still_delivered() {
        let schema = TestSchema::new().await;
        let mut progress = StreamProgress::new(START);
        let b = put(&schema, &event(START + 20, Detail::LockyRansomware));
        assert_eq!(poll(&schema, &mut progress), [b]);

        // Model A's time is still at the start, so its record at an earlier
        // time than B's, visible before any stuck-check advance, is
        // delivered.
        let a = put(&schema, &event(START + 10, Detail::DnsCovertChannel));
        assert_eq!(poll(&schema, &mut progress), [a]);
        // A record of B before B's time is not.
        put(&schema, &event(START + 15, Detail::LockyRansomware));
        assert_eq!(poll(&schema, &mut progress), Vec::<i128>::new());
        assert_eq!(poll(&schema, &mut progress), Vec::<i128>::new());
    }

    #[tokio::test]
    async fn a_late_record_below_its_raised_time_is_never_delivered() {
        let schema = TestSchema::new().await;
        let mut progress = StreamProgress::new(START);
        let b = put(&schema, &event(START + 20, Detail::LockyRansomware));
        assert_eq!(poll(&schema, &mut progress), [b]);

        // The stuck check raises every model still at the start to B's
        // next-delivery time, just past its record.
        progress.advance_stuck();
        put(&schema, &event(START + 10, Detail::DnsCovertChannel));
        put(&schema, &event(START + 20, Detail::DnsCovertChannel));
        assert_eq!(poll(&schema, &mut progress), Vec::<i128>::new());

        // A record exactly at the raised time is at or after it.
        let boundary = put(&schema, &event(START + 21, Detail::DnsCovertChannel));
        assert_eq!(poll(&schema, &mut progress), [boundary]);
        assert_eq!(poll(&schema, &mut progress), Vec::<i128>::new());
    }

    #[tokio::test]
    async fn the_stuck_check_raises_only_models_at_the_floor() {
        let schema = TestSchema::new().await;
        let mut progress = StreamProgress::new(START);
        let b = put(&schema, &event(START + 20, Detail::LockyRansomware));
        let c = put(&schema, &event(START + 50, Detail::TorExitNode));
        assert_eq!(poll(&schema, &mut progress), [b, c]);

        // The floor rises to B's time, the smallest above it; C keeps its own.
        progress.advance_stuck();
        let late_c = put(&schema, &event(START + 30, Detail::TorExitNode));
        let a = put(&schema, &event(START + 30, Detail::DnsCovertChannel));
        assert_eq!(poll(&schema, &mut progress), [a]);
        assert!(!poll(&schema, &mut progress).contains(&late_c));

        // The next advance raises the models at the new floor, A excluded
        // since it has moved past it.
        progress.advance_stuck();
        // B was at the floor, so it rose to A's time, just past A's record.
        let below = put(&schema, &event(START + 25, Detail::LockyRansomware));
        let d = put(&schema, &event(START + 51, Detail::LockyRansomware));
        let delivered = poll(&schema, &mut progress);
        assert!(!delivered.contains(&below), "{delivered:?}");
        assert_eq!(delivered, [d]);
    }

    #[tokio::test]
    async fn without_progress_above_the_floor_the_stuck_check_changes_nothing() {
        let schema = TestSchema::new().await;
        let mut progress = StreamProgress::new(START);
        progress.advance_stuck();
        let a = put(&schema, &event(START, Detail::DnsCovertChannel));
        assert_eq!(poll(&schema, &mut progress), [a]);
    }
}

/// `detectionEventsByRawEventKeys`.
mod raw_event_keys {
    use review_protocol::types::{Detail, PrimarySubject, RawEventBody, RawEventKind};
    use serde_json::{Value, json};

    use super::*;
    use crate::graphql::event_test_support::{conn_body, raw_event, subject_event};

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(1_700_000_000 + second).expect("a test time")
    }

    fn key(kind: &str, sensor: &str, time: Timestamp) -> String {
        format!(r#"{{ rawEventKind: {kind}, sensor: "{sensor}", time: "{time}" }}"#)
    }

    fn query(keys: &[String]) -> String {
        format!(
            "{{ detectionEventsByRawEventKeys(keys: [{}]) {{ id detectionModel }} }}",
            keys.join(", ")
        )
    }

    /// Stores, at `at(0)` for `SENSOR1_EVENT_SENSOR`, two models' events
    /// about one DNS raw event, and records that differ from it in one way
    /// each. Returns the keys of the two matching events.
    fn seed(schema: &TestSchema) -> (i128, i128) {
        let store = schema.store();
        let events = store.events();
        let dns = |detail: Detail| {
            let mut event = super::sensor1_event_at(at(0), 1, 2);
            event.detection_model = detail.detection_model();
            event.detail = detail;
            event
        };
        let first = events.put_event(&dns(Detail::DnsCovertChannel)).unwrap();
        let second = events.put_event(&dns(Detail::LockyRansomware)).unwrap();
        // Another kind at the same time and sensor.
        events
            .put_event(&raw_event(
                at(0),
                SENSOR1_EVENT_SENSOR,
                RawEventKind::Conn,
                RawEventBody::Conn(conn_body(
                    "0.0.0.1".parse().unwrap(),
                    "0.0.0.2".parse().unwrap(),
                )),
                Detail::TorExitNode,
            ))
            .unwrap();
        // Another sensor.
        let mut other = super::sensor1_event_at(at(0), 1, 2);
        other.sensor = Some("piglet.other".to_string());
        events.put_event(&other).unwrap();
        // A subject at the same time, sensor and raw event kind.
        let mut subject = subject_event(
            at(0),
            Some(SENSOR1_EVENT_SENSOR),
            PrimarySubject::Sensor,
            Vec::new(),
            Detail::TorExitNode,
        );
        subject.raw_event_kind = RawEventKind::Dns;
        events.put_event(&subject).unwrap();
        // Another time.
        events
            .put_event(&super::sensor1_event_at(at(1), 1, 2))
            .unwrap();
        (first, second)
    }

    fn ids(value: &Value) -> Vec<Vec<String>> {
        value["detectionEventsByRawEventKeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|list| {
                list.as_array()
                    .unwrap()
                    .iter()
                    .map(|event| event["id"].as_str().unwrap().to_string())
                    .collect()
            })
            .collect()
    }

    #[tokio::test]
    async fn every_model_on_the_raw_event_is_returned_and_nothing_else() {
        let schema = TestSchema::new().await;
        let (first, second) = seed(&schema);
        let res = schema
            .execute_as_system_admin(&query(&[key("DNS", SENSOR1_EVENT_SENSOR, at(0))]))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let lists = data["detectionEventsByRawEventKeys"].as_array().unwrap();
        assert_eq!(lists.len(), 1);
        let mut models: Vec<_> = lists[0]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["detectionModel"].as_str().unwrap())
            .collect();
        models.sort_unstable();
        assert_eq!(models, ["DNS_COVERT_CHANNEL", "LOCKY_RANSOMWARE"]);
        let mut found = ids(&data).pop().unwrap();
        found.sort_unstable();
        let mut expected = vec![first.to_string(), second.to_string()];
        expected.sort_unstable();
        assert_eq!(found, expected);
    }

    #[tokio::test]
    async fn each_key_keeps_its_position() {
        let schema = TestSchema::new().await;
        insert_sensor1_node(&schema).await;
        let (first, second) = seed(&schema);
        let keys = [
            key("DNS", "piglet.nowhere", at(0)),
            key("DNS", SENSOR1_EVENT_SENSOR, at(0)),
            key("DNS", "piglet.other", at(0)),
            key("DNS", SENSOR1_EVENT_SENSOR, at(5)),
            key("CONN", SENSOR1_EVENT_SENSOR, at(0)),
        ];
        let mut matching = vec![first.to_string(), second.to_string()];
        matching.sort_unstable();
        let sorted = |mut lists: Vec<Vec<String>>| {
            for list in &mut lists {
                list.sort_unstable();
            }
            lists
        };

        let res = schema.execute_as_system_admin(&query(&keys)).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let lists = sorted(ids(&res.data.into_json().unwrap()));
        assert_eq!(lists.len(), 5);
        assert_eq!(lists[0], Vec::<String>::new());
        assert_eq!(lists[1], matching);
        assert_eq!(lists[2].len(), 1);
        assert_eq!(lists[3], Vec::<String>::new());
        assert_eq!(lists[4].len(), 1);

        // A caller scoped to customer 0, which owns only sensor1, gets an
        // empty list for the other sensor's key, at its position.
        let res = schema
            .execute_as_scoped_user(&query(&keys), Role::SecurityMonitor, Some(vec![0]))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let scoped = sorted(ids(&res.data.into_json().unwrap()));
        assert_eq!(scoped.len(), 5);
        assert_eq!(scoped[0], Vec::<String>::new());
        assert_eq!(scoped[1], matching);
        assert_eq!(scoped[2], Vec::<String>::new());
        assert_eq!(scoped[3], Vec::<String>::new());
        assert_eq!(scoped[4], lists[4]);

        // A caller scoped to another customer gets only empty lists.
        let res = schema
            .execute_as_scoped_user(&query(&keys), Role::SecurityMonitor, Some(vec![1]))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert!(
            ids(&res.data.into_json().unwrap())
                .iter()
                .all(Vec::is_empty)
        );
    }

    #[tokio::test]
    async fn an_empty_input_returns_an_empty_list() {
        let schema = TestSchema::new().await;
        let res = schema.execute_as_system_admin(&query(&[])).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({ "detectionEventsByRawEventKeys": [] })
        );
    }

    #[tokio::test]
    async fn more_than_the_maximum_keys_is_an_error() {
        let schema = TestSchema::new().await;
        seed(&schema);
        let keys: Vec<String> = (0..1001)
            .map(|_| key("DNS", SENSOR1_EVENT_SENSOR, at(0)))
            .collect();
        let res = schema.execute_as_system_admin(&query(&keys)).await;
        assert_eq!(res.data, async_graphql::Value::Null);
        assert_eq!(res.errors.len(), 1, "{:?}", res.errors);
        assert!(
            res.errors[0].message.contains("exceed the maximum of 1000"),
            "{:?}",
            res.errors
        );

        let res = schema.execute_as_system_admin(&query(&keys[..1000])).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[tokio::test]
    async fn a_caller_without_a_role_is_refused() {
        let schema = TestSchema::new().await;
        seed(&schema);
        let res = schema
            .schema
            .execute(async_graphql::Request::new(query(&[key(
                "DNS",
                SENSOR1_EVENT_SENSOR,
                at(0),
            )])))
            .await;
        assert_eq!(res.data, async_graphql::Value::Null);
        assert_eq!(res.errors.len(), 1, "{:?}", res.errors);
    }
}

/// Header-less time-series detection events: their `WindowOutlier` detail,
/// and their selection through the sensors of the policy their time-series
/// id names.
mod time_series_events {
    use review_protocol::types::{
        DetectionModel, PrimarySubject, RawEventKind, SlotDeviation, ThreatRole,
        WindowOutlierDetail,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::graphql::{
        event_test_support::subject_event,
        time_series_generation_test_support::{
            PolicyShape, insert_generator_node, insert_shaped_policy, sensor_name,
        },
    };

    const HOST_1: &str = "s1.example.com";
    const HOST_2: &str = "s2.example.com";
    const OTHER_HOST: &str = "d.example.com";

    fn at(second: i64) -> Timestamp {
        Timestamp::from_second(1_700_000_000 + second).expect("a test time")
    }

    /// A store with two sensor nodes of customer 1, one of customer 2, a
    /// policy of customer 1 reading both of customer 1's sensors, and two
    /// header-less `WindowOutlier` events of that policy.
    struct Fixture {
        schema: TestSchema,
        second_node: u32,
        other_node: u32,
        /// The key of the first event.
        first: i128,
    }

    /// Returns a header-less `WindowOutlier` event of the series `series` at
    /// `second`, whose session lookup cut `pcap_truncated` sessions.
    fn window_outlier(second: i64, series: &str, pcap_truncated: Option<u64>) -> DetectionEvent {
        let mut event = subject_event(
            at(second),
            None,
            PrimarySubject::Host {
                ip: "10.0.0.1".parse().unwrap(),
                role: ThreatRole::Target,
            },
            Vec::new(),
            Detail::WindowOutlier(WindowOutlierDetail {
                time_series_id: series.to_string(),
                window_start: at(second),
                nearest_cluster_id: u32::MAX,
                distance: 12.5,
                top_slots: vec![
                    SlotDeviation {
                        slot_start: at(second + 300),
                        value: 310.0,
                        centroid_value: 12.0,
                    },
                    SlotDeviation {
                        slot_start: at(second),
                        value: 95.0,
                        centroid_value: 10.5,
                    },
                ],
                truncated: u64::MAX,
                pcap_truncated,
            }),
        );
        event.raw_event_kind = RawEventKind::Tls;
        event.score = 12.5;
        event
    }

    async fn seed() -> Fixture {
        let schema = TestSchema::new().await;
        let (second_node, other_node, first) = {
            let store = schema.store();
            insert_generator_node(&store, HOST_1, 1);
            let second = insert_generator_node(&store, HOST_2, 1);
            let other = insert_generator_node(&store, OTHER_HOST, 2);
            let policy = insert_shaped_policy(
                &store,
                "series",
                1,
                &[&sensor_name(HOST_1), &sensor_name(HOST_2)],
                PolicyShape::default(),
            );
            let events = store.events();
            let series = format!("{policy}/10.0.0.1");
            let first = events
                .put_event(&window_outlier(0, &series, Some(17)))
                .unwrap();
            events.put_event(&window_outlier(1, &series, None)).unwrap();
            (second.node_id, other.node_id, first)
        };
        Fixture {
            schema,
            second_node,
            other_node,
            first,
        }
    }

    fn times(res: async_graphql::Response) -> Vec<String> {
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        res.data.into_json().unwrap()["eventList"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["node"]["time"].as_str().unwrap().to_string())
            .collect()
    }

    fn list(filter: &str) -> String {
        format!(
            "{{ eventList(filter: {{ {filter} }}) {{ \
                edges {{ node {{ ... on DetectionEvent {{ time }} }} }} \
            }} }}"
        )
    }

    #[tokio::test]
    async fn a_window_outlier_event_returns_its_detail() {
        let f = seed().await;
        let res = f
            .schema
            .execute_as_system_admin(&list("detectionModels: [WINDOW_OUTLIER]").replace(
                "{ time }",
                "{ time sensor detectionModel detail { __typename ... on WindowOutlierDetail { \
                    timeSeriesId windowStart nearestClusterId distance \
                    topSlots { slotStart value centroidValue } truncated pcapTruncated } } }",
            ))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let nodes: Vec<Value> = data["eventList"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["node"].clone())
            .collect();
        let expected = |second: i64, pcap_truncated: Value| {
            json!({
                "time": at(second).to_string(),
                "sensor": null,
                "detectionModel": "WINDOW_OUTLIER",
                "detail": {
                    "__typename": "WindowOutlierDetail",
                    "timeSeriesId": "0/10.0.0.1",
                    "windowStart": at(second).to_string(),
                    "nearestClusterId": u32::MAX.to_string(),
                    "distance": 12.5,
                    "topSlots": [
                        {
                            "slotStart": at(second + 300).to_string(),
                            "value": 310.0,
                            "centroidValue": 12.0,
                        },
                        {
                            "slotStart": at(second).to_string(),
                            "value": 95.0,
                            "centroidValue": 10.5,
                        },
                    ],
                    "truncated": u64::MAX.to_string(),
                    "pcapTruncated": pcap_truncated,
                },
            })
        };
        assert_eq!(nodes, [expected(0, json!("17")), expected(1, Value::Null)]);

        // `detectionModels` selects the model.
        let res = f
            .schema
            .execute_as_system_admin(&list("detectionModels: [FAR_OUTLIER]"))
            .await;
        assert_eq!(times(res), Vec::<String>::new());
        assert_eq!(
            DetectionModel::from(crate::graphql::filter::DetectionModel::WindowOutlier),
            DetectionModel::WindowOutlier
        );
    }

    #[tokio::test]
    async fn a_header_less_event_is_selected_through_its_policys_sensors() {
        let f = seed().await;
        let both = vec![at(0).to_string(), at(1).to_string()];

        let res = f
            .schema
            .execute_as_scoped_user(&list(""), Role::SecurityMonitor, Some(vec![1]))
            .await;
        assert_eq!(times(res), both);
        let res = f
            .schema
            .execute_as_scoped_user(&list(""), Role::SecurityMonitor, Some(vec![2]))
            .await;
        assert_eq!(times(res), Vec::<String>::new());

        // A sensor filter naming the policy's second sensor selects it, and
        // one naming another customer's sensor does not.
        let res = f
            .schema
            .execute_as_system_admin(&list(&format!("sensors: [\"{}\"]", f.second_node)))
            .await;
        assert_eq!(times(res), both);
        let res = f
            .schema
            .execute_as_scoped_user(
                &list(&format!("sensors: [\"{}\"]", f.second_node)),
                Role::SecurityMonitor,
                Some(vec![1]),
            )
            .await;
        assert_eq!(times(res), both);
        let res = f
            .schema
            .execute_as_system_admin(&list(&format!("sensors: [\"{}\"]", f.other_node)))
            .await;
        assert_eq!(times(res), Vec::<String>::new());

        // Reading one event by its ID takes the customer scope too.
        let query = format!(
            "{{ event(id: \"{}\") {{ ... on DetectionEvent {{ time }} }} }}",
            f.first
        );
        let res = f
            .schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![1]))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{event: {{time: "{}"}}}}"#, at(0))
        );
        let res = f
            .schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![2]))
            .await;
        assert_eq!(res.data.to_string(), r"{event: null}");
    }
}
