use async_graphql::{Request, Variables};
use serde_json::{Value, json};

use crate::graphql::{Role, RoleGuard, TestSchema};

const RANGE_QUERY: &str = "{ topTimeSeriesOfCluster(model: 1, clusterId: 1) { earliest latest }
    timeRangeOfModel(model: 1) { lower upper } }";
const QUERIES: [(&str, &str, &str); 2] = [
    (
        "topTimeSeriesOfCluster(model: 1, clusterId: 1",
        "earliest latest series { columnIndex series { count } seriesTrend { count } }",
        "/result/series/0/series",
    ),
    (
        "topTimeSeries(model: 1, minSlope: -1000",
        "countIndex trends { clusterId series { count } trend lines { regOriginal { slope } } }",
        "/result/0/trends/0/series",
    ),
];

async fn data(schema: &TestSchema, query: &str) -> Value {
    let response = schema.execute_as_system_admin(query).await;
    assert!(response.errors.is_empty(), "{query}: {response:?}");
    response.data.into_json().unwrap()
}

fn insert(schema: &TestSchema, value: i64, batch: i64, count: usize) {
    schema
        .store()
        .time_series_map()
        .insert(&review_database::TimeSeries {
            model_id: 1,
            cluster_id: 1,
            time: batch,
            value,
            count_index: Some(0),
            count,
        })
        .unwrap();
}

async fn populated() -> TestSchema {
    populated_with_step(1_000_000_000).await
}

async fn populated_with_step(step: i64) -> TestSchema {
    let schema = TestSchema::new().await;
    for index in 0..100_i64 {
        let count = usize::try_from((20 - (index % 40).abs_diff(20)) * 100 + 100).unwrap();
        insert(&schema, index * step, 0, count);
    }
    schema
}

fn query(resolver: &str, selection: &str, bounds: &str) -> String {
    format!("{{ result: {resolver}, trendiOrder: 0{bounds}) {{ {selection} }} }}")
}

#[tokio::test]
async fn datetime_bounds_preserve_selection_counts_trends_and_offsets() {
    let schema = populated().await;
    for (resolver, selection, path) in QUERIES {
        let all = data(&schema, &query(resolver, selection, "")).await;
        assert_eq!(all.pointer(path).unwrap().as_array().unwrap().len(), 100);
        for (bounds, first, last) in [
            ("", 0, 99),
            (", start: null, end: null", 0, 99),
            (", start: null", 0, 99),
            (", end: null", 0, 99),
            (", start: \"1970-01-01T00:00:10Z\"", 10, 99),
            (", start: \"1970-01-01T00:00:10Z\", end: null", 10, 99),
            (", end: \"1970-01-01T00:01:29Z\"", 0, 89),
            (", start: null, end: \"1970-01-01T00:01:29Z\"", 0, 89),
            (
                ", start: \"1970-01-01T00:00:10Z\", end: \"1970-01-01T00:01:29Z\"",
                10,
                89,
            ),
        ] {
            let result = data(&schema, &query(resolver, selection, bounds)).await;
            let counts = result.pointer(path).unwrap().as_array().unwrap();
            let expected: Vec<_> = (first..=last)
                .map(|index: u32| json!({"count": (20 - (index % 40).abs_diff(20)) * 100 + 100}))
                .collect();
            assert_eq!(counts, &expected, "{resolver}: {bounds}");
            if resolver.starts_with("topTimeSeriesOfCluster") {
                assert_eq!(
                    result["result"]["series"][0]["seriesTrend"],
                    json!(expected)
                );
            } else {
                let expected_trend: Vec<_> = expected
                    .iter()
                    .map(|point| point["count"].as_u64().unwrap().to_string())
                    .collect();
                assert_eq!(
                    result["result"][0]["trends"][0]["trend"],
                    json!(expected_trend)
                );
            }
            if resolver.starts_with("topTimeSeriesOfCluster") {
                assert_eq!(result["result"]["earliest"], all["result"]["earliest"]);
                assert_eq!(result["result"]["latest"], all["result"]["latest"]);
            }
        }
        let utc = data(
            &schema,
            &query(
                resolver,
                selection,
                ", start: \"1970-01-01T00:00:10Z\", end: \"1970-01-01T00:01:29Z\"",
            ),
        )
        .await;
        let offset = data(
            &schema,
            &query(
                resolver,
                selection,
                ", start: \"1970-01-01T01:00:10+01:00\", end: \"1969-12-31T16:01:29-08:00\"",
            ),
        )
        .await;
        assert_eq!(utc, offset);
    }
}

#[tokio::test]
async fn datetime_bounds_filter_with_nanosecond_precision() {
    let schema = TestSchema::new().await;
    for (nanos, count) in [(0, 100), (1, 200), (2, 300)] {
        insert(&schema, nanos, 0, count);
    }
    let (resolver, selection, path) = QUERIES[0];
    for (bounds, expected) in [
        (", start: \"1970-01-01T00:00:00.000000002Z\"", 300),
        (", end: \"1970-01-01T00:00:00Z\"", 100),
        (
            ", start: \"1970-01-01T00:00:00.000000001Z\", end: \"1970-01-01T00:00:00.000000001Z\"",
            200,
        ),
    ] {
        let result = data(&schema, &query(resolver, selection, bounds)).await;
        assert_eq!(
            result.pointer(path).unwrap(),
            &json!([{"count": expected}]),
            "{bounds}"
        );
    }
}

#[tokio::test]
async fn datetime_ranges_round_trip_with_trends() {
    let schema = populated().await;
    let ranges = data(&schema, RANGE_QUERY).await;
    for ((resolver, selection, path), (object, lower, upper)) in QUERIES.into_iter().zip([
        ("topTimeSeriesOfCluster", "earliest", "latest"),
        ("timeRangeOfModel", "lower", "upper"),
    ]) {
        let bounds = format!(
            ", start: {}, end: {}",
            ranges[object][lower], ranges[object][upper]
        );
        let all = data(
            &schema,
            &query(resolver, selection, "").replace("trendiOrder: 0", "trendiOrder: 4"),
        )
        .await;
        let round_trip = data(
            &schema,
            &query(resolver, selection, &bounds).replace("trendiOrder: 0", "trendiOrder: 4"),
        )
        .await;
        assert_eq!(all, round_trip);
        assert_eq!(all.pointer(path).unwrap().as_array().unwrap().len(), 100);
        let trend_path = if object == "timeRangeOfModel" {
            "/result/0/trends/0/trend"
        } else {
            "/result/series/0/seriesTrend"
        };
        assert!(
            !all.pointer(trend_path)
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty(),
            "{all}"
        );
    }
}

#[tokio::test]
async fn datetime_range_outputs_are_exact_and_nullable() {
    let empty = TestSchema::new().await;
    assert_eq!(
        data(&empty, RANGE_QUERY).await,
        json!({
            "topTimeSeriesOfCluster": {"earliest": null, "latest": null},
            "timeRangeOfModel": {"lower": null, "upper": null},
        })
    );
    for (nanos, expected) in [
        (-1, "1969-12-31T23:59:59.999999999+00:00"),
        (1, "1970-01-01T00:00:00.000000001+00:00"),
        (i64::MIN, "1677-09-21T00:12:43.145224192+00:00"),
        (i64::MAX, "2262-04-11T23:47:16.854775807+00:00"),
    ] {
        let schema = TestSchema::new().await;
        insert(&schema, nanos, 0, 1);
        let query = RANGE_QUERY.replace(
            "clusterId: 1)",
            &format!("clusterId: 1, start: \"{expected}\", end: \"{expected}\")"),
        );
        let result = data(&schema, &query).await;
        for path in [
            "/topTimeSeriesOfCluster/earliest",
            "/topTimeSeriesOfCluster/latest",
            "/timeRangeOfModel/lower",
            "/timeRangeOfModel/upper",
        ] {
            assert_eq!(result.pointer(path).unwrap(), expected);
        }
    }
}

#[tokio::test]
async fn datetime_bounds_accept_i64_limits_and_reject_adjacent_instants() {
    let schema = TestSchema::new().await;
    for (resolver, selection, _) in QUERIES {
        let time_arguments = if resolver.starts_with("topTimeSeriesOfCluster") {
            vec![""]
        } else {
            vec!["", ", time: \"1970-01-01T00:00:00\""]
        };
        for time_argument in time_arguments {
            for bound in ["start", "end"] {
                for (instant, valid) in [
                    ("1677-09-21T00:12:43.145224192Z", true),
                    ("2262-04-11T23:47:16.854775807Z", true),
                    ("1677-09-21T00:12:43.145224191Z", false),
                    ("2262-04-11T23:47:16.854775808Z", false),
                ] {
                    let bounds = format!("{time_argument}, {bound}: \"{instant}\"");
                    let response = schema
                        .execute_as_system_admin(&query(resolver, selection, &bounds))
                        .await;
                    if valid {
                        assert!(response.errors.is_empty(), "{bounds}: {response:?}");
                    } else {
                        assert!(
                            response.errors.iter().any(|error| error
                                .message
                                .contains("out of range for i64 nanoseconds")),
                            "{bounds}: {response:?}"
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn datetime_bounds_do_not_filter_a_selected_batch() {
    let schema = populated().await;
    // A second batch has different values and counts, and must not be included.
    for index in 0..100_i64 {
        insert(&schema, index * 1_000_000_000, 1_000_000_000, 50_000);
    }
    let (resolver, selection, path) = QUERIES[1];
    let batch = ", time: \"1970-01-01T00:00:00\"";
    let selected = data(&schema, &query(resolver, selection, batch)).await;
    assert_eq!(
        selected.pointer(path).unwrap().as_array().unwrap().len(),
        100
    );
    for bounds in [
        ", start: \"2000-01-01T00:00:00Z\", end: \"2000-01-02T00:00:00Z\"",
        ", start: \"2262-04-11T23:47:16.854775807Z\"",
    ] {
        let result = data(
            &schema,
            &query(resolver, selection, &format!("{batch}{bounds}")),
        )
        .await;
        assert_eq!(result, selected);
    }
}

#[tokio::test]
async fn datetime_bounds_reject_integer_literals_and_variables() {
    let schema = TestSchema::new().await;
    for (resolver, selection, _) in QUERIES {
        for bound in ["start", "end"] {
            let response = schema
                .execute_as_system_admin(&query(resolver, selection, &format!(", {bound}: 0")))
                .await;
            assert!(!response.errors.is_empty(), "{response:?}");
            let query = format!(
                "query($bound: DateTime) {{ result: {resolver}, {bound}: $bound) {{ {selection} }} }}"
            );
            let request = Request::new(query).variables(Variables::from_json(json!({"bound": 0})));
            let request = schema.request_with_context(
                request,
                RoleGuard::Role(Role::SystemAdministrator),
                None,
            );
            let response = schema.schema.execute(request).await;
            assert!(!response.errors.is_empty(), "{response:?}");
        }
    }
}

#[tokio::test]
async fn datetime_schema_signatures() {
    let schema = TestSchema::new().await;
    let sdl = schema.schema.sdl();
    for name in ["topTimeSeries(", "topTimeSeriesOfCluster("] {
        let arguments = sdl.split_once(name).unwrap().1.split_once("): ").unwrap().0;
        assert!(arguments.contains("start: DateTime"), "{arguments}");
        assert!(arguments.contains("end: DateTime"), "{arguments}");
        if name == "topTimeSeries(" {
            assert!(arguments.contains("time: NaiveDateTime"));
        }
    }
    for (name, fields) in [
        ("TimeRange", ["lower", "upper"]),
        ("TimeSeriesResult", ["earliest", "latest"]),
    ] {
        let body = sdl
            .split_once(&format!("type {name} {{"))
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        for field in fields {
            assert!(body.contains(&format!("\n\t{field}: DateTime\n")), "{body}");
        }
    }
    let body = sdl
        .split_once("type TimeCount {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert!(body.contains("time: NaiveDateTime!"));
}

#[tokio::test]
async fn datetime_optional_bounds_keep_two_hour_windows() {
    let schema = populated_with_step(180_000_000_000).await;
    for (resolver, selection, path) in QUERIES {
        for (bounds, first, last) in [
            ("", 59, 99),
            (", start: null, end: null", 59, 99),
            (", start: null", 59, 99),
            (", end: null", 59, 99),
            (", start: \"1970-01-01T00:30:00Z\"", 10, 50),
            (", start: \"1970-01-01T00:30:00Z\", end: null", 10, 50),
            (", end: \"1970-01-01T04:27:00Z\"", 49, 89),
            (", start: null, end: \"1970-01-01T04:27:00Z\"", 49, 89),
        ] {
            let result = data(&schema, &query(resolver, selection, bounds)).await;
            let expected: Vec<_> = (first..=last)
                .map(|index: u32| json!({"count": (20 - (index % 40).abs_diff(20)) * 100 + 100}))
                .collect();
            assert_eq!(
                result
                    .pointer(path)
                    .unwrap_or_else(|| panic!("{resolver}: {bounds}: {result}")),
                &json!(expected),
                "{resolver}: {bounds}"
            );
        }
    }
}

#[tokio::test]
async fn datetime_ranges_describe_all_stored_data_in_their_scope() {
    let schema = TestSchema::new().await;
    insert(&schema, -1, 0, 1);
    insert(&schema, 1, 0, 1);
    {
        let store = schema.store();
        let map = store.time_series_map();
        for (model_id, cluster_id, value) in [(1, 2, 10), (2, 1, 100)] {
            map.insert(&review_database::TimeSeries {
                model_id,
                cluster_id,
                time: 0,
                value,
                count_index: Some(0),
                count: 1,
            })
            .unwrap();
        }
    }
    let query = RANGE_QUERY.replace(
        "clusterId: 1)",
        "clusterId: 1, start: \"2000-01-01T00:00:00Z\", end: \"2000-01-02T00:00:00Z\")",
    );
    let result = data(&schema, &query).await;
    assert_eq!(
        result,
        json!({
            "topTimeSeriesOfCluster": {
                "earliest": "1969-12-31T23:59:59.999999999+00:00",
                "latest": "1970-01-01T00:00:00.000000001+00:00",
            },
            "timeRangeOfModel": {
                "lower": "1969-12-31T23:59:59.999999999+00:00",
                "upper": "1970-01-01T00:00:00.000000010+00:00",
            },
        })
    );
}
