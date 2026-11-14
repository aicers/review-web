use serde_json::{Value, json};

use crate::graphql::TestSchema;
use crate::graphql::model_test_support::schema_with_models_through;

const HOUR: i64 = 3_600_000_000_000;
// 2024-01-01T00:00:00Z
const BASE: i64 = 1_704_067_200_000_000_000;
const I64_MIN: &str = "1677-09-21T00:12:43.145224192Z";
const I64_MAX: &str = "2262-04-11T23:47:16.854775807Z";
const BUDGET_EXCEEDED: &str = "response budget exceeded";

fn insert(
    schema: &TestSchema,
    cluster_id: u32,
    count_index: Option<i32>,
    value: i64,
    count: usize,
) {
    schema
        .store()
        .time_series_map()
        .insert(&review_database::TimeSeries {
            model_id: 1,
            cluster_id,
            time: 0,
            value,
            count_index,
            count,
        })
        .unwrap();
}

/// Returns a schema whose cluster 1 holds `T`, `T + 1h`, `T + 3h` and `T + 6h`
/// with counts 10, 20, 30 and 40, and whose cluster 2 holds `T + 10h`.
async fn populated() -> TestSchema {
    let schema = schema_with_models_through(1).await;
    for (hours, count) in [(0, 10), (1, 20), (3, 30), (6, 40)] {
        insert(&schema, 1, Some(0), BASE + hours * HOUR, count);
    }
    insert(&schema, 2, Some(0), BASE + 10 * HOUR, 50);
    schema
}

async fn data(schema: &TestSchema, query: &str) -> Value {
    let response = schema.execute_as_system_admin(query).await;
    assert!(response.errors.is_empty(), "{query}: {response:?}");
    response.data.into_json().unwrap()
}

async fn error(schema: &TestSchema, query: &str) -> String {
    let response = schema.execute_as_system_admin(query).await;
    assert_eq!(response.errors.len(), 1, "{query}: {response:?}");
    assert_eq!(response.data, async_graphql::Value::Null, "{response:?}");
    response.errors[0].message.clone()
}

fn cluster_query(cluster_id: u32, bounds: &str, selection: &str) -> String {
    format!(
        "{{ topTimeSeriesOfCluster(model: 1, clusterId: {cluster_id}{bounds}) {{ {selection} }} }}"
    )
}

fn budget_message(sum: u128) -> String {
    format!(
        "{BUDGET_EXCEEDED}: series length sum {sum}, limit 100000; narrow the query period using start and end"
    )
}

#[tokio::test]
async fn unbounded_query_uses_the_latest_value_of_the_cluster() {
    let schema = populated().await;
    let result = data(
        &schema,
        &cluster_query(1, "", "series { series { time count } }"),
    )
    .await;
    assert_eq!(
        result["topTimeSeriesOfCluster"]["series"],
        json!([{"series": [{"time": "2024-01-01T06:00:00", "count": 40}]}])
    );
}

#[tokio::test]
async fn unbounded_query_of_an_empty_cluster_is_empty() {
    let schema = populated().await;
    let result = data(
        &schema,
        &cluster_query(3, "", "earliest latest series { series { count } }"),
    )
    .await;
    assert_eq!(
        result["topTimeSeriesOfCluster"],
        json!({"earliest": null, "latest": null, "series": []})
    );
}

#[tokio::test]
async fn single_bound_and_latest_windows_saturate_at_i64_limits() {
    let schema = schema_with_models_through(1).await;
    insert(&schema, 1, Some(0), i64::MAX, 1);
    insert(&schema, 2, Some(0), i64::MIN, 2);
    insert(&schema, 3, Some(0), i64::MIN, 3);
    insert(&schema, 3, Some(0), i64::MIN + HOUR, 4);
    for (cluster_id, bounds, expected) in [
        (
            1,
            ", start: \"2262-04-11T22:47:16.854775807Z\"",
            json!([{"count": 1}]),
        ),
        (
            2,
            ", end: \"1677-09-21T01:12:43.145224192Z\"",
            json!([{"count": 2}]),
        ),
        (2, "", json!([{"count": 2}])),
        // The minimum interval is an hour, so the hour is not filled.
        (3, "", json!([{"count": 3}, {"count": 4}])),
    ] {
        let result = data(
            &schema,
            &cluster_query(cluster_id, bounds, "series { series { count } }"),
        )
        .await;
        assert_eq!(
            result["topTimeSeriesOfCluster"]["series"][0]["series"], expected,
            "{cluster_id}{bounds}"
        );
    }
}

#[tokio::test]
async fn cluster_series_and_trend_share_zero_filled_slots() {
    let schema = populated().await;
    let start = "2024-01-01T00:00:00Z";
    let end = "2024-01-01T06:00:00Z";
    let result = data(
        &schema,
        &cluster_query(
            1,
            &format!(", start: \"{start}\", end: \"{end}\", trendiOrder: 0, cutoffRate: 1"),
            "series { columnIndex series { time count } seriesTrend { time count } }",
        ),
    )
    .await;
    let expected: Vec<_> = [10, 20, 0, 30, 0, 0, 40]
        .into_iter()
        .enumerate()
        .map(|(hour, count)| json!({"time": format!("2024-01-01T0{hour}:00:00"), "count": count}))
        .collect();
    let column = &result["topTimeSeriesOfCluster"]["series"][0];
    assert_eq!(column["columnIndex"], "0");
    assert_eq!(column["series"], json!(expected));
    assert_eq!(column["seriesTrend"], json!(expected));
}

#[tokio::test]
async fn cluster_response_budget_limits_the_filled_length_sum() {
    let schema = schema_with_models_through(1).await;
    // Cluster 1 fills to exactly 100,000 points, and cluster 2 to 100,001.
    for (cluster_id, end) in [(1, 99_999), (2, 100_000)] {
        for value in [0, 1, end] {
            insert(&schema, cluster_id, Some(0), value, 1);
        }
    }
    // Cluster 3 has two columns of 60,000 points each.
    for index in [0, 1] {
        for value in [0, 1, 59_999] {
            insert(&schema, 3, Some(index), value, 1);
        }
    }
    // Cluster 4 would fill to more points than memory can hold.
    for value in [0, 1, 1_000_000_000_000_000_000] {
        insert(&schema, 4, Some(0), value, 1);
    }
    let bounds = ", start: \"1970-01-01T00:00:00Z\", end: \"2001-09-09T01:46:40Z\"";

    let result = data(
        &schema,
        &cluster_query(1, bounds, "series { series { count } }"),
    )
    .await;
    let series = result["topTimeSeriesOfCluster"]["series"][0]["series"]
        .as_array()
        .unwrap();
    assert_eq!(series.len(), 100_000);

    for selection in ["series { seriesTrend { count } }", "earliest latest"] {
        assert_eq!(
            error(&schema, &cluster_query(2, bounds, selection)).await,
            budget_message(100_001),
            "{selection}"
        );
    }
    assert_eq!(
        error(&schema, &cluster_query(3, bounds, "earliest")).await,
        budget_message(120_000)
    );
    assert_eq!(
        error(&schema, &cluster_query(4, bounds, "earliest")).await,
        budget_message(1_000_000_000_000_000_001)
    );
}

#[tokio::test]
async fn cluster_zero_filling_errors_name_the_column() {
    let schema = schema_with_models_through(1).await;
    for value in [i64::MIN, 0, i64::MAX] {
        insert(&schema, 1, Some(7), value, 1);
    }
    // Two points need no filling, but their interval still has to fit in i64.
    for value in [i64::MIN, i64::MAX] {
        insert(&schema, 2, None, value, 1);
    }
    let bounds = format!(", start: \"{I64_MIN}\", end: \"{I64_MAX}\"");
    for (cluster_id, prefix) in [
        (1, "cannot zero-fill column 7: "),
        (2, "cannot zero-fill column 100000: "),
    ] {
        for selection in ["series { series { count } }", "earliest"] {
            let message = error(&schema, &cluster_query(cluster_id, &bounds, selection)).await;
            assert!(message.starts_with(prefix), "{message}");
            assert!(!message.contains(BUDGET_EXCEEDED), "{message}");
        }
    }
}
