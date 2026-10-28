//! Customer-scope tests of the model-keyed reads and writes, and tests of the
//! model record and the previous training result they expose.

use chrono::{DateTime, Utc};
use review_database::{Cluster, ColumnStats, OutlierInfo, Store, types::ModelBatchInfo};
use serde_json::{Value, json};

use crate::graphql::model_test_support::{
    TEST_AGENT_KEY, TestModel, data, replace_model, single_error, test_instance,
};
use crate::graphql::{Role, TestSchema};

const CUSTOMER_A: u32 = 1;
const CUSTOMER_B: u32 = 2;
/// A model id no model has.
const MISSING_MODEL: u32 = 99;
/// The cluster every fixture model has.
const CLUSTER: u32 = 1;

/// The reads that take a model, as `(query, argument name, takes previous)`.
/// `{m}` stands for the model id and `{p}` for the `previous` argument.
const READS: [(&str, &str, bool); 16] = [
    ("clusters(model: {m}{p}) { totalCount }", "model", true),
    ("outliers(model: {m}{p}) { totalCount }", "model", true),
    (
        "rankedOutliers(modelId: {m}{p}) { totalCount }",
        "modelId",
        true,
    ),
    (
        "savedOutliers(modelId: {m}{p}) { totalCount }",
        "modelId",
        true,
    ),
    ("roundsByModel(model: {m}{p}) { totalCount }", "model", true),
    (
        "roundsByCluster(model: {m}, cluster: 1{p}) { totalCount }",
        "model",
        true,
    ),
    (
        "columnStatistics(model: {m}, cluster: 1, time: []{p})",
        "model",
        true,
    ),
    (
        "topIpAddressesOfCluster(model: {m}, clusterId: 1{p}) { columnIndex }",
        "model",
        true,
    ),
    ("topColumns(model: {m}) { columnIndex }", "model", false),
    ("topIpAddresses(model: {m}) { columnIndex }", "model", false),
    ("topTimeSeries(model: {m}) { countIndex }", "model", false),
    (
        "topTimeSeriesOfCluster(model: {m}, clusterId: 1) { earliest }",
        "model",
        false,
    ),
    ("topMultimaps(model: {m}) { nIndex }", "model", false),
    ("timeRangeOfModel(model: {m}) { lower }", "model", false),
    (
        "structuredColumnTypes(model: {m}) { columnIndex }",
        "model",
        false,
    ),
    ("csvColumnExtra(model: {m}) { id }", "model", false),
];

/// Returns the reads, each with and, where it takes one, without `previous:
/// true`, as `(query with {m}, argument name)`.
fn read_queries() -> Vec<(String, &'static str)> {
    let mut queries = Vec::new();
    for (query, field, takes_previous) in READS {
        queries.push((format!("{{ {} }}", query.replace("{p}", "")), field));
        if takes_previous {
            queries.push((
                format!("{{ {} }}", query.replace("{p}", ", previous: true")),
                field,
            ));
        }
    }
    queries
}

fn with_model(query: &str, model: u32) -> String {
    query.replace("{m}", &model.to_string())
}

fn cluster(model_id: u32, id: u32, size: i64, category_id: i32) -> Cluster {
    Cluster {
        model_id,
        id,
        category_id,
        detector_id: 1,
        event_ids: vec![1],
        sensors: vec!["sensor".to_string()],
        labels: None,
        qualifier_id: 1,
        status_id: 1,
        signature: String::new(),
        size,
        score: None,
        last_modification_time: None,
    }
}

fn outlier(model_id: u32, timestamp: i64, id: i64, is_saved: bool) -> OutlierInfo {
    OutlierInfo {
        model_id,
        timestamp,
        rank: id,
        id,
        sensor: "sensor".to_string(),
        distance: 1.0,
        is_saved,
    }
}

/// Returns the column statistics of an IP address column of `cluster_id`
/// whose top value is `address`.
fn ip_column_stats(model_id: u32, cluster_id: u32, batch_ts: i64, address: &str) -> ColumnStats {
    let element = json!({ "IpAddr": address });
    ColumnStats {
        model_id,
        cluster_id,
        batch_ts,
        column_index: 0,
        description: serde_json::from_value(json!({
            "count": 1, "mean": null, "s_deviation": null, "min": element, "max": element,
        }))
        .expect("valid description"),
        n_largest_count: serde_json::from_value(json!({
            "number_of_elements": 1,
            "top_n": [{ "value": element, "count": 3 }],
            "mode": element,
        }))
        .expect("valid n-largest count"),
    }
}

/// Stores one cluster, one saved and one unsaved outlier and one column
/// statistics row of `model_id` in the current tables.
fn put_rows(store: &Store, model_id: u32) {
    store
        .cluster_map()
        .put(&cluster(model_id, CLUSTER, 10, 1))
        .unwrap();
    store
        .outlier_map()
        .insert(&outlier(model_id, 1_000, 1, true))
        .unwrap();
    store
        .outlier_map()
        .insert(&outlier(model_id, 1_000, 2, false))
        .unwrap();
    store
        .column_stats_map()
        .put(&ip_column_stats(model_id, CLUSTER, 1_000, "10.0.0.1"))
        .unwrap();
}

/// Stores customer A's model `model-a` and customer B's model `model-b`, each
/// with current rows and a previous training result, and returns their ids.
async fn fixture() -> (TestSchema, u32, u32) {
    let schema = TestSchema::new().await;
    let (model_a, model_b) = {
        let store = schema.store();
        let mut ids = Vec::new();
        for (name, customer_id) in [("model-a", CUSTOMER_A), ("model-b", CUSTOMER_B)] {
            let id = replace_model(&store, name, customer_id);
            put_rows(&store, id);
            replace_model(&store, name, customer_id);
            put_rows(&store, id);
            ids.push(id);
        }
        (ids[0], ids[1])
    };
    (schema, model_a, model_b)
}

fn assert_forbidden(response: &async_graphql::Response, query: &str) {
    assert_eq!(single_error(response).0, "Forbidden", "{query}");
}

fn assert_ok(response: &async_graphql::Response, query: &str) {
    assert!(response.errors.is_empty(), "{query}: {response:?}");
}

fn assert_not_found(response: &async_graphql::Response, field: &str, value: &str, query: &str) {
    assert_eq!(
        single_error(response).1,
        json!({ "code": "NOT_FOUND", "field": field, "value": value }),
        "{query}"
    );
}

#[tokio::test]
async fn model_reads_are_limited_to_the_model_customer() {
    let (schema, model_a, model_b) = fixture().await;
    for (query, field) in read_queries() {
        for role in [Role::SecurityAdministrator, Role::SecurityMonitor] {
            let scoped = |model| {
                let query = with_model(&query, model);
                let schema = &schema;
                async move {
                    let response = schema
                        .execute_as_scoped_user(&query, role, Some(vec![CUSTOMER_B]))
                        .await;
                    (query, response)
                }
            };
            let (q, response) = scoped(model_a).await;
            assert_forbidden(&response, &q);
            let (q, response) = scoped(model_b).await;
            assert_ok(&response, &q);
        }
        for model in [model_a, model_b] {
            let q = with_model(&query, model);
            assert_ok(&schema.execute_as_system_admin(&q).await, &q);
        }
        let q = with_model(&query, MISSING_MODEL);
        let response = schema.execute_as_system_admin(&q).await;
        assert_not_found(&response, field, &MISSING_MODEL.to_string(), &q);
    }
}

#[tokio::test]
async fn model_fields_of_clusters_and_outliers_resolve_in_scope() {
    let (schema, _, model_b) = fixture().await;
    for previous in ["", ", previous: true"] {
        let query = format!(
            "{{ clusters(model: {model_b}{previous}) {{ nodes {{ model {{ name customerId }} }} }}
                outliers(model: {model_b}{previous}) {{ nodes {{ model {{ name }} }} }} }}"
        );
        let res = schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![CUSTOMER_B]))
            .await;
        assert_eq!(
            data(res),
            json!({
                "clusters": { "nodes": [{ "model": { "name": "model-b", "customerId": "2" } }] },
                "outliers": { "nodes": [{ "model": { "name": "model-b" } }] },
            })
        );
    }
}

/// Runs a write as a Security Administrator of customer B against a model of
/// A and of B, then as a System Administrator against both, each on a fresh
/// fixture, and against a missing model.
async fn check_write(query: impl Fn(&Store, u32) -> String, field: &str) {
    let (schema, model_a, model_b) = fixture().await;
    let q = query(&schema.store(), model_a);
    let res = schema
        .execute_as_scoped_user(&q, Role::SecurityAdministrator, Some(vec![CUSTOMER_B]))
        .await;
    assert_forbidden(&res, &q);
    let q = query(&schema.store(), model_b);
    let res = schema
        .execute_as_scoped_user(&q, Role::SecurityAdministrator, Some(vec![CUSTOMER_B]))
        .await;
    assert_ok(&res, &q);
    let q = query(&schema.store(), model_a);
    assert_ok(&schema.execute_as_system_admin(&q).await, &q);

    let (schema, _, model_b) = fixture().await;
    let q = query(&schema.store(), model_b);
    assert_ok(&schema.execute_as_system_admin(&q).await, &q);

    let q = query(&schema.store(), MISSING_MODEL);
    let res = schema.execute_as_system_admin(&q).await;
    assert_not_found(&res, field, &MISSING_MODEL.to_string(), &q);
}

#[tokio::test]
async fn update_cluster_is_limited_to_the_model_customer() {
    check_write(
        |_, model| {
            format!(r#"mutation {{ updateCluster(model: {model}, id: "1", category: "3") }}"#)
        },
        "model",
    )
    .await;
}

#[tokio::test]
async fn add_csv_column_extra_is_limited_to_the_model_customer() {
    check_write(
        |_, model| {
            format!(r#"mutation {{ addCsvColumnExtra(model: {model}, columnAlias: ["a"]) }}"#)
        },
        "model",
    )
    .await;
}

#[tokio::test]
async fn csv_column_extras_of_a_customer_being_deleted_cannot_change() {
    use crate::graphql::customer_deletion_guard::test_support::{
        assert_locked, put_completed_job, put_stopped_job,
    };

    let (schema, model_a, model_b) = fixture().await;
    let extra_a = schema
        .store()
        .csv_column_extra_map()
        .insert(model_a, None, None, None, None, None)
        .unwrap();
    let add = |model: u32| {
        format!(r#"mutation {{ addCsvColumnExtra(model: {model}, columnAlias: ["a"]) }}"#)
    };
    let update =
        |id: u32| format!(r#"mutation {{ updateCsvColumnExtra(id: "{id}", columnAlias: ["b"]) }}"#);
    put_stopped_job(&schema.store(), CUSTOMER_A, &[]);

    assert_locked(&schema.execute_as_system_admin(&add(model_a)).await);
    assert_locked(&schema.execute_as_system_admin(&update(extra_a)).await);
    let res = schema.execute_as_system_admin(&add(model_b)).await;
    assert_ok(&res, "add B");
    let extra_b = res.data.into_json().unwrap()["addCsvColumnExtra"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_ok(
        &schema.execute_as_system_admin(&update(extra_b)).await,
        "update B",
    );

    put_completed_job(&schema.store(), CUSTOMER_A, &[]);
    assert_ok(
        &schema.execute_as_system_admin(&update(extra_a)).await,
        "update A",
    );
}

#[tokio::test]
async fn update_csv_column_extra_follows_the_model_of_the_stored_extra() {
    let (schema, model_a, model_b) = fixture().await;
    let (extra_a, extra_b, orphan) = {
        let store = schema.store();
        let map = store.csv_column_extra_map();
        let extra = |model| map.insert(model, None, None, None, None, None).unwrap();
        (extra(model_a), extra(model_b), extra(MISSING_MODEL))
    };
    let query =
        |id: u32| format!(r#"mutation {{ updateCsvColumnExtra(id: "{id}", columnAlias: ["b"]) }}"#);

    let res = schema
        .execute_as_scoped_user(
            &query(extra_a),
            Role::SecurityAdministrator,
            Some(vec![CUSTOMER_B]),
        )
        .await;
    assert_forbidden(&res, "extra of A");
    let res = schema
        .execute_as_scoped_user(
            &query(extra_b),
            Role::SecurityAdministrator,
            Some(vec![CUSTOMER_B]),
        )
        .await;
    assert_ok(&res, "extra of B");
    for id in [extra_a, extra_b] {
        assert_ok(&schema.execute_as_system_admin(&query(id)).await, "admin");
    }
    let alias = |model| {
        schema
            .store()
            .csv_column_extra_map()
            .get_by_model(model)
            .unwrap()
            .unwrap()
            .column_alias
    };
    assert_eq!(alias(model_a), Some(vec!["b".to_string()]));
    assert_eq!(alias(model_b), Some(vec!["b".to_string()]));

    let res = schema.execute_as_system_admin(&query(orphan)).await;
    assert_not_found(&res, "id", &orphan.to_string(), "orphan");
}

fn preserve_input(model: u32, id: i64) -> String {
    format!(r#"{{ id: {id}, modelId: {model}, timestamp: 1000, rank: {id}, sensor: "sensor" }}"#)
}

fn is_saved(store: &Store, model: u32, id: i64) -> bool {
    store
        .outlier_map()
        .get(
            model,
            Some(1_000),
            review_database::event::Direction::Forward,
            None,
        )
        .map(Result::unwrap)
        .find(|outlier| outlier.id == id)
        .unwrap()
        .is_saved
}

#[tokio::test]
async fn preserve_outliers_is_scoped_by_every_input() {
    let (schema, model_a, model_b) = fixture().await;
    let preserve = |inputs: &[String]| {
        format!(
            "mutation {{ preserveOutliers(input: [{}]) {{ id modelId }} }}",
            inputs.join(", ")
        )
    };

    let mixed = preserve(&[preserve_input(model_b, 2), preserve_input(model_a, 2)]);
    let res = schema
        .execute_as_scoped_user(&mixed, Role::SecurityAdministrator, Some(vec![CUSTOMER_B]))
        .await;
    assert_forbidden(&res, &mixed);
    assert!(!is_saved(&schema.store(), model_b, 2));
    let res = schema
        .execute_as_scoped_user(&mixed, Role::SecurityMonitor, Some(vec![CUSTOMER_B]))
        .await;
    assert_forbidden(&res, "monitor");

    let own = preserve(&[preserve_input(model_b, 1), preserve_input(model_b, 2)]);
    let res = schema
        .execute_as_scoped_user(&own, Role::SecurityAdministrator, Some(vec![CUSTOMER_B]))
        .await;
    assert_eq!(
        data(res),
        json!({ "preserveOutliers": [{ "id": "1", "modelId": model_b.to_string() }] })
    );
    assert!(is_saved(&schema.store(), model_b, 2));

    let res = schema.execute_as_system_admin(&mixed).await;
    assert_ok(&res, "admin");
    assert!(is_saved(&schema.store(), model_a, 2));

    let missing = preserve(&[preserve_input(model_a, 1), preserve_input(MISSING_MODEL, 1)]);
    let res = schema.execute_as_system_admin(&missing).await;
    assert_not_found(
        &res,
        "input[1].modelId",
        &MISSING_MODEL.to_string(),
        &missing,
    );
}

fn names(response: &Value) -> Vec<String> {
    response["models"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge| edge["node"]["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn models_pages_hold_only_the_caller_models() {
    let schema = TestSchema::new().await;
    {
        let store = schema.store();
        for i in 0..10 {
            let customer_id = if i % 2 == 0 { CUSTOMER_A } else { CUSTOMER_B };
            replace_model(&store, &format!("m{i:02}"), customer_id);
        }
    }
    let page = |arguments: &str| {
        format!(
            "{{ models({arguments}) {{ totalCount edges {{ cursor node {{ name }} }}
                pageInfo {{ hasNextPage hasPreviousPage startCursor endCursor }} }} }}"
        )
    };
    let scoped = |query: String| {
        let schema = &schema;
        async move {
            data(
                schema
                    .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![CUSTOMER_A]))
                    .await,
            )
        }
    };
    let own = ["m00", "m02", "m04", "m06", "m08"];

    let mut forward = Vec::new();
    let mut arguments = "first: 2".to_string();
    loop {
        let res = scoped(page(&arguments)).await;
        assert_eq!(res["models"]["totalCount"], "5");
        let page_names = names(&res);
        let has_next = res["models"]["pageInfo"]["hasNextPage"].as_bool().unwrap();
        forward.extend(page_names.clone());
        if !has_next {
            assert_eq!(page_names.len(), 1);
            break;
        }
        assert_eq!(page_names.len(), 2);
        let cursor = res["models"]["pageInfo"]["endCursor"].as_str().unwrap();
        arguments = format!("first: 2, after: \"{cursor}\"");
    }
    assert_eq!(forward, own);

    let mut backward = Vec::new();
    let mut arguments = "last: 2".to_string();
    loop {
        let res = scoped(page(&arguments)).await;
        assert_eq!(res["models"]["totalCount"], "5");
        let mut page_names = names(&res);
        let has_previous = res["models"]["pageInfo"]["hasPreviousPage"]
            .as_bool()
            .unwrap();
        let mut sorted = page_names.clone();
        sorted.sort_unstable();
        assert_eq!(page_names, sorted, "a page is in ascending order");
        page_names.reverse();
        backward.extend(page_names);
        if !has_previous {
            break;
        }
        let cursor = res["models"]["pageInfo"]["startCursor"].as_str().unwrap();
        arguments = format!("last: 2, before: \"{cursor}\"");
    }
    backward.reverse();
    assert_eq!(backward, own);

    let res = data(schema.execute_as_system_admin(&page("first: 100")).await);
    assert_eq!(res["models"]["totalCount"], "10");
    assert_eq!(names(&res).len(), 10);
    let res = data(
        schema
            .execute_as_scoped_user(&page("first: 100"), Role::SecurityMonitor, Some(vec![]))
            .await,
    );
    assert_eq!(res["models"]["totalCount"], "0");
    assert_eq!(names(&res), Vec::<String>::new());
}

#[tokio::test]
async fn model_digest_returns_the_record() {
    let schema = TestSchema::new().await;
    let trained_at: DateTime<Utc> = "2026-01-02T03:04:05Z".parse().unwrap();
    let retrained_at: DateTime<Utc> = "2026-02-03T04:05:06Z".parse().unwrap();
    let detached = review_database::ModelInstance {
        node_id: 50,
        agent_key: TEST_AGENT_KEY.to_string(),
    };
    {
        let store = schema.store();
        let id = TestModel {
            trained_at,
            ..TestModel::new("multi", CUSTOMER_A)
        }
        .replace(&store);
        store.cluster_map().put(&cluster(id, 1, 5, 1)).unwrap();
        store.cluster_map().put(&cluster(id, 2, 4, 1)).unwrap();
        for i in 0..3 {
            store
                .outlier_map()
                .insert(&outlier(id, 1_000 + i, i, false))
                .unwrap();
        }
        TestModel {
            version: 2,
            trained_at: retrained_at,
            ..TestModel::new("multi", CUSTOMER_A)
        }
        .replace(&store);
        TestModel {
            kind: "Prefix",
            ..TestModel::new("prefix", CUSTOMER_B)
        }
        .replace(&store);
        TestModel {
            kind: "Timeseries",
            instance: detached.clone(),
            ..TestModel::new("timeseries", CUSTOMER_B)
        }
        .replace(&store);
        store
            .detach_engine_instance(&detached, "removed")
            .expect("detach instance");
    }
    let res = schema
        .execute_as_system_admin(
            "{ models { nodes { name method eventKind customerId trainedAt
                instance { nodeId agentKey }
                previousTrainingResult { trainedAt version clusterCount outlierCount } } } }",
        )
        .await;
    assert!(res.errors.is_empty(), "{res:?}");
    let instance_a = test_instance(CUSTOMER_A);
    let instance_b = test_instance(CUSTOMER_B);
    assert_eq!(
        res.data.into_json().unwrap()["models"]["nodes"],
        json!([
            {
                "name": "multi",
                "method": "MULTIDIMENSION",
                "eventKind": "http",
                "customerId": "1",
                "trainedAt": retrained_at.to_rfc3339(),
                "instance": {
                    "nodeId": instance_a.node_id.to_string(),
                    "agentKey": instance_a.agent_key,
                },
                "previousTrainingResult": {
                    "trainedAt": trained_at.to_rfc3339(),
                    "version": 1,
                    "clusterCount": "2",
                    "outlierCount": "3",
                },
            },
            {
                "name": "prefix",
                "method": "PREFIX",
                "eventKind": "http",
                "customerId": "2",
                "trainedAt": res_time(&schema, "prefix"),
                "instance": {
                    "nodeId": instance_b.node_id.to_string(),
                    "agentKey": instance_b.agent_key,
                },
                "previousTrainingResult": null,
            },
            {
                "name": "timeseries",
                "method": "TIMESERIES",
                "eventKind": "http",
                "customerId": "2",
                "trainedAt": res_time(&schema, "timeseries"),
                "instance": null,
                "previousTrainingResult": null,
            },
        ])
    );
}

/// Returns the training time of the model `name` as `trainedAt` renders it.
fn res_time(schema: &TestSchema, name: &str) -> String {
    schema
        .store()
        .model_map()
        .load_model_by_name(name)
        .unwrap()
        .trained_at
        .to_rfc3339()
}

fn put_batch_info(store: &Store, model: u32, id: i64) {
    store
        .batch_info_map()
        .put(&review_database::BatchInfo::new(
            model,
            ModelBatchInfo {
                id,
                earliest: id,
                latest: id + 1,
                size: 1,
                sensors: vec!["sensor".to_string()],
            },
        ))
        .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn previous_reads_return_the_previous_rows() {
    let schema = TestSchema::new().await;
    let (model, fresh) = {
        let store = schema.store();
        let model = TestModel {
            rounds: &[100, 200],
            ..TestModel::new("model", CUSTOMER_A)
        }
        .replace(&store);
        // The previous result: two clusters, two outlier rounds with three
        // outliers (one saved), and column statistics of cluster 1 in two
        // rounds.
        store.cluster_map().put(&cluster(model, 1, 10, 1)).unwrap();
        store.cluster_map().put(&cluster(model, 2, 5, 1)).unwrap();
        for (timestamp, id, saved) in [(100, 1, true), (100, 2, false), (200, 3, false)] {
            store
                .outlier_map()
                .insert(&outlier(model, timestamp, id, saved))
                .unwrap();
        }
        for batch_ts in [100, 200] {
            store
                .column_stats_map()
                .put(&ip_column_stats(model, 1, batch_ts, "10.0.0.1"))
                .unwrap();
        }
        TestModel {
            rounds: &[300],
            ..TestModel::new("model", CUSTOMER_A)
        }
        .replace(&store);
        // The current result: three clusters, one outlier round with two
        // saved outliers, and column statistics of cluster 1 in one round.
        for id in 1..=3 {
            store.cluster_map().put(&cluster(model, id, 7, 1)).unwrap();
        }
        for id in [9, 10] {
            store
                .outlier_map()
                .insert(&outlier(model, 300, id, true))
                .unwrap();
        }
        store
            .column_stats_map()
            .put(&ip_column_stats(model, 1, 300, "10.0.0.2"))
            .unwrap();
        put_batch_info(&store, model, 400);
        let fresh = replace_model(&store, "fresh", CUSTOMER_A);
        store.cluster_map().put(&cluster(fresh, 1, 7, 1)).unwrap();
        (model, fresh)
    };

    let counts = |model: u32, previous: &str| {
        format!(
            "{{ clusters(model: {model}{previous}) {{ totalCount }}
                outliers(model: {model}{previous}) {{ totalCount }}
                rankedOutliers(modelId: {model}{previous}) {{ totalCount }}
                savedOutliers(modelId: {model}{previous}) {{ totalCount }}
                roundsByModel(model: {model}{previous}) {{ totalCount nodes {{ firstEventId }} }}
                roundsByCluster(model: {model}, cluster: 1{previous}) {{ totalCount }}
                topIpAddressesOfCluster(model: {model}, clusterId: 1{previous}) {{
                    counts {{ value }} }}
                columnStatistics(model: {model}, cluster: 1, time: []{previous}) }}"
        )
    };
    let current = data(schema.execute_as_system_admin(&counts(model, "")).await);
    let previous = data(
        schema
            .execute_as_system_admin(&counts(model, ", previous: true"))
            .await,
    );
    for (field, current_count, previous_count) in [
        ("clusters", "3", "2"),
        ("outliers", "1", "2"),
        ("rankedOutliers", "2", "3"),
        ("savedOutliers", "2", "1"),
        ("roundsByModel", "2", "2"),
        ("roundsByCluster", "1", "2"),
    ] {
        assert_eq!(current[field]["totalCount"], current_count, "{field}");
        assert_eq!(previous[field]["totalCount"], previous_count, "{field}");
    }
    assert_eq!(
        current["roundsByModel"]["nodes"],
        json!([{ "firstEventId": "300" }, { "firstEventId": "400" }])
    );
    assert_eq!(
        previous["roundsByModel"]["nodes"],
        json!([{ "firstEventId": "100" }, { "firstEventId": "200" }])
    );
    assert_eq!(
        current["topIpAddressesOfCluster"],
        json!([{ "counts": [{ "value": "10.0.0.2" }] }])
    );
    assert_eq!(
        previous["topIpAddressesOfCluster"],
        json!([{ "counts": [{ "value": "10.0.0.1" }] }])
    );
    assert_eq!(current["columnStatistics"].as_array().unwrap().len(), 1);
    assert_eq!(previous["columnStatistics"].as_array().unwrap().len(), 2);
    assert_ne!(current["columnStatistics"], previous["columnStatistics"]);

    let empty = data(
        schema
            .execute_as_system_admin(&counts(fresh, ", previous: true"))
            .await,
    );
    for field in [
        "clusters",
        "outliers",
        "rankedOutliers",
        "savedOutliers",
        "roundsByModel",
        "roundsByCluster",
    ] {
        assert_eq!(empty[field]["totalCount"], "0", "{field}");
    }
    assert_eq!(empty["topIpAddressesOfCluster"], json!([]));
    assert_eq!(empty["columnStatistics"], json!([]));
}
