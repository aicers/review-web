//! Tests of the clustering model type catalog, the training definition key
//! table and the custom defaults as GraphQL reads them.

use async_graphql::{
    EmptyMutation, EmptySubscription, InputType, Request, Schema, resolver_utils::EnumType,
};
use review_database::Role;
use serde_json::{Value, json};

use super::*;
use crate::graphql::TestSchema;

fn schema() -> Schema<ClusteringModelTypeQuery, EmptyMutation, EmptySubscription> {
    Schema::build(ClusteringModelTypeQuery, EmptyMutation, EmptySubscription).finish()
}

async fn query(text: &str) -> Value {
    let res = schema()
        .execute(Request::new(text).data(RoleGuard::Role(Role::SecurityMonitor)))
        .await;
    assert!(res.errors.is_empty(), "{:?}", res.errors);
    res.data.into_json().expect("JSON data")
}

/// Returns `value` as a TOML value, built without the resolver's writer.
fn toml_value(value: &database::DefinitionValue) -> toml::Value {
    match value {
        database::DefinitionValue::String(s) => toml::Value::String((*s).to_string()),
        database::DefinitionValue::Integer(i) => toml::Value::Integer(*i),
        database::DefinitionValue::Float(f) => toml::Value::Float(*f),
        database::DefinitionValue::IntegerList(items) => {
            toml::Value::Array(items.iter().map(|i| toml::Value::Integer(*i)).collect())
        }
        database::DefinitionValue::Table(fields) => toml_table(fields),
        database::DefinitionValue::TableList(tables) => {
            toml::Value::Array(tables.iter().map(|fields| toml_table(fields)).collect())
        }
    }
}

fn toml_table(fields: &[database::FixedValue]) -> toml::Value {
    toml::Value::Table(
        fields
            .iter()
            .map(|field| (field.key.to_string(), toml_value(&field.value)))
            .collect(),
    )
}

/// Parses `text`, the text of one TOML value.
fn parse(text: &str) -> toml::Value {
    let mut table: toml::Table =
        toml::from_str(&format!("v = {text}")).unwrap_or_else(|e| panic!("{text}: {e}"));
    table.remove("v").expect("the value")
}

/// Returns the keys of the inline table `text` at its top level, in order.
fn top_level_keys(text: &str) -> Vec<String> {
    let body = text
        .strip_prefix("{ ")
        .and_then(|t| t.strip_suffix(" }"))
        .expect("an inline table");
    let mut keys = Vec::new();
    let mut depth = 0_i32;
    let mut start = 0;
    for (i, c) in body.char_indices() {
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            '=' if depth == 0 => {
                keys.push(body[start..i].trim().trim_start_matches(", ").to_string());
            }
            ',' if depth == 0 => start = i,
            _ => {}
        }
    }
    keys
}

fn enum_name<T: InputType>(value: &T) -> String {
    match value.to_value() {
        async_graphql::Value::Enum(name) => name.to_string(),
        other => panic!("not an enum: {other:?}"),
    }
}

const TYPES: &str = "{
    clusteringModelTypes {
        id version order rawEventKind method approach
        fixedValues { key value }
        operatorValues { name valueType optional min max defaultValue }
        minWindowSeconds detectionModels descriptionEn descriptionKo
    }
}";

#[tokio::test]
async fn http_url_version_1_is_returned_with_every_field() {
    let data = query(TYPES).await;
    let types = data["clusteringModelTypes"].as_array().unwrap();
    assert_eq!(types.len(), database::clustering_model_types().len());
    let http_url = database::clustering_model_type("http_url").unwrap();
    let entry = types.first().unwrap();
    assert_eq!(entry["id"], "http_url");
    assert_eq!(entry["version"], "1");
    assert_eq!(entry["order"], "0");
    assert_eq!(entry["rawEventKind"], "HTTP");
    assert_eq!(entry["method"], "MULTIDIMENSION");
    assert_eq!(entry["approach"], "PREFIX");
    assert_eq!(entry["minWindowSeconds"], 604_800);
    assert_eq!(
        entry["detectionModels"],
        json!(["LABEL_DB_MATCH", "FAR_OUTLIER"])
    );
    assert_eq!(entry["descriptionEn"], http_url.description_en);
    assert_eq!(entry["descriptionKo"], http_url.description_ko);

    let fixed = entry["fixedValues"].as_array().unwrap();
    assert_eq!(fixed.len(), 10);
    let keys: Vec<&str> = fixed.iter().map(|f| f["key"].as_str().unwrap()).collect();
    assert_eq!(
        keys,
        [
            "raw_event_kind",
            "method",
            "csv",
            "numbers_of_top_n",
            "precision",
            "min_token_length",
            "max_data_len",
            "long_pattern_len",
            "algorithm",
            "eps",
        ]
    );
    for (entry, expected) in fixed.iter().zip(http_url.fixed) {
        let text = entry["value"].as_str().unwrap();
        assert_eq!(parse(text), toml_value(&expected.value), "{}", expected.key);
    }
    let value = |key: &str| {
        fixed
            .iter()
            .find(|f| f["key"] == key)
            .and_then(|f| f["value"].as_str())
            .unwrap()
            .to_string()
    };
    assert_eq!(value("raw_event_kind"), "\"http\"");
    assert_eq!(value("eps"), "5.0");
    assert_eq!(value("precision"), "2");
    // `csv` is one inline table whose keys keep the catalog's order.
    let csv = value("csv");
    assert_eq!(
        top_level_keys(&csv),
        [
            "reader",
            "format",
            "prefix_columns",
            "slot_sizes",
            "time_column",
            "count_columns",
        ]
    );
    assert!(
        csv.contains("{ name = \"uri\", data_type = \"utf8\", weight = 2147483647.0 }"),
        "{csv}"
    );

    assert_eq!(
        entry["operatorValues"],
        json!([
            { "name": "sources", "valueType": "STRING_LIST", "optional": false,
              "min": null, "max": null, "defaultValue": null },
            { "name": "window_start", "valueType": "TIMESTAMP", "optional": false,
              "min": null, "max": null, "defaultValue": null },
            { "name": "window_end", "valueType": "TIMESTAMP", "optional": false,
              "min": null, "max": null, "defaultValue": null },
            { "name": "batch_size", "valueType": "INTEGER", "optional": false,
              "min": "10000", "max": "1000000", "defaultValue": "1000000" },
            { "name": "max_event_id_num", "valueType": "INTEGER", "optional": false,
              "min": "1", "max": "100", "defaultValue": "50" },
            { "name": "suspicious_tokens", "valueType": "STRING", "optional": true,
              "min": null, "max": null, "defaultValue": null },
            { "name": "data_store", "valueType": "TABLE", "optional": false,
              "min": null, "max": null, "defaultValue": null },
        ])
    );
}

#[tokio::test]
async fn every_catalog_type_equals_the_catalog() {
    let data = query(TYPES).await;
    let types = data["clusteringModelTypes"].as_array().unwrap();
    for (entry, t) in types.iter().zip(database::clustering_model_types()) {
        assert_eq!(entry["id"], t.id);
        assert_eq!(entry["version"], t.version.to_string());
        assert_eq!(entry["order"], t.order.to_string());
        assert_eq!(
            entry["rawEventKind"],
            enum_name(&RawEventKind::from(t.raw_event_kind))
        );
        assert_eq!(entry["method"], enum_name(&ModelMethod::from(t.method)));
        assert_eq!(
            entry["approach"],
            enum_name(&ClusteringApproach::from(t.approach))
        );
        let detection_models: Vec<String> = t
            .detection_models
            .iter()
            .map(|m| enum_name(&DetectionModel::from(*m)))
            .collect();
        assert_eq!(entry["detectionModels"], json!(detection_models));
        let fixed = entry["fixedValues"].as_array().unwrap();
        assert_eq!(fixed.len(), t.fixed.len());
        for (entry, expected) in fixed.iter().zip(t.fixed) {
            assert_eq!(entry["key"], expected.key);
            assert_eq!(
                parse(entry["value"].as_str().unwrap()),
                toml_value(&expected.value)
            );
        }
        let values = entry["operatorValues"].as_array().unwrap();
        assert_eq!(values.len(), t.operator_values.len());
        for (entry, expected) in values.iter().zip(t.operator_values) {
            assert_eq!(entry["name"], expected.name);
            assert_eq!(
                entry["valueType"],
                enum_name(&TrainingValueType::from(expected.value_type))
            );
            assert_eq!(entry["optional"], expected.optional);
            if let Some(database::DefinitionValueRange::Integer { min, max }) = expected.range {
                assert_eq!(entry["min"], min.to_string());
                assert_eq!(entry["max"], max.to_string());
            } else {
                assert_eq!(entry["min"], Value::Null);
                assert_eq!(entry["max"], Value::Null);
            }
            match &expected.default {
                Some(default) => assert_eq!(
                    parse(entry["defaultValue"].as_str().unwrap()),
                    toml_value(default)
                ),
                None => assert_eq!(entry["defaultValue"], Value::Null),
            }
        }
    }
}

#[test]
fn every_value_type_and_key_status_maps() {
    use database::{DefinitionKeyStatus as Status, DefinitionValueType as Type};

    let cases = [
        (Type::String, "STRING"),
        (Type::Timestamp, "TIMESTAMP"),
        (Type::Integer, "INTEGER"),
        (Type::Float, "FLOAT"),
        (Type::StringList, "STRING_LIST"),
        (Type::IntegerList, "INTEGER_LIST"),
        (Type::Table, "TABLE"),
        (Type::TableList, "TABLE_LIST"),
    ];
    assert_eq!(cases.len(), TrainingValueType::items().len());
    for (value_type, name) in cases {
        assert_eq!(enum_name(&TrainingValueType::from(value_type)), name);
    }

    let cases = [
        (Status::Required, "REQUIRED"),
        (Status::AbsentMeans, "ABSENT_MEANS"),
        (Status::Rejected, "REJECTED"),
        (Status::RequiredForCatalogType, "CATALOG_TYPE_ONLY"),
    ];
    assert_eq!(cases.len(), TrainingKeyStatus::items().len());
    for (status, name) in cases {
        assert_eq!(enum_name(&TrainingKeyStatus::from(status)), name);
    }
}

#[test]
fn values_are_written_as_toml_that_parses_back() {
    const NESTED: &[database::FixedValue] = &[
        database::FixedValue {
            key: "z first",
            value: database::DefinitionValue::String("a \"quoted\" \\ text"),
        },
        database::FixedValue {
            key: "a_second",
            value: database::DefinitionValue::TableList(&[
                &[database::FixedValue {
                    key: "w",
                    value: database::DefinitionValue::Float(-0.5),
                }],
                &[],
            ]),
        },
        database::FixedValue {
            key: "list",
            value: database::DefinitionValue::IntegerList(&[]),
        },
    ];
    let value = database::DefinitionValue::Table(NESTED);
    let text = value_text(&value);
    assert_eq!(
        text,
        r#"{ "z first" = 'a "quoted" \ text', a_second = [{ w = -0.5 }, {}], list = [] }"#
    );
    assert_eq!(parse(&text), toml_value(&value));
    assert_eq!(value_text(&database::DefinitionValue::Float(2.0)), "2.0");
    assert_eq!(value_text(&database::DefinitionValue::Integer(-3)), "-3");
}

#[tokio::test]
async fn the_key_table_of_each_method_is_returned_in_order() {
    for (method, name) in [
        (database::ModelMethod::Multidimension, "MULTIDIMENSION"),
        (database::ModelMethod::Prefix, "PREFIX"),
        (database::ModelMethod::Timeseries, "TIMESERIES"),
    ] {
        let data = query(&format!(
            "{{ trainingDefinitionKeys(method: {name}) {{ key status description }} }}"
        ))
        .await;
        let expected: Vec<Value> = database::definition_keys(method)
            .iter()
            .map(|row| {
                json!({
                    "key": row.key,
                    "status": enum_name(&TrainingKeyStatus::from(row.status)),
                    "description": row.note,
                })
            })
            .collect();
        assert_eq!(data["trainingDefinitionKeys"], json!(expected), "{name}");
    }

    let data = query("{ trainingDefinitionKeys(method: PREFIX) { key status description } }").await;
    let rows = data["trainingDefinitionKeys"].as_array().unwrap();
    assert_eq!(
        rows.first().unwrap(),
        &json!({ "key": "type", "status": "REQUIRED", "description": null })
    );
    assert_eq!(
        rows.get(1).unwrap(),
        &json!({ "key": "type_version", "status": "CATALOG_TYPE_ONLY", "description": null })
    );
    assert!(
        rows.contains(&json!({ "key": "log_kind", "status": "REQUIRED", "description": null }))
    );
    assert!(rows.contains(&json!({
        "key": "max_token_length",
        "status": "ABSENT_MEANS",
        "description": "Absent means no limit.",
    })));
    let data = query("{ trainingDefinitionKeys(method: MULTIDIMENSION) { key status } }").await;
    assert!(
        data["trainingDefinitionKeys"]
            .as_array()
            .unwrap()
            .contains(&json!({ "key": "csv.format", "status": "REQUIRED" }))
    );
}

#[tokio::test]
async fn custom_defaults_are_returned_per_method_with_csv_only_for_a_multidimension_kind() {
    let http_url_csv = {
        let t = database::clustering_model_type("http_url").unwrap();
        toml_value(t.fixed_value("csv").unwrap())
    };
    for (method, name) in [
        (database::ModelMethod::Multidimension, "MULTIDIMENSION"),
        (database::ModelMethod::Prefix, "PREFIX"),
        (database::ModelMethod::Timeseries, "TIMESERIES"),
    ] {
        for kind in ["", "(rawEventKind: HTTP)", "(rawEventKind: CONN)"] {
            let arguments = if kind.is_empty() {
                format!("(method: {name})")
            } else {
                format!("(method: {name}, {})", &kind[1..kind.len() - 1])
            };
            let data = query(&format!(
                "{{ customTrainingDefaults{arguments} {{ key value }} }}"
            ))
            .await;
            let entries = data["customTrainingDefaults"].as_array().unwrap();
            let defaults = database::custom_defaults(method);
            let with_csv =
                method == database::ModelMethod::Multidimension && kind == "(rawEventKind: HTTP)";
            assert_eq!(
                entries.len(),
                defaults.len() + usize::from(with_csv),
                "{arguments}"
            );
            for (entry, expected) in entries.iter().zip(defaults) {
                assert_eq!(entry["key"], expected.key, "{arguments}");
                assert_eq!(
                    parse(entry["value"].as_str().unwrap()),
                    toml_value(&expected.value),
                    "{arguments}"
                );
            }
            if with_csv {
                let csv = entries.last().unwrap();
                assert_eq!(csv["key"], "csv");
                assert_eq!(parse(csv["value"].as_str().unwrap()), http_url_csv);
            } else {
                assert!(
                    entries.iter().all(|entry| entry["key"] != "csv"),
                    "{arguments}"
                );
            }
        }
    }

    let data = query("{ customTrainingDefaults(method: PREFIX) { key value } }").await;
    assert_eq!(
        data["customTrainingDefaults"],
        json!([
            { "key": "type", "value": "\"custom\"" },
            { "key": "batch_size", "value": "1000000" },
            { "key": "max_event_id_num", "value": "25" },
            { "key": "min_token_length", "value": "2" },
            { "key": "long_pattern_len", "value": "16000" },
        ])
    );
}

#[tokio::test]
async fn the_queries_take_the_training_definition_roles() {
    const QUERY: &str = "{
        clusteringModelTypes { id }
        trainingDefinitionKeys(method: PREFIX) { key }
        customTrainingDefaults(method: PREFIX) { key }
    }";
    let schema = TestSchema::new().await;
    for role in [
        Role::SystemAdministrator,
        Role::SecurityAdministrator,
        Role::SecurityManager,
        Role::SecurityMonitor,
    ] {
        let res = schema
            .execute_as_scoped_user(QUERY, role, Some(vec![7]))
            .await;
        assert!(res.errors.is_empty(), "{role:?}: {:?}", res.errors);
    }
    let res = schema.schema.execute(Request::new(QUERY)).await;
    assert_eq!(res.errors.first().unwrap().message, "Forbidden");
}

#[test]
fn training_read_times_keep_their_nanoseconds() {
    let at = timestamp(1_773_586_804_123_456_789).unwrap();
    assert_eq!(at.to_string(), "2026-03-15T15:00:04.123456789Z");
    let at = timestamp(i64::MIN).unwrap();
    assert_eq!(at.to_string(), "1677-09-21T00:12:43.145224192Z");
}
