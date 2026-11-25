//! Tests of the time-series type catalog as GraphQL reads it.

use async_graphql::{EmptyMutation, EmptySubscription, InputType, Request, Schema};
use review_database::Role;
use serde_json::{Value, json};

use super::*;
use crate::graphql::{
    RoleGuard, TestSchema,
    clustering_model_type::{ClusteringModelTypeQuery, TrainingValueType},
};

const TYPES: &str = "{
    timeSeriesTypes {
        id version order rawEventKind method measure groupBy groupByUnit
        counterpartScope slotSize windowSize threatRole
        fixedValues { key value }
        operatorValues { name valueType optional min max defaultValue }
        minWindowSeconds detectionModels descriptionEn descriptionKo
    }
}";

async fn query(text: &str) -> Value {
    let schema = Schema::build(ClusteringModelTypeQuery, EmptyMutation, EmptySubscription).finish();
    let res = schema
        .execute(Request::new(text).data(RoleGuard::Role(Role::SecurityMonitor)))
        .await;
    assert!(res.errors.is_empty(), "{:?}", res.errors);
    res.data.into_json().expect("JSON data")
}

fn enum_name<T: InputType>(value: &T) -> String {
    match value.to_value() {
        async_graphql::Value::Enum(name) => name.to_string(),
        other => panic!("not an enum: {other:?}"),
    }
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

#[tokio::test]
async fn every_time_series_type_equals_the_catalog() {
    let data = query(TYPES).await;
    let types = data["timeSeriesTypes"].as_array().unwrap();
    let catalog = database::time_series_types();
    assert_eq!(types.len(), 12);
    assert_eq!(types.len(), catalog.len());
    for (entry, t) in types.iter().zip(catalog) {
        assert_eq!(entry["id"], t.id);
        assert_eq!(entry["version"], t.version.to_string());
        assert_eq!(entry["order"], t.order.to_string());
        assert_eq!(
            entry["rawEventKind"],
            enum_name(&RawEventKind::from(t.raw_event_kind))
        );
        assert_eq!(entry["method"], enum_name(&ModelMethod::from(t.method)));
        assert_eq!(entry["measure"], enum_name(&Measure::from(t.measure)));
        assert_eq!(entry["groupBy"], enum_name(&EndpointRole::from(t.group_by)));
        assert_eq!(
            entry["groupByUnit"],
            enum_name(&GroupByUnit::from(t.group_by_unit))
        );
        assert_eq!(
            entry["counterpartScope"],
            enum_name(&CounterpartScope::from(t.counterpart_scope))
        );
        assert_eq!(entry["slotSize"], enum_name(&SlotSize::from(t.slot_size)));
        assert_eq!(
            entry["windowSize"],
            enum_name(&WindowSize::from(t.window_size))
        );
        assert_eq!(
            entry["threatRole"],
            enum_name(&ThreatRole::from(t.threat_role))
        );
        let detection_models: Vec<String> = t
            .detection_models
            .iter()
            .map(|m| enum_name(&DetectionModel::from(*m)))
            .collect();
        assert_eq!(entry["detectionModels"], json!(detection_models));
        assert_eq!(entry["descriptionEn"], t.description_en);
        assert_eq!(entry["descriptionKo"], t.description_ko);
        assert_eq!(
            entry["minWindowSeconds"],
            json!(min_window_seconds(t.id, t.operator_values).unwrap())
        );

        let fixed = entry["fixedValues"].as_array().unwrap();
        assert_eq!(fixed.len(), t.fixed.len(), "{}", t.id);
        for (entry, expected) in fixed.iter().zip(t.fixed) {
            assert_eq!(entry["key"], expected.key);
            assert_eq!(
                parse(entry["value"].as_str().unwrap()),
                toml_value(&expected.value),
                "{}",
                expected.key
            );
        }
        let values = entry["operatorValues"].as_array().unwrap();
        assert_eq!(values.len(), t.operator_values.len(), "{}", t.id);
        for (entry, expected) in values.iter().zip(t.operator_values) {
            assert_eq!(entry["name"], expected.name);
            assert_eq!(
                entry["valueType"],
                enum_name(&TrainingValueType::from(expected.value_type))
            );
            assert_eq!(entry["optional"], expected.optional);
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

#[tokio::test]
async fn server_daily_tls_and_a_hog_only_type_are_returned() {
    let data = query(TYPES).await;
    let types = data["timeSeriesTypes"].as_array().unwrap();
    let entry = |id: &str| {
        types
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap_or_else(|| panic!("{id} is listed"))
            .clone()
    };

    let tls = entry("server_daily_tls");
    assert_eq!(tls["version"], "1");
    assert_eq!(tls["rawEventKind"], "TLS");
    assert_eq!(tls["method"], "TIMESERIES");
    assert_eq!(tls["measure"], "COUNT");
    assert_eq!(tls["groupBy"], "DESTINATION");
    assert_eq!(tls["groupByUnit"], "IP");
    assert_eq!(tls["counterpartScope"], "ANY");
    assert_eq!(tls["slotSize"], "FIVE_MINUTES");
    assert_eq!(tls["windowSize"], "ONE_DAY");
    assert_eq!(tls["threatRole"], "TARGET");
    assert_eq!(tls["detectionModels"], json!(["WINDOW_OUTLIER"]));
    assert_ne!(tls["fixedValues"], json!([]));

    let rdp = entry("host_daily_rdp");
    assert_eq!(rdp["fixedValues"], json!([]));
    assert_eq!(rdp["operatorValues"], json!([]));
    assert_eq!(rdp["minWindowSeconds"], Value::Null);
}

#[tokio::test]
async fn time_series_types_take_the_catalog_roles() {
    const QUERY: &str = "{ timeSeriesTypes { id } }";
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
