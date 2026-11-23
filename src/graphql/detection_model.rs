//! The static properties of the detection models.
//!
//! Every value here comes from the table review-database keeps in code,
//! [`database::properties`]; nothing is read from the store.

use async_graphql::{Enum, Object, SimpleObject, resolver_utils::EnumType};
use review_database::{self as database};
use review_protocol::types as protocol;

use super::{
    Role, RoleGuard,
    event::ThreatRole,
    filter::{DetectionModel, LearningMethod, RawEventKind},
    triage::ThreatCategory,
};

#[derive(Default)]
pub(super) struct DetectionModelQuery;

#[Object]
impl DetectionModelQuery {
    /// The static properties of every detection model, one entry per model
    /// in model number order.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn detection_model_properties(&self) -> Vec<DetectionModelProperties> {
        all_models()
            .into_iter()
            .map(DetectionModelProperties::new)
            .collect()
    }
}

/// Returns every detection model, in model number order.
///
/// The GraphQL enum binds the protocol enum as a remote enum, so it lists
/// every model the protocol has.
fn all_models() -> Vec<protocol::DetectionModel> {
    let mut models: Vec<protocol::DetectionModel> = DetectionModel::items()
        .iter()
        .map(|item| item.value.into())
        .collect();
    models.sort_unstable_by_key(|model| u32::from(*model));
    models
}

/// The detection technique a model belongs to.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::DetectionFamily")]
pub(super) enum DetectionFamily {
    /// Matches traffic against a list of known threats.
    KnownThreat,
    /// Applies a classifier trained before deployment.
    PretrainedClassifier,
    /// Counts a behavior and reports when the count reaches a threshold.
    BehaviorThreshold,
    /// Reports traffic that breaks a policy.
    PolicyViolation,
    /// Measures how random a name is.
    Randomness,
    /// Reports a deviation from a learned baseline.
    BaselineDeviation,
    /// Reports what clustering finds anomalous.
    ClusteringAnomaly,
}

/// A detection model and its row of the property table.
pub(super) struct DetectionModelProperties {
    model: protocol::DetectionModel,
    properties: &'static database::DetectionModelProperties,
}

impl DetectionModelProperties {
    fn new(model: protocol::DetectionModel) -> Self {
        Self {
            model,
            properties: database::properties(model),
        }
    }
}

/// The static properties of a detection model, shared by every detection
/// event it reports.
#[Object]
impl DetectionModelProperties {
    /// The detection model these properties describe.
    async fn detection_model(&self) -> DetectionModel {
        self.model.into()
    }

    /// The detection technique.
    async fn family(&self) -> DetectionFamily {
        self.properties.family.into()
    }

    /// The MITRE tactics of the model; empty when no tactic applies.
    async fn categories(&self) -> Vec<ThreatCategory> {
        self.properties
            .categories
            .iter()
            .map(|category| (*category).into())
            .collect()
    }

    /// The engine that runs the model.
    async fn learning_method(&self) -> LearningMethod {
        self.properties.learning_method.into()
    }

    /// The kinds of the raw events the model can report.
    async fn raw_event_kinds(&self) -> Vec<RawEventKind> {
        self.properties
            .raw_event_kinds
            .iter()
            .map(|kind| (*kind).into())
            .collect()
    }

    /// What the model's detection events are about.
    async fn primary_subject(&self) -> DetectionModelSubject {
        self.properties.primary_subject.into()
    }

    /// What the score measures, in one line. A higher score always means more
    /// suspicious.
    async fn score_meaning(&self) -> &'static str {
        self.properties.score_meaning
    }

    /// Whether the model needs device and account identification.
    async fn requires_device_account_identification(&self) -> bool {
        self.properties.requires_device_account_identification
    }

    /// The values an operator may set for the model in its section of an
    /// engine configuration document, in the order completion adds them.
    async fn operator_values(&self) -> Vec<OperatorValue> {
        self.properties
            .operator_values
            .iter()
            .map(OperatorValue::from)
            .collect()
    }
}

/// The kind of the primary subject a model's detection events are about.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(super) enum DetectionModelSubjectKind {
    /// No primary subject: the detection is about a raw event.
    RawEvent,
    /// A host.
    Host,
    /// A cluster.
    Cluster,
    /// A sensor.
    Sensor,
    /// A network.
    Network,
}

/// The primary subject a model's detection events are about.
#[derive(Clone, Copy, Debug, Eq, PartialEq, SimpleObject)]
pub(super) struct DetectionModelSubject {
    /// The kind of the subject.
    kind: DetectionModelSubjectKind,
    /// Where the subject's threat role comes from; non-null exactly for
    /// `HOST` and `NETWORK`.
    role_source: Option<ThreatRoleSource>,
}

impl From<database::PrimarySubjectKind> for DetectionModelSubject {
    fn from(subject: database::PrimarySubjectKind) -> Self {
        let (kind, role_source) = match subject {
            database::PrimarySubjectKind::RawEvent => (DetectionModelSubjectKind::RawEvent, None),
            database::PrimarySubjectKind::Host(source) => {
                (DetectionModelSubjectKind::Host, Some(source.into()))
            }
            database::PrimarySubjectKind::Cluster => (DetectionModelSubjectKind::Cluster, None),
            database::PrimarySubjectKind::Sensor => (DetectionModelSubjectKind::Sensor, None),
            database::PrimarySubjectKind::Network(source) => {
                (DetectionModelSubjectKind::Network, Some(source.into()))
            }
        };
        Self { kind, role_source }
    }
}

/// Where the threat role of a model's primary subject comes from.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(super) enum ThreatRoleSourceKind {
    /// The model always assigns the same role.
    Fixed,
    /// Each detection event sets the role.
    PerEvent,
    /// The time-series type sets the role.
    TimeSeriesType,
}

/// The source of the threat role of a model's primary subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq, SimpleObject)]
pub(super) struct ThreatRoleSource {
    /// Where the role comes from.
    kind: ThreatRoleSourceKind,
    /// The role the model always assigns; non-null exactly for `FIXED`.
    role: Option<ThreatRole>,
}

impl From<database::RoleSource> for ThreatRoleSource {
    fn from(source: database::RoleSource) -> Self {
        match source {
            database::RoleSource::Fixed(role) => Self {
                kind: ThreatRoleSourceKind::Fixed,
                role: Some(role.into()),
            },
            database::RoleSource::PerEvent => Self {
                kind: ThreatRoleSourceKind::PerEvent,
                role: None,
            },
            database::RoleSource::TimeSeriesType => Self {
                kind: ThreatRoleSourceKind::TimeSeriesType,
                role: None,
            },
        }
    }
}

/// The type of an operator value.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(super) enum OperatorValueType {
    /// A boolean.
    Boolean,
    /// A 64-bit signed integer.
    Integer,
    /// A 64-bit float.
    Float,
    /// A list of strings.
    StringList,
}

impl From<database::OperatorValueType> for OperatorValueType {
    fn from(value_type: database::OperatorValueType) -> Self {
        match value_type {
            database::OperatorValueType::Bool => Self::Boolean,
            database::OperatorValueType::Integer => Self::Integer,
            database::OperatorValueType::Float => Self::Float,
            database::OperatorValueType::StringList => Self::StringList,
        }
    }
}

/// A value an operator may set for a detection model, in that model's
/// section of an engine configuration document.
#[derive(Clone, Debug, PartialEq, SimpleObject)]
pub(super) struct OperatorValue {
    /// The key of the value in the model's section.
    name: String,
    /// The type of the value.
    value_type: OperatorValueType,
    /// The default, written as a TOML value.
    default_value: String,
    /// The inclusive lower bound, written as a TOML value; null unless the
    /// value is a ranged integer or float.
    min: Option<String>,
    /// The inclusive upper bound, written as a TOML value; null unless the
    /// value is a ranged integer or float.
    max: Option<String>,
}

impl From<&database::OperatorValueSpec> for OperatorValue {
    fn from(spec: &database::OperatorValueSpec) -> Self {
        let (default_value, range) = match spec.kind {
            database::OperatorValueKind::Bool { default } => (toml::Value::from(default), None),
            database::OperatorValueKind::Integer { min, max, default } => (
                toml::Value::from(default),
                Some((toml::Value::from(min), toml::Value::from(max))),
            ),
            database::OperatorValueKind::Float { min, max, default } => (
                toml::Value::from(default),
                Some((toml::Value::from(min), toml::Value::from(max))),
            ),
            database::OperatorValueKind::StringList { default } => (
                toml::Value::Array(default.iter().map(|s| toml::Value::from(*s)).collect()),
                None,
            ),
        };
        let (min, max) = range.map_or((None, None), |(min, max)| {
            (Some(min.to_string()), Some(max.to_string()))
        });
        Self {
            name: spec.name.to_string(),
            value_type: spec.kind.value_type().into(),
            default_value: default_value.to_string(),
            min,
            max,
        }
    }
}

#[cfg(test)]
mod tests {
    use async_graphql::{EmptyMutation, EmptySubscription, InputType, Request, Schema, Value};
    use review_database::Role;

    use super::*;
    use crate::graphql::{RoleGuard, TestSchema};

    fn schema() -> Schema<DetectionModelQuery, EmptyMutation, EmptySubscription> {
        Schema::build(DetectionModelQuery, EmptyMutation, EmptySubscription).finish()
    }

    fn spec(kind: database::OperatorValueKind) -> OperatorValue {
        OperatorValue::from(&database::OperatorValueSpec { name: "v", kind })
    }

    #[test]
    fn operator_values_are_written_as_toml_values() {
        assert_eq!(
            spec(database::OperatorValueKind::Bool { default: true }),
            OperatorValue {
                name: "v".to_string(),
                value_type: OperatorValueType::Boolean,
                default_value: "true".to_string(),
                min: None,
                max: None,
            }
        );
        assert_eq!(
            spec(database::OperatorValueKind::Integer {
                min: -3,
                max: 10,
                default: 5,
            }),
            OperatorValue {
                name: "v".to_string(),
                value_type: OperatorValueType::Integer,
                default_value: "5".to_string(),
                min: Some("-3".to_string()),
                max: Some("10".to_string()),
            }
        );
        assert_eq!(
            spec(database::OperatorValueKind::Float {
                min: 0.0,
                max: 1.0,
                default: 0.5,
            }),
            OperatorValue {
                name: "v".to_string(),
                value_type: OperatorValueType::Float,
                default_value: "0.5".to_string(),
                min: Some("0.0".to_string()),
                max: Some("1.0".to_string()),
            }
        );
        assert_eq!(
            spec(database::OperatorValueKind::StringList { default: &["a"] }),
            OperatorValue {
                name: "v".to_string(),
                value_type: OperatorValueType::StringList,
                default_value: r#"["a"]"#.to_string(),
                min: None,
                max: None,
            }
        );
        assert_eq!(
            spec(database::OperatorValueKind::StringList { default: &[] }).default_value,
            "[]"
        );
    }

    #[test]
    fn every_role_source_and_subject_kind_maps() {
        use database::{PrimarySubjectKind as Kind, RoleSource as Source};

        let fixed = |role| ThreatRoleSource {
            kind: ThreatRoleSourceKind::Fixed,
            role: Some(role),
        };
        let per_event = ThreatRoleSource {
            kind: ThreatRoleSourceKind::PerEvent,
            role: None,
        };
        let time_series_type = ThreatRoleSource {
            kind: ThreatRoleSourceKind::TimeSeriesType,
            role: None,
        };
        let cases = [
            (Kind::RawEvent, DetectionModelSubjectKind::RawEvent, None),
            (Kind::Cluster, DetectionModelSubjectKind::Cluster, None),
            (Kind::Sensor, DetectionModelSubjectKind::Sensor, None),
            (
                Kind::Host(Source::Fixed(protocol::ThreatRole::Actor)),
                DetectionModelSubjectKind::Host,
                Some(fixed(ThreatRole::Actor)),
            ),
            (
                Kind::Network(Source::Fixed(protocol::ThreatRole::Target)),
                DetectionModelSubjectKind::Network,
                Some(fixed(ThreatRole::Target)),
            ),
            (
                Kind::Host(Source::PerEvent),
                DetectionModelSubjectKind::Host,
                Some(per_event),
            ),
            (
                Kind::Network(Source::TimeSeriesType),
                DetectionModelSubjectKind::Network,
                Some(time_series_type),
            ),
        ];
        for (subject, kind, role_source) in cases {
            assert_eq!(
                DetectionModelSubject::from(subject),
                DetectionModelSubject { kind, role_source },
                "{subject:?}"
            );
        }
    }

    #[test]
    fn every_operator_value_type_maps() {
        use database::OperatorValueType as Type;

        let cases = [
            (Type::Bool, OperatorValueType::Boolean),
            (Type::Integer, OperatorValueType::Integer),
            (Type::Float, OperatorValueType::Float),
            (Type::StringList, OperatorValueType::StringList),
        ];
        assert_eq!(cases.len(), OperatorValueType::items().len());
        for (database, graphql) in cases {
            assert_eq!(OperatorValueType::from(database), graphql);
        }
    }

    #[test]
    fn models_are_listed_once_each_in_number_order() {
        let models = all_models();
        let numbers: Vec<u32> = models.iter().map(|model| u32::from(*model)).collect();
        let mut expected = Vec::new();
        for n in 0..=u32::from(u16::MAX) {
            if protocol::DetectionModel::try_from(n).is_ok() {
                expected.push(n);
            }
        }
        assert_eq!(numbers, expected);
    }

    /// Returns the expected GraphQL value of the entry of `model`, built from
    /// `properties` without going through the resolver's conversions.
    fn expected_entry(model: protocol::DetectionModel) -> serde_json::Value {
        let properties = database::properties(model);
        let name = |value: Value| match value {
            Value::Enum(name) => name.to_string(),
            other => panic!("not an enum: {other:?}"),
        };
        let enum_name = |value: Value| serde_json::Value::String(name(value));
        let subject = match properties.primary_subject {
            database::PrimarySubjectKind::RawEvent => ("RAW_EVENT", None),
            database::PrimarySubjectKind::Host(source) => ("HOST", Some(source)),
            database::PrimarySubjectKind::Cluster => ("CLUSTER", None),
            database::PrimarySubjectKind::Sensor => ("SENSOR", None),
            database::PrimarySubjectKind::Network(source) => ("NETWORK", Some(source)),
        };
        let role_source = subject.1.map(|source| match source {
            database::RoleSource::Fixed(role) => serde_json::json!({
                "kind": "FIXED",
                "role": enum_name(ThreatRole::from(role).to_value()),
            }),
            database::RoleSource::PerEvent => {
                serde_json::json!({ "kind": "PER_EVENT", "role": null })
            }
            database::RoleSource::TimeSeriesType => {
                serde_json::json!({ "kind": "TIME_SERIES_TYPE", "role": null })
            }
        });
        let operator_values: Vec<_> = properties
            .operator_values
            .iter()
            .map(|spec| {
                let value_type = match spec.kind.value_type() {
                    database::OperatorValueType::Bool => "BOOLEAN",
                    database::OperatorValueType::Integer => "INTEGER",
                    database::OperatorValueType::Float => "FLOAT",
                    database::OperatorValueType::StringList => "STRING_LIST",
                };
                let value = OperatorValue::from(spec);
                serde_json::json!({
                    "name": spec.name,
                    "valueType": value_type,
                    "defaultValue": value.default_value,
                    "min": value.min,
                    "max": value.max,
                })
            })
            .collect();
        serde_json::json!({
            "detectionModel": enum_name(DetectionModel::from(model).to_value()),
            "family": enum_name(DetectionFamily::from(properties.family).to_value()),
            "categories": properties
                .categories
                .iter()
                .map(|c| enum_name(ThreatCategory::from(*c).to_value()))
                .collect::<Vec<_>>(),
            "learningMethod": enum_name(LearningMethod::from(properties.learning_method).to_value()),
            "rawEventKinds": properties
                .raw_event_kinds
                .iter()
                .map(|k| enum_name(RawEventKind::from(*k).to_value()))
                .collect::<Vec<_>>(),
            "primarySubject": { "kind": subject.0, "roleSource": role_source },
            "scoreMeaning": properties.score_meaning,
            "requiresDeviceAccountIdentification":
                properties.requires_device_account_identification,
            "operatorValues": operator_values,
        })
    }

    const QUERY: &str = "{
        detectionModelProperties {
            detectionModel
            family
            categories
            learningMethod
            rawEventKinds
            primarySubject { kind roleSource { kind role } }
            scoreMeaning
            requiresDeviceAccountIdentification
            operatorValues { name valueType defaultValue min max }
        }
    }";

    #[tokio::test]
    async fn every_entry_equals_the_property_table() {
        let res = schema()
            .execute(Request::new(QUERY).data(RoleGuard::Role(Role::SecurityMonitor)))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let entries = data["detectionModelProperties"].as_array().unwrap();
        let models = all_models();
        assert_eq!(entries.len(), DetectionModel::items().len());
        assert_eq!(entries.len(), models.len());
        for (entry, model) in entries.iter().zip(models) {
            assert_eq!(*entry, expected_entry(model), "{model:?}");
        }
    }

    #[tokio::test]
    async fn the_current_table_has_only_the_enabled_switch() {
        let res = schema()
            .execute(Request::new(QUERY).data(RoleGuard::Role(Role::SecurityManager)))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let entries = data["detectionModelProperties"].as_array().unwrap();
        for entry in entries {
            assert_eq!(
                entry["operatorValues"],
                serde_json::json!([{
                    "name": "enabled",
                    "valueType": "BOOLEAN",
                    "defaultValue": "true",
                    "min": null,
                    "max": null,
                }]),
                "{entry}"
            );
        }
        let watchlist = entries.first().unwrap();
        assert_eq!(watchlist["detectionModel"], "WATCHLIST_MATCH");
        assert_eq!(
            watchlist["primarySubject"],
            serde_json::json!({
                "kind": "HOST",
                "roleSource": { "kind": "PER_EVENT", "role": null },
            })
        );
    }

    #[tokio::test]
    async fn the_query_takes_the_event_list_roles() {
        const QUERY: &str = "{ detectionModelProperties { detectionModel } }";
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
}
