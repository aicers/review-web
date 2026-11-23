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
    /// A list of tables, each with the cells `cells` lists.
    TableList,
}

impl From<&database::OperatorValueKind> for OperatorValueType {
    fn from(kind: &database::OperatorValueKind) -> Self {
        // No wildcard arm: a kind added to review-database must be mapped.
        match kind {
            database::OperatorValueKind::Bool { .. } => Self::Boolean,
            database::OperatorValueKind::Integer { .. } => Self::Integer,
            database::OperatorValueKind::Float { .. } => Self::Float,
            database::OperatorValueKind::StringList { .. } => Self::StringList,
            database::OperatorValueKind::TableList { .. } => Self::TableList,
        }
    }
}

/// The type of a cell of a `TABLE_LIST` operator value's entries.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(super) enum OperatorValueCellType {
    /// A boolean.
    Boolean,
    /// A 64-bit signed integer.
    Integer,
    /// A 64-bit float.
    Float,
    /// A list of strings.
    StringList,
    /// A non-empty list of 64-bit signed integers.
    IntegerList,
    /// A non-empty string.
    NonEmptyString,
}

impl From<&database::CellKind> for OperatorValueCellType {
    fn from(kind: &database::CellKind) -> Self {
        // No wildcard arm: a kind added to review-database must be mapped.
        match kind {
            database::CellKind::Bool { .. } => Self::Boolean,
            database::CellKind::Integer { .. } => Self::Integer,
            database::CellKind::Float { .. } => Self::Float,
            database::CellKind::StringList { .. } => Self::StringList,
            database::CellKind::IntegerList { .. } => Self::IntegerList,
            database::CellKind::NonEmptyString { .. } => Self::NonEmptyString,
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
    /// The default, written as a TOML value; `[]` for a `TABLE_LIST`.
    default_value: String,
    /// The lower bound, written as a TOML value; null unless the value is a
    /// ranged integer or float. It is inclusive unless `minExclusive` is
    /// true.
    min: Option<String>,
    /// The inclusive upper bound, written as a TOML value; null unless the
    /// value is a ranged integer or float.
    max: Option<String>,
    /// Whether `min` is excluded: true exactly for a float range that
    /// excludes its lower bound.
    min_exclusive: bool,
    /// The cells of each entry; non-null exactly for a `TABLE_LIST`.
    cells: Option<Vec<OperatorValueCell>>,
}

/// A cell of the entries of a `TABLE_LIST` operator value.
#[derive(Clone, Debug, PartialEq, SimpleObject)]
pub(super) struct OperatorValueCell {
    /// The key of the cell in an entry.
    name: String,
    /// The type of the cell.
    value_type: OperatorValueCellType,
    /// The default, written as a TOML value; null when the cell has none, and
    /// then every entry must hold the cell.
    default_value: Option<String>,
    /// The lower bound, written as a TOML value; null unless the cell is a
    /// ranged integer, float or integer list. For an `INTEGER_LIST` it bounds
    /// each element. It is inclusive unless `minExclusive` is true.
    min: Option<String>,
    /// The inclusive upper bound, written as a TOML value; null unless the
    /// cell is a ranged integer, float or integer list. For an
    /// `INTEGER_LIST` it bounds each element.
    max: Option<String>,
    /// Whether `min` is excluded: true exactly for a float range that
    /// excludes its lower bound.
    min_exclusive: bool,
}

/// Returns a list of strings as a TOML value.
fn string_list(items: &[&str]) -> toml::Value {
    toml::Value::Array(items.iter().map(|s| toml::Value::from(*s)).collect())
}

/// Returns a range as the TOML text of its bounds.
fn bounds(
    min: impl Into<toml::Value>,
    max: impl Into<toml::Value>,
) -> (Option<String>, Option<String>) {
    (Some(min.into().to_string()), Some(max.into().to_string()))
}

impl From<&database::OperatorValueSpec> for OperatorValue {
    fn from(spec: &database::OperatorValueSpec) -> Self {
        let mut min_exclusive = false;
        let mut cells = None;
        let (default_value, (min, max)) = match spec.kind {
            database::OperatorValueKind::Bool { default } => {
                (toml::Value::from(default), (None, None))
            }
            database::OperatorValueKind::Integer { min, max, default } => {
                (toml::Value::from(default), bounds(min, max))
            }
            database::OperatorValueKind::Float {
                min,
                max,
                min_exclusive: exclusive,
                default,
            } => {
                min_exclusive = exclusive;
                (toml::Value::from(default), bounds(min, max))
            }
            database::OperatorValueKind::StringList { default } => {
                (string_list(default), (None, None))
            }
            database::OperatorValueKind::TableList { cells: specs } => {
                cells = Some(specs.iter().map(OperatorValueCell::from).collect());
                (toml::Value::Array(Vec::new()), (None, None))
            }
        };
        Self {
            name: spec.name.to_string(),
            value_type: (&spec.kind).into(),
            default_value: default_value.to_string(),
            min,
            max,
            min_exclusive,
            cells,
        }
    }
}

impl From<&database::CellSpec> for OperatorValueCell {
    fn from(spec: &database::CellSpec) -> Self {
        let mut min_exclusive = false;
        let (default_value, (min, max)) = match spec.kind {
            database::CellKind::Bool { default } => (default.map(toml::Value::from), (None, None)),
            database::CellKind::Integer { min, max, default } => {
                (default.map(toml::Value::from), bounds(min, max))
            }
            database::CellKind::Float {
                min,
                max,
                min_exclusive: exclusive,
                default,
            } => {
                min_exclusive = exclusive;
                (default.map(toml::Value::from), bounds(min, max))
            }
            database::CellKind::StringList { default } => (default.map(string_list), (None, None)),
            database::CellKind::IntegerList { min, max, default } => (
                default.map(|items| {
                    toml::Value::Array(items.iter().map(|i| toml::Value::from(*i)).collect())
                }),
                bounds(min, max),
            ),
            database::CellKind::NonEmptyString { default } => {
                (default.map(toml::Value::from), (None, None))
            }
        };
        Self {
            name: spec.name.to_string(),
            value_type: (&spec.kind).into(),
            default_value: default_value.map(|value| value.to_string()),
            min,
            max,
            min_exclusive,
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
                min_exclusive: false,
                cells: None,
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
                min_exclusive: false,
                cells: None,
            }
        );
        assert_eq!(
            spec(database::OperatorValueKind::Float {
                min: 0.0,
                max: 1.0,
                min_exclusive: false,
                default: 0.5,
            }),
            OperatorValue {
                name: "v".to_string(),
                value_type: OperatorValueType::Float,
                default_value: "0.5".to_string(),
                min: Some("0.0".to_string()),
                max: Some("1.0".to_string()),
                min_exclusive: false,
                cells: None,
            }
        );
        assert!(
            spec(database::OperatorValueKind::Float {
                min: 0.0,
                max: 1.0,
                min_exclusive: true,
                default: 0.5,
            })
            .min_exclusive
        );
        assert_eq!(
            spec(database::OperatorValueKind::StringList { default: &["a"] }),
            OperatorValue {
                name: "v".to_string(),
                value_type: OperatorValueType::StringList,
                default_value: r#"["a"]"#.to_string(),
                min: None,
                max: None,
                min_exclusive: false,
                cells: None,
            }
        );
        assert_eq!(
            spec(database::OperatorValueKind::StringList { default: &[] }).default_value,
            "[]"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one cell per kind
    fn cells_are_written_as_toml_values() {
        const CELLS: &[database::CellSpec] = &[
            database::CellSpec {
                name: "b",
                kind: database::CellKind::Bool {
                    default: Some(false),
                },
            },
            database::CellSpec {
                name: "i",
                kind: database::CellKind::Integer {
                    min: -1,
                    max: 9,
                    default: None,
                },
            },
            database::CellSpec {
                name: "f",
                kind: database::CellKind::Float {
                    min: 0.0,
                    max: 1.0,
                    min_exclusive: true,
                    default: Some(0.25),
                },
            },
            database::CellSpec {
                name: "s",
                kind: database::CellKind::StringList {
                    default: Some(&["x", "y"]),
                },
            },
            database::CellSpec {
                name: "l",
                kind: database::CellKind::IntegerList {
                    min: 0,
                    max: i64::MAX,
                    default: Some(&[14, 15]),
                },
            },
            database::CellSpec {
                name: "n",
                kind: database::CellKind::NonEmptyString { default: None },
            },
        ];
        let value = spec(database::OperatorValueKind::TableList { cells: CELLS });
        let cell = |name: &str,
                    value_type,
                    default_value: Option<&str>,
                    range: Option<(&str, &str)>,
                    min_exclusive| OperatorValueCell {
            name: name.to_string(),
            value_type,
            default_value: default_value.map(ToString::to_string),
            min: range.map(|(min, _)| min.to_string()),
            max: range.map(|(_, max)| max.to_string()),
            min_exclusive,
        };
        assert_eq!(
            value,
            OperatorValue {
                name: "v".to_string(),
                value_type: OperatorValueType::TableList,
                default_value: "[]".to_string(),
                min: None,
                max: None,
                min_exclusive: false,
                cells: Some(vec![
                    cell(
                        "b",
                        OperatorValueCellType::Boolean,
                        Some("false"),
                        None,
                        false
                    ),
                    cell(
                        "i",
                        OperatorValueCellType::Integer,
                        None,
                        Some(("-1", "9")),
                        false
                    ),
                    cell(
                        "f",
                        OperatorValueCellType::Float,
                        Some("0.25"),
                        Some(("0.0", "1.0")),
                        true,
                    ),
                    cell(
                        "s",
                        OperatorValueCellType::StringList,
                        Some(r#"["x", "y"]"#),
                        None,
                        false,
                    ),
                    cell(
                        "l",
                        OperatorValueCellType::IntegerList,
                        Some("[14, 15]"),
                        Some(("0", "9223372036854775807")),
                        false,
                    ),
                    cell(
                        "n",
                        OperatorValueCellType::NonEmptyString,
                        None,
                        None,
                        false
                    ),
                ]),
            }
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
        use database::{CellKind as Cell, OperatorValueKind as Kind};

        let cases = [
            (Kind::Bool { default: true }, OperatorValueType::Boolean),
            (
                Kind::Integer {
                    min: 0,
                    max: 1,
                    default: 0,
                },
                OperatorValueType::Integer,
            ),
            (
                Kind::Float {
                    min: 0.0,
                    max: 1.0,
                    min_exclusive: false,
                    default: 0.0,
                },
                OperatorValueType::Float,
            ),
            (
                Kind::StringList { default: &[] },
                OperatorValueType::StringList,
            ),
            (Kind::TableList { cells: &[] }, OperatorValueType::TableList),
        ];
        assert_eq!(cases.len(), OperatorValueType::items().len());
        for (kind, graphql) in cases {
            assert_eq!(OperatorValueType::from(&kind), graphql);
        }

        let cases = [
            (Cell::Bool { default: None }, OperatorValueCellType::Boolean),
            (
                Cell::Integer {
                    min: 0,
                    max: 1,
                    default: None,
                },
                OperatorValueCellType::Integer,
            ),
            (
                Cell::Float {
                    min: 0.0,
                    max: 1.0,
                    min_exclusive: false,
                    default: None,
                },
                OperatorValueCellType::Float,
            ),
            (
                Cell::StringList { default: None },
                OperatorValueCellType::StringList,
            ),
            (
                Cell::IntegerList {
                    min: 0,
                    max: 1,
                    default: None,
                },
                OperatorValueCellType::IntegerList,
            ),
            (
                Cell::NonEmptyString { default: None },
                OperatorValueCellType::NonEmptyString,
            ),
        ];
        assert_eq!(cases.len(), OperatorValueCellType::items().len());
        for (kind, graphql) in cases {
            assert_eq!(OperatorValueCellType::from(&kind), graphql);
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
                let value = OperatorValue::from(spec);
                let cells = value.cells.as_ref().map(|cells| {
                    cells
                        .iter()
                        .map(|cell| {
                            serde_json::json!({
                                "name": cell.name,
                                "valueType": enum_name(cell.value_type.to_value()),
                                "defaultValue": cell.default_value,
                                "min": cell.min,
                                "max": cell.max,
                                "minExclusive": cell.min_exclusive,
                            })
                        })
                        .collect::<Vec<_>>()
                });
                serde_json::json!({
                    "name": spec.name,
                    "valueType": enum_name(value.value_type.to_value()),
                    "defaultValue": value.default_value,
                    "min": value.min,
                    "max": value.max,
                    "minExclusive": value.min_exclusive,
                    "cells": cells,
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
            operatorValues {
                name valueType defaultValue min max minExclusive
                cells { name valueType defaultValue min max minExclusive }
            }
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
    async fn every_model_but_label_db_match_has_only_the_enabled_switch() {
        let res = schema()
            .execute(Request::new(QUERY).data(RoleGuard::Role(Role::SecurityManager)))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let entries = data["detectionModelProperties"].as_array().unwrap();
        assert_eq!(entries.len(), 20);
        let enabled = serde_json::json!({
            "name": "enabled",
            "valueType": "BOOLEAN",
            "defaultValue": "true",
            "min": null,
            "max": null,
            "minExclusive": false,
            "cells": null,
        });
        for entry in entries {
            if entry["detectionModel"] == "LABEL_DB_MATCH" {
                continue;
            }
            assert_eq!(
                entry["operatorValues"],
                serde_json::json!([enabled]),
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
        let last: Vec<_> = entries
            .iter()
            .skip(18)
            .map(|entry| {
                (
                    entry["detectionModel"].clone(),
                    entry["rawEventKinds"].clone(),
                )
            })
            .collect();
        assert_eq!(
            last,
            [
                (
                    serde_json::json!("LABEL_DB_MATCH"),
                    serde_json::json!(["HTTP"])
                ),
                (
                    serde_json::json!("FAR_OUTLIER"),
                    serde_json::json!(["HTTP"])
                ),
            ]
        );
    }

    #[tokio::test]
    async fn label_db_match_columns_is_a_table_list_with_its_cells() {
        let res = schema()
            .execute(Request::new(QUERY).data(RoleGuard::Role(Role::SecurityMonitor)))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let entries = data["detectionModelProperties"].as_array().unwrap();
        let label_db_match = entries
            .iter()
            .find(|entry| entry["detectionModel"] == "LABEL_DB_MATCH")
            .unwrap();
        let values = label_db_match["operatorValues"].as_array().unwrap();
        for value in values {
            assert_eq!(value["minExclusive"], false, "{value}");
            if value["name"] != "columns" {
                assert_eq!(value["cells"], serde_json::Value::Null, "{value}");
            }
        }
        let columns = values
            .iter()
            .find(|value| value["name"] == "columns")
            .unwrap();
        assert_eq!(
            *columns,
            serde_json::json!({
                "name": "columns",
                "valueType": "TABLE_LIST",
                "defaultValue": "[]",
                "min": null,
                "max": null,
                "minExclusive": false,
                "cells": [
                    {
                        "name": "column_ids",
                        "valueType": "INTEGER_LIST",
                        "defaultValue": null,
                        "min": "0",
                        "max": "9223372036854775807",
                        "minExclusive": false,
                    },
                    {
                        "name": "db",
                        "valueType": "NON_EMPTY_STRING",
                        "defaultValue": null,
                        "min": null,
                        "max": null,
                        "minExclusive": false,
                    },
                    {
                        "name": "min_score",
                        "valueType": "FLOAT",
                        "defaultValue": "0.7",
                        "min": "0.0",
                        "max": "1.0",
                        "minExclusive": true,
                    },
                ],
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
