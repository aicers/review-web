//! The clustering model type catalog, the training definition key table and
//! the defaults of a custom definition, which the training screen reads.
//!
//! Every value here comes from the tables review-database keeps in code,
//! [`database::clustering_model_types`], [`database::definition_keys`],
//! [`database::custom_defaults`] and [`database::custom_csv_default`];
//! nothing is read from the store, and no rule is copied here.

use async_graphql::{Enum, Object, Result, SimpleObject, StringNumber};
use review_database::{self as database};

use super::{
    Role, RoleGuard,
    filter::{DetectionModel, RawEventKind},
    model::ModelMethod,
    timestamp::Timestamp,
};

#[derive(Default)]
pub(super) struct ClusteringModelTypeQuery;

#[Object]
impl ClusteringModelTypeQuery {
    /// Every clustering model type of the catalog, in catalog order.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn clustering_model_types(&self) -> Vec<ClusteringModelType> {
        database::clustering_model_types()
            .iter()
            .map(ClusteringModelType)
            .collect()
    }

    /// The keys a training definition of `method` holds, one row per key of
    /// the method's key table, in its order. A `[csv]` part is a row of its
    /// own, dotted, such as `csv.format`. Keys the method does not define
    /// yet are not listed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn training_definition_keys(&self, method: ModelMethod) -> Vec<TrainingDefinitionKey> {
        database::definition_keys(method.into())
            .iter()
            .map(TrainingDefinitionKey::from)
            .collect()
    }

    /// The defaults of a custom training definition of `method`, in key
    /// table order, for the keys that have one.
    ///
    /// `csv` is listed, as one entry, only for `MULTIDIMENSION` with a
    /// `rawEventKind` that has a `[csv]` default: the `[csv]` of the first
    /// `MULTIDIMENSION` catalog type that reads that kind.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn custom_training_defaults(
        &self,
        method: ModelMethod,
        raw_event_kind: Option<RawEventKind>,
    ) -> Vec<TrainingValue> {
        let method = database::ModelMethod::from(method);
        let mut defaults: Vec<TrainingValue> = database::custom_defaults(method)
            .iter()
            .map(TrainingValue::from)
            .collect();
        if let Some(csv) = raw_event_kind.and_then(|kind| custom_csv(method, kind.into())) {
            defaults.push(TrainingValue {
                key: CSV.to_string(),
                value: table_text(csv),
            });
        }
        defaults
    }
}

/// The key of a definition's `[csv]` table.
const CSV: &str = "csv";
/// The definition key a catalog type fixes its raw event kind's name in.
const RAW_EVENT_KIND: &str = "raw_event_kind";

/// Returns the `[csv]` default of a custom definition of `method` reading
/// `kind`: [`database::custom_csv_default`] of the name the first
/// `multidimension` catalog type reading `kind` fixes in `raw_event_kind`,
/// since review-protocol's `RawEventKind` has no snake-case name of its own.
fn custom_csv(
    method: database::ModelMethod,
    kind: database::RawEventKind,
) -> Option<&'static [database::FixedValue]> {
    if method != database::ModelMethod::Multidimension {
        return None;
    }
    let t = database::clustering_model_types()
        .iter()
        .find(|t| t.method == database::ModelMethod::Multidimension && t.raw_event_kind == kind)?;
    match t.fixed_value(RAW_EVENT_KIND)? {
        database::DefinitionValue::String(name) => database::custom_csv_default(name),
        _ => None,
    }
}

/// A clustering model type: a fixed recipe for training a clustering model on
/// one raw event kind.
pub(super) struct ClusteringModelType(&'static database::ClusteringModelType);

/// A clustering model type: a fixed recipe for training a clustering model on
/// one raw event kind.
#[Object]
impl ClusteringModelType {
    /// The snake-case identifier, never changed; a definition names it in
    /// `type`.
    async fn id(&self) -> &'static str {
        self.0.id
    }

    /// The current version, raised whenever the fixed values or the allowed
    /// detection models change; a definition names it in `type_version`.
    async fn version(&self) -> StringNumber<u32> {
        StringNumber(self.0.version)
    }

    /// The position in the catalog.
    async fn order(&self) -> StringNumber<u32> {
        StringNumber(self.0.order)
    }

    /// The kind of the raw events the model reads.
    async fn raw_event_kind(&self) -> RawEventKind {
        self.0.raw_event_kind.into()
    }

    /// The clustering method.
    async fn method(&self) -> ModelMethod {
        self.0.method.into()
    }

    /// How the model groups raw events.
    async fn approach(&self) -> ClusteringApproach {
        self.0.approach.into()
    }

    /// The top-level definition keys the type fixes, with their values, in
    /// catalog order. `csv` is one entry, its value an inline table.
    async fn fixed_values(&self) -> Vec<TrainingValue> {
        self.0.fixed.iter().map(TrainingValue::from).collect()
    }

    /// The definition values the operator sets, in catalog order.
    async fn operator_values(&self) -> Vec<TrainingOperatorValue> {
        self.0
            .operator_values
            .iter()
            .map(TrainingOperatorValue::from)
            .collect()
    }

    /// The shortest training window, from `window_start` to `window_end`, in
    /// seconds; null when the type sets no minimum.
    async fn min_window_seconds(&self) -> Result<Option<i32>> {
        let Some(min) = self
            .0
            .operator_values
            .iter()
            .filter_map(|value| match value.range {
                Some(database::DefinitionValueRange::Window { min }) => Some(min),
                Some(
                    database::DefinitionValueRange::Integer { .. }
                    | database::DefinitionValueRange::NonEmpty,
                )
                | None => None,
            })
            .max()
        else {
            return Ok(None);
        };
        i32::try_from(min.as_secs()).map(Some).map_err(|_| {
            format!(
                "the shortest window of {} is too long to report in seconds",
                self.0.id
            )
            .into()
        })
    }

    /// The detection models allowed to run on the model, in detection model
    /// number order.
    async fn detection_models(&self) -> Vec<DetectionModel> {
        self.0
            .detection_models
            .iter()
            .map(|model| (*model).into())
            .collect()
    }

    /// What the type groups and what its limits are, in English.
    async fn description_en(&self) -> &'static str {
        self.0.description_en
    }

    /// What the type groups and what its limits are, in Korean.
    async fn description_ko(&self) -> &'static str {
        self.0.description_ko
    }
}

/// How a clustering model type groups raw events.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::ClusteringApproach")]
pub(super) enum ClusteringApproach {
    /// Groups raw events by the leading tokens of their prefix columns.
    Prefix,
    /// Groups raw events around centroids of their feature vectors.
    Centroid,
}

/// A key of a training definition and its value.
#[derive(Clone, Debug, Eq, PartialEq, SimpleObject)]
pub(super) struct TrainingValue {
    /// The top-level key in the training definition.
    key: String,
    /// The value, written as a TOML value; a table is an inline table.
    value: String,
}

impl From<&database::FixedValue> for TrainingValue {
    fn from(fixed: &database::FixedValue) -> Self {
        Self {
            key: fixed.key.to_string(),
            value: value_text(&fixed.value),
        }
    }
}

/// A value of a training definition that the operator sets for a clustering
/// model type.
#[derive(Clone, Debug, Eq, PartialEq, SimpleObject)]
pub(super) struct TrainingOperatorValue {
    /// The top-level key in the training definition.
    name: String,
    /// The type of the value.
    value_type: TrainingValueType,
    /// Whether the key may be absent, absence then being its value.
    optional: bool,
    /// The inclusive lower bound, written as a TOML value; null unless the
    /// value is a ranged `INTEGER` or `FLOAT`.
    min: Option<String>,
    /// The inclusive upper bound, written as a TOML value; null unless the
    /// value is a ranged `INTEGER` or `FLOAT`.
    max: Option<String>,
    /// The default, written as a TOML value; null when there is none.
    default_value: Option<String>,
}

impl From<&database::TypeOperatorValue> for TrainingOperatorValue {
    fn from(value: &database::TypeOperatorValue) -> Self {
        let (min, max) = match value.range {
            Some(database::DefinitionValueRange::Integer { min, max }) => (
                Some(toml::Value::from(min).to_string()),
                Some(toml::Value::from(max).to_string()),
            ),
            Some(
                database::DefinitionValueRange::NonEmpty
                | database::DefinitionValueRange::Window { .. },
            )
            | None => (None, None),
        };
        Self {
            name: value.name.to_string(),
            value_type: value.value_type.into(),
            optional: value.optional,
            min,
            max,
            default_value: value.default.as_ref().map(value_text),
        }
    }
}

/// The type of a value of a training definition.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::DefinitionValueType")]
pub(super) enum TrainingValueType {
    /// A string.
    String,
    /// An RFC 3339 timestamp with an offset, written as a string.
    Timestamp,
    /// An integer.
    Integer,
    /// A float; an integer of the same value is also taken.
    Float,
    /// A list of strings.
    StringList,
    /// A list of integers.
    IntegerList,
    /// A table.
    Table,
    /// A list of tables.
    TableList,
}

/// A row of a method's training definition key table.
#[derive(Clone, Debug, Eq, PartialEq, SimpleObject)]
pub(super) struct TrainingDefinitionKey {
    /// The key, dotted from the top level, such as `batch_size` or
    /// `csv.format`.
    key: String,
    /// Whether a definition of the method holds the key.
    status: TrainingKeyStatus,
    /// What an absent key means, or how the engine fills a value shorter than
    /// it needs, in one English line; null when neither applies.
    description: Option<String>,
}

impl From<&database::DefinitionKey> for TrainingDefinitionKey {
    fn from(row: &database::DefinitionKey) -> Self {
        Self {
            key: row.key.to_string(),
            status: row.status.into(),
            description: row.note.map(ToString::to_string),
        }
    }
}

/// Whether a training definition of a method holds a key.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(super) enum TrainingKeyStatus {
    /// The key must be present.
    Required,
    /// The key may be absent, with the meaning the row's description states.
    AbsentMeans,
    /// The method does not use the key; a present key is refused.
    Rejected,
    /// The key must be present in a definition of a catalog type and absent
    /// from a custom one: `type_version`.
    CatalogTypeOnly,
}

impl From<database::DefinitionKeyStatus> for TrainingKeyStatus {
    fn from(status: database::DefinitionKeyStatus) -> Self {
        // No wildcard arm: a status added to review-database must be mapped.
        match status {
            database::DefinitionKeyStatus::Required => Self::Required,
            database::DefinitionKeyStatus::AbsentMeans => Self::AbsentMeans,
            database::DefinitionKeyStatus::Rejected => Self::Rejected,
            database::DefinitionKeyStatus::RequiredForCatalogType => Self::CatalogTypeOnly,
        }
    }
}

/// The clustering model type a training definition or a model names, or a
/// detection event records.
pub(super) struct ClusteringModelTypeRef<'a>(&'a database::ClusteringModelTypeRef);

impl<'a> From<&'a database::ClusteringModelTypeRef> for ClusteringModelTypeRef<'a> {
    fn from(model_type: &'a database::ClusteringModelTypeRef) -> Self {
        Self(model_type)
    }
}

/// The `type` of a custom definition.
const CUSTOM: &str = "custom";

/// The clustering model type a training definition or a model names, or a
/// detection event records.
#[Object]
impl ClusteringModelTypeRef<'_> {
    /// The catalog id of the type, or `custom` for a definition whose every
    /// value the operator set.
    async fn id(&self) -> &str {
        match self.0 {
            database::ClusteringModelTypeRef::Catalog { id, .. } => id,
            database::ClusteringModelTypeRef::Custom => CUSTOM,
        }
    }

    /// The catalog version of the type; null for `custom`.
    async fn version(&self) -> Option<StringNumber<u32>> {
        match self.0 {
            database::ClusteringModelTypeRef::Catalog { version, .. } => {
                Some(StringNumber(*version))
            }
            database::ClusteringModelTypeRef::Custom => None,
        }
    }
}

/// A summary of the raw events the training of a model read.
pub(super) struct TrainingRead<'a>(&'a database::TrainingRead);

impl<'a> From<&'a database::TrainingRead> for TrainingRead<'a> {
    fn from(read: &'a database::TrainingRead) -> Self {
        Self(read)
    }
}

/// A summary of the raw events the training of a model read.
#[Object]
impl TrainingRead<'_> {
    /// The time of the first raw event read.
    async fn first(&self) -> Result<Timestamp> {
        timestamp(self.0.first)
    }

    /// The time of the last raw event read.
    async fn last(&self) -> Result<Timestamp> {
        timestamp(self.0.last)
    }

    /// The number of raw events read on each day, in the order the model
    /// records them.
    async fn days(&self) -> Vec<TrainingReadDay<'_>> {
        self.0.days.iter().map(TrainingReadDay).collect()
    }
}

/// The number of raw events the training of a model read on one day.
pub(super) struct TrainingReadDay<'a>(&'a database::TrainingReadDay);

/// The number of raw events the training of a model read on one day.
#[Object]
impl TrainingReadDay<'_> {
    /// The start of the day.
    async fn start(&self) -> Result<Timestamp> {
        timestamp(self.0.start)
    }

    /// The number of raw events read on the day.
    async fn count(&self) -> StringNumber<u64> {
        StringNumber(self.0.count)
    }
}

/// Returns the time `nanoseconds` after the Unix epoch, at full precision.
fn timestamp(nanoseconds: i64) -> Result<Timestamp> {
    jiff::Timestamp::from_nanosecond(i128::from(nanoseconds))
        .map(Into::into)
        .map_err(|e| format!("{nanoseconds} ns is not a time: {e}").into())
}

/// Returns `value` as the text of a TOML value; a table is an inline table
/// whose keys keep the order of the catalog.
fn value_text(value: &database::DefinitionValue) -> String {
    let mut text = String::new();
    write_value(&mut text, value);
    text
}

/// Returns the table `fields` as the text of an inline TOML table whose keys
/// keep their order.
fn table_text(fields: &[database::FixedValue]) -> String {
    let mut text = String::new();
    write_table(&mut text, fields);
    text
}

fn write_value(text: &mut String, value: &database::DefinitionValue) {
    match value {
        database::DefinitionValue::String(s) => text.push_str(&toml::Value::from(*s).to_string()),
        database::DefinitionValue::Integer(i) => text.push_str(&toml::Value::from(*i).to_string()),
        database::DefinitionValue::Float(f) => text.push_str(&toml::Value::from(*f).to_string()),
        database::DefinitionValue::IntegerList(items) => {
            write_list(text, items, |text, i| {
                text.push_str(&toml::Value::from(*i).to_string());
            });
        }
        database::DefinitionValue::Table(fields) => write_table(text, fields),
        database::DefinitionValue::TableList(tables) => {
            write_list(text, tables, |text, fields| write_table(text, fields));
        }
    }
}

fn write_list<T>(text: &mut String, items: &[T], write: impl Fn(&mut String, &T)) {
    text.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            text.push_str(", ");
        }
        write(text, item);
    }
    text.push(']');
}

fn write_table(text: &mut String, fields: &[database::FixedValue]) {
    if fields.is_empty() {
        text.push_str("{}");
        return;
    }
    text.push_str("{ ");
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            text.push_str(", ");
        }
        write_key(text, field.key);
        text.push_str(" = ");
        write_value(text, &field.value);
    }
    text.push_str(" }");
}

/// Writes `key` bare when TOML allows it, and as a quoted string otherwise.
fn write_key(text: &mut String, key: &str) {
    let bare = !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if bare {
        text.push_str(key);
    } else {
        text.push_str(&toml::Value::from(key).to_string());
    }
}

#[cfg(test)]
mod tests;
