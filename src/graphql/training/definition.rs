//! The training definition document and its validation (RFC 0006 §5.2, §5.4,
//! §5.5).
//!
//! The schema is the one review-protocol documents on
//! `TrainModelRequest::definition`, which is its single statement; the types
//! here mirror it field for field. Every table refuses unknown keys, so no
//! path field, nor any other key outside the schema, is accepted.
//!
//! The rules of the definition's clustering model type, of its method's key
//! table and of a custom definition are review-database's
//! [`check_training_definition`], which runs before the rules here; this
//! module keeps no copy of them.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

use async_graphql::Result;
use jiff::Timestamp;
use review_database::{
    ClusteringModelTypeRef, ModelMethod, Store, TrainingDefinitionRefusal,
    TrainingDefinitionRefusalCode, check_training_definition,
};
use serde::{Deserialize, Serialize};

use crate::graphql::{
    customer_access::customer_source_names,
    refusal::{RefusalCode, refusal},
    rfc3339::{self, LeapAwareTime},
    time_series_generation::{CustomKeys, ShapeReference, check_policy_sources},
    toml_refusal::parse_refusal,
    unsupervised::{DataStore, check_data_store, data_store_retention},
};

/// The most event ids a cluster keeps.
const MAX_EVENT_ID_NUM: u32 = 100;
/// The raw event kind of every `prefix` definition, which reads the log its
/// `log_kind` names.
const PREFIX_RAW_EVENT_KIND: &str = "log";

/// The names giganto-client 0.31.0's `RawEventKind::from_str` maps to a kind
/// other than `Log`, aliases included (`giganto-client` `src/lib.rs`,
/// `RawEventKind`). A `prefix` definition reads a log kind, which is any other
/// non-empty name.
const NAMED_EVENT_KINDS: [&str; 52] = [
    "conn",
    "dns",
    "http",
    "rdp",
    "periodic_time_series",
    "timeseries",
    "smtp",
    "ntlm",
    "kerberos",
    "ssh",
    "dce_rpc",
    "dce rpc",
    "statistics",
    "op_log",
    "packet",
    "ftp",
    "mqtt",
    "ldap",
    "tls",
    "smb",
    "nfs",
    "secu_log",
    "bootp",
    "dhcp",
    "radius",
    "malformed_dns",
    "icmp",
    "process_create",
    "file_create_time",
    "network_connect",
    "process_terminate",
    "image_load",
    "file_create",
    "registry_value_set",
    "registry_key_rename",
    "file_create_stream_hash",
    "pipe_event",
    "dns_query",
    "dns_event",
    "file_delete",
    "process_tamper",
    "file_delete_detected",
    "netflow5",
    "netflow9",
    "driver_load",
    "create_remote_thread",
    "raw_access_read",
    "process_access",
    "registry_object_add_del",
    "endpoint_windows_event_log",
    "endpoint_journald",
    "endpoint_auditd",
];

/// A training definition, as review-protocol's `TrainModelRequest::definition`
/// documents it.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrainingDocument {
    /// The clustering model type: a catalog id or `custom`. Every definition
    /// stored by an insert or update has it; one copied from a model trained
    /// before types existed may not.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub(crate) model_type: Option<String>,
    /// The version of a catalog `type`; absent for `custom`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) type_version: Option<i64>,
    pub(crate) raw_event_kind: String,
    /// The log a `prefix` definition reads; absent for every other method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) log_kind: Option<String>,
    pub(crate) method: Method,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) endpoint_scope: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) os_family: Option<String>,
    /// RFC 3339 with an offset, kept as text so a re-serialization keeps it.
    pub(crate) window_start: String,
    /// RFC 3339 with an offset, kept as text so a re-serialization keeps it.
    pub(crate) window_end: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) batch_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) algorithm: Option<Algorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) eps: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) min_token_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_token_length: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_data_len: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) long_pattern_len: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) precision: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) numbers_of_top_n: Option<Vec<usize>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_event_id_num: Option<u32>,
    /// The name of a model indicator, never a path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) suspicious_tokens: Option<String>,
    pub(crate) data_store: DataStore,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) csv: Option<CsvConfig>,
    /// The slot length of a `timeseries` definition's series, in seconds.
    /// [`check_training_definition`] decides where it may appear; a custom
    /// definition's must be its source policies' slot size, as
    /// [`check_policy_sources`] checks it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) slot_size: Option<u64>,
    /// The endpoint a `timeseries` definition's source policies are grouped
    /// by; absent means they are not grouped. A custom definition's must be
    /// its source policies', as [`check_policy_sources`] checks it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) group_by: Option<GroupBy>,
    /// The threat role of the detections of a catalog `timeseries` type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) threat_role: Option<ThreatRole>,
    /// The smallest cluster a `timeseries` definition's model keeps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) min_cluster_size: Option<u64>,
    /// The input transform of a `timeseries` definition's series.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) transform: Option<Transform>,
}

/// The endpoint a `timeseries` definition's source policies are grouped by.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GroupBy {
    Source,
    Destination,
}

impl GroupBy {
    /// Returns the name a definition writes the endpoint as.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }
}

/// The threat role of the detections of a catalog `timeseries` type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ThreatRole {
    Actor,
    Target,
}

/// The input transform of a `timeseries` definition's series.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum Transform {
    /// The series as counted.
    #[serde(rename = "none")]
    None,
    /// `ln(1 + x)` of each value.
    #[serde(rename = "log1p")]
    Log1p,
}

/// The clustering method of a definition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Method {
    Multidimension,
    Prefix,
    Timeseries,
}

impl From<Method> for ModelMethod {
    fn from(method: Method) -> Self {
        match method {
            Method::Multidimension => Self::Multidimension,
            Method::Prefix => Self::Prefix,
            Method::Timeseries => Self::Timeseries,
        }
    }
}

/// The clustering algorithm of a definition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Algorithm {
    Dbscan,
    Hdbscan,
    Optics,
}

/// The `[csv]` table, `REconverge`'s `remake::csv::Config`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CsvConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reader: Option<CsvReader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) format: Option<Vec<ColumnDescription>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) slot_sizes: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) time_column: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) count_columns: Option<Vec<usize>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prefix_columns: Option<Vec<usize>>,
}

/// The CSV reader settings, `structured::csv::Config`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CsvReader {
    pub(crate) delimiter: u8,
    pub(crate) quote: u8,
}

/// One column of the CSV format.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ColumnDescription {
    pub(crate) data_type: ColumnType,
    pub(crate) weight: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    /// A datetime parse format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) format: Option<String>,
}

/// The type of a CSV column, `structured::ColumnType`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ColumnType {
    Int64,
    Float64,
    Datetime,
    Ipaddr,
    Enum,
    Utf8,
    Binary,
}

impl TrainingDocument {
    /// Checks `text` against its clustering model type with
    /// [`check_training_definition`], then parses it and checks every other
    /// rule that needs nothing stored, as [`Self::parse_and_validate`] does.
    /// Returns the definition and the clustering model type it names.
    ///
    /// # Errors
    ///
    /// Returns the refusal of [`check_training_definition`], with its key in
    /// `field` and its value in `value`, or a refusal of
    /// [`Self::parse_and_validate`].
    pub(crate) fn check(text: &str) -> Result<(Self, ClusteringModelTypeRef)> {
        let model_type = check_type(text)?;
        let document = Self::parse_and_validate(text)?;
        Ok((document, model_type))
    }

    /// Parses `text` and checks every rule that needs nothing stored and is
    /// not [`check_training_definition`]'s: the schema, the event and log
    /// kinds, the window's order, the bounds and the sources' shape.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `INVALID_DOCUMENT`, `UNKNOWN_FIELD`,
    /// `EVENT_KIND_NOT_ALLOWED`, `BOUND_VIOLATED` or `DUPLICATE_ENTRY`.
    pub(crate) fn parse_and_validate(text: &str) -> Result<Self> {
        let document = Self::parse(text)?;
        document.validate()?;
        Ok(document)
    }

    /// Parses `text` into the schema types, checking nothing else.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `UNKNOWN_FIELD` for a key outside the schema,
    /// and with `INVALID_DOCUMENT` for anything else that does not parse.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| parse_refusal(text, &e, "training definition"))
    }

    /// Returns the definition as TOML text.
    ///
    /// The text has no comment and no key outside the schema.
    ///
    /// # Errors
    ///
    /// Returns an error if the definition cannot be serialized.
    pub(crate) fn to_text(&self) -> Result<String> {
        toml::to_string(self)
            .map_err(|e| format!("cannot serialize a training definition: {e}").into())
    }

    /// Returns the raw event kind and the log kind the definition's record
    /// stores.
    ///
    /// A `prefix` definition reads the log `log_kind` names, so its record
    /// stores `log` and that name. A `multidimension` or `timeseries`
    /// definition's record stores its text's raw event kind, a network kind
    /// such as `tls` for a `timeseries` one, which the engine records on the
    /// model too: review-database refuses a run's upload, or a clone, whose
    /// raw event kind differs from the record's. Only a `prefix` record has a
    /// log kind.
    #[must_use]
    pub(crate) fn record_kinds(&self) -> (String, Option<String>) {
        match self.method {
            Method::Prefix => (PREFIX_RAW_EVENT_KIND.to_string(), self.log_kind.clone()),
            Method::Multidimension | Method::Timeseries => (self.raw_event_kind.clone(), None),
        }
    }

    /// Checks every rule of the definition that needs nothing stored.
    fn validate(&self) -> Result<()> {
        self.check_kinds()?;
        self.check_window()?;
        self.check_bounds()?;
        self.check_source_list()
    }

    /// Checks the log kind of a `prefix` definition;
    /// [`check_training_definition`] checks the rest of the kinds, a
    /// `timeseries` definition's network raw event kind included.
    fn check_kinds(&self) -> Result<()> {
        match self.method {
            Method::Timeseries | Method::Multidimension => Ok(()),
            Method::Prefix => {
                let Some(log_kind) = self.log_kind.as_deref() else {
                    return Err(refusal(
                        RefusalCode::FieldNotAllowed,
                        "the prefix method requires log_kind",
                        "log_kind",
                        "",
                    ));
                };
                if log_kind.is_empty() || NAMED_EVENT_KINDS.contains(&log_kind) {
                    return Err(refusal(
                        RefusalCode::EventKindNotAllowed,
                        format!("the prefix method takes a log kind, not {log_kind:?}"),
                        "log_kind",
                        log_kind,
                    ));
                }
                Ok(())
            }
        }
    }

    fn check_window(&self) -> Result<()> {
        let start = leap_aware("window_start", &self.window_start)?;
        let end = leap_aware("window_end", &self.window_end)?;
        if start >= end {
            return Err(refusal(
                RefusalCode::BoundViolated,
                "window_start must be before window_end",
                "window_end",
                self.window_end.as_str(),
            ));
        }
        Ok(())
    }

    fn check_bounds(&self) -> Result<()> {
        if let Some(max_event_id_num) = self.max_event_id_num
            && max_event_id_num > MAX_EVENT_ID_NUM
        {
            return Err(refusal(
                RefusalCode::BoundViolated,
                format!("max_event_id_num is larger than {MAX_EVENT_ID_NUM}"),
                "max_event_id_num",
                max_event_id_num.to_string(),
            ));
        }
        if let (Some(max_token_length), Some(min_token_length)) =
            (self.max_token_length, self.min_token_length)
            && min_token_length
                .checked_mul(2)
                .is_none_or(|least| max_token_length < least)
        {
            return Err(refusal(
                RefusalCode::BoundViolated,
                format!(
                    "max_token_length must be at least twice min_token_length \
                     ({min_token_length})"
                ),
                "max_token_length",
                max_token_length.to_string(),
            ));
        }
        Ok(())
    }

    fn check_source_list(&self) -> Result<()> {
        if self.endpoint_scope.is_some() {
            return Ok(());
        }
        if self.sources.is_empty() {
            return Err(refusal(
                RefusalCode::InvalidDocument,
                "sources must not be empty",
                "sources",
                "",
            ));
        }
        let mut seen = HashSet::new();
        for (i, source) in self.sources.iter().enumerate() {
            if !seen.insert(source) {
                return Err(refusal(
                    RefusalCode::DuplicateEntry,
                    format!("source {source:?} is listed twice"),
                    &format!("sources[{i}]"),
                    source.as_str(),
                ));
            }
        }
        Ok(())
    }

    /// Checks the window against how long the Data Store `[data_store]`
    /// names keeps raw events, as [`data_store_retention`] reads it, at
    /// `now`: a window longer than that is refused on `window_end`, and a
    /// `window_start` earlier than `now` less that on `window_start`.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `INVALID_DOCUMENT` for a bound that is not RFC
    /// 3339 with an offset or `BOUND_VIOLATED`, or an error if the store
    /// cannot be read.
    pub(crate) fn check_retention(&self, store: &Store, now: Timestamp) -> Result<()> {
        let retention = data_store_retention(store, &self.data_store.server_name)?;
        let start = leap_aware("window_start", &self.window_start)?;
        let end = leap_aware("window_end", &self.window_end)?;
        if end.duration_since(start) > retention {
            return Err(refusal(
                RefusalCode::BoundViolated,
                format!(
                    "the training window is longer than the {retention:#} Data Store {:?} keeps \
                     raw events for",
                    self.data_store.server_name
                ),
                "window_end",
                self.window_end.as_str(),
            ));
        }
        let start = rfc3339::parse(&self.window_start).map_err(|e| {
            refusal(
                RefusalCode::InvalidDocument,
                format!("window_start is not RFC 3339 with an offset{}", e.detail()),
                "window_start",
                self.window_start.as_str(),
            )
        })?;
        if now
            .checked_sub(retention)
            .is_ok_and(|earliest| start < earliest)
        {
            return Err(refusal(
                RefusalCode::BoundViolated,
                format!(
                    "window_start is earlier than the {retention:#} Data Store {:?} keeps raw \
                     events for",
                    self.data_store.server_name
                ),
                "window_start",
                self.window_start.as_str(),
            ));
        }
        Ok(())
    }

    /// Checks the rules that read the store, with the engine configuration
    /// lock held: the sources, the Data Store and the indicator, for the
    /// definition's customer `customer_id`.
    ///
    /// `addrs` and `kept` are the Data Store rule's, as [`check_data_store`]
    /// takes them, and `shape` and `model_type` the shape and the clustering
    /// model type a timeseries definition's sources are checked by, as
    /// [`Self::check_sources`] takes them.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `SOURCE_NOT_ALLOWED`, `SOURCES_INCOMPATIBLE`,
    /// `DATA_STORE_NOT_INSTALLED`, `ADDRESS_OVERRIDE_FORBIDDEN` or
    /// `INDICATOR_NOT_ALLOWED`, or an error if the store cannot be read.
    // Each argument is a distinct input of the rules; bundling them would only
    // move the list into a struct every caller builds once.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn check_stored(
        &self,
        store: &Store,
        customer_id: u32,
        addrs: &[IpAddr],
        kept: &HashSet<(String, SocketAddr)>,
        shape: ShapeReference<'_>,
        model_type: &ClusteringModelTypeRef,
        system_admin: bool,
    ) -> Result<()> {
        self.check_sources(store, customer_id, shape, model_type)?;
        self.check_data_store(store, addrs, kept, system_admin)?;
        self.check_indicator(store, customer_id)
    }

    /// Checks the sources for the customer `customer_id`.
    ///
    /// A timeseries definition's sources must be assigned time series
    /// generation policies of the customer, of the shape `shape` gives, all
    /// kept in the Data Store `[data_store]` names, as
    /// [`check_policy_sources`] checks them. `model_type` is the definition's
    /// clustering model type: when it is a time-series type, every source
    /// policy must be of that type and version, and when it is `Custom`, the
    /// definition's `raw_event_kind`, `group_by` and `slot_size` must equal
    /// the source policies' values. A host definition's selected groups must
    /// have current policy rows belonging to the customer; their collection
    /// modes and endpoint membership do not affect selection. Other
    /// definitions require source names of the customer. Neither host nor
    /// source-name validation reads `shape` or `model_type`.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `SOURCE_NOT_ALLOWED`, `SOURCES_INCOMPATIBLE` or
    /// `DATA_STORE_NOT_INSTALLED`, or an error if the store cannot be read.
    pub(crate) fn check_sources(
        &self,
        store: &Store,
        customer_id: u32,
        shape: ShapeReference<'_>,
        model_type: &ClusteringModelTypeRef,
    ) -> Result<()> {
        if let Some(scope) = self.endpoint_scope.as_ref() {
            return crate::graphql::host_scope::check_groups(
                store,
                customer_id,
                &crate::graphql::host_scope::parse_scope(scope)?,
            );
        }
        if self.method == Method::Timeseries {
            let custom_keys = (*model_type == ClusteringModelTypeRef::Custom).then(|| CustomKeys {
                raw_event_kind: &self.raw_event_kind,
                group_by: self.group_by.map(GroupBy::as_str),
                slot_size: self.slot_size,
            });
            return match check_policy_sources(
                store,
                customer_id,
                &self.sources,
                shape,
                model_type,
                custom_keys,
                &self.data_store.server_name,
            )? {
                Some(refused) => Err(refused.into_error("")),
                None => Ok(()),
            };
        }
        let names = customer_source_names(store, customer_id)?;
        for (i, source) in self.sources.iter().enumerate() {
            if !names.contains(source) {
                return Err(refusal(
                    RefusalCode::SourceNotAllowed,
                    format!("{source:?} is not a source of customer {customer_id}"),
                    &format!("sources[{i}]"),
                    source.as_str(),
                ));
            }
        }
        Ok(())
    }

    /// Applies the Data Store rule to `[data_store]`.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `DATA_STORE_NOT_INSTALLED` or
    /// `ADDRESS_OVERRIDE_FORBIDDEN`, or an error if the store cannot be read.
    pub(crate) fn check_data_store(
        &self,
        store: &Store,
        addrs: &[IpAddr],
        kept: &HashSet<(String, SocketAddr)>,
        system_admin: bool,
    ) -> Result<()> {
        match check_data_store(store, &self.data_store, addrs, kept, system_admin)? {
            Some(refused) => Err(refused.into_error("data_store.", &self.data_store)),
            None => Ok(()),
        }
    }

    /// Checks that `suspicious_tokens`, when set, names an indicator whose
    /// model belongs to the customer.
    fn check_indicator(&self, store: &Store, customer_id: u32) -> Result<()> {
        let Some(name) = self.suspicious_tokens.as_deref() else {
            return Ok(());
        };
        if is_customer_indicator(store, name, customer_id)? {
            Ok(())
        } else {
            Err(indicator_not_allowed(name))
        }
    }
}

/// Returns whether `name` is an indicator whose model belongs to the customer
/// `customer_id`.
///
/// # Errors
///
/// Returns an error if the store cannot be read.
pub(crate) fn is_customer_indicator(store: &Store, name: &str, customer_id: u32) -> Result<bool> {
    Ok(match store.model_indicator_map().get(name)? {
        Some(indicator) => store
            .model_map()
            .get_by_id(indicator.model_id)?
            .is_some_and(|model| model.customer_id == customer_id),
        None => false,
    })
}

/// Returns the `INDICATOR_NOT_ALLOWED` refusal of `suspicious_tokens` naming
/// `name`.
pub(crate) fn indicator_not_allowed(name: &str) -> async_graphql::Error {
    refusal(
        RefusalCode::IndicatorNotAllowed,
        format!("{name:?} is not an indicator of the definition's customer"),
        "suspicious_tokens",
        name,
    )
}

/// Returns the `sources` of a definition text, or none if it does not parse.
#[must_use]
pub(crate) fn sources_of(text: &str) -> Vec<String> {
    toml::from_str::<TrainingDocument>(text).map_or_default(|document| document.sources)
}

/// Checks `text` against its clustering model type with
/// [`check_training_definition`], returning the type it names.
///
/// # Errors
///
/// Returns the refusal of [`check_training_definition`], with its key in
/// `field` and its value in `value`.
pub(crate) fn check_type(text: &str) -> Result<ClusteringModelTypeRef> {
    check_training_definition(text).map_err(|refused| definition_refusal(&refused))
}

/// Returns the refusal of `refused`, with its key in `field` and its value in
/// `value`.
fn definition_refusal(refused: &TrainingDefinitionRefusal) -> async_graphql::Error {
    refusal(
        definition_refusal_code(refused.code),
        refused.message.as_str(),
        &refused.key,
        refused.value.as_str(),
    )
}

/// Returns the refusal code of a [`TrainingDefinitionRefusalCode`].
fn definition_refusal_code(code: TrainingDefinitionRefusalCode) -> RefusalCode {
    // No wildcard arm: a code added to review-database must be mapped.
    match code {
        TrainingDefinitionRefusalCode::InvalidDocument => RefusalCode::InvalidDocument,
        TrainingDefinitionRefusalCode::UnknownField => RefusalCode::UnknownField,
        TrainingDefinitionRefusalCode::UnknownModelType => RefusalCode::UnknownModelType,
        TrainingDefinitionRefusalCode::ModelTypeVersionMismatch => {
            RefusalCode::ModelTypeVersionMismatch
        }
        TrainingDefinitionRefusalCode::EventKindNotAllowed => RefusalCode::EventKindNotAllowed,
        TrainingDefinitionRefusalCode::FieldFixed => RefusalCode::FieldFixed,
        TrainingDefinitionRefusalCode::FieldNotAllowed => RefusalCode::FieldNotAllowed,
        TrainingDefinitionRefusalCode::BoundViolated => RefusalCode::BoundViolated,
    }
}

/// Checks that `value` is RFC 3339 with an offset.
fn leap_aware(field: &str, value: &str) -> Result<LeapAwareTime> {
    LeapAwareTime::parse(value).map_err(|e| {
        refusal(
            RefusalCode::InvalidDocument,
            format!("{field} is not RFC 3339 with an offset{}", e.detail()),
            field,
            value,
        )
    })
}

#[cfg(test)]
mod tests;
