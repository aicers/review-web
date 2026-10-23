//! The training definition document and its validation (RFC 0006 §5.2, §5.4,
//! §5.5).
//!
//! The schema is the one review-protocol documents on
//! `TrainModelRequest::definition`, which is its single statement; the types
//! here mirror it field for field. Every table refuses unknown keys, so no
//! path field, nor any other key outside the schema, is accepted.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    ops::Range,
};

use async_graphql::Result;
use chrono::{DateTime, TimeDelta};
use review_database::{ModelMethod, Store};
use serde::{Deserialize, Serialize};
use toml::de::{DeTable, DeValue};

use crate::graphql::{
    customer_access::customer_source_names,
    refusal::{RefusalCode, refusal},
    unsupervised::{DataStore, check_data_store},
};

/// The most events a training reads.
const MAX_BATCH_SIZE: usize = 5_000_000;
/// The longest training window, in days.
const MAX_WINDOW_DAYS: i64 = 90;
/// The most event ids a cluster keeps.
const MAX_EVENT_ID_NUM: u32 = 100;
/// The engine's `min_token_length` when a definition sets none.
const DEFAULT_MIN_TOKEN_LENGTH: usize = 3;

/// The Giganto event kinds a `multidimension` definition can train on: the
/// column-structured kinds.
const MULTIDIMENSION_EVENT_KINDS: [&str; 36] = [
    "conn",
    "dns",
    "http",
    "rdp",
    "smtp",
    "ntlm",
    "kerberos",
    "ssh",
    "dce_rpc",
    "ftp",
    "mqtt",
    "ldap",
    "tls",
    "smb",
    "nfs",
    "bootp",
    "dhcp",
    "radius",
    "malformed_dns",
    "icmp",
    "netflow5",
    "netflow9",
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
    "file_delete",
    "process_tamper",
    "file_delete_detected",
];

/// The names giganto-client 0.28.0's `RawEventKind::from_str` maps to a kind
/// other than `Log`, aliases included (`giganto-client` `src/lib.rs`,
/// `RawEventKind`). A `prefix` definition reads a log kind, which is any other
/// non-empty name.
const NAMED_EVENT_KINDS: [&str; 44] = [
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
];

/// A training definition, as review-protocol's `TrainModelRequest::definition`
/// documents it.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrainingDocument {
    pub(crate) event_kind: String,
    pub(crate) method: Method,
    pub(crate) sources: Vec<String>,
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
    pub(crate) time_intervals: Option<Vec<u32>>,
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
    /// Parses `text` and checks every rule that needs nothing stored: the
    /// schema, the method, the event kind, `[csv]`, the bounds and the
    /// sources' shape.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `INVALID_DOCUMENT`, `UNKNOWN_FIELD`,
    /// `TIMESERIES_UNSUPPORTED`, `FIELD_NOT_ALLOWED`,
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
        toml::from_str(text).map_err(|e| parse_refusal(text, &e))
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

    /// Checks every rule of the definition that needs nothing stored.
    fn validate(&self) -> Result<()> {
        self.check_method()?;
        self.check_window()?;
        self.check_bounds()?;
        self.check_source_list()
    }

    fn check_method(&self) -> Result<()> {
        match self.method {
            Method::Timeseries => Err(refusal(
                RefusalCode::TimeseriesUnsupported,
                "the timeseries method is not supported yet",
                "method",
                "timeseries",
            )),
            Method::Multidimension => {
                if self.csv.is_none() {
                    return Err(refusal(
                        RefusalCode::FieldNotAllowed,
                        "the multidimension method requires [csv]",
                        "csv",
                        "",
                    ));
                }
                if !MULTIDIMENSION_EVENT_KINDS.contains(&self.event_kind.as_str()) {
                    return Err(refusal(
                        RefusalCode::EventKindNotAllowed,
                        format!(
                            "the multidimension method does not take event kind {:?}",
                            self.event_kind
                        ),
                        "event_kind",
                        self.event_kind.as_str(),
                    ));
                }
                Ok(())
            }
            Method::Prefix => {
                if self.csv.is_some() {
                    return Err(refusal(
                        RefusalCode::FieldNotAllowed,
                        "the prefix method does not take [csv]",
                        "csv",
                        "",
                    ));
                }
                if self.event_kind.is_empty()
                    || NAMED_EVENT_KINDS.contains(&self.event_kind.as_str())
                {
                    return Err(refusal(
                        RefusalCode::EventKindNotAllowed,
                        format!(
                            "the prefix method takes a log kind, not {:?}",
                            self.event_kind
                        ),
                        "event_kind",
                        self.event_kind.as_str(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn check_window(&self) -> Result<()> {
        let start = rfc3339("window_start", &self.window_start)?;
        let end = rfc3339("window_end", &self.window_end)?;
        if start >= end {
            return Err(refusal(
                RefusalCode::BoundViolated,
                "window_start must be before window_end",
                "window_end",
                self.window_end.as_str(),
            ));
        }
        if end - start > TimeDelta::days(MAX_WINDOW_DAYS) {
            return Err(refusal(
                RefusalCode::BoundViolated,
                format!("the training window is longer than {MAX_WINDOW_DAYS} days"),
                "window_end",
                self.window_end.as_str(),
            ));
        }
        Ok(())
    }

    fn check_bounds(&self) -> Result<()> {
        if let Some(batch_size) = self.batch_size
            && batch_size > MAX_BATCH_SIZE
        {
            return Err(refusal(
                RefusalCode::BoundViolated,
                format!("batch_size is larger than {MAX_BATCH_SIZE}"),
                "batch_size",
                batch_size.to_string(),
            ));
        }
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
        if let Some(max_token_length) = self.max_token_length {
            let min_token_length = self.min_token_length.unwrap_or(DEFAULT_MIN_TOKEN_LENGTH);
            if min_token_length
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
        }
        Ok(())
    }

    fn check_source_list(&self) -> Result<()> {
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

    /// Checks the rules that read the store, with the engine configuration
    /// lock held: the sources, the Data Store and the indicator, for the
    /// definition's customer `customer_id`.
    ///
    /// `addrs` and `kept` are the Data Store rule's, as [`check_data_store`]
    /// takes them.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `SOURCE_NOT_ALLOWED`,
    /// `DATA_STORE_NOT_INSTALLED`, `ADDRESS_OVERRIDE_FORBIDDEN` or
    /// `INDICATOR_NOT_ALLOWED`, or an error if the store cannot be read.
    pub(crate) fn check_stored(
        &self,
        store: &Store,
        customer_id: u32,
        addrs: &[IpAddr],
        kept: &HashSet<(String, SocketAddr)>,
        system_admin: bool,
    ) -> Result<()> {
        self.check_sources(store, customer_id)?;
        self.check_data_store(store, addrs, kept, system_admin)?;
        self.check_indicator(store, customer_id)
    }

    /// Checks that every source is a source name of the customer.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `SOURCE_NOT_ALLOWED`, or an error if the store
    /// cannot be read.
    pub(crate) fn check_sources(&self, store: &Store, customer_id: u32) -> Result<()> {
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
        let allowed = match store.model_indicator_map().get(name)? {
            Some(indicator) => store
                .model_map()
                .get_by_id(indicator.model_id)?
                .is_some_and(|model| model.customer_id == customer_id),
            None => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(indicator_not_allowed(name))
        }
    }
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
    toml::from_str::<TrainingDocument>(text)
        .map(|document| document.sources)
        .unwrap_or_default()
}

/// Checks that `value` is RFC 3339 with an offset.
fn rfc3339(field: &str, value: &str) -> Result<DateTime<chrono::FixedOffset>> {
    DateTime::parse_from_rfc3339(value).map_err(|e| {
        refusal(
            RefusalCode::InvalidDocument,
            format!("{field} is not RFC 3339 with an offset: {e}"),
            field,
            value,
        )
    })
}

/// Returns the refusal of a definition that does not parse.
///
/// A key outside the schema is `UNKNOWN_FIELD`, anything else
/// `INVALID_DOCUMENT`. `field` is the dotted path of the offending key, found
/// from the error's position; it is empty where the document as a whole is
/// at fault, such as a TOML syntax error.
fn parse_refusal(text: &str, error: &toml::de::Error) -> async_graphql::Error {
    let message = error.message();
    let mut field = error
        .span()
        .and_then(|span| path_at(text, &span))
        .unwrap_or_default();
    let value = error
        .span()
        .and_then(|span| text.get(span))
        .unwrap_or_default();
    if let Some(key) = quoted(message, "unknown field `") {
        let field = if field.is_empty() {
            key.to_string()
        } else {
            field
        };
        return refusal(
            RefusalCode::UnknownField,
            format!("unknown key {field}"),
            &field,
            key,
        );
    }
    if let Some(key) = quoted(message, "missing field `") {
        field = if field.is_empty() {
            key.to_string()
        } else {
            format!("{field}.{key}")
        };
        return refusal(
            RefusalCode::InvalidDocument,
            format!("required key {field} is missing"),
            &field,
            "",
        );
    }
    refusal(
        RefusalCode::InvalidDocument,
        format!("invalid training definition: {message}"),
        &field,
        value,
    )
}

/// Returns the text between `prefix` and the next backtick of `message`, if
/// `message` starts with `prefix`.
fn quoted<'a>(message: &'a str, prefix: &str) -> Option<&'a str> {
    message.strip_prefix(prefix)?.split('`').next()
}

/// Returns the dotted path of the deepest key or value of `text` whose span
/// covers `span`, or `None` for an empty span or a document that does not
/// parse.
fn path_at(text: &str, span: &Range<usize>) -> Option<String> {
    if span.is_empty() {
        return None;
    }
    let table = DeTable::parse(text).ok()?;
    let mut found = None;
    walk_table(table.get_ref(), span, "", 0, &mut found);
    found.map(|(path, _)| path)
}

/// Records in `found` the deepest path under `table` whose key or value
/// covers `span`, with its depth.
fn walk_table(
    table: &DeTable<'_>,
    span: &Range<usize>,
    prefix: &str,
    depth: usize,
    found: &mut Option<(String, usize)>,
) {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.get_ref().to_string()
        } else {
            format!("{prefix}.{}", key.get_ref())
        };
        if covers(&key.span(), span) || covers(&value.span(), span) {
            record(found, &path, depth + 1);
        }
        walk_value(value.get_ref(), span, &path, depth + 1, found);
    }
}

fn walk_value(
    value: &DeValue<'_>,
    span: &Range<usize>,
    path: &str,
    depth: usize,
    found: &mut Option<(String, usize)>,
) {
    match value {
        DeValue::Table(table) => walk_table(table, span, path, depth, found),
        DeValue::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let path = format!("{path}[{i}]");
                if covers(&item.span(), span) {
                    record(found, &path, depth + 1);
                }
                walk_value(item.get_ref(), span, &path, depth + 1, found);
            }
        }
        _ => {}
    }
}

fn covers(outer: &Range<usize>, inner: &Range<usize>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn record(found: &mut Option<(String, usize)>, path: &str, depth: usize) {
    if found.as_ref().is_none_or(|(_, deepest)| *deepest < depth) {
        *found = Some((path.to_string(), depth));
    }
}

#[cfg(test)]
mod tests;
