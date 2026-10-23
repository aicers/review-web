//! The engine document of an Unsupervised Engine instance and its validation
//! (RFC 0006 §5.2, §5.3).
//!
//! The document is the TOML configuration Clumit Security Web writes as an
//! engine agent's draft and Apply makes its config; the engine reads it in
//! remote mode. Every table refuses unknown keys, so no path, event kind, CSV
//! setting nor any other key outside the schema is accepted. The types follow
//! `REconverge`'s `DetectorConfig`, `StateConfig` and `LabelDbConfig`.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use async_graphql::{ErrorExtensions, Result};
use review_database::{EngineDetectorRef, EngineDocumentRefs, ModelInstance, Store};
use serde::{Deserialize, Deserializer, de::Error as _};
use toml::de::{DeTable, DeValue};

use super::{
    customer_access::{customer_source_names, model_by_name},
    model::MULTIFIELD_KIND,
    refusal::{RefusalCode, refusal},
    toml_refusal::parse_refusal,
    training::is_customer_indicator,
    unsupervised::{DataStore, check_data_store},
};

/// The most CPUs a document may give the engine.
const MAX_CPUS: usize = 64;
/// The most events a detector reads in one round.
const MAX_BATCH_SIZE: usize = 5_000_000;
/// The most event ids a cluster keeps.
const MAX_EVENT_ID_NUM: u32 = 100;
/// The shortest period of a detector.
const MIN_PERIOD: Duration = Duration::from_mins(1);
/// The longest read lag of a detector.
const MAX_READ_LAG: Duration = Duration::from_hours(1);

/// An engine document.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EngineDocument {
    pub(crate) cpus: Option<usize>,
    #[serde(default)]
    pub(crate) detectors: Vec<Detector>,
}

/// One `[[detectors]]` entry: a model analysing the data of its sources.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Detector {
    pub(crate) id: i32,
    pub(crate) enabled: bool,
    pub(crate) model: String,
    pub(crate) sources: Vec<String>,
    pub(crate) period: TextDuration,
    /// RFC 3339 with an offset, kept as text.
    #[serde(deserialize_with = "rfc3339")]
    pub(crate) start: String,
    pub(crate) batch_size: usize,
    pub(crate) read_lag: Option<TextDuration>,
    pub(crate) max_event_id_num: Option<u32>,
    /// The name of a model indicator, never a path.
    pub(crate) suspicious_tokens: Option<String>,
    pub(crate) stats: Option<bool>,
    pub(crate) timeseries: Option<bool>,
    pub(crate) data_store: DataStore,
    pub(crate) labeldb: Option<LabelDb>,
}

/// The `[detectors.labeldb]` table, `REconverge`'s `LabelDbConfig` without the
/// `protocol` its model decides.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LabelDb {
    pub(crate) event_range: Option<usize>,
    pub(crate) min_events_ratio: Option<usize>,
    pub(crate) generate_unlabeled_from_outliers: Option<bool>,
    pub(crate) limit_unlabeled_from_outliers: Option<usize>,
    pub(crate) columns: Vec<LabelColumn>,
}

/// One entry of `labeldb.columns`.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LabelColumn {
    pub(crate) column_ids: Vec<usize>,
    pub(crate) db: String,
    #[serde(default, deserialize_with = "optional_f32")]
    pub(crate) min_score: Option<f32>,
}

/// A duration written as `humantime` text, such as `5m`, with its text.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TextDuration {
    pub(crate) text: String,
    pub(crate) duration: Duration,
}

impl<'de> Deserialize<'de> for TextDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let duration = humantime::parse_duration(&text)
            .map_err(|e| D::Error::custom(format!("{text:?} is not a duration: {e}")))?;
        Ok(Self { text, duration })
    }
}

/// Deserializes text that is RFC 3339 with an offset.
fn rfc3339<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let text = String::deserialize(deserializer)?;
    chrono::DateTime::parse_from_rfc3339(&text)
        .map_err(|e| D::Error::custom(format!("{text:?} is not RFC 3339 with an offset: {e}")))?;
    Ok(text)
}

/// Deserializes an `f32`, refusing a finite number too large for one, which
/// a derived `f32` field would take as infinity.
fn optional_f32<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<f32>, D::Error> {
    let Some(value) = Option::<f64>::deserialize(deserializer)? else {
        return Ok(None);
    };
    // Narrowing rounds to the nearest `f32`, which loses no more than the
    // precision a score of the engine's own `f32` has; only a finite value
    // past `f32::MAX` turns infinite, and that one is refused below.
    #[allow(clippy::cast_possible_truncation)]
    let narrowed = value as f32;
    if value.is_finite() && narrowed.is_infinite() {
        return Err(D::Error::custom(format!("{value} is too large for f32")));
    }
    Ok(Some(narrowed))
}

/// The engine instance a document is checked for, and what the rules that
/// read the store need besides the store.
pub(crate) struct DocumentTarget<'a> {
    /// The instance whose document it is.
    pub(crate) instance: &'a ModelInstance,
    /// The customer of the instance: its node's applied `customer_id`, or
    /// `None` when the node has no applied profile.
    pub(crate) customer_id: Option<u32>,
    /// The addresses [`data_store_addrs`](super::unsupervised::data_store_addrs)
    /// returned, by `server_name`.
    pub(crate) addrs: &'a HashMap<String, Vec<IpAddr>>,
    /// The `(server_name, address)` pairs the Data Store rule keeps.
    pub(crate) kept: &'a HashSet<(String, SocketAddr)>,
    pub(crate) system_admin: bool,
}

impl EngineDocument {
    /// Parses `text` and checks every rule that needs nothing stored, in this
    /// order: the schema, a non-empty source list included, the bounds, and
    /// repeated ids, models and sources.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `INVALID_DOCUMENT`, `UNKNOWN_FIELD`,
    /// `BOUND_VIOLATED` or `DUPLICATE_ENTRY`.
    pub(crate) fn parse_and_validate(text: &str) -> Result<Self> {
        let document = Self::parse(text)?;
        document.check_sources_present()?;
        document.check_bounds()?;
        document.check_repeats()?;
        Ok(document)
    }

    /// Parses `text` into the schema types, checking nothing else.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `UNKNOWN_FIELD` for a key outside the schema,
    /// and with `INVALID_DOCUMENT` for anything else that does not parse.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| {
            let error = parse_refusal(text, &e, "engine document");
            match refused_detector_id(text, &error) {
                Some(id) => error.extend_with(|_, extensions| extensions.set("detectorId", id)),
                None => error,
            }
        })
    }

    /// Returns the references the document's detectors make, a disabled
    /// detector's included.
    #[must_use]
    pub(crate) fn refs(&self) -> EngineDocumentRefs {
        EngineDocumentRefs {
            detectors: self
                .detectors
                .iter()
                .map(|detector| EngineDetectorRef {
                    id: detector.id,
                    model: detector.model.clone(),
                    sources: detector.sources.clone(),
                    indicator: detector.suspicious_tokens.clone(),
                })
                .collect(),
        }
    }

    /// Returns the distinct `server_name`s of the detectors' Data Stores.
    #[must_use]
    pub(crate) fn server_names(&self) -> BTreeSet<&str> {
        self.detectors
            .iter()
            .map(|detector| detector.data_store.server_name.as_str())
            .collect()
    }

    /// Refuses a detector with no source, which the schema's types alone do
    /// not: it cannot be run, so it is as invalid as a missing source list.
    fn check_sources_present(&self) -> Result<()> {
        for (i, detector) in self.detectors.iter().enumerate() {
            if detector.sources.is_empty() {
                return Err(detector_refusal(
                    RefusalCode::InvalidDocument,
                    "sources must not be empty".to_string(),
                    i,
                    "sources",
                    String::new(),
                    detector,
                ));
            }
        }
        Ok(())
    }

    fn check_bounds(&self) -> Result<()> {
        if let Some(cpus) = self.cpus
            && cpus > MAX_CPUS
        {
            return Err(refusal(
                RefusalCode::BoundViolated,
                format!("cpus is larger than {MAX_CPUS}"),
                "cpus",
                cpus.to_string(),
            ));
        }
        for (i, detector) in self.detectors.iter().enumerate() {
            let refused = |key: &str, message: String, value: String| {
                detector_refusal(RefusalCode::BoundViolated, message, i, key, value, detector)
            };
            if detector.period.duration < MIN_PERIOD {
                return Err(refused(
                    "period",
                    "period is shorter than 1 minute".to_string(),
                    detector.period.text.clone(),
                ));
            }
            if let Some(read_lag) = &detector.read_lag
                && read_lag.duration > MAX_READ_LAG
            {
                return Err(refused(
                    "read_lag",
                    "read_lag is longer than 1 hour".to_string(),
                    read_lag.text.clone(),
                ));
            }
            if detector.batch_size > MAX_BATCH_SIZE {
                return Err(refused(
                    "batch_size",
                    format!("batch_size is larger than {MAX_BATCH_SIZE}"),
                    detector.batch_size.to_string(),
                ));
            }
            if let Some(max_event_id_num) = detector.max_event_id_num
                && max_event_id_num > MAX_EVENT_ID_NUM
            {
                return Err(refused(
                    "max_event_id_num",
                    format!("max_event_id_num is larger than {MAX_EVENT_ID_NUM}"),
                    max_event_id_num.to_string(),
                ));
            }
        }
        Ok(())
    }

    fn check_repeats(&self) -> Result<()> {
        let mut ids = HashSet::new();
        let mut models = HashSet::new();
        for (i, detector) in self.detectors.iter().enumerate() {
            if !ids.insert(detector.id) {
                return Err(duplicate_id(i, detector));
            }
            if !models.insert(detector.model.as_str()) {
                return Err(duplicate_model(i, detector));
            }
            let mut sources = HashSet::new();
            for (j, source) in detector.sources.iter().enumerate() {
                if !sources.insert(source) {
                    return Err(detector_refusal(
                        RefusalCode::DuplicateEntry,
                        format!("source {source:?} is listed twice"),
                        i,
                        &format!("sources[{j}]"),
                        source.clone(),
                        detector,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks the rules that read the store, with the engine configuration
    /// lock held, detector by detector in document order: the applied
    /// profile, the model, `labeldb`, the sources, the Data Store and the
    /// indicator.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `SOURCE_NOT_ALLOWED`, `MODEL_NOT_OF_INSTANCE`,
    /// `FIELD_NOT_ALLOWED`, `DATA_STORE_NOT_INSTALLED`,
    /// `ADDRESS_OVERRIDE_FORBIDDEN` or `INDICATOR_NOT_ALLOWED`, or an error
    /// if the store cannot be read.
    pub(crate) fn check_stored(&self, store: &Store, target: &DocumentTarget<'_>) -> Result<()> {
        let mut customer_sources = None;
        for (i, detector) in self.detectors.iter().enumerate() {
            let Some(customer_id) = target.customer_id else {
                let source = detector.sources.first().cloned().unwrap_or_default();
                return Err(detector_refusal(
                    RefusalCode::SourceNotAllowed,
                    "the node has no applied profile, so its engine document can have no detector"
                        .to_string(),
                    i,
                    "sources[0]",
                    source,
                    detector,
                ));
            };

            let model = model_by_name(store, &detector.model)?
                .filter(|model| model.instance.as_ref() == Some(target.instance));
            let Some(model) = model else {
                return Err(model_not_of_instance(i, detector));
            };

            if detector.labeldb.is_some() && model.kind != MULTIFIELD_KIND {
                return Err(detector_refusal(
                    RefusalCode::FieldNotAllowed,
                    format!(
                        "labeldb is only for a multidimension model, and {:?} is not one",
                        detector.model
                    ),
                    i,
                    "labeldb",
                    String::new(),
                    detector,
                ));
            }

            let names = match customer_sources.take() {
                Some(names) => names,
                None => customer_source_names(store, customer_id)?,
            };
            for (j, source) in detector.sources.iter().enumerate() {
                if !names.contains(source) {
                    return Err(detector_refusal(
                        RefusalCode::SourceNotAllowed,
                        format!("{source:?} is not a source of customer {customer_id}"),
                        i,
                        &format!("sources[{j}]"),
                        source.clone(),
                        detector,
                    ));
                }
            }
            customer_sources = Some(names);

            let addrs = target
                .addrs
                .get(&detector.data_store.server_name)
                .map_or(&[][..], Vec::as_slice);
            if let Some(refused) = check_data_store(
                store,
                &detector.data_store,
                addrs,
                target.kept,
                target.system_admin,
            )? {
                let id = detector.id;
                return Err(refused
                    .into_error(&format!("detectors[{i}].data_store."), &detector.data_store)
                    .extend_with(|_, extensions| extensions.set("detectorId", id)));
            }

            if let Some(name) = detector.suspicious_tokens.as_deref()
                && !is_customer_indicator(store, name, customer_id)?
            {
                return Err(indicator_not_allowed(i, detector));
            }
        }
        Ok(())
    }
}

/// Returns the `(server_name, address)` pairs of the detectors of each of
/// `texts`, stored documents whose pairs the Data Store rule keeps.
///
/// A text that does not parse under the schema, such as one in the retired
/// file format, contributes none.
#[must_use]
pub(crate) fn kept_pairs<'a>(
    texts: impl IntoIterator<Item = &'a str>,
) -> HashSet<(String, SocketAddr)> {
    texts
        .into_iter()
        .filter_map(|text| toml::from_str::<EngineDocument>(text).ok())
        .flat_map(|document| {
            document
                .detectors
                .into_iter()
                .map(|detector| detector.data_store.pair())
        })
        .collect()
}

/// Returns a refusal of the key `key` of detector `i`, with its `detectorId`.
pub(crate) fn detector_refusal(
    code: RefusalCode,
    message: String,
    i: usize,
    key: &str,
    value: String,
    detector: &Detector,
) -> async_graphql::Error {
    let id = detector.id;
    refusal(code, message, &format!("detectors[{i}].{key}"), value)
        .extend_with(|_, extensions| extensions.set("detectorId", id))
}

/// Returns the `MODEL_NOT_OF_INSTANCE` refusal of detector `i`.
///
/// A model that does not exist and one of another instance get this one
/// message, so the refusal does not tell whether another customer's model
/// exists.
pub(crate) fn model_not_of_instance(i: usize, detector: &Detector) -> async_graphql::Error {
    detector_refusal(
        RefusalCode::ModelNotOfInstance,
        format!(
            "{:?} is not a model of this engine instance",
            detector.model
        ),
        i,
        "model",
        detector.model.clone(),
        detector,
    )
}

/// Returns the `DUPLICATE_ENTRY` refusal of detector `i` repeating an id.
pub(crate) fn duplicate_id(i: usize, detector: &Detector) -> async_graphql::Error {
    detector_refusal(
        RefusalCode::DuplicateEntry,
        format!("detector id {} is used twice", detector.id),
        i,
        "id",
        detector.id.to_string(),
        detector,
    )
}

/// Returns the `DUPLICATE_ENTRY` refusal of detector `i` naming a model
/// another detector names.
pub(crate) fn duplicate_model(i: usize, detector: &Detector) -> async_graphql::Error {
    detector_refusal(
        RefusalCode::DuplicateEntry,
        format!("model {:?} is named by two detectors", detector.model),
        i,
        "model",
        detector.model.clone(),
        detector,
    )
}

/// Returns the `INDICATOR_NOT_ALLOWED` refusal of the `suspicious_tokens` of
/// detector `i`.
pub(crate) fn indicator_not_allowed(i: usize, detector: &Detector) -> async_graphql::Error {
    let name = detector.suspicious_tokens.clone().unwrap_or_default();
    detector_refusal(
        RefusalCode::IndicatorNotAllowed,
        format!("{name:?} is not an indicator of the instance's customer"),
        i,
        "suspicious_tokens",
        name,
        detector,
    )
}

/// Returns the id of the detector a parse refusal of `text` names in its
/// `field`, `detectors[<i>]…`, if that detector has an `i32` id.
fn refused_detector_id(text: &str, error: &async_graphql::Error) -> Option<i32> {
    let field = match error.extensions.as_ref()?.get("field")? {
        async_graphql::Value::String(field) => field.as_str(),
        _ => return None,
    };
    let index = field
        .strip_prefix("detectors[")?
        .split(']')
        .next()?
        .parse::<usize>()
        .ok()?;
    let table = DeTable::parse(text).ok()?;
    let DeValue::Array(detectors) = entry(table.get_ref(), "detectors")? else {
        return None;
    };
    let DeValue::Table(detector) = detectors.get(index)?.get_ref() else {
        return None;
    };
    let DeValue::Integer(id) = entry(detector, "id")? else {
        return None;
    };
    i32::from_str_radix(id.as_str(), id.radix()).ok()
}

/// Returns the value of `key` in `table`.
fn entry<'a, 'i>(table: &'a DeTable<'i>, key: &str) -> Option<&'a DeValue<'i>> {
    table
        .iter()
        .find(|(k, _)| k.get_ref() == key)
        .map(|(_, value)| value.get_ref())
}

#[cfg(test)]
mod tests;
