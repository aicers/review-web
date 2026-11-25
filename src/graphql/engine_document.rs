//! The engine document of an Unsupervised Engine instance and its validation
//! (RFC 0006 §5.2, §5.3).
//!
//! The document is the TOML configuration Clumit Security Web writes as an
//! engine agent's draft and Apply makes its config; the engine reads it in
//! remote mode. Every table refuses unknown keys, so no path, event kind, CSV
//! setting nor any other key outside the schema is accepted. The types follow
//! `REconverge`'s `DetectorConfig` and `StateConfig`.
//!
//! A detector's `detection_models` table holds one section per detection
//! model the clustering model type of its model allows. The parse takes it as
//! an untyped table; its sections are checked against review-database's
//! detection model property table, the runtime source of what they may hold,
//! by [`EngineDocument::check_stored`].

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use async_graphql::{ErrorExtensions, Result};
use review_database::{
    AgentKind, CellErrorKind, CompletionMode, DetectionModelsSectionError, EngineDetectorRef,
    EngineDocumentRefs, ModelDigest, ModelInstance, Store, complete_engine_document,
};
use serde::{Deserialize, Deserializer, de::Error as _};
use toml::de::{DeTable, DeValue};

use super::{
    customer_access::{customer_source_names, model_by_name},
    model::TIMESERIES_KIND,
    refusal::{RefusalCode, refusal},
    time_series_generation::{
        check_policy_sources, policy_id, policy_sensors, time_series_type_of, trained_shape,
    },
    toml_refusal::parse_refusal,
    training::is_customer_indicator,
    unsupervised::{DataStore, check_data_store},
};

/// The most CPUs a document may give the engine.
const MAX_CPUS: usize = 64;
/// The most events a detector reads in one round.
const MAX_BATCH_SIZE: usize = 5_000_000;
/// The shortest period of a detector.
const MIN_PERIOD: Duration = Duration::from_mins(1);
/// The longest read lag of a detector.
const MAX_READ_LAG: Duration = Duration::from_hours(1);
/// The key of a detector's table of detection model sections.
const DETECTION_MODELS: &str = "detection_models";
/// The key of a detector's table of the sensors of each source policy.
const SOURCE_SENSORS: &str = "source_sensors";
/// The section of the detection model that matches label DBs.
const LABEL_DB_MATCH: &str = "label_db_match";
/// The list of `LABEL_DB_MATCH` whose entries name columns and a label DB.
const COLUMNS: &str = "columns";
/// The cell of a `COLUMNS` entry listing indices into the model's format.
const COLUMN_IDS: &str = "column_ids";
/// The cell of a `COLUMNS` entry naming a label DB.
const DB: &str = "db";

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
    pub(crate) read_lag: TextDuration,
    /// The name of a model indicator, never a path.
    pub(crate) suspicious_tokens: Option<String>,
    pub(crate) stats: bool,
    pub(crate) timeseries: bool,
    pub(crate) data_store: DataStore,
    /// The detection model sections, by section name, kept untyped so that
    /// every document the database write completes parses: their contents
    /// are checked by [`EngineDocument::check_stored`], never by the parse.
    pub(crate) detection_models: Option<toml::Table>,
    /// The sensors of each source policy, by policy id, which the database
    /// write's completion sets for a detector of a time-series type's model
    /// from the stored policies. It is declared so that every document the
    /// completion writes parses. Only a detector of a time-series type's
    /// model may have it, and each of its entries must be the stored sensors
    /// of one of the detector's sources, as [`EngineDocument::check_stored`]
    /// checks it; a source with no entry gets one from the completion.
    pub(crate) source_sensors: Option<BTreeMap<String, Vec<String>>>,
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
    super::rfc3339::parse(&text).map_err(|e| {
        D::Error::custom(format!(
            "{text:?} is not RFC 3339 with an offset{}",
            e.detail()
        ))
    })?;
    Ok(text)
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
    /// order: the schema, `detectors` written as the database write takes
    /// them, a non-empty source list included, the bounds, and repeated ids,
    /// models and sources.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `INVALID_DOCUMENT`, `UNKNOWN_FIELD`,
    /// `BOUND_VIOLATED` or `DUPLICATE_ENTRY`.
    pub(crate) fn parse_and_validate(text: &str) -> Result<Self> {
        let document = Self::parse(text)?;
        check_detectors_shape(text)?;
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
            if detector.read_lag.duration > MAX_READ_LAG {
                return Err(refused(
                    "read_lag",
                    "read_lag is longer than 1 hour".to_string(),
                    detector.read_lag.text.clone(),
                ));
            }
            if detector.batch_size > MAX_BATCH_SIZE {
                return Err(refused(
                    "batch_size",
                    format!("batch_size is larger than {MAX_BATCH_SIZE}"),
                    detector.batch_size.to_string(),
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
    /// profile, the model, the detection model sections, the sources, the
    /// Data Store and the indicator. `text` is the document `self` was parsed
    /// from.
    ///
    /// The detection model sections are checked as the database write's
    /// completion of `text` in [`CompletionMode::Apply`] checks them, with
    /// the clustering model type of each model of the instance, and the
    /// completed document is discarded: a section may lack any value that has
    /// a default, and a detector any section its model's type allows, since
    /// the write fills them. A refusal of that completion for a detector is
    /// returned only when the checks reach it, after its model check, so no
    /// model of another instance decides one; [`Self::parse_and_validate`]
    /// has already refused a document the completion refuses as a whole.
    /// Then each `columns` entry of
    /// `label_db_match` must name, in `column_ids`, indices into the `format`
    /// of the `[csv]` table of the model's trained definition (none if it has
    /// no such list), and, in `db`, a stored label DB.
    ///
    /// A detector of a timeseries model reads time series generation policies
    /// of the customer, as [`check_policy_sources`] checks them, each of the
    /// shape of the policies the model was trained on; while none of those is
    /// stored, the shape is unknown and any source is refused. A detector of
    /// a model whose recorded clustering model type is a time-series type
    /// reads only policies made from that type at that version. Any other
    /// detector reads source names of the customer.
    ///
    /// After its sources, a detector's `source_sensors` is checked, as
    /// [`check_source_sensors`] does.
    ///
    /// # Errors
    ///
    /// Returns a refusal with `SOURCE_NOT_ALLOWED`, `MODEL_NOT_OF_INSTANCE`,
    /// `INVALID_DOCUMENT`, `UNKNOWN_FIELD`, `FIELD_NOT_ALLOWED`,
    /// `BOUND_VIOLATED`, `NOT_FOUND`, `SOURCES_INCOMPATIBLE`,
    /// `DATA_STORE_NOT_INSTALLED`, `ADDRESS_OVERRIDE_FORBIDDEN` or
    /// `INDICATOR_NOT_ALLOWED`, or an error if the store cannot be read.
    pub(crate) fn check_stored(
        &self,
        text: &str,
        store: &Store,
        target: &DocumentTarget<'_>,
    ) -> Result<()> {
        let mut customer_sources = None;
        let mut completion = None;
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

            let refused = match &completion {
                Some(refused) => refused,
                None => completion.insert(self.completion_refusal(text, store, target.instance)?),
            };
            if let Some(refused @ DetectionModelsSectionError::Detector(of)) = refused
                && of.index == i
            {
                let (code, field, value) = completion_parts(refused);
                let id = detector.id;
                return Err(refusal(code, refused.to_string(), &field, value)
                    .extend_with(|_, extensions| extensions.set("detectorId", id)));
            }
            check_label_columns(store, i, detector, &model)?;

            if model.kind == TIMESERIES_KIND {
                let shape =
                    trained_shape(store, &model.name, &model.trained_sources).map_err(|e| {
                        format!(
                            "cannot read the sources model {:?} was trained on: {e:#}",
                            model.name
                        )
                    })?;
                let refused = check_policy_sources(
                    store,
                    customer_id,
                    &detector.sources,
                    shape,
                    &model.clustering_model_type,
                    None,
                    &detector.data_store.server_name,
                )
                .map_err(|e| format!("cannot read time series generation policies: {e:#}"))?;
                if let Some(refused) = refused {
                    let id = detector.id;
                    return Err(refused
                        .into_error(&format!("detectors[{i}]."))
                        .extend_with(|_, extensions| extensions.set("detectorId", id)));
                }
            } else {
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
            }
            check_source_sensors(store, i, detector, &model)?;

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

    /// Returns the refusal of a detector by the database write's completion
    /// of `text`, the text of `self`, in [`CompletionMode::Apply`], or `None`
    /// if it completes or refuses the document as a whole.
    ///
    /// The clustering model type of a model is that of its record when the
    /// model is of `instance`, and none for any other name, so the refusal of
    /// a detector whose model is not of the instance is never returned before
    /// that detector's model check. A document whose `detectors` the parse
    /// takes but the completion does not, such as an inline array of tables,
    /// has already been refused by [`check_detectors_shape`].
    fn completion_refusal(
        &self,
        text: &str,
        store: &Store,
        instance: &ModelInstance,
    ) -> Result<Option<DetectionModelsSectionError>> {
        let mut types = HashMap::new();
        for detector in &self.detectors {
            if let Some(model) = model_by_name(store, &detector.model)?
                .filter(|model| model.instance.as_ref() == Some(instance))
            {
                types.insert(detector.model.as_str(), model.clustering_model_type);
            }
        }
        let model_type = |name: &str| types.get(name).cloned();
        let sensors = policy_sensors(store)?;
        let policy_sensors = |id: u32| sensors.get(&id).cloned();
        Ok(complete_engine_document(
            AgentKind::Unsupervised,
            text,
            &model_type,
            &policy_sensors,
            CompletionMode::Apply,
        )
        .err()
        .filter(|refused| matches!(refused, DetectionModelsSectionError::Detector(_))))
    }
}

/// Refuses `text` if the database write's completion refuses it as a whole
/// although the schema parses it: its `detectors` are not written with
/// `[[detectors]]` headers, as an inline array of tables is not.
///
/// The completion checks no detection model section of such a document, so
/// without this a draft could be saved with sections no Apply would accept.
/// The code, `field` and `value` are those [`completion_parts`] gives the same
/// refusal of the database write, so the refusal does not depend on which
/// layer reports it.
fn check_detectors_shape(text: &str) -> Result<()> {
    // The shape is checked before any detector is, so no model type or
    // policy is needed.
    let no_type = |_: &str| None;
    let no_policy = |_: u32| None;
    match complete_engine_document(
        AgentKind::Unsupervised,
        text,
        &no_type,
        &no_policy,
        CompletionMode::Apply,
    ) {
        Err(refused @ DetectionModelsSectionError::DetectorsNotAnArrayOfTables) => {
            let (code, field, value) = completion_parts(&refused);
            Err(refusal(code, refused.to_string(), &field, value))
        }
        _ => Ok(()),
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

/// Returns the code, `field` and `value` of the refusal of `refused`, a
/// completion error of an Unsupervised Engine document.
///
/// `field` is the dotted path of the offence from the document root, with
/// list positions, as [`DetectorError::path`] gives it; it is empty for a
/// document that does not parse and for a `detectors` that is not an array of
/// tables. `value` is the offending value as text, as [`DetectorError::value`]
/// gives it, for a value of the wrong type, out of its range or empty, and
/// empty otherwise.
///
/// [`DetectorError::path`]: review_database::DetectorError::path
/// [`DetectorError::value`]: review_database::DetectorError::value
pub(crate) fn completion_parts(
    refused: &DetectionModelsSectionError,
) -> (RefusalCode, String, String) {
    match refused {
        DetectionModelsSectionError::Detector(detector) => (
            section_code(&detector.error),
            detector.path(),
            detector.value.clone().unwrap_or_default(),
        ),
        other => (section_code(other), String::new(), String::new()),
    }
}

/// Returns the refusal code of a completion error of an Unsupervised Engine
/// document, by what it rejects.
fn section_code(error: &DetectionModelsSectionError) -> RefusalCode {
    // No wildcard arm: an error added to review-database must be mapped.
    match error {
        DetectionModelsSectionError::InvalidToml(_)
        | DetectionModelsSectionError::DetectorsNotAnArrayOfTables
        | DetectionModelsSectionError::ModelNotAString
        | DetectionModelsSectionError::NotATable
        | DetectionModelsSectionError::SectionNotATable { .. }
        | DetectionModelsSectionError::EntryNotATable { .. }
        | DetectionModelsSectionError::TypeMismatch { .. } => RefusalCode::InvalidDocument,
        DetectionModelsSectionError::UnknownModel { .. }
        | DetectionModelsSectionError::ModelOfAnotherEngine { .. }
        | DetectionModelsSectionError::UnknownKey { .. } => RefusalCode::UnknownField,
        DetectionModelsSectionError::DisallowedModel { .. } => RefusalCode::FieldNotAllowed,
        DetectionModelsSectionError::OutOfRange { .. } => RefusalCode::BoundViolated,
        DetectionModelsSectionError::Cell(cell) => match cell.kind {
            CellErrorKind::TypeMismatch { .. } => RefusalCode::InvalidDocument,
            CellErrorKind::Unknown => RefusalCode::UnknownField,
            CellErrorKind::Missing => RefusalCode::FieldNotAllowed,
            CellErrorKind::OutOfRange { .. } | CellErrorKind::Empty => RefusalCode::BoundViolated,
        },
        // Never nested; a nested one is located by its own entry.
        DetectionModelsSectionError::Detector(detector) => section_code(&detector.error),
    }
}

/// Refuses a `columns` entry of the `label_db_match` section of detector `i`
/// whose `column_ids` lists an index outside the `format` of `model`'s
/// trained definition, or whose `db` names no stored label DB, entry by entry
/// and the column ids of an entry before its label DB.
///
/// The section has passed the completion check, so its entries are tables
/// whose `column_ids` are lists of integers of at least 0 and whose `db` are
/// strings; anything else is left to that check.
fn check_label_columns(
    store: &Store,
    i: usize,
    detector: &Detector,
    model: &ModelDigest,
) -> Result<()> {
    let Some(columns) = detector
        .detection_models
        .as_ref()
        .and_then(|sections| sections.get(LABEL_DB_MATCH))
        .and_then(toml::Value::as_table)
        .and_then(|section| section.get(COLUMNS))
        .and_then(toml::Value::as_array)
    else {
        return Ok(());
    };
    let mut columns_of_format = None;
    let label_dbs = store.label_db_map();
    for (j, entry) in columns.iter().enumerate() {
        let Some(entry) = entry.as_table() else {
            continue;
        };
        let path =
            |cell: &str| format!("{DETECTION_MODELS}.{LABEL_DB_MATCH}.{COLUMNS}[{j}].{cell}");
        let count = *columns_of_format.get_or_insert_with(|| format_len(&model.trained_definition));
        let ids = entry
            .get(COLUMN_IDS)
            .and_then(toml::Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        for id in ids.iter().filter_map(toml::Value::as_integer) {
            if !usize::try_from(id).is_ok_and(|id| id < count) {
                return Err(detector_refusal(
                    RefusalCode::BoundViolated,
                    format!(
                        "column id {id} is not an index into the {count} columns of the format \
                         model {:?} was trained with",
                        model.name
                    ),
                    i,
                    &path(COLUMN_IDS),
                    id.to_string(),
                    detector,
                ));
            }
        }
        if let Some(db) = entry.get(DB).and_then(toml::Value::as_str)
            && label_dbs
                .get(db)
                .map_err(|e| format!("cannot read label DB {db:?}: {e:#}"))?
                .is_none()
        {
            return Err(detector_refusal(
                RefusalCode::NotFound,
                format!("{db:?} is not a label DB"),
                i,
                &path(DB),
                db.to_string(),
                detector,
            ));
        }
    }
    Ok(())
}

/// Checks the `source_sensors` of detector `i`, whose model is `model` and
/// whose sources have passed the source rule.
///
/// Only a detector of a model whose recorded clustering model type is a
/// time-series type may have it; any other detector's, an empty table
/// included, is refused with `FIELD_NOT_ALLOWED`. On such a detector, each
/// key must be one of the detector's `sources`, and its list the stored
/// `sensors` of that policy, in the same order; otherwise it is refused with
/// `SOURCES_INCOMPATIBLE`. A source with no key is accepted: the completion
/// on apply writes its sensors.
fn check_source_sensors(
    store: &Store,
    i: usize,
    detector: &Detector,
    model: &ModelDigest,
) -> Result<()> {
    let Some(source_sensors) = detector.source_sensors.as_ref() else {
        return Ok(());
    };
    if time_series_type_of(&model.clustering_model_type).is_none() {
        return Err(detector_refusal(
            RefusalCode::FieldNotAllowed,
            format!(
                "{SOURCE_SENSORS} is only for a detector of a time-series type's model, which \
                 model {:?} is not",
                model.name
            ),
            i,
            SOURCE_SENSORS,
            String::new(),
            detector,
        ));
    }
    let map = store.time_series_generation_policy_map();
    for (key, sensors) in source_sensors {
        let stored = if detector.sources.contains(key) {
            match policy_id(key) {
                Some(id) => map
                    .get_by_id(id)
                    .map_err(|e| format!("cannot read time series generation policy {id}: {e:#}"))?
                    .map(|policy| policy.sensors),
                None => None,
            }
        } else {
            None
        };
        let message = match stored {
            None => format!(
                "{SOURCE_SENSORS} lists time series generation policy {key:?}, which is not a \
                 source of the detector"
            ),
            Some(stored) if stored != *sensors => format!(
                "{SOURCE_SENSORS} lists sensors for time series generation policy {key:?} \
                 that are not its sensors {stored:?}"
            ),
            Some(_) => continue,
        };
        return Err(detector_refusal(
            RefusalCode::SourcesIncompatible,
            message,
            i,
            SOURCE_SENSORS,
            key.clone(),
            detector,
        ));
    }
    Ok(())
}

/// Returns the length of the `format` list of the `[csv]` table of
/// `definition`, a trained definition, or 0 if it has no such list.
fn format_len(definition: &str) -> usize {
    definition
        .parse::<toml::Table>()
        .ok()
        .as_ref()
        .and_then(|table| table.get("csv"))
        .and_then(toml::Value::as_table)
        .and_then(|csv| csv.get("format"))
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len)
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

/// Returns the `DUPLICATE_ENTRY` refusal of detector `i` taking an id that a
/// removed detector used, carrying the store's `message`.
pub(crate) fn retired_id(i: usize, detector: &Detector, message: String) -> async_graphql::Error {
    detector_refusal(
        RefusalCode::DuplicateEntry,
        message,
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
