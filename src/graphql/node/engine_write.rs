//! The engine documents of a node write and the node guards (RFC 0006 §5.3,
//! §5.11).
//!
//! `insertNode`, `updateNodeDraft`, `applyNode` and `applyNodeDraft` validate
//! the Unsupervised Engine documents they write and refuse a customer or
//! hostname change that would strand a model or a source reference. The
//! steps run around the engine configuration lock: [`lookup_addrs`],
//! [`check_agent_keys`] and [`check_duplicate_keys`] need only the request
//! and run before it; everything else reads the store and runs with it held,
//! through the store write.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::IpAddr,
};

use async_graphql::{Context, Error, ErrorExtensions, Result};
use review_database::{
    Agent, AgentConfig, AgentKind, CellErrorKind, ClusteringModelTypeRef, CompletionMode,
    DetectionModelsSectionError, DetectorError, EngineDocumentError, EngineDocumentWrite,
    ModelInstance, Node, NodeProfile, NodeUpdate, Referrer, Store, complete_engine_document,
};

use crate::graphql::{
    customer_access::model_by_name,
    engine_document::{
        Detector, DocumentTarget, EngineDocument, duplicate_id, duplicate_model,
        indicator_not_allowed, kept_pairs, model_not_of_instance, retired_id,
    },
    refusal::{RefusalCode, refusal},
    unsupervised::data_store_addrs,
};

/// The refusal of a write made from a node that is no longer the stored one.
pub(super) const STALE_NODE: &str = "the node changed since it was read; reload and retry";

/// Which document of an agent a node write changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Slot {
    /// The draft, as `updateNodeDraft` writes it.
    Draft,
    /// The config, as Apply writes it from the draft.
    Config,
}

impl Slot {
    fn of(self, agent: &Agent) -> Option<&AgentConfig> {
        match self {
            Self::Draft => agent.draft.as_ref(),
            Self::Config => agent.config.as_ref(),
        }
    }
}

/// An Unsupervised Engine agent whose document a node write changes, with
/// the document validated.
pub(super) struct ChangedDocument {
    agent_key: String,
    /// `None` for an agent whose document is `None`.
    document: Option<EngineDocument>,
}

/// An Unsupervised Engine draft of a draft save that is not TOML, refused
/// only once the request is known not to be stale.
pub(super) struct NotToml {
    pub(super) agent_key: String,
    /// The `INVALID_DOCUMENT` refusal of the draft.
    pub(super) refusal: Error,
}

/// Returns the Unsupervised Engine agents of `new` whose `slot` document
/// differs from `old`'s, a new agent included; the request alone decides
/// them.
fn requested_changes<'a>(
    old: &NodeUpdate,
    new: &'a NodeUpdate,
    slot: Slot,
) -> impl Iterator<Item = &'a Agent> {
    new.agents
        .iter()
        .filter(|agent| agent.kind == AgentKind::Unsupervised)
        .filter(move |agent| {
            old.agents
                .iter()
                .find(|old_agent| old_agent.key == agent.key)
                .is_none_or(|old_agent| slot.of(old_agent) != slot.of(agent))
        })
}

/// Looks up, before the engine configuration lock is taken, the addresses
/// of every Data Store a document the request changes names.
///
/// After the stale check of [`changed_agents`], the documents that differ
/// from `old`'s are exactly the listed ones, so these cover them.
pub(super) async fn lookup_addrs(
    ctx: &Context<'_>,
    old: &NodeUpdate,
    new: &NodeUpdate,
    slot: Slot,
) -> HashMap<String, Vec<IpAddr>> {
    let mut server_names = BTreeSet::new();
    for agent in requested_changes(old, new, slot) {
        if let Some(text) = slot.of(agent)
            && let Ok(document) = toml::from_str::<EngineDocument>(text.as_ref())
        {
            server_names.extend(document.server_names().into_iter().map(str::to_string));
        }
    }
    let mut addrs = HashMap::new();
    for server_name in server_names {
        let resolved = data_store_addrs(ctx, &server_name).await;
        addrs.insert(server_name, resolved);
    }
    addrs
}

/// Refuses an Unsupervised Engine draft that is not TOML with
/// `INVALID_DOCUMENT`, its `field` empty and the parser's message in `value`.
///
/// # Errors
///
/// Returns the `INVALID_DOCUMENT` refusal.
pub(super) fn check_toml(text: &str) -> Result<()> {
    match text.parse::<toml::Table>() {
        Ok(_) => Ok(()),
        Err(e) => Err(refusal(
            RefusalCode::InvalidDocument,
            format!("invalid engine document: {}", e.message()),
            "",
            e.message(),
        )),
    }
}

/// Returns the agent keys of the Unsupervised Engine agents of `update`.
pub(super) fn engine_keys(update: &NodeUpdate) -> Vec<&str> {
    update
        .agents
        .iter()
        .filter(|agent| agent.kind == AgentKind::Unsupervised)
        .map(|agent| agent.key.as_str())
        .collect()
}

/// Refuses, before the lock, a write that changes an agent's kind to or from
/// Unsupervised, or that lists an Unsupervised Engine agent key more than
/// once.
///
/// # Errors
///
/// Returns a plain error naming the agent key.
pub(super) fn check_agent_keys(old: &NodeUpdate, new: &NodeUpdate) -> Result<()> {
    for agent in &new.agents {
        let rekinded = old.agents.iter().any(|old_agent| {
            old_agent.key == agent.key
                && old_agent.kind != agent.kind
                && (old_agent.kind == AgentKind::Unsupervised
                    || agent.kind == AgentKind::Unsupervised)
        });
        if rekinded {
            return Err(kind_changed(&agent.key));
        }
    }
    check_duplicate_keys(&new.agents)
}

/// Refuses, before the lock, `agents` that list an Unsupervised Engine agent
/// key more than once.
///
/// # Errors
///
/// Returns a plain error naming the agent key.
pub(super) fn check_duplicate_keys(agents: &[Agent]) -> Result<()> {
    for agent in agents
        .iter()
        .filter(|agent| agent.kind == AgentKind::Unsupervised)
    {
        if agents.iter().filter(|a| a.key == agent.key).count() > 1 {
            return Err(duplicate_agent_key(&agent.key));
        }
    }
    Ok(())
}

fn kind_changed(agent_key: &str) -> Error {
    Error::new(format!(
        "agent `{agent_key}` cannot change its kind to or from Unsupervised"
    ))
}

fn duplicate_agent_key(agent_key: &str) -> Error {
    Error::new(format!("agent key `{agent_key}` is listed more than once"))
}

/// Returns the Unsupervised Engine agents of `new` whose `slot` document the
/// write changes, with the lock held: those whose document differs from the
/// stored one or from `old`'s.
///
/// Refuses with [`STALE_NODE`] a listed agent kept from `old` whose `old`
/// document is not the stored one: its draft for [`Slot::Draft`], its config
/// or draft for [`Slot::Config`]. An agent whose stored row is gone or is not
/// Unsupervised counts as changed.
///
/// # Errors
///
/// Returns [`STALE_NODE`] for a stale agent.
pub(super) fn changed_agents<'a>(
    stored: &Node,
    old: &NodeUpdate,
    new: &'a NodeUpdate,
    slot: Slot,
) -> Result<Vec<&'a Agent>> {
    let mut changed = Vec::new();
    for agent in new
        .agents
        .iter()
        .filter(|agent| agent.kind == AgentKind::Unsupervised)
    {
        let stored_agent = stored
            .agents
            .iter()
            .find(|stored| stored.key == agent.key && stored.kind == AgentKind::Unsupervised);
        let old_agent = old.agents.iter().find(|old| old.key == agent.key);
        let differs_from_stored = stored_agent.is_none_or(|s| slot.of(s) != slot.of(agent));
        let differs_from_old = old_agent.is_none_or(|o| slot.of(o) != slot.of(agent));
        if !differs_from_stored && !differs_from_old {
            continue;
        }
        if old_agent.is_some_and(|old_agent| is_stale(stored, old_agent, slot)) {
            return Err(STALE_NODE.into());
        }
        changed.push(agent);
    }
    Ok(changed)
}

/// Returns whether the `old` agent `old_agent` is not the stored one: its
/// draft for [`Slot::Draft`], its config or draft for [`Slot::Config`]. An
/// agent whose stored row is gone or is not Unsupervised counts as changed.
fn is_stale(stored: &Node, old_agent: &Agent, slot: Slot) -> bool {
    stored
        .agents
        .iter()
        .find(|stored| stored.key == old_agent.key && stored.kind == AgentKind::Unsupervised)
        .is_none_or(|s| match slot {
            Slot::Draft => s.draft != old_agent.draft,
            Slot::Config => s.config != old_agent.config || s.draft != old_agent.draft,
        })
}

/// Refuses, with the lock held and before any document is validated, a
/// draft save with an Unsupervised Engine draft that is not TOML.
///
/// Such a draft differs from its `old` one, so its agent is listed: the save
/// is refused with [`STALE_NODE`] when one of them is kept from `old` and its
/// `old` draft is not the stored one, like any listed agent, and otherwise
/// with the first one's `INVALID_DOCUMENT` refusal.
///
/// # Errors
///
/// Returns [`STALE_NODE`] or the `INVALID_DOCUMENT` refusal.
pub(super) fn check_not_toml(
    stored: &Node,
    old: &NodeUpdate,
    not_toml: Vec<NotToml>,
) -> Result<()> {
    let stale = not_toml.iter().any(|draft| {
        old.agents
            .iter()
            .find(|old_agent| old_agent.key == draft.agent_key)
            .is_some_and(|old_agent| is_stale(stored, old_agent, Slot::Draft))
    });
    if stale {
        return Err(STALE_NODE.into());
    }
    match not_toml.into_iter().next() {
        Some(first) => Err(first.refusal),
        None => Ok(()),
    }
}

/// Validates the `slot` document of each of `agents` of node `node_id` with
/// every rule of RFC 0006 §5.3, with the lock held.
///
/// The instance's customer is the stored node's applied `customer_id`, and
/// the Data Store rule keeps every pair of the stored agent's draft and
/// config.
///
/// # Errors
///
/// Returns the first refusal of a document, or an error if the store cannot
/// be read.
pub(super) fn validate_documents(
    store: &Store,
    node_id: u32,
    stored: &Node,
    agents: &[&Agent],
    slot: Slot,
    addrs: &HashMap<String, Vec<IpAddr>>,
    system_admin: bool,
) -> Result<Vec<ChangedDocument>> {
    let customer_id = stored.profile.as_ref().map(|profile| profile.customer_id);
    let mut documents = Vec::with_capacity(agents.len());
    for agent in agents {
        let document = match slot.of(agent) {
            Some(text) => {
                let document = EngineDocument::parse_and_validate(text.as_ref())?;
                let stored_agent = stored.agents.iter().find(|s| s.key == agent.key);
                let kept = kept_pairs(
                    stored_agent
                        .into_iter()
                        .flat_map(|s| [s.draft.as_ref(), s.config.as_ref()])
                        .flatten()
                        .map(AsRef::as_ref),
                );
                let instance = ModelInstance {
                    node_id,
                    agent_key: agent.key.clone(),
                };
                document.check_stored(
                    store,
                    &DocumentTarget {
                        instance: &instance,
                        customer_id,
                        addrs,
                        kept: &kept,
                        system_admin,
                    },
                )?;
                Some(document)
            }
            None => None,
        };
        documents.push(ChangedDocument {
            agent_key: agent.key.clone(),
            document,
        });
    }
    Ok(documents)
}

/// Validates the draft of each Unsupervised Engine agent of a new node, which
/// has no applied profile, so a document with any detector is refused.
///
/// # Errors
///
/// Returns the first refusal of a document, or an error if the store cannot
/// be read.
pub(super) fn validate_new_node_documents(store: &Store, agents: &[Agent]) -> Result<()> {
    for agent in agents
        .iter()
        .filter(|agent| agent.kind == AgentKind::Unsupervised)
    {
        if let Some(text) = agent.draft.as_ref() {
            let document = EngineDocument::parse_and_validate(text.as_ref())?;
            let instance = ModelInstance {
                node_id: u32::MAX,
                agent_key: agent.key.clone(),
            };
            document.check_stored(
                store,
                &DocumentTarget {
                    instance: &instance,
                    customer_id: None,
                    addrs: &HashMap::new(),
                    kept: &HashSet::new(),
                    system_admin: false,
                },
            )?;
        }
    }
    Ok(())
}

/// Returns the references to write for `documents`: the pending slot for a
/// draft save, and both slots for Apply, which leaves the draft as it is.
pub(super) fn document_writes(
    documents: &[ChangedDocument],
    slot: Slot,
) -> Vec<EngineDocumentWrite> {
    documents
        .iter()
        .map(|changed| {
            let refs = changed
                .document
                .as_ref()
                .map_or_default(EngineDocument::refs);
            match slot {
                Slot::Draft => EngineDocumentWrite {
                    agent_key: changed.agent_key.clone(),
                    applied: None,
                    pending: Some(refs),
                },
                Slot::Config => EngineDocumentWrite {
                    agent_key: changed.agent_key.clone(),
                    applied: Some(refs.clone()),
                    pending: Some(refs),
                },
            }
        })
        .collect()
}

/// Maps a refusal of `NodeTable::update_with_engine_documents`.
///
/// The [`EngineDocumentError`]s of a document become the codes the resolver's
/// own checks return, with `field` and `detectorId` from `documents`; a stale
/// or a refused request becomes a plain error; the refusals that only a bug
/// of this resolver can cause, and every other error, pass through as
/// internal errors carrying the store's message.
pub(super) fn store_refusal(
    error: anyhow::Error,
    old: &NodeUpdate,
    documents: &[ChangedDocument],
) -> Error {
    let Some(refused) = error.downcast_ref::<EngineDocumentError>() else {
        return error.into();
    };
    let detectors = |agent_key: &str| -> &[Detector] {
        documents
            .iter()
            .find(|changed| changed.agent_key == agent_key)
            .and_then(|changed| changed.document.as_ref())
            .map_or(&[], |document| document.detectors.as_slice())
    };
    let mapped = match refused {
        EngineDocumentError::ModelNotFound { agent_key, model }
        | EngineDocumentError::ModelOfAnotherInstance { agent_key, model } => Some(
            match find_detector(detectors(agent_key), |d| d.model == *model) {
                Some((i, detector)) => model_not_of_instance(i, detector),
                None => unnamed(RefusalCode::ModelNotOfInstance, model),
            },
        ),
        EngineDocumentError::DuplicateModel { agent_key, model } => Some(
            match find_detector(detectors(agent_key), |d| d.model == *model) {
                Some((i, detector)) => duplicate_model(i, detector),
                None => unnamed(RefusalCode::DuplicateEntry, model),
            },
        ),
        EngineDocumentError::DuplicateDetectorId {
            agent_key,
            detector_id,
        } => Some(
            match find_detector(detectors(agent_key), |d| d.id == *detector_id) {
                Some((i, detector)) => duplicate_id(i, detector),
                None => unnamed(RefusalCode::DuplicateEntry, &detector_id.to_string()),
            },
        ),
        EngineDocumentError::DetectorIdRetired {
            agent_key,
            detector_id,
        } => Some(
            match find_detector(detectors(agent_key), |d| d.id == *detector_id) {
                Some((i, detector)) => retired_id(i, detector, refused.to_string()),
                None => unnamed(RefusalCode::DuplicateEntry, &detector_id.to_string()),
            },
        ),
        EngineDocumentError::IndicatorNotFound {
            agent_key,
            indicator,
        } => Some(
            match find_detector(detectors(agent_key), |d| {
                d.suspicious_tokens.as_ref() == Some(indicator)
            }) {
                Some((i, detector)) => indicator_not_allowed(i, detector),
                None => unnamed(RefusalCode::IndicatorNotAllowed, indicator),
            },
        ),
        EngineDocumentError::StaleDocument { .. } => Some(STALE_NODE.into()),
        EngineDocumentError::NotUnsupervisedAgent { agent_key, .. }
            if old.agents.iter().any(|agent| agent.key == *agent_key) =>
        {
            Some(STALE_NODE.into())
        }
        EngineDocumentError::KindChanged { agent_key } => Some(kind_changed(agent_key)),
        EngineDocumentError::DuplicateAgentKey { agent_key } => {
            Some(duplicate_agent_key(agent_key))
        }
        _ => None,
    };
    mapped.unwrap_or_else(|| error.into())
}

/// Maps a refusal of a node write that completion of an engine document
/// caused, or returns `None` for any other error.
///
/// The store names the refused agent only in a context message, which is not
/// parsed: the agent is found by completing again, in
/// [`CompletionMode::Apply`], the `config` of each Semi-supervised or
/// Unsupervised Engine agent of `new` whose `config` the write changes from
/// `stored`, in `new`'s order, and taking the first whose error equals the
/// store's. Should none match, which needs `stored` to have changed under the
/// write, every such agent of `new` is tried in the same way; should none of
/// them match either, the error is left to the caller.
///
/// The clustering model type of a model an Unsupervised Engine document
/// names is that of the stored model record of that name, and none when
/// there is no record or it cannot be read. The completed documents only
/// attribute the refusal; none is stored.
pub(super) fn completion_refusal(
    error: &anyhow::Error,
    store: &Store,
    stored: &Node,
    new: &NodeUpdate,
) -> Option<Error> {
    let refused = error.downcast_ref::<DetectionModelsSectionError>()?;
    let model_type = |name: &str| -> Option<ClusteringModelTypeRef> {
        model_by_name(store, name)
            .ok()
            .flatten()
            .map(|model| model.clustering_model_type)
    };
    let fails_alike = |agent: &&Agent| {
        matches!(
            agent.kind,
            AgentKind::SemiSupervised | AgentKind::Unsupervised
        ) && agent.config.as_ref().is_some_and(|config| {
            complete_engine_document(
                agent.kind,
                config.as_ref(),
                &model_type,
                CompletionMode::Apply,
            )
            .err()
            .as_ref()
                == Some(refused)
        })
    };
    let changes_config = |agent: &&Agent| {
        stored
            .agents
            .iter()
            .find(|stored_agent| stored_agent.key == agent.key)
            .is_none_or(|stored_agent| {
                stored_agent.kind != agent.kind || stored_agent.config != agent.config
            })
    };
    let agent = new
        .agents
        .iter()
        .filter(changes_config)
        .find(fails_alike)
        .or_else(|| new.agents.iter().find(fails_alike))?;
    Some(if agent.kind == AgentKind::Unsupervised {
        unsupervised_refusal(refused, &agent.key)
    } else {
        let document = agent.config.as_ref().map_or("", AsRef::as_ref);
        detection_models_refusal(refused, &agent.key, document)
    })
}

/// Returns the refusal of `refused`, the completion error of the
/// Semi-supervised Engine document `document` of agent `agent_key`, with the
/// extension `agentKey`.
///
/// `field` is the dotted path of the offending part, empty for a document
/// that does not parse. `value` is the parser's message for such a
/// document, the offending value as TOML for a value of the wrong type or
/// out of range, and empty otherwise.
///
/// The errors that only an Unsupervised Engine document yields map as
/// [`unsupervised_refusal`] maps them; completion of a Semi-supervised
/// Engine document never returns one.
pub(super) fn detection_models_refusal(
    refused: &DetectionModelsSectionError,
    agent_key: &str,
    document: &str,
) -> Error {
    const SECTION: &str = "detection_models";
    let (code, field, value) = match refused {
        DetectionModelsSectionError::InvalidToml(message) => {
            (RefusalCode::InvalidDocument, String::new(), message.clone())
        }
        DetectionModelsSectionError::NotATable => (
            RefusalCode::InvalidDocument,
            SECTION.to_string(),
            String::new(),
        ),
        DetectionModelsSectionError::SectionNotATable { section } => (
            RefusalCode::InvalidDocument,
            format!("{SECTION}.{section}"),
            String::new(),
        ),
        DetectionModelsSectionError::TypeMismatch { section, key, .. } => (
            RefusalCode::InvalidDocument,
            format!("{SECTION}.{section}.{key}"),
            operator_value(document, section, key).unwrap_or_default(),
        ),
        DetectionModelsSectionError::UnknownModel { section }
        | DetectionModelsSectionError::ModelOfAnotherEngine { section, .. } => (
            RefusalCode::UnknownField,
            format!("{SECTION}.{section}"),
            String::new(),
        ),
        DetectionModelsSectionError::UnknownKey { section, key } => (
            RefusalCode::UnknownField,
            format!("{SECTION}.{section}.{key}"),
            String::new(),
        ),
        DetectionModelsSectionError::OutOfRange {
            section,
            key,
            value,
            ..
        } => (
            RefusalCode::BoundViolated,
            format!("{SECTION}.{section}.{key}"),
            value.clone(),
        ),
        DetectionModelsSectionError::EntryNotATable { .. }
        | DetectionModelsSectionError::Cell(_)
        | DetectionModelsSectionError::DetectorsNotAnArrayOfTables
        | DetectionModelsSectionError::ModelNotAString
        | DetectionModelsSectionError::DisallowedModel { .. }
        | DetectionModelsSectionError::Detector(_) => {
            return unsupervised_refusal(refused, agent_key);
        }
    };
    let agent_key = agent_key.to_string();
    refusal(code, refused.to_string(), &field, value)
        .extend_with(|_, extensions| extensions.set("agentKey", agent_key.as_str()))
}

/// Returns the refusal of `refused`, the completion error of the
/// Unsupervised Engine document of agent `agent_key`, with the extension
/// `agentKey`.
///
/// `field` is the dotted path of the offence from the document root, with
/// list positions, as [`DetectorError::path`] gives it; it is empty for a
/// document that does not parse and for a `detectors` that is not an array
/// of tables. `value` is the offending value as text, as
/// [`DetectorError::value`] gives it, for a value of the wrong type, out of
/// its range or empty, and empty otherwise.
pub(super) fn unsupervised_refusal(
    refused: &DetectionModelsSectionError,
    agent_key: &str,
) -> Error {
    let (code, field, value) = match refused {
        DetectionModelsSectionError::Detector(detector) => (
            detector_code(detector),
            detector.path(),
            detector.value.clone().unwrap_or_default(),
        ),
        other => (section_code(other), String::new(), String::new()),
    };
    let agent_key = agent_key.to_string();
    refusal(code, refused.to_string(), &field, value)
        .extend_with(|_, extensions| extensions.set("agentKey", agent_key.as_str()))
}

/// Returns the refusal code of the rejection of a `[[detectors]]` entry.
fn detector_code(detector: &DetectorError) -> RefusalCode {
    section_code(&detector.error)
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
        DetectionModelsSectionError::Detector(detector) => detector_code(detector),
    }
}

/// Returns the value at `detection_models.<section>.<key>` of `document`,
/// written as a TOML value, or `None` if there is none.
fn operator_value(document: &str, section: &str, key: &str) -> Option<String> {
    let table = document.parse::<toml::Table>().ok()?;
    let value = table
        .get("detection_models")?
        .as_table()?
        .get(section)?
        .as_table()?
        .get(key)?;
    Some(value.to_string().trim().to_string())
}

/// Returns the last detector that `matches`, with its index: for a repeated
/// id or model, the detector that repeats it.
fn find_detector(
    detectors: &[Detector],
    matches: impl Fn(&Detector) -> bool,
) -> Option<(usize, &Detector)> {
    detectors
        .iter()
        .enumerate()
        .filter(|(_, detector)| matches(detector))
        .last()
}

/// Returns a refusal of the store naming `value` that the resolver's own
/// parse cannot place in the document, with an empty `field`.
fn unnamed(code: RefusalCode, value: &str) -> Error {
    let message = if code == RefusalCode::ModelNotOfInstance {
        format!("{value:?} is not a model of this engine instance")
    } else {
        format!("the engine document refers to {value:?}, which it may not")
    };
    refusal(code, message, "", value)
}

/// Applies the node guards of RFC 0006 §5.11 to a write of node `node_id`
/// (`None` for a new node) whose resulting profile is `resulting`, from the
/// stored applied profile `applied`, with the lock held.
///
/// `engines` are the agent keys of the node's Unsupervised Engine agents after
/// the write; the store detaches the records of one the write removes.
///
/// # Errors
///
/// Returns a `CUSTOMER_CHANGE_REFUSED` refusal, or an error if the store
/// cannot be read.
pub(super) fn check_node_guards(
    store: &Store,
    node_id: Option<u32>,
    engines: &[&str],
    applied: Option<&NodeProfile>,
    resulting: Option<&NodeProfile>,
    system_admin: bool,
) -> Result<()> {
    let customer_changed =
        applied.map(|profile| profile.customer_id) != resulting.map(|profile| profile.customer_id);
    if customer_changed && let Some(node_id) = node_id {
        check_owned_models(store, node_id, engines)?;
    }
    match resulting.filter(|profile| !profile.hostname.is_empty()) {
        Some(resulting) => check_source_holders(store, applied, resulting, system_admin),
        None => Ok(()),
    }
}

/// Refuses a customer change of node `node_id` while one of its engine
/// instances `engines` owns a model or a training definition.
fn check_owned_models(store: &Store, node_id: u32, engines: &[&str]) -> Result<()> {
    for agent_key in engines {
        let instance = ModelInstance {
            node_id,
            agent_key: (*agent_key).to_string(),
        };
        if let Some(owned) = store.engine_instance_owns_models(&instance)?.first() {
            return Err(refusal(
                RefusalCode::CustomerChangeRefused,
                format!(
                    "engine instance `{agent_key}` of node {node_id} owns {owned:?}, so the \
                     node's customer cannot change"
                ),
                "customer_id",
                owned.as_str(),
            ));
        }
    }
    Ok(())
}

/// Refuses a write whose resulting customer or hostname differs from the
/// applied one while an engine document or a training definition of another
/// customer lists `piglet.<hostname>` or `reproduce.<hostname>` of the
/// resulting hostname.
///
/// The names are built from the hostname whether or not the node has a
/// Sensor or a Log Collector, so removing one first does not lift the guard.
/// Only a System Administrator gets the holder named.
fn check_source_holders(
    store: &Store,
    applied: Option<&NodeProfile>,
    resulting: &NodeProfile,
    system_admin: bool,
) -> Result<()> {
    let unchanged = applied.is_some_and(|profile| {
        profile.customer_id == resulting.customer_id && profile.hostname == resulting.hostname
    });
    if unchanged {
        return Ok(());
    }
    let field = if applied.is_some_and(|profile| profile.customer_id == resulting.customer_id) {
        "hostname"
    } else {
        "customer_id"
    };
    let names: Vec<String> = [AgentKind::Sensor, AgentKind::LogCollector]
        .into_iter()
        .filter_map(|kind| kind.package_id())
        .map(|service| format!("{service}.{}", resulting.hostname))
        .collect();
    let mut node_customers = HashMap::new();
    for reference in store.source_references(&names)? {
        let holder_customer = match &reference.by {
            Referrer::Detector { instance, .. } => {
                if let Some(customer) = node_customers.get(&instance.node_id) {
                    *customer
                } else {
                    let customer = store
                        .node_map()
                        .get_by_id(instance.node_id)?
                        .and_then(|(node, _, _)| node.profile)
                        .map(|profile| profile.customer_id);
                    node_customers.insert(instance.node_id, customer);
                    customer
                }
            }
            Referrer::Definition { name } => store
                .training_definition(name)?
                .map(|definition| definition.customer_id),
        };
        if holder_customer != Some(resulting.customer_id) {
            return Err(holder_refusal(
                &reference.source,
                &reference.by,
                field,
                system_admin,
            ));
        }
    }
    Ok(())
}

/// Returns the `CUSTOMER_CHANGE_REFUSED` refusal of `source`, listed by
/// `holder` of another customer, naming the holder only to a System
/// Administrator.
fn holder_refusal(source: &str, holder: &Referrer, field: &str, system_admin: bool) -> Error {
    if !system_admin {
        return refusal(
            RefusalCode::CustomerChangeRefused,
            format!(
                "{source:?} is listed by an engine configuration or a training definition of \
                 another customer"
            ),
            field,
            source,
        );
    }
    match holder {
        Referrer::Detector {
            instance,
            detector_id,
        } => refusal(
            RefusalCode::CustomerChangeRefused,
            format!(
                "{source:?} is listed by detector {detector_id} of engine instance `{}` of node \
                 {}, of another customer",
                instance.agent_key, instance.node_id
            ),
            field,
            source,
        )
        .extend_with(|_, extensions| {
            extensions.set("detectorId", *detector_id);
            extensions.set("nodeId", instance.node_id.to_string());
            extensions.set("agentKey", instance.agent_key.as_str());
        }),
        Referrer::Definition { name } => refusal(
            RefusalCode::CustomerChangeRefused,
            format!("{source:?} is listed by training definition {name:?}, of another customer"),
            field,
            source,
        )
        .extend_with(|_, extensions| extensions.set("definition", name.as_str())),
    }
}

#[cfg(test)]
mod tests;
