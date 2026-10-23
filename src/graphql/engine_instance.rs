//! The operations on an Unsupervised Engine instance (RFC 0006 §5.8): running
//! a detector once, starting and stopping the instance, and reading its
//! stopped state and its detectors' statuses.
//!
//! None of these takes the engine configuration lock: they write nothing to
//! the store and check no reference. The stopped state is written only by the
//! [`AgentManager`](crate::backend::AgentManager), after the Host Agent
//! confirms a start or a stop.

use async_graphql::{
    Context, Enum, ErrorExtensions, Object, Result, SimpleObject, StringNumber, types::ID,
};
use chrono::{DateTime, Utc};
use review_database as database;
use tracing::info;

use super::{
    Role, RoleGuard, SharedAgentManager,
    customer_access::{load_accessible_node, users_customers},
    gen_agent_lookup_key,
    refusal::{RefusalCode, refusal},
    training::{TargetInstance, relay_refusal, resolve_instance},
};
use crate::info_with_username;

#[derive(Default)]
pub(super) struct EngineInstanceQuery;

#[Object]
impl EngineInstanceQuery {
    /// The engine instance `agentKey` of node `nodeId`: whether it is
    /// stopped, and the last status each of its detectors reported.
    ///
    /// Scope is the node's customer: a node of none of the caller's customers
    /// is refused with `Forbidden`, and an unknown node with `no such node`.
    ///
    /// Refusals carry `extensions.code`: `INSTANCE_NOT_ELIGIBLE` unless
    /// `agentKey` is an installed Unsupervised Engine instance of the node and
    /// the node has an applied profile with a hostname.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn engine_instance(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        agent_key: String,
    ) -> Result<EngineInstance> {
        let target = eligible_instance(ctx, &node_id, &agent_key)?;
        let store = super::get_store(ctx)?;
        let stopped = store.engine_instance_state(&target.instance)?.stopped;
        let detectors = store
            .detector_statuses(&target.instance)?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(EngineInstance {
            node_id: ID(target.instance.node_id.to_string()),
            agent_key,
            stopped,
            detectors,
        })
    }
}

#[derive(Default)]
pub(super) struct EngineInstanceMutation;

#[Object]
impl EngineInstanceMutation {
    /// Asks the engine instance `agentKey` of node `nodeId` to run one round
    /// of its detector `detectorId` now, returning `true` once the instance
    /// accepts.
    ///
    /// A detector of the applied document is relayed whether or not it is
    /// enabled. Scope is the node's customer: a node of none of the caller's
    /// customers is refused with `Forbidden`, and an unknown node with
    /// `no such node`.
    ///
    /// Refusals carry `extensions.code`: `INSTANCE_NOT_ELIGIBLE`;
    /// `INSTANCE_STOPPED` for a stopped instance; `DETECTOR_NOT_FOUND` for a
    /// `detectorId` that is not an id of the applied document, with
    /// `detectorId` when it is an integer; and, with `detectorId`,
    /// `ENGINE_REFUSED` with the engine's reason in `value` (a round is
    /// running, or the detector is paused for a run) or
    /// `INSTANCE_UNREACHABLE` when the request did not reach the instance or
    /// the instance was stopped meanwhile.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn run_detector_once(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        agent_key: String,
        detector_id: ID,
    ) -> Result<bool> {
        let (agent_lookup_key, id) = {
            let target = eligible_instance(ctx, &node_id, &agent_key)?;
            let store = super::get_store(ctx)?;
            let state = store.engine_instance_state(&target.instance)?;
            if state.stopped {
                return Err(refusal(
                    RefusalCode::InstanceStopped,
                    format!(
                        "engine instance {agent_key:?} of node {} is stopped",
                        target.instance.node_id
                    ),
                    "agentKey",
                    agent_key.as_str(),
                ));
            }
            let not_found = || {
                refusal(
                    RefusalCode::DetectorNotFound,
                    format!(
                        "detector {} is not in the applied document of engine instance \
                         {agent_key:?} of node {}",
                        detector_id.as_str(),
                        target.instance.node_id
                    ),
                    "detectorId",
                    detector_id.as_str(),
                )
            };
            let id = detector_id
                .as_str()
                .parse::<i32>()
                .map_err(|_| not_found())?;
            if !state.applied.detectors.iter().any(|d| d.id == id) {
                return Err(not_found().extend_with(|_, e| e.set("detectorId", id)));
            }
            (gen_agent_lookup_key(&agent_key, &target.hostname), id)
        };

        let agent_manager = ctx.data::<SharedAgentManager>()?;
        info_with_username!(
            ctx,
            "Run once request of detector {id} sent to {agent_lookup_key}"
        );
        agent_manager
            .run_detector_once(&agent_lookup_key, id)
            .await
            .map_err(|e| {
                relay_refusal(&e, "detectorId", &agent_lookup_key)
                    .extend_with(|_, e| e.set("detectorId", id))
            })?;
        Ok(true)
    }

    /// Starts the engine instance `agentKey` of node `nodeId` through the
    /// node's Host Agent, returning `true` once the Host Agent confirms.
    ///
    /// The instance fetches its engine document itself when it starts. Scope
    /// is the node's customer: a node of none of the caller's customers is
    /// refused with `Forbidden`, and an unknown node with `no such node`.
    ///
    /// Refusals carry `extensions.code`: `INSTANCE_NOT_ELIGIBLE`, and
    /// `INSTANCE_UNREACHABLE` when the start did not complete, with the
    /// backend's error text as the message.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn start_engine_instance(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        agent_key: String,
    ) -> Result<bool> {
        let node_id = eligible_instance(ctx, &node_id, &agent_key)?
            .instance
            .node_id;
        let agent_manager = ctx.data::<SharedAgentManager>()?;
        info_with_username!(
            ctx,
            "Start request of engine instance {agent_key} sent to node {node_id}"
        );
        agent_manager
            .start_engine_instance(node_id, &agent_key)
            .await
            .map_err(|e| unit_refusal(&e, &agent_key))?;
        Ok(true)
    }

    /// Stops and disables the engine instance `agentKey` of node `nodeId`
    /// through the node's Host Agent, returning `true` once the Host Agent
    /// confirms.
    ///
    /// Scope is the node's customer: a node of none of the caller's customers
    /// is refused with `Forbidden`, and an unknown node with `no such node`.
    ///
    /// Refusals carry `extensions.code`: `INSTANCE_NOT_ELIGIBLE`, and
    /// `INSTANCE_UNREACHABLE` when the stop did not complete, with the
    /// backend's error text as the message.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn stop_engine_instance(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        agent_key: String,
    ) -> Result<bool> {
        let node_id = eligible_instance(ctx, &node_id, &agent_key)?
            .instance
            .node_id;
        let agent_manager = ctx.data::<SharedAgentManager>()?;
        info_with_username!(
            ctx,
            "Stop request of engine instance {agent_key} sent to node {node_id}"
        );
        agent_manager
            .stop_engine_instance(node_id, &agent_key)
            .await
            .map_err(|e| unit_refusal(&e, &agent_key))?;
        Ok(true)
    }
}

/// Loads node `node_id` within the caller's scope and resolves its engine
/// instance `agent_key`.
///
/// Refuses an unknown node with `no such node`, a node of none of the
/// caller's customers with `Forbidden`, and an instance that is not eligible
/// with `INSTANCE_NOT_ELIGIBLE`, before anything reads the instance's
/// records.
fn eligible_instance(ctx: &Context<'_>, node_id: &ID, agent_key: &str) -> Result<TargetInstance> {
    let node = load_accessible_node(ctx, node_id)?;
    let users_customers = users_customers(ctx)?;
    let store = super::get_store(ctx)?;
    resolve_instance(&store, users_customers.as_deref(), node.id, agent_key)
}

/// Returns the `INSTANCE_UNREACHABLE` refusal of a start or stop of the
/// instance `agent_key` that did not complete, with the error's text as the
/// message.
fn unit_refusal(error: &anyhow::Error, agent_key: &str) -> async_graphql::Error {
    refusal(
        RefusalCode::InstanceUnreachable,
        format!("{error:#}"),
        "agentKey",
        agent_key,
    )
}

/// An Unsupervised Engine instance's stopped state and detector statuses.
#[derive(SimpleObject)]
struct EngineInstance {
    /// The node of the instance.
    node_id: ID,
    /// The key of the instance's agent on the node.
    agent_key: String,
    /// Whether the instance is stopped.
    stopped: bool,
    /// The last status of each detector that has reported one, ordered by
    /// detector id.
    detectors: Vec<DetectorStatus>,
}

/// The status a detector of an engine instance last reported.
#[derive(SimpleObject)]
struct DetectorStatus {
    /// The detector's id in the engine document.
    detector_id: ID,
    /// The detector's state, which says why it does not run if it does not.
    state: DetectorState,
    /// When the detector's last round finished, or null before its first.
    finished_at: Option<DateTime<Utc>>,
    /// The outcome of the detector's last round, or null before its first.
    outcome: Option<RoundOutcome>,
    /// The failure reason of the detector's last round.
    reason: Option<String>,
    /// The number of events the detector's last round analysed.
    events: StringNumber<u64>,
    /// The state of each of the detector's sources in its last round.
    sources: Vec<DetectorSourceStatus>,
    /// When the Central Manager stored the report.
    reported_at: DateTime<Utc>,
}

impl From<(i32, database::DetectorStatus)> for DetectorStatus {
    fn from((detector_id, status): (i32, database::DetectorStatus)) -> Self {
        Self {
            detector_id: ID(detector_id.to_string()),
            state: status.state.into(),
            finished_at: status.finished_at,
            outcome: status.outcome.map(Into::into),
            reason: status.reason,
            events: StringNumber(status.events),
            sources: status.sources.into_iter().map(Into::into).collect(),
            reported_at: status.reported_at,
        }
    }
}

/// Why a detector does or does not run.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::DetectorState")]
enum DetectorState {
    /// The detector is scheduled and runs its rounds.
    Running,
    /// The detector is disabled.
    Disabled,
    /// The detector has no model to run.
    NoModel,
    /// The detector is paused for a training or clone run of its model.
    PausedForRun,
}

/// The outcome of a detector's round.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::RoundOutcome")]
enum RoundOutcome {
    /// The round succeeded.
    Succeeded,
    /// The round failed; the status's `reason` says why.
    Failed,
}

/// The status of one source of a detector.
#[derive(SimpleObject)]
struct DetectorSourceStatus {
    /// The source's name.
    source: String,
    /// The source's state.
    state: SourceState,
    /// Why the source failed, when it did.
    reason: Option<String>,
}

impl From<database::DetectorSourceStatus> for DetectorSourceStatus {
    fn from(status: database::DetectorSourceStatus) -> Self {
        Self {
            source: status.source,
            state: status.state.into(),
            reason: status.reason,
        }
    }
}

/// The state of a detector's source in its last round.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::SourceState")]
enum SourceState {
    /// A Data Store node served the source's events.
    Served,
    /// No Data Store node served the source; the round went on and the
    /// source kept its read position.
    ServedByNoNode,
    /// Reading the source's events failed, which failed the round.
    Failed,
}

#[cfg(test)]
mod tests;
