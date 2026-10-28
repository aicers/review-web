//! Customer data deletion results, orchestration, and startup recovery.
//!
//! A deletion runs in stages:
//!
//! 1. The customer's Sensors and Semi-supervised Engines delete their files,
//!    and every one of their results is waited for until it is terminal.
//! 2. Every module the Central Manager installed on the customer's nodes,
//!    other than its Data Stores, is uninstalled, so that nothing sends the
//!    customer's data any more.
//! 3. The Data Store step asks every listed Data Store to delete the
//!    customer's events and its sampling policies' periodic time series.
//! 4. The Data Stores on the customer's nodes are uninstalled.
//! 5. The Review stage deletes what the Central Manager keeps, its nodes
//!    among it.
//!
//! Each stage decides from the job and the store, so a deletion resumed after
//! a restart skips what is done. A deletion that stops leaves no result it
//! did not dispatch `InProgress`.
//!
//! What a deletion leaves behind:
//!
//! - A sampling policy ID recycled before the store's policy IDs became
//!   unique names the periodic time series of every policy that held it;
//!   deleting the customer of the last holder deletes all of them.
//! - A host name used earlier by another customer's node names that
//!   customer's older events too. Nothing in the Data Store tells them
//!   apart, and deleting by the name deletes them.
//! - A Data Store without an instance number, registered by hand, is not
//!   listed, so it is never asked, and the customer's data in it stays.
//! - The events of a node removed before the deletion cannot be found, since
//!   nothing records the node's host name any more, and stay.
//! - A module registered by hand, with no instance number, is removed from the
//!   records only, and keeps running.
//! - A Data Store uninstalled with the customer leaves its data directory on
//!   the host.
#![allow(clippy::unused_async_trait_impl)]

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use async_graphql::{
    Context, Enum, ErrorExtensions, ID, Object, Result as GraphqlResult, SimpleObject,
};
use chrono::Utc;
use futures::{
    future::join_all,
    stream::{FuturesUnordered, StreamExt},
};
use jiff::Timestamp;
use review_database::Role;
use review_database::{
    AgentKind, CustomerDataDeletionJob, CustomerDataDeletionService,
    CustomerDataDeletionServiceResult, CustomerDataDeletionStatus, ExternalServiceKind, Iterable,
    Node, OperationAction, OperationAttempt, OperationOutcome, Store, event::Direction,
};
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
};
use tracing::{error, warn};

use crate::{
    backend::{DeployError, MODULE_PACKAGE_IDS, SharedAgentManager, SharedPackageDeployer},
    graphql::{
        RoleGuard, SamplingPoliciesLock, agent_lookup_key_service_token, data_store_in_use_message,
        data_stores_in_use, listed_rows, operator_installs,
    },
};

const TERMINAL_STATUS_UPDATE_ATTEMPTS: usize = 2;
/// How often the Data Store step reads a Data Store's result.
const DATA_STORE_POLL_INTERVAL: Duration = Duration::from_secs(30);
/// How long the Data Store step waits before it sends again to a Data Store
/// that answered `Blocked`.
const DATA_STORE_BLOCKED_RETRY_INTERVAL: Duration = Duration::from_secs(60);
/// How long a Data Store's result may fail to be read before it is `Failed`.
const DATA_STORE_TRANSPORT_ERROR_LIMIT: Duration = Duration::from_mins(10);
/// How long after its request a Data Store's result may stay unfinished, in
/// nanoseconds.
const DATA_STORE_RESULT_DEADLINE_NANOS: i64 = 24 * 60 * 60 * 1_000_000_000;
/// The error text of a Data Store result recorded `Succeeded` because the
/// Data Store is no longer listed.
const DATA_STORE_NOT_REGISTERED: &str =
    "the Data Store is no longer registered with the Central Manager; nothing was deleted in it";
/// The fewest non-empty labels the Data Store accepts in a service FQDN.
const MIN_SERVICE_FQDN_LABELS: usize = 3;
/// The `extensions.code` of a deletion refused while a Data Store on the
/// customer's nodes is used by others.
const DATA_STORE_IN_USE: &str = "DATA_STORE_IN_USE";
/// The `extensions.code` of a request refused because the customer's data
/// was already deleted and it holds records created since.
const CUSTOMER_DATA_ALREADY_DELETED: &str = "CUSTOMER_DATA_ALREADY_DELETED";
/// How often a stage re-reads the job, an attempt or a row it waits for.
const STAGE_POLL_INTERVAL: Duration = Duration::from_secs(10);
/// How long a Sensor or Semi-supervised result may stay unreported, from the
/// later of its request and the start of the supervisor waiting for it, in
/// nanoseconds.
const REPORT_DEADLINE_NANOS: i64 = 60 * 60 * 1_000_000_000;
/// How long `remove` may keep answering, for one row, that a teardown is
/// still owed or that `REview` is under maintenance.
const REMOVE_REFUSAL_LIMIT: Duration = Duration::from_hours(1);

/// A deletion refused, before anything is written, because a Data Store on
/// the customer's nodes is used by another customer or by a system log
/// collector. The message names each such Data Store, its users, and how to
/// free it.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct DataStoreInUseError(String);

/// A request refused, before anything is written, because the customer's
/// data was already deleted and it holds records created since. The message
/// says when, and what it holds.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct CustomerDataAlreadyDeletedError(String);

/// A remote service that must delete data belonging to a customer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomerDataDeletionTarget {
    customer_id: u32,
    host_fqdn: String,
    target_service_key: String,
}

impl CustomerDataDeletionTarget {
    #[must_use]
    pub fn new(customer_id: u32, host_fqdn: String, target_service_key: String) -> Self {
        Self {
            customer_id,
            host_fqdn,
            target_service_key,
        }
    }

    #[must_use]
    pub fn customer_id(&self) -> u32 {
        self.customer_id
    }

    #[must_use]
    pub fn host_fqdn(&self) -> &str {
        &self.host_fqdn
    }

    #[must_use]
    pub fn target_service_key(&self) -> &str {
        &self.target_service_key
    }
}

/// A Data Store that must delete a customer's events and the periodic time
/// series of its sampling policies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataStoreDeletionTarget {
    customer_id: u32,
    server_name: String,
    hostname: String,
    instance: u32,
    service_fqdns: Vec<String>,
    periodic_time_series_ids: Vec<String>,
}

impl DataStoreDeletionTarget {
    #[must_use]
    pub fn new(
        customer_id: u32,
        hostname: String,
        instance: u32,
        service_fqdns: Vec<String>,
        periodic_time_series_ids: Vec<String>,
    ) -> Self {
        Self {
            customer_id,
            server_name: data_store_server_name(instance, &hostname),
            hostname,
            instance,
            service_fqdns,
            periodic_time_series_ids,
        }
    }

    #[must_use]
    pub fn customer_id(&self) -> u32 {
        self.customer_id
    }

    /// Returns the Data Store's server name, `<instance:03>.giganto.<hostname>`.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Returns the host name of the Data Store's node.
    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Returns the Data Store's instance number on its host.
    #[must_use]
    pub fn instance(&self) -> u32 {
        self.instance
    }

    /// Returns the sorted service FQDNs, `piglet.<host>` and
    /// `reproduce.<host>`, whose events the Data Store deletes. It may be
    /// empty when only periodic time series are deleted.
    #[must_use]
    pub fn service_fqdns(&self) -> &[String] {
        &self.service_fqdns
    }

    /// Returns the decimal sampling policy IDs, ascending, whose periodic time
    /// series the Data Store deletes.
    #[must_use]
    pub fn periodic_time_series_ids(&self) -> &[String] {
        &self.periodic_time_series_ids
    }
}

/// A Data Store's answer to a request to delete a customer's data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataStoreRequestAnswer {
    /// The Data Store started the deletion.
    Accepted,
    /// The Data Store already runs a deletion of the customer.
    InProgress,
    /// The Data Store already finished a deletion of the customer.
    AlreadyCompleted,
    /// The Data Store has nothing of the customer to delete.
    NoLocalTarget,
    /// The request could not start now, because the Data Store runs another
    /// customer's deletion, applies its retention or shuts down, or because
    /// nothing was sent while `REview`'s maintenance gate is closed. It is
    /// sent again later.
    Blocked,
}

/// Result of requesting customer data deletion.
#[allow(clippy::unused_async_trait_impl)]
#[derive(Clone, Copy, Debug, Eq, Enum, PartialEq)]
pub enum CustomerDataDeletionRequestStatus {
    Accepted,
    AlreadyCompleted,
    DeletionInProgress,
    BlockedByAnotherDeletion,
    BlockedByShutdown,
    NoTarget,
}

/// Owns the deletion supervisor so application shutdown can await it.
#[derive(Default)]
pub struct CustomerDataDeletionTaskManager {
    state: Mutex<CustomerDataDeletionTaskState>,
    /// The lock `removeSamplingPolicies` takes, which the deletion takes
    /// around its removal of the customer's sampling policies. The GraphQL
    /// schema is given this one, so the two share it.
    sampling_policies_lock: Arc<SamplingPoliciesLock>,
    /// Set when shutdown starts, which ends the supervisor's waits.
    shutdown: watch::Sender<bool>,
}

#[derive(Default)]
struct CustomerDataDeletionTaskState {
    shutting_down: bool,
    active: Option<(u32, JoinHandle<()>)>,
}

impl CustomerDataDeletionTaskManager {
    /// Returns the lock that orders the removals of sampling policies.
    pub(crate) fn sampling_policies_lock(&self) -> &Arc<SamplingPoliciesLock> {
        &self.sampling_policies_lock
    }

    /// Blocks new deletion requests and tells the active supervisor to stop,
    /// without waiting for it.
    ///
    /// The supervisor stops waiting, drops a `remove` call in flight, and
    /// returns without recording anything more, so the next start resumes
    /// the deletion; a Review stage already running finishes first. The
    /// embedding application calls this before it stops the applies a
    /// deletion waits for, so that an apply ended by that stop is not taken
    /// for the deletion's failure, and then
    /// [`shutdown_and_wait`](Self::shutdown_and_wait).
    pub async fn begin_shutdown(&self) {
        let mut state = self.state.lock().await;
        state.shutting_down = true;
        self.shutdown.send_replace(true);
    }

    /// Blocks new deletion requests and waits for the active supervisor.
    ///
    /// The supervisor stops as [`begin_shutdown`](Self::begin_shutdown)
    /// describes, and leaves its unfinished results `InProgress` for the next
    /// start to resume.
    pub async fn shutdown_and_wait(&self) {
        let active = {
            let mut state = self.state.lock().await;
            state.shutting_down = true;
            self.shutdown.send_replace(true);
            state.active.take()
        };
        if let Some((customer_id, supervisor)) = active
            && let Err(join_error) = supervisor.await
        {
            error!(
                customer_id,
                "Customer data deletion supervisor failed: {join_error}"
            );
        }
    }
}

#[derive(Debug)]
struct ReviewDeletionTargets {
    node_ids: Vec<u32>,
    host_fqdns: Vec<String>,
    event_service_fqdns: Vec<String>,
}

#[derive(Debug)]
struct CustomerDataDeletionExecutionPlan {
    customer_id: u32,
    review_targets: Option<ReviewDeletionTargets>,
    remote_targets: Vec<CustomerDataDeletionTarget>,
    /// The customer's sampling policy IDs, read for an initial plan only; a
    /// retry or a resume keeps the ones stored with the job.
    periodic_time_series_ids: Vec<String>,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(
    name = "CustomerDataDeletionService",
    remote = "review_database::CustomerDataDeletionService"
)]
enum DeletionService {
    Review,
    Sensor,
    SemiSupervised,
    DataStore,
    ModuleRemoval,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(
    name = "CustomerDataDeletionStatus",
    remote = "review_database::CustomerDataDeletionStatus"
)]
enum DeletionStatus {
    InProgress,
    Succeeded,
    Failed,
}

#[derive(SimpleObject)]
#[graphql(name = "CustomerDataDeletionServiceResult")]
struct DeletionServiceResult {
    service: DeletionService,
    host_fqdns: Vec<String>,
    status: DeletionStatus,
    requested_at: Timestamp,
    completed_at: Option<Timestamp>,
    error: Option<String>,
}

impl TryFrom<CustomerDataDeletionServiceResult> for DeletionServiceResult {
    type Error = anyhow::Error;

    fn try_from(result: CustomerDataDeletionServiceResult) -> anyhow::Result<Self> {
        Ok(Self {
            service: result.service.into(),
            host_fqdns: result.host_fqdns,
            status: result.status.into(),
            requested_at: Timestamp::from_nanosecond(i128::from(result.requested_at))
                .context("converting deletion result request timestamp")?,
            completed_at: result
                .completed_at
                .map(|value| Timestamp::from_nanosecond(i128::from(value)))
                .transpose()
                .context("converting deletion result completion timestamp")?,
            error: result.error,
        })
    }
}

#[derive(SimpleObject)]
#[graphql(name = "CustomerDataDeletionResult")]
struct DeletionResult {
    customer_id: ID,
    service_results: Vec<DeletionServiceResult>,
}

#[derive(Default)]
pub(crate) struct CustomerDataDeletionQuery;

#[Object]
impl CustomerDataDeletionQuery {
    /// Returns persisted deletion results; null means no persisted job exists.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn customer_data_deletion_result(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
    ) -> GraphqlResult<Option<DeletionResult>> {
        let customer_id = customer_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| async_graphql::Error::new("invalid customer ID"))?;
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        let store = read_store(store)?;
        let job = store
            .customer_data_deletion_map()
            .get(customer_id)
            .with_context(|| format!("retrieving customer data deletion job {customer_id}"))?;
        job.map(|job| {
            Ok(DeletionResult {
                customer_id: job.customer_id.into(),
                service_results: job
                    .service_results
                    .into_iter()
                    .map(DeletionServiceResult::try_from)
                    .collect::<anyhow::Result<_>>()?,
            })
        })
        .transpose()
    }
}

#[derive(Default)]
pub struct CustomerDataDeletionMutation;

#[Object]
impl CustomerDataDeletionMutation {
    /// Requests the deletion of a customer's data, or a retry of its stopped
    /// deletion.
    ///
    /// Refused before anything is written, with `extensions.code`
    /// `DATA_STORE_IN_USE`, while a Data Store on one of the customer's
    /// nodes is named by an agent on another node, a training definition of
    /// another customer, or a system log collector. The message names each
    /// such Data Store, its users, and how to free it.
    ///
    /// Refused the same way, with `CUSTOMER_DATA_ALREADY_DELETED`, when the
    /// customer's data was already deleted and it holds nodes, sampling
    /// policies, models or training definitions created since. Once they are
    /// removed, the request is answered `ALREADY_COMPLETED`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn delete_customer_data(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
    ) -> GraphqlResult<CustomerDataDeletionRequestStatus> {
        let customer_id = customer_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| async_graphql::Error::new("invalid customer ID"))?;
        let task_manager = ctx.data::<Arc<CustomerDataDeletionTaskManager>>()?;
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        let agent_manager = ctx.data::<SharedAgentManager>()?;
        let deployer = ctx.data::<SharedPackageDeployer>()?;
        request_deletion(customer_id, store, agent_manager, deployer, task_manager)
            .await
            .map_err(|error| {
                if let Some(DataStoreInUseError(message)) = error.downcast_ref() {
                    async_graphql::Error::new(message)
                        .extend_with(|_, extensions| extensions.set("code", DATA_STORE_IN_USE))
                } else if let Some(CustomerDataAlreadyDeletedError(message)) = error.downcast_ref()
                {
                    async_graphql::Error::new(message).extend_with(|_, extensions| {
                        extensions.set("code", CUSTOMER_DATA_ALREADY_DELETED);
                    })
                } else {
                    async_graphql::Error::new(format!("{error:#}"))
                }
            })
    }
}

async fn request_deletion(
    customer_id: u32,
    store: &Arc<RwLock<Store>>,
    agent_manager: &SharedAgentManager,
    deployer: &SharedPackageDeployer,
    task_manager: &Arc<CustomerDataDeletionTaskManager>,
) -> anyhow::Result<CustomerDataDeletionRequestStatus> {
    let mut state = task_manager.state.lock().await;
    if state.shutting_down {
        return Ok(CustomerDataDeletionRequestStatus::BlockedByShutdown);
    }
    if let Some((active_customer_id, supervisor)) = state.active.as_ref() {
        if !supervisor.is_finished() {
            return Ok(if *active_customer_id == customer_id {
                CustomerDataDeletionRequestStatus::DeletionInProgress
            } else {
                CustomerDataDeletionRequestStatus::BlockedByAnotherDeletion
            });
        }
        // A finished handle owns no live work. The persisted state below is
        // authoritative even if the completed task panicked after persisting.
        _ = state.active.take();
    }

    let existing = {
        let store = read_store(store)?;
        #[cfg(test)]
        tests::checkpoint(&store, tests::Stage::ScanJobs, customer_id)?;
        let mut existing = None;
        for job in store
            .customer_data_deletion_map()
            .iter(Direction::Forward, None)
        {
            let job = job.context("scanning customer data deletion jobs")?;
            if job.customer_id == customer_id {
                existing = Some(job);
            } else if job
                .service_results
                .iter()
                .any(|result| result.status == CustomerDataDeletionStatus::InProgress)
            {
                return Ok(CustomerDataDeletionRequestStatus::BlockedByAnotherDeletion);
            }
        }
        existing
    };

    let plan = if let Some(job) = existing {
        if job
            .service_results
            .iter()
            .all(|result| result.status == CustomerDataDeletionStatus::Succeeded)
        {
            // A completed job is never replaced: each Data Store keeps its
            // own completed deletion of the customer and would delete
            // nothing again.
            if let Some(message) = already_deleted_refusal(store, &job)? {
                return Err(CustomerDataAlreadyDeletedError(message).into());
            }
            return Ok(CustomerDataDeletionRequestStatus::AlreadyCompleted);
        }
        if job
            .service_results
            .iter()
            .any(|result| result.status == CustomerDataDeletionStatus::InProgress)
        {
            return Ok(CustomerDataDeletionRequestStatus::DeletionInProgress);
        }
        // A job exists, so the customer's nodes can no longer leave it.
        check_data_stores_in_use(store, customer_id, false)?;
        let requested_at = timestamp_nanos()?;
        let plan = retry_plan(store, &job)?;
        let mut updated_job = job.clone();
        // A Data Store result stays `Failed` until the Data Store step sends
        // to it again, which sets it `InProgress` itself.
        for result in &mut updated_job.service_results {
            if result.status == CustomerDataDeletionStatus::Failed
                && result.service != CustomerDataDeletionService::DataStore
            {
                result.status = CustomerDataDeletionStatus::InProgress;
                result.requested_at = requested_at;
                result.completed_at = None;
                result.error = None;
            }
        }
        persist_retry_request(store, &job, &updated_job)?;
        plan
    } else {
        let Some(plan) = collect_initial_plan(store, customer_id)? else {
            return Ok(CustomerDataDeletionRequestStatus::NoTarget);
        };
        check_data_stores_in_use(store, customer_id, true)?;
        let job = initial_job(&plan, timestamp_nanos()?);
        persist_request(store, &job)?;
        plan
    };

    let supervisor = Supervisor {
        store: Arc::clone(store),
        agent_manager: Arc::clone(agent_manager),
        deployer: Arc::clone(deployer),
        policies_lock: Arc::clone(task_manager.sampling_policies_lock()),
        shutdown: task_manager.shutdown.subscribe(),
    };
    let supervisor = tokio::spawn(async move { supervisor.run(plan, Start::Request).await });
    // There is deliberately no await between spawn and registration. The
    // task-manager mutex decides the ordering against shutdown.
    state.active = Some((customer_id, supervisor));
    Ok(CustomerDataDeletionRequestStatus::Accepted)
}

/// Refuses the deletion of customer `customer_id` with a
/// [`DataStoreInUseError`] while a Data Store on its nodes is used by others.
///
/// `node_may_move` is whether no job of the customer exists yet, so that the
/// node holding the Data Store may still move to another customer.
fn check_data_stores_in_use(
    store: &RwLock<Store>,
    customer_id: u32,
    node_may_move: bool,
) -> anyhow::Result<()> {
    let in_use = data_stores_in_use(&*read_store(store)?, customer_id)
        .with_context(|| format!("checking the Data Stores of customer {customer_id}"))?;
    if in_use.is_empty() {
        return Ok(());
    }
    Err(DataStoreInUseError(data_store_in_use_message(&in_use, node_may_move)).into())
}

/// Returns the refusal of a request for a customer whose deletion `job` is
/// complete, when the customer again holds what an initial plan collects, or
/// `None` when it holds nothing.
fn already_deleted_refusal(
    store: &RwLock<Store>,
    job: &CustomerDataDeletionJob,
) -> anyhow::Result<Option<String>> {
    let customer_id = job.customer_id;
    let store = read_store(store)?;
    let mut nodes = 0_usize;
    for node in store.node_map().iter(Direction::Forward, None) {
        let node = node.context("reading the customer's nodes")?;
        if node
            .profile
            .as_ref()
            .is_some_and(|profile| profile.customer_id == customer_id)
        {
            nodes += 1;
        }
    }
    let mut policies = 0_usize;
    for policy in store.sampling_policy_map().iter(Direction::Forward, None) {
        if policy.context("reading the sampling policies")?.customer_id == Some(customer_id) {
            policies += 1;
        }
    }
    let mut models = 0_usize;
    for model in store.model_map().iter(Direction::Forward, None) {
        if model.context("reading the models")?.customer_id == customer_id {
            models += 1;
        }
    }
    let definitions = store
        .training_definitions()
        .context("reading the training definitions")?
        .iter()
        .filter(|definition| definition.customer_id == customer_id)
        .count();
    let held: Vec<String> = [
        (nodes, "node", "nodes"),
        (policies, "sampling policy", "sampling policies"),
        (models, "model", "models"),
        (definitions, "training definition", "training definitions"),
    ]
    .into_iter()
    .filter(|(count, _, _)| *count > 0)
    .map(|(count, one, many)| format!("{count} {}", if count == 1 { one } else { many }))
    .collect();
    if held.is_empty() {
        return Ok(None);
    }
    let deleted_at = job
        .service_results
        .iter()
        .map(|result| result.completed_at.unwrap_or(result.requested_at))
        .max()
        .unwrap_or_default();
    let deleted_at = Timestamp::from_nanosecond(i128::from(deleted_at))
        .context("converting the deletion's completion timestamp")?;
    Ok(Some(format!(
        "the customer's data was deleted on {deleted_at}; it now holds {}, created since; \
         remove them, then retry",
        held.join(", ")
    )))
}

fn persist_request(store: &RwLock<Store>, job: &CustomerDataDeletionJob) -> anyhow::Result<()> {
    let store = read_store(store)?;
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::PersistRequest, job.customer_id)?;
    store
        .customer_data_deletion_map()
        .put(job)
        .context("persisting initial customer data deletion job")
}

fn persist_retry_request(
    store: &RwLock<Store>,
    old: &CustomerDataDeletionJob,
    new: &CustomerDataDeletionJob,
) -> anyhow::Result<()> {
    let store = read_store(store)?;
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::PersistRequest, old.customer_id)?;
    // Preserve service reports received after the job was read.
    store
        .customer_data_deletion_map()
        .update(old, new)
        .with_context(|| {
            format!(
                "persisting customer data deletion retry for customer {}",
                old.customer_id
            )
        })
}

fn timestamp_nanos() -> anyhow::Result<i64> {
    #[cfg(test)]
    if let Some(now) = tests::mocked_now() {
        return Ok(now);
    }
    Utc::now()
        .timestamp_nanos_opt()
        .ok_or_else(|| anyhow!("current UTC time is outside the i64 nanosecond range"))
}

fn read_store(store: &RwLock<Store>) -> anyhow::Result<std::sync::RwLockReadGuard<'_, Store>> {
    store
        .read()
        .map_err(|_| anyhow!("database store lock poisoned"))
}

fn service_fqdn(service: &str, host_fqdn: &str) -> String {
    format!("{service}.{host_fqdn}")
}

pub(crate) fn data_store_server_name(instance: u32, hostname: &str) -> String {
    format!("{instance:03}.giganto.{hostname}")
}

fn agent_has_service(key: &str, service: &str) -> bool {
    agent_lookup_key_service_token(key) == Some(service)
}

fn collect_initial_plan(
    store: &RwLock<Store>,
    customer_id: u32,
) -> anyhow::Result<Option<CustomerDataDeletionExecutionPlan>> {
    let store = read_store(store)?;
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::CollectNodes, customer_id)?;
    let mut node_ids = Vec::new();
    let mut host_fqdns = Vec::new();
    let mut event_service_fqdns = Vec::new();
    let mut remote_targets = Vec::new();

    let node_map = store.node_map();
    for candidate in store.node_map().iter(Direction::Forward, None) {
        let candidate = candidate.context("collecting customer deletion nodes")?;
        let Some(profile) = candidate.profile.as_ref() else {
            continue;
        };
        if profile.customer_id != customer_id {
            continue;
        }
        let node_id = candidate.id;

        // The node_map iterator silently skips missing or unreadable Agent and
        // ExternalService records. Re-read the target Node to propagate lookup
        // errors and reject missing associations before persisting the job.
        let Some((node, missing_agents, missing_external_services)) =
            node_map
                .get_by_id(node_id)
                .with_context(|| format!("retrieving customer deletion node {node_id}"))?
        else {
            bail!("customer deletion node {node_id} no longer exists");
        };
        if !missing_agents.is_empty() || !missing_external_services.is_empty() {
            bail!(
                "retrieving connected records for node {node_id} failed (agents: {missing_agents:?}, external services: {missing_external_services:?})"
            );
        }
        let profile = node
            .profile
            .as_ref()
            .ok_or_else(|| anyhow!("customer deletion node {node_id} no longer has a profile"))?;
        node_ids.push(node.id);
        host_fqdns.push(profile.hostname.clone());
        for agent in &node.agents {
            if agent_has_service(&agent.key, "piglet") {
                event_service_fqdns.push(service_fqdn("piglet", &profile.hostname));
            }
            // Reproduce registration and sysmon ingestion are not supported
            // yet; retain this key shape for that future event source.
            if agent_has_service(&agent.key, "reproduce") {
                event_service_fqdns.push(service_fqdn("reproduce", &profile.hostname));
            }
            let service = match agent.kind {
                AgentKind::Sensor => Some("piglet"),
                AgentKind::SemiSupervised => Some("hog"),
                _ => None,
            };
            if let Some(service) = service {
                remote_targets.push(CustomerDataDeletionTarget::new(
                    customer_id,
                    profile.hostname.clone(),
                    service_fqdn(service, &profile.hostname),
                ));
            }
        }
    }
    sort_dedup(&mut node_ids);
    sort_dedup(&mut host_fqdns);
    sort_dedup(&mut event_service_fqdns);
    remote_targets.sort_unstable_by(|a, b| a.target_service_key.cmp(&b.target_service_key));
    remote_targets.dedup_by(|a, b| a.target_service_key == b.target_service_key);

    // A policy whose `customer_id` is `None` is not the customer's.
    let mut policy_ids = Vec::new();
    for policy in store.sampling_policy_map().iter(Direction::Forward, None) {
        let policy = policy.context("collecting customer deletion sampling policies")?;
        if policy.customer_id == Some(customer_id) {
            policy_ids.push(policy.id);
        }
    }
    sort_dedup(&mut policy_ids);
    if node_ids.is_empty()
        && policy_ids.is_empty()
        && !has_unsupervised_records(&store, customer_id)?
    {
        return Ok(None);
    }
    Ok(Some(CustomerDataDeletionExecutionPlan {
        customer_id,
        review_targets: Some(ReviewDeletionTargets {
            node_ids,
            host_fqdns,
            event_service_fqdns,
        }),
        remote_targets,
        periodic_time_series_ids: policy_ids.iter().map(ToString::to_string).collect(),
    }))
}

/// Returns whether the customer has an Unsupervised Engine model or a
/// training definition.
fn has_unsupervised_records(store: &Store, customer_id: u32) -> anyhow::Result<bool> {
    for model in store.model_map().iter(Direction::Forward, None) {
        if model
            .context("collecting customer deletion models")?
            .customer_id
            == customer_id
        {
            return Ok(true);
        }
    }
    Ok(store
        .training_definitions()
        .context("collecting customer deletion training definitions")?
        .iter()
        .any(|definition| definition.customer_id == customer_id))
}

fn sort_dedup<T: Ord>(values: &mut Vec<T>) {
    values.sort_unstable();
    values.dedup();
}

fn initial_job(
    plan: &CustomerDataDeletionExecutionPlan,
    requested_at: i64,
) -> CustomerDataDeletionJob {
    let review_targets = plan
        .review_targets
        .as_ref()
        .expect("an initial plan always contains Review targets");
    let mut service_results = vec![service_result(
        CustomerDataDeletionService::Review,
        review_targets.host_fqdns.clone(),
        requested_at,
    )];
    for target in &plan.remote_targets {
        let service = if target.target_service_key.starts_with("piglet.") {
            CustomerDataDeletionService::Sensor
        } else {
            CustomerDataDeletionService::SemiSupervised
        };
        service_results.push(service_result(
            service,
            vec![target.host_fqdn.clone()],
            requested_at,
        ));
    }
    // A plan with no node has no host and nothing to uninstall.
    if !review_targets.node_ids.is_empty() {
        for host in &review_targets.host_fqdns {
            service_results.push(service_result(
                CustomerDataDeletionService::ModuleRemoval,
                vec![host.clone()],
                requested_at,
            ));
        }
    }
    let mut job = CustomerDataDeletionJob::new(plan.customer_id, service_results);
    job.periodic_time_series_ids
        .clone_from(&plan.periodic_time_series_ids);
    job
}

fn service_result(
    service: CustomerDataDeletionService,
    host_fqdns: Vec<String>,
    requested_at: i64,
) -> CustomerDataDeletionServiceResult {
    CustomerDataDeletionServiceResult {
        service,
        host_fqdns,
        status: CustomerDataDeletionStatus::InProgress,
        requested_at,
        completed_at: None,
        error: None,
    }
}

fn retry_plan(
    store: &RwLock<Store>,
    job: &CustomerDataDeletionJob,
) -> anyhow::Result<CustomerDataDeletionExecutionPlan> {
    plan_from_results(store, job, CustomerDataDeletionStatus::Failed)
}

fn plan_from_results(
    store: &RwLock<Store>,
    job: &CustomerDataDeletionJob,
    selected_status: CustomerDataDeletionStatus,
) -> anyhow::Result<CustomerDataDeletionExecutionPlan> {
    let mut review_targets = None;
    let mut remote_targets = Vec::new();
    for result in job
        .service_results
        .iter()
        .filter(|result| result.status == selected_status)
    {
        let service = match result.service {
            CustomerDataDeletionService::Review => {
                if review_targets.is_some() {
                    bail!(
                        "customer deletion job {} has duplicate Review results",
                        job.customer_id
                    );
                }

                review_targets = Some(restore_review_targets(
                    store,
                    job.customer_id,
                    &result.host_fqdns,
                )?);
                continue;
            }
            CustomerDataDeletionService::Sensor => "piglet",
            CustomerDataDeletionService::SemiSupervised => "hog",
            // The Data Store step computes its targets itself, and the
            // stages read the `ModuleRemoval` results from the stored job.
            CustomerDataDeletionService::DataStore | CustomerDataDeletionService::ModuleRemoval => {
                continue;
            }
        };
        let host_fqdn = result
            .host_fqdns
            .first()
            .ok_or_else(|| anyhow!("remote deletion result has no host FQDN"))?;
        remote_targets.push(CustomerDataDeletionTarget::new(
            job.customer_id,
            host_fqdn.clone(),
            service_fqdn(service, host_fqdn),
        ));
    }
    remote_targets.sort_unstable_by(|a, b| a.target_service_key.cmp(&b.target_service_key));
    remote_targets.dedup_by(|a, b| a.target_service_key == b.target_service_key);
    Ok(CustomerDataDeletionExecutionPlan {
        customer_id: job.customer_id,
        review_targets,
        remote_targets,
        periodic_time_series_ids: Vec::new(),
    })
}

fn restore_review_targets(
    store: &RwLock<Store>,
    customer_id: u32,
    persisted_host_fqdns: &[String],
) -> anyhow::Result<ReviewDeletionTargets> {
    let store = read_store(store)?;
    let mut node_ids = store
        .node_map()
        .iter(Direction::Forward, None)
        .filter_map(|node| match node {
            Ok(node)
                if node
                    .profile
                    .as_ref()
                    .is_some_and(|profile| profile.customer_id == customer_id) =>
            {
                Some(Ok(node.id))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    sort_dedup(&mut node_ids);
    let mut host_fqdns = persisted_host_fqdns.to_vec();
    sort_dedup(&mut host_fqdns);
    let mut event_service_fqdns = Vec::with_capacity(host_fqdns.len() * 2);
    for host in &host_fqdns {
        event_service_fqdns.push(service_fqdn("piglet", host));
        // Prepared now for future reproduce-windows registration and events.
        event_service_fqdns.push(service_fqdn("reproduce", host));
    }
    sort_dedup(&mut event_service_fqdns);
    Ok(ReviewDeletionTargets {
        node_ids,
        host_fqdns,
        event_service_fqdns,
    })
}

/// How a supervisor starts with a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Start {
    /// A request or a retry: the plan's Sensor and Semi-supervised targets
    /// are sent first.
    Request,
    /// A resume at startup: nothing is sent, since the embedding application
    /// holds the job's unreported targets and sends them itself.
    Resume,
}

/// Why a stage did not let the deletion go on.
#[derive(Debug)]
enum Halt {
    /// Shutdown started. Nothing more is recorded; the next start resumes.
    ShutDown,
    /// The deletion stops.
    Stop(Stop),
}

/// A deletion that stops, and how its unfinished results are recorded.
#[derive(Debug)]
struct Stop {
    reason: String,
    /// The text of each host's `ModuleRemoval` result not yet terminal that
    /// is not recorded with the stage's default text, by host.
    hosts: HashMap<String, String>,
    /// Whether the hosts not in `hosts` were waiting on the Data Store step,
    /// rather than not yet started.
    waiting_for_data_store: bool,
    /// The server names of the Data Stores the Data Store step sent to or
    /// waited for, when the stop came from that step; `None` when the Data
    /// Stores sent before a restart are still to be waited for.
    dispatched: Option<Vec<String>>,
}

impl Stop {
    fn new(reason: String) -> Self {
        Self {
            reason,
            hosts: HashMap::new(),
            waiting_for_data_store: false,
            dispatched: None,
        }
    }

    /// Stops the deletion with `error` as the error of `host`'s
    /// `ModuleRemoval` result.
    fn on_host(host: &str, error: String) -> Self {
        let mut stop = Self::new(error.clone());
        stop.hosts.insert(host.to_string(), error);
        stop
    }

    /// Returns the text a `ModuleRemoval` result of `host` not yet terminal
    /// is recorded with.
    fn module_removal_error(&self, host: &str) -> String {
        if let Some(error) = self.hosts.get(host) {
            error.clone()
        } else if self.waiting_for_data_store {
            format!(
                "stopped while waiting for the Data Store deletion: {}",
                self.reason
            )
        } else {
            format!("stopped before this part: {}", self.reason)
        }
    }
}

impl From<Stop> for Halt {
    fn from(stop: Stop) -> Self {
        Self::Stop(stop)
    }
}

impl Halt {
    /// Stops the deletion with `error`, which no host's result carries as its
    /// own.
    fn stop(error: &anyhow::Error) -> Self {
        Self::Stop(Stop::new(format!("{error:#}")))
    }

    /// Names, for each host `remove` was called on in this stage, what was
    /// removed there before another host stopped the deletion.
    fn after_removals(self, progress: &std::sync::Mutex<HashMap<String, HostProgress>>) -> Self {
        let Self::Stop(mut stop) = self else {
            return self;
        };
        let progress = progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (host, host_progress) in progress.iter() {
            if !host_progress.remove_called || stop.hosts.contains_key(host) {
                continue;
            }
            let removed = if host_progress.removed.is_empty() {
                "none".to_string()
            } else {
                host_progress.removed.join(", ")
            };
            let error = format!(
                "stopped while another host's removal failed: {}; removed here so far: {removed}",
                stop.reason
            );
            stop.hosts.insert(host.clone(), error);
        }
        Self::Stop(stop)
    }
}

/// Where the Sensor and Semi-supervised results of a job stand.
enum Reports {
    /// One is still `InProgress`.
    Waiting,
    /// Every one is terminal; the error of the first `Failed` one, if any.
    Done(Option<String>),
}

/// What one host's uninstall has done in the current stage.
#[derive(Debug, Default)]
struct HostProgress {
    /// Whether `remove` was called for any of the host's rows.
    remove_called: bool,
    /// The rows `remove` was called for that are gone, as
    /// `<package_id> <instance>`.
    removed: Vec<String>,
}

/// A row with an instance number on one of a customer's nodes: what the
/// Central Manager installed there.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NumberedRow {
    host: String,
    /// The package-id `remove` takes, or, for a kind nothing deploys, the
    /// kind's name.
    package_id: String,
    instance: u32,
    /// Whether the row is a Data Store's, which is uninstalled after the
    /// Data Store step rather than before it.
    data_store: bool,
}

impl NumberedRow {
    fn name(&self) -> String {
        format!("{} {}", self.package_id, self.instance)
    }

    fn on_host(&self) -> String {
        format!("{} {} on {}", self.package_id, self.instance, self.host)
    }
}

/// Returns the rows with an instance number of `node`, whose host is `host`,
/// in the order of its agents, then of its external services.
fn node_numbered_rows(node: &Node, host: &str) -> Vec<NumberedRow> {
    let agents = node.agents.iter().filter_map(|agent| {
        Some(NumberedRow {
            host: host.to_string(),
            package_id: agent
                .kind
                .package_id()
                .map_or_else(|| format!("{:?}", agent.kind), str::to_owned),
            instance: agent.instance?,
            data_store: false,
        })
    });
    let external_services = node.external_services.iter().filter_map(|service| {
        Some(NumberedRow {
            host: host.to_string(),
            package_id: service
                .kind
                .package_id()
                .map_or_else(|| format!("{:?}", service.kind), str::to_owned),
            instance: service.instance?,
            data_store: service.kind == ExternalServiceKind::DataStore,
        })
    });
    agents.chain(external_services).collect()
}

/// Returns every row with an instance number on the nodes whose applied
/// profile is customer `customer_id`'s.
fn numbered_rows(store: &RwLock<Store>, customer_id: u32) -> anyhow::Result<Vec<NumberedRow>> {
    let store = read_store(store)?;
    let mut rows = Vec::new();
    for node in store.node_map().iter(Direction::Forward, None) {
        let node = node.context("reading the customer's nodes")?;
        let Some(profile) = node
            .profile
            .as_ref()
            .filter(|profile| profile.customer_id == customer_id)
        else {
            continue;
        };
        rows.extend(node_numbered_rows(&node, &profile.hostname));
    }
    Ok(rows)
}

/// Returns the host FQDN of each `ModuleRemoval` result of `job`, and
/// whether that result is `InProgress`.
fn module_removal_hosts(job: &CustomerDataDeletionJob) -> Vec<(String, bool)> {
    job.service_results
        .iter()
        .filter(|result| result.service == CustomerDataDeletionService::ModuleRemoval)
        .filter_map(|result| {
            let host = result.host_fqdns.first()?;
            Some((
                host.clone(),
                result.status == CustomerDataDeletionStatus::InProgress,
            ))
        })
        .collect()
}

/// Returns the error of an attempt that removed nothing.
fn failed_removal(attempt: &OperationAttempt) -> Stop {
    let failure = match (attempt.failure_kind, attempt.outcome) {
        (Some(kind), _) => format!("{kind:?}"),
        (None, Some(outcome)) => format!("{outcome:?}"),
        (None, None) => "not finished".to_string(),
    };
    let instance = attempt
        .instance
        .map_or_else(|| "-".to_string(), |instance| instance.to_string());
    Stop::on_host(
        &attempt.host,
        format!(
            "removing {} {instance} on {} failed: {failure}",
            attempt.target, attempt.host
        ),
    )
}

/// Runs one customer's deletion, stage after stage, deciding each from the
/// job and the store, so that a resumed deletion skips what is done.
struct Supervisor {
    store: Arc<RwLock<Store>>,
    agent_manager: SharedAgentManager,
    deployer: SharedPackageDeployer,
    policies_lock: Arc<SamplingPoliciesLock>,
    /// Turns `true` when shutdown starts. Once it has, the supervisor records
    /// nothing more, except a Review stage already running.
    shutdown: watch::Receiver<bool>,
}

impl Supervisor {
    /// Runs the deletion of `plan`'s customer.
    ///
    /// 1. Its Sensors and Semi-supervised Engines delete their files: the
    ///    plan's targets are sent, unless the job is resumed, and every result
    ///    is waited for until it is terminal.
    /// 2. Every module installed on its nodes, other than its Data Stores, is
    ///    uninstalled.
    /// 3. Every listed Data Store deletes its data.
    /// 4. Its own Data Stores are uninstalled.
    /// 5. The Review stage deletes what the Central Manager keeps, when the
    ///    plan has Review targets.
    ///
    /// A resumed job whose Review result is not `InProgress` was stopped; only
    /// the wait of stage 1 runs for it.
    async fn run(&self, plan: CustomerDataDeletionExecutionPlan, start: Start) {
        let customer_id = plan.customer_id;
        let started_at = match timestamp_nanos() {
            Ok(now) => now,
            Err(error) => {
                error!(
                    customer_id,
                    "cannot start customer data deletion: {error:#}"
                );
                return;
            }
        };
        if start == Start::Request && !plan.remote_targets.is_empty() {
            // The agent manager records `Failed` every target it could not
            // deliver, and keeps the ones it holds `InProgress` to send later.
            // Its error only sums those up; the stored results decide what
            // happens next.
            let delivery = self
                .agent_manager
                .request_customer_data_deletion(&plan.remote_targets);
            match self.unless_shutdown(delivery).await {
                None => return,
                Some(Err(delivery_error)) => warn!(
                    customer_id,
                    "remote customer data deletion dispatch reported an error: {delivery_error:#}"
                ),
                Some(Ok(())) => {}
            }
        }
        let Ok(remote_failure) = self.wait_for_reports(customer_id, started_at).await else {
            return;
        };
        if start == Start::Resume && plan.review_targets.is_none() {
            return;
        }
        let outcome = match remote_failure {
            Some(reason) => Err(Halt::Stop(Stop::new(reason))),
            None => self.uninstall_and_delete(customer_id).await,
        };
        match outcome {
            Ok(()) => {}
            Err(Halt::ShutDown) => return,
            Err(Halt::Stop(stop)) => {
                self.persist_stop(customer_id, stop).await;
                return;
            }
        }
        if let Some(targets) = plan.review_targets {
            // Once spawned, the Review stage's blocking worker is awaited to
            // its end: a deletion half done is worse than a late shutdown.
            if self.shutting_down() {
                return;
            }
            run_review_worker_and_persist(
                Arc::clone(&self.store),
                Arc::clone(&self.policies_lock),
                customer_id,
                targets,
            )
            .await;
        }
    }

    /// Runs stages 2 to 4: uninstalls the senders, runs the Data Store step,
    /// and uninstalls the customer's own Data Stores.
    async fn uninstall_and_delete(&self, customer_id: u32) -> Result<(), Halt> {
        self.remove_senders(customer_id).await?;
        let mut shutdown = self.shutdown.clone();
        match data_store_step(&self.store, &self.agent_manager, &mut shutdown, customer_id).await {
            DataStoreStepOutcome::Completed => {}
            DataStoreStepOutcome::ShutDown => return Err(Halt::ShutDown),
            DataStoreStepOutcome::Stopped { reason, dispatched } => {
                let mut stop = Stop::new(reason);
                stop.waiting_for_data_store = true;
                stop.dispatched = Some(dispatched);
                return Err(stop.into());
            }
        }
        self.remove_data_stores(customer_id).await
    }

    /// Records the stop of the deletion, after waiting for the Data Stores
    /// sent to before a restart, since nothing else reads their results.
    async fn persist_stop(&self, customer_id: u32, stop: Stop) {
        // Settling the sent Data Stores may record results too.
        if self.shutting_down() {
            return;
        }
        let dispatched = if let Some(dispatched) = &stop.dispatched {
            dispatched.clone()
        } else {
            let mut shutdown = self.shutdown.clone();
            match settle_sent_data_stores(
                &self.store,
                &self.agent_manager,
                &mut shutdown,
                customer_id,
                &stop.reason,
            )
            .await
            {
                DataStoreStepOutcome::Completed => Vec::new(),
                DataStoreStepOutcome::ShutDown => return,
                DataStoreStepOutcome::Stopped { dispatched, .. } => dispatched,
            }
        };
        if self.shutting_down() {
            return;
        }
        if let Err(persist_error) = persist_stop(&self.store, customer_id, &stop, &dispatched) {
            error!(
                customer_id,
                "failed to persist the stop of customer data deletion: {persist_error:#}"
            );
        }
    }

    fn shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }

    /// Runs `future` unless shutdown starts first, and returns its output, or
    /// `None` if shutdown started.
    async fn unless_shutdown<F: Future>(&self, future: F) -> Option<F::Output> {
        let mut shutdown = self.shutdown.clone();
        tokio::select! {
            biased;
            () = wait_for_shutdown(&mut shutdown) => None,
            output = future => Some(output),
        }
    }

    /// Waits one poll interval, or until shutdown starts.
    async fn pause(&self) -> Result<(), Halt> {
        self.unless_shutdown(tokio::time::sleep(STAGE_POLL_INTERVAL))
            .await
            .ok_or(Halt::ShutDown)
    }

    /// Stage 1: waits until every Sensor and Semi-supervised result of the
    /// job is terminal, and returns the error of the first `Failed` one.
    ///
    /// A result still `InProgress` one hour after the later of its
    /// `requested_at` and `started_at` is recorded `Failed`. Only shutdown
    /// ends the wait early.
    async fn wait_for_reports(
        &self,
        customer_id: u32,
        started_at: i64,
    ) -> Result<Option<String>, Halt> {
        loop {
            if self.shutting_down() {
                return Err(Halt::ShutDown);
            }
            match self.end_overdue_reports(customer_id, started_at) {
                Ok(Reports::Done(failure)) => return Ok(failure),
                Ok(Reports::Waiting) => {}
                Err(error) => warn!(
                    customer_id,
                    "reading the Sensor and Semi-supervised deletion results failed: {error:#}"
                ),
            }
            self.pause().await?;
        }
    }

    /// Records `Failed` every Sensor and Semi-supervised result past its
    /// hour, and returns whether every one is terminal.
    ///
    /// The write is a compare-and-swap against the job just read, so a
    /// report written in between is never overwritten; the write is then
    /// refused, and the next pass decides again.
    fn end_overdue_reports(&self, customer_id: u32, started_at: i64) -> anyhow::Result<Reports> {
        let store = read_store(&self.store)?;
        let map = store.customer_data_deletion_map();
        let old = map
            .get(customer_id)
            .with_context(|| format!("retrieving customer data deletion job {customer_id}"))?
            .ok_or_else(|| anyhow!("customer deletion job {customer_id} does not exist"))?;
        let now = timestamp_nanos()?;
        let mut new = old.clone();
        let mut overdue = false;
        for result in new.service_results.iter_mut().filter(|result| {
            is_remote_service(result.service)
                && result.status == CustomerDataDeletionStatus::InProgress
        }) {
            if result
                .requested_at
                .max(started_at)
                .saturating_add(REPORT_DEADLINE_NANOS)
                > now
            {
                continue;
            }
            let host = result.host_fqdns.first().map_or("", String::as_str);
            result.status = CustomerDataDeletionStatus::Failed;
            result.completed_at = Some(now);
            result.error = Some(format!("no deletion report from {host} within 1 hour"));
            overdue = true;
        }
        if overdue {
            if self.shutting_down() {
                return Ok(Reports::Waiting);
            }
            #[cfg(test)]
            tests::checkpoint(&store, tests::Stage::ReportTimeout, customer_id)?;
            map.update(&old, &new).with_context(|| {
                format!("recording the overdue deletion reports of customer {customer_id}")
            })?;
        }
        if new.service_results.iter().any(|result| {
            is_remote_service(result.service)
                && result.status == CustomerDataDeletionStatus::InProgress
        }) {
            return Ok(Reports::Waiting);
        }
        Ok(Reports::Done(first_failed_remote_result(&new)))
    }

    /// Stage 2: uninstalls every module the Central Manager installed on the
    /// customer's nodes, other than its Data Stores.
    ///
    /// Live attempts of the customer's modules on its hosts are waited for
    /// before the stage starts and again before it ends, since an install
    /// that has not yet succeeded has no row. A host left with no row with an
    /// instance number has its `ModuleRemoval` result recorded `Succeeded`.
    async fn remove_senders(&self, customer_id: u32) -> Result<(), Halt> {
        let job = read_job(&self.store, customer_id).map_err(|error| Halt::stop(&error))?;
        let review_hosts: Vec<String> = job
            .service_results
            .iter()
            .find(|result| result.service == CustomerDataDeletionService::Review)
            .map(|result| result.host_fqdns.clone())
            .unwrap_or_default();
        let hosts = module_removal_hosts(&job);
        let progress = std::sync::Mutex::default();
        let removal = async {
            let mut closing = false;
            loop {
                let found = self.wait_for_module_attempts(&review_hosts).await?;
                if closing && !found {
                    return Ok(());
                }
                closing = true;
                let rows = numbered_rows(&self.store, customer_id)
                    .map_err(|error| Halt::stop(&error))?
                    .into_iter()
                    .filter(|row| !row.data_store)
                    .collect();
                self.remove_rows(customer_id, rows, &hosts, &progress, false)
                    .await?;
            }
        };
        removal
            .await
            .map_err(|halt: Halt| halt.after_removals(&progress))?;
        self.finish_hosts(customer_id, &hosts, false)
    }

    /// Stage 4: uninstalls the customer's own Data Stores, each only while no
    /// one else uses one of them.
    async fn remove_data_stores(&self, customer_id: u32) -> Result<(), Halt> {
        let job = read_job(&self.store, customer_id).map_err(|error| Halt::stop(&error))?;
        let hosts = module_removal_hosts(&job);
        let rows = numbered_rows(&self.store, customer_id)
            .map_err(|error| Halt::stop(&error))?
            .into_iter()
            .filter(|row| row.data_store)
            .collect();
        let progress = std::sync::Mutex::default();
        self.remove_rows(customer_id, rows, &hosts, &progress, true)
            .await
            .map_err(|halt| halt.after_removals(&progress))?;
        self.finish_hosts(customer_id, &hosts, true)
    }

    /// Records `Succeeded` the `ModuleRemoval` result of every host among
    /// `hosts` still `InProgress` that holds no row with an instance number.
    ///
    /// Until `last`, a host still holding one waits for a later stage. In the
    /// last, it stops the deletion, naming the rows: the Review stage would
    /// refuse them.
    fn finish_hosts(
        &self,
        customer_id: u32,
        hosts: &[(String, bool)],
        last: bool,
    ) -> Result<(), Halt> {
        let rows = numbered_rows(&self.store, customer_id).map_err(|error| Halt::stop(&error))?;
        let mut left = Vec::new();
        for (host, in_progress) in hosts {
            if !in_progress {
                continue;
            }
            let held: Vec<_> = rows.iter().filter(|row| row.host == *host).collect();
            if !held.is_empty() {
                left.extend(
                    held.into_iter()
                        .map(|row| format!("{} {}", row.host, row.name())),
                );
                continue;
            }
            if self.shutting_down() {
                return Err(Halt::ShutDown);
            }
            persist_terminal(
                &self.store,
                customer_id,
                CustomerDataDeletionService::ModuleRemoval,
                Some(host),
                CustomerDataDeletionStatus::Succeeded,
                None,
            )
            .map_err(|error| Halt::stop(&error))?;
        }
        if last && !left.is_empty() {
            return Err(Stop::new(installed_modules_message(&left)).into());
        }
        Ok(())
    }

    /// Uninstalls `rows`, the hosts concurrently and each host's rows one at
    /// a time.
    ///
    /// When one host stops the deletion, the other hosts' calls in flight
    /// are dropped and none is issued. Dropping one is safe: the embedding
    /// application runs every apply in a task of its own, and a later run
    /// waits for the attempt it left live.
    async fn remove_rows(
        &self,
        customer_id: u32,
        rows: Vec<NumberedRow>,
        hosts: &[(String, bool)],
        progress: &std::sync::Mutex<HashMap<String, HostProgress>>,
        check_in_use: bool,
    ) -> Result<(), Halt> {
        let mut by_host: BTreeMap<String, Vec<NumberedRow>> = BTreeMap::new();
        for row in rows {
            if !hosts.iter().any(|(host, _)| *host == row.host) {
                return Err(Stop::new(format!(
                    "{} belongs to the customer, but the deletion has no MODULE_REMOVAL result for {}",
                    row.on_host(),
                    row.host
                ))
                .into());
            }
            by_host.entry(row.host.clone()).or_default().push(row);
        }
        let mut running: FuturesUnordered<_> = by_host
            .into_values()
            .map(|rows| async move {
                for row in &rows {
                    self.remove_row(customer_id, row, progress, check_in_use)
                        .await?;
                }
                Ok::<(), Halt>(())
            })
            .collect();
        while let Some(outcome) = running.next().await {
            outcome?;
        }
        Ok(())
    }

    /// Uninstalls one row, and returns once it is gone.
    ///
    /// A live attempt on the row is waited for first. With `check_in_use`,
    /// each call is preceded by the check that no one else uses the
    /// customer's Data Stores.
    #[allow(clippy::too_many_lines)]
    async fn remove_row(
        &self,
        customer_id: u32,
        row: &NumberedRow,
        progress: &std::sync::Mutex<HashMap<String, HostProgress>>,
        check_in_use: bool,
    ) -> Result<(), Halt> {
        let mut cleanup_pending_since = None;
        let mut under_maintenance_since = None;
        let mut called = false;
        loop {
            if self.shutting_down() {
                return Err(Halt::ShutDown);
            }
            let (live, latest) = read_store(&self.store)
                .and_then(|store| {
                    let map = store.operation_attempt_map();
                    let live = map.live_attempt(&row.host, &row.package_id, Some(row.instance))?;
                    let latest = if live.is_none() {
                        map.latest_attempt(&row.host, &row.package_id, Some(row.instance))?
                    } else {
                        None
                    };
                    Ok((live, latest))
                })
                .map_err(|error| {
                    Stop::on_host(
                        &row.host,
                        format!("reading the attempts of {}: {error:#}", row.on_host()),
                    )
                })?;
            if let Some(attempt) = live {
                self.wait_for_attempt(attempt).await?;
                continue;
            }
            // A removal that succeeded leaves the row to review's finalizer,
            // also one waited for before a restart or by the scan for live
            // attempts; calling `remove` again before the row is gone would
            // start a second removal of the same instance.
            if latest.is_some_and(|attempt| {
                attempt.action == OperationAction::Remove
                    && attempt.outcome == Some(OperationOutcome::Succeeded)
            }) {
                self.wait_until_gone(customer_id, row).await?;
                record_removed(progress, row, called);
                return Ok(());
            }
            if !self.row_present(customer_id, row)? {
                record_removed(progress, row, called);
                return Ok(());
            }
            if check_in_use
                && let Err(error) = check_data_stores_in_use(&self.store, customer_id, false)
            {
                let reason = match error.downcast_ref::<DataStoreInUseError>() {
                    Some(DataStoreInUseError(message)) => message.clone(),
                    None => format!("{error:#}"),
                };
                return Err(Stop::new(reason).into());
            }
            progress
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(row.host.clone())
                .or_default()
                .remove_called = true;
            called = true;
            let removal = self
                .deployer
                .remove(&row.host, &row.package_id, Some(row.instance));
            let Some(answer) = self.unless_shutdown(removal).await else {
                return Err(Halt::ShutDown);
            };
            let (refused, since) = match answer {
                Ok(operation_id) => {
                    let attempt = read_store(&self.store)
                        .and_then(|store| store.operation_attempt_map().get(operation_id.as_str()))
                        .map_err(|error| {
                            Stop::on_host(
                                &row.host,
                                format!(
                                    "reading the attempt removing {}: {error:#}",
                                    row.on_host()
                                ),
                            )
                        })?;
                    let Some(attempt) = attempt else {
                        return Err(Stop::on_host(
                            &row.host,
                            format!(
                                "removing {} failed: the attempt {operation_id} is not in the ledger",
                                row.on_host()
                            ),
                        )
                        .into());
                    };
                    // A removal that succeeded is waited for to its row's
                    // end at the top of the loop.
                    self.wait_for_attempt(attempt).await?;
                    cleanup_pending_since = None;
                    under_maintenance_since = None;
                    continue;
                }
                Err(DeployError::CleanupPending { .. }) => {
                    under_maintenance_since = None;
                    (
                        "a teardown was still owed after 1 hour",
                        *cleanup_pending_since.get_or_insert_with(tokio::time::Instant::now),
                    )
                }
                Err(DeployError::UnderMaintenance) => {
                    cleanup_pending_since = None;
                    (
                        "REview stayed under maintenance for 1 hour",
                        *under_maintenance_since.get_or_insert_with(tokio::time::Instant::now),
                    )
                }
                Err(DeployError::SystemInstance { .. }) => {
                    return Err(Stop::on_host(
                        &row.host,
                        format!(
                            "removing {}: REview reports this row as the host's system log collector; the records disagree",
                            row.on_host()
                        ),
                    )
                    .into());
                }
                Err(error) => {
                    // An apply aborted by the embedding application's
                    // shutdown fails this way; its attempt stays live for the
                    // next start to wait for.
                    if self.shutting_down() {
                        return Err(Halt::ShutDown);
                    }
                    return Err(Stop::on_host(
                        &row.host,
                        format!("removing {} failed: {error:#}", row.on_host()),
                    )
                    .into());
                }
            };
            if since.elapsed() >= REMOVE_REFUSAL_LIMIT {
                return Err(Stop::on_host(
                    &row.host,
                    format!("removing {}: {refused}", row.on_host()),
                )
                .into());
            }
            self.pause().await?;
        }
    }

    /// Returns whether `row` is still on one of the customer's nodes.
    fn row_present(&self, customer_id: u32, row: &NumberedRow) -> Result<bool, Halt> {
        Ok(numbered_rows(&self.store, customer_id)
            .map_err(|error| Stop::on_host(&row.host, format!("{error:#}")))?
            .contains(row))
    }

    /// Waits until review's finalizer has dropped `row`.
    async fn wait_until_gone(&self, customer_id: u32, row: &NumberedRow) -> Result<(), Halt> {
        while self.row_present(customer_id, row)? {
            self.pause().await?;
        }
        Ok(())
    }

    /// Waits until `attempt` is terminal, re-reading it every poll interval,
    /// and returns it as it ended, or `None` if the ledger no longer holds
    /// it.
    ///
    /// A `Remove` that ends `Failed`, `RolledBack` or `Cancelled` stops the
    /// deletion. The wait has no bound of its own: review ends every attempt
    /// by its deadline.
    async fn wait_for_attempt(
        &self,
        mut attempt: OperationAttempt,
    ) -> Result<Option<OperationAttempt>, Halt> {
        loop {
            if attempt.is_terminal() {
                if attempt.action == OperationAction::Remove
                    && attempt.outcome != Some(OperationOutcome::Succeeded)
                {
                    return Err(failed_removal(&attempt).into());
                }
                return Ok(Some(attempt));
            }
            self.pause().await?;
            let read = read_store(&self.store)
                .and_then(|store| store.operation_attempt_map().get(&attempt.idempotency_key));
            attempt = match read {
                Ok(Some(attempt)) => attempt,
                Ok(None) => return Ok(None),
                Err(error) => {
                    return Err(Stop::on_host(
                        &attempt.host,
                        format!(
                            "reading the attempt {} on {}: {error:#}",
                            attempt.idempotency_key, attempt.host
                        ),
                    )
                    .into());
                }
            };
        }
    }

    /// Waits until no live attempt of a customer module exists on `hosts`,
    /// and returns whether it found one.
    async fn wait_for_module_attempts(&self, hosts: &[String]) -> Result<bool, Halt> {
        if hosts.is_empty() {
            return Ok(false);
        }
        let attempts =
            live_module_attempts(&self.store, hosts).map_err(|error| Halt::stop(&error))?;
        let found = !attempts.is_empty();
        for attempt in attempts {
            self.wait_for_attempt(attempt).await?;
        }
        Ok(found)
    }
}

/// Returns the live attempts of customer modules on `hosts`: those whose
/// target is a module, other than the hosts' own system log collectors.
///
/// No index of the ledger is keyed by host alone, so the records are
/// scanned, as `inFlightInstalls` scans them.
fn live_module_attempts(
    store: &RwLock<Store>,
    hosts: &[String],
) -> anyhow::Result<Vec<OperationAttempt>> {
    let store = read_store(store)?;
    let keep = |attempt: &OperationAttempt| {
        !attempt.is_terminal()
            && hosts.contains(&attempt.host)
            && MODULE_PACKAGE_IDS.contains(&attempt.target.as_str())
    };
    let mut candidates = Vec::new();
    for attempt in store.operation_attempt_map().iter(Direction::Forward, None) {
        let attempt = attempt.context("scanning the operation attempts")?;
        if keep(&attempt) {
            candidates.push(attempt);
        }
    }
    let candidates = operator_installs(&store, candidates, keep)
        .map_err(|error| anyhow!("reading the operation attempts: {}", error.message))?;
    let collectors = store.system_log_collector_map();
    let mut attempts = Vec::new();
    for attempt in candidates {
        if Some(attempt.target.as_str()) == AgentKind::LogCollector.package_id()
            && let Some(instance) = attempt.instance
            && collectors
                .get_by_instance(&attempt.host, instance)
                .context("reading the system log collectors")?
                .is_some()
        {
            continue;
        }
        attempts.push(attempt);
    }
    Ok(attempts)
}

/// Records `row` removed in its host's progress, if `remove` was called for
/// it.
fn record_removed(
    progress: &std::sync::Mutex<HashMap<String, HostProgress>>,
    row: &NumberedRow,
    called: bool,
) {
    if called {
        progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(row.host.clone())
            .or_default()
            .removed
            .push(row.name());
    }
}

/// Returns the refusal of the Review stage while the customer's nodes still
/// hold the rows named in `rows`, each as `<host> <package_id> <instance>`.
fn installed_modules_message(rows: &[String]) -> String {
    format!(
        "the customer's nodes still hold installed modules: {}",
        rows.join(", ")
    )
}

fn is_remote_service(service: CustomerDataDeletionService) -> bool {
    matches!(
        service,
        CustomerDataDeletionService::Sensor | CustomerDataDeletionService::SemiSupervised
    )
}

/// Returns the error of the job's first `Failed` Sensor or Semi-supervised
/// result, if there is one.
fn first_failed_remote_result(job: &CustomerDataDeletionJob) -> Option<String> {
    job.service_results
        .iter()
        .find(|result| {
            is_remote_service(result.service) && result.status == CustomerDataDeletionStatus::Failed
        })
        .map(|result| {
            result
                .error
                .clone()
                .unwrap_or_else(|| format!("{:?} deletion failed", result.service))
        })
}

fn read_job(store: &RwLock<Store>, customer_id: u32) -> anyhow::Result<CustomerDataDeletionJob> {
    read_store(store)?
        .customer_data_deletion_map()
        .get(customer_id)
        .with_context(|| format!("retrieving customer data deletion job {customer_id}"))?
        .ok_or_else(|| anyhow!("customer deletion job {customer_id} does not exist"))
}

/// Records the stop of a deletion: sets `Failed` the job's `InProgress`
/// Review result and every `Failed` Data Store result not in `dispatched`,
/// with "stopped before this part: <the reason>", and every `ModuleRemoval`
/// result not yet terminal, with the text `stop` gives its host.
///
/// Results already dispatched keep their state until reported: an
/// `InProgress` Data Store result was sent before it was recorded so.
fn persist_stop(
    store: &RwLock<Store>,
    customer_id: u32,
    stop: &Stop,
    dispatched: &[String],
) -> anyhow::Result<()> {
    let job = read_job(store, customer_id)?;
    let message = format!("stopped before this part: {}", stop.reason);
    let mut failures = Vec::new();
    for result in &job.service_results {
        let (host, error) = match (result.service, result.status) {
            (CustomerDataDeletionService::Review, CustomerDataDeletionStatus::InProgress) => {
                (None, message.clone())
            }
            (CustomerDataDeletionService::DataStore, CustomerDataDeletionStatus::Failed) => {
                match result.host_fqdns.first() {
                    Some(server_name) if !dispatched.contains(server_name) => {
                        (Some(server_name.as_str()), message.clone())
                    }
                    _ => continue,
                }
            }
            (
                CustomerDataDeletionService::ModuleRemoval,
                CustomerDataDeletionStatus::InProgress,
            ) => {
                let Some(host) = result.host_fqdns.first() else {
                    continue;
                };
                (Some(host.as_str()), stop.module_removal_error(host))
            }
            _ => continue,
        };
        if let Err(error) = persist_terminal(
            store,
            customer_id,
            result.service,
            host,
            CustomerDataDeletionStatus::Failed,
            Some(&error),
        ) {
            failures.push(format!("{:?}: {error:#}", result.service));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("{}", failures.join("; "))
    }
}

/// How the Data Store step ended.
#[derive(Debug, PartialEq, Eq)]
enum DataStoreStepOutcome {
    /// Every Data Store result is `Succeeded`.
    Completed,
    /// A Data Store result is `Failed`, or the step itself failed.
    Stopped {
        reason: String,
        /// The server names of the Data Stores this run sent to or waited
        /// for.
        dispatched: Vec<String>,
    },
    /// Shutdown ended the step's waits; the results it sent stay
    /// `InProgress`.
    ShutDown,
}

/// Where the Data Store step starts with one Data Store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataStoreNext {
    Send,
    /// Reads the result, after the poll interval when `delayed`.
    Read {
        delayed: bool,
    },
}

/// Asks every listed Data Store to delete the customer's events and its
/// sampling policies' periodic time series, and waits until each one's
/// result is terminal.
///
/// The targets are computed when the step runs: one per listed Data Store,
/// with `piglet.<host>` and `reproduce.<host>` for each host FQDN of the
/// job's Review result, and the job's periodic time series IDs. A service
/// FQDN the Data Store would refuse, one with fewer than three non-empty
/// labels, is left out; no event can have been ingested under it. With
/// neither a service FQDN nor an ID, no Data Store is asked.
///
/// A Data Store with no result or a `Failed` one has its result recorded
/// `InProgress` and is sent to; one with an `InProgress` result, sent before
/// a restart, is waited for. A Data Store no longer listed whose result is
/// not `Succeeded` can never be reached again, and is recorded `Succeeded`
/// with an error text saying nothing was deleted in it.
async fn data_store_step(
    store: &RwLock<Store>,
    agent_manager: &SharedAgentManager,
    shutdown: &mut watch::Receiver<bool>,
    customer_id: u32,
) -> DataStoreStepOutcome {
    drive_data_stores(store, agent_manager, shutdown, customer_id, None).await
}

/// Waits until the result of every Data Store already sent to is terminal,
/// for a deletion stopping with `reason`, and sends to none.
///
/// Only an `InProgress` result is waited for. One whose Data Store answers
/// it has no job was never sent, and is set `Failed` with "stopped before
/// this part: `reason`"; one no longer listed is recorded `Succeeded` as in
/// [`data_store_step`].
async fn settle_sent_data_stores(
    store: &RwLock<Store>,
    agent_manager: &SharedAgentManager,
    shutdown: &mut watch::Receiver<bool>,
    customer_id: u32,
    reason: &str,
) -> DataStoreStepOutcome {
    drive_data_stores(store, agent_manager, shutdown, customer_id, Some(reason)).await
}

/// Runs [`data_store_step`], or [`settle_sent_data_stores`] when
/// `stop_reason` is given.
async fn drive_data_stores(
    store: &RwLock<Store>,
    agent_manager: &SharedAgentManager,
    shutdown: &mut watch::Receiver<bool>,
    customer_id: u32,
    stop_reason: Option<&str>,
) -> DataStoreStepOutcome {
    let starts = match data_store_starts(store, customer_id, stop_reason.is_none()) {
        Ok(starts) => starts,
        Err(error) => {
            return DataStoreStepOutcome::Stopped {
                reason: format!("{error:#}"),
                dispatched: Vec::new(),
            };
        }
    };
    if starts.is_empty() {
        return DataStoreStepOutcome::Completed;
    }
    let dispatched: Vec<String> = starts
        .iter()
        .map(|start| start.target.server_name.clone())
        .collect();
    let drive = join_all(
        starts
            .iter()
            .map(|start| drive_data_store(store, agent_manager, start, stop_reason)),
    );
    // Dropping `drive` on shutdown drops each Data Store's work at an await,
    // a sleep or an agent manager call, never inside a store write. Its
    // result is `InProgress` from before the send, and the next start reads
    // it again, sending again if the Data Store has no job.
    let outcomes = tokio::select! {
        outcomes = drive => outcomes,
        () = wait_for_shutdown(shutdown) => return DataStoreStepOutcome::ShutDown,
    };
    match outcomes.into_iter().find_map(Result::err) {
        None => DataStoreStepOutcome::Completed,
        Some(reason) => DataStoreStepOutcome::Stopped { reason, dispatched },
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    if shutdown.wait_for(|stopping| *stopping).await.is_err() {
        // The task manager is gone, and nothing can shut the step down.
        std::future::pending::<()>().await;
    }
}

/// One Data Store the step drives, and where it starts.
struct DataStoreStart {
    target: DataStoreDeletionTarget,
    /// The `requested_at` of the Data Store's stored result, or the time to
    /// record it with.
    requested_at: i64,
    /// Whether no result is stored for the Data Store yet.
    new: bool,
    next: DataStoreNext,
}

/// Computes the Data Store targets and settles the results of Data Stores no
/// longer listed.
///
/// Unless `sending`, only the Data Stores with an `InProgress` result are
/// considered.
fn data_store_starts(
    store: &RwLock<Store>,
    customer_id: u32,
    sending: bool,
) -> anyhow::Result<Vec<DataStoreStart>> {
    let job = read_job(store, customer_id)?;
    let review_hosts = job
        .service_results
        .iter()
        .find(|result| result.service == CustomerDataDeletionService::Review)
        .map_or(&[][..], |result| result.host_fqdns.as_slice());
    let service_fqdns = data_store_service_fqdns(review_hosts);
    if service_fqdns.is_empty() && job.periodic_time_series_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut rows = listed_rows(&*read_store(store)?)
        .map_err(|error| anyhow!("listing the Data Stores: {}", error.message))?;
    rows.sort_unstable_by(|a, b| (&a.hostname, a.instance).cmp(&(&b.hostname, b.instance)));
    rows.dedup_by(|a, b| a.hostname == b.hostname && a.instance == b.instance);

    let existing: Vec<_> = job
        .service_results
        .iter()
        .filter(|result| result.service == CustomerDataDeletionService::DataStore)
        .collect();
    for result in &existing {
        let Some(server_name) = result.host_fqdns.first() else {
            continue;
        };
        if result.status == CustomerDataDeletionStatus::Succeeded
            || (!sending && result.status == CustomerDataDeletionStatus::Failed)
            || rows.iter().any(|row| row.server_name() == *server_name)
        {
            continue;
        }
        warn!(
            customer_id,
            server_name, "a Data Store to delete the customer's data in is no longer registered"
        );
        persist_terminal(
            store,
            customer_id,
            CustomerDataDeletionService::DataStore,
            Some(server_name),
            CustomerDataDeletionStatus::Succeeded,
            Some(DATA_STORE_NOT_REGISTERED),
        )?;
    }

    let now = timestamp_nanos()?;
    let mut starts = Vec::new();
    for row in rows {
        let target = DataStoreDeletionTarget::new(
            customer_id,
            row.hostname,
            row.instance,
            service_fqdns.clone(),
            job.periodic_time_series_ids.clone(),
        );
        let stored = existing
            .iter()
            .find(|result| result.host_fqdns.first() == Some(&target.server_name));
        let (requested_at, new, next) = match stored {
            None if sending => (now, true, DataStoreNext::Send),
            None => continue,
            Some(result) => match result.status {
                CustomerDataDeletionStatus::Failed if sending => (now, false, DataStoreNext::Send),
                CustomerDataDeletionStatus::Succeeded | CustomerDataDeletionStatus::Failed => {
                    continue;
                }
                CustomerDataDeletionStatus::InProgress => (
                    result.requested_at,
                    false,
                    DataStoreNext::Read { delayed: false },
                ),
            },
        };
        starts.push(DataStoreStart {
            target,
            requested_at,
            new,
            next,
        });
    }
    Ok(starts)
}

/// Returns the sorted service FQDNs of `hosts` the Data Store accepts.
fn data_store_service_fqdns(hosts: &[String]) -> Vec<String> {
    let mut fqdns = Vec::with_capacity(hosts.len() * 2);
    for host in hosts {
        let names = [
            service_fqdn("piglet", host),
            service_fqdn("reproduce", host),
        ];
        if names.iter().any(|name| {
            name.split('.').filter(|label| !label.is_empty()).count() < MIN_SERVICE_FQDN_LABELS
        }) {
            // Such a host has no events in a Data Store, which accepts only
            // certificates naming `<instance>.<service>.<host>.<domain>`.
            warn!(
                host,
                "host name is too short for the Data Store; its service names are left out"
            );
            continue;
        }
        fqdns.extend(names);
    }
    sort_dedup(&mut fqdns);
    fqdns
}

/// Sends to and waits for one Data Store until its result is terminal, and
/// returns the result's error if it ended `Failed`, or if a store write
/// failed.
async fn drive_data_store(
    store: &RwLock<Store>,
    agent_manager: &SharedAgentManager,
    start: &DataStoreStart,
    stop_reason: Option<&str>,
) -> Result<(), String> {
    let target = &start.target;
    let customer_id = target.customer_id;
    if start.next == DataStoreNext::Send {
        record_data_store_request(store, customer_id, start)
            .map_err(|error| format!("{error:#}"))?;
    }
    let (status, error) = wait_for_data_store(agent_manager, start, stop_reason)
        .await
        .map_err(|error| format!("{error:#}"))?;
    persist_terminal(
        store,
        customer_id,
        CustomerDataDeletionService::DataStore,
        Some(&target.server_name),
        status,
        error.as_deref(),
    )
    .map_err(|error| format!("{error:#}"))?;
    match error {
        Some(error) if status == CustomerDataDeletionStatus::Failed => Err(error),
        _ => Ok(()),
    }
}

/// Records a Data Store's result `InProgress` before it is sent to.
fn record_data_store_request(
    store: &RwLock<Store>,
    customer_id: u32,
    start: &DataStoreStart,
) -> anyhow::Result<()> {
    let result = service_result(
        CustomerDataDeletionService::DataStore,
        vec![start.target.server_name.clone()],
        start.requested_at,
    );
    let store = read_store(store)?;
    let map = store.customer_data_deletion_map();
    if start.new {
        map.add_service(customer_id, &result)
    } else {
        map.update_service(customer_id, &result)
    }
    .with_context(|| {
        format!(
            "recording the Data Store deletion request to {}",
            start.target.server_name
        )
    })?;
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::DataStoreRecorded, customer_id)?;
    Ok(())
}

/// Sends to and reads one Data Store until it is done, and returns the
/// terminal status and error to record.
///
/// The deadlines bound the agent manager's calls too: a send that has not
/// returned by the 24-hour deadline ends there, and a read that has not
/// returned counts as a transport error from when it was made. With
/// `stop_reason`, a Data Store with no job is not sent to; its result is
/// set `Failed` with "stopped before this part: `stop_reason`".
#[allow(clippy::too_many_lines)]
async fn wait_for_data_store(
    agent_manager: &SharedAgentManager,
    start: &DataStoreStart,
    stop_reason: Option<&str>,
) -> anyhow::Result<(CustomerDataDeletionStatus, Option<String>)> {
    let target = &start.target;
    let deadline = start
        .requested_at
        .saturating_add(DATA_STORE_RESULT_DEADLINE_NANOS);
    let no_result = || {
        (
            CustomerDataDeletionStatus::Failed,
            Some(format!(
                "no result from {} within 24 hours",
                target.server_name
            )),
        )
    };
    let mut next = start.next;
    let mut failing_since: Option<tokio::time::Instant> = None;
    loop {
        if let DataStoreNext::Read { delayed: true } = next {
            tokio::time::sleep(DATA_STORE_POLL_INTERVAL).await;
        }
        let now = timestamp_nanos()?;
        if now >= deadline {
            return Ok(no_result());
        }
        let until_deadline =
            Duration::from_nanos(u64::try_from(deadline.saturating_sub(now)).unwrap_or_default());
        next = match next {
            DataStoreNext::Send => {
                let Ok(answer) = tokio::time::timeout(
                    until_deadline,
                    agent_manager.request_data_store_customer_deletion(target),
                )
                .await
                else {
                    return Ok(no_result());
                };
                match answer {
                    Ok(DataStoreRequestAnswer::Accepted | DataStoreRequestAnswer::InProgress) => {
                        DataStoreNext::Read { delayed: true }
                    }
                    Ok(
                        DataStoreRequestAnswer::AlreadyCompleted
                        | DataStoreRequestAnswer::NoLocalTarget,
                    ) => return Ok((CustomerDataDeletionStatus::Succeeded, None)),
                    Ok(DataStoreRequestAnswer::Blocked) => {
                        tokio::time::sleep(DATA_STORE_BLOCKED_RETRY_INTERVAL).await;
                        DataStoreNext::Send
                    }
                    Err(error) => {
                        return Ok((
                            CustomerDataDeletionStatus::Failed,
                            Some(format!("{error:#}")),
                        ));
                    }
                }
            }
            DataStoreNext::Read { .. } => {
                let read_at = tokio::time::Instant::now();
                let since = failing_since.unwrap_or(read_at);
                let until_error_limit =
                    (since + DATA_STORE_TRANSPORT_ERROR_LIMIT).saturating_duration_since(read_at);
                let Ok(read) = tokio::time::timeout(
                    until_deadline.min(until_error_limit),
                    agent_manager.data_store_customer_deletion_result(target),
                )
                .await
                else {
                    if until_deadline <= until_error_limit {
                        return Ok(no_result());
                    }
                    return Ok((
                        CustomerDataDeletionStatus::Failed,
                        Some(format!(
                            "no answer from {} for 10 minutes: the result query did not return",
                            target.server_name
                        )),
                    ));
                };
                match read {
                    Ok(Some(CustomerDataDeletionStatus::Succeeded)) => {
                        return Ok((CustomerDataDeletionStatus::Succeeded, None));
                    }
                    Ok(Some(CustomerDataDeletionStatus::Failed)) => {
                        return Ok((
                            CustomerDataDeletionStatus::Failed,
                            Some(format!(
                                "{} reported that the deletion failed",
                                target.server_name
                            )),
                        ));
                    }
                    Ok(Some(CustomerDataDeletionStatus::InProgress)) => {
                        failing_since = None;
                        DataStoreNext::Read { delayed: true }
                    }
                    // The request was recorded but never reached the Data
                    // Store: it is sent again, unless the deletion is
                    // stopping.
                    Ok(None) => match stop_reason {
                        None => {
                            failing_since = None;
                            DataStoreNext::Send
                        }
                        Some(reason) => {
                            return Ok((
                                CustomerDataDeletionStatus::Failed,
                                Some(format!("stopped before this part: {reason}")),
                            ));
                        }
                    },
                    Err(error) => {
                        failing_since = Some(since);
                        if since.elapsed() >= DATA_STORE_TRANSPORT_ERROR_LIMIT {
                            return Ok((
                                CustomerDataDeletionStatus::Failed,
                                Some(format!(
                                    "no answer from {} for 10 minutes: {error:#}",
                                    target.server_name
                                )),
                            ));
                        }
                        DataStoreNext::Read { delayed: true }
                    }
                }
            }
        };
    }
}

async fn run_review_worker_and_persist(
    store: Arc<RwLock<Store>>,
    policies_lock: Arc<SamplingPoliciesLock>,
    customer_id: u32,
    targets: ReviewDeletionTargets,
) {
    let worker_store = Arc::clone(&store);
    let outcome = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        tests::checkpoint(
            &*read_store(&worker_store)?,
            tests::Stage::Worker,
            customer_id,
        )?;
        delete_review_data(&worker_store, &policies_lock, customer_id, &targets)
    })
    .await;
    let (status, error_message) = match outcome {
        Ok(Ok(())) => (CustomerDataDeletionStatus::Succeeded, None),
        Ok(Err(worker_error)) => (
            CustomerDataDeletionStatus::Failed,
            Some(format!("{worker_error:#}")),
        ),
        Err(join_error) => (
            CustomerDataDeletionStatus::Failed,
            Some(format!(
                "Review deletion worker failed to join: {join_error}"
            )),
        ),
    };
    if let Err(persist_error) =
        persist_review_terminal(&store, customer_id, status, error_message.as_deref())
    {
        error!(
            customer_id,
            "failed to persist Review deletion result: {persist_error:#}"
        );
    }
}

/// Deletes the Review data of customer `customer_id`.
///
/// It refuses before touching anything while one of the customer's nodes
/// still holds a row with an instance number, what the Central Manager
/// installed and the earlier stages uninstall. A row without one, registered
/// by hand, is removed from the records only, and its removal is logged.
///
/// It runs on a blocking worker: it waits for `policies_lock` there.
fn delete_review_data(
    store_lock: &RwLock<Store>,
    policies_lock: &SamplingPoliciesLock,
    customer_id: u32,
    targets: &ReviewDeletionTargets,
) -> anyhow::Result<()> {
    let store = read_store(store_lock)?;
    refuse_installed_modules(&store, &targets.node_ids)?;
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::Events, customer_id).with_context(|| {
        format!(
            "deleting customer events for {:?}",
            targets.event_service_fqdns
        )
    })?;
    store
        .events()
        .remove_by_sensors(&targets.event_service_fqdns)
        .with_context(|| {
            format!(
                "deleting customer events for {:?}",
                targets.event_service_fqdns
            )
        })?;
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::Hosts, customer_id)?;
    store
        .hosts_map()
        .remove_by_customer_id(customer_id)
        .with_context(|| format!("deleting hosts for customer {customer_id}"))?;
    for host_fqdn in &targets.host_fqdns {
        #[cfg(test)]
        tests::checkpoint(&store, tests::Stage::TrafficFilters, customer_id)?;
        store
            .traffic_filter_map()
            .remove(host_fqdn)
            .with_context(|| format!("deleting traffic filter rules for {host_fqdn}"))?;
    }
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::CustomerNetworks, customer_id)
        .with_context(|| format!("deleting customer networks for customer {customer_id}"))?;
    store
        .customer_networks_map()
        .remove(customer_id)
        .with_context(|| format!("deleting customer networks for customer {customer_id}"))?;
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::NetworkLists, customer_id)
        .with_context(|| format!("deleting network lists for customer {customer_id}"))?;
    store
        .network_lists_map()
        .remove(customer_id)
        .with_context(|| format!("deleting network lists for customer {customer_id}"))?;
    for node_id in &targets.node_ids {
        #[cfg(test)]
        tests::checkpoint(&store, tests::Stage::Nodes, customer_id)?;
        let Some((node, _, _)) = store.node_map().get_by_id(*node_id)? else {
            continue;
        };
        let host = node_host(&node);
        for agent in &node.agents {
            warn!(
                node_id,
                host,
                kind = ?agent.kind,
                "removing an agent registered by hand from the records only; it keeps running"
            );
        }
        for service in &node.external_services {
            warn!(
                node_id,
                host,
                kind = ?service.kind,
                "removing an external service registered by hand from the records only; it keeps running"
            );
        }
        let (_, invalid_agents, invalid_external_services) = store
            .node_map()
            .remove(*node_id)
            .with_context(|| format!("deleting node {node_id}"))?;
        #[cfg(test)]
        let (invalid_agents, invalid_external_services) =
            tests::injected_associated_deletion_failures(&store, *node_id)
                .unwrap_or((invalid_agents, invalid_external_services));
        retry_failed_associated_deletions(
            &store,
            *node_id,
            &invalid_agents,
            &invalid_external_services,
        )?;
    }
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::Unsupervised, customer_id).with_context(|| {
        format!("deleting Unsupervised Engine records for customer {customer_id}")
    })?;
    store
        .remove_customer_unsupervised_records(customer_id)
        .with_context(|| {
            format!("deleting Unsupervised Engine records for customer {customer_id}")
        })?;
    // Removing the nodes detached the customer's engine instances and
    // cleared every assignment of its generators, so no generator is told.
    // The customer's models and definitions, which may have named these
    // policies, are already gone. The lock keeps a `removeSamplingPolicies`
    // from finding a policy it checked gone; it is taken before the store,
    // as a removal takes it.
    drop(store);
    let _policies = policies_lock.blocking_lock();
    read_store(store_lock)?
        .sampling_policy_map()
        .remove_customer_policies(customer_id)
        .with_context(|| format!("deleting sampling policies for customer {customer_id}"))?;
    Ok(())
}

/// Refuses while one of `node_ids` holds a row with an instance number.
///
/// This is the numbered half of the check `removeNodes` applies; a row whose
/// record is missing is left to `retry_failed_associated_deletions`.
fn refuse_installed_modules(store: &Store, node_ids: &[u32]) -> anyhow::Result<()> {
    let mut installed = Vec::new();
    for node_id in node_ids {
        if let Some((node, _, _)) = store
            .node_map()
            .get_by_id(*node_id)
            .with_context(|| format!("retrieving node {node_id}"))?
        {
            installed.extend(
                node_numbered_rows(&node, node_host(&node))
                    .into_iter()
                    .map(|row| format!("{} {}", row.host, row.name())),
            );
        }
    }
    if installed.is_empty() {
        Ok(())
    } else {
        bail!("{}", installed_modules_message(&installed))
    }
}

/// Returns the host name of `node`'s applied profile, or its name without
/// one.
fn node_host(node: &Node) -> &str {
    node.profile
        .as_ref()
        .map_or(node.name.as_str(), |profile| profile.hostname.as_str())
}

fn retry_failed_associated_deletions(
    store: &Store,
    node_id: u32,
    invalid_agents: &[String],
    invalid_external_services: &[String],
) -> anyhow::Result<()> {
    let mut failed_agents = Vec::new();
    for agent_key in invalid_agents {
        let result = retry_agent_deletion(store, node_id, agent_key);
        if let Err(error) = result {
            error!(
                node_id,
                agent_key, "retrying connected agent deletion failed: {error:#}"
            );
            failed_agents.push(format!("{agent_key}: {error:#}"));
        }
    }

    let mut failed_external_services = Vec::new();
    for external_service_key in invalid_external_services {
        let result = retry_external_service_deletion(store, node_id, external_service_key);
        if let Err(error) = result {
            error!(
                node_id,
                external_service_key,
                "retrying connected external service deletion failed: {error:#}"
            );
            failed_external_services.push(format!("{external_service_key}: {error:#}"));
        }
    }

    if failed_agents.is_empty() && failed_external_services.is_empty() {
        return Ok(());
    }
    bail!(
        "deleting connected records for node {node_id} failed after retry (agents: {failed_agents:?}, external services: {failed_external_services:?})"
    )
}

fn retry_agent_deletion(store: &Store, node_id: u32, agent_key: &str) -> anyhow::Result<()> {
    #[cfg(test)]
    tests::checkpoint(store, tests::Stage::RetryAgent, node_id)?;
    store.agents_map().delete(node_id, agent_key)
}

fn retry_external_service_deletion(
    store: &Store,
    node_id: u32,
    external_service_key: &str,
) -> anyhow::Result<()> {
    #[cfg(test)]
    tests::checkpoint(store, tests::Stage::RetryExternalService, node_id)?;
    store
        .external_service_map()
        .delete(node_id, external_service_key)
}

fn persist_review_terminal(
    store: &RwLock<Store>,
    customer_id: u32,
    status: CustomerDataDeletionStatus,
    error_message: Option<&str>,
) -> anyhow::Result<()> {
    persist_terminal(
        store,
        customer_id,
        CustomerDataDeletionService::Review,
        None,
        status,
        error_message,
    )
}

/// Records a terminal `status` on one result of the job, keeping its
/// `requested_at`, and tries once more if that fails.
///
/// `host` names the result's only host FQDN; the Review result, of which a
/// job has one, is found without it.
fn persist_terminal(
    store: &RwLock<Store>,
    customer_id: u32,
    service: CustomerDataDeletionService,
    host: Option<&str>,
    status: CustomerDataDeletionStatus,
    error_message: Option<&str>,
) -> anyhow::Result<()> {
    let completed_at = timestamp_nanos()?;
    let mut last_error = None;
    for _ in 1..=TERMINAL_STATUS_UPDATE_ATTEMPTS {
        match persist_terminal_once(
            store,
            customer_id,
            service,
            host,
            status,
            completed_at,
            error_message,
        ) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("two terminal persistence attempts always produce an error"))
}

fn persist_terminal_once(
    store: &RwLock<Store>,
    customer_id: u32,
    service: CustomerDataDeletionService,
    host: Option<&str>,
    status: CustomerDataDeletionStatus,
    completed_at: i64,
    error_message: Option<&str>,
) -> anyhow::Result<()> {
    let store = read_store(store)?;
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::PersistTerminal, customer_id)?;
    let job = store
        .customer_data_deletion_map()
        .get(customer_id)?
        .ok_or_else(|| anyhow!("customer deletion job {customer_id} does not exist"))?;
    let mut result = job
        .service_results
        .into_iter()
        .find(|result| {
            result.service == service
                && host
                    .is_none_or(|host| result.host_fqdns.first().map(String::as_str) == Some(host))
        })
        .ok_or_else(|| {
            anyhow!("customer deletion job {customer_id} has no {service:?} result for {host:?}")
        })?;
    result.status = status;
    result.completed_at = Some(completed_at);
    result.error = error_message.map(str::to_owned);
    store
        .customer_data_deletion_map()
        .update_service(customer_id, &result)
        .with_context(|| format!("updating {service:?} customer deletion result"))
}

/// The customer deletions found unfinished at startup.
///
/// The embedding application dispatches the remote targets when their
/// agents connect, and calls [`start`](Self::start) to resume the jobs.
pub struct RecoveredDeletions {
    store: Arc<RwLock<Store>>,
    remote_targets: Vec<CustomerDataDeletionTarget>,
    jobs: Vec<CustomerDataDeletionExecutionPlan>,
}

impl RecoveredDeletions {
    /// Returns the `InProgress` Sensor and Semi-supervised targets, to
    /// dispatch when their agents connect.
    #[must_use]
    pub fn remote_targets(&self) -> &[CustomerDataDeletionTarget] {
        &self.remote_targets
    }

    /// Takes the targets [`remote_targets`](Self::remote_targets) returns,
    /// leaving none.
    pub fn take_remote_targets(&mut self) -> Vec<CustomerDataDeletionTarget> {
        std::mem::take(&mut self.remote_targets)
    }

    /// Returns the customers whose jobs [`start`](Self::start) resumes, in
    /// the order it resumes them.
    #[must_use]
    pub fn resumed_customer_ids(&self) -> Vec<u32> {
        self.jobs.iter().map(|job| job.customer_id).collect()
    }

    /// Spawns the supervisor that resumes each job, one after another, from
    /// its persisted state.
    ///
    /// A job resumes at its first stage, and each stage skips what is done:
    /// it sends no Sensor or Semi-supervised target, which the embedding
    /// application sends itself, but waits for their results; it waits for a
    /// live attempt rather than removing a module again; it waits for the
    /// Data Stores it sent to, after its senders are uninstalled, and sends
    /// to those it has not; and it runs its Review stage if its Review result
    /// is `InProgress`. A stopped job, whose Review result is not
    /// `InProgress`, only waits for its Sensor and Semi-supervised results.
    ///
    /// `deployer` uninstalls the customer's modules; it is the one the GraphQL
    /// schema holds.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown has started or a deletion supervisor is
    /// already active.
    pub async fn start(
        self,
        deployer: SharedPackageDeployer,
        agent_manager: SharedAgentManager,
        task_manager: Arc<CustomerDataDeletionTaskManager>,
    ) -> anyhow::Result<()> {
        let Some(first_customer_id) = self.jobs.first().map(|job| job.customer_id) else {
            return Ok(());
        };
        let mut state = task_manager.state.lock().await;
        if state.shutting_down {
            bail!("cannot start customer data deletion recovery during shutdown");
        }
        if state
            .active
            .as_ref()
            .is_some_and(|(_, handle)| !handle.is_finished())
        {
            bail!("a customer data deletion supervisor is already active");
        }
        _ = state.active.take();
        let jobs = self.jobs;
        let supervisor_manager = Arc::clone(&task_manager);
        let deletion = Supervisor {
            store: self.store,
            agent_manager,
            deployer,
            policies_lock: Arc::clone(task_manager.sampling_policies_lock()),
            shutdown: task_manager.shutdown.subscribe(),
        };
        let supervisor = tokio::spawn(async move {
            for job in jobs {
                {
                    let mut state = supervisor_manager.state.lock().await;
                    if state.shutting_down {
                        break;
                    }
                    if let Some((active_customer_id, _)) = state.active.as_mut() {
                        *active_customer_id = job.customer_id;
                    }
                }
                deletion.run(job, Start::Resume).await;
            }
        });
        // Do not yield between creating and publishing the outer supervisor.
        state.active = Some((first_customer_id, supervisor));
        Ok(())
    }
}

/// Scans the persisted customer deletions for unfinished work.
///
/// It only reads: the returned [`RecoveredDeletions`] holds the remote
/// targets to dispatch, and resumes the jobs once started. A job is resumed
/// when any of its results is `InProgress`.
///
/// # Errors
///
/// Returns an error if the job table cannot be scanned or a persisted
/// deletion result is invalid.
pub fn recover_customer_data_deletion_on_startup(
    store: Arc<RwLock<Store>>,
) -> anyhow::Result<RecoveredDeletions> {
    let jobs = {
        let store_guard = read_store(&store)?;
        let mut jobs = Vec::new();
        for job in store_guard
            .customer_data_deletion_map()
            .iter(Direction::Forward, None)
        {
            let job = job.context("scanning customer data deletion jobs for recovery")?;
            if job
                .service_results
                .iter()
                .any(|result| result.status == CustomerDataDeletionStatus::InProgress)
            {
                jobs.push(job);
            }
        }
        jobs
    };
    let mut plans = Vec::with_capacity(jobs.len());
    for job in &jobs {
        plans.push(plan_from_results(
            &store,
            job,
            CustomerDataDeletionStatus::InProgress,
        )?);
    }
    plans.sort_unstable_by_key(|plan| plan.customer_id);
    if plans.len() > 1 {
        let customer_ids: Vec<_> = plans.iter().map(|plan| plan.customer_id).collect();
        error!(
            count = plans.len(),
            ?customer_ids,
            "multiple customer deletion jobs require startup recovery"
        );
    }
    let mut remote_targets = Vec::new();
    for plan in &mut plans {
        remote_targets.append(&mut plan.remote_targets);
    }
    Ok(RecoveredDeletions {
        store,
        remote_targets,
        jobs: plans,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, VecDeque};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use async_graphql::{EmptySubscription, Request, Schema};
    use async_trait::async_trait;
    use ipnet::IpNet;
    use review_database::{
        Agent, AgentStatus, EventCategory, ExternalService, ExternalServiceStatus,
        HostNetworkGroup, NetworkListEntry, NodeProfile, OperationFailureKind, OperationPhase,
        OperationRetryPolicy, OwnedNetwork,
        event::{DnsEventFields, Event, EventKind, EventMessage, NetworkType},
    };
    use rocksdb::{OptimisticTransactionDB, Options, SingleThreaded};

    use super::*;
    use crate::backend::{AgentManager, PackageDeployer, ResourceUsage};
    use crate::graphql::NetworksTargetAgentLookupKeysPair;
    use crate::graphql::model_test_support::{
        TestModel, insert_definition, insert_engine_node, insert_indicator,
        name_in_applied_document,
    };

    const RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);

    static TEST_DB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct TestStore {
        _permit: std::sync::MutexGuard<'static, ()>,
        _db_dir: tempfile::TempDir,
        _backup_dir: tempfile::TempDir,
        store: Arc<RwLock<Store>>,
    }

    struct TestQuery;

    #[Object]
    impl TestQuery {
        async fn api_version(&self) -> &str {
            "test"
        }
    }

    impl TestStore {
        fn new() -> Self {
            let permit = TEST_DB_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let db_dir = tempfile::tempdir().unwrap();
            let backup_dir = tempfile::tempdir().unwrap();
            let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
            Self {
                _permit: permit,
                _db_dir: db_dir,
                _backup_dir: backup_dir,
                store: Arc::new(RwLock::new(store)),
            }
        }
    }

    type DataStoreRead = Result<Option<CustomerDataDeletionStatus>, String>;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum DataStoreCall {
        Send,
        Read,
    }

    #[derive(Default)]
    struct RecordingAgentManager {
        targets: std::sync::Mutex<Vec<CustomerDataDeletionTarget>>,
        fail_delivery: bool,
        /// The targets, by service key, whose agents report that the
        /// deletion failed.
        fail_reports: Vec<String>,
        /// Returns an error and leaves every target `InProgress`, as a
        /// closed maintenance gate does. Otherwise a delivery that does not
        /// fail records every target `Succeeded` when the manager has a
        /// store, as the agents' reports would.
        hold_delivery: bool,
        delivery_gate: Option<Arc<tokio::sync::Semaphore>>,
        delivery_started: tokio::sync::Notify,
        /// The store a failed delivery records its targets `Failed` in, and
        /// the job is read from when a Data Store is sent to.
        store: Option<Arc<RwLock<Store>>>,
        /// The answers to Data Store requests, in order; after them,
        /// `default_answer`, or `Accepted`.
        answers: std::sync::Mutex<VecDeque<Result<DataStoreRequestAnswer, String>>>,
        default_answer: Option<DataStoreRequestAnswer>,
        /// The answers to Data Store result reads, in order; after them,
        /// `default_read`, or `Succeeded`.
        reads: std::sync::Mutex<VecDeque<DataStoreRead>>,
        default_read: Option<DataStoreRead>,
        /// The Data Store call that never returns once `answers` or `reads`
        /// run out.
        hang: Option<DataStoreCall>,
        /// Every Data Store request, when it was made, and the job then.
        sent: std::sync::Mutex<Vec<(DataStoreDeletionTarget, tokio::time::Instant)>>,
        jobs_at_send: std::sync::Mutex<Vec<CustomerDataDeletionJob>>,
        /// Every Data Store result read, and when it was made.
        read_at: std::sync::Mutex<Vec<(String, tokio::time::Instant)>>,
        /// The order of the dispatch and the Data Store requests.
        log: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RecordingAgentManager {
        fn with_store(store: &Arc<RwLock<Store>>) -> Self {
            Self {
                store: Some(Arc::clone(store)),
                ..Self::default()
            }
        }

        fn answers(self, answers: impl IntoIterator<Item = DataStoreRequestAnswer>) -> Self {
            *self.answers.lock().unwrap() = answers.into_iter().map(Ok).collect();
            self
        }

        fn reads(self, reads: impl IntoIterator<Item = DataStoreRead>) -> Self {
            *self.reads.lock().unwrap() = reads.into_iter().collect();
            self
        }

        /// Returns whether no Sensor or Semi-supervised target was sent.
        fn dispatched_nothing(&self) -> bool {
            self.targets.lock().unwrap().is_empty()
                && !self
                    .log
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|entry| entry == "dispatch")
        }

        fn sent_server_names(&self) -> Vec<String> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .map(|(target, _)| target.server_name().to_string())
                .collect()
        }
    }

    /// Records the result of `target` `Failed` with `error`, as the agent
    /// manager does for a target it cannot deliver.
    fn fail_target(store: &RwLock<Store>, target: &CustomerDataDeletionTarget, error: &str) {
        report_target(
            store,
            target,
            CustomerDataDeletionStatus::Failed,
            Some(error),
        );
    }

    /// Records the result of `target` `status`, as a report does.
    fn report_target(
        store: &RwLock<Store>,
        target: &CustomerDataDeletionTarget,
        status: CustomerDataDeletionStatus,
        error: Option<&str>,
    ) {
        let service = if target.target_service_key().starts_with("piglet.") {
            CustomerDataDeletionService::Sensor
        } else {
            CustomerDataDeletionService::SemiSupervised
        };
        persist_terminal(
            store,
            target.customer_id(),
            service,
            Some(target.host_fqdn()),
            status,
            error,
        )
        .unwrap();
    }

    #[async_trait]
    impl AgentManager for RecordingAgentManager {
        async fn request_customer_data_deletion(
            &self,
            targets: &[CustomerDataDeletionTarget],
        ) -> anyhow::Result<()> {
            self.targets.lock().unwrap().extend_from_slice(targets);
            self.log.lock().unwrap().push("dispatch".to_string());
            self.delivery_started.notify_one();
            if let Some(gate) = &self.delivery_gate {
                gate.acquire().await.unwrap().forget();
            }
            if self.fail_delivery {
                if let Some(store) = &self.store {
                    for target in targets {
                        fail_target(store, target, "delivery failed");
                    }
                }
                bail!("delivery failed");
            }
            if self.hold_delivery {
                bail!("held by the closed maintenance gate");
            }
            if let Some(store) = &self.store {
                for target in targets {
                    if self
                        .fail_reports
                        .iter()
                        .any(|key| key == target.target_service_key())
                    {
                        report_target(
                            store,
                            target,
                            CustomerDataDeletionStatus::Failed,
                            Some("the deletion failed on the host"),
                        );
                    } else {
                        report_target(store, target, CustomerDataDeletionStatus::Succeeded, None);
                    }
                }
            }
            Ok(())
        }

        async fn request_data_store_customer_deletion(
            &self,
            target: &DataStoreDeletionTarget,
        ) -> anyhow::Result<DataStoreRequestAnswer> {
            self.sent
                .lock()
                .unwrap()
                .push((target.clone(), tokio::time::Instant::now()));
            self.log
                .lock()
                .unwrap()
                .push(format!("send {}", target.server_name()));
            if let Some(store) = &self.store {
                let job = job(store, target.customer_id());
                self.jobs_at_send.lock().unwrap().push(job);
            }
            let answer = self.answers.lock().unwrap().pop_front();
            match answer {
                Some(answer) => answer.map_err(|error| anyhow!(error)),
                None if self.hang == Some(DataStoreCall::Send) => std::future::pending().await,
                None => Ok(self
                    .default_answer
                    .unwrap_or(DataStoreRequestAnswer::Accepted)),
            }
        }

        async fn data_store_customer_deletion_result(
            &self,
            target: &DataStoreDeletionTarget,
        ) -> anyhow::Result<Option<CustomerDataDeletionStatus>> {
            self.read_at.lock().unwrap().push((
                target.server_name().to_string(),
                tokio::time::Instant::now(),
            ));
            let read = self.reads.lock().unwrap().pop_front();
            if read.is_none() && self.hang == Some(DataStoreCall::Read) {
                return std::future::pending().await;
            }
            read.or_else(|| self.default_read.clone())
                .unwrap_or(Ok(Some(CustomerDataDeletionStatus::Succeeded)))
                .map_err(|error| anyhow!(error))
        }

        async fn send_agent_specific_internal_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn send_agent_specific_allow_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn send_agent_specific_block_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn online_apps_by_host_id(
            &self,
        ) -> anyhow::Result<HashMap<String, Vec<(String, String)>>> {
            Ok(HashMap::new())
        }

        async fn sampling_policies_changed(&self, _generators: &[review_database::ModelInstance]) {}

        async fn capabilities(&self, _hostname: &str) -> anyhow::Result<BTreeSet<String>> {
            Ok(BTreeSet::new())
        }

        async fn get_resource_usage(&self, _hostname: &str) -> anyhow::Result<ResourceUsage> {
            bail!("not used")
        }

        async fn halt(&self, _hostname: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn ping(&self, _hostname: &str) -> anyhow::Result<Duration> {
            Ok(Duration::ZERO)
        }

        async fn reboot(&self, _hostname: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn update_config(&self, _agent_lookup_key: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn update_traffic_filter_rules(
            &self,
            _host: &str,
            _rules: &[(IpNet, Option<Vec<u16>>, Option<Vec<u16>>)],
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// What [`RecordingDeployer`] does with one `remove` call.
    #[derive(Clone, Debug)]
    enum RemoveAnswer {
        /// Records a `Remove` attempt `Succeeded` and drops the row, as
        /// review's finalizer does.
        Succeed,
        /// Records a live `Remove` attempt and returns its id; the test ends
        /// it.
        Live,
        CleanupPending,
        UnderMaintenance,
        SystemInstance,
        Other,
        /// Records a live `Remove` attempt and never returns. The apply goes
        /// on in a task of the deployer's own, as review's does, and ends
        /// `Succeeded` when `release` is notified.
        Hang,
    }

    /// A `remove` call: the host, the package-id and the instance.
    type RemoveCall = (String, String, u32);

    fn remove_call(host: &str, target: &str, instance: u32) -> RemoveCall {
        (host.to_string(), target.to_string(), instance)
    }

    /// Records `remove` calls and answers them as review would, writing the
    /// attempts to the ledger and dropping the rows it removes.
    struct RecordingDeployer {
        store: Arc<RwLock<Store>>,
        /// The answers to the calls for one row, in order; after them,
        /// `Succeed`.
        answers: std::sync::Mutex<HashMap<RemoveCall, VecDeque<RemoveAnswer>>>,
        removes: std::sync::Mutex<Vec<RemoveCall>>,
        /// Every job when a call was made.
        jobs_at_remove: std::sync::Mutex<Vec<CustomerDataDeletionJob>>,
        /// The order of the calls, shared with an agent manager's.
        log: Arc<std::sync::Mutex<Vec<String>>>,
        remove_started: tokio::sync::Notify,
        /// The task manager whose shutdown starts when a call is made, as
        /// the embedding application's shutdown would.
        shut_down_on_remove: Option<Arc<CustomerDataDeletionTaskManager>>,
        /// Ends a `Hang` call's apply.
        release: Arc<tokio::sync::Notify>,
        /// Runs when the first call is made.
        on_remove: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
        applies: std::sync::Mutex<Vec<JoinHandle<()>>>,
        next_key: AtomicUsize,
    }

    impl RecordingDeployer {
        fn new(store: &Arc<RwLock<Store>>) -> Self {
            Self {
                store: Arc::clone(store),
                answers: std::sync::Mutex::default(),
                removes: std::sync::Mutex::default(),
                jobs_at_remove: std::sync::Mutex::default(),
                log: Arc::default(),
                remove_started: tokio::sync::Notify::new(),
                shut_down_on_remove: None,
                release: Arc::new(tokio::sync::Notify::new()),
                on_remove: std::sync::Mutex::default(),
                applies: std::sync::Mutex::default(),
                next_key: AtomicUsize::new(0),
            }
        }

        /// Shares `agent_manager`'s log, so the calls of both are in order.
        fn logging_with(mut self, agent_manager: &RecordingAgentManager) -> Self {
            self.log = Arc::clone(&agent_manager.log);
            self
        }

        fn answer(self, call: RemoveCall, answers: impl IntoIterator<Item = RemoveAnswer>) -> Self {
            self.answers
                .lock()
                .unwrap()
                .entry(call)
                .or_default()
                .extend(answers);
            self
        }

        fn removes(&self) -> Vec<RemoveCall> {
            self.removes.lock().unwrap().clone()
        }
    }

    /// The `expires_at` of every attempt the tests write: far enough that
    /// nothing in this module sweeps it.
    fn attempt_deadline() -> chrono::DateTime<Utc> {
        Utc::now() + chrono::TimeDelta::days(1)
    }

    /// Returns a live attempt of `action` on `(host, target, instance)`.
    fn live_attempt(
        key: &str,
        action: OperationAction,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> OperationAttempt {
        OperationAttempt {
            idempotency_key: key.to_string(),
            host: host.to_string(),
            target: target.to_string(),
            instance,
            action,
            install_intent: (action == OperationAction::Install).then_some([7; 32]),
            config_template: None,
            package_digest: "digest".to_string(),
            resolved_version: "1.0.0".to_string(),
            resolved_commit: "abcdef".to_string(),
            phase: OperationPhase::Dispatched,
            cleanup_state: None,
            started_at: Utc::now(),
            retry_policy: OperationRetryPolicy {
                max_attempts: 3,
                attempts_made: 0,
                backoff_seconds: 1,
            },
            outcome: None,
            failure_kind: None,
            finalized_at: None,
            expires_at: attempt_deadline(),
            backup_id: None,
            pre_update_version: None,
        }
    }

    /// Returns `attempt` ended with `outcome`; a `Failed` one with `kind`.
    fn ended(
        mut attempt: OperationAttempt,
        outcome: OperationOutcome,
        kind: OperationFailureKind,
    ) -> OperationAttempt {
        attempt.phase = OperationPhase::Completed;
        attempt.outcome = Some(outcome);
        attempt.failure_kind = (outcome == OperationOutcome::Failed).then_some(kind);
        attempt.finalized_at = Some(Utc::now());
        attempt
    }

    /// Writes `attempt` to the ledger, creating an install under its request
    /// key.
    fn write_attempt(store: &RwLock<Store>, attempt: &OperationAttempt) {
        let store = read_store(store).unwrap();
        let map = store.operation_attempt_map();
        if attempt.install_intent.is_some() && map.get(&attempt.idempotency_key).unwrap().is_none()
        {
            map.create_or_resolve(attempt).unwrap();
        } else {
            map.upsert(attempt).unwrap();
        }
    }

    /// Drops the row of `(host, target, instance)` from its node, as review's
    /// finalizer does once a removal succeeded.
    fn drop_row(store: &RwLock<Store>, host: &str, target: &str, instance: u32) {
        let store = read_store(store).unwrap();
        let node = store
            .node_map()
            .iter(Direction::Forward, None)
            .map(Result::unwrap)
            .find(|node| node.profile.as_ref().is_some_and(|p| p.hostname == host))
            .unwrap_or_else(|| panic!("no node on {host}"));
        let old = review_database::NodeUpdate::from(node.clone());
        let mut new = review_database::NodeUpdate::from(node.clone());
        new.agents.retain(|agent| {
            !(agent.instance == Some(instance) && agent.kind.package_id() == Some(target))
        });
        new.external_services.retain(|service| {
            !(service.instance == Some(instance) && service.kind.package_id() == Some(target))
        });
        store.node_map().update(node.id, &old, &new).unwrap();
    }

    #[async_trait]
    impl PackageDeployer for RecordingDeployer {
        async fn install(
            &self,
            _host: &str,
            _target: &str,
            _selector: review_database::BuildSelector,
            _on_failure: review_protocol::types::node::FailurePolicy,
            _bind_addrs: Option<Vec<crate::backend::BindAddrInput>>,
            _config_template: Option<String>,
            _request_key: &str,
        ) -> Result<(crate::backend::DeployOutcome, crate::backend::OperationId), DeployError>
        {
            unimplemented!("a customer deletion only removes")
        }

        async fn update(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
            _selector: review_database::BuildSelector,
            _on_failure: review_protocol::types::node::FailurePolicy,
        ) -> Result<(crate::backend::DeployOutcome, crate::backend::OperationId), DeployError>
        {
            unimplemented!("a customer deletion only removes")
        }

        async fn remove(
            &self,
            host: &str,
            target: &str,
            instance: Option<u32>,
        ) -> Result<crate::backend::OperationId, DeployError> {
            let instance = instance.expect("a customer deletion removes numbered rows");
            let call = remove_call(host, target, instance);
            self.removes.lock().unwrap().push(call.clone());
            self.log
                .lock()
                .unwrap()
                .push(format!("remove {target} {instance} on {host}"));
            {
                let store = read_store(&self.store).unwrap();
                let map = store.customer_data_deletion_map();
                let jobs = map.iter(Direction::Forward, None).map(Result::unwrap);
                self.jobs_at_remove.lock().unwrap().extend(jobs);
            }
            self.remove_started.notify_one();
            let on_remove = self.on_remove.lock().unwrap().take();
            if let Some(on_remove) = on_remove {
                on_remove();
            }
            if let Some(manager) = &self.shut_down_on_remove {
                manager.begin_shutdown().await;
            }
            let answer = self
                .answers
                .lock()
                .unwrap()
                .get_mut(&call)
                .and_then(VecDeque::pop_front)
                .unwrap_or(RemoveAnswer::Succeed);
            let key = format!("remove-{}", self.next_key.fetch_add(1, Ordering::SeqCst));
            let attempt = live_attempt(&key, OperationAction::Remove, host, target, Some(instance));
            let operation_id = crate::backend::OperationId::new(key);
            match answer {
                RemoveAnswer::Succeed => {
                    write_attempt(
                        &self.store,
                        &ended(
                            attempt,
                            OperationOutcome::Succeeded,
                            OperationFailureKind::Other,
                        ),
                    );
                    drop_row(&self.store, host, target, instance);
                    Ok(operation_id)
                }
                RemoveAnswer::Live => {
                    write_attempt(&self.store, &attempt);
                    Ok(operation_id)
                }
                RemoveAnswer::CleanupPending => Err(DeployError::CleanupPending {
                    host: host.to_string(),
                    target: target.to_string(),
                    instance: Some(instance),
                    operation_id,
                }),
                RemoveAnswer::UnderMaintenance => Err(DeployError::UnderMaintenance),
                RemoveAnswer::SystemInstance => Err(DeployError::SystemInstance {
                    host: host.to_string(),
                }),
                RemoveAnswer::Other => Err(DeployError::Other(anyhow!("the apply was aborted"))),
                RemoveAnswer::Hang => {
                    write_attempt(&self.store, &attempt);
                    let store = Arc::clone(&self.store);
                    let release = Arc::clone(&self.release);
                    let (host, target) = (host.to_string(), target.to_string());
                    let apply = tokio::spawn(async move {
                        release.notified().await;
                        write_attempt(
                            &store,
                            &ended(
                                attempt,
                                OperationOutcome::Succeeded,
                                OperationFailureKind::Other,
                            ),
                        );
                        drop_row(&store, &host, &target, instance);
                    });
                    self.applies.lock().unwrap().push(apply);
                    std::future::pending().await
                }
            }
        }

        async fn recommend_bind_addrs(
            &self,
            _host: &str,
            _target: &str,
        ) -> Result<Vec<review_database::ListenerBinding>, DeployError> {
            unimplemented!("a customer deletion only removes")
        }

        async fn latest_build(
            &self,
            _target: &str,
        ) -> anyhow::Result<Option<crate::backend::BuildId>> {
            unimplemented!("a customer deletion only removes")
        }

        async fn servable_builds(
            &self,
            _target: &str,
        ) -> anyhow::Result<Vec<crate::backend::BuildId>> {
            unimplemented!("a customer deletion only removes")
        }

        async fn config_templates(
            &self,
            _target: &str,
        ) -> anyhow::Result<crate::backend::ConfigTemplateCatalog> {
            unimplemented!("a customer deletion only removes")
        }

        async fn is_build_withdrawn(
            &self,
            _target: &str,
            _build: &crate::backend::BuildId,
        ) -> anyhow::Result<bool> {
            unimplemented!("a customer deletion only removes")
        }

        async fn package_status(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> anyhow::Result<review_protocol::types::node::PackageState> {
            unimplemented!("a customer deletion only removes")
        }

        async fn read_version(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> anyhow::Result<Option<crate::backend::BuildId>> {
            unimplemented!("a customer deletion only removes")
        }

        async fn register(
            &self,
            _service_name: &str,
            _host: &str,
            _instance: Option<u32>,
            _mode: review_protocol::types::node::DeliveryMode,
        ) -> anyhow::Result<review_protocol::types::node::BootstrapMaterial> {
            unimplemented!("a customer deletion only removes")
        }

        async fn deregister(
            &self,
            _service_name: &str,
            _host: &str,
            _instance: Option<u32>,
        ) -> anyhow::Result<()> {
            unimplemented!("a customer deletion only removes")
        }
    }

    /// Returns a deployer that removes every row it is asked to.
    fn deployer(test_store: &TestStore) -> SharedPackageDeployer {
        Arc::new(RecordingDeployer::new(&test_store.store))
    }

    fn test_schema(
        test_store: &TestStore,
        agent_manager: SharedAgentManager,
        task_manager: Arc<CustomerDataDeletionTaskManager>,
    ) -> Schema<TestQuery, CustomerDataDeletionMutation, EmptySubscription> {
        Schema::build(TestQuery, CustomerDataDeletionMutation, EmptySubscription)
            .data(Arc::clone(&test_store.store))
            .data(agent_manager)
            .data(deployer(test_store))
            .data(task_manager)
            .finish()
    }

    fn pending_result(
        service: CustomerDataDeletionService,
        hosts: &[&str],
    ) -> CustomerDataDeletionServiceResult {
        service_result(
            service,
            hosts.iter().map(|host| (*host).to_string()).collect(),
            123,
        )
    }

    fn put_active_node(test_store: &TestStore, customer_id: u32, hostname: &str) -> u32 {
        let sensor = Agent::new(
            0,
            "001.piglet".to_string(),
            AgentKind::Sensor,
            AgentStatus::Enabled,
            None,
            None,
        )
        .unwrap();
        let semi_supervised = Agent::new(
            0,
            "001.hog".to_string(),
            AgentKind::SemiSupervised,
            AgentStatus::Enabled,
            None,
            None,
        )
        .unwrap();
        let duplicate_sensor_instance = Agent::new(
            0,
            "002.piglet".to_string(),
            AgentKind::Sensor,
            AgentStatus::Enabled,
            None,
            None,
        )
        .unwrap();
        let external_service = ExternalService::new(
            0,
            "001.giganto".to_string(),
            ExternalServiceKind::DataStore,
            ExternalServiceStatus::Enabled,
            None,
        )
        .unwrap();
        let node = Node {
            id: 0,
            name: hostname.to_string(),
            name_draft: None,
            profile: Some(NodeProfile {
                customer_id,
                description: String::new(),
                hostname: hostname.to_string(),
            }),
            profile_draft: None,
            agents: vec![sensor, semi_supervised, duplicate_sensor_instance],
            external_services: vec![external_service],
            creation_time: Utc::now(),
        };
        read_store(&test_store.store)
            .unwrap()
            .node_map()
            .put(&node)
            .unwrap()
    }

    fn put_customer_network_data(test_store: &TestStore, customer_id: u32) {
        let store = read_store(&test_store.store).unwrap();
        let group = HostNetworkGroup::new(
            vec!["192.0.2.1".parse().unwrap()],
            vec!["192.0.2.0/24".parse().unwrap()],
            vec![],
        );
        store
            .customer_networks_map()
            .replace(
                customer_id,
                1,
                vec![OwnedNetwork {
                    name: "office".to_string(),
                    network_type: NetworkType::Intranet,
                    group: group.clone(),
                }],
            )
            .unwrap();
        store
            .network_lists_map()
            .replace(
                customer_id,
                1,
                vec![NetworkListEntry {
                    name: "allowed".to_string(),
                    group,
                }],
                vec![NetworkListEntry {
                    name: "blocked".to_string(),
                    group: HostNetworkGroup::new(
                        vec!["198.51.100.1".parse().unwrap()],
                        vec![],
                        vec![],
                    ),
                }],
            )
            .unwrap();
    }

    fn put_dns_event(test_store: &TestStore, sensor: &str, second: i64) {
        let fields = DnsEventFields {
            sensor: sensor.to_string(),
            orig_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            orig_port: 10_000,
            resp_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            resp_port: 53,
            proto: 17,
            start_time: second * 1_000_000_000,
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            query: "example.com".to_string(),
            answer: vec!["127.0.0.1".to_string()],
            trans_id: 1,
            rtt: 1,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: vec![1],
            confidence: 0.8,
            category: Some(EventCategory::CommandAndControl),
        };
        read_store(&test_store.store)
            .unwrap()
            .events()
            .put(&EventMessage {
                time: jiff::Timestamp::from_second(second).unwrap(),
                kind: EventKind::DnsCovertChannel,
                fields: bincode::serialize(&fields).unwrap(),
            })
            .unwrap();
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Stage {
        ScanJobs,
        CollectNodes,
        PersistRequest,
        Worker,
        Events,
        Hosts,
        TrafficFilters,
        CustomerNetworks,
        NetworkLists,
        Nodes,
        Unsupervised,
        DataStoreRecorded,
        /// Before the write recording overdue Sensor and Semi-supervised
        /// results `Failed`.
        ReportTimeout,
        RetryAgent,
        RetryExternalService,
        PersistTerminal,
    }

    type Hook = Arc<dyn Fn(Stage, u32) -> anyhow::Result<()> + Send + Sync>;
    static HOOK: std::sync::Mutex<Option<(usize, Hook)>> = std::sync::Mutex::new(None);
    type AssociatedFailures = (usize, u32, Vec<String>, Vec<String>);
    static ASSOCIATED_FAILURES: std::sync::Mutex<Option<AssociatedFailures>> =
        std::sync::Mutex::new(None);

    // Hooks are scoped to a particular Store, never to a thread: the worker runs
    // on Tokio's blocking pool. Other modules' concurrently running tests cannot
    // hit this Store's hook, and a guard clears it even after a failed assertion.
    struct HookGuard;

    impl HookGuard {
        fn install(store: &RwLock<Store>, hook: Hook) -> Self {
            let address = std::ptr::from_ref(&*read_store(store).unwrap()).addr();
            *HOOK.lock().unwrap() = Some((address, hook));
            Self
        }
    }

    impl Drop for HookGuard {
        fn drop(&mut self) {
            *HOOK.lock().unwrap() = None;
        }
    }

    struct AssociatedFailureGuard;

    impl AssociatedFailureGuard {
        fn install(
            store: &RwLock<Store>,
            node_id: u32,
            agents: Vec<String>,
            external_services: Vec<String>,
        ) -> Self {
            let address = std::ptr::from_ref(&*read_store(store).unwrap()).addr();
            *ASSOCIATED_FAILURES.lock().unwrap() =
                Some((address, node_id, agents, external_services));
            Self
        }
    }

    impl Drop for AssociatedFailureGuard {
        fn drop(&mut self) {
            *ASSOCIATED_FAILURES.lock().unwrap() = None;
        }
    }

    pub(super) fn injected_associated_deletion_failures(
        store: &Store,
        node_id: u32,
    ) -> Option<(Vec<String>, Vec<String>)> {
        ASSOCIATED_FAILURES.lock().unwrap().as_ref().and_then(
            |(address, injected_node_id, agents, external_services)| {
                (*address == std::ptr::from_ref(store).addr() && *injected_node_id == node_id)
                    .then(|| (agents.clone(), external_services.clone()))
            },
        )
    }

    /// The mocked wall clock: the time it was installed at, in nanoseconds,
    /// and Tokio's instant then. It follows Tokio's clock, so a test with
    /// paused time drives `timestamp_nanos` and the sleeps together.
    static CLOCK: std::sync::Mutex<Option<(i64, tokio::time::Instant)>> =
        std::sync::Mutex::new(None);
    /// The mocked clock's start, 2023-11-14T22:13:20Z.
    const CLOCK_START: i64 = 1_700_000_000_000_000_000;

    /// Mocks `timestamp_nanos` while it lives. Only tests holding a
    /// `TestStore`, which serializes them, install it.
    struct ClockGuard;

    impl ClockGuard {
        fn install(_test_store: &TestStore) -> Self {
            *CLOCK.lock().unwrap() = Some((CLOCK_START, tokio::time::Instant::now()));
            Self
        }
    }

    impl Drop for ClockGuard {
        fn drop(&mut self) {
            *CLOCK.lock().unwrap() = None;
        }
    }

    pub(super) fn mocked_now() -> Option<i64> {
        CLOCK.lock().unwrap().map(|(start, at)| {
            start + i64::try_from(at.elapsed().as_nanos()).expect("a test runs for under 292 years")
        })
    }

    pub(crate) fn checkpoint(store: &Store, stage: Stage, customer_id: u32) -> anyhow::Result<()> {
        let hook = HOOK.lock().unwrap().as_ref().and_then(|(address, hook)| {
            (*address == std::ptr::from_ref(store).addr()).then(|| Arc::clone(hook))
        });
        if let Some(hook) = hook {
            hook(stage, customer_id)?;
        }
        Ok(())
    }

    fn job(store: &RwLock<Store>, customer_id: u32) -> CustomerDataDeletionJob {
        read_store(store)
            .unwrap()
            .customer_data_deletion_map()
            .get(customer_id)
            .unwrap()
            .unwrap()
    }

    fn put_job(
        store: &RwLock<Store>,
        customer_id: u32,
        results: Vec<CustomerDataDeletionServiceResult>,
    ) {
        read_store(store)
            .unwrap()
            .customer_data_deletion_map()
            .put(&CustomerDataDeletionJob::new(customer_id, results))
            .unwrap();
    }

    fn terminal_result(
        service: CustomerDataDeletionService,
        host: &str,
        status: CustomerDataDeletionStatus,
    ) -> CustomerDataDeletionServiceResult {
        CustomerDataDeletionServiceResult {
            status,
            completed_at: Some(456),
            error: (status == CustomerDataDeletionStatus::Failed)
                .then(|| "old failure".to_string()),
            ..pending_result(service, &[host])
        }
    }

    /// Scans for unfinished deletions, starts resuming them with an agent
    /// manager that answers every Data Store request, and returns the remote
    /// targets.
    ///
    /// The targets are dispatched as the embedding application does, and
    /// each one's report, `Succeeded`, is recorded before the resume starts.
    async fn recover_and_start(
        store: &Arc<RwLock<Store>>,
        manager: &Arc<CustomerDataDeletionTaskManager>,
    ) -> Vec<CustomerDataDeletionTarget> {
        let mut recovered = recover_customer_data_deletion_on_startup(Arc::clone(store)).unwrap();
        let targets = recovered.take_remote_targets();
        for target in &targets {
            report_target(store, target, CustomerDataDeletionStatus::Succeeded, None);
        }
        recovered
            .start(
                Arc::new(RecordingDeployer::new(store)),
                Arc::new(RecordingAgentManager::with_store(store)),
                Arc::clone(manager),
            )
            .await
            .unwrap();
        targets
    }

    async fn wait_for_recovery(manager: &CustomerDataDeletionTaskManager) {
        // Keep the supervisor registered, and release the state lock before yielding.
        tokio::time::timeout(RECOVERY_TIMEOUT, async {
            loop {
                let finished = {
                    let state = manager.state.lock().await;
                    state
                        .active
                        .as_ref()
                        .expect(
                            "startup recovery registers a supervisor for pending Review results",
                        )
                        .1
                        .is_finished()
                };
                if finished {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("customer deletion recovery did not finish within 10 seconds");
    }

    const RESULT_QUERY: &str = r#"{
        customerDataDeletionResult(customerId: "7") {
            customerId
            serviceResults { service hostFqdns status requestedAt completedAt error }
        }
    }"#;

    fn result_schema(
        test_store: &TestStore,
    ) -> Schema<CustomerDataDeletionQuery, CustomerDataDeletionMutation, EmptySubscription> {
        // Deliberately omit the agent and task managers: reading results must
        // not require any orchestration dependencies.
        Schema::build(
            CustomerDataDeletionQuery,
            CustomerDataDeletionMutation,
            EmptySubscription,
        )
        .data(Arc::clone(&test_store.store))
        .finish()
    }

    fn admin_request(query: &str) -> Request {
        Request::new(query).data(RoleGuard::new(Role::SystemAdministrator))
    }

    async fn result_query_data(
        schema: &Schema<CustomerDataDeletionQuery, CustomerDataDeletionMutation, EmptySubscription>,
    ) -> serde_json::Value {
        let response = schema.execute(admin_request(RESULT_QUERY)).await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        response.data.into_json().unwrap()
    }

    #[tokio::test]
    async fn result_preserves_order_hosts_enums_timestamps_and_persisted_state() {
        let test_store = TestStore::new();
        let node_id = put_active_node(&test_store, 7, "z.example");
        put_customer_network_data(&test_store, 7);
        put_dns_event(&test_store, "piglet.z.example", 1);
        let error = "failure: café\n\t\"unchanged\" ";
        let results = vec![
            CustomerDataDeletionServiceResult {
                service: CustomerDataDeletionService::Review,
                host_fqdns: vec!["z.example".into(), "a.example".into(), "z.example".into()],
                status: CustomerDataDeletionStatus::Succeeded,
                requested_at: 1_700_000_000_123_456_789,
                completed_at: Some(1_700_000_001_987_654_321),
                error: None,
            },
            CustomerDataDeletionServiceResult {
                service: CustomerDataDeletionService::Sensor,
                host_fqdns: vec!["b.example".into()],
                status: CustomerDataDeletionStatus::Failed,
                requested_at: -123_456_789,
                completed_at: Some(987_654_321),
                error: Some(error.into()),
            },
            pending_result(CustomerDataDeletionService::Sensor, &["a.example"]),
            pending_result(CustomerDataDeletionService::SemiSupervised, &["z.example"]),
        ];
        put_job(&test_store.store, 7, results);
        put_job(
            &test_store.store,
            8,
            vec![pending_result(
                CustomerDataDeletionService::Review,
                &["other.example"],
            )],
        );
        let original = job(&test_store.store, 7);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(|stage, _| panic!("result query invoked deletion processing at {stage:?}")),
        );
        assert_eq!(
            result_query_data(&result_schema(&test_store)).await,
            serde_json::json!({
                "customerDataDeletionResult": {
                    "customerId": "7",
                    "serviceResults": [
                        { "service": "REVIEW", "hostFqdns": ["z.example", "a.example", "z.example"],
                          "status": "SUCCEEDED", "requestedAt": "2023-11-14T22:13:20.123456789Z",
                          "completedAt": "2023-11-14T22:13:21.987654321Z", "error": null },
                        { "service": "SENSOR", "hostFqdns": ["b.example"], "status": "FAILED",
                          "requestedAt": "1969-12-31T23:59:59.876543211Z",
                          "completedAt": "1970-01-01T00:00:00.987654321Z", "error": error },
                        { "service": "SENSOR", "hostFqdns": ["a.example"], "status": "IN_PROGRESS",
                          "requestedAt": "1970-01-01T00:00:00.000000123Z", "completedAt": null, "error": null },
                        { "service": "SEMI_SUPERVISED", "hostFqdns": ["z.example"], "status": "IN_PROGRESS",
                          "requestedAt": "1970-01-01T00:00:00.000000123Z", "completedAt": null, "error": null }
                    ]
                }
            })
        );
        assert_eq!(job(&test_store.store, 7), original);
        let store = read_store(&test_store.store).unwrap();
        assert!(store.node_map().get_by_id(node_id).unwrap().is_some());
        assert_eq!(store.events().iter_forward().count(), 1);
        assert!(store.customer_networks_map().get(7).unwrap().is_some());
    }

    #[tokio::test]
    async fn result_null_means_no_persisted_job_and_completed_jobs_remain_visible() {
        let test_store = TestStore::new();
        let schema = result_schema(&test_store);
        let response = schema.execute(admin_request(RESULT_QUERY)).await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(
            response.data.into_json().unwrap(),
            serde_json::json!({"customerDataDeletionResult": null})
        );
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .customer_data_deletion_map()
                .get(7)
                .unwrap()
                .is_none()
        );

        put_job(
            &test_store.store,
            7,
            vec![terminal_result(
                CustomerDataDeletionService::Review,
                "done.example",
                CustomerDataDeletionStatus::Succeeded,
            )],
        );
        let original = job(&test_store.store, 7);
        let response = schema.execute(admin_request(RESULT_QUERY)).await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert!(!response.data.into_json().unwrap()["customerDataDeletionResult"].is_null());
        assert_eq!(job(&test_store.store, 7), original);
    }

    #[tokio::test]
    async fn result_propagates_persisted_job_decoding_failure() {
        const CUSTOMER_ID: u32 = 7;
        const STATES_DIRECTORY: &str = "states.db";
        const JOB_COLUMN_FAMILY: &str = "customer deletion jobs";

        let permit = TEST_DB_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        {
            // Match review-database's layout and write an undecodable service-results value.
            // Close the raw database before Store opens it and creates the remaining tables.
            let mut options = Options::default();
            options.create_if_missing(true);
            options.create_missing_column_families(true);
            let db = OptimisticTransactionDB::<SingleThreaded>::open_cf(
                &options,
                db_dir.path().join(STATES_DIRECTORY),
                [JOB_COLUMN_FAMILY],
            )
            .unwrap();
            let column_family = db.cf_handle(JOB_COLUMN_FAMILY).unwrap();
            db.put_cf(column_family, CUSTOMER_ID.to_be_bytes(), [0xff])
                .unwrap();
        }
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        assert!(store.customer_data_deletion_map().get(CUSTOMER_ID).is_err());
        let test_store = TestStore {
            _permit: permit,
            _db_dir: db_dir,
            _backup_dir: backup_dir,
            store: Arc::new(RwLock::new(store)),
        };

        let schema = result_schema(&test_store);
        let response = schema.execute(admin_request(RESULT_QUERY)).await;
        assert_eq!(response.errors.len(), 1, "{:?}", response.errors);
        let error = response.errors.first().unwrap();
        assert_eq!(
            error.message,
            format!("retrieving customer data deletion job {CUSTOMER_ID}")
        );
        assert_eq!(
            error.path,
            vec![async_graphql::PathSegment::Field(
                "customerDataDeletionResult".to_string()
            )]
        );

        // An unrelated malformed row must not turn a missing job into an error.
        let response = schema
            .execute(admin_request(&RESULT_QUERY.replace("\"7\"", "\"8\"")))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(
            response.data.into_json().unwrap(),
            serde_json::json!({"customerDataDeletionResult": null})
        );
    }

    #[tokio::test]
    async fn result_reflects_persisted_retry_updates() {
        const CUSTOMER_ID: u32 = 7;
        const FIRST_REQUEST: i64 = 1_700_000_000_123_456_789;
        const FAILED_AT: i64 = 1_700_000_001_234_567_891;
        const RETRY_REQUEST: i64 = 1_700_000_002_345_678_901;
        const FAILURE: &str = "first attempt failed";
        const RESULT_PATH: &str = "/customerDataDeletionResult/serviceResults/0";

        let test_store = TestStore::new();
        let schema = result_schema(&test_store);
        let mut deletion_job = CustomerDataDeletionJob::new(
            CUSTOMER_ID,
            vec![CustomerDataDeletionServiceResult {
                service: CustomerDataDeletionService::Sensor,
                host_fqdns: vec!["sensor.example".to_string()],
                status: CustomerDataDeletionStatus::Failed,
                requested_at: FIRST_REQUEST,
                completed_at: Some(FAILED_AT),
                error: Some(FAILURE.to_string()),
            }],
        );
        read_store(&test_store.store)
            .unwrap()
            .customer_data_deletion_map()
            .put(&deletion_job)
            .unwrap();

        let data = result_query_data(&schema).await;
        let result = data.pointer(RESULT_PATH).unwrap();
        assert_eq!(result["status"], "FAILED");
        assert_eq!(result["requestedAt"], "2023-11-14T22:13:20.123456789Z");
        assert_eq!(result["completedAt"], "2023-11-14T22:13:21.234567891Z");
        assert_eq!(result["error"], FAILURE);

        // Reuse the schema and query after the retry update to detect stale results.
        let result = deletion_job.service_results.first_mut().unwrap();
        result.status = CustomerDataDeletionStatus::InProgress;
        result.requested_at = RETRY_REQUEST;
        result.completed_at = None;
        result.error = None;
        read_store(&test_store.store)
            .unwrap()
            .customer_data_deletion_map()
            .update_service(CUSTOMER_ID, result)
            .unwrap();

        let data = result_query_data(&schema).await;
        let result = data.pointer(RESULT_PATH).unwrap();
        assert_eq!(result["status"], "IN_PROGRESS");
        assert_eq!(result["requestedAt"], "2023-11-14T22:13:22.345678901Z");
        assert_eq!(result.get("completedAt"), Some(&serde_json::Value::Null));
        assert_eq!(result.get("error"), Some(&serde_json::Value::Null));
    }

    #[tokio::test]
    async fn result_rejects_other_roles_and_invalid_ids_before_lookup() {
        let test_store = TestStore::new();
        let schema = result_schema(&test_store);
        for role in [
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let response = schema
                .execute(Request::new(RESULT_QUERY).data(RoleGuard::new(role)))
                .await;
            assert_eq!(response.errors.len(), 1);
            assert_eq!(response.errors[0].message, "Forbidden");
        }
        let response = schema.execute(Request::new(RESULT_QUERY)).await;
        assert_eq!(response.errors[0].message, "Forbidden");
        for id in ["invalid", "-1", "4294967296", ""] {
            let query = RESULT_QUERY.replace("\"7\"", &format!("\"{id}\""));
            let response = schema.execute(admin_request(&query)).await;
            assert_eq!(response.errors.len(), 1);
            assert_eq!(response.errors[0].message, "invalid customer ID");
        }
    }

    #[test]
    fn target_getters_and_service_fqdn_have_no_instance() {
        let target = CustomerDataDeletionTarget::new(
            7,
            "node.example".to_string(),
            service_fqdn("piglet", "node.example"),
        );
        assert_eq!(target.customer_id(), 7);
        assert_eq!(target.host_fqdn(), "node.example");
        assert_eq!(target.target_service_key(), "piglet.node.example");
    }

    #[test]
    fn only_the_service_segment_matches() {
        for service in ["piglet", "reproduce"] {
            assert!(agent_has_service(&format!("001.{service}"), service));
            assert!(agent_has_service(
                &format!("001.{service}.node.example"),
                service
            ));
            for key in [
                format!("{service}.hog.node.example"),
                format!("001.hog.{service}.example"),
                format!("001.not-{service}.example"),
                service.to_string(),
            ] {
                assert!(!agent_has_service(&key, service), "{key}");
            }
        }
    }

    #[test]
    fn draft_only_nodes_are_not_deletion_targets() {
        let test_store = TestStore::new();
        let node = Node {
            id: 0,
            name: "draft".to_string(),
            name_draft: Some("draft".to_string()),
            profile: None,
            profile_draft: Some(NodeProfile {
                customer_id: 8,
                description: String::new(),
                hostname: "draft.example".to_string(),
            }),
            agents: Vec::new(),
            external_services: Vec::new(),
            creation_time: Utc::now(),
        };
        read_store(&test_store.store)
            .unwrap()
            .node_map()
            .put(&node)
            .unwrap();
        assert!(
            collect_initial_plan(&test_store.store, 8)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn initial_and_retry_plans_are_sorted_and_deduplicated() {
        let test_store = TestStore::new();
        let z = put_active_node(&test_store, 1, "z.example");
        let a = put_active_node(&test_store, 1, "a.example");
        put_active_node(&test_store, 2, "unrelated.example");
        let plan = collect_initial_plan(&test_store.store, 1).unwrap().unwrap();
        let review = plan.review_targets.as_ref().unwrap();
        assert_eq!(review.node_ids, [z, a]);
        assert_eq!(review.host_fqdns, ["a.example", "z.example"]);
        assert_eq!(
            review.event_service_fqdns,
            ["piglet.a.example", "piglet.z.example"]
        );
        let initial = initial_job(&plan, 123);
        // Review, four remote targets, and one `ModuleRemoval` per host.
        assert_eq!(initial.service_results.len(), 7);
        assert_eq!(
            initial
                .service_results
                .iter()
                .filter(|r| r.service == CustomerDataDeletionService::ModuleRemoval)
                .map(|r| r.host_fqdns.clone())
                .collect::<Vec<_>>(),
            [vec!["a.example".to_string()], vec!["z.example".to_string()]]
        );
        assert!(initial.service_results.iter().all(|r| r.requested_at == 123
            && r.completed_at.is_none()
            && r.error.is_none()
            && r.status == CustomerDataDeletionStatus::InProgress));
        assert_eq!(
            plan.remote_targets
                .iter()
                .map(CustomerDataDeletionTarget::target_service_key)
                .collect::<Vec<_>>(),
            [
                "hog.a.example",
                "hog.z.example",
                "piglet.a.example",
                "piglet.z.example"
            ]
        );

        let mut failed = initial;
        for result in &mut failed.service_results {
            result.status = CustomerDataDeletionStatus::Failed;
        }
        let duplicate = failed
            .service_results
            .iter()
            .find(|r| r.service == CustomerDataDeletionService::Sensor)
            .unwrap()
            .clone();
        failed.service_results.push(duplicate);
        failed.service_results.first_mut().unwrap().host_fqdns =
            vec!["z.example".into(), "a.example".into(), "z.example".into()];
        let retry = retry_plan(&test_store.store, &failed).unwrap();
        assert_eq!(retry.remote_targets, plan.remote_targets);
        let review = retry.review_targets.unwrap();
        assert_eq!(review.node_ids, [z, a]);
        assert_eq!(review.host_fqdns, ["a.example", "z.example"]);
        assert_eq!(
            review.event_service_fqdns,
            [
                "piglet.a.example",
                "piglet.z.example",
                "reproduce.a.example",
                "reproduce.z.example"
            ]
        );
    }

    #[tokio::test]
    async fn missing_associated_records_abort_before_persisting_or_spawning() {
        let test_store = TestStore::new();
        let node_id = put_active_node(&test_store, 1, "one.example");
        read_store(&test_store.store)
            .unwrap()
            .agents_map()
            .delete(node_id, "001.piglet")
            .unwrap();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent_manager: SharedAgentManager = Arc::new(RecordingAgentManager::default());

        let error = request_deletion(
            1,
            &test_store.store,
            &agent_manager,
            &deployer(&test_store),
            &manager,
        )
        .await
        .unwrap_err();

        let error = format!("{error:#}");
        assert!(error.contains("connected records"));
        assert!(error.contains("001.piglet"));
        assert!(manager.state.lock().await.active.is_none());
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .customer_data_deletion_map()
                .get(1)
                .unwrap()
                .is_none()
        );

        let node_id = put_active_node(&test_store, 2, "two.example");
        read_store(&test_store.store)
            .unwrap()
            .external_service_map()
            .delete(node_id, "001.giganto")
            .unwrap();
        let error = request_deletion(
            2,
            &test_store.store,
            &agent_manager,
            &deployer(&test_store),
            &manager,
        )
        .await
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("connected records"));
        assert!(error.contains("001.giganto"));
        assert!(manager.state.lock().await.active.is_none());
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .customer_data_deletion_map()
                .get(2)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn mutation_rejects_non_admin_before_reading_state() {
        let test_store = TestStore::new();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        put_active_node(&test_store, 1, "protected.example");
        let agent_manager = Arc::new(RecordingAgentManager::default());
        let shared: SharedAgentManager = agent_manager.clone();
        let schema = test_schema(&test_store, shared, Arc::clone(&manager));
        for role in [
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let response = schema
                .execute(
                    Request::new(r#"mutation { deleteCustomerData(customerId: "1") }"#)
                        .data(RoleGuard::Role(role))
                        .data(SocketAddr::from(([127, 0, 0, 1], 1))),
                )
                .await;
            assert_eq!(response.errors.len(), 1);
            assert!(manager.state.lock().await.active.is_none());
            assert!(agent_manager.targets.lock().unwrap().is_empty());
        }
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .customer_data_deletion_map()
                .get(1)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn mutation_reports_invalid_id_no_target_and_shutdown() {
        let test_store = TestStore::new();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let schema = test_schema(
            &test_store,
            Arc::new(RecordingAgentManager::default()),
            Arc::clone(&manager),
        );
        let admin =
            |query: &str| Request::new(query).data(RoleGuard::Role(Role::SystemAdministrator));
        let invalid = schema
            .execute(admin(r#"mutation { deleteCustomerData(customerId: "x") }"#))
            .await;
        assert_eq!(invalid.errors.len(), 1);
        let no_target = schema
            .execute(admin(r#"mutation { deleteCustomerData(customerId: "1") }"#))
            .await;
        assert_eq!(
            no_target.data.to_string(),
            "{deleteCustomerData: NO_TARGET}"
        );
        manager.shutdown_and_wait().await;
        let shutdown = schema
            .execute(admin(r#"mutation { deleteCustomerData(customerId: "1") }"#))
            .await;
        assert_eq!(
            shutdown.data.to_string(),
            "{deleteCustomerData: BLOCKED_BY_SHUTDOWN}"
        );
    }

    #[tokio::test]
    async fn persisted_other_customer_in_progress_takes_precedence() {
        let test_store = TestStore::new();
        for customer_id in [1, 2] {
            put_job(
                &test_store.store,
                customer_id,
                vec![pending_result(
                    CustomerDataDeletionService::Sensor,
                    &[if customer_id == 1 { "one" } else { "two" }],
                )],
            );
        }
        let agent_manager: SharedAgentManager = Arc::new(RecordingAgentManager::default());
        let status = request_deletion(
            1,
            &test_store.store,
            &agent_manager,
            &deployer(&test_store),
            &Arc::new(CustomerDataDeletionTaskManager::default()),
        )
        .await
        .unwrap();
        assert_eq!(
            status,
            CustomerDataDeletionRequestStatus::BlockedByAnotherDeletion
        );
    }

    #[tokio::test]
    async fn completed_and_in_progress_jobs_return_without_starting_work() {
        let test_store = TestStore::new();
        put_job(
            &test_store.store,
            1,
            vec![terminal_result(
                CustomerDataDeletionService::Review,
                "one",
                CustomerDataDeletionStatus::Succeeded,
            )],
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent_manager: SharedAgentManager = Arc::new(RecordingAgentManager::default());
        assert_eq!(
            request_deletion(
                1,
                &test_store.store,
                &agent_manager,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::AlreadyCompleted
        );
        put_job(
            &test_store.store,
            2,
            vec![pending_result(
                CustomerDataDeletionService::Sensor,
                &["two"],
            )],
        );
        assert_eq!(
            request_deletion(
                2,
                &test_store.store,
                &agent_manager,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::DeletionInProgress
        );
        assert!(manager.state.lock().await.active.is_none());
    }

    #[tokio::test]
    async fn active_supervisor_distinguishes_same_and_other_customer() {
        let test_store = TestStore::new();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let release = Arc::new(tokio::sync::Notify::new());
        let task_release = Arc::clone(&release);
        let supervisor = tokio::spawn(async move { task_release.notified().await });
        manager.state.lock().await.active = Some((3, supervisor));
        let agent_manager: SharedAgentManager = Arc::new(RecordingAgentManager::default());
        assert_eq!(
            request_deletion(
                3,
                &test_store.store,
                &agent_manager,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::DeletionInProgress
        );
        assert_eq!(
            request_deletion(
                4,
                &test_store.store,
                &agent_manager,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::BlockedByAnotherDeletion
        );
        release.notify_one();
        manager.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn pre_start_failures_return_graphql_errors_without_starting_work() {
        let test_store = TestStore::new();
        put_active_node(&test_store, 1, "one.example");
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent = Arc::new(RecordingAgentManager::default());
        let shared: SharedAgentManager = agent.clone();
        let schema = test_schema(&test_store, shared, Arc::clone(&manager));
        for stage in [Stage::ScanJobs, Stage::CollectNodes, Stage::PersistRequest] {
            let _hook = HookGuard::install(
                &test_store.store,
                Arc::new(move |at, _| {
                    if at == stage {
                        bail!("injected {stage:?} failure");
                    }
                    Ok(())
                }),
            );
            let response = schema
                .execute(
                    Request::new(r#"mutation { deleteCustomerData(customerId: "1") }"#)
                        .data(RoleGuard::Role(Role::SystemAdministrator)),
                )
                .await;
            assert_eq!(response.errors.len(), 1);
            assert!(
                response
                    .errors
                    .first()
                    .unwrap()
                    .message
                    .contains(&format!("{stage:?}"))
            );
            assert!(manager.state.lock().await.active.is_none());
            assert!(agent.targets.lock().unwrap().is_empty());
            assert!(
                read_store(&test_store.store)
                    .unwrap()
                    .customer_data_deletion_map()
                    .get(1)
                    .unwrap()
                    .is_none()
            );
        }
        let failed = terminal_result(
            CustomerDataDeletionService::Sensor,
            "one.example",
            CustomerDataDeletionStatus::Failed,
        );
        put_job(&test_store.store, 1, vec![failed]);
        let before = job(&test_store.store, 1);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(|stage, _| {
                if stage == Stage::PersistRequest {
                    bail!("retry persistence failed");
                }
                Ok(())
            }),
        );
        let response = schema
            .execute(
                Request::new(r#"mutation { deleteCustomerData(customerId: "1") }"#)
                    .data(RoleGuard::Role(Role::SystemAdministrator)),
            )
            .await;
        assert_eq!(response.errors.len(), 1);
        assert!(manager.state.lock().await.active.is_none());
        assert!(agent.targets.lock().unwrap().is_empty());
        assert_eq!(job(&test_store.store, 1), before);
    }

    #[tokio::test]
    async fn initial_request_delivers_normalized_targets_and_deletes_local_data() {
        let test_store = TestStore::new();
        let node_id = put_active_node(&test_store, 42, "node.example");
        let agent_manager = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let shared_agent_manager: SharedAgentManager = agent_manager.clone();
        let task_manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let status = request_deletion(
            42,
            &test_store.store,
            &shared_agent_manager,
            &deployer(&test_store),
            &task_manager,
        )
        .await
        .unwrap();
        assert_eq!(status, CustomerDataDeletionRequestStatus::Accepted);
        finish_supervisor(&task_manager).await;

        let targets = agent_manager.targets.lock().unwrap().clone();
        assert_eq!(
            targets
                .iter()
                .map(CustomerDataDeletionTarget::target_service_key)
                .collect::<Vec<_>>(),
            ["hog.node.example", "piglet.node.example"]
        );
        assert!(
            targets
                .iter()
                .all(|target| !target.target_service_key().starts_with("001."))
        );
        let store = read_store(&test_store.store).unwrap();
        assert!(store.node_map().get_by_id(node_id).unwrap().is_none());
        let job = store.customer_data_deletion_map().get(42).unwrap().unwrap();
        let review = job
            .service_results
            .iter()
            .find(|result| result.service == CustomerDataDeletionService::Review)
            .unwrap();
        assert_eq!(review.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(review.host_fqdns, ["node.example"]);
        assert!(review.completed_at.is_some());
        // The reports the agent manager recorded, and the host's uninstall,
        // which had nothing with an instance number to remove.
        assert!(
            job.service_results
                .iter()
                .all(|result| result.status == CustomerDataDeletionStatus::Succeeded)
        );
        assert!(
            service_of(
                &job,
                CustomerDataDeletionService::ModuleRemoval,
                "node.example"
            )
            .is_some()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn local_deletion_removes_exact_customer_data_and_is_idempotent() {
        let test_store = TestStore::new();
        let target_node = put_active_node(&test_store, 1, "one.example");
        let other_node = put_active_node(&test_store, 2, "other.example");
        put_customer_network_data(&test_store, 1);
        // The same network values belong to both customers; only the ID selects deletion.
        put_customer_network_data(&test_store, 2);
        put_dns_event(&test_store, "piglet.one.example", 1);
        put_dns_event(&test_store, "piglet.one.example.extra", 2);
        put_dns_event(&test_store, "piglet.other.example", 3);
        let target_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let other_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        {
            let store = read_store(&test_store.store).unwrap();
            store
                .hosts_map()
                .update_opened_ports(
                    1,
                    &HashMap::from([(target_ip, HashMap::from([((80, 6), 1)]))]),
                )
                .unwrap();
            store
                .hosts_map()
                .update_opened_ports(
                    2,
                    &HashMap::from([(other_ip, HashMap::from([((443, 6), 1)]))]),
                )
                .unwrap();
            for hostname in ["one.example", "one.example.extra", "other.example"] {
                store
                    .traffic_filter_map()
                    .add_rules(hostname, "10.0.0.0/24".parse().unwrap(), None, None, None)
                    .unwrap();
            }
        }
        let plan = collect_initial_plan(&test_store.store, 1).unwrap().unwrap();
        let targets = plan.review_targets.unwrap();

        delete_review_data(
            &test_store.store,
            &SamplingPoliciesLock::default(),
            1,
            &targets,
        )
        .unwrap();
        delete_review_data(
            &test_store.store,
            &SamplingPoliciesLock::default(),
            1,
            &targets,
        )
        .unwrap();

        let store = read_store(&test_store.store).unwrap();
        assert!(store.customer_networks_map().get(1).unwrap().is_none());
        assert!(store.network_lists_map().get(1).unwrap().is_none());
        assert!(store.customer_networks_map().get(2).unwrap().is_some());
        assert!(store.network_lists_map().get(2).unwrap().is_some());
        assert!(store.hosts_map().get(1, target_ip).unwrap().is_none());
        assert!(store.hosts_map().get(2, other_ip).unwrap().is_some());
        assert!(
            store
                .traffic_filter_map()
                .get("one.example")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .traffic_filter_map()
                .get("one.example.extra")
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .traffic_filter_map()
                .get("other.example")
                .unwrap()
                .is_some()
        );
        assert!(store.node_map().get_by_id(target_node).unwrap().is_none());
        assert!(store.node_map().get_by_id(other_node).unwrap().is_some());
        for agent_key in ["001.piglet", "001.hog", "002.piglet"] {
            assert!(
                store
                    .agents_map()
                    .get(target_node, agent_key)
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .agents_map()
                    .get(other_node, agent_key)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            store
                .external_service_map()
                .get(target_node, "001.giganto")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .external_service_map()
                .get(other_node, "001.giganto")
                .unwrap()
                .is_some()
        );
        let sensors = store
            .events()
            .iter_forward()
            .map(|entry| match entry.unwrap().1 {
                Event::DnsCovertChannel(event) => event.sensor,
                _ => panic!("expected DNS event"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            sensors,
            ["piglet.one.example.extra", "piglet.other.example"]
        );
    }

    #[tokio::test]
    async fn remote_delivery_failure_keeps_nodes_and_fails_review() {
        let test_store = TestStore::new();
        let node_id = put_active_node(&test_store, 55, "failure.example");
        put_data_store(&test_store, "ds.example", 1);
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent = Arc::new(RecordingAgentManager {
            fail_delivery: true,
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let agent_manager: SharedAgentManager = agent.clone();
        let status = request_deletion(
            55,
            &test_store.store,
            &agent_manager,
            &deployer(&test_store),
            &manager,
        )
        .await
        .unwrap();
        assert_eq!(status, CustomerDataDeletionRequestStatus::Accepted);
        finish_supervisor(&manager).await;
        {
            let store = read_store(&test_store.store).unwrap();
            assert!(store.node_map().get_by_id(node_id).unwrap().is_some());
        }
        let job = job(&test_store.store, 55);
        let review = job.service_results.first().unwrap();
        assert_eq!(review.service, CustomerDataDeletionService::Review);
        assert_eq!(review.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(
            review.error.as_deref(),
            Some("stopped before this part: delivery failed")
        );
        assert!(review.completed_at.is_some());
        for result in job.service_results.iter().skip(1) {
            assert_ne!(result.service, CustomerDataDeletionService::DataStore);
            assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
            let error = if result.service == CustomerDataDeletionService::ModuleRemoval {
                "stopped before this part: delivery failed"
            } else {
                "delivery failed"
            };
            assert_eq!(result.error.as_deref(), Some(error));
        }
        assert!(agent.sent.lock().unwrap().is_empty());

        // Nothing is left `InProgress`, so another customer's deletion runs.
        put_active_node(&test_store, 56, "other.example");
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let shared: SharedAgentManager = Arc::new(RecordingAgentManager::default());
        assert_eq!(
            request_deletion(
                56,
                &test_store.store,
                &shared,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::Accepted
        );
        manager.shutdown_and_wait().await;
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn delivery_finishes_before_local_work_for_initial_and_retry_requests() {
        let test_store = TestStore::new();
        for (customer_id, retry, fail) in [
            (1, false, false),
            (2, true, false),
            (3, false, true),
            (4, true, true),
        ] {
            // Complete earlier remote results so they do not block the next customer.
            for previous in 1..customer_id {
                put_job(
                    &test_store.store,
                    previous,
                    vec![terminal_result(
                        CustomerDataDeletionService::Review,
                        "done",
                        CustomerDataDeletionStatus::Succeeded,
                    )],
                );
            }
            let node = put_active_node(&test_store, customer_id, &format!("{customer_id}.example"));
            if retry {
                let plan = collect_initial_plan(&test_store.store, customer_id)
                    .unwrap()
                    .unwrap();
                let mut persisted = initial_job(&plan, 123);
                for result in &mut persisted.service_results {
                    result.status = CustomerDataDeletionStatus::Failed;
                }
                put_job(&test_store.store, customer_id, persisted.service_results);
            }
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let agent = Arc::new(RecordingAgentManager {
                fail_delivery: fail,
                delivery_gate: Some(Arc::clone(&gate)),
                ..RecordingAgentManager::with_store(&test_store.store)
            });
            let shared: SharedAgentManager = agent.clone();
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());
            assert_eq!(
                request_deletion(
                    customer_id,
                    &test_store.store,
                    &shared,
                    &deployer(&test_store),
                    &manager
                )
                .await
                .unwrap(),
                CustomerDataDeletionRequestStatus::Accepted
            );
            agent.delivery_started.notified().await;
            assert_eq!(agent.targets.lock().unwrap().len(), 2);
            assert!(
                read_store(&test_store.store)
                    .unwrap()
                    .node_map()
                    .get_by_id(node)
                    .unwrap()
                    .is_some()
            );
            let before = job(&test_store.store, customer_id);
            assert!(
                before
                    .service_results
                    .iter()
                    .all(|r| r.status == CustomerDataDeletionStatus::InProgress)
            );
            // Nothing local runs before the delivery returns.
            let supervisor = finish_supervisor(&manager);
            tokio::pin!(supervisor);
            assert!(futures::poll!(&mut supervisor).is_pending());
            assert_eq!(job(&test_store.store, customer_id), before);
            gate.add_permits(1);
            supervisor.await;
            let after = job(&test_store.store, customer_id);
            let review = after.service_results.first().unwrap();
            assert_eq!(
                review.requested_at,
                before.service_results.first().unwrap().requested_at
            );
            assert!(review.completed_at.is_some());
            assert_eq!(
                review.status,
                if fail {
                    CustomerDataDeletionStatus::Failed
                } else {
                    CustomerDataDeletionStatus::Succeeded
                }
            );
            assert_eq!(
                read_store(&test_store.store)
                    .unwrap()
                    .node_map()
                    .get_by_id(node)
                    .unwrap()
                    .is_some(),
                fail
            );
            if fail {
                assert_eq!(
                    review.error.as_deref(),
                    Some("stopped before this part: delivery failed")
                );
            }
            // The agent manager records the targets it could not deliver,
            // or their reports; the deletion records each host's uninstall.
            assert!(after.service_results.iter().skip(1).all(|r| r.status
                == if fail {
                    CustomerDataDeletionStatus::Failed
                } else {
                    CustomerDataDeletionStatus::Succeeded
                }));
        }
    }

    #[tokio::test]
    async fn worker_errors_and_panics_persist_failure_without_changing_requested_at() {
        let test_store = TestStore::new();
        for panic_worker in [false, true] {
            put_job(
                &test_store.store,
                1,
                vec![pending_result(
                    CustomerDataDeletionService::Review,
                    &["one.example"],
                )],
            );
            let _hook = HookGuard::install(
                &test_store.store,
                Arc::new(move |stage, _| {
                    if stage == Stage::Worker {
                        assert!(!panic_worker, "injected worker panic");
                        bail!("injected deletion failure");
                    }
                    Ok(())
                }),
            );
            let targets =
                restore_review_targets(&test_store.store, 1, &["one.example".into()]).unwrap();
            run_review_worker_and_persist(
                Arc::clone(&test_store.store),
                Arc::default(),
                1,
                targets,
            )
            .await;
            let result = job(&test_store.store, 1).service_results.remove(0);
            assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
            assert_eq!(result.requested_at, 123);
            assert!(result.completed_at.is_some());
            assert!(result.error.unwrap().contains(if panic_worker {
                "failed to join"
            } else {
                "injected deletion failure"
            }));
        }
    }

    /// Stores a draft sampling policy `name` of `customer_id` reading
    /// `node`, and returns its ID.
    fn put_policy(store: &Store, name: &str, customer_id: u32, node: &str) -> u32 {
        store
            .sampling_policy_map()
            .insert(review_database::NewSamplingPolicy {
                name: name.to_string(),
                kind: review_database::SamplingKind::Conn,
                interval: review_database::SamplingInterval::FifteenMinutes,
                period: review_database::SamplingPeriod::OneDay,
                offset: 0,
                src_ip: None,
                dst_ip: None,
                node: Some(node.to_string()),
                column: None,
                customer_id,
            })
            .unwrap()
    }

    #[tokio::test]
    async fn deletion_removes_the_customers_sampling_policies_even_in_use() {
        let test_store = TestStore::new();
        put_active_node(&test_store, 1, "one.example");
        put_active_node(&test_store, 2, "two.example");
        let (own, used, other) = {
            let store = read_store(&test_store.store).unwrap();
            let mut engine = Agent::new(
                0,
                "001.unsupervised".to_string(),
                AgentKind::Unsupervised,
                AgentStatus::Enabled,
                None,
                None,
            )
            .unwrap();
            engine.instance = Some(1);
            let engine_node = store
                .node_map()
                .put(&Node {
                    id: 0,
                    name: "engine.one.example".to_string(),
                    name_draft: None,
                    profile: Some(NodeProfile {
                        customer_id: 1,
                        description: String::new(),
                        hostname: "engine.one.example".to_string(),
                    }),
                    profile_draft: None,
                    agents: vec![engine],
                    external_services: vec![],
                    creation_time: Utc::now(),
                })
                .unwrap();
            let own = put_policy(&store, "own", 1, "piglet.one.example");
            let used = put_policy(&store, "used", 1, "piglet.one.example");
            let other = put_policy(&store, "other", 2, "piglet.two.example");
            store
                .insert_training_definition(review_database::NewTrainingDefinition {
                    name: "series".to_string(),
                    customer_id: 1,
                    instance: review_database::ModelInstance {
                        node_id: engine_node,
                        agent_key: "001.unsupervised".to_string(),
                    },
                    method: review_database::ModelMethod::Timeseries,
                    event_kind: "conn".to_string(),
                    sources: vec![used.to_string()],
                    indicator: None,
                    definition: String::new(),
                })
                .unwrap();
            assert_eq!(
                store.sampling_policy_uses(used).unwrap(),
                [review_database::PolicyUse::Definition {
                    name: "series".to_string()
                }]
            );
            (own, used, other)
        };
        // The Review stage runs once the engine is uninstalled.
        drop_row(&test_store.store, "engine.one.example", "reconverge", 1);
        put_job(
            &test_store.store,
            1,
            vec![pending_result(
                CustomerDataDeletionService::Review,
                &["one.example"],
            )],
        );

        let targets =
            restore_review_targets(&test_store.store, 1, &["one.example".into()]).unwrap();
        run_review_worker_and_persist(Arc::clone(&test_store.store), Arc::default(), 1, targets)
            .await;
        assert_eq!(
            job(&test_store.store, 1).service_results.remove(0).status,
            CustomerDataDeletionStatus::Succeeded
        );
        let store = read_store(&test_store.store).unwrap();
        let map = store.sampling_policy_map();
        assert!(map.get_by_id(own).unwrap().is_none());
        assert!(map.get_by_id(used).unwrap().is_none());
        assert!(map.get_by_id(other).unwrap().is_some());
    }

    #[tokio::test]
    async fn deletion_waits_for_a_held_sampling_policies_lock() {
        let test_store = TestStore::new();
        let node = put_active_node(&test_store, 1, "one.example");
        put_active_node(&test_store, 2, "two.example");
        let (own, other) = {
            let store = read_store(&test_store.store).unwrap();
            (
                put_policy(&store, "own", 1, "piglet.one.example"),
                put_policy(&store, "other", 2, "piglet.two.example"),
            )
        };
        put_job(
            &test_store.store,
            1,
            vec![pending_result(
                CustomerDataDeletionService::Review,
                &["one.example"],
            )],
        );
        let lock = Arc::new(SamplingPoliciesLock::default());
        // A `removeSamplingPolicies` holds the lock from its checks through
        // its last removal, so the deletion cannot take a policy it checked.
        let guard = lock.hold().await;

        let targets =
            restore_review_targets(&test_store.store, 1, &["one.example".into()]).unwrap();
        let worker = tokio::spawn(run_review_worker_and_persist(
            Arc::clone(&test_store.store),
            Arc::clone(&lock),
            1,
            targets,
        ));
        while lock.users() < 2 {
            tokio::task::yield_now().await;
        }
        {
            let store = read_store(&test_store.store).unwrap();
            assert!(store.node_map().get_by_id(node).unwrap().is_none());
            let map = store.sampling_policy_map();
            assert!(map.get_by_id(own).unwrap().is_some());
            assert!(map.get_by_id(other).unwrap().is_some());
        }
        drop(guard);
        worker.await.unwrap();

        assert_eq!(lock.users(), 0);
        assert_eq!(
            job(&test_store.store, 1).service_results.remove(0).status,
            CustomerDataDeletionStatus::Succeeded
        );
        let store = read_store(&test_store.store).unwrap();
        let map = store.sampling_policy_map();
        assert!(map.get_by_id(own).unwrap().is_none());
        assert!(map.get_by_id(other).unwrap().is_some());
    }

    /// Stores the timeseries training definition `name` of `customer_id` on
    /// `instance`, reading the sampling policy `policy`.
    fn put_timeseries_definition(
        store: &Store,
        name: &str,
        customer_id: u32,
        instance: &review_database::ModelInstance,
        policy: u32,
    ) {
        store
            .insert_training_definition(review_database::NewTrainingDefinition {
                name: name.to_string(),
                customer_id,
                instance: instance.clone(),
                method: review_database::ModelMethod::Timeseries,
                event_kind: "timeseries".to_string(),
                sources: vec![policy.to_string()],
                indicator: None,
                definition: String::new(),
            })
            .unwrap();
    }

    /// Returns the names of the models of `customer_id`, from the table
    /// `models` lists.
    fn customer_models(store: &Store, customer_id: u32) -> Vec<String> {
        store
            .model_map()
            .iter(Direction::Forward, None)
            .map(Result::unwrap)
            .filter(|model| model.customer_id == customer_id)
            .map(|model| model.name)
            .collect()
    }

    /// Returns the training definitions of `customer_id`, as
    /// `trainingDefinitions` reads them.
    fn customer_definitions(
        store: &Store,
        customer_id: u32,
    ) -> Vec<review_database::TrainingDefinition> {
        store
            .training_definitions()
            .unwrap()
            .into_iter()
            .filter(|definition| definition.customer_id == customer_id)
            .collect()
    }

    /// Returns the ids of the sampling policies of `customer_id`, from the
    /// table `samplingPolicyList` lists.
    fn customer_policies(store: &Store, customer_id: u32) -> Vec<u32> {
        store
            .sampling_policy_map()
            .iter(Direction::Forward, None)
            .map(Result::unwrap)
            .filter(|policy| policy.customer_id == Some(customer_id))
            .map(|policy| policy.id)
            .collect()
    }

    /// Requests the deletion of `customer_id` through `deleteCustomerData`,
    /// waits for the work it starts, and returns the mutation's status.
    async fn delete_customer_data(test_store: &TestStore, customer_id: u32) -> String {
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let schema = test_schema(
            test_store,
            Arc::new(RecordingAgentManager::with_store(&test_store.store)),
            Arc::clone(&manager),
        );
        let response = schema
            .execute(admin_request(&format!(
                r#"mutation {{ deleteCustomerData(customerId: "{customer_id}") }}"#
            )))
            .await;
        assert!(response.errors.is_empty(), "{response:?}");
        let supervisor = manager.state.lock().await.active.take();
        if let Some((_, supervisor)) = supervisor {
            supervisor.await.unwrap();
        }
        response.data.into_json().unwrap()["deleteCustomerData"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Returns the job's Review result, the only result other than its
    /// hosts' `ModuleRemoval` results.
    fn review_result(store: &RwLock<Store>, customer_id: u32) -> CustomerDataDeletionServiceResult {
        let job = job(store, customer_id);
        let mut others = job
            .service_results
            .iter()
            .filter(|result| result.service != CustomerDataDeletionService::ModuleRemoval);
        let review = others.next().cloned();
        assert!(others.next().is_none(), "{job:?}");
        review
            .filter(|result| result.service == CustomerDataDeletionService::Review)
            .unwrap_or_else(|| panic!("no Review result: {job:?}"))
    }

    #[tokio::test]
    async fn deletion_removes_the_customers_unsupervised_records() {
        let test_store = TestStore::new();
        let (other_definitions, other_policies) = {
            let store = read_store(&test_store.store).unwrap();
            let engine = insert_engine_node(&store, 1);
            let detected = TestModel {
                instance: engine.clone(),
                ..TestModel::new("detected", 1)
            }
            .replace(&store);
            insert_indicator(&store, "detected-indicator", detected);
            name_in_applied_document(&store, &engine, 7, "detected", "detected-indicator");
            let named = TestModel {
                instance: engine.clone(),
                ..TestModel::new("named", 1)
            }
            .replace(&store);
            insert_indicator(&store, "named-indicator", named);
            insert_definition(&store, "naming", 1, &engine, "named-indicator");
            let policy = put_policy(&store, "own", 1, "piglet.one.example");
            put_timeseries_definition(&store, "series", 1, &engine, policy);
            assert_eq!(
                store.sampling_policy_uses(policy).unwrap(),
                [review_database::PolicyUse::Definition {
                    name: "series".to_string()
                }]
            );

            let other_engine = insert_engine_node(&store, 2);
            let other = TestModel {
                instance: other_engine.clone(),
                ..TestModel::new("other", 2)
            }
            .replace(&store);
            insert_indicator(&store, "other-indicator", other);
            name_in_applied_document(&store, &other_engine, 7, "other", "other-indicator");
            insert_definition(&store, "other-naming", 2, &other_engine, "other-indicator");
            let other_policy = put_policy(&store, "other", 2, "piglet.two.example");
            put_timeseries_definition(&store, "other-series", 2, &other_engine, other_policy);

            assert_eq!(customer_models(&store, 1), ["detected", "named"]);
            assert_eq!(customer_definitions(&store, 1).len(), 2);
            assert_eq!(customer_policies(&store, 1), [policy]);
            (
                customer_definitions(&store, 2),
                customer_policies(&store, 2),
            )
        };

        assert_eq!(delete_customer_data(&test_store, 1).await, "ACCEPTED");
        assert_eq!(
            review_result(&test_store.store, 1).status,
            CustomerDataDeletionStatus::Succeeded
        );
        {
            let store = read_store(&test_store.store).unwrap();
            assert_eq!(customer_models(&store, 1), Vec::<String>::new());
            assert_eq!(customer_definitions(&store, 1), []);
            assert_eq!(customer_policies(&store, 1), Vec::<u32>::new());
            for indicator in ["detected-indicator", "named-indicator"] {
                assert!(
                    store
                        .model_indicator_map()
                        .get(indicator)
                        .unwrap()
                        .is_none()
                );
            }
            assert_eq!(customer_models(&store, 2), ["other"]);
            assert_eq!(customer_definitions(&store, 2), other_definitions);
            assert_eq!(customer_policies(&store, 2), other_policies);
            assert!(
                store
                    .model_indicator_map()
                    .get("other-indicator")
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(
            delete_customer_data(&test_store, 1).await,
            "ALREADY_COMPLETED"
        );
    }

    #[tokio::test]
    async fn deletion_fails_while_another_customer_names_its_indicator() {
        let test_store = TestStore::new();
        let (model, foreign) = {
            let store = read_store(&test_store.store).unwrap();
            let engine = insert_engine_node(&store, 1);
            let model = TestModel {
                instance: engine,
                ..TestModel::new("model", 1)
            }
            .replace(&store);
            insert_indicator(&store, "indicator", model);
            let other_engine = insert_engine_node(&store, 2);
            insert_definition(&store, "foreign", 2, &other_engine, "indicator");
            (
                model,
                store.training_definition("foreign").unwrap().unwrap(),
            )
        };

        assert_eq!(delete_customer_data(&test_store, 1).await, "ACCEPTED");
        let failed = review_result(&test_store.store, 1);
        assert_eq!(failed.status, CustomerDataDeletionStatus::Failed);
        let error = failed.error.unwrap();
        assert!(
            error.contains("deleting Unsupervised Engine records for customer 1"),
            "{error}"
        );
        assert!(error.contains("is used by training definition"), "{error}");
        {
            let store = read_store(&test_store.store).unwrap();
            assert_eq!(store.training_definition("foreign").unwrap(), Some(foreign));
            assert_eq!(store.model_map().load_model(model).unwrap().name, "model");
            store.remove_training_definition("foreign").unwrap();
        }

        assert_eq!(delete_customer_data(&test_store, 1).await, "ACCEPTED");
        assert_eq!(
            review_result(&test_store.store, 1).status,
            CustomerDataDeletionStatus::Succeeded
        );
        {
            let store = read_store(&test_store.store).unwrap();
            assert_eq!(customer_models(&store, 1), Vec::<String>::new());
            assert!(
                store
                    .model_indicator_map()
                    .get("indicator")
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            delete_customer_data(&test_store, 1).await,
            "ALREADY_COMPLETED"
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn deletion_stops_at_each_failed_boundary_and_retry_finishes() {
        const STAGES: [Stage; 7] = [
            Stage::Events,
            Stage::Hosts,
            Stage::TrafficFilters,
            Stage::CustomerNetworks,
            Stage::NetworkLists,
            Stage::Nodes,
            Stage::Unsupervised,
        ];
        let test_store = TestStore::new();
        for (index, fail_stage) in STAGES.into_iter().enumerate() {
            let node = put_active_node(&test_store, 1, "one.example");
            put_customer_network_data(&test_store, 1);
            let target_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            put_dns_event(
                &test_store,
                "piglet.one.example",
                i64::try_from(index * 2 + 10).unwrap(),
            );
            put_dns_event(
                &test_store,
                "piglet.one.example.extra",
                i64::try_from(index * 2 + 11).unwrap(),
            );
            {
                let store = read_store(&test_store.store).unwrap();
                store
                    .hosts_map()
                    .update_opened_ports(
                        1,
                        &HashMap::from([(target_ip, HashMap::from([((80, 6), 1)]))]),
                    )
                    .unwrap();
                store
                    .traffic_filter_map()
                    .add_rules(
                        "one.example",
                        "10.0.0.0/24".parse().unwrap(),
                        None,
                        None,
                        None,
                    )
                    .unwrap();
                TestModel::new("model", 1).replace(&store);
            }
            put_job(
                &test_store.store,
                1,
                vec![pending_result(
                    CustomerDataDeletionService::Review,
                    &["one.example"],
                )],
            );
            let visited = Arc::new(std::sync::Mutex::new(Vec::new()));
            let calls = Arc::clone(&visited);
            let hook = HookGuard::install(
                &test_store.store,
                Arc::new(move |stage, _| {
                    if STAGES.contains(&stage) {
                        calls.lock().unwrap().push(stage);
                    }
                    if stage == fail_stage {
                        bail!("injected RocksDB boundary error");
                    }
                    Ok(())
                }),
            );
            let targets =
                restore_review_targets(&test_store.store, 1, &["one.example".into()]).unwrap();
            run_review_worker_and_persist(
                Arc::clone(&test_store.store),
                Arc::default(),
                1,
                targets,
            )
            .await;
            let expected: Vec<_> = STAGES
                .into_iter()
                .take_while(|s| *s != fail_stage)
                .chain([fail_stage])
                .collect();
            assert_eq!(*visited.lock().unwrap(), expected);
            let failed = job(&test_store.store, 1);
            assert_eq!(
                failed.service_results.first().unwrap().status,
                CustomerDataDeletionStatus::Failed
            );
            if fail_stage == Stage::Events {
                let error = failed
                    .service_results
                    .first()
                    .unwrap()
                    .error
                    .as_ref()
                    .unwrap();
                assert!(error.contains("events"));
                assert!(error.contains("piglet.one.example"));
                assert!(error.contains("reproduce.one.example"));
                assert!(error.contains("injected RocksDB boundary error"));
            }
            let error_context = match fail_stage {
                Stage::CustomerNetworks => Some("deleting customer networks for customer 1"),
                Stage::NetworkLists => Some("deleting network lists for customer 1"),
                Stage::Unsupervised => Some("deleting Unsupervised Engine records for customer 1"),
                _ => None,
            };
            if let Some(context) = error_context {
                let error = failed
                    .service_results
                    .first()
                    .unwrap()
                    .error
                    .as_ref()
                    .unwrap();
                assert!(error.contains(context));
                assert!(error.contains("injected RocksDB boundary error"));
            }
            {
                let store = read_store(&test_store.store).unwrap();
                let target_event_exists = store.events().iter_forward().any(|entry| {
                    matches!(
                        entry.unwrap().1,
                        Event::DnsCovertChannel(event)
                            if event.sensor == "piglet.one.example"
                    )
                });
                assert_eq!(target_event_exists, fail_stage == Stage::Events);
                assert_eq!(
                    store.hosts_map().get(1, target_ip).unwrap().is_some(),
                    matches!(fail_stage, Stage::Events | Stage::Hosts)
                );
                assert_eq!(
                    store
                        .traffic_filter_map()
                        .get("one.example")
                        .unwrap()
                        .is_some(),
                    matches!(
                        fail_stage,
                        Stage::Events | Stage::Hosts | Stage::TrafficFilters
                    )
                );
                assert_eq!(
                    store.customer_networks_map().get(1).unwrap().is_some(),
                    matches!(
                        fail_stage,
                        Stage::Events
                            | Stage::Hosts
                            | Stage::TrafficFilters
                            | Stage::CustomerNetworks
                    )
                );
                assert_eq!(
                    store.network_lists_map().get(1).unwrap().is_some(),
                    matches!(
                        fail_stage,
                        Stage::Events
                            | Stage::Hosts
                            | Stage::TrafficFilters
                            | Stage::CustomerNetworks
                            | Stage::NetworkLists
                    )
                );
                let nodes_kept = fail_stage != Stage::Unsupervised;
                assert_eq!(
                    store.node_map().get_by_id(node).unwrap().is_some(),
                    nodes_kept
                );
                assert_eq!(
                    store
                        .agents_map()
                        .get(node, "001.piglet")
                        .unwrap()
                        .is_some(),
                    nodes_kept
                );
                assert_eq!(
                    store
                        .external_service_map()
                        .get(node, "001.giganto")
                        .unwrap()
                        .is_some(),
                    nodes_kept
                );
                assert_eq!(customer_models(&store, 1), ["model"]);
            }
            drop(hook);
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());
            let agent = Arc::new(RecordingAgentManager::default());
            let shared: SharedAgentManager = agent.clone();
            assert_eq!(
                request_deletion(
                    1,
                    &test_store.store,
                    &shared,
                    &deployer(&test_store),
                    &manager
                )
                .await
                .unwrap(),
                CustomerDataDeletionRequestStatus::Accepted
            );
            finish_supervisor(&manager).await;
            assert_eq!(
                job(&test_store.store, 1)
                    .service_results
                    .first()
                    .unwrap()
                    .status,
                CustomerDataDeletionStatus::Succeeded
            );
            assert!(agent.targets.lock().unwrap().is_empty());
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());
            assert_eq!(
                request_deletion(
                    1,
                    &test_store.store,
                    &shared,
                    &deployer(&test_store),
                    &manager
                )
                .await
                .unwrap(),
                CustomerDataDeletionRequestStatus::AlreadyCompleted
            );
            let store = read_store(&test_store.store).unwrap();
            assert!(store.customer_networks_map().get(1).unwrap().is_none());
            assert!(store.network_lists_map().get(1).unwrap().is_none());
            assert!(store.hosts_map().get(1, target_ip).unwrap().is_none());
            assert!(
                store
                    .traffic_filter_map()
                    .get("one.example")
                    .unwrap()
                    .is_none()
            );
            assert!(store.node_map().get_by_id(node).unwrap().is_none());
            assert!(
                store
                    .agents_map()
                    .get(node, "001.piglet")
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .external_service_map()
                    .get(node, "001.giganto")
                    .unwrap()
                    .is_none()
            );
            assert!(store.events().iter_forward().all(|entry| {
                !matches!(
                    entry.unwrap().1,
                    Event::DnsCovertChannel(event) if event.sensor == "piglet.one.example"
                )
            }));
            assert!(store.events().iter_forward().any(|entry| {
                matches!(
                    entry.unwrap().1,
                    Event::DnsCovertChannel(event)
                        if event.sensor == "piglet.one.example.extra"
                )
            }));
            assert_eq!(customer_models(&store, 1), Vec::<String>::new());
            drop(store);
        }
    }

    #[test]
    fn associated_record_retries_attempt_every_key_and_report_only_final_failures() {
        let test_store = TestStore::new();
        let agent_attempts = Arc::new(AtomicUsize::new(0));
        let service_attempts = Arc::new(AtomicUsize::new(0));
        let hook_agent_attempts = Arc::clone(&agent_attempts);
        let hook_service_attempts = Arc::clone(&service_attempts);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, _| match stage {
                Stage::RetryAgent => {
                    let attempt = hook_agent_attempts.fetch_add(1, Ordering::SeqCst);
                    if attempt != 1 {
                        bail!("agent retry {attempt} failed");
                    }
                    Ok(())
                }
                Stage::RetryExternalService => {
                    let attempt = hook_service_attempts.fetch_add(1, Ordering::SeqCst);
                    if attempt == 1 {
                        bail!("external service retry failed");
                    }
                    Ok(())
                }
                _ => Ok(()),
            }),
        );
        let store = read_store(&test_store.store).unwrap();
        let error = retry_failed_associated_deletions(
            &store,
            9,
            &["agent-a".into(), "agent-b".into(), "agent-c".into()],
            &["service-a".into(), "service-b".into()],
        )
        .unwrap_err();
        drop(store);

        assert_eq!(agent_attempts.load(Ordering::SeqCst), 3);
        assert_eq!(service_attempts.load(Ordering::SeqCst), 2);
        let error = format!("{error:#}");
        assert!(error.contains("agent-a"));
        assert!(!error.contains("agent-b"));
        assert!(error.contains("agent-c"));
        assert!(!error.contains("service-a"));
        assert!(error.contains("service-b"));
    }

    #[test]
    fn final_associated_record_failures_stop_before_the_next_node() {
        let test_store = TestStore::new();
        let first_node = put_active_node(&test_store, 1, "a.example");
        let second_node = put_active_node(&test_store, 1, "b.example");
        let _failures = AssociatedFailureGuard::install(
            &test_store.store,
            first_node,
            vec!["agent-a".into(), "agent-b".into()],
            vec!["service-a".into(), "service-b".into()],
        );
        let agent_attempts = Arc::new(AtomicUsize::new(0));
        let service_attempts = Arc::new(AtomicUsize::new(0));
        let hook_agent_attempts = Arc::clone(&agent_attempts);
        let hook_service_attempts = Arc::clone(&service_attempts);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, _| match stage {
                Stage::RetryAgent => {
                    if hook_agent_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        bail!("agent retry failed");
                    }
                    Ok(())
                }
                Stage::RetryExternalService => {
                    hook_service_attempts.fetch_add(1, Ordering::SeqCst);
                    bail!("external service retry failed")
                }
                _ => Ok(()),
            }),
        );

        let error = delete_review_data(
            &test_store.store,
            &SamplingPoliciesLock::default(),
            1,
            &ReviewDeletionTargets {
                node_ids: vec![first_node, second_node],
                host_fqdns: Vec::new(),
                event_service_fqdns: Vec::new(),
            },
        )
        .unwrap_err();

        assert_eq!(agent_attempts.load(Ordering::SeqCst), 2);
        assert_eq!(service_attempts.load(Ordering::SeqCst), 2);
        let error = format!("{error:#}");
        assert!(error.contains("agent-a"));
        assert!(!error.contains("agent-b"));
        assert!(error.contains("service-a"));
        assert!(error.contains("service-b"));
        let store = read_store(&test_store.store).unwrap();
        assert!(store.node_map().get_by_id(first_node).unwrap().is_none());
        assert!(store.node_map().get_by_id(second_node).unwrap().is_some());
        assert!(
            store
                .agents_map()
                .get(second_node, "001.piglet")
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .external_service_map()
                .get(second_node, "001.giganto")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn terminal_persistence_retries_once_and_preserves_final_values() {
        let test_store = TestStore::new();
        put_job(
            &test_store.store,
            1,
            vec![pending_result(
                CustomerDataDeletionService::Review,
                &["one.example"],
            )],
        );
        let attempts = Arc::new(AtomicUsize::new(0));
        let hook_attempts = Arc::clone(&attempts);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, _| {
                if stage == Stage::PersistTerminal
                    && hook_attempts.fetch_add(1, Ordering::SeqCst) == 0
                {
                    bail!("first persistence attempt failed: database unavailable");
                }
                Ok(())
            }),
        );

        persist_review_terminal(
            &test_store.store,
            1,
            CustomerDataDeletionStatus::Failed,
            Some("deletion failed: underlying database error"),
        )
        .unwrap();

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        let result = job(&test_store.store, 1).service_results.remove(0);
        assert_eq!(result.requested_at, 123);
        assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(
            result.error.as_deref(),
            Some("deletion failed: underlying database error")
        );
        assert!(result.completed_at.is_some());
    }

    #[test]
    fn terminal_persistence_stops_after_two_failures() {
        let test_store = TestStore::new();
        put_job(
            &test_store.store,
            1,
            vec![pending_result(
                CustomerDataDeletionService::Review,
                &["one.example"],
            )],
        );
        let attempts = Arc::new(AtomicUsize::new(0));
        let hook_attempts = Arc::clone(&attempts);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, _| {
                if stage == Stage::PersistTerminal {
                    hook_attempts.fetch_add(1, Ordering::SeqCst);
                    bail!("database unavailable");
                }
                Ok(())
            }),
        );

        assert!(
            persist_review_terminal(
                &test_store.store,
                1,
                CustomerDataDeletionStatus::Succeeded,
                None,
            )
            .is_err()
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            job(&test_store.store, 1).service_results.remove(0),
            pending_result(CustomerDataDeletionService::Review, &["one.example"])
        );
    }

    #[tokio::test]
    async fn retry_resets_and_runs_only_failed_results() {
        let test_store = TestStore::new();
        let original_review = terminal_result(
            CustomerDataDeletionService::Review,
            "retry.example",
            CustomerDataDeletionStatus::Succeeded,
        );
        let failed_sensor = CustomerDataDeletionServiceResult {
            status: CustomerDataDeletionStatus::Failed,
            completed_at: Some(789),
            error: Some("old failure".to_string()),
            ..pending_result(CustomerDataDeletionService::Sensor, &["retry.example"])
        };
        put_job(
            &test_store.store,
            77,
            vec![original_review.clone(), failed_sensor],
        );
        // The delivery leaves the target `InProgress`, as a closed gate does.
        let agent_manager = Arc::new(RecordingAgentManager {
            hold_delivery: true,
            ..RecordingAgentManager::default()
        });
        let shared_agent_manager: SharedAgentManager = agent_manager.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_deletion(
                77,
                &test_store.store,
                &shared_agent_manager,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::Accepted
        );
        agent_manager.delivery_started.notified().await;
        manager.shutdown_and_wait().await;
        assert_eq!(
            agent_manager
                .targets
                .lock()
                .unwrap()
                .first()
                .unwrap()
                .target_service_key(),
            "piglet.retry.example"
        );
        let job = job(&test_store.store, 77);
        assert_eq!(job.service_results.first().unwrap(), &original_review);
        let retried = job.service_results.get(1).unwrap();
        assert_eq!(retried.status, CustomerDataDeletionStatus::InProgress);
        assert!(retried.requested_at > 123);
        assert_eq!(retried.completed_at, None);
        assert_eq!(retried.error, None);
    }

    #[tokio::test]
    async fn retry_preserves_a_service_report_received_before_persistence() {
        let test_store = TestStore::new();
        let node_id = put_active_node(&test_store, 1, "retry.example");
        put_job(
            &test_store.store,
            1,
            vec![
                terminal_result(
                    CustomerDataDeletionService::Review,
                    "retry.example",
                    CustomerDataDeletionStatus::Failed,
                ),
                terminal_result(
                    CustomerDataDeletionService::Sensor,
                    "retry.example",
                    CustomerDataDeletionStatus::Failed,
                ),
                terminal_result(
                    CustomerDataDeletionService::SemiSupervised,
                    "retry.example",
                    CustomerDataDeletionStatus::Succeeded,
                ),
            ],
        );
        let mut expected = job(&test_store.store, 1);
        let reported = expected.service_results.get_mut(1).unwrap();
        reported.status = CustomerDataDeletionStatus::Succeeded;
        reported.completed_at = Some(789);
        reported.error = None;
        let reported = reported.clone();
        let hook_store = Arc::clone(&test_store.store);
        // Deliver a late success after lookup but before the conditional write.
        let hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, customer_id| {
                if stage == Stage::PersistRequest {
                    read_store(&hook_store)?
                        .customer_data_deletion_map()
                        .update_service(customer_id, &reported)?;
                }
                Ok(())
            }),
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent = Arc::new(RecordingAgentManager::default());
        let shared: SharedAgentManager = agent.clone();
        let schema = test_schema(&test_store, shared, Arc::clone(&manager));
        let response = schema
            .execute(
                Request::new(r#"mutation { deleteCustomerData(customerId: "1") }"#)
                    .data(RoleGuard::Role(Role::SystemAdministrator)),
            )
            .await;

        assert_eq!(response.errors.len(), 1);
        let error = &response.errors.first().unwrap().message;
        assert!(error.contains("persisting customer data deletion retry for customer 1"));
        assert!(error.contains("old value mismatch"));
        assert_eq!(job(&test_store.store, 1), expected);
        assert!(manager.state.lock().await.active.is_none());
        assert!(agent.targets.lock().unwrap().is_empty());
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .node_map()
                .get_by_id(node_id)
                .unwrap()
                .is_some()
        );
        drop(hook);

        // An explicit retry uses the latest job and leaves successful services unchanged.
        let response = schema
            .execute(
                Request::new(r#"mutation { deleteCustomerData(customerId: "1") }"#)
                    .data(RoleGuard::Role(Role::SystemAdministrator)),
            )
            .await;
        assert_eq!(response.errors, []);
        assert_eq!(response.data.to_string(), "{deleteCustomerData: ACCEPTED}");
        finish_supervisor(&manager).await;
        let after = job(&test_store.store, 1);
        assert_eq!(
            after.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Succeeded
        );
        assert!(
            after
                .service_results
                .iter()
                .skip(1)
                .eq(expected.service_results.iter().skip(1))
        );
        assert!(agent.targets.lock().unwrap().is_empty());
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .node_map()
                .get_by_id(node_id)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn retry_and_recovery_use_persisted_keys_after_node_deletion() {
        let test_store = TestStore::new();
        let agent_manager: SharedAgentManager = Arc::new(RecordingAgentManager::default());

        for (customer_id, hostname, ip, retry) in [
            (
                1,
                "retry.example",
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                true,
            ),
            (
                2,
                "recovery.example",
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                false,
            ),
        ] {
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());
            let node_id = put_active_node(&test_store, customer_id, hostname);
            put_customer_network_data(&test_store, customer_id);
            let mut review = pending_result(CustomerDataDeletionService::Review, &[hostname]);
            if retry {
                review.status = CustomerDataDeletionStatus::Failed;
                review.completed_at = Some(456);
                review.error = Some("previous failure".to_string());
            }
            put_job(&test_store.store, customer_id, vec![review]);
            put_dns_event(
                &test_store,
                &format!("piglet.{hostname}"),
                i64::from(customer_id),
            );
            {
                let store = read_store(&test_store.store).unwrap();
                store
                    .hosts_map()
                    .update_opened_ports(
                        customer_id,
                        &HashMap::from([(ip, HashMap::from([((80, 6), 1)]))]),
                    )
                    .unwrap();
                store
                    .traffic_filter_map()
                    .add_rules(hostname, "10.0.0.0/24".parse().unwrap(), None, None, None)
                    .unwrap();
                store.node_map().remove(node_id).unwrap();
            }

            if retry {
                assert_eq!(
                    request_deletion(
                        customer_id,
                        &test_store.store,
                        &agent_manager,
                        &deployer(&test_store),
                        &manager
                    )
                    .await
                    .unwrap(),
                    CustomerDataDeletionRequestStatus::Accepted
                );
                finish_supervisor(&manager).await;
            } else {
                assert_eq!(recover_and_start(&test_store.store, &manager).await, []);
                wait_for_recovery(&manager).await;
                manager.shutdown_and_wait().await;
            }

            let store = read_store(&test_store.store).unwrap();
            assert!(
                store
                    .customer_networks_map()
                    .get(customer_id)
                    .unwrap()
                    .is_none(),
                "customer {customer_id} networks remain"
            );
            assert!(
                store
                    .network_lists_map()
                    .get(customer_id)
                    .unwrap()
                    .is_none(),
                "customer {customer_id} network lists remain"
            );
            assert!(
                store.hosts_map().get(customer_id, ip).unwrap().is_none(),
                "customer {customer_id} host remains"
            );
            assert!(store.traffic_filter_map().get(hostname).unwrap().is_none());
            assert!(store.events().iter_forward().all(|entry| {
                !matches!(
                    entry.unwrap().1,
                    Event::DnsCovertChannel(event)
                        if event.sensor == format!("piglet.{hostname}")
                )
            }));
            assert_eq!(
                job(&test_store.store, customer_id)
                    .service_results
                    .first()
                    .unwrap()
                    .status,
                CustomerDataDeletionStatus::Succeeded
            );
        }
    }

    #[tokio::test]
    async fn startup_recovery_with_no_pending_results_does_nothing() {
        let test_store = TestStore::new();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let targets = recover_and_start(&test_store.store, &manager).await;
        assert_eq!(targets, []);
        assert!(manager.state.lock().await.active.is_none());
    }

    #[tokio::test]
    async fn startup_recovery_resumes_a_stopped_job_only_for_its_reports() {
        let test_store = TestStore::new();
        // A stopped job: its Review result is `Failed`, and its only
        // `InProgress` result a Sensor's.
        put_job(
            &test_store.store,
            9,
            vec![
                terminal_result(
                    CustomerDataDeletionService::Review,
                    "node.example",
                    CustomerDataDeletionStatus::Failed,
                ),
                pending_result(CustomerDataDeletionService::Sensor, &["node.example"]),
                CustomerDataDeletionServiceResult {
                    status: CustomerDataDeletionStatus::Failed,
                    completed_at: Some(789),
                    error: Some("failed".to_string()),
                    ..pending_result(
                        CustomerDataDeletionService::SemiSupervised,
                        &["node.example"],
                    )
                },
            ],
        );
        let before = job(&test_store.store, 9);
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let targets = recover_and_start(&test_store.store, &manager).await;
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target_service_key(), "piglet.node.example");
        finish_supervisor(&manager).await;
        // Only the report was recorded; the stop stays as it was.
        let after = job(&test_store.store, 9);
        assert_eq!(after.service_results[0], before.service_results[0]);
        assert_eq!(
            after.service_results[1].status,
            CustomerDataDeletionStatus::Succeeded
        );
        assert_eq!(after.service_results[2], before.service_results[2]);
    }

    #[tokio::test]
    async fn startup_recovery_processes_multiple_customers_in_order() {
        let test_store = TestStore::new();
        for customer_id in [20, 10] {
            let hostname = format!("node-{customer_id}.example");
            put_job(
                &test_store.store,
                customer_id,
                vec![
                    pending_result(CustomerDataDeletionService::Review, &[&hostname]),
                    pending_result(CustomerDataDeletionService::Sensor, &[&hostname]),
                ],
            );
        }
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let targets = recover_and_start(&test_store.store, &manager).await;
        assert_eq!(
            targets
                .iter()
                .map(CustomerDataDeletionTarget::customer_id)
                .collect::<Vec<_>>(),
            [10, 20]
        );
        let supervisor = manager
            .state
            .lock()
            .await
            .active
            .take()
            .expect("startup recovery registers one supervisor")
            .1;
        supervisor.await.unwrap();
        for customer_id in [10, 20] {
            let job = job(&test_store.store, customer_id);
            let review = job
                .service_results
                .iter()
                .find(|result| result.service == CustomerDataDeletionService::Review)
                .unwrap();
            assert_eq!(review.status, CustomerDataDeletionStatus::Succeeded);
        }
    }

    #[tokio::test]
    async fn recovery_returns_all_remote_targets_before_sequential_workers_finish() {
        let test_store = TestStore::new();
        for customer_id in [20, 10] {
            let host = format!("{customer_id}.example");
            put_job(
                &test_store.store,
                customer_id,
                vec![
                    pending_result(CustomerDataDeletionService::Review, &[&host]),
                    pending_result(CustomerDataDeletionService::Sensor, &[&host]),
                ],
            );
        }
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let (release, releases) = std::sync::mpsc::channel();
        let releases = std::sync::Mutex::new(releases);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, customer| {
                if stage == Stage::Worker {
                    started.send(customer).unwrap();
                    releases.lock().unwrap().recv().unwrap();
                }
                Ok(())
            }),
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let targets = recover_and_start(&test_store.store, &manager).await;
        assert_eq!(
            targets
                .iter()
                .map(CustomerDataDeletionTarget::customer_id)
                .collect::<Vec<_>>(),
            [10, 20]
        );
        assert_eq!(
            targets
                .iter()
                .map(CustomerDataDeletionTarget::target_service_key)
                .collect::<BTreeSet<_>>()
                .len(),
            2
        );
        let outer_id = manager.state.lock().await.active.as_ref().unwrap().1.id();
        assert_eq!(starts.recv().await, Some(10));
        assert_eq!(manager.state.lock().await.active.as_ref().unwrap().0, 10);
        assert!(starts.try_recv().is_err());
        assert_eq!(
            job(&test_store.store, 20)
                .service_results
                .first()
                .unwrap()
                .status,
            CustomerDataDeletionStatus::InProgress
        );
        release.send(()).unwrap();
        assert_eq!(starts.recv().await, Some(20));
        {
            let state = manager.state.lock().await;
            let (customer, handle) = state.active.as_ref().unwrap();
            assert_eq!(*customer, 20);
            assert_eq!(handle.id(), outer_id);
        }
        assert_eq!(
            job(&test_store.store, 10)
                .service_results
                .first()
                .unwrap()
                .status,
            CustomerDataDeletionStatus::Succeeded
        );
        release.send(()).unwrap();
        manager.shutdown_and_wait().await;
        assert_eq!(
            job(&test_store.store, 20)
                .service_results
                .first()
                .unwrap()
                .status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    #[tokio::test]
    async fn recovery_continues_after_worker_and_terminal_persistence_failures() {
        let test_store = TestStore::new();
        for customer_id in [4, 3, 2, 1] {
            put_job(
                &test_store.store,
                customer_id,
                vec![pending_result(
                    CustomerDataDeletionService::Review,
                    &[&format!("{customer_id}.example")],
                )],
            );
        }
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls = Arc::clone(&order);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, customer| {
                if stage == Stage::Worker {
                    calls.lock().unwrap().push(customer);
                    if customer == 1 {
                        bail!("deletion failed");
                    }
                    assert_ne!(customer, 2, "worker panicked");
                }
                if stage == Stage::PersistTerminal && customer == 3 {
                    bail!("terminal persistence failed");
                }
                Ok(())
            }),
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(recover_and_start(&test_store.store, &manager).await, []);
        wait_for_recovery(&manager).await;
        manager.shutdown_and_wait().await;
        assert_eq!(*order.lock().unwrap(), [1, 2, 3, 4]);
        for (customer_id, status) in [
            (1, CustomerDataDeletionStatus::Failed),
            (2, CustomerDataDeletionStatus::Failed),
            (3, CustomerDataDeletionStatus::InProgress),
            (4, CustomerDataDeletionStatus::Succeeded),
        ] {
            let result = job(&test_store.store, customer_id)
                .service_results
                .remove(0);
            assert_eq!(result.status, status);
            assert_eq!(result.requested_at, 123);
            assert_eq!(result.completed_at.is_none(), customer_id == 3);
        }
    }

    #[tokio::test]
    async fn shutdown_waits_for_active_supervisor_and_blocks_requests() {
        let manager = CustomerDataDeletionTaskManager::default();
        let completed = Arc::new(AtomicBool::new(false));
        let task_completed = Arc::clone(&completed);
        let (release, wait) = tokio::sync::oneshot::channel();
        let supervisor = tokio::spawn(async move {
            wait.await.unwrap();
            task_completed.store(true, Ordering::SeqCst);
        });
        manager.state.lock().await.active = Some((11, supervisor));
        let shutdown = manager.shutdown_and_wait();
        tokio::pin!(shutdown);
        assert!(futures::poll!(&mut shutdown).is_pending());
        assert!(!completed.load(Ordering::SeqCst));
        release.send(()).unwrap();
        shutdown.await;
        assert!(completed.load(Ordering::SeqCst));
        let state = manager.state.lock().await;
        assert!(state.shutting_down);
        assert!(state.active.is_none());
    }

    #[tokio::test]
    async fn shutdown_finishes_current_recovery_and_leaves_queued_jobs_pending() {
        let test_store = TestStore::new();
        for customer_id in [1, 2] {
            put_job(
                &test_store.store,
                customer_id,
                vec![pending_result(
                    CustomerDataDeletionService::Review,
                    &[&format!("{customer_id}.example")],
                )],
            );
        }
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let (release, releases) = std::sync::mpsc::channel();
        let releases = std::sync::Mutex::new(releases);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, customer| {
                if stage == Stage::Worker {
                    started.send(customer).unwrap();
                    releases.lock().unwrap().recv().unwrap();
                }
                Ok(())
            }),
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        recover_and_start(&test_store.store, &manager).await;
        assert_eq!(starts.recv().await, Some(1));
        let shutdown = manager.shutdown_and_wait();
        tokio::pin!(shutdown);
        assert!(futures::poll!(&mut shutdown).is_pending());
        assert!(manager.state.lock().await.shutting_down);
        release.send(()).unwrap();
        shutdown.await;
        assert!(starts.try_recv().is_err());
        assert_eq!(
            job(&test_store.store, 1)
                .service_results
                .first()
                .unwrap()
                .status,
            CustomerDataDeletionStatus::Succeeded
        );
        assert_eq!(
            job(&test_store.store, 2).service_results.first().unwrap(),
            &pending_result(CustomerDataDeletionService::Review, &["2.example"])
        );
    }

    #[tokio::test]
    async fn shutdown_winning_the_mutex_prevents_request_registration() {
        let test_store = TestStore::new();
        put_active_node(&test_store, 1, "one.example");
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent = Arc::new(RecordingAgentManager::default());
        let shared: SharedAgentManager = agent.clone();
        let state = manager.state.lock().await;
        let shutdown = manager.shutdown_and_wait();
        tokio::pin!(shutdown);
        assert!(futures::poll!(&mut shutdown).is_pending());
        let deployer = deployer(&test_store);
        let request = request_deletion(1, &test_store.store, &shared, &deployer, &manager);
        tokio::pin!(request);
        assert!(futures::poll!(&mut request).is_pending());
        drop(state);
        shutdown.await;
        assert_eq!(
            request.await.unwrap(),
            CustomerDataDeletionRequestStatus::BlockedByShutdown
        );
        assert!(manager.state.lock().await.active.is_none());
        assert!(agent.targets.lock().unwrap().is_empty());
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .customer_data_deletion_map()
                .get(1)
                .unwrap()
                .is_none()
        );
    }

    const DATA_STORE: &str = "001.giganto.ds.example";
    /// A Data Store no longer listed.
    const GONE: &str = "001.giganto.gone.example";

    fn sensor_agent() -> Agent {
        Agent::new(
            0,
            "001.piglet".to_string(),
            AgentKind::Sensor,
            AgentStatus::Enabled,
            None,
            None,
        )
        .unwrap()
    }

    /// Returns an agent of `kind` the Central Manager installed as instance
    /// `instance`.
    fn numbered_agent(kind: AgentKind, instance: u32) -> Agent {
        let package_id = kind.package_id().unwrap();
        let mut agent = Agent::new(
            0,
            format!("{instance:03}.{package_id}"),
            kind,
            AgentStatus::Enabled,
            None,
            None,
        )
        .unwrap();
        agent.instance = Some(instance);
        agent
    }

    fn sorted<T: Ord>(mut values: Vec<T>) -> Vec<T> {
        values.sort_unstable();
        values
    }

    /// Stores a node of `customer_id` on `hostname` running `agents`.
    fn put_customer_node(
        test_store: &TestStore,
        customer_id: u32,
        hostname: &str,
        agents: Vec<Agent>,
    ) -> u32 {
        read_store(&test_store.store)
            .unwrap()
            .node_map()
            .put(&Node {
                id: 0,
                name: hostname.to_string(),
                name_draft: None,
                profile: Some(NodeProfile {
                    customer_id,
                    description: String::new(),
                    hostname: hostname.to_string(),
                }),
                profile_draft: None,
                agents,
                external_services: Vec::new(),
                creation_time: Utc::now(),
            })
            .unwrap()
    }

    /// Stores a listed Data Store, installed, `RUNNING` and numbered
    /// `instance`, on a node of the platform's customer 0 on `hostname`.
    fn put_data_store(test_store: &TestStore, hostname: &str, instance: u32) {
        put_customer_data_store(test_store, 0, hostname, instance, Vec::new());
    }

    /// Stores a listed Data Store, installed, `RUNNING` and numbered
    /// `instance`, on a node of `customer_id` on `hostname` running `agents`.
    fn put_customer_data_store(
        test_store: &TestStore,
        customer_id: u32,
        hostname: &str,
        instance: u32,
        agents: Vec<Agent>,
    ) {
        let service = ExternalService {
            node_id: u32::MAX,
            key: format!("{instance:03}.giganto"),
            kind: ExternalServiceKind::DataStore,
            status: ExternalServiceStatus::Enabled,
            draft: None,
            installed_version: Some("1.0.0".to_string()),
            installed_commit: Some("abcdef".to_string()),
            lifecycle: review_database::Lifecycle::Running,
            bound_addrs: Vec::new(),
            instance: Some(instance),
        };
        read_store(&test_store.store)
            .unwrap()
            .node_map()
            .put(&Node {
                id: 0,
                name: hostname.to_string(),
                name_draft: None,
                profile: Some(NodeProfile {
                    customer_id,
                    description: String::new(),
                    hostname: hostname.to_string(),
                }),
                profile_draft: None,
                agents,
                external_services: vec![service],
                creation_time: Utc::now(),
            })
            .unwrap();
    }

    /// Awaits the registered supervisor, which a test with paused time cannot
    /// poll for without stopping its clock.
    async fn finish_supervisor(manager: &CustomerDataDeletionTaskManager) {
        let supervisor = manager.state.lock().await.active.take();
        supervisor
            .expect("a supervisor is registered")
            .1
            .await
            .unwrap();
    }

    fn services(job: &CustomerDataDeletionJob) -> Vec<CustomerDataDeletionService> {
        job.service_results
            .iter()
            .map(|result| result.service)
            .collect()
    }

    fn service_of<'a>(
        job: &'a CustomerDataDeletionJob,
        service: CustomerDataDeletionService,
        host: &str,
    ) -> Option<&'a CustomerDataDeletionServiceResult> {
        job.service_results.iter().find(|result| {
            result.service == service && result.host_fqdns.first().map(String::as_str) == Some(host)
        })
    }

    fn data_store_result(
        job: &CustomerDataDeletionJob,
        server_name: &str,
    ) -> CustomerDataDeletionServiceResult {
        service_of(job, CustomerDataDeletionService::DataStore, server_name)
            .unwrap_or_else(|| panic!("no Data Store result for {server_name}: {job:?}"))
            .clone()
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::too_many_lines)]
    async fn data_store_step_sends_the_customers_names_and_ids_after_the_dispatch() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(&test_store, 7, "a.example", vec![sensor_agent()]);
        put_customer_node(&test_store, 7, "b.example", Vec::new());
        let (first, second, other) = {
            let store = read_store(&test_store.store).unwrap();
            (
                put_policy(&store, "first", 7, "piglet.a.example"),
                put_policy(&store, "second", 7, "piglet.b.example"),
                put_policy(&store, "other", 8, "piglet.c.example"),
            )
        };
        put_data_store(&test_store, "ds2.example", 2);
        put_data_store(&test_store, "ds1.example", 1);
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let shared: SharedAgentManager = agent.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());

        assert_eq!(
            request_deletion(
                7,
                &test_store.store,
                &shared,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::Accepted
        );
        let ids = vec![first.to_string(), second.to_string()];
        let initial = job(&test_store.store, 7);
        assert_eq!(initial.periodic_time_series_ids, ids);
        assert!(
            !initial
                .periodic_time_series_ids
                .contains(&other.to_string())
        );
        assert_eq!(
            services(&initial),
            [
                CustomerDataDeletionService::Review,
                CustomerDataDeletionService::Sensor,
                CustomerDataDeletionService::ModuleRemoval,
                CustomerDataDeletionService::ModuleRemoval
            ]
        );
        finish_supervisor(&manager).await;

        assert_eq!(
            *agent.log.lock().unwrap(),
            [
                "dispatch",
                "send 001.giganto.ds1.example",
                "send 002.giganto.ds2.example"
            ]
        );
        {
            let sent = agent.sent.lock().unwrap();
            let names: Vec<_> = sent
                .iter()
                .map(|(target, _)| (target.hostname(), target.instance()))
                .collect();
            assert_eq!(names, [("ds1.example", 1), ("ds2.example", 2)]);
            for (target, _) in sent.iter() {
                assert_eq!(target.customer_id(), 7);
                assert_eq!(
                    target.service_fqdns(),
                    [
                        "piglet.a.example",
                        "piglet.b.example",
                        "reproduce.a.example",
                        "reproduce.b.example"
                    ]
                );
                assert_eq!(target.periodic_time_series_ids(), ids);
            }
        }
        // Each Data Store's result was recorded `InProgress` before it was sent to.
        for (at_send, server_name) in agent
            .jobs_at_send
            .lock()
            .unwrap()
            .iter()
            .zip(["001.giganto.ds1.example", "002.giganto.ds2.example"])
        {
            let result = data_store_result(at_send, server_name);
            assert_eq!(result.status, CustomerDataDeletionStatus::InProgress);
            assert_eq!(result.requested_at, CLOCK_START);
        }
        let done = job(&test_store.store, 7);
        assert_eq!(
            services(&done),
            [
                CustomerDataDeletionService::Review,
                CustomerDataDeletionService::Sensor,
                CustomerDataDeletionService::ModuleRemoval,
                CustomerDataDeletionService::ModuleRemoval,
                CustomerDataDeletionService::DataStore,
                CustomerDataDeletionService::DataStore
            ]
        );
        for server_name in ["001.giganto.ds1.example", "002.giganto.ds2.example"] {
            let result = data_store_result(&done, server_name);
            assert_eq!(result.host_fqdns, [server_name]);
            assert_eq!(result.status, CustomerDataDeletionStatus::Succeeded);
            assert_eq!(result.error, None);
        }
        assert_eq!(
            done.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Succeeded
        );
        let store = read_store(&test_store.store).unwrap();
        assert_eq!(customer_policies(&store, 7), Vec::<u32>::new());
        assert_eq!(customer_policies(&store, 8), [other]);
    }

    #[test]
    fn single_label_hosts_contribute_no_service_fqdn() {
        assert_eq!(
            data_store_service_fqdns(&[
                "node1".to_string(),
                "a.example".to_string(),
                "node1.".to_string()
            ]),
            ["piglet.a.example", "reproduce.a.example"]
        );
        assert_eq!(
            data_store_service_fqdns(&["node1".to_string()]),
            Vec::<String>::new()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_single_label_host_is_left_out_and_the_request_still_goes_out() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(&test_store, 7, "node1", vec![sensor_agent()]);
        put_customer_node(&test_store, 7, "a.example", Vec::new());
        put_data_store(&test_store, "ds.example", 1);
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let shared: SharedAgentManager = agent.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_deletion(
            7,
            &test_store.store,
            &shared,
            &deployer(&test_store),
            &manager,
        )
        .await
        .unwrap();
        finish_supervisor(&manager).await;
        let sent = agent.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent.first().unwrap().0.service_fqdns(),
            ["piglet.a.example", "reproduce.a.example"]
        );
        assert_eq!(
            data_store_result(&job(&test_store.store, 7), DATA_STORE).status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    #[tokio::test(start_paused = true)]
    async fn targets_name_every_host_and_id_and_none_without_either() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        // Neither a Sensor nor a Log Collector runs on these hosts.
        put_customer_node(&test_store, 7, "a.example", Vec::new());
        put_customer_node(&test_store, 7, "b.example", Vec::new());
        let ids = {
            let store = read_store(&test_store.store).unwrap();
            // A customer with a model only, and so no host and no ID.
            TestModel::new("model", 9).replace(&store);
            [
                put_policy(&store, "first", 7, "piglet.a.example"),
                put_policy(&store, "second", 7, "piglet.a.example"),
            ]
            .map(|id| id.to_string())
        };
        put_data_store(&test_store, "ds.example", 1);
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let shared: SharedAgentManager = agent.clone();
        for customer_id in [7, 9] {
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());
            assert_eq!(
                request_deletion(
                    customer_id,
                    &test_store.store,
                    &shared,
                    &deployer(&test_store),
                    &manager
                )
                .await
                .unwrap(),
                CustomerDataDeletionRequestStatus::Accepted
            );
            finish_supervisor(&manager).await;
        }
        let sent = agent.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let target = &sent.first().unwrap().0;
        assert_eq!(target.customer_id(), 7);
        assert_eq!(
            target.service_fqdns(),
            [
                "piglet.a.example",
                "piglet.b.example",
                "reproduce.a.example",
                "reproduce.b.example"
            ]
        );
        assert_eq!(target.periodic_time_series_ids(), ids);
        let without = job(&test_store.store, 9);
        assert_eq!(services(&without), [CustomerDataDeletionService::Review]);
        assert_eq!(
            without.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_customer_with_no_node_left_is_deleted_when_it_has_records() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let policy = {
            let store = read_store(&test_store.store).unwrap();
            TestModel::new("model", 5).replace(&store);
            put_policy(&store, "own", 5, "piglet.gone.example")
        };
        put_data_store(&test_store, "ds.example", 1);
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let shared: SharedAgentManager = agent.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_deletion(
                5,
                &test_store.store,
                &shared,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::Accepted
        );
        let initial = job(&test_store.store, 5);
        assert_eq!(services(&initial), [CustomerDataDeletionService::Review]);
        assert_eq!(
            initial.service_results.first().unwrap().host_fqdns,
            Vec::<String>::new()
        );
        finish_supervisor(&manager).await;

        assert!(agent.targets.lock().unwrap().is_empty());
        {
            let sent = agent.sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            let target = &sent.first().unwrap().0;
            assert_eq!(target.service_fqdns(), Vec::<String>::new());
            assert_eq!(target.periodic_time_series_ids(), [policy.to_string()]);
        }
        let done = job(&test_store.store, 5);
        assert_eq!(
            done.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Succeeded
        );
        assert_eq!(
            data_store_result(&done, DATA_STORE).status,
            CustomerDataDeletionStatus::Succeeded
        );
        {
            let store = read_store(&test_store.store).unwrap();
            assert_eq!(customer_models(&store, 5), Vec::<String>::new());
            assert_eq!(customer_policies(&store, 5), Vec::<u32>::new());
        }

        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_deletion(
                6,
                &test_store.store,
                &shared,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::NoTarget
        );
    }

    /// Deletes customer 7, with the node `a.example` and the Data Store
    /// `001.giganto.ds.example`, through `agent`, and returns the job.
    async fn delete_with_one_data_store(
        test_store: &TestStore,
        agent: &Arc<RecordingAgentManager>,
    ) -> CustomerDataDeletionJob {
        put_customer_node(test_store, 7, "a.example", Vec::new());
        put_data_store(test_store, "ds.example", 1);
        let shared: SharedAgentManager = agent.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_deletion(
                7,
                &test_store.store,
                &shared,
                &deployer(test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::Accepted
        );
        finish_supervisor(&manager).await;
        job(&test_store.store, 7)
    }

    fn gaps(times: &[tokio::time::Instant]) -> Vec<Duration> {
        times
            .windows(2)
            .map(|pair| *pair.last().unwrap() - *pair.first().unwrap())
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn an_accepted_request_is_read_every_30_seconds_until_it_succeeds() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let agent = Arc::new(
            RecordingAgentManager::with_store(&test_store.store)
                .answers([DataStoreRequestAnswer::Accepted])
                .reads([
                    Ok(Some(CustomerDataDeletionStatus::InProgress)),
                    Ok(Some(CustomerDataDeletionStatus::InProgress)),
                    Ok(Some(CustomerDataDeletionStatus::Succeeded)),
                ]),
        );
        let done = delete_with_one_data_store(&test_store, &agent).await;
        let result = data_store_result(&done, DATA_STORE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(result.requested_at, CLOCK_START);
        assert_eq!(result.completed_at, Some(CLOCK_START + 90 * 1_000_000_000));
        let sent_at = agent.sent.lock().unwrap().first().unwrap().1;
        let times: Vec<_> = std::iter::once(sent_at)
            .chain(agent.read_at.lock().unwrap().iter().map(|(_, at)| *at))
            .collect();
        assert_eq!(gaps(&times), [Duration::from_secs(30); 3]);
        assert_eq!(
            done.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_deletion_already_in_progress_is_waited_for() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let agent = Arc::new(
            RecordingAgentManager::with_store(&test_store.store)
                .answers([DataStoreRequestAnswer::InProgress])
                .reads([Ok(Some(CustomerDataDeletionStatus::InProgress))]),
        );
        let done = delete_with_one_data_store(&test_store, &agent).await;
        assert_eq!(
            data_store_result(&done, DATA_STORE).status,
            CustomerDataDeletionStatus::Succeeded
        );
        assert_eq!(agent.sent.lock().unwrap().len(), 1);
        assert_eq!(agent.read_at.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn finished_and_empty_answers_succeed_without_reading() {
        for answer in [
            DataStoreRequestAnswer::AlreadyCompleted,
            DataStoreRequestAnswer::NoLocalTarget,
        ] {
            let test_store = TestStore::new();
            let _clock = ClockGuard::install(&test_store);
            let agent =
                Arc::new(RecordingAgentManager::with_store(&test_store.store).answers([answer]));
            let done = delete_with_one_data_store(&test_store, &agent).await;
            assert_eq!(
                data_store_result(&done, DATA_STORE).status,
                CustomerDataDeletionStatus::Succeeded
            );
            assert!(agent.read_at.lock().unwrap().is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_blocked_request_is_sent_again_after_60_seconds() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let agent = Arc::new(
            RecordingAgentManager::with_store(&test_store.store).answers([
                DataStoreRequestAnswer::Blocked,
                DataStoreRequestAnswer::Blocked,
                DataStoreRequestAnswer::Accepted,
            ]),
        );
        let done = delete_with_one_data_store(&test_store, &agent).await;
        let times: Vec<_> = agent
            .sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, at)| *at)
            .collect();
        assert_eq!(gaps(&times), [Duration::from_secs(60); 2]);
        // While blocked, every job read showed the result `InProgress`, from
        // its first request.
        for at_send in agent.jobs_at_send.lock().unwrap().iter() {
            let result = data_store_result(at_send, DATA_STORE);
            assert_eq!(result.status, CustomerDataDeletionStatus::InProgress);
            assert_eq!(result.requested_at, CLOCK_START);
        }
        let result = data_store_result(&done, DATA_STORE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(result.requested_at, CLOCK_START);
    }

    #[tokio::test(start_paused = true)]
    async fn a_data_store_blocked_for_24_hours_fails_and_stops_the_deletion() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let agent = Arc::new(RecordingAgentManager {
            default_answer: Some(DataStoreRequestAnswer::Blocked),
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let done = delete_with_one_data_store(&test_store, &agent).await;
        assert_eq!(agent.sent.lock().unwrap().len(), 24 * 60);
        let result = data_store_result(&done, DATA_STORE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
        let error = format!("no result from {DATA_STORE} within 24 hours");
        assert_eq!(result.error.as_deref(), Some(error.as_str()));
        assert_eq!(
            result.completed_at,
            Some(CLOCK_START + DATA_STORE_RESULT_DEADLINE_NANOS)
        );
        let review = done.service_results.first().unwrap();
        assert_eq!(review.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(
            review.error,
            Some(format!("stopped before this part: {error}"))
        );
        let store = read_store(&test_store.store).unwrap();
        assert_eq!(
            store
                .node_map()
                .iter(Direction::Forward, None)
                .filter(|node| node
                    .as_ref()
                    .unwrap()
                    .profile
                    .as_ref()
                    .is_some_and(|profile| profile.customer_id == 7))
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ten_minutes_of_transport_errors_fail_the_data_store() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let agent = Arc::new(RecordingAgentManager {
            default_read: Some(Err("connection refused".to_string())),
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let done = delete_with_one_data_store(&test_store, &agent).await;
        // Reads 30 s apart, from 30 s to 630 s after the request.
        assert_eq!(agent.read_at.lock().unwrap().len(), 21);
        let result = data_store_result(&done, DATA_STORE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(
            result.error.as_deref(),
            Some(
                format!("no answer from {DATA_STORE} for 10 minutes: connection refused").as_str()
            )
        );
        assert_eq!(
            done.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Failed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_send_that_never_returns_fails_at_the_24_hour_deadline() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let agent = Arc::new(RecordingAgentManager {
            hang: Some(DataStoreCall::Send),
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let done = delete_with_one_data_store(&test_store, &agent).await;
        assert_eq!(agent.sent.lock().unwrap().len(), 1);
        let result = data_store_result(&done, DATA_STORE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
        let error = format!("no result from {DATA_STORE} within 24 hours");
        assert_eq!(result.error.as_deref(), Some(error.as_str()));
        assert_eq!(
            result.completed_at,
            Some(CLOCK_START + DATA_STORE_RESULT_DEADLINE_NANOS)
        );
        assert_eq!(
            done.service_results.first().unwrap().error,
            Some(format!("stopped before this part: {error}"))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_that_never_returns_counts_as_a_transport_error() {
        const SECOND: i64 = 1_000_000_000;
        let hung =
            format!("no answer from {DATA_STORE} for 10 minutes: the result query did not return");
        // Reads at 30 s, then 60 s and 90 s after the errors; the error
        // window opens with the first read that did not answer.
        for (errors, reads, failed_at) in [(0, 1, 630), (2, 3, 630)] {
            let test_store = TestStore::new();
            let _clock = ClockGuard::install(&test_store);
            let agent = Arc::new(
                RecordingAgentManager {
                    hang: Some(DataStoreCall::Read),
                    ..RecordingAgentManager::with_store(&test_store.store)
                }
                .reads((0..errors).map(|_| Err("connection refused".to_string()))),
            );
            let done = delete_with_one_data_store(&test_store, &agent).await;
            assert_eq!(agent.read_at.lock().unwrap().len(), reads);
            let result = data_store_result(&done, DATA_STORE);
            assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
            assert_eq!(result.error.as_deref(), Some(hung.as_str()));
            assert_eq!(result.completed_at, Some(CLOCK_START + failed_at * SECOND));
        }

        // A read hanging past the 24-hour deadline ends at the deadline.
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(&test_store, 7, "a.example", Vec::new());
        put_data_store(&test_store, "ds.example", 1);
        put_job(
            &test_store.store,
            7,
            vec![
                pending_result(CustomerDataDeletionService::Review, &["a.example"]),
                CustomerDataDeletionServiceResult {
                    requested_at: CLOCK_START - DATA_STORE_RESULT_DEADLINE_NANOS + 60 * SECOND,
                    ..pending_result(CustomerDataDeletionService::DataStore, &[DATA_STORE])
                },
            ],
        );
        let agent = Arc::new(RecordingAgentManager {
            hang: Some(DataStoreCall::Read),
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store))
            .unwrap()
            .start(deployer(&test_store), agent.clone(), Arc::clone(&manager))
            .await
            .unwrap();
        finish_supervisor(&manager).await;
        assert_eq!(agent.read_at.lock().unwrap().len(), 1);
        let result = data_store_result(&job(&test_store.store, 7), DATA_STORE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(
            result.error,
            Some(format!("no result from {DATA_STORE} within 24 hours"))
        );
        assert_eq!(result.completed_at, Some(CLOCK_START + 60 * SECOND));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_send_or_a_reported_failure_fails_the_data_store() {
        for (send_error, expected) in [
            (true, "refused".to_string()),
            (
                false,
                format!("{DATA_STORE} reported that the deletion failed"),
            ),
        ] {
            let test_store = TestStore::new();
            let _clock = ClockGuard::install(&test_store);
            let agent = RecordingAgentManager::with_store(&test_store.store)
                .reads([Ok(Some(CustomerDataDeletionStatus::Failed))]);
            if send_error {
                *agent.answers.lock().unwrap() = VecDeque::from([Err("refused".to_string())]);
            }
            let done = delete_with_one_data_store(&test_store, &Arc::new(agent)).await;
            let result = data_store_result(&done, DATA_STORE);
            assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
            assert_eq!(result.error.as_deref(), Some(expected.as_str()));
            assert_eq!(
                done.service_results.first().unwrap().error,
                Some(format!("stopped before this part: {expected}"))
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_crash_between_recording_and_sending_sends_once_on_resume() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(&test_store, 7, "a.example", Vec::new());
        put_data_store(&test_store, "ds.example", 1);
        let crashed = Arc::new(AtomicBool::new(false));
        let hook_crashed = Arc::clone(&crashed);
        let hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, _| {
                assert!(
                    stage != Stage::DataStoreRecorded || hook_crashed.swap(true, Ordering::SeqCst),
                    "simulated crash after recording the Data Store request"
                );
                Ok(())
            }),
        );
        let first = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let shared: SharedAgentManager = first.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_deletion(
            7,
            &test_store.store,
            &shared,
            &deployer(&test_store),
            &manager,
        )
        .await
        .unwrap();
        let supervisor = manager.state.lock().await.active.take().unwrap().1;
        assert!(supervisor.await.unwrap_err().is_panic());
        drop(hook);
        assert!(first.sent.lock().unwrap().is_empty());
        let crashed_job = job(&test_store.store, 7);
        let recorded = data_store_result(&crashed_job, DATA_STORE);
        assert_eq!(recorded.status, CustomerDataDeletionStatus::InProgress);

        // The Data Store never received the request, so it has no job.
        let second =
            Arc::new(RecordingAgentManager::with_store(&test_store.store).reads([Ok(None)]));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let recovered =
            recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store)).unwrap();
        assert_eq!(recovered.resumed_customer_ids(), [7]);
        recovered
            .start(deployer(&test_store), second.clone(), Arc::clone(&manager))
            .await
            .unwrap();
        finish_supervisor(&manager).await;
        assert_eq!(second.sent_server_names(), [DATA_STORE]);
        assert_eq!(second.read_at.lock().unwrap().len(), 2);
        let done = job(&test_store.store, 7);
        let result = data_store_result(&done, DATA_STORE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(result.requested_at, recorded.requested_at);
        assert_eq!(
            done.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_leaves_a_failed_data_store_failed_until_it_sends_again() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(&test_store, 7, "a.example", Vec::new());
        put_data_store(&test_store, "ds.example", 1);
        let review = terminal_result(
            CustomerDataDeletionService::Review,
            "a.example",
            CustomerDataDeletionStatus::Succeeded,
        );
        put_job(
            &test_store.store,
            7,
            vec![
                review.clone(),
                terminal_result(
                    CustomerDataDeletionService::DataStore,
                    DATA_STORE,
                    CustomerDataDeletionStatus::Failed,
                ),
            ],
        );
        let agent = Arc::new(
            RecordingAgentManager::with_store(&test_store.store)
                .reads([Ok(Some(CustomerDataDeletionStatus::InProgress))]),
        );
        let shared: SharedAgentManager = agent.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_deletion(
                7,
                &test_store.store,
                &shared,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::Accepted
        );
        let retried = data_store_result(&job(&test_store.store, 7), DATA_STORE);
        assert_eq!(retried.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(retried.error.as_deref(), Some("old failure"));
        finish_supervisor(&manager).await;

        let at_send = data_store_result(
            agent.jobs_at_send.lock().unwrap().first().unwrap(),
            DATA_STORE,
        );
        assert_eq!(at_send.status, CustomerDataDeletionStatus::InProgress);
        assert_eq!(at_send.requested_at, CLOCK_START);
        assert_eq!(at_send.error, None);
        assert_eq!(agent.sent.lock().unwrap().len(), 1);
        assert_eq!(agent.read_at.lock().unwrap().len(), 2);
        let done = job(&test_store.store, 7);
        assert_eq!(done.service_results.first().unwrap(), &review);
        assert_eq!(
            data_store_result(&done, DATA_STORE).status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_data_store_no_longer_listed_is_recorded_succeeded() {
        let test_store = TestStore::new();
        let clock = ClockGuard::install(&test_store);
        put_job(
            &test_store.store,
            7,
            vec![
                terminal_result(
                    CustomerDataDeletionService::Review,
                    "a.example",
                    CustomerDataDeletionStatus::Succeeded,
                ),
                terminal_result(
                    CustomerDataDeletionService::DataStore,
                    GONE,
                    CustomerDataDeletionStatus::Failed,
                ),
            ],
        );
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let shared: SharedAgentManager = agent.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_deletion(
            7,
            &test_store.store,
            &shared,
            &deployer(&test_store),
            &manager,
        )
        .await
        .unwrap();
        finish_supervisor(&manager).await;
        assert!(agent.sent.lock().unwrap().is_empty());
        let result = data_store_result(&job(&test_store.store, 7), GONE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(result.error.as_deref(), Some(DATA_STORE_NOT_REGISTERED));
        assert!(result.completed_at.is_some());
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_deletion(
                7,
                &test_store.store,
                &shared,
                &deployer(&test_store),
                &manager
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::AlreadyCompleted
        );

        // A result sent before a restart is settled the same way on resume.
        drop(clock);
        drop(test_store);
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_job(
            &test_store.store,
            7,
            vec![
                pending_result(CustomerDataDeletionService::Review, &["a.example"]),
                pending_result(CustomerDataDeletionService::DataStore, &[GONE]),
            ],
        );
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store))
            .unwrap()
            .start(deployer(&test_store), agent.clone(), Arc::clone(&manager))
            .await
            .unwrap();
        finish_supervisor(&manager).await;
        assert!(agent.sent.lock().unwrap().is_empty());
        assert!(agent.read_at.lock().unwrap().is_empty());
        let done = job(&test_store.store, 7);
        let result = data_store_result(&done, GONE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(result.error.as_deref(), Some(DATA_STORE_NOT_REGISTERED));
        assert_eq!(
            done.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_held_dispatch_holds_every_later_stage_until_its_report() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let node = put_customer_node(
            &test_store,
            7,
            "held.example",
            vec![
                numbered_agent(AgentKind::Sensor, 1),
                numbered_agent(AgentKind::SemiSupervised, 1),
            ],
        );
        put_data_store(&test_store, "ds.example", 1);
        let agent = Arc::new(RecordingAgentManager {
            hold_delivery: true,
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let shared: SharedAgentManager = agent.clone();
        let recording = Arc::new(RecordingDeployer::new(&test_store.store).logging_with(&agent));
        let deployer: SharedPackageDeployer = recording.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_deletion(7, &test_store.store, &shared, &deployer, &manager)
            .await
            .unwrap();

        // The closed gate keeps both targets `InProgress`: nothing is
        // removed, and no Data Store is asked.
        tokio::time::sleep(Duration::from_mins(50)).await;
        assert_eq!(*agent.log.lock().unwrap(), ["dispatch"]);
        assert_eq!(recording.removes(), Vec::<RemoveCall>::new());
        let held = job(&test_store.store, 7);
        assert!(
            held.service_results
                .iter()
                .all(|result| result.status == CustomerDataDeletionStatus::InProgress)
        );

        // The gate reopens and the agents report.
        for target in agent.targets.lock().unwrap().iter() {
            report_target(
                &test_store.store,
                target,
                CustomerDataDeletionStatus::Succeeded,
                None,
            );
        }
        finish_supervisor(&manager).await;
        assert_eq!(
            sorted(recording.removes()),
            sorted(vec![
                remove_call("held.example", "piglet", 1),
                remove_call("held.example", "hog", 1),
            ])
        );
        assert_eq!(
            *agent.log.lock().unwrap(),
            [
                "dispatch",
                "remove piglet 1 on held.example",
                "remove hog 1 on held.example",
                "send 001.giganto.ds.example"
            ]
        );
        let done = job(&test_store.store, 7);
        assert!(
            done.service_results
                .iter()
                .all(|result| result.status == CustomerDataDeletionStatus::Succeeded),
            "{done:?}"
        );
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .node_map()
                .get_by_id(node)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_resumes_waiting_and_sends_nothing_twice() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(&test_store, 7, "a.example", Vec::new());
        put_data_store(&test_store, "ds.example", 1);
        let sent = CustomerDataDeletionServiceResult {
            requested_at: CLOCK_START,
            ..pending_result(CustomerDataDeletionService::DataStore, &[DATA_STORE])
        };
        put_job(
            &test_store.store,
            7,
            vec![
                pending_result(CustomerDataDeletionService::Review, &["a.example"]),
                sent.clone(),
            ],
        );

        // Shutdown ends the wait and leaves both results for the next start.
        let first = Arc::new(RecordingAgentManager {
            default_read: Some(Ok(Some(CustomerDataDeletionStatus::InProgress))),
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let recovered =
            recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store)).unwrap();
        assert_eq!(recovered.remote_targets(), []);
        assert_eq!(recovered.resumed_customer_ids(), [7]);
        recovered
            .start(deployer(&test_store), first.clone(), Arc::clone(&manager))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(100)).await;
        manager.shutdown_and_wait().await;
        assert!(first.sent.lock().unwrap().is_empty());
        assert_eq!(first.read_at.lock().unwrap().len(), 4);
        let stopped = job(&test_store.store, 7);
        assert_eq!(data_store_result(&stopped, DATA_STORE), sent);
        assert_eq!(
            stopped.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::InProgress
        );

        let second = Arc::new(
            RecordingAgentManager::with_store(&test_store.store)
                .reads([Ok(Some(CustomerDataDeletionStatus::InProgress))]),
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store))
            .unwrap()
            .start(deployer(&test_store), second.clone(), Arc::clone(&manager))
            .await
            .unwrap();
        finish_supervisor(&manager).await;
        assert!(second.sent.lock().unwrap().is_empty());
        assert_eq!(second.read_at.lock().unwrap().len(), 2);
        let done = job(&test_store.store, 7);
        let result = data_store_result(&done, DATA_STORE);
        assert_eq!(result.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(result.requested_at, CLOCK_START);
        assert_eq!(
            done.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    /// Stores customer 7's job as a restart finds it after its Sensor
    /// reported a failure while `DATA_STORE` and the unlisted `GONE` were
    /// still being waited for, with a second Data Store listed and never
    /// sent to, and resumes it through `agent`.
    async fn resume_after_a_failed_sensor(
        test_store: &TestStore,
        agent: &Arc<RecordingAgentManager>,
    ) -> CustomerDataDeletionJob {
        put_customer_node(test_store, 7, "a.example", Vec::new());
        put_data_store(test_store, "ds.example", 1);
        put_data_store(test_store, "unsent.example", 1);
        let sensor = CustomerDataDeletionServiceResult {
            error: Some("sensor failed".to_string()),
            ..terminal_result(
                CustomerDataDeletionService::Sensor,
                "a.example",
                CustomerDataDeletionStatus::Failed,
            )
        };
        let sent = |server_name| CustomerDataDeletionServiceResult {
            requested_at: CLOCK_START,
            ..pending_result(CustomerDataDeletionService::DataStore, &[server_name])
        };
        put_job(
            &test_store.store,
            7,
            vec![
                pending_result(CustomerDataDeletionService::Review, &["a.example"]),
                sensor,
                sent(DATA_STORE),
                sent(GONE),
            ],
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let recovered =
            recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store)).unwrap();
        assert_eq!(recovered.remote_targets(), []);
        assert_eq!(recovered.resumed_customer_ids(), [7]);
        recovered
            .start(deployer(test_store), agent.clone(), Arc::clone(&manager))
            .await
            .unwrap();
        finish_supervisor(&manager).await;
        job(&test_store.store, 7)
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_after_a_failed_sensor_still_waits_for_sent_data_stores() {
        const STOPPED: &str = "stopped before this part: sensor failed";
        let test_store = TestStore::new();
        let clock = ClockGuard::install(&test_store);
        let agent = Arc::new(
            RecordingAgentManager::with_store(&test_store.store)
                .reads([Ok(Some(CustomerDataDeletionStatus::InProgress))]),
        );
        let done = resume_after_a_failed_sensor(&test_store, &agent).await;
        assert!(agent.sent.lock().unwrap().is_empty());
        let read: Vec<_> = agent
            .read_at
            .lock()
            .unwrap()
            .iter()
            .map(|(server_name, _)| server_name.clone())
            .collect();
        assert_eq!(read, [DATA_STORE, DATA_STORE]);
        assert_eq!(
            data_store_result(&done, DATA_STORE).status,
            CustomerDataDeletionStatus::Succeeded
        );
        let gone = data_store_result(&done, GONE);
        assert_eq!(gone.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(gone.error.as_deref(), Some(DATA_STORE_NOT_REGISTERED));
        assert!(
            service_of(
                &done,
                CustomerDataDeletionService::DataStore,
                "001.giganto.unsent.example"
            )
            .is_none()
        );
        let review = done.service_results.first().unwrap();
        assert_eq!(review.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(review.error.as_deref(), Some(STOPPED));
        assert!(
            done.service_results
                .iter()
                .all(|result| result.status != CustomerDataDeletionStatus::InProgress)
        );
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .node_map()
                .iter(Direction::Forward, None)
                .any(|node| node.unwrap().name == "a.example")
        );

        // A recorded request that never reached its Data Store is not sent.
        drop(clock);
        drop(test_store);
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let agent =
            Arc::new(RecordingAgentManager::with_store(&test_store.store).reads([Ok(None)]));
        let done = resume_after_a_failed_sensor(&test_store, &agent).await;
        assert!(agent.sent.lock().unwrap().is_empty());
        let unsent = data_store_result(&done, DATA_STORE);
        assert_eq!(unsent.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(unsent.error.as_deref(), Some(STOPPED));
        assert_eq!(
            done.service_results.first().unwrap().error.as_deref(),
            Some(STOPPED)
        );
    }

    #[tokio::test]
    async fn result_lists_data_store_results() {
        let test_store = TestStore::new();
        put_job(
            &test_store.store,
            7,
            vec![
                pending_result(CustomerDataDeletionService::Review, &[]),
                pending_result(CustomerDataDeletionService::DataStore, &[DATA_STORE]),
            ],
        );
        let data = result_query_data(&result_schema(&test_store)).await;
        let results = data
            .pointer("/customerDataDeletionResult/serviceResults")
            .unwrap();
        assert_eq!(results[0]["service"], "REVIEW");
        assert_eq!(results[0]["hostFqdns"], serde_json::json!([]));
        assert_eq!(results[1]["service"], "DATA_STORE");
        assert_eq!(results[1]["hostFqdns"], serde_json::json!([DATA_STORE]));
        assert_eq!(results[1]["status"], "IN_PROGRESS");
    }

    /// The server name of the Data Store customer 1's node holds in the
    /// in-use tests.
    const OWN_DATA_STORE: &str = "001.giganto.store.example";

    fn agent_naming(
        key: &str,
        kind: AgentKind,
        config: Option<String>,
        draft: Option<String>,
    ) -> Agent {
        Agent::new(
            0,
            key.to_string(),
            kind,
            AgentStatus::Enabled,
            config,
            draft,
        )
        .unwrap()
    }

    fn giganto_name(server_name: &str) -> String {
        format!("giganto_name = \"{server_name}\"\n")
    }

    fn engine_document(server_name: &str) -> String {
        format!(
            r#"[[detectors]]
id = 1
enabled = true
model = "m"
sources = ["piglet.other.example"]
period = "1m"
start = "2026-10-14T00:00:00Z"
batch_size = 100
[detectors.data_store]
address = "10.0.0.5:38371"
server_name = "{server_name}"
"#
        )
    }

    /// Requests the deletion of customer 1 and returns the response.
    async fn request_customer_1(
        test_store: &TestStore,
        manager: &Arc<CustomerDataDeletionTaskManager>,
    ) -> async_graphql::Response {
        test_schema(
            test_store,
            Arc::new(RecordingAgentManager::with_store(&test_store.store)),
            Arc::clone(manager),
        )
        .execute(admin_request(
            r#"mutation { deleteCustomerData(customerId: "1") }"#,
        ))
        .await
    }

    /// Returns the code and message of the single error of `response`.
    fn refusal(response: &async_graphql::Response) -> (String, String) {
        assert_eq!(response.errors.len(), 1, "{response:?}");
        let error = &response.errors[0];
        let code = error
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.get("code"))
            .map(ToString::to_string)
            .unwrap_or_default();
        (code, error.message.clone())
    }

    #[tokio::test]
    async fn a_data_store_others_use_refuses_the_request_before_anything_is_written() {
        let other_user = [
            (
                "applied",
                agent_naming(
                    "001.piglet",
                    AgentKind::Sensor,
                    Some(giganto_name(OWN_DATA_STORE)),
                    None,
                ),
                "the Sensor agent 001.piglet on other.example",
            ),
            (
                "draft",
                agent_naming(
                    "001.piglet",
                    AgentKind::Sensor,
                    None,
                    Some(giganto_name(OWN_DATA_STORE)),
                ),
                "the Sensor agent 001.piglet on other.example",
            ),
            (
                "engine",
                agent_naming(
                    "001.reconverge",
                    AgentKind::Unsupervised,
                    Some(engine_document(OWN_DATA_STORE)),
                    None,
                ),
                "the Unsupervised Engine agent 001.reconverge on other.example",
            ),
        ];
        for (case, agent, user) in other_user {
            let test_store = TestStore::new();
            put_customer_data_store(&test_store, 1, "store.example", 1, vec![sensor_agent()]);
            put_data_store(&test_store, "second.example", 1);
            put_customer_node(&test_store, 2, "other.example", vec![agent]);
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());

            let response = request_customer_1(&test_store, &manager).await;
            let (code, message) = refusal(&response);
            assert_eq!(code, "\"DATA_STORE_IN_USE\"", "{case}");
            assert_eq!(
                message,
                format!(
                    "Data Store {OWN_DATA_STORE} on store.example is used by {user}. Point them \
                     at another Data Store — another customer's agents in their own settings, \
                     the platform's system log collector with \
                     `setSystemLogCollectorDataStore` — then retry. Nothing has been deleted \
                     yet, so you may also move the node that holds the Data Store to another \
                     customer first."
                ),
                "{case}"
            );
            assert!(job_of(&test_store, 1).is_none(), "{case}");
            assert!(manager.state.lock().await.active.is_none(), "{case}");
        }
    }

    fn job_of(test_store: &TestStore, customer_id: u32) -> Option<CustomerDataDeletionJob> {
        read_store(&test_store.store)
            .unwrap()
            .customer_data_deletion_map()
            .get(customer_id)
            .unwrap()
    }

    #[tokio::test]
    async fn the_only_data_store_used_by_a_system_log_collector_needs_another_first() {
        let test_store = TestStore::new();
        put_customer_data_store(&test_store, 1, "store.example", 1, vec![sensor_agent()]);
        {
            let store = read_store(&test_store.store).unwrap();
            let collectors = store.system_log_collector_map();
            collectors
                .append_install_key("c.example", "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b", None)
                .unwrap();
            collectors
                .set_data_store("c.example", Some(OWN_DATA_STORE.to_string()))
                .unwrap();
        }
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());

        let response = request_customer_1(&test_store, &manager).await;
        let (code, message) = refusal(&response);
        assert_eq!(code, "\"DATA_STORE_IN_USE\"");
        assert!(
            message.starts_with(&format!(
                "Data Store {OWN_DATA_STORE} on store.example is used by the system log \
                 collector on c.example. "
            )),
            "{message}"
        );
        assert!(message.contains("move the node"), "{message}");
        assert!(
            message.ends_with(
                "It is the only Data Store installed, and each host's system log collector \
                 takes the first Data Store installed, so this customer can be deleted only \
                 after another Data Store is installed and the system log collectors are \
                 repointed to it with `setSystemLogCollectorDataStore`."
            ),
            "{message}"
        );
        assert!(job_of(&test_store, 1).is_none());
    }

    #[tokio::test]
    async fn the_customers_own_users_do_not_hold_its_data_store() {
        let test_store = TestStore::new();
        put_customer_data_store(
            &test_store,
            1,
            "store.example",
            1,
            vec![agent_naming(
                "001.piglet",
                AgentKind::Sensor,
                Some(giganto_name(OWN_DATA_STORE)),
                None,
            )],
        );
        put_customer_node(
            &test_store,
            1,
            "sensor.example",
            vec![agent_naming(
                "001.piglet",
                AgentKind::Sensor,
                Some(giganto_name(OWN_DATA_STORE)),
                Some(giganto_name(OWN_DATA_STORE)),
            )],
        );
        // Another customer's agent naming a Data Store not on the customer's
        // nodes holds nothing either.
        put_data_store(&test_store, "second.example", 1);
        put_customer_node(
            &test_store,
            2,
            "other.example",
            vec![agent_naming(
                "001.piglet",
                AgentKind::Sensor,
                Some(giganto_name("001.giganto.second.example")),
                None,
            )],
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());

        let response = request_customer_1(&test_store, &manager).await;
        assert!(response.errors.is_empty(), "{response:?}");
        assert_eq!(response.data.to_string(), "{deleteCustomerData: ACCEPTED}");
        manager.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn a_retry_is_refused_too_without_the_advice_to_move_the_node() {
        let test_store = TestStore::new();
        put_customer_data_store(&test_store, 1, "store.example", 1, vec![sensor_agent()]);
        put_data_store(&test_store, "second.example", 1);
        put_customer_node(
            &test_store,
            2,
            "other.example",
            vec![agent_naming(
                "001.piglet",
                AgentKind::Sensor,
                Some(giganto_name(OWN_DATA_STORE)),
                None,
            )],
        );
        put_job(
            &test_store.store,
            1,
            vec![
                terminal_result(
                    CustomerDataDeletionService::Review,
                    "store.example",
                    CustomerDataDeletionStatus::Failed,
                ),
                terminal_result(
                    CustomerDataDeletionService::Sensor,
                    "store.example",
                    CustomerDataDeletionStatus::Failed,
                ),
            ],
        );
        let before = job_of(&test_store, 1);
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());

        let response = request_customer_1(&test_store, &manager).await;
        let (code, message) = refusal(&response);
        assert_eq!(code, "\"DATA_STORE_IN_USE\"");
        assert!(message.ends_with("then retry."), "{message}");
        assert!(!message.contains("move the node"), "{message}");
        assert_eq!(job_of(&test_store, 1), before);
        assert!(manager.state.lock().await.active.is_none());
    }

    // The stages of K2b: the own files, the senders, the Data Store, the
    // customer's own Data Stores, and the Review stage.

    const A: &str = "a.example";
    const B: &str = "b.example";
    const C: &str = "c.example";
    const B_DATA_STORE: &str = "001.giganto.b.example";
    /// The longest a test waits for the deletion to reach a state, in
    /// seconds of paused time.
    const EVENTUALLY_LIMIT_SECS: u32 = 4 * 60 * 60;

    /// Stores customer 7's nodes: a Sensor, a Time Series Generator and an
    /// Unsupervised Engine on `a.example`, and a Data Store nothing else uses
    /// on `b.example`.
    fn put_stage_fixture(test_store: &TestStore) {
        put_customer_node(
            test_store,
            7,
            A,
            vec![
                numbered_agent(AgentKind::Sensor, 1),
                numbered_agent(AgentKind::TimeSeriesGenerator, 1),
                numbered_agent(AgentKind::Unsupervised, 1),
            ],
        );
        put_customer_data_store(test_store, 7, B, 1, Vec::new());
    }

    /// Requests the deletion of `customer_id` with `agent` and `deployer`.
    async fn request_with(
        test_store: &TestStore,
        customer_id: u32,
        agent: &Arc<RecordingAgentManager>,
        deployer: &Arc<RecordingDeployer>,
        manager: &Arc<CustomerDataDeletionTaskManager>,
    ) -> CustomerDataDeletionRequestStatus {
        let shared: SharedAgentManager = agent.clone();
        let deployer: SharedPackageDeployer = deployer.clone();
        request_deletion(customer_id, &test_store.store, &shared, &deployer, manager)
            .await
            .unwrap()
    }

    /// Lets paused time run, a second at a time, until `condition` holds.
    async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
        for _ in 0..EVENTUALLY_LIMIT_SECS {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!("{what} did not happen");
    }

    fn status_of(
        job: &CustomerDataDeletionJob,
        service: CustomerDataDeletionService,
        host: &str,
    ) -> CustomerDataDeletionStatus {
        service_of(job, service, host)
            .unwrap_or_else(|| panic!("no {service:?} result for {host}: {job:?}"))
            .status
    }

    fn error_of(
        job: &CustomerDataDeletionJob,
        service: CustomerDataDeletionService,
        host: &str,
    ) -> String {
        service_of(job, service, host)
            .and_then(|result| result.error.clone())
            .unwrap_or_else(|| panic!("no {service:?} error for {host}: {job:?}"))
    }

    fn review_of(job: &CustomerDataDeletionJob) -> &CustomerDataDeletionServiceResult {
        job.service_results
            .iter()
            .find(|result| result.service == CustomerDataDeletionService::Review)
            .unwrap()
    }

    fn in_progress(job: &CustomerDataDeletionJob) -> bool {
        job.service_results
            .iter()
            .any(|result| result.status == CustomerDataDeletionStatus::InProgress)
    }

    fn nodes_of(test_store: &TestStore, customer_id: u32) -> usize {
        read_store(&test_store.store)
            .unwrap()
            .node_map()
            .iter(Direction::Forward, None)
            .map(Result::unwrap)
            .filter(|node| {
                node.profile
                    .as_ref()
                    .is_some_and(|profile| profile.customer_id == customer_id)
            })
            .count()
    }

    fn live_on(
        test_store: &TestStore,
        host: &str,
        target: &str,
        instance: u32,
    ) -> Option<OperationAttempt> {
        read_store(&test_store.store)
            .unwrap()
            .operation_attempt_map()
            .live_attempt(host, target, Some(instance))
            .unwrap()
    }

    /// Requests another customer's deletion, which nothing blocks once no
    /// result of customer 7 is `InProgress`.
    async fn another_customer_is_accepted(test_store: &TestStore) {
        let policy = put_policy(&read_store(&test_store.store).unwrap(), "other", 9, "x");
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        assert_eq!(
            request_with(test_store, 9, &agent, &deployer, &manager).await,
            CustomerDataDeletionRequestStatus::Accepted
        );
        finish_supervisor(&manager).await;
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .sampling_policy_map()
                .get_by_id(policy)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::too_many_lines)]
    async fn the_stages_run_in_order() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_stage_fixture(&test_store);
        let other = put_customer_node(
            &test_store,
            8,
            "x.example",
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store).logging_with(&agent));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let at_review = Arc::new(std::sync::Mutex::new(None));
        let snapshot = Arc::clone(&at_review);
        let hook_store = Arc::clone(&test_store.store);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, customer_id| {
                if stage == Stage::Worker {
                    *snapshot.lock().unwrap() = read_store(&hook_store)?
                        .customer_data_deletion_map()
                        .get(customer_id)?;
                }
                Ok(())
            }),
        );

        assert_eq!(
            request_with(&test_store, 7, &agent, &deployer, &manager).await,
            CustomerDataDeletionRequestStatus::Accepted
        );
        finish_supervisor(&manager).await;

        // 1. the dispatch; 2. the senders on `a`; 3. the Data Store; 4. `b`'s
        // own Data Store.
        let log = agent.log.lock().unwrap().clone();
        assert_eq!(log.len(), 6, "{log:?}");
        assert_eq!(log[0], "dispatch");
        assert_eq!(
            sorted(log[1..4].to_vec()),
            sorted(vec![
                "remove piglet 1 on a.example".to_string(),
                "remove crusher 1 on a.example".to_string(),
                "remove reconverge 1 on a.example".to_string(),
            ])
        );
        assert_eq!(
            log[4..],
            [
                format!("send {B_DATA_STORE}"),
                "remove giganto 1 on b.example".to_string()
            ]
        );
        let at_remove = deployer.jobs_at_remove.lock().unwrap().clone();
        for job in &at_remove[..3] {
            assert_eq!(
                status_of(job, CustomerDataDeletionService::Sensor, A),
                CustomerDataDeletionStatus::Succeeded
            );
            assert!(!services(job).contains(&CustomerDataDeletionService::DataStore));
        }
        let at_send = agent.jobs_at_send.lock().unwrap()[0].clone();
        assert_eq!(
            status_of(&at_send, CustomerDataDeletionService::ModuleRemoval, A),
            CustomerDataDeletionStatus::Succeeded
        );
        assert_eq!(
            status_of(&at_send, CustomerDataDeletionService::ModuleRemoval, B),
            CustomerDataDeletionStatus::InProgress
        );
        let at_giganto = &at_remove[3];
        assert_eq!(
            data_store_result(at_giganto, B_DATA_STORE).status,
            CustomerDataDeletionStatus::Succeeded
        );
        assert_eq!(
            status_of(at_giganto, CustomerDataDeletionService::ModuleRemoval, B),
            CustomerDataDeletionStatus::InProgress
        );
        let at_review = at_review.lock().unwrap().clone().unwrap();
        assert_eq!(
            status_of(&at_review, CustomerDataDeletionService::ModuleRemoval, B),
            CustomerDataDeletionStatus::Succeeded
        );
        assert_eq!(
            review_of(&at_review).status,
            CustomerDataDeletionStatus::InProgress
        );

        let done = job(&test_store.store, 7);
        assert!(
            done.service_results
                .iter()
                .all(|result| result.status == CustomerDataDeletionStatus::Succeeded),
            "{done:?}"
        );
        assert_eq!(nodes_of(&test_store, 7), 0);
        // Another customer's nodes and rows are untouched.
        let (node, _, _) = read_store(&test_store.store)
            .unwrap()
            .node_map()
            .get_by_id(other)
            .unwrap()
            .unwrap();
        assert_eq!(node.agents.len(), 1);
        assert!(
            deployer
                .removes()
                .iter()
                .all(|(host, _, _)| host != "x.example")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_user_added_during_the_uninstall_stops_it_before_the_data_store() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_stage_fixture(&test_store);
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let mut deployer = RecordingDeployer::new(&test_store.store);
        let user_store = Arc::clone(&test_store.store);
        deployer.on_remove = std::sync::Mutex::new(Some(Box::new(move || {
            read_store(&user_store)
                .unwrap()
                .node_map()
                .put(&Node {
                    id: 0,
                    name: "other.example".to_string(),
                    name_draft: None,
                    profile: Some(NodeProfile {
                        customer_id: 2,
                        description: String::new(),
                        hostname: "other.example".to_string(),
                    }),
                    profile_draft: None,
                    agents: vec![agent_naming(
                        "001.piglet",
                        AgentKind::Sensor,
                        Some(giganto_name(B_DATA_STORE)),
                        None,
                    )],
                    external_services: Vec::new(),
                    creation_time: Utc::now(),
                })
                .unwrap();
        })));
        let deployer = Arc::new(deployer);
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        finish_supervisor(&manager).await;

        assert!(
            deployer
                .removes()
                .iter()
                .all(|(_, target, _)| target != "giganto")
        );
        let stopped = job(&test_store.store, 7);
        assert_eq!(
            data_store_result(&stopped, B_DATA_STORE).status,
            CustomerDataDeletionStatus::Succeeded
        );
        let error = error_of(&stopped, CustomerDataDeletionService::ModuleRemoval, B);
        assert!(
            error.starts_with(&format!(
                "stopped before this part: Data Store {B_DATA_STORE} on b.example is used by \
                 the Sensor agent 001.piglet on other.example."
            )),
            "{error}"
        );
        assert!(!error.contains("move the node"), "{error}");
        assert_eq!(review_of(&stopped).error.as_deref(), Some(error.as_str()));
        assert!(!in_progress(&stopped));
        assert_eq!(nodes_of(&test_store, 7), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_report_stops_before_any_uninstall_and_a_retry_sends_it_alone() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_stage_fixture(&test_store);
        put_customer_node(
            &test_store,
            7,
            C,
            vec![numbered_agent(AgentKind::SemiSupervised, 1)],
        );
        let agent = Arc::new(RecordingAgentManager {
            fail_reports: vec![format!("piglet.{A}")],
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        finish_supervisor(&manager).await;

        assert_eq!(deployer.removes(), Vec::<RemoveCall>::new());
        let stopped = job(&test_store.store, 7);
        let reason = "stopped before this part: the deletion failed on the host";
        for host in [A, B, C] {
            assert_eq!(
                error_of(&stopped, CustomerDataDeletionService::ModuleRemoval, host),
                reason
            );
        }
        assert_eq!(review_of(&stopped).error.as_deref(), Some(reason));
        assert!(!in_progress(&stopped));
        another_customer_is_accepted(&test_store).await;

        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_with(&test_store, 7, &agent, &deployer, &manager).await,
            CustomerDataDeletionRequestStatus::Accepted
        );
        finish_supervisor(&manager).await;
        assert_eq!(
            agent
                .targets
                .lock()
                .unwrap()
                .iter()
                .map(CustomerDataDeletionTarget::target_service_key)
                .collect::<Vec<_>>(),
            [format!("piglet.{A}")]
        );
        assert!(!in_progress(&job(&test_store.store, 7)));
        assert_eq!(nodes_of(&test_store, 7), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn every_report_is_waited_for_before_the_stop_is_recorded() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        put_customer_node(
            &test_store,
            7,
            C,
            vec![numbered_agent(AgentKind::SemiSupervised, 1)],
        );
        let agent = Arc::new(RecordingAgentManager {
            hold_delivery: true,
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        agent.delivery_started.notified().await;
        let targets = agent.targets.lock().unwrap().clone();
        let sensor = targets
            .iter()
            .find(|target| target.target_service_key().starts_with("piglet."))
            .unwrap();
        let semi = targets
            .iter()
            .find(|target| target.target_service_key().starts_with("hog."))
            .unwrap();
        report_target(
            &test_store.store,
            sensor,
            CustomerDataDeletionStatus::Failed,
            Some("piglet failed"),
        );

        tokio::time::sleep(Duration::from_mins(30)).await;
        let waiting = job(&test_store.store, 7);
        assert_eq!(
            review_of(&waiting).status,
            CustomerDataDeletionStatus::InProgress
        );
        assert_eq!(
            status_of(&waiting, CustomerDataDeletionService::ModuleRemoval, A),
            CustomerDataDeletionStatus::InProgress
        );

        report_target(
            &test_store.store,
            semi,
            CustomerDataDeletionStatus::Succeeded,
            None,
        );
        finish_supervisor(&manager).await;
        let stopped = job(&test_store.store, 7);
        assert_eq!(
            review_of(&stopped).error.as_deref(),
            Some("stopped before this part: piglet failed")
        );
        assert!(!in_progress(&stopped));
        assert_eq!(deployer.removes(), Vec::<RemoveCall>::new());
        another_customer_is_accepted(&test_store).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_live_update_is_waited_for_before_the_remove() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        let update = live_attempt("update-1", OperationAction::Update, A, "piglet", Some(1));
        write_attempt(&test_store.store, &update);
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;

        tokio::time::sleep(Duration::from_mins(20)).await;
        assert_eq!(deployer.removes(), Vec::<RemoveCall>::new());
        write_attempt(
            &test_store.store,
            &ended(
                update,
                OperationOutcome::Succeeded,
                OperationFailureKind::Other,
            ),
        );
        finish_supervisor(&manager).await;
        assert_eq!(deployer.removes(), [remove_call(A, "piglet", 1)]);
        assert!(!in_progress(&job(&test_store.store, 7)));
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::too_many_lines)]
    async fn a_failed_removal_stops_the_other_hosts_and_a_retry_removes_what_is_left() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        put_customer_node(
            &test_store,
            7,
            C,
            vec![
                numbered_agent(AgentKind::TimeSeriesGenerator, 1),
                numbered_agent(AgentKind::Unsupervised, 1),
            ],
        );
        put_data_store(&test_store, "ds.example", 1);
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(
            RecordingDeployer::new(&test_store.store)
                .answer(remove_call(A, "piglet", 1), [RemoveAnswer::Live])
                .answer(remove_call(C, "reconverge", 1), [RemoveAnswer::Hang]),
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        eventually("both hosts' removals", || deployer.removes().len() == 3).await;
        let removal = live_on(&test_store, A, "piglet", 1).unwrap();
        write_attempt(
            &test_store.store,
            &ended(
                removal,
                OperationOutcome::Failed,
                OperationFailureKind::ServiceFailed,
            ),
        );
        finish_supervisor(&manager).await;

        let stopped = job(&test_store.store, 7);
        let own = "removing piglet 1 on a.example failed: ServiceFailed";
        assert_eq!(
            error_of(&stopped, CustomerDataDeletionService::ModuleRemoval, A),
            own
        );
        assert_eq!(
            error_of(&stopped, CustomerDataDeletionService::ModuleRemoval, C),
            format!(
                "stopped while another host's removal failed: {own}; removed here so far: crusher 1"
            )
        );
        assert!(!services(&stopped).contains(&CustomerDataDeletionService::DataStore));
        assert!(agent.sent.lock().unwrap().is_empty());
        assert!(!in_progress(&stopped));

        // `c`'s apply goes on in review's own task.
        deployer.release.notify_one();
        eventually("the apply on c", || {
            live_on(&test_store, C, "reconverge", 1).is_none()
        })
        .await;
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_with(&test_store, 7, &agent, &deployer, &manager).await,
            CustomerDataDeletionRequestStatus::Accepted
        );
        finish_supervisor(&manager).await;
        assert_eq!(deployer.removes()[3..], [remove_call(A, "piglet", 1)]);
        assert!(!in_progress(&job(&test_store.store, 7)));
        assert_eq!(nodes_of(&test_store, 7), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_sensor_unreported_for_an_hour_fails() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        let agent = Arc::new(RecordingAgentManager {
            hold_delivery: true,
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;

        tokio::time::sleep(Duration::from_mins(59)).await;
        assert_eq!(
            status_of(
                &job(&test_store.store, 7),
                CustomerDataDeletionService::Sensor,
                A
            ),
            CustomerDataDeletionStatus::InProgress
        );
        finish_supervisor(&manager).await;
        let stopped = job(&test_store.store, 7);
        let sensor = service_of(&stopped, CustomerDataDeletionService::Sensor, A).unwrap();
        assert_eq!(
            sensor.error.as_deref(),
            Some("no deletion report from a.example within 1 hour")
        );
        assert!(sensor.completed_at.unwrap() >= CLOCK_START + REPORT_DEADLINE_NANOS);
        assert!(!in_progress(&stopped));
        assert_eq!(deployer.removes(), Vec::<RemoveCall>::new());
        another_customer_is_accepted(&test_store).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_report_after_the_hour_stays_and_is_not_sent_again() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        let agent = Arc::new(RecordingAgentManager {
            hold_delivery: true,
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        finish_supervisor(&manager).await;
        let target = agent.targets.lock().unwrap()[0].clone();
        report_target(
            &test_store.store,
            &target,
            CustomerDataDeletionStatus::Succeeded,
            None,
        );

        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        finish_supervisor(&manager).await;
        assert!(agent.targets.lock().unwrap().is_empty());
        let done = job(&test_store.store, 7);
        assert_eq!(
            status_of(&done, CustomerDataDeletionService::Sensor, A),
            CustomerDataDeletionStatus::Succeeded
        );
        assert!(!in_progress(&done));
        assert_eq!(nodes_of(&test_store, 7), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_report_written_during_the_timeout_write_wins() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        let agent = Arc::new(RecordingAgentManager {
            hold_delivery: true,
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let hook_store = Arc::clone(&test_store.store);
        let reported = Arc::new(AtomicBool::new(false));
        let reports = Arc::clone(&reported);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, customer_id| {
                if stage == Stage::ReportTimeout && !reports.swap(true, Ordering::SeqCst) {
                    let store = read_store(&hook_store)?;
                    let map = store.customer_data_deletion_map();
                    let mut result = map
                        .get(customer_id)?
                        .unwrap()
                        .service_results
                        .into_iter()
                        .find(|r| r.service == CustomerDataDeletionService::Sensor)
                        .unwrap();
                    result.status = CustomerDataDeletionStatus::Succeeded;
                    result.completed_at = Some(1);
                    map.update_service(customer_id, &result)?;
                }
                Ok(())
            }),
        );
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        finish_supervisor(&manager).await;

        assert!(reported.load(Ordering::SeqCst));
        let done = job(&test_store.store, 7);
        let sensor = service_of(&done, CustomerDataDeletionService::Sensor, A).unwrap();
        assert_eq!(sensor.status, CustomerDataDeletionStatus::Succeeded);
        assert_eq!(sensor.error, None);
        assert_eq!(deployer.removes(), [remove_call(A, "piglet", 1)]);
        assert!(!in_progress(&done));
    }

    /// Requests customer 7's deletion of a Sensor on `a.example`, whose
    /// removal `deployer` answers, and returns the job once the supervisor
    /// is done.
    async fn delete_sensor_with(
        test_store: &TestStore,
        deployer: RecordingDeployer,
    ) -> (CustomerDataDeletionJob, Arc<RecordingDeployer>) {
        put_customer_node(test_store, 7, A, vec![numbered_agent(AgentKind::Sensor, 1)]);
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(deployer);
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(test_store, 7, &agent, &deployer, &manager).await;
        finish_supervisor(&manager).await;
        (job(&test_store.store, 7), deployer)
    }

    #[tokio::test(start_paused = true)]
    async fn a_teardown_owed_for_an_hour_stops_the_deletion() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let deployer = RecordingDeployer::new(&test_store.store).answer(
            remove_call(A, "piglet", 1),
            std::iter::repeat_n(RemoveAnswer::CleanupPending, 1_000),
        );
        let (stopped, deployer) = delete_sensor_with(&test_store, deployer).await;
        assert_eq!(
            error_of(&stopped, CustomerDataDeletionService::ModuleRemoval, A),
            "removing piglet 1 on a.example: a teardown was still owed after 1 hour"
        );
        assert_eq!(deployer.removes().len(), 361);
        assert!(!in_progress(&stopped));
    }

    #[tokio::test(start_paused = true)]
    async fn maintenance_is_waited_out_for_an_hour() {
        {
            let test_store = TestStore::new();
            let _clock = ClockGuard::install(&test_store);
            let deployer = RecordingDeployer::new(&test_store.store).answer(
                remove_call(A, "piglet", 1),
                [
                    RemoveAnswer::UnderMaintenance,
                    RemoveAnswer::UnderMaintenance,
                ],
            );
            let (done, deployer) = delete_sensor_with(&test_store, deployer).await;
            assert_eq!(deployer.removes().len(), 3);
            assert!(
                done.service_results
                    .iter()
                    .all(|result| result.status == CustomerDataDeletionStatus::Succeeded)
            );
        }
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let deployer = RecordingDeployer::new(&test_store.store).answer(
            remove_call(A, "piglet", 1),
            std::iter::repeat_n(RemoveAnswer::UnderMaintenance, 1_000),
        );
        let (stopped, _) = delete_sensor_with(&test_store, deployer).await;
        let error = error_of(&stopped, CustomerDataDeletionService::ModuleRemoval, A);
        assert!(
            error.contains("REview stayed under maintenance for 1 hour"),
            "{error}"
        );
        assert_eq!(
            review_of(&stopped).status,
            CustomerDataDeletionStatus::Failed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_row_review_calls_a_system_instance_stops_the_deletion() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let deployer = RecordingDeployer::new(&test_store.store)
            .answer(remove_call(A, "piglet", 1), [RemoveAnswer::SystemInstance]);
        let (stopped, _) = delete_sensor_with(&test_store, deployer).await;
        assert_eq!(
            error_of(&stopped, CustomerDataDeletionService::ModuleRemoval, A),
            "removing piglet 1 on a.example: REview reports this row as the host's system log \
             collector; the records disagree"
        );
        assert!(!in_progress(&stopped));
        assert_eq!(nodes_of(&test_store, 7), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_install_is_waited_for_and_its_row_removed() {
        const COLLECTOR_KEY: &str = "0f6c5d9e-2b1a-4c3d-8e7f-a1b2c3d4e5f6";
        const INSTALL_KEY: &str = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d";
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        let install = live_attempt(INSTALL_KEY, OperationAction::Install, A, "crusher", Some(1));
        write_attempt(&test_store.store, &install);
        read_store(&test_store.store)
            .unwrap()
            .system_log_collector_map()
            .append_install_key(A, COLLECTOR_KEY, None)
            .unwrap();
        write_attempt(
            &test_store.store,
            &live_attempt(
                COLLECTOR_KEY,
                OperationAction::Install,
                A,
                "reproduce",
                Some(1),
            ),
        );
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store).logging_with(&agent));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;

        tokio::time::sleep(Duration::from_mins(20)).await;
        assert_eq!(
            status_of(
                &job(&test_store.store, 7),
                CustomerDataDeletionService::ModuleRemoval,
                A
            ),
            CustomerDataDeletionStatus::InProgress
        );
        // The install succeeds and adds its row.
        {
            let store = read_store(&test_store.store).unwrap();
            let node = store
                .node_map()
                .iter(Direction::Forward, None)
                .map(Result::unwrap)
                .find(|node| node.name == A)
                .unwrap();
            let old = review_database::NodeUpdate::from(node.clone());
            let mut new = review_database::NodeUpdate::from(node.clone());
            new.agents
                .push(numbered_agent(AgentKind::TimeSeriesGenerator, 1));
            store.node_map().update(node.id, &old, &new).unwrap();
        }
        write_attempt(
            &test_store.store,
            &ended(
                install,
                OperationOutcome::Succeeded,
                OperationFailureKind::Other,
            ),
        );
        finish_supervisor(&manager).await;

        assert!(deployer.removes().contains(&remove_call(A, "crusher", 1)));
        // The system log collector's install, still live, was not waited for.
        assert!(live_on(&test_store, A, "reproduce", 1).is_some());
        assert!(!in_progress(&job(&test_store.store, 7)));
        assert_eq!(nodes_of(&test_store, 7), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_customer_with_no_node_is_deleted_without_any_uninstall() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_policy(&read_store(&test_store.store).unwrap(), "only", 7, "x");
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        finish_supervisor(&manager).await;
        let done = job(&test_store.store, 7);
        assert_eq!(services(&done), [CustomerDataDeletionService::Review]);
        assert_eq!(
            review_of(&done).status,
            CustomerDataDeletionStatus::Succeeded
        );
        assert_eq!(deployer.removes(), Vec::<RemoveCall>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn a_row_registered_by_hand_is_removed_from_the_records_only() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        let node = put_active_node(&test_store, 7, A);
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        finish_supervisor(&manager).await;
        assert_eq!(deployer.removes(), Vec::<RemoveCall>::new());
        let store = read_store(&test_store.store).unwrap();
        assert!(store.node_map().get_by_id(node).unwrap().is_none());
        assert!(
            store
                .agents_map()
                .get(node, "001.piglet")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .external_service_map()
                .get(node, "001.giganto")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_review_stage_refuses_while_a_numbered_row_remains() {
        let test_store = TestStore::new();
        let node = put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        put_customer_network_data(&test_store, 7);
        put_job(
            &test_store.store,
            7,
            vec![pending_result(CustomerDataDeletionService::Review, &[A])],
        );
        let targets = restore_review_targets(&test_store.store, 7, &[A.to_string()]).unwrap();
        run_review_worker_and_persist(Arc::clone(&test_store.store), Arc::default(), 7, targets)
            .await;
        let failed = review_of(&job(&test_store.store, 7)).clone();
        assert_eq!(failed.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(
            failed.error.as_deref(),
            Some("the customer's nodes still hold installed modules: a.example piglet 1")
        );
        let store = read_store(&test_store.store).unwrap();
        assert!(store.node_map().get_by_id(node).unwrap().is_some());
        assert!(store.customer_networks_map().get(7).unwrap().is_some());
    }

    /// Stores customer 7's job as stage 2 left it before a restart: its
    /// Sensor reported, and each host's uninstall unfinished.
    fn put_job_in_stage_2(test_store: &TestStore) {
        let plan = collect_initial_plan(&test_store.store, 7).unwrap().unwrap();
        let mut stored = initial_job(&plan, CLOCK_START);
        for result in &mut stored.service_results {
            if result.service == CustomerDataDeletionService::Sensor {
                result.status = CustomerDataDeletionStatus::Succeeded;
                result.completed_at = Some(CLOCK_START);
            }
        }
        read_store(&test_store.store)
            .unwrap()
            .customer_data_deletion_map()
            .put(&stored)
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_in_stage_2_waits_for_the_live_removal() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_stage_fixture(&test_store);
        put_job_in_stage_2(&test_store);
        let removal = live_attempt(
            "remove-before",
            OperationAction::Remove,
            A,
            "piglet",
            Some(1),
        );
        write_attempt(&test_store.store, &removal);

        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store).logging_with(&agent));
        let recovered =
            recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store)).unwrap();
        assert_eq!(recovered.remote_targets().len(), 0);
        recovered
            .start(deployer.clone(), agent.clone(), Arc::clone(&manager))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_mins(10)).await;
        assert_eq!(deployer.removes(), Vec::<RemoveCall>::new());
        assert!(agent.sent.lock().unwrap().is_empty());

        // review finishes the removal, and its finalizer drops the row later.
        write_attempt(
            &test_store.store,
            &ended(
                removal,
                OperationOutcome::Succeeded,
                OperationFailureKind::Other,
            ),
        );
        tokio::time::sleep(Duration::from_mins(1)).await;
        assert!(agent.sent.lock().unwrap().is_empty());
        drop_row(&test_store.store, A, "piglet", 1);
        finish_supervisor(&manager).await;

        assert!(!deployer.removes().contains(&remove_call(A, "piglet", 1)));
        assert!(agent.dispatched_nothing());
        assert_eq!(agent.sent_server_names(), [B_DATA_STORE]);
        assert!(!in_progress(&job(&test_store.store, 7)));
        assert_eq!(nodes_of(&test_store, 7), 0);
    }

    /// Stores a job of customer 7 whose Sensor result on `a.example` was
    /// requested two hours before the mocked clock starts.
    fn put_job_with_old_sensor_request(test_store: &TestStore, review: CustomerDataDeletionStatus) {
        let requested_at = CLOCK_START - 2 * REPORT_DEADLINE_NANOS;
        let mut sensor = pending_result(CustomerDataDeletionService::Sensor, &[A]);
        sensor.requested_at = requested_at;
        let mut review = CustomerDataDeletionServiceResult {
            status: review,
            ..pending_result(CustomerDataDeletionService::Review, &[A])
        };
        let mut module_removal = pending_result(CustomerDataDeletionService::ModuleRemoval, &[A]);
        if review.status == CustomerDataDeletionStatus::Failed {
            review.completed_at = Some(requested_at);
            review.error = Some("old failure".to_string());
            module_removal.status = CustomerDataDeletionStatus::Failed;
            module_removal.completed_at = Some(requested_at);
            module_removal.error = Some("old failure".to_string());
        }
        put_job(&test_store.store, 7, vec![review, sensor, module_removal]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_resumed_wait_counts_its_hour_from_the_restart() {
        for reported in [true, false] {
            let test_store = TestStore::new();
            let _clock = ClockGuard::install(&test_store);
            put_customer_node(
                &test_store,
                7,
                A,
                vec![numbered_agent(AgentKind::Sensor, 1)],
            );
            put_job_with_old_sensor_request(&test_store, CustomerDataDeletionStatus::InProgress);
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());
            let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
            let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
            let mut recovered =
                recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store)).unwrap();
            let targets = recovered.take_remote_targets();
            assert_eq!(targets.len(), 1);
            recovered
                .start(deployer.clone(), agent.clone(), Arc::clone(&manager))
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_mins(59)).await;
            assert_eq!(
                status_of(
                    &job(&test_store.store, 7),
                    CustomerDataDeletionService::Sensor,
                    A
                ),
                CustomerDataDeletionStatus::InProgress
            );
            if reported {
                report_target(
                    &test_store.store,
                    &targets[0],
                    CustomerDataDeletionStatus::Succeeded,
                    None,
                );
            }
            finish_supervisor(&manager).await;
            assert!(agent.dispatched_nothing());
            let after = job(&test_store.store, 7);
            assert!(!in_progress(&after));
            if reported {
                assert_eq!(deployer.removes(), [remove_call(A, "piglet", 1)]);
                assert_eq!(
                    review_of(&after).status,
                    CustomerDataDeletionStatus::Succeeded
                );
            } else {
                let sensor = service_of(&after, CustomerDataDeletionService::Sensor, A).unwrap();
                assert_eq!(sensor.status, CustomerDataDeletionStatus::Failed);
                assert!(sensor.completed_at.unwrap() >= CLOCK_START + REPORT_DEADLINE_NANOS);
                assert_eq!(deployer.removes(), Vec::<RemoveCall>::new());
                another_customer_is_accepted(&test_store).await;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_stopped_job_resumes_only_to_end_its_reports() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        put_data_store(&test_store, "ds.example", 1);
        put_job_with_old_sensor_request(&test_store, CustomerDataDeletionStatus::Failed);
        let before = job(&test_store.store, 7);
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let recovered =
            recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store)).unwrap();
        assert_eq!(recovered.resumed_customer_ids(), [7]);
        recovered
            .start(deployer.clone(), agent.clone(), Arc::clone(&manager))
            .await
            .unwrap();
        finish_supervisor(&manager).await;

        let after = job(&test_store.store, 7);
        assert_eq!(
            error_of(&after, CustomerDataDeletionService::Sensor, A),
            "no deletion report from a.example within 1 hour"
        );
        assert_eq!(review_of(&after), review_of(&before));
        assert_eq!(
            service_of(&after, CustomerDataDeletionService::ModuleRemoval, A),
            service_of(&before, CustomerDataDeletionService::ModuleRemoval, A)
        );
        assert!(!in_progress(&after));
        assert_eq!(deployer.removes(), Vec::<RemoveCall>::new());
        assert!(agent.sent.lock().unwrap().is_empty());
        assert!(agent.dispatched_nothing());
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_in_stage_1_returns_at_once_and_records_nothing() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        let agent = Arc::new(RecordingAgentManager {
            hold_delivery: true,
            ..RecordingAgentManager::with_store(&test_store.store)
        });
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        tokio::time::sleep(Duration::from_mins(5)).await;
        let before = job(&test_store.store, 7);
        tokio::time::timeout(Duration::from_secs(15), manager.shutdown_and_wait())
            .await
            .unwrap();
        assert_eq!(job(&test_store.store, 7), before);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_in_stage_2_drops_the_remove_and_the_apply_goes_on() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(
            RecordingDeployer::new(&test_store.store)
                .answer(remove_call(A, "piglet", 1), [RemoveAnswer::Hang]),
        );
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        deployer.remove_started.notified().await;
        let before = job(&test_store.store, 7);
        tokio::time::timeout(Duration::from_secs(15), manager.shutdown_and_wait())
            .await
            .unwrap();
        assert_eq!(job(&test_store.store, 7), before);
        assert!(live_on(&test_store, A, "piglet", 1).is_some());
        deployer.release.notify_one();
        let apply = deployer.applies.lock().unwrap().pop().unwrap();
        apply.await.unwrap();
        assert!(live_on(&test_store, A, "piglet", 1).is_none());
        assert_eq!(nodes_of(&test_store, 7), 1);
        assert_eq!(job(&test_store.store, 7), before);
    }

    #[tokio::test]
    async fn shutdown_in_stage_5_waits_for_the_review_worker() {
        let test_store = TestStore::new();
        put_customer_node(&test_store, 7, A, Vec::new());
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let (release, releases) = std::sync::mpsc::channel();
        let releases = std::sync::Mutex::new(releases);
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, _| {
                if stage == Stage::Worker {
                    started.send(()).unwrap();
                    releases.lock().unwrap().recv().unwrap();
                }
                Ok(())
            }),
        );
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let deployer = Arc::new(RecordingDeployer::new(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        starts.recv().await.unwrap();
        let shutdown = manager.shutdown_and_wait();
        tokio::pin!(shutdown);
        assert!(futures::poll!(&mut shutdown).is_pending());
        release.send(()).unwrap();
        shutdown.await;
        assert_eq!(
            review_of(&job(&test_store.store, 7)).status,
            CustomerDataDeletionStatus::Succeeded
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_shutdown_signal_ends_a_waiting_supervisor_without_a_write() {
        for in_stage_2 in [false, true] {
            let test_store = TestStore::new();
            let _clock = ClockGuard::install(&test_store);
            put_customer_node(
                &test_store,
                7,
                A,
                vec![numbered_agent(AgentKind::Sensor, 1)],
            );
            let agent = Arc::new(RecordingAgentManager {
                hold_delivery: !in_stage_2,
                ..RecordingAgentManager::with_store(&test_store.store)
            });
            let deployer = Arc::new(
                RecordingDeployer::new(&test_store.store)
                    .answer(remove_call(A, "piglet", 1), [RemoveAnswer::Live]),
            );
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());
            request_with(&test_store, 7, &agent, &deployer, &manager).await;
            if in_stage_2 {
                deployer.remove_started.notified().await;
            }
            tokio::time::sleep(Duration::from_mins(2)).await;
            let before = job(&test_store.store, 7);

            manager.begin_shutdown().await;
            assert_eq!(
                request_with(&test_store, 8, &agent, &deployer, &manager).await,
                CustomerDataDeletionRequestStatus::BlockedByShutdown
            );
            let supervisor = manager.state.lock().await.active.take().unwrap().1;
            tokio::time::timeout(Duration::from_secs(15), supervisor)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(job(&test_store.store, 7), before, "stage 2: {in_stage_2}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_remove_failing_after_the_signal_records_nothing() {
        let test_store = TestStore::new();
        let _clock = ClockGuard::install(&test_store);
        put_customer_node(
            &test_store,
            7,
            A,
            vec![numbered_agent(AgentKind::Sensor, 1)],
        );
        let agent = Arc::new(RecordingAgentManager::with_store(&test_store.store));
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let mut deployer = RecordingDeployer::new(&test_store.store)
            .answer(remove_call(A, "piglet", 1), [RemoveAnswer::Other]);
        deployer.shut_down_on_remove = Some(Arc::clone(&manager));
        let deployer = Arc::new(deployer);
        request_with(&test_store, 7, &agent, &deployer, &manager).await;
        deployer.remove_started.notified().await;
        let before = job(&test_store.store, 7);
        tokio::time::timeout(Duration::from_secs(15), manager.shutdown_and_wait())
            .await
            .unwrap();
        let after = job(&test_store.store, 7);
        assert_eq!(after, before);
        assert_eq!(
            status_of(&after, CustomerDataDeletionService::ModuleRemoval, A),
            CustomerDataDeletionStatus::InProgress
        );
    }

    #[tokio::test]
    async fn a_completed_deletion_is_refused_while_new_records_exist() {
        let test_store = TestStore::new();
        put_job(
            &test_store.store,
            1,
            vec![
                terminal_result(
                    CustomerDataDeletionService::Review,
                    "one.example",
                    CustomerDataDeletionStatus::Succeeded,
                ),
                terminal_result(
                    CustomerDataDeletionService::DataStore,
                    "001.giganto.ds.example",
                    CustomerDataDeletionStatus::Succeeded,
                ),
            ],
        );
        let completed = job(&test_store.store, 1);
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let response = request_customer_1(&test_store, &manager).await;
        assert_eq!(
            response.data.to_string(),
            "{deleteCustomerData: ALREADY_COMPLETED}"
        );

        let node = put_customer_node(&test_store, 1, "new.example", Vec::new());
        put_policy(&read_store(&test_store.store).unwrap(), "new-1", 1, "x");
        put_policy(&read_store(&test_store.store).unwrap(), "new-2", 1, "y");
        let response = request_customer_1(&test_store, &manager).await;
        let (code, message) = refusal(&response);
        assert_eq!(code, "\"CUSTOMER_DATA_ALREADY_DELETED\"");
        assert_eq!(
            message,
            "the customer's data was deleted on 1970-01-01T00:00:00.000000456Z; it now holds \
             1 node, 2 sampling policies, created since; remove them, then retry"
        );
        assert_eq!(job(&test_store.store, 1), completed);
        assert!(manager.state.lock().await.active.is_none());

        {
            let store = read_store(&test_store.store).unwrap();
            store.node_map().remove(node).unwrap();
            store
                .sampling_policy_map()
                .remove_customer_policies(1)
                .unwrap();
        }
        let response = request_customer_1(&test_store, &manager).await;
        assert_eq!(
            response.data.to_string(),
            "{deleteCustomerData: ALREADY_COMPLETED}"
        );
    }

    #[tokio::test]
    async fn a_completed_review_only_deletion_is_refused_for_a_new_model() {
        let test_store = TestStore::new();
        put_job(
            &test_store.store,
            1,
            vec![terminal_result(
                CustomerDataDeletionService::Review,
                "one.example",
                CustomerDataDeletionStatus::Succeeded,
            )],
        );
        TestModel::new("model", 1).replace(&read_store(&test_store.store).unwrap());
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let response = request_customer_1(&test_store, &manager).await;
        let (code, message) = refusal(&response);
        assert_eq!(code, "\"CUSTOMER_DATA_ALREADY_DELETED\"");
        assert!(
            message.contains("it now holds 1 model, created since"),
            "{message}"
        );
        assert!(manager.state.lock().await.active.is_none());
    }
}
