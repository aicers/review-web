//! Customer data deletion orchestration and startup recovery.
#![allow(clippy::unused_async_trait_impl)]

use std::sync::{Arc, RwLock};

use anyhow::{Context as _, anyhow, bail};
use async_graphql::{Context, Enum, ID, Object, Result as GraphqlResult};
use chrono::Utc;
use review_database::Role;
use review_database::{
    AgentKind, CustomerDataDeletionJob, CustomerDataDeletionService,
    CustomerDataDeletionServiceResult, CustomerDataDeletionStatus, Iterable, Store,
    event::Direction,
};
use tokio::{sync::Mutex, task::JoinHandle};
use tracing::error;

use crate::{backend::SharedAgentManager, graphql::RoleGuard};

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
}

#[derive(Default)]
struct CustomerDataDeletionTaskState {
    shutting_down: bool,
    active: Option<(u32, JoinHandle<()>)>,
}

impl CustomerDataDeletionTaskManager {
    /// Blocks new deletion requests and waits for the active supervisor.
    pub async fn shutdown_and_wait(&self) {
        let active = {
            let mut state = self.state.lock().await;
            state.shutting_down = true;
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
}

#[derive(Default)]
pub struct CustomerDataDeletionMutation;

#[Object]
impl CustomerDataDeletionMutation {
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
        let task_manager = Arc::clone(ctx.data::<Arc<CustomerDataDeletionTaskManager>>()?);
        let store = Arc::clone(ctx.data::<Arc<RwLock<Store>>>()?);
        let agent_manager = Arc::clone(ctx.data::<SharedAgentManager>()?);
        request_deletion(customer_id, store, agent_manager, &task_manager)
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))
    }
}

async fn request_deletion(
    customer_id: u32,
    store: Arc<RwLock<Store>>,
    agent_manager: SharedAgentManager,
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

    let (jobs, existing) = {
        let store = read_store(&store)?;
        let jobs = store
            .customer_data_deletion_map()
            .iter(Direction::Forward, None)
            .collect::<anyhow::Result<Vec<_>>>()
            .context("scanning customer data deletion jobs")?;
        let existing = jobs
            .iter()
            .find(|job| job.customer_id == customer_id)
            .cloned();
        (jobs, existing)
    };
    if jobs.iter().any(|job| {
        job.customer_id != customer_id
            && job
                .service_results
                .iter()
                .any(|result| result.status == CustomerDataDeletionStatus::InProgress)
    }) {
        return Ok(CustomerDataDeletionRequestStatus::BlockedByAnotherDeletion);
    }

    let plan = if let Some(mut job) = existing {
        if job
            .service_results
            .iter()
            .all(|result| result.status == CustomerDataDeletionStatus::Succeeded)
        {
            return Ok(CustomerDataDeletionRequestStatus::AlreadyCompleted);
        }
        if job
            .service_results
            .iter()
            .any(|result| result.status == CustomerDataDeletionStatus::InProgress)
        {
            return Ok(CustomerDataDeletionRequestStatus::DeletionInProgress);
        }
        let requested_at = timestamp_nanos()?;
        let plan = retry_plan(&store, &job)?;
        for result in &mut job.service_results {
            if result.status == CustomerDataDeletionStatus::Failed {
                result.status = CustomerDataDeletionStatus::InProgress;
                result.requested_at = requested_at;
                result.completed_at = None;
                result.error = None;
            }
        }
        read_store(&store)?
            .customer_data_deletion_map()
            .put(&job)
            .context("persisting customer data deletion retry")?;
        plan
    } else {
        let Some(plan) = collect_initial_plan(&store, customer_id)? else {
            return Ok(CustomerDataDeletionRequestStatus::NoTarget);
        };
        let job = initial_job(&plan, timestamp_nanos()?);
        read_store(&store)?
            .customer_data_deletion_map()
            .put(&job)
            .context("persisting initial customer data deletion job")?;
        plan
    };

    let supervisor = tokio::spawn(run_supervisor(store, agent_manager, plan));
    // There is deliberately no await between spawn and registration. The
    // task-manager mutex decides the ordering against shutdown.
    state.active = Some((customer_id, supervisor));
    Ok(CustomerDataDeletionRequestStatus::Accepted)
}

fn timestamp_nanos() -> anyhow::Result<i64> {
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

fn agent_has_service(key: &str, service: &str) -> bool {
    key.split('.').any(|segment| segment == service)
}

fn collect_initial_plan(
    store: &RwLock<Store>,
    customer_id: u32,
) -> anyhow::Result<Option<CustomerDataDeletionExecutionPlan>> {
    let store = read_store(store)?;
    let nodes = store
        .node_map()
        .iter(Direction::Forward, None)
        .collect::<anyhow::Result<Vec<_>>>()
        .context("collecting customer deletion nodes")?;
    let mut node_ids = Vec::new();
    let mut host_fqdns = Vec::new();
    let mut event_service_fqdns = Vec::new();
    let mut remote_targets = Vec::new();
    for node in nodes {
        let Some(profile) = node.profile.as_ref() else {
            continue;
        };
        if profile.customer_id != customer_id {
            continue;
        }
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
    if node_ids.is_empty() {
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
    }))
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
    CustomerDataDeletionJob {
        customer_id: plan.customer_id,
        service_results,
    }
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
    let selected: Vec<_> = job
        .service_results
        .iter()
        .filter(|result| result.status == selected_status)
        .collect();
    let review = selected
        .iter()
        .find(|result| result.service == CustomerDataDeletionService::Review);
    let review_targets = review
        .map(|result| restore_review_targets(store, job.customer_id, &result.host_fqdns))
        .transpose()?;
    let mut remote_targets = Vec::new();
    for result in selected {
        let service = match result.service {
            CustomerDataDeletionService::Sensor => Some("piglet"),
            CustomerDataDeletionService::SemiSupervised => Some("hog"),
            CustomerDataDeletionService::Review => None,
        };
        if let Some(service) = service {
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
    }
    remote_targets.sort_unstable_by(|a, b| a.target_service_key.cmp(&b.target_service_key));
    remote_targets.dedup_by(|a, b| a.target_service_key == b.target_service_key);
    Ok(CustomerDataDeletionExecutionPlan {
        customer_id: job.customer_id,
        review_targets,
        remote_targets,
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

async fn run_supervisor(
    store: Arc<RwLock<Store>>,
    agent_manager: SharedAgentManager,
    plan: CustomerDataDeletionExecutionPlan,
) {
    if !plan.remote_targets.is_empty()
        && let Err(delivery_error) = agent_manager
            .request_customer_data_deletion(&plan.remote_targets)
            .await
    {
        if plan.review_targets.is_some()
            && let Err(persist_error) = persist_review_terminal(
                &store,
                plan.customer_id,
                CustomerDataDeletionStatus::Failed,
                Some(format!(
                    "Review deletion not started because remote deletion delivery failed: {delivery_error}"
                )),
            )
        {
            error!(customer_id = plan.customer_id, %persist_error, "failed to persist Review deletion result");
        }
        return;
    }
    let Some(targets) = plan.review_targets else {
        return;
    };
    run_review_worker_and_persist(store, plan.customer_id, targets).await;
}

async fn run_review_worker_and_persist(
    store: Arc<RwLock<Store>>,
    customer_id: u32,
    targets: ReviewDeletionTargets,
) {
    let worker_store = Arc::clone(&store);
    let outcome = tokio::task::spawn_blocking(move || {
        delete_review_data(&worker_store, customer_id, &targets)
    })
    .await;
    let (status, error_message) = match outcome {
        Ok(Ok(())) => (CustomerDataDeletionStatus::Succeeded, None),
        Ok(Err(worker_error)) => (
            CustomerDataDeletionStatus::Failed,
            Some(worker_error.to_string()),
        ),
        Err(join_error) => (
            CustomerDataDeletionStatus::Failed,
            Some(format!(
                "Review deletion worker failed to join: {join_error}"
            )),
        ),
    };
    if let Err(persist_error) = persist_review_terminal(&store, customer_id, status, error_message)
    {
        error!(customer_id, %persist_error, "failed to persist Review deletion result");
    }
}

fn delete_review_data(
    store: &RwLock<Store>,
    customer_id: u32,
    targets: &ReviewDeletionTargets,
) -> anyhow::Result<()> {
    let store = read_store(store)?;
    store
        .events()
        .remove_by_sensors(&targets.event_service_fqdns)
        .context("deleting customer events")?;
    store
        .hosts_map()
        .remove_by_customer_id(customer_id)
        .with_context(|| format!("deleting hosts for customer {customer_id}"))?;
    for host_fqdn in &targets.host_fqdns {
        store
            .traffic_filter_map()
            .remove(host_fqdn)
            .with_context(|| format!("deleting traffic filter rules for {host_fqdn}"))?;
    }
    for node_id in &targets.node_ids {
        if store.node_map().get_by_id(*node_id)?.is_none() {
            continue;
        }
        let (_, invalid_agents, invalid_external_services) = store
            .node_map()
            .remove(*node_id)
            .with_context(|| format!("deleting node {node_id}"))?;
        if !invalid_agents.is_empty() || !invalid_external_services.is_empty() {
            bail!(
                "deleting connected records for node {node_id} failed (agents: {invalid_agents:?}, external services: {invalid_external_services:?})"
            );
        }
    }
    Ok(())
}

fn persist_review_terminal(
    store: &RwLock<Store>,
    customer_id: u32,
    status: CustomerDataDeletionStatus,
    error_message: Option<String>,
) -> anyhow::Result<()> {
    let store = read_store(store)?;
    let job = store
        .customer_data_deletion_map()
        .get(customer_id)?
        .ok_or_else(|| anyhow!("customer deletion job {customer_id} does not exist"))?;
    let mut review_result = job
        .service_results
        .into_iter()
        .find(|result| result.service == CustomerDataDeletionService::Review)
        .ok_or_else(|| anyhow!("customer deletion job {customer_id} has no Review result"))?;
    review_result.status = status;
    review_result.completed_at = Some(timestamp_nanos()?);
    review_result.error = error_message;
    store
        .customer_data_deletion_map()
        .update_service(customer_id, &review_result)
        .context("updating Review customer deletion result")
}

/// Restores every persisted in-progress customer deletion operation.
///
/// # Errors
///
/// Returns an error if the job table cannot be scanned, a persisted deletion
/// result is invalid, or a recovery supervisor is already active.
pub async fn recover_customer_data_deletion_on_startup(
    store: Arc<RwLock<Store>>,
    task_manager: Arc<CustomerDataDeletionTaskManager>,
) -> anyhow::Result<Vec<CustomerDataDeletionTarget>> {
    let jobs = read_store(&store)?
        .customer_data_deletion_map()
        .iter(Direction::Forward, None)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut plans = jobs
        .iter()
        .filter(|job| {
            job.service_results
                .iter()
                .any(|result| result.status == CustomerDataDeletionStatus::InProgress)
        })
        .map(|job| plan_from_results(&store, job, CustomerDataDeletionStatus::InProgress))
        .collect::<anyhow::Result<Vec<_>>>()?;
    plans.sort_unstable_by_key(|plan| plan.customer_id);
    if plans.len() > 1 {
        let customer_ids: Vec<_> = plans.iter().map(|plan| plan.customer_id).collect();
        error!(
            count = plans.len(),
            ?customer_ids,
            "multiple customer deletion jobs require startup recovery"
        );
    }
    let remote_targets = plans
        .iter()
        .flat_map(|plan| plan.remote_targets.iter().cloned())
        .collect();
    let review_plans: Vec<_> = plans
        .into_iter()
        .filter(|plan| plan.review_targets.is_some())
        .collect();
    let Some(first_customer_id) = review_plans.first().map(|plan| plan.customer_id) else {
        return Ok(remote_targets);
    };

    let mut state = task_manager.state.lock().await;
    if state.shutting_down {
        return Ok(remote_targets);
    }
    if state
        .active
        .as_ref()
        .is_some_and(|(_, handle)| !handle.is_finished())
    {
        bail!("a customer data deletion supervisor is already active");
    }
    _ = state.active.take();
    let supervisor_store = Arc::clone(&store);
    let supervisor_manager = Arc::clone(&task_manager);
    let supervisor = tokio::spawn(async move {
        for plan in review_plans {
            {
                let mut state = supervisor_manager.state.lock().await;
                if state.shutting_down {
                    break;
                }
                if let Some((active_customer_id, _)) = state.active.as_mut() {
                    *active_customer_id = plan.customer_id;
                }
            }
            if let Some(targets) = plan.review_targets {
                run_review_worker_and_persist(
                    Arc::clone(&supervisor_store),
                    plan.customer_id,
                    targets,
                )
                .await;
            }
        }
    });
    // Do not yield between creating and publishing the outer supervisor.
    state.active = Some((first_customer_id, supervisor));
    Ok(remote_targets)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use async_graphql::{EmptySubscription, Request, Schema};
    use async_trait::async_trait;
    use ipnet::IpNet;
    use review_database::{Agent, AgentStatus, Node, NodeProfile};

    use super::*;
    use crate::backend::{AgentManager, Process, ResourceUsage};
    use crate::graphql::{NetworksTargetAgentLookupKeysPair, SamplingPolicy};

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

    #[derive(Default)]
    struct RecordingAgentManager {
        targets: std::sync::Mutex<Vec<CustomerDataDeletionTarget>>,
        fail_delivery: bool,
    }

    #[async_trait]
    impl AgentManager for RecordingAgentManager {
        async fn request_customer_data_deletion(
            &self,
            targets: &[CustomerDataDeletionTarget],
        ) -> anyhow::Result<()> {
            self.targets.lock().unwrap().extend_from_slice(targets);
            if self.fail_delivery {
                bail!("delivery failed");
            }
            Ok(())
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

        async fn broadcast_crusher_sampling_policy(
            &self,
            _sampling_policies: &[SamplingPolicy],
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn capabilities(&self, _hostname: &str) -> anyhow::Result<BTreeSet<String>> {
            Ok(BTreeSet::new())
        }

        async fn get_process_list(&self, _hostname: &str) -> anyhow::Result<Vec<Process>> {
            Ok(Vec::new())
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

    fn test_schema(
        test_store: &TestStore,
        agent_manager: SharedAgentManager,
        task_manager: Arc<CustomerDataDeletionTaskManager>,
    ) -> Schema<TestQuery, CustomerDataDeletionMutation, EmptySubscription> {
        Schema::build(TestQuery, CustomerDataDeletionMutation, EmptySubscription)
            .data(Arc::clone(&test_store.store))
            .data(agent_manager)
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
            external_services: Vec::new(),
            creation_time: Utc::now(),
        };
        read_store(&test_store.store)
            .unwrap()
            .node_map()
            .put(&node)
            .unwrap()
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

    #[tokio::test]
    async fn shutdown_waits_for_active_supervisor_and_blocks_requests() {
        let manager = CustomerDataDeletionTaskManager::default();
        let completed = Arc::new(AtomicBool::new(false));
        let task_completed = Arc::clone(&completed);
        let supervisor = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            task_completed.store(true, Ordering::SeqCst);
        });
        manager.state.lock().await.active = Some((11, supervisor));
        manager.shutdown_and_wait().await;
        assert!(completed.load(Ordering::SeqCst));
        let state = manager.state.lock().await;
        assert!(state.shutting_down);
        assert!(state.active.is_none());
    }

    #[tokio::test]
    async fn mutation_rejects_non_admin_before_reading_state() {
        let test_store = TestStore::new();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        manager.state.lock().await.shutting_down = true;
        let schema = test_schema(
            &test_store,
            Arc::new(RecordingAgentManager::default()),
            manager,
        );
        let response = schema
            .execute(
                Request::new(r#"mutation { deleteCustomerData(customerId: "1") }"#)
                    .data(RoleGuard::Role(Role::SecurityAdministrator))
                    .data(SocketAddr::from(([127, 0, 0, 1], 1))),
            )
            .await;
        assert_eq!(response.errors.len(), 1);
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

    #[tokio::test]
    async fn initial_request_delivers_normalized_targets_and_deletes_local_data() {
        let test_store = TestStore::new();
        let node_id = put_active_node(&test_store, 42, "node.example");
        let agent_manager = Arc::new(RecordingAgentManager::default());
        let shared_agent_manager: SharedAgentManager = agent_manager.clone();
        let task_manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let status = request_deletion(
            42,
            Arc::clone(&test_store.store),
            shared_agent_manager,
            &task_manager,
        )
        .await
        .unwrap();
        assert_eq!(status, CustomerDataDeletionRequestStatus::Accepted);
        task_manager.shutdown_and_wait().await;

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
        assert!(
            job.service_results
                .iter()
                .filter(|result| result.service != CustomerDataDeletionService::Review)
                .all(|result| result.status == CustomerDataDeletionStatus::InProgress)
        );
    }

    #[tokio::test]
    async fn persisted_other_customer_in_progress_takes_precedence() {
        let test_store = TestStore::new();
        {
            let store = read_store(&test_store.store).unwrap();
            for customer_id in [1, 2] {
                store
                    .customer_data_deletion_map()
                    .put(&CustomerDataDeletionJob {
                        customer_id,
                        service_results: vec![pending_result(
                            CustomerDataDeletionService::Sensor,
                            &[if customer_id == 1 { "one" } else { "two" }],
                        )],
                    })
                    .unwrap();
            }
        }
        let status = request_deletion(
            1,
            Arc::clone(&test_store.store),
            Arc::new(RecordingAgentManager::default()),
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
    async fn startup_recovery_returns_remote_only_targets_without_supervisor() {
        let test_store = TestStore::new();
        read_store(&test_store.store)
            .unwrap()
            .customer_data_deletion_map()
            .put(&CustomerDataDeletionJob {
                customer_id: 9,
                service_results: vec![
                    CustomerDataDeletionServiceResult {
                        status: CustomerDataDeletionStatus::Succeeded,
                        completed_at: Some(456),
                        ..pending_result(CustomerDataDeletionService::Review, &["node.example"])
                    },
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
            })
            .unwrap();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let targets = recover_customer_data_deletion_on_startup(
            Arc::clone(&test_store.store),
            Arc::clone(&manager),
        )
        .await
        .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target_service_key(), "piglet.node.example");
        assert!(manager.state.lock().await.active.is_none());
    }

    #[tokio::test]
    async fn startup_recovery_with_no_pending_results_does_nothing() {
        let test_store = TestStore::new();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let targets = recover_customer_data_deletion_on_startup(
            Arc::clone(&test_store.store),
            Arc::clone(&manager),
        )
        .await
        .unwrap();
        assert!(targets.is_empty());
        assert!(manager.state.lock().await.active.is_none());
    }

    #[tokio::test]
    async fn startup_recovery_processes_multiple_customers_in_order() {
        let test_store = TestStore::new();
        {
            let store = read_store(&test_store.store).unwrap();
            for customer_id in [20, 10] {
                let hostname = format!("node-{customer_id}.example");
                store
                    .customer_data_deletion_map()
                    .put(&CustomerDataDeletionJob {
                        customer_id,
                        service_results: vec![
                            pending_result(CustomerDataDeletionService::Review, &[&hostname]),
                            pending_result(CustomerDataDeletionService::Sensor, &[&hostname]),
                        ],
                    })
                    .unwrap();
            }
        }
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let targets = recover_customer_data_deletion_on_startup(
            Arc::clone(&test_store.store),
            Arc::clone(&manager),
        )
        .await
        .unwrap();
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
        let store = read_store(&test_store.store).unwrap();
        for customer_id in [10, 20] {
            let job = store
                .customer_data_deletion_map()
                .get(customer_id)
                .unwrap()
                .unwrap();
            let review = job
                .service_results
                .iter()
                .find(|result| result.service == CustomerDataDeletionService::Review)
                .unwrap();
            assert_eq!(review.status, CustomerDataDeletionStatus::Succeeded);
        }
    }

    #[tokio::test]
    async fn completed_and_in_progress_jobs_return_without_starting_work() {
        let test_store = TestStore::new();
        {
            let store = read_store(&test_store.store).unwrap();
            store
                .customer_data_deletion_map()
                .put(&CustomerDataDeletionJob {
                    customer_id: 1,
                    service_results: vec![CustomerDataDeletionServiceResult {
                        status: CustomerDataDeletionStatus::Succeeded,
                        completed_at: Some(456),
                        ..pending_result(CustomerDataDeletionService::Review, &["one"])
                    }],
                })
                .unwrap();
        }
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent_manager: SharedAgentManager = Arc::new(RecordingAgentManager::default());
        assert_eq!(
            request_deletion(
                1,
                Arc::clone(&test_store.store),
                Arc::clone(&agent_manager),
                &manager,
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::AlreadyCompleted
        );
        {
            let store = read_store(&test_store.store).unwrap();
            store
                .customer_data_deletion_map()
                .put(&CustomerDataDeletionJob {
                    customer_id: 2,
                    service_results: vec![pending_result(
                        CustomerDataDeletionService::Sensor,
                        &["two"],
                    )],
                })
                .unwrap();
        }
        assert_eq!(
            request_deletion(2, Arc::clone(&test_store.store), agent_manager, &manager,)
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
                Arc::clone(&test_store.store),
                Arc::clone(&agent_manager),
                &manager,
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::DeletionInProgress
        );
        assert_eq!(
            request_deletion(4, Arc::clone(&test_store.store), agent_manager, &manager)
                .await
                .unwrap(),
            CustomerDataDeletionRequestStatus::BlockedByAnotherDeletion
        );
        release.notify_one();
        manager.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn remote_delivery_failure_keeps_nodes_and_fails_review() {
        let test_store = TestStore::new();
        let node_id = put_active_node(&test_store, 55, "failure.example");
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let status = request_deletion(
            55,
            Arc::clone(&test_store.store),
            Arc::new(RecordingAgentManager {
                targets: std::sync::Mutex::new(Vec::new()),
                fail_delivery: true,
            }),
            &manager,
        )
        .await
        .unwrap();
        assert_eq!(status, CustomerDataDeletionRequestStatus::Accepted);
        manager.shutdown_and_wait().await;
        let store = read_store(&test_store.store).unwrap();
        assert!(store.node_map().get_by_id(node_id).unwrap().is_some());
        let job = store.customer_data_deletion_map().get(55).unwrap().unwrap();
        let review = job
            .service_results
            .iter()
            .find(|result| result.service == CustomerDataDeletionService::Review)
            .unwrap();
        assert_eq!(review.status, CustomerDataDeletionStatus::Failed);
        assert!(
            review
                .error
                .as_deref()
                .is_some_and(|error| error.contains("delivery failed"))
        );
    }

    #[tokio::test]
    async fn retry_resets_and_runs_only_failed_results() {
        let test_store = TestStore::new();
        let original_review = CustomerDataDeletionServiceResult {
            status: CustomerDataDeletionStatus::Succeeded,
            completed_at: Some(456),
            ..pending_result(CustomerDataDeletionService::Review, &["retry.example"])
        };
        let failed_sensor = CustomerDataDeletionServiceResult {
            status: CustomerDataDeletionStatus::Failed,
            completed_at: Some(789),
            error: Some("old failure".to_string()),
            ..pending_result(CustomerDataDeletionService::Sensor, &["retry.example"])
        };
        read_store(&test_store.store)
            .unwrap()
            .customer_data_deletion_map()
            .put(&CustomerDataDeletionJob {
                customer_id: 77,
                service_results: vec![original_review.clone(), failed_sensor],
            })
            .unwrap();
        let agent_manager = Arc::new(RecordingAgentManager::default());
        let shared_agent_manager: SharedAgentManager = agent_manager.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_deletion(
                77,
                Arc::clone(&test_store.store),
                shared_agent_manager,
                &manager,
            )
            .await
            .unwrap(),
            CustomerDataDeletionRequestStatus::Accepted
        );
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
        let job = read_store(&test_store.store)
            .unwrap()
            .customer_data_deletion_map()
            .get(77)
            .unwrap()
            .unwrap();
        assert_eq!(job.service_results.first().unwrap(), &original_review);
        let retried = job.service_results.get(1).unwrap();
        assert_eq!(retried.status, CustomerDataDeletionStatus::InProgress);
        assert!(retried.requested_at > 123);
        assert_eq!(retried.completed_at, None);
        assert_eq!(retried.error, None);
    }
}
