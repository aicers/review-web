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

use crate::{
    backend::SharedAgentManager,
    graphql::{RoleGuard, agent_lookup_key_service_token},
};

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
        let task_manager = ctx.data::<Arc<CustomerDataDeletionTaskManager>>()?;
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        let agent_manager = ctx.data::<SharedAgentManager>()?;
        request_deletion(customer_id, store, agent_manager, task_manager)
            .await
            .map_err(|error| async_graphql::Error::new(format!("{error:#}")))
    }
}

async fn request_deletion(
    customer_id: u32,
    store: &Arc<RwLock<Store>>,
    agent_manager: &SharedAgentManager,
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

    let (blocked_by_another_deletion, existing) = {
        let store = read_store(store)?;
        #[cfg(test)]
        tests::checkpoint(&store, tests::Stage::ScanJobs, customer_id)?;
        let mut blocked_by_another_deletion = false;
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
                blocked_by_another_deletion = true;
            }
        }
        (blocked_by_another_deletion, existing)
    };
    if blocked_by_another_deletion {
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
        let plan = retry_plan(store, &job)?;
        for result in &mut job.service_results {
            if result.status == CustomerDataDeletionStatus::Failed {
                result.status = CustomerDataDeletionStatus::InProgress;
                result.requested_at = requested_at;
                result.completed_at = None;
                result.error = None;
            }
        }
        persist_request(store, &job, "persisting customer data deletion retry")?;
        plan
    } else {
        let Some(plan) = collect_initial_plan(store, customer_id)? else {
            return Ok(CustomerDataDeletionRequestStatus::NoTarget);
        };
        let job = initial_job(&plan, timestamp_nanos()?);
        persist_request(store, &job, "persisting initial customer data deletion job")?;
        plan
    };

    let supervisor = tokio::spawn(run_supervisor(
        Arc::clone(store),
        Arc::clone(agent_manager),
        plan,
    ));
    // There is deliberately no await between spawn and registration. The
    // task-manager mutex decides the ordering against shutdown.
    state.active = Some((customer_id, supervisor));
    Ok(CustomerDataDeletionRequestStatus::Accepted)
}

fn persist_request(
    store: &RwLock<Store>,
    job: &CustomerDataDeletionJob,
    context: &'static str,
) -> anyhow::Result<()> {
    let store = read_store(store)?;
    #[cfg(test)]
    tests::checkpoint(&store, tests::Stage::PersistRequest, job.customer_id)?;
    store.customer_data_deletion_map().put(job).context(context)
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
    for node in store.node_map().iter(Direction::Forward, None) {
        let node = node.context("collecting customer deletion nodes")?;
        let Some(profile) = node.profile.as_ref() else {
            continue;
        };
        if profile.customer_id != customer_id {
            continue;
        }
        let node_id = node.id;
        let Some((node, missing_agents, missing_external_services)) = store
            .node_map()
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
    let mut review_targets = None;
    let mut remote_targets = Vec::new();
    for result in job
        .service_results
        .iter()
        .filter(|result| result.status == selected_status)
    {
        let service = match result.service {
            CustomerDataDeletionService::Review => {
                if review_targets.is_none() {
                    review_targets = Some(restore_review_targets(
                        store,
                        job.customer_id,
                        &result.host_fqdns,
                    )?);
                }
                continue;
            }
            CustomerDataDeletionService::Sensor => "piglet",
            CustomerDataDeletionService::SemiSupervised => "hog",
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
        let error_message = format!(
            "Review deletion not started because remote deletion delivery failed: {delivery_error:#}"
        );
        if plan.review_targets.is_some()
            && let Err(persist_error) = persist_review_terminal(
                &store,
                plan.customer_id,
                CustomerDataDeletionStatus::Failed,
                Some(&error_message),
            )
        {
            error!(
                customer_id = plan.customer_id,
                "failed to persist Review deletion result: {persist_error:#}"
            );
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
        #[cfg(test)]
        tests::checkpoint(
            &*read_store(&worker_store)?,
            tests::Stage::Worker,
            customer_id,
        )?;
        delete_review_data(&worker_store, customer_id, &targets)
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

fn delete_review_data(
    store: &RwLock<Store>,
    customer_id: u32,
    targets: &ReviewDeletionTargets,
) -> anyhow::Result<()> {
    let store = read_store(store)?;
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
    for node_id in &targets.node_ids {
        #[cfg(test)]
        tests::checkpoint(&store, tests::Stage::Nodes, customer_id)?;
        if store.node_map().get_by_id(*node_id)?.is_none() {
            continue;
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
    Ok(())
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
    let completed_at = timestamp_nanos()?;
    let mut last_error = None;
    for _ in 0..2 {
        match persist_review_terminal_once(store, customer_id, status, completed_at, error_message)
        {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("two terminal persistence attempts always produce an error"))
}

fn persist_review_terminal_once(
    store: &RwLock<Store>,
    customer_id: u32,
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
    let mut review_result = job
        .service_results
        .into_iter()
        .find(|result| result.service == CustomerDataDeletionService::Review)
        .ok_or_else(|| anyhow!("customer deletion job {customer_id} has no Review result"))?;
    review_result.status = status;
    review_result.completed_at = Some(completed_at);
    review_result.error = error_message.map(str::to_owned);
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
    let mut plans = jobs
        .iter()
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
    let mut remote_targets = Vec::new();
    for plan in &mut plans {
        remote_targets.append(&mut plan.remote_targets);
    }
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use async_graphql::{EmptySubscription, Request, Schema};
    use async_trait::async_trait;
    use ipnet::IpNet;
    use review_database::{
        Agent, AgentStatus, EventCategory, ExternalService, ExternalServiceKind,
        ExternalServiceStatus, Node, NodeProfile,
        event::{DnsEventFields, Event, EventKind, EventMessage},
    };

    use super::*;
    use crate::backend::{AgentManager, ResourceUsage};
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
        delivery_gate: Option<Arc<tokio::sync::Semaphore>>,
        delivery_started: tokio::sync::Notify,
    }

    #[async_trait]
    impl AgentManager for RecordingAgentManager {
        async fn request_customer_data_deletion(
            &self,
            targets: &[CustomerDataDeletionTarget],
        ) -> anyhow::Result<()> {
            self.targets.lock().unwrap().extend_from_slice(targets);
            self.delivery_started.notify_one();
            if let Some(gate) = &self.delivery_gate {
                gate.acquire().await.unwrap().forget();
            }
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
        let status = request_deletion(42, &test_store.store, &shared_agent_manager, &task_manager)
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
        let agent_manager: SharedAgentManager = Arc::new(RecordingAgentManager::default());
        let status = request_deletion(
            1,
            &test_store.store,
            &agent_manager,
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
            request_deletion(1, &test_store.store, &agent_manager, &manager,)
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
            request_deletion(2, &test_store.store, &agent_manager, &manager)
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
            request_deletion(3, &test_store.store, &agent_manager, &manager,)
                .await
                .unwrap(),
            CustomerDataDeletionRequestStatus::DeletionInProgress
        );
        assert_eq!(
            request_deletion(4, &test_store.store, &agent_manager, &manager)
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
        let agent_manager: SharedAgentManager = Arc::new(RecordingAgentManager {
            targets: std::sync::Mutex::new(Vec::new()),
            fail_delivery: true,
            ..RecordingAgentManager::default()
        });
        let status = request_deletion(55, &test_store.store, &agent_manager, &manager)
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
            request_deletion(77, &test_store.store, &shared_agent_manager, &manager,)
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

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Stage {
        ScanJobs,
        CollectNodes,
        PersistRequest,
        Worker,
        Events,
        Hosts,
        TrafficFilters,
        Nodes,
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
            .put(&CustomerDataDeletionJob {
                customer_id,
                service_results: results,
            })
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
        assert_eq!(initial.service_results.len(), 5);
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
        failed
            .service_results
            .push(failed.service_results.last().unwrap().clone());
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
                ..RecordingAgentManager::default()
            });
            let shared: SharedAgentManager = agent.clone();
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());
            assert_eq!(
                request_deletion(customer_id, &test_store.store, &shared, &manager)
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
            // Shutdown must await the outer delivery supervisor, even though no
            // blocking worker exists yet.
            let shutdown = manager.shutdown_and_wait();
            tokio::pin!(shutdown);
            assert!(futures::poll!(&mut shutdown).is_pending());
            gate.add_permits(1);
            shutdown.await;
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
            assert!(
                after
                    .service_results
                    .iter()
                    .skip(1)
                    .all(|r| r.status == CustomerDataDeletionStatus::InProgress)
            );
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
            run_review_worker_and_persist(Arc::clone(&test_store.store), 1, targets).await;
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

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn deletion_stops_at_each_failed_boundary_and_retry_finishes() {
        const STAGES: [Stage; 4] = [
            Stage::Events,
            Stage::Hosts,
            Stage::TrafficFilters,
            Stage::Nodes,
        ];
        let test_store = TestStore::new();
        for (index, fail_stage) in STAGES.into_iter().enumerate() {
            let node = put_active_node(&test_store, 1, "one.example");
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
            run_review_worker_and_persist(Arc::clone(&test_store.store), 1, targets).await;
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
                assert!(store.node_map().get_by_id(node).unwrap().is_some());
                assert!(
                    store
                        .agents_map()
                        .get(node, "001.piglet")
                        .unwrap()
                        .is_some()
                );
                assert!(
                    store
                        .external_service_map()
                        .get(node, "001.giganto")
                        .unwrap()
                        .is_some()
                );
            }
            drop(hook);
            let manager = Arc::new(CustomerDataDeletionTaskManager::default());
            let agent = Arc::new(RecordingAgentManager::default());
            let shared: SharedAgentManager = agent.clone();
            assert_eq!(
                request_deletion(1, &test_store.store, &shared, &manager)
                    .await
                    .unwrap(),
                CustomerDataDeletionRequestStatus::Accepted
            );
            manager.shutdown_and_wait().await;
            assert_eq!(
                job(&test_store.store, 1)
                    .service_results
                    .first()
                    .unwrap()
                    .status,
                CustomerDataDeletionStatus::Succeeded
            );
            assert!(agent.targets.lock().unwrap().is_empty());
            let store = read_store(&test_store.store).unwrap();
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
            drop(store);
        }
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
                    request_deletion(customer_id, &test_store.store, &agent_manager, &manager,)
                        .await
                        .unwrap(),
                    CustomerDataDeletionRequestStatus::Accepted
                );
                manager.shutdown_and_wait().await;
            } else {
                assert!(
                    recover_customer_data_deletion_on_startup(
                        Arc::clone(&test_store.store),
                        Arc::clone(&manager),
                    )
                    .await
                    .unwrap()
                    .is_empty()
                );
                loop {
                    if manager
                        .state
                        .lock()
                        .await
                        .active
                        .as_ref()
                        .unwrap()
                        .1
                        .is_finished()
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                manager.shutdown_and_wait().await;
            }

            let store = read_store(&test_store.store).unwrap();
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
        assert!(
            recover_customer_data_deletion_on_startup(
                Arc::clone(&test_store.store),
                Arc::clone(&manager)
            )
            .await
            .unwrap()
            .is_empty()
        );
        // Keep the outer handle registered while waiting for it.
        loop {
            if manager
                .state
                .lock()
                .await
                .active
                .as_ref()
                .unwrap()
                .1
                .is_finished()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
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
        recover_customer_data_deletion_on_startup(
            Arc::clone(&test_store.store),
            Arc::clone(&manager),
        )
        .await
        .unwrap();
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
        let request = request_deletion(1, &test_store.store, &shared, &manager);
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

        let error = request_deletion(1, &test_store.store, &agent_manager, &manager)
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
        let error = request_deletion(2, &test_store.store, &agent_manager, &manager)
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
    #[allow(clippy::too_many_lines)]
    fn local_deletion_removes_exact_customer_data_and_is_idempotent() {
        let test_store = TestStore::new();
        let target_node = put_active_node(&test_store, 1, "one.example");
        let other_node = put_active_node(&test_store, 2, "other.example");
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

        delete_review_data(&test_store.store, 1, &targets).unwrap();
        delete_review_data(&test_store.store, 1, &targets).unwrap();

        let store = read_store(&test_store.store).unwrap();
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
}
