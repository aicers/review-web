//! What a customer's data deletion refuses elsewhere, and what refuses it.
//!
//! From the first write of a customer's deletion job until every result of
//! it is `Succeeded`, also while the deletion is stopped, the writes that
//! would change what it works from are refused with
//! `CUSTOMER_DELETION_IN_PROGRESS`: those of the customer's nodes, services,
//! sampling policies, models and training definitions, and any node write
//! that takes a host name saved in the job. A retry rebuilds its targets from
//! those saved names, so a name another node took in the meantime would have
//! that node's data deleted.
//!
//! The check is a read before the resolver's write, not one transaction with
//! it. The deletion's own stages write through the store and the deployer,
//! never through these resolvers, so they are never refused.
//!
//! A deletion in turn is refused while a Data Store on one of the customer's
//! nodes, which the deletion removes with the node, is used by another
//! customer or by a host's system log collector; [`data_stores_in_use`]
//! finds those users.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, anyhow};
use async_graphql::{ErrorExtensions, Result};
use review_database::{
    AgentKind, CustomerDataDeletionJob, CustomerDataDeletionService, CustomerDataDeletionStatus,
    ExternalServiceKind, Iterable, Node, Store, event::Direction,
};

use super::{
    customer_access::derive_customer_id_from_hostname, engine_document::EngineDocument,
    node::listed_rows, sampling::giganto_name, training::TrainingDocument,
};
use crate::customer_data_deletion::data_store_server_name;

/// The `extensions.code` of a write refused while a customer's deletion is
/// unfinished.
const CUSTOMER_DELETION_IN_PROGRESS: &str = "CUSTOMER_DELETION_IN_PROGRESS";

/// Returns whether customer `customer_id` has a deletion job with a result
/// that is not `Succeeded`: one still running, or one stopped with a
/// `Failed` result a retry would resume.
///
/// Every job is judged this way, whichever results it holds.
///
/// # Errors
///
/// Returns an error if the job cannot be read.
pub(crate) fn customer_deletion_in_progress(
    store: &Store,
    customer_id: u32,
) -> anyhow::Result<bool> {
    Ok(store
        .customer_data_deletion_map()
        .get(customer_id)
        .with_context(|| format!("reading the deletion job of customer {customer_id}"))?
        .is_some_and(|job| unfinished(&job)))
}

fn unfinished(job: &CustomerDataDeletionJob) -> bool {
    job.service_results
        .iter()
        .any(|result| result.status != CustomerDataDeletionStatus::Succeeded)
}

fn in_progress(message: String) -> async_graphql::Error {
    async_graphql::Error::new(message)
        .extend_with(|_, extensions| extensions.set("code", CUSTOMER_DELETION_IN_PROGRESS))
}

/// Refuses a write of the customers `customer_ids` while any of them has an
/// unfinished deletion.
///
/// # Errors
///
/// Returns `CUSTOMER_DELETION_IN_PROGRESS` for the first such customer, and
/// an error if a job cannot be read.
pub(super) fn check_customers(
    store: &Store,
    customer_ids: impl IntoIterator<Item = u32>,
) -> Result<()> {
    for customer_id in customer_ids {
        if customer_deletion_in_progress(store, customer_id).map_err(|e| format!("{e:#}"))? {
            return Err(in_progress(format!(
                "the data of customer {customer_id} is being deleted; its nodes, services, \
                 sampling policies, models and training definitions cannot change until the \
                 deletion completes"
            )));
        }
    }
    Ok(())
}

/// Refuses a node write that gives a node one of `hostnames` while an
/// unfinished deletion job, of any customer, saved it as a host of its
/// Review result.
///
/// The refusal names neither the customer nor the job, since a caller scoped
/// to other customers can meet it.
///
/// # Errors
///
/// Returns `CUSTOMER_DELETION_IN_PROGRESS` for the first such host name, and
/// an error if a job cannot be read.
pub(super) fn check_hostnames<'a>(
    store: &Store,
    hostnames: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let hostnames: Vec<&str> = hostnames
        .into_iter()
        .filter(|hostname| !hostname.is_empty())
        .collect();
    if hostnames.is_empty() {
        return Ok(());
    }
    for job in store
        .customer_data_deletion_map()
        .iter(Direction::Forward, None)
    {
        let job = job.map_err(|e| format!("reading the customer deletion jobs: {e:#}"))?;
        if !unfinished(&job) {
            continue;
        }
        for result in job
            .service_results
            .iter()
            .filter(|result| result.service == CustomerDataDeletionService::Review)
        {
            if let Some(hostname) = hostnames
                .iter()
                .find(|hostname| result.host_fqdns.iter().any(|saved| saved == *hostname))
            {
                return Err(in_progress(format!(
                    "host name {hostname} is held by a customer data deletion that has not \
                     completed; choose another host name"
                )));
            }
        }
    }
    Ok(())
}

/// Refuses a write of a node of the customers `customer_ids`, or one giving
/// a node one of `hostnames`, while a deletion holds either.
///
/// # Errors
///
/// Returns `CUSTOMER_DELETION_IN_PROGRESS` as [`check_customers`] and
/// [`check_hostnames`] do.
pub(super) fn check_node_write<'a>(
    store: &Store,
    customer_ids: impl IntoIterator<Item = u32>,
    hostnames: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    check_customers(store, customer_ids)?;
    check_hostnames(store, hostnames)
}

/// Refuses a service write on `host` while the customer of the node whose
/// applied hostname it is has an unfinished deletion.
///
/// # Errors
///
/// Returns `CUSTOMER_DELETION_IN_PROGRESS` as [`check_customers`] does, and
/// an error if the nodes or a job cannot be read.
pub(super) fn check_host(store: &Store, host: &str) -> Result<()> {
    check_customers(store, derive_customer_id_from_hostname(store, host)?)
}

/// A Data Store on one of a customer's nodes, and who else uses it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DataStoreInUse {
    /// The Data Store's server name, `<instance:03>.giganto.<hostname>`.
    pub(crate) server_name: String,
    /// The hostname of the Data Store's node.
    pub(crate) hostname: String,
    /// Each user, named by kind, name, and host or customer, sorted.
    pub(crate) users: Vec<String>,
}

/// The Data Stores a customer's deletion would remove that others use.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DataStoresInUse {
    /// Each such Data Store, by server name.
    pub(crate) data_stores: Vec<DataStoreInUse>,
    /// Whether the Central Manager lists exactly one Data Store and it is one
    /// of these, which each host's system log collector then takes, being the
    /// first installed.
    pub(crate) only_data_store: bool,
}

impl DataStoresInUse {
    /// Returns whether no Data Store of the customer is used by others.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.data_stores.is_empty()
    }
}

/// Returns the Data Stores on the nodes of customer `customer_id` that others
/// use, with their users.
///
/// A Data Store counts when it is a `DATA_STORE` row with an instance number
/// on a node whose applied profile is the customer's, installed or not. Its
/// users are:
///
/// - an agent on a node that is not the customer's, or has no applied
///   profile, whose configuration or draft names it as its top-level
///   `giganto_name`, or, for an Unsupervised Engine agent, as the Data Store
///   of a detector;
/// - a training definition of another customer whose `[data_store]` names
///   it;
/// - a system log collector whose `data_store` it is.
///
/// A text that does not parse names nothing.
///
/// # Errors
///
/// Returns an error if the nodes, training definitions or system log
/// collectors cannot be read.
pub(crate) fn data_stores_in_use(
    store: &Store,
    customer_id: u32,
) -> anyhow::Result<DataStoresInUse> {
    let mut own = Users::new();
    let mut others = Vec::new();
    for node in store.node_map().iter(Direction::Forward, None) {
        let node = node.context("reading the nodes")?;
        match node.profile.as_ref() {
            Some(profile) if profile.customer_id == customer_id => {
                for service in &node.external_services {
                    if service.kind != ExternalServiceKind::DataStore {
                        continue;
                    }
                    let Some(instance) = service.instance else {
                        continue;
                    };
                    own.entry(data_store_server_name(instance, &profile.hostname))
                        .or_insert_with(|| (profile.hostname.clone(), BTreeSet::new()));
                }
            }
            _ => others.push(node),
        }
    }
    if own.is_empty() {
        return Ok(DataStoresInUse::default());
    }

    for node in &others {
        add_agent_users(&mut own, node);
    }
    for definition in store
        .training_definitions()
        .context("reading the training definitions")?
    {
        if definition.customer_id == customer_id {
            continue;
        }
        if let Ok(document) = TrainingDocument::parse(&definition.definition) {
            add_user(&mut own, &document.data_store.server_name, || {
                format!(
                    "the training definition {:?} of customer {}",
                    definition.name, definition.customer_id
                )
            });
        }
    }
    for collector in store
        .system_log_collector_map()
        .list()
        .context("reading the system log collectors")?
    {
        if let Some(name) = collector.data_store.as_deref() {
            add_user(&mut own, name, || {
                format!("the system log collector on {}", collector.host)
            });
        }
    }

    let data_stores: Vec<_> = own
        .into_iter()
        .filter(|(_, (_, users))| !users.is_empty())
        .map(|(server_name, (hostname, users))| DataStoreInUse {
            server_name,
            hostname,
            users: users.into_iter().collect(),
        })
        .collect();
    // The advice holds only when the one listed is one of these: were it
    // another customer's, the system log collectors would be using that one.
    let only_data_store = !data_stores.is_empty()
        && match listed_rows(store)
            .map_err(|e| anyhow!("listing the Data Stores: {}", e.message))?
            .as_slice()
        {
            [only] => {
                let name = only.server_name();
                data_stores
                    .iter()
                    .any(|data_store| data_store.server_name == name)
            }
            _ => false,
        };
    Ok(DataStoresInUse {
        data_stores,
        only_data_store,
    })
}

/// The customer's Data Stores by server name, each with its node's hostname
/// and its users.
type Users = BTreeMap<String, (String, BTreeSet<String>)>;

/// Adds the user `user` names to the Data Store `server_name`, if it is one
/// of the customer's.
fn add_user(own: &mut Users, server_name: &str, user: impl FnOnce() -> String) {
    if let Some((_, users)) = own.get_mut(server_name) {
        users.insert(user());
    }
}

/// Adds each agent of `node`, a node that is not the customer's, as a user
/// of the Data Stores its configuration or draft names.
fn add_agent_users(own: &mut Users, node: &Node) {
    let place = match node.profile.as_ref() {
        Some(profile) if !profile.hostname.is_empty() => profile.hostname.clone(),
        _ => format!("node {:?}", node.name),
    };
    for agent in &node.agents {
        let user = || {
            format!(
                "the {} agent {} on {place}",
                agent_kind(agent.kind),
                agent.key
            )
        };
        for config in [agent.config.as_ref(), agent.draft.as_ref()]
            .into_iter()
            .flatten()
        {
            if let Some(name) = giganto_name(config) {
                add_user(own, &name, user);
            }
            if agent.kind == AgentKind::Unsupervised
                && let Ok(document) = EngineDocument::parse(config.as_ref())
            {
                for name in document.server_names() {
                    add_user(own, name, user);
                }
            }
        }
    }
}

fn agent_kind(kind: AgentKind) -> &'static str {
    match kind {
        AgentKind::Unsupervised => "Unsupervised Engine",
        AgentKind::Sensor => "Sensor",
        AgentKind::SemiSupervised => "Semi-supervised Engine",
        AgentKind::TimeSeriesGenerator => "Time Series Generator",
        AgentKind::LogCollector => "Log Collector",
    }
}

/// Returns the message refusing a customer's deletion over `in_use`.
///
/// `node_may_move` adds that the node holding a Data Store may be moved to
/// another customer instead, which is true only before the customer's
/// deletion job exists: from its first write, the node cannot leave the
/// customer.
#[must_use]
pub(crate) fn data_store_in_use_message(in_use: &DataStoresInUse, node_may_move: bool) -> String {
    let mut sentences: Vec<String> = in_use
        .data_stores
        .iter()
        .map(|data_store| {
            format!(
                "Data Store {} on {} is used by {}.",
                data_store.server_name,
                data_store.hostname,
                natural_list(&data_store.users)
            )
        })
        .collect();
    sentences.push(
        "Point them at another Data Store — another customer's agents in their own settings, \
         the platform's system log collector with `setSystemLogCollectorDataStore` — then retry."
            .to_string(),
    );
    if node_may_move {
        sentences.push(
            "Nothing has been deleted yet, so you may also move the node that holds the Data \
             Store to another customer first."
                .to_string(),
        );
    }
    if in_use.only_data_store {
        sentences.push(
            "It is the only Data Store installed, and each host's system log collector takes the \
             first Data Store installed, so this customer can be deleted only after another Data \
             Store is installed and the system log collectors are repointed to it with \
             `setSystemLogCollectorDataStore`."
                .to_string(),
        );
    }
    sentences.join(" ")
}

/// Returns `items` joined as "a", "a and b", or "a, b and c".
fn natural_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use review_database::{
        CustomerDataDeletionJob, CustomerDataDeletionService, CustomerDataDeletionServiceResult,
        CustomerDataDeletionStatus, Store,
    };

    /// Stores a deletion job of `customer_id` whose Review result saved
    /// `hosts`, with that result in `review` and a Sensor result in
    /// `sensor`.
    pub(crate) fn put_job(
        store: &Store,
        customer_id: u32,
        hosts: &[&str],
        review: CustomerDataDeletionStatus,
        sensor: CustomerDataDeletionStatus,
    ) {
        let result = |service, status| CustomerDataDeletionServiceResult {
            service,
            host_fqdns: hosts.iter().map(ToString::to_string).collect(),
            status,
            requested_at: 1,
            completed_at: (status != CustomerDataDeletionStatus::InProgress).then_some(2),
            error: (status == CustomerDataDeletionStatus::Failed).then(|| "failed".to_string()),
        };
        let job = CustomerDataDeletionJob::new(
            customer_id,
            vec![
                result(CustomerDataDeletionService::Review, review),
                result(CustomerDataDeletionService::Sensor, sensor),
            ],
        );
        store.customer_data_deletion_map().put(&job).unwrap();
    }

    /// Stores a running deletion job of `customer_id` that saved `hosts`.
    pub(crate) fn put_running_job(store: &Store, customer_id: u32, hosts: &[&str]) {
        put_job(
            store,
            customer_id,
            hosts,
            CustomerDataDeletionStatus::InProgress,
            CustomerDataDeletionStatus::InProgress,
        );
    }

    /// Stores a deletion job of `customer_id` that saved `hosts` and stopped
    /// with its Review result `Failed`.
    pub(crate) fn put_stopped_job(store: &Store, customer_id: u32, hosts: &[&str]) {
        put_job(
            store,
            customer_id,
            hosts,
            CustomerDataDeletionStatus::Failed,
            CustomerDataDeletionStatus::Succeeded,
        );
    }

    /// Stores a completed deletion job of `customer_id` that saved `hosts`.
    pub(crate) fn put_completed_job(store: &Store, customer_id: u32, hosts: &[&str]) {
        put_job(
            store,
            customer_id,
            hosts,
            CustomerDataDeletionStatus::Succeeded,
            CustomerDataDeletionStatus::Succeeded,
        );
    }

    /// Asserts that `response` is refused with `CUSTOMER_DELETION_IN_PROGRESS`.
    pub(crate) fn assert_locked(response: &async_graphql::Response) {
        let codes: Vec<_> = response
            .errors
            .iter()
            .map(|error| {
                error
                    .extensions
                    .as_ref()
                    .and_then(|extensions| extensions.get("code"))
                    .cloned()
            })
            .collect();
        assert_eq!(
            codes,
            [Some(async_graphql::Value::from(
                super::CUSTOMER_DELETION_IN_PROGRESS
            ))],
            "{:?}",
            response.errors
        );
    }

    /// Asserts that `response` is not refused with
    /// `CUSTOMER_DELETION_IN_PROGRESS`.
    pub(crate) fn assert_not_locked(response: &async_graphql::Response) {
        assert!(
            response.errors.iter().all(|error| {
                error
                    .extensions
                    .as_ref()
                    .and_then(|extensions| extensions.get("code"))
                    != Some(&async_graphql::Value::from(
                        super::CUSTOMER_DELETION_IN_PROGRESS,
                    ))
            }),
            "{:?}",
            response.errors
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use review_database::{
        Agent, AgentStatus, CustomerDataDeletionServiceResult, ExternalService,
        ExternalServiceStatus, Lifecycle, NewTrainingDefinition, Node, NodeProfile,
    };

    use super::test_support::{put_completed_job, put_job, put_running_job, put_stopped_job};
    use super::*;
    use crate::customer_data_deletion::{
        CustomerDataDeletionTaskManager, recover_customer_data_deletion_on_startup,
    };
    use crate::graphql::{MockAgentManager, TestSchema, model_test_support::insert_engine_node};

    #[tokio::test]
    async fn a_job_locks_until_every_result_succeeds() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        assert!(!customer_deletion_in_progress(&store, 1).unwrap());

        put_running_job(&store, 1, &["a.example.com"]);
        assert!(customer_deletion_in_progress(&store, 1).unwrap());
        assert!(!customer_deletion_in_progress(&store, 2).unwrap());

        put_stopped_job(&store, 1, &["a.example.com"]);
        assert!(customer_deletion_in_progress(&store, 1).unwrap());

        put_completed_job(&store, 1, &["a.example.com"]);
        assert!(!customer_deletion_in_progress(&store, 1).unwrap());
    }

    #[tokio::test]
    async fn any_unfinished_result_locks_whatever_the_job_holds() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        for service in [
            CustomerDataDeletionService::DataStore,
            CustomerDataDeletionService::ModuleRemoval,
            CustomerDataDeletionService::Review,
        ] {
            for status in [
                CustomerDataDeletionStatus::InProgress,
                CustomerDataDeletionStatus::Failed,
            ] {
                // A job with no `ModuleRemoval` result, as an earlier release
                // wrote it, is judged the same way.
                let job = CustomerDataDeletionJob::new(
                    1,
                    vec![
                        CustomerDataDeletionServiceResult {
                            service: CustomerDataDeletionService::Sensor,
                            host_fqdns: vec!["a.example.com".to_string()],
                            status: CustomerDataDeletionStatus::Succeeded,
                            requested_at: 1,
                            completed_at: Some(2),
                            error: None,
                        },
                        CustomerDataDeletionServiceResult {
                            service,
                            host_fqdns: vec!["a.example.com".to_string()],
                            status,
                            requested_at: 1,
                            completed_at: None,
                            error: None,
                        },
                    ],
                );
                store.customer_data_deletion_map().put(&job).unwrap();
                assert!(
                    customer_deletion_in_progress(&store, 1).unwrap(),
                    "{service:?} {status:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_job_resumed_at_start_up_still_locks() {
        let schema = TestSchema::new().await;
        // One `InProgress` result and no `ModuleRemoval` result.
        put_job(
            &schema.store(),
            1,
            &["a.example.com"],
            CustomerDataDeletionStatus::Succeeded,
            CustomerDataDeletionStatus::InProgress,
        );
        let mut recovered =
            recover_customer_data_deletion_on_startup(Arc::clone(&schema.store)).unwrap();
        assert_eq!(recovered.take_remote_targets().len(), 1);
        recovered
            .start(
                Arc::new(crate::graphql::MockPackageDeployer::default()),
                Arc::new(MockAgentManager {}),
                Arc::new(CustomerDataDeletionTaskManager::default()),
            )
            .await
            .unwrap();
        assert!(customer_deletion_in_progress(&schema.store(), 1).unwrap());
    }

    #[tokio::test]
    async fn saved_host_names_are_held_only_while_the_job_is_unfinished() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        assert!(check_hostnames(&store, ["a.example.com"]).is_ok());

        put_stopped_job(&store, 1, &["a.example.com"]);
        let error = check_hostnames(&store, ["", "b.example.com", "a.example.com"]).unwrap_err();
        assert_eq!(
            error.message,
            "host name a.example.com is held by a customer data deletion that has not \
             completed; choose another host name"
        );
        assert!(check_hostnames(&store, ["b.example.com"]).is_ok());

        put_completed_job(&store, 1, &["a.example.com"]);
        assert!(check_hostnames(&store, ["a.example.com"]).is_ok());
    }

    fn agent(key: &str, kind: AgentKind, config: Option<&str>, draft: Option<&str>) -> Agent {
        Agent {
            node_id: u32::MAX,
            key: key.to_string(),
            kind,
            status: AgentStatus::Enabled,
            config: config.map(|text| text.to_string().try_into().unwrap()),
            draft: draft.map(|text| text.to_string().try_into().unwrap()),
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::NotInstalled,
            bound_addrs: vec![],
            instance: None,
            run_as_root: false,
            run_as_root_draft: None,
            privilege_profile: None,
        }
    }

    fn data_store(instance: Option<u32>) -> ExternalService {
        ExternalService {
            node_id: u32::MAX,
            key: "giganto".to_string(),
            kind: ExternalServiceKind::DataStore,
            status: ExternalServiceStatus::Enabled,
            draft: None,
            installed_version: Some("1.0.0".to_string()),
            installed_commit: Some("abcdef".to_string()),
            lifecycle: Lifecycle::Running,
            bound_addrs: vec![],
            instance,
        }
    }

    fn put_node(
        store: &Store,
        name: &str,
        profile: Option<(u32, &str)>,
        agents: Vec<Agent>,
        external_services: Vec<ExternalService>,
    ) {
        let node = Node {
            id: u32::MAX,
            name: name.to_string(),
            name_draft: Some(name.to_string()),
            profile: profile.map(|(customer_id, hostname)| NodeProfile {
                customer_id,
                description: String::new(),
                hostname: hostname.to_string(),
            }),
            profile_draft: None,
            agents,
            external_services,
            creation_time: chrono::Utc::now(),
        };
        store.node_map().put(&node).unwrap();
    }

    const OWN: &str = "001.giganto.store.example.com";
    const COLLECTOR_KEY: &str = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";

    fn giganto(name: &str) -> String {
        format!("giganto_name = \"{name}\"\n")
    }

    fn engine_document(server_name: &str) -> String {
        format!(
            r#"[[detectors]]
id = 1
enabled = true
model = "m"
sources = ["piglet.b.example.com"]
period = "1m"
start = "2026-10-14T00:00:00Z"
batch_size = 100
[detectors.data_store]
address = "10.0.0.5:38371"
server_name = "{server_name}"
"#
        )
    }

    fn training_definition(server_name: &str) -> String {
        format!(
            r#"event_kind = "http"
method = "multidimension"
sources = ["piglet.b.example.com"]
window_start = "2026-10-14T00:00:00Z"
window_end = "2026-10-21T00:00:00Z"

[data_store]
address = "10.0.0.5:38371"
server_name = "{server_name}"

[csv]
format = [{{ data_type = "utf8", weight = 1.0 }}]
"#
        )
    }

    #[tokio::test]
    async fn every_kind_of_user_is_named() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        put_node(
            &store,
            "store",
            Some((1, "store.example.com")),
            vec![agent(
                "001.piglet",
                AgentKind::Sensor,
                Some(&giganto(OWN)),
                None,
            )],
            vec![data_store(Some(1))],
        );
        put_node(
            &store,
            "b",
            Some((2, "b.example.com")),
            vec![
                agent("001.piglet", AgentKind::Sensor, None, Some(&giganto(OWN))),
                agent(
                    "001.reconverge",
                    AgentKind::Unsupervised,
                    Some(&engine_document(OWN)),
                    None,
                ),
                agent(
                    "001.crusher",
                    AgentKind::TimeSeriesGenerator,
                    Some(&giganto("001.giganto.other.example.com")),
                    Some("giganto_name = 5"),
                ),
            ],
            vec![],
        );
        put_node(
            &store,
            "drafted",
            None,
            vec![agent(
                "001.piglet",
                AgentKind::Sensor,
                Some(&giganto(OWN)),
                None,
            )],
            vec![],
        );
        for (name, customer_id) in [("own-def", 1), ("other-def", 2)] {
            store
                .insert_training_definition(NewTrainingDefinition {
                    name: name.to_string(),
                    customer_id,
                    instance: insert_engine_node(&store, customer_id),
                    method: review_database::ModelMethod::Multidimension,
                    event_kind: "http".to_string(),
                    sources: vec!["piglet.b.example.com".to_string()],
                    indicator: None,
                    definition: training_definition(OWN),
                })
                .unwrap();
        }
        let collectors = store.system_log_collector_map();
        collectors
            .append_install_key("c.example.com", COLLECTOR_KEY, None)
            .unwrap();
        collectors
            .set_data_store("c.example.com", Some(OWN.to_string()))
            .unwrap();

        let in_use = data_stores_in_use(&store, 1).unwrap();
        assert_eq!(
            in_use,
            DataStoresInUse {
                data_stores: vec![DataStoreInUse {
                    server_name: OWN.to_string(),
                    hostname: "store.example.com".to_string(),
                    users: vec![
                        "the Sensor agent 001.piglet on b.example.com".to_string(),
                        "the Sensor agent 001.piglet on node \"drafted\"".to_string(),
                        "the Unsupervised Engine agent 001.reconverge on b.example.com".to_string(),
                        "the system log collector on c.example.com".to_string(),
                        "the training definition \"other-def\" of customer 2".to_string(),
                    ],
                }],
                only_data_store: true,
            }
        );
        assert!(data_stores_in_use(&store, 2).unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_numbered_row_counts_even_when_not_listed() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let mut not_installed = data_store(Some(2));
        not_installed.installed_version = None;
        not_installed.installed_commit = None;
        not_installed.lifecycle = Lifecycle::NotInstalled;
        not_installed.key = "giganto-2".to_string();
        put_node(
            &store,
            "store",
            Some((1, "store.example.com")),
            vec![],
            vec![data_store(None), not_installed],
        );
        put_node(
            &store,
            "other-store",
            Some((2, "other.example.com")),
            vec![],
            vec![data_store(Some(1))],
        );
        put_node(
            &store,
            "b",
            Some((2, "b.example.com")),
            vec![agent(
                "001.piglet",
                AgentKind::Sensor,
                Some(&giganto("002.giganto.store.example.com")),
                None,
            )],
            vec![],
        );

        let in_use = data_stores_in_use(&store, 1).unwrap();
        assert_eq!(
            in_use.data_stores,
            [DataStoreInUse {
                server_name: "002.giganto.store.example.com".to_string(),
                hostname: "store.example.com".to_string(),
                users: vec!["the Sensor agent 001.piglet on b.example.com".to_string()],
            }]
        );
        // The only one listed is another customer's, which the system log
        // collectors would use instead.
        assert!(!in_use.only_data_store);
    }

    #[test]
    fn the_message_names_each_data_store_and_how_to_free_it() {
        let in_use = DataStoresInUse {
            data_stores: vec![
                DataStoreInUse {
                    server_name: "001.giganto.a.example.com".to_string(),
                    hostname: "a.example.com".to_string(),
                    users: vec!["x".to_string(), "y".to_string(), "z".to_string()],
                },
                DataStoreInUse {
                    server_name: "002.giganto.a.example.com".to_string(),
                    hostname: "a.example.com".to_string(),
                    users: vec!["w".to_string()],
                },
            ],
            only_data_store: false,
        };
        let first = "Data Store 001.giganto.a.example.com on a.example.com is used by x, y and \
                     z. Data Store 002.giganto.a.example.com on a.example.com is used by w. \
                     Point them at another Data Store — another customer's agents in their own \
                     settings, the platform's system log collector with \
                     `setSystemLogCollectorDataStore` — then retry.";
        let moving = " Nothing has been deleted yet, so you may also move the node that holds \
                      the Data Store to another customer first.";
        assert_eq!(
            data_store_in_use_message(&in_use, true),
            format!("{first}{moving}")
        );
        assert_eq!(data_store_in_use_message(&in_use, false), first);

        let only = DataStoresInUse {
            data_stores: vec![DataStoreInUse {
                server_name: "001.giganto.a.example.com".to_string(),
                hostname: "a.example.com".to_string(),
                users: vec!["x".to_string()],
            }],
            only_data_store: true,
        };
        assert!(data_store_in_use_message(&only, true).ends_with(
            "It is the only Data Store installed, and each host's system log collector \
                 takes the first Data Store installed, so this customer can be deleted only \
                 after another Data Store is installed and the system log collectors are \
                 repointed to it with `setSystemLogCollectorDataStore`."
        ));
    }
}
