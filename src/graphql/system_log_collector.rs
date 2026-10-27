//! The operational log collectors: the `reproduce` instance `REview` installs
//! on each host with a connected Host Agent, the host's system instance, to
//! send Clumit Security's own logs to a Data Store.
//!
//! A system instance is not a node agent. It belongs to the host, has no
//! customer, and is not a child of a node record, so its listing and its two
//! mutations are top-level rather than fields of `Node`: hanging them there
//! would inherit the customer scoping a node read carries, which is the wrong
//! guard for an instance that serves no customer. They are for a System
//! Administrator alone, and none checks a customer scope.
//!
//! review-web holds none of this state. Every operation asks the
//! [`PackageDeployer`](crate::backend::PackageDeployer), which owns the rows,
//! the connection state, and each collector's attempts.

use async_graphql::{Context, Object, Result, SimpleObject, StringNumber, Union};
use chrono::{DateTime, Utc};
use review_database as database;
use tracing::info;

use super::{
    BoxedPackageDeployer, Role, RoleGuard, install_state,
    node::deploy::{
        BuildNotServable, BuildSelectorInput, CleanupPending, DeployDisposition, FailurePolicy,
        ManifestFormatUnsupported, RollbackUnsupported, build_selector, check_rollback_support,
        cleanup_pending,
    },
    operation_attempt::OperationAttempt,
};
use crate::{
    backend::{DeployError, SystemLogCollectorState},
    info_with_username,
};

#[derive(Default)]
pub(super) struct SystemLogCollectorQuery;

#[derive(Default)]
pub(super) struct SystemLogCollectorMutation;

/// The operational log collector of one host.
#[derive(SimpleObject)]
pub(crate) struct SystemLogCollector {
    /// The host the collector runs on.
    host: String,

    /// The instance number of `reproduce` on the host. It is null until an
    /// install succeeded.
    instance: Option<StringNumber<u32>>,

    /// The version of the build installed on the host.
    ///
    /// It is null together with `installedCommit` or not at all: the two are
    /// one build identity, and half of one names no build.
    installed_version: Option<String>,

    /// The commit of the build installed on the host.
    ///
    /// Null together with `installedVersion` or not at all.
    installed_commit: Option<String>,

    /// The server name of the Data Store the collector sends to. It is null
    /// until one is chosen.
    data_store: Option<String>,

    /// Whether the collector's instance is connected. It is `false` for a
    /// collector with no instance.
    connected: bool,

    /// The last refusal of an install of the collector, if any.
    last_refusal: Option<SystemLogCollectorRefusal>,

    /// The collector's newest operation attempt, or null if it has none.
    ///
    /// For a collector with an instance it is the current attempt of that
    /// instance; for one without, the attempt of its newest install request,
    /// if the ledger still holds it.
    latest_operation_attempt: Option<OperationAttempt>,
}

impl From<SystemLogCollectorState> for SystemLogCollector {
    fn from(state: SystemLogCollectorState) -> Self {
        let SystemLogCollectorState {
            collector,
            connected,
            latest_attempt,
        } = state;
        let (installed_version, installed_commit) = install_state::paired_identity(
            collector.installed_version.as_deref(),
            collector.installed_commit.as_deref(),
        );
        Self {
            host: collector.host,
            instance: collector.instance.map(StringNumber),
            installed_version,
            installed_commit,
            data_store: collector.data_store,
            connected,
            last_refusal: collector.last_refusal.map(Into::into),
            latest_operation_attempt: latest_attempt.map(Into::into),
        }
    }
}

/// A refusal of an install of a host's operational log collector.
#[derive(SimpleObject)]
pub(crate) struct SystemLogCollectorRefusal {
    /// When the install was refused.
    at: DateTime<Utc>,
    /// The reason the install was refused, as reported.
    message: String,
}

impl From<database::SystemLogCollectorRefusal> for SystemLogCollectorRefusal {
    fn from(refusal: database::SystemLogCollectorRefusal) -> Self {
        Self {
            at: refusal.at,
            message: refusal.message,
        }
    }
}

/// The collector's update was accepted, and this is the operation to poll.
#[derive(SimpleObject)]
pub(crate) struct UpdateSystemLogCollectorSuccess {
    /// The attempt's durable identity.
    operation_id: String,
    /// Whether the apply finished or was accepted for later reconciliation.
    disposition: DeployDisposition,
}

/// What `updateSystemLogCollector` answers with.
///
/// These are the members of `updateService`'s result except `SystemInstance`:
/// the collector is the system instance this mutation is for.
#[derive(Union)]
pub(crate) enum UpdateSystemLogCollectorResult {
    Success(UpdateSystemLogCollectorSuccess),
    CleanupPending(CleanupPending),
    RollbackUnsupported(RollbackUnsupported),
    BuildNotServable(BuildNotServable),
    ManifestFormatUnsupported(ManifestFormatUnsupported),
}

#[Object]
impl SystemLogCollectorQuery {
    /// The operational log collector of every host, in host order.
    ///
    /// The order is the one review answers in; nothing here re-sorts it.
    ///
    /// # Errors
    ///
    /// Returns an error if review could not list the collectors.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn system_log_collector_list(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Vec<SystemLogCollector>> {
        info_with_username!(ctx, "System log collector list requested");
        let deployer = ctx.data::<BoxedPackageDeployer>()?;
        let collectors = deployer.system_log_collectors().await?;
        Ok(collectors.into_iter().map(Into::into).collect())
    }
}

#[Object]
impl SystemLogCollectorMutation {
    /// Chooses `serverName` as the Data Store of `host`'s operational log
    /// collector, and has the collector's configuration rendered and pushed.
    ///
    /// Whether `serverName` names an installed Data Store is review's answer;
    /// nothing here checks it.
    ///
    /// # Errors
    ///
    /// Returns an error if `host` has no collector, if `serverName` is not an
    /// installed Data Store, or if review could not store the choice.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn set_system_log_collector_data_store(
        &self,
        ctx: &Context<'_>,
        host: String,
        server_name: String,
    ) -> Result<bool> {
        let deployer = ctx.data::<BoxedPackageDeployer>()?;
        info_with_username!(
            ctx,
            "Data Store {server_name} requested for the system log collector on {host}"
        );
        deployer
            .set_system_log_collector_data_store(&host, &server_name)
            .await?;
        Ok(true)
    }

    /// Updates the build of `host`'s operational log collector and returns the
    /// operation to poll.
    ///
    /// `ROLLBACK` is refused as `RollbackUnsupported` on a host that
    /// advertises no rollback supervisor, before review is asked, as
    /// `updateService` refuses it.
    ///
    /// # Errors
    ///
    /// Returns an error if `buildSelector` sets both fields or neither, if the
    /// host's capabilities could not be read, if `host` has no collector or
    /// its collector has no instance, or for any other failure review reports
    /// outside the result union.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn update_system_log_collector(
        &self,
        ctx: &Context<'_>,
        host: String,
        build_selector: BuildSelectorInput,
        #[graphql(default_with = "FailurePolicy::Rollback")] on_failure: FailurePolicy,
    ) -> Result<UpdateSystemLogCollectorResult> {
        let selector = self::build_selector(build_selector)?;
        if let Some(refusal) = check_rollback_support(ctx, &host, on_failure).await? {
            return Ok(UpdateSystemLogCollectorResult::RollbackUnsupported(refusal));
        }

        let deployer = ctx.data::<BoxedPackageDeployer>()?;
        // Logged before the call, as the deploy mutations log theirs, so a
        // refusal is in the log too.
        info_with_username!(
            ctx,
            "Update of the system log collector requested on {host}"
        );
        match deployer
            .update_system_log_collector(&host, selector, on_failure.into())
            .await
        {
            Ok((outcome, operation_id)) => Ok(UpdateSystemLogCollectorResult::Success(
                UpdateSystemLogCollectorSuccess {
                    operation_id: operation_id.into_inner(),
                    disposition: outcome.into(),
                },
            )),
            Err(DeployError::CleanupPending {
                host,
                target,
                instance,
                operation_id,
            }) => Ok(UpdateSystemLogCollectorResult::CleanupPending(
                cleanup_pending(host, target, instance, operation_id),
            )),
            Err(DeployError::BuildNotServable { target }) => Ok(
                UpdateSystemLogCollectorResult::BuildNotServable(BuildNotServable { target }),
            ),
            Err(DeployError::ManifestFormatUnsupported {
                host,
                format_version,
                min,
                max,
            }) => Ok(UpdateSystemLogCollectorResult::ManifestFormatUnsupported(
                ManifestFormatUnsupported {
                    host,
                    format_version,
                    min,
                    max,
                },
            )),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use assert_json_diff::assert_json_eq;
    use chrono::{DateTime, TimeZone, Utc};
    use review_database::{
        BuildSelector, ListenerBinding, ListenerTransport, OperationAction,
        OperationAttempt as Record, OperationOutcome, OperationPhase, OperationRetryPolicy,
        PortOwner, Role, SystemLogCollector as Row, SystemLogCollectorRefusal as Refusal,
    };
    use review_protocol::types::{
        ResourceUsage,
        capability::ROLLBACK_SUPERVISOR,
        node::{
            BootstrapMaterial, DeliveryMode, FailurePolicy as BackendFailurePolicy, PackageState,
        },
    };
    use serde_json::json;

    use crate::{
        backend::{
            AgentManager, BindAddrInput, BuildId, ConfigTemplateCatalog, DeployError,
            DeployOutcome, OperationId, PackageDeployer, SystemLogCollectorState,
        },
        customer_data_deletion::CustomerDataDeletionTarget,
        graphql::{
            BoxedPackageDeployer, NetworksTargetAgentLookupKeysPair, SharedAgentManager, TestSchema,
        },
    };

    const HOST: &str = "host1.example.com";
    const OTHER_HOST: &str = "host0.example.com";
    const SERVER_NAME: &str = "001.giganto.host2.example.com";
    const OPERATION_ID: &str = "11111111-2222-4333-8444-555555555555";
    const ATTEMPT_KEY: &str = "0aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    /// The roles below System Administrator, each of which the three
    /// operations refuse.
    const LOWER_ROLES: [Role; 3] = [
        Role::SecurityAdministrator,
        Role::SecurityManager,
        Role::SecurityMonitor,
    ];

    const LIST_QUERY: &str = "{ systemLogCollectorList { host instance installedVersion \
                              installedCommit dataStore connected lastRefusal { at message } \
                              latestOperationAttempt { id action phase outcome host target \
                              instance } } }";

    const UPDATE_SELECTION: &str = "__typename
        ... on UpdateSystemLogCollectorSuccess { operationId disposition }
        ... on CleanupPending { host target instance operationId }
        ... on RollbackUnsupported { host capability }
        ... on BuildNotServable { target }
        ... on ManifestFormatUnsupported { host formatVersion min max }";

    fn data_store_mutation(host: &str, server_name: &str) -> String {
        format!(
            r#"mutation {{ setSystemLogCollectorDataStore(host: "{host}", serverName: "{server_name}") }}"#
        )
    }

    /// The update mutation for [`HOST`] with `args` after the host.
    fn update_mutation(args: &str) -> String {
        format!(
            r#"mutation {{ updateSystemLogCollector(host: "{HOST}", {args}) {{ {UPDATE_SELECTION} }} }}"#
        )
    }

    fn instant(offset: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + offset, 0)
            .single()
            .expect("a fixed timestamp is representable")
    }

    /// A running install attempt of `reproduce` on `host`.
    fn attempt(host: &str, instance: Option<u32>) -> Record {
        Record {
            idempotency_key: ATTEMPT_KEY.to_string(),
            host: host.to_string(),
            target: "reproduce".to_string(),
            instance,
            action: OperationAction::Install,
            config_template: None,
            install_intent: Some([7; 32]),
            package_digest: "digest".to_string(),
            resolved_version: "1.2.0".to_string(),
            resolved_commit: "abcabc".to_string(),
            phase: OperationPhase::Dispatched,
            cleanup_state: None,
            started_at: instant(0),
            retry_policy: OperationRetryPolicy {
                max_attempts: 3,
                attempts_made: 0,
                backoff_seconds: 1,
            },
            outcome: None,
            failure_kind: None,
            finalized_at: None,
            expires_at: instant(3_600),
            backup_id: None,
            pre_update_version: None,
        }
    }

    /// An empty row for `host`.
    fn row(host: &str) -> Row {
        Row {
            host: host.to_string(),
            instance: None,
            install_keys: vec![],
            installed_version: None,
            installed_commit: None,
            data_store: None,
            config: None,
            last_refusal: None,
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    struct UpdateCall {
        host: String,
        selector: BuildSelector,
        on_failure: BackendFailurePolicy,
    }

    /// Every call the stub was asked to make, in order.
    #[derive(Default)]
    struct Calls {
        lists: Mutex<usize>,
        data_stores: Mutex<Vec<(String, String)>>,
        updates: Mutex<Vec<UpdateCall>>,
    }

    impl Calls {
        fn lists(&self) -> usize {
            *self.lists.lock().unwrap()
        }

        fn data_stores(&self) -> Vec<(String, String)> {
            self.data_stores.lock().unwrap().clone()
        }

        fn updates(&self) -> Vec<UpdateCall> {
            self.updates.lock().unwrap().clone()
        }

        fn total(&self) -> usize {
            self.lists() + self.data_stores().len() + self.updates().len()
        }
    }

    /// Answers the three system log collector methods from a script, each at
    /// most once, and records what they were asked.
    ///
    /// The other methods panic: none of these operations reaches them.
    struct CollectorDeployer {
        calls: Arc<Calls>,
        list: Mutex<Option<Result<Vec<SystemLogCollectorState>, anyhow::Error>>>,
        data_store: Mutex<Option<Result<(), anyhow::Error>>>,
        update: Mutex<Option<Result<(DeployOutcome, OperationId), DeployError>>>,
    }

    impl CollectorDeployer {
        fn boxed() -> (Self, Arc<Calls>) {
            let calls = Arc::<Calls>::default();
            let deployer = Self {
                calls: Arc::clone(&calls),
                list: Mutex::new(None),
                data_store: Mutex::new(None),
                update: Mutex::new(None),
            };
            (deployer, calls)
        }

        fn listing(
            answer: Result<Vec<SystemLogCollectorState>, anyhow::Error>,
        ) -> (BoxedPackageDeployer, Arc<Calls>) {
            let (deployer, calls) = Self::boxed();
            *deployer.list.lock().unwrap() = Some(answer);
            (Box::new(deployer), calls)
        }

        fn storing(answer: Result<(), anyhow::Error>) -> (BoxedPackageDeployer, Arc<Calls>) {
            let (deployer, calls) = Self::boxed();
            *deployer.data_store.lock().unwrap() = Some(answer);
            (Box::new(deployer), calls)
        }

        fn updating(
            answer: Result<(DeployOutcome, OperationId), DeployError>,
        ) -> (BoxedPackageDeployer, Arc<Calls>) {
            let (deployer, calls) = Self::boxed();
            *deployer.update.lock().unwrap() = Some(answer);
            (Box::new(deployer), calls)
        }

        /// A stub whose update succeeds with `Applied`.
        fn applying() -> (BoxedPackageDeployer, Arc<Calls>) {
            Self::updating(Ok((
                DeployOutcome::Applied,
                OperationId::new(OPERATION_ID.to_string()),
            )))
        }
    }

    #[async_trait::async_trait]
    impl PackageDeployer for CollectorDeployer {
        async fn install(
            &self,
            _host: &str,
            _target: &str,
            _selector: BuildSelector,
            _on_failure: BackendFailurePolicy,
            _bind_addrs: Option<Vec<BindAddrInput>>,
            _config_template: Option<String>,
            _request_key: &str,
        ) -> Result<(DeployOutcome, OperationId), DeployError> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn update(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
            _selector: BuildSelector,
            _on_failure: BackendFailurePolicy,
        ) -> Result<(DeployOutcome, OperationId), DeployError> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn remove(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> Result<OperationId, DeployError> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn recommend_bind_addrs(
            &self,
            _host: &str,
            _target: &str,
        ) -> Result<Vec<ListenerBinding>, DeployError> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn latest_build(&self, _target: &str) -> Result<Option<BuildId>, anyhow::Error> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn servable_builds(&self, _target: &str) -> Result<Vec<BuildId>, anyhow::Error> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn config_templates(
            &self,
            _target: &str,
        ) -> Result<ConfigTemplateCatalog, anyhow::Error> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn is_build_withdrawn(
            &self,
            _target: &str,
            _build: &BuildId,
        ) -> Result<bool, anyhow::Error> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn package_status(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> Result<PackageState, anyhow::Error> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn read_version(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> Result<Option<BuildId>, anyhow::Error> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn system_log_collectors(
            &self,
        ) -> Result<Vec<SystemLogCollectorState>, anyhow::Error> {
            *self.calls.lists.lock().unwrap() += 1;
            self.list
                .lock()
                .unwrap()
                .take()
                .expect("the list is scripted once")
        }

        async fn set_system_log_collector_data_store(
            &self,
            host: &str,
            server_name: &str,
        ) -> Result<(), anyhow::Error> {
            self.calls
                .data_stores
                .lock()
                .unwrap()
                .push((host.to_string(), server_name.to_string()));
            self.data_store
                .lock()
                .unwrap()
                .take()
                .expect("the Data Store choice is scripted once")
        }

        async fn update_system_log_collector(
            &self,
            host: &str,
            selector: BuildSelector,
            on_failure: BackendFailurePolicy,
        ) -> Result<(DeployOutcome, OperationId), DeployError> {
            self.calls.updates.lock().unwrap().push(UpdateCall {
                host: host.to_string(),
                selector,
                on_failure,
            });
            self.update
                .lock()
                .unwrap()
                .take()
                .expect("the update is scripted once")
        }

        async fn register(
            &self,
            _service_name: &str,
            _host: &str,
            _instance: Option<u32>,
            _mode: DeliveryMode,
        ) -> Result<BootstrapMaterial, anyhow::Error> {
            unimplemented!("this stub answers the system log collector methods only")
        }

        async fn deregister(
            &self,
            _service_name: &str,
            _host: &str,
            _instance: Option<u32>,
        ) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the system log collector methods only")
        }
    }

    /// Advertises a fixed capability set for every host and records every
    /// host it was asked about, in order.
    ///
    /// The other methods panic: none of these operations reaches them.
    struct CapabilityStub {
        reads: Arc<Mutex<Vec<String>>>,
        advertised: &'static [&'static str],
    }

    impl CapabilityStub {
        fn advertising(
            advertised: &'static [&'static str],
        ) -> (SharedAgentManager, Arc<Mutex<Vec<String>>>) {
            let reads = Arc::<Mutex<Vec<String>>>::default();
            let stub = Self {
                reads: Arc::clone(&reads),
                advertised,
            };
            (Arc::new(stub), reads)
        }
    }

    #[async_trait::async_trait]
    impl AgentManager for CapabilityStub {
        async fn request_customer_data_deletion(
            &self,
            _targets: &[CustomerDataDeletionTarget],
        ) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }

        async fn send_agent_specific_internal_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }

        async fn send_agent_specific_allow_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }

        async fn send_agent_specific_block_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }

        async fn online_apps_by_host_id(
            &self,
        ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }

        async fn sampling_policies_changed(&self, _generators: &[review_database::ModelInstance]) {}

        async fn capabilities(&self, hostname: &str) -> Result<BTreeSet<String>, anyhow::Error> {
            self.reads.lock().unwrap().push(hostname.to_string());
            Ok(self
                .advertised
                .iter()
                .map(|tag| (*tag).to_string())
                .collect())
        }

        async fn get_resource_usage(
            &self,
            _hostname: &str,
        ) -> Result<ResourceUsage, anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }

        async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }

        async fn ping(&self, _hostname: &str) -> Result<Duration, anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }

        async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }

        async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the capability read only")
        }
    }

    /// A schema whose deployer is `deployer` and whose every host advertises
    /// `advertised`, returned with the capability reads it records.
    async fn collector_schema(
        deployer: BoxedPackageDeployer,
        advertised: &'static [&'static str],
    ) -> (TestSchema, Arc<Mutex<Vec<String>>>) {
        let (agents, reads) = CapabilityStub::advertising(advertised);
        let schema = TestSchema::new_with_all(agents, deployer, None, "testuser", None).await;
        (schema, reads)
    }

    /// Each operation refuses every role below System Administrator with the
    /// guard's `Forbidden`, before the backend or the capability read.
    #[tokio::test]
    async fn the_lower_roles_are_refused_before_the_backend() {
        let operations = [
            LIST_QUERY.to_string(),
            data_store_mutation(HOST, SERVER_NAME),
            update_mutation(r#"buildSelector: {version: "1.2.0"}"#),
        ];
        for query in &operations {
            for role in LOWER_ROLES {
                let (deployer, calls) = CollectorDeployer::boxed();
                let (schema, reads) =
                    collector_schema(Box::new(deployer), &[ROLLBACK_SUPERVISOR]).await;

                let res = schema
                    .execute_as_scoped_user(query, role, Some(vec![0]))
                    .await;

                assert_eq!(res.errors.len(), 1, "{role:?}: {query}");
                assert_eq!(res.errors[0].message, "Forbidden", "{role:?}: {query}");
                assert_eq!(calls.total(), 0, "{role:?}: {query}");
                assert!(reads.lock().unwrap().is_empty(), "{role:?}: {query}");
            }
        }
    }

    /// A System Administrator with no customer scope at all reaches each
    /// operation.
    #[tokio::test]
    async fn a_system_administrator_reaches_each_operation() {
        let (deployer, calls) = CollectorDeployer::listing(Ok(vec![]));
        let (schema, _reads) = collector_schema(deployer, &[]).await;
        let res = schema
            .execute_as_scoped_user(LIST_QUERY, Role::SystemAdministrator, Some(vec![]))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(calls.lists(), 1);

        let (deployer, calls) = CollectorDeployer::storing(Ok(()));
        let (schema, _reads) = collector_schema(deployer, &[]).await;
        let res = schema
            .execute_as_scoped_user(
                &data_store_mutation(HOST, SERVER_NAME),
                Role::SystemAdministrator,
                Some(vec![]),
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(calls.data_stores().len(), 1);

        let (deployer, calls) = CollectorDeployer::applying();
        let (schema, _reads) = collector_schema(deployer, &[]).await;
        let res = schema
            .execute_as_scoped_user(
                &update_mutation(r#"buildSelector: {version: "1.2.0"}, onFailure: HOLD"#),
                Role::SystemAdministrator,
                Some(vec![]),
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(calls.updates().len(), 1);
    }

    /// Each entry is mapped field by field, in the order the backend answered
    /// in, with a half build reported as none.
    #[tokio::test]
    async fn the_list_maps_each_entry_in_the_backends_order() {
        let mut installed = row(HOST);
        installed.instance = Some(3_000_000_000);
        installed.install_keys = vec![ATTEMPT_KEY.to_string()];
        installed.installed_version = Some("1.2.0".to_string());
        installed.installed_commit = Some("abcabc".to_string());
        installed.data_store = Some(SERVER_NAME.to_string());
        installed.config = Some("secret = \"config\"".to_string());
        installed.last_refusal = Some(Refusal {
            at: instant(10),
            message: "the host refused".to_string(),
        });
        let mut finished = attempt(HOST, Some(3_000_000_000));
        finished.phase = OperationPhase::Completed;
        finished.outcome = Some(OperationOutcome::Succeeded);
        finished.finalized_at = Some(instant(60));

        let mut uninstalled = row(OTHER_HOST);
        uninstalled.install_keys = vec![ATTEMPT_KEY.to_string()];
        uninstalled.installed_version = Some("1.2.0".to_string());

        let without_attempt = row("host2.example.com");

        // The hosts are deliberately out of order, so a resolver that sorted
        // them would fail the assertion.
        let (deployer, calls) = CollectorDeployer::listing(Ok(vec![
            SystemLogCollectorState {
                collector: installed,
                connected: true,
                latest_attempt: Some(finished),
            },
            SystemLogCollectorState {
                collector: uninstalled,
                connected: false,
                latest_attempt: Some(attempt(OTHER_HOST, None)),
            },
            SystemLogCollectorState {
                collector: without_attempt,
                connected: false,
                latest_attempt: None,
            },
        ]));
        let (schema, _reads) = collector_schema(deployer, &[]).await;

        let res = schema.execute_as_system_admin(LIST_QUERY).await;

        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(calls.lists(), 1);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "systemLogCollectorList": [
                    {
                        "host": HOST,
                        "instance": "3000000000",
                        "installedVersion": "1.2.0",
                        "installedCommit": "abcabc",
                        "dataStore": SERVER_NAME,
                        "connected": true,
                        "lastRefusal": {
                            "at": "2023-11-14T22:13:30+00:00",
                            "message": "the host refused",
                        },
                        "latestOperationAttempt": {
                            "id": ATTEMPT_KEY,
                            "action": "INSTALL",
                            "phase": "COMPLETED",
                            "outcome": "SUCCEEDED",
                            "host": HOST,
                            "target": "reproduce",
                            "instance": "3000000000",
                        },
                    },
                    {
                        "host": OTHER_HOST,
                        "instance": null,
                        "installedVersion": null,
                        "installedCommit": null,
                        "dataStore": null,
                        "connected": false,
                        "lastRefusal": null,
                        "latestOperationAttempt": {
                            "id": ATTEMPT_KEY,
                            "action": "INSTALL",
                            "phase": "DISPATCHED",
                            "outcome": null,
                            "host": OTHER_HOST,
                            "target": "reproduce",
                            "instance": null,
                        },
                    },
                    {
                        "host": "host2.example.com",
                        "instance": null,
                        "installedVersion": null,
                        "installedCommit": null,
                        "dataStore": null,
                        "connected": false,
                        "lastRefusal": null,
                        "latestOperationAttempt": null,
                    },
                ],
            })
        );
    }

    /// The row's configuration and install keys are not part of the type.
    #[tokio::test]
    async fn the_configuration_and_install_keys_are_not_exposed() {
        let (deployer, _calls) = CollectorDeployer::listing(Ok(vec![]));
        let (schema, _reads) = collector_schema(deployer, &[]).await;
        for field in ["config", "installKeys"] {
            let res = schema
                .execute_as_system_admin(&format!("{{ systemLogCollectorList {{ {field} }} }}"))
                .await;
            assert_eq!(res.errors.len(), 1, "{field}");
        }
    }

    /// A failed listing fails the whole query, never an empty list.
    #[tokio::test]
    async fn a_failed_listing_is_an_error() {
        let (deployer, calls) =
            CollectorDeployer::listing(Err(anyhow::anyhow!("the collectors could not be read")));
        let (schema, _reads) = collector_schema(deployer, &[]).await;

        let res = schema.execute_as_system_admin(LIST_QUERY).await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "the collectors could not be read");
        assert!(res.data.into_json().unwrap().is_null());
        assert_eq!(calls.lists(), 1);
    }

    /// The host and the server name reach the backend unchanged, and success
    /// answers `true`.
    #[tokio::test]
    async fn the_data_store_choice_passes_through() {
        let (deployer, calls) = CollectorDeployer::storing(Ok(()));
        let (schema, _reads) = collector_schema(deployer, &[]).await;

        let res = schema
            .execute_as_system_admin(&data_store_mutation(HOST, SERVER_NAME))
            .await;

        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({ "setSystemLogCollectorDataStore": true })
        );
        assert_eq!(
            calls.data_stores(),
            vec![(HOST.to_string(), SERVER_NAME.to_string())]
        );
        assert_eq!(calls.total(), 1);
    }

    /// A refusal of the choice is an ordinary error carrying the backend's
    /// message, with no `extensions.code`.
    #[tokio::test]
    async fn a_refused_data_store_choice_is_an_error() {
        const MESSAGE: &str = "001.giganto.host2.example.com is not an installed Data Store";
        let (deployer, calls) = CollectorDeployer::storing(Err(anyhow::anyhow!(MESSAGE)));
        let (schema, _reads) = collector_schema(deployer, &[]).await;

        let res = schema
            .execute_as_system_admin(&data_store_mutation(HOST, SERVER_NAME))
            .await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, MESSAGE);
        assert!(res.errors[0].extensions.is_none());
        assert!(res.data.into_json().unwrap().is_null());
        assert_eq!(calls.data_stores().len(), 1);
    }

    /// `ROLLBACK`, the default, on a host without a rollback supervisor is
    /// refused as its member before the backend is asked.
    #[tokio::test]
    async fn rollback_on_a_host_without_the_supervisor_is_refused() {
        for args in [
            r#"buildSelector: {version: "1.2.0"}"#,
            r#"buildSelector: {version: "1.2.0"}, onFailure: ROLLBACK"#,
        ] {
            let (deployer, calls) = CollectorDeployer::applying();
            let (schema, reads) = collector_schema(deployer, &[]).await;

            let res = schema.execute_as_system_admin(&update_mutation(args)).await;

            assert!(res.errors.is_empty(), "{args}: {:?}", res.errors);
            assert_json_eq!(
                res.data.into_json().unwrap(),
                json!({
                    "updateSystemLogCollector": {
                        "__typename": "RollbackUnsupported",
                        "host": HOST,
                        "capability": ROLLBACK_SUPERVISOR,
                    },
                })
            );
            assert_eq!(calls.total(), 0, "{args}");
            assert_eq!(*reads.lock().unwrap(), vec![HOST.to_string()], "{args}");
        }
    }

    /// `ROLLBACK` on a host with a rollback supervisor reaches the backend
    /// with the converted selector and policy.
    #[tokio::test]
    async fn rollback_on_a_supported_host_reaches_the_backend() {
        let (deployer, calls) = CollectorDeployer::applying();
        let (schema, reads) = collector_schema(deployer, &[ROLLBACK_SUPERVISOR]).await;

        let res = schema
            .execute_as_system_admin(&update_mutation(r#"buildSelector: {commit: "abcabc"}"#))
            .await;

        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "updateSystemLogCollector": {
                    "__typename": "UpdateSystemLogCollectorSuccess",
                    "operationId": OPERATION_ID,
                    "disposition": "APPLIED",
                },
            })
        );
        assert_eq!(
            calls.updates(),
            vec![UpdateCall {
                host: HOST.to_string(),
                selector: BuildSelector::Commit("abcabc".to_string()),
                on_failure: BackendFailurePolicy::Rollback,
            }]
        );
        assert_eq!(*reads.lock().unwrap(), vec![HOST.to_string()]);
    }

    /// `HOLD` reads no capability set and reaches the backend, whatever the
    /// host advertises.
    #[tokio::test]
    async fn hold_reads_no_capability() {
        let (deployer, calls) = CollectorDeployer::updating(Ok((
            DeployOutcome::Accepted,
            OperationId::new(OPERATION_ID.to_string()),
        )));
        let (schema, reads) = collector_schema(deployer, &[]).await;

        let res = schema
            .execute_as_system_admin(&update_mutation(
                r#"buildSelector: {version: "1.2.0"}, onFailure: HOLD"#,
            ))
            .await;

        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "updateSystemLogCollector": {
                    "__typename": "UpdateSystemLogCollectorSuccess",
                    "operationId": OPERATION_ID,
                    "disposition": "ACCEPTED",
                },
            })
        );
        assert_eq!(
            calls.updates(),
            vec![UpdateCall {
                host: HOST.to_string(),
                selector: BuildSelector::Version("1.2.0".to_string()),
                on_failure: BackendFailurePolicy::Hold,
            }]
        );
        assert!(reads.lock().unwrap().is_empty());
    }

    /// A selector setting both fields or neither is refused before the
    /// capability read and the backend.
    #[tokio::test]
    async fn a_malformed_selector_is_refused_before_the_backend() {
        for selector in ["{}", r#"{version: "1.2.0", commit: "abcabc"}"#] {
            let (deployer, calls) = CollectorDeployer::applying();
            let (schema, reads) = collector_schema(deployer, &[ROLLBACK_SUPERVISOR]).await;

            let res = schema
                .execute_as_system_admin(&update_mutation(&format!("buildSelector: {selector}")))
                .await;

            assert_eq!(res.errors.len(), 1, "{selector}");
            assert_eq!(calls.total(), 0, "{selector}");
            assert!(reads.lock().unwrap().is_empty(), "{selector}");
        }
    }

    /// The backend's refusals in the union arrive as their members, with the
    /// fields the backend named.
    #[tokio::test]
    async fn the_union_refusals_arrive_as_their_members() {
        let cases = [
            (
                DeployError::CleanupPending {
                    host: "backend-host".to_string(),
                    target: "reproduce".to_string(),
                    instance: Some(4),
                    operation_id: OperationId::new(OPERATION_ID.to_string()),
                },
                json!({
                    "__typename": "CleanupPending",
                    "host": "backend-host",
                    "target": "reproduce",
                    "instance": "4",
                    "operationId": OPERATION_ID,
                }),
            ),
            (
                DeployError::BuildNotServable {
                    target: "backend-target".to_string(),
                },
                json!({
                    "__typename": "BuildNotServable",
                    "target": "backend-target",
                }),
            ),
            (
                DeployError::ManifestFormatUnsupported {
                    host: "backend-host".to_string(),
                    format_version: 9,
                    min: 3,
                    max: 8,
                },
                json!({
                    "__typename": "ManifestFormatUnsupported",
                    "host": "backend-host",
                    "formatVersion": 9,
                    "min": 3,
                    "max": 8,
                }),
            ),
        ];
        for (error, expected) in cases {
            let (deployer, calls) = CollectorDeployer::updating(Err(error));
            let (schema, _reads) = collector_schema(deployer, &[]).await;

            let res = schema
                .execute_as_system_admin(&update_mutation(
                    r#"buildSelector: {version: "1.2.0"}, onFailure: HOLD"#,
                ))
                .await;

            assert!(res.errors.is_empty(), "{expected}: {:?}", res.errors);
            assert_json_eq!(
                res.data.into_json().unwrap()["updateSystemLogCollector"].clone(),
                expected
            );
            assert_eq!(calls.updates().len(), 1);
        }
    }

    /// Every other variant is an ordinary GraphQL error carrying its message,
    /// with no `extensions.code`.
    #[tokio::test]
    async fn every_other_variant_is_an_ordinary_error() {
        let errors = [
            DeployError::Other(anyhow::anyhow!(
                "host1.example.com has no system log collector"
            )),
            DeployError::SystemInstance {
                host: HOST.to_string(),
            },
            DeployError::PortAllocationConflict {
                host: HOST.to_string(),
                transport: ListenerTransport::Tcp,
                port: 38_370,
                owner: PortOwner {
                    component: "giganto".to_string(),
                    instance: 1,
                    listener_key: "ingest".to_string(),
                },
            },
            DeployError::ConfigTemplateRequired {
                target: "reproduce".to_string(),
            },
        ];
        for error in errors {
            let message = error.to_string();
            let (deployer, calls) = CollectorDeployer::updating(Err(error));
            let (schema, _reads) = collector_schema(deployer, &[]).await;

            let res = schema
                .execute_as_system_admin(&update_mutation(
                    r#"buildSelector: {version: "1.2.0"}, onFailure: HOLD"#,
                ))
                .await;

            assert_eq!(res.errors.len(), 1, "{message}");
            assert_eq!(res.errors[0].message, message);
            assert!(res.errors[0].extensions.is_none(), "{message}");
            assert!(res.data.into_json().unwrap().is_null(), "{message}");
            assert_eq!(calls.updates().len(), 1, "{message}");
        }
    }
}
