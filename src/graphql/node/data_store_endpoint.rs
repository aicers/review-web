use async_graphql::{Context, Result, SimpleObject};
use futures::future::join_all;
use review_database::{self as database, event::Direction};
use tracing::warn;

use super::super::{
    SharedAgentManager, get_store,
    install_state::{self, Lifecycle},
};

/// The endpoint at which `REview` reaches one installed Data Store (Giganto)
/// instance.
#[derive(Debug, PartialEq, SimpleObject)]
pub(super) struct DataStoreEndpoint {
    /// The certificate name `REview`'s configuration plane verifies when it
    /// dials this instance, `<instance:03>.giganto.<hostname>`.
    server_name: String,

    /// The GraphQL port `REview`'s configuration plane dials on this instance.
    ///
    /// `0` means `REview` could not compute this instance's endpoint.
    port: u16,

    /// The IP addresses, as text, `REview`'s configuration plane dials for
    /// this instance's host.
    ///
    /// `[]` means `REview` could not compute this instance's endpoint.
    addrs: Vec<String>,
}

/// One Data Store row that is listed: the hostname of its node's applied
/// profile, its instance number, and its stored configuration.
pub(crate) struct ListedRow {
    pub(crate) hostname: String,
    pub(crate) instance: u32,
    /// The Data Store external service's stored `draft`.
    pub(crate) draft: Option<database::ExternalServiceConfig>,
}

impl ListedRow {
    /// Returns the row's Data Store name, `<instance:03>.giganto.<hostname>`.
    #[must_use]
    pub(crate) fn server_name(&self) -> String {
        format!("{:03}.giganto.{}", self.instance, self.hostname)
    }
}

/// Returns every listed Data Store row, in node-map order.
///
/// A row is listed when it is a `DATA_STORE` row on a node with an applied
/// profile, it has an instance number, its projected installed state has a
/// version, and its lifecycle is neither `NOT_INSTALLED` nor `REMOVING`. The
/// instance, version and lifecycle are read as `ExternalService` resolves them.
///
/// # Errors
///
/// Returns an error if the node map cannot be read.
pub(crate) fn listed_rows(store: &database::Store) -> Result<Vec<ListedRow>> {
    let map = store.node_map();
    let mut rows = Vec::new();
    for entry in map.iter(Direction::Forward, None) {
        let node = entry.map_err(|_| "invalid value in database")?;
        let Some(profile) = node.profile.as_ref() else {
            continue;
        };
        for service in node.external_services {
            if service.kind != database::ExternalServiceKind::DataStore {
                continue;
            }
            let Some(instance) = service.instance else {
                continue;
            };
            let state = install_state::projected_state(
                service.kind.package_id(),
                service.installed_version.as_deref(),
                service.installed_commit.as_deref(),
                service.lifecycle,
            );
            if state.version.is_none() {
                continue;
            }
            if !matches!(
                state.lifecycle,
                Some(
                    Lifecycle::Installing
                        | Lifecycle::Running
                        | Lifecycle::Stopped
                        | Lifecycle::Failed
                        | Lifecycle::Unknown
                )
            ) {
                continue;
            }
            rows.push(ListedRow {
                hostname: profile.hostname.clone(),
                instance,
                draft: service.draft,
            });
        }
    }
    Ok(rows)
}

/// Asks the agent manager for one row's endpoint.
///
/// A failure is this element's alone: it is logged, and the element carries
/// port `0` and no address under a name composed here as a label only.
async fn endpoint(agent_manager: &SharedAgentManager, row: ListedRow) -> DataStoreEndpoint {
    let ListedRow {
        hostname, instance, ..
    } = row;
    match agent_manager
        .data_store_read_endpoint(&hostname, instance)
        .await
    {
        Ok(endpoint) => DataStoreEndpoint {
            server_name: endpoint.server_name,
            port: endpoint.port,
            addrs: endpoint.addrs.iter().map(ToString::to_string).collect(),
        },
        Err(e) => {
            warn!(
                "cannot compute the read endpoint of Data Store instance {instance} on \
                 {hostname}: {e:#}"
            );
            DataStoreEndpoint {
                server_name: format!("{instance:03}.giganto.{hostname}"),
                port: 0,
                addrs: Vec::new(),
            }
        }
    }
}

pub(super) async fn load(ctx: &Context<'_>) -> Result<Vec<DataStoreEndpoint>> {
    let rows = listed_rows(&*get_store(ctx)?)?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let agent_manager = ctx.data::<SharedAgentManager>()?;
    let mut endpoints = join_all(rows.into_iter().map(|row| endpoint(agent_manager, row))).await;
    endpoints.sort_unstable_by(|a, b| a.server_name.cmp(&b.server_name));
    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::IpAddr,
        sync::{Arc, Mutex},
    };

    use chrono::Utc;
    use review_database::{ExternalServiceKind, Lifecycle, Node, NodeProfile, Role};
    use serde_json::{Value, json};

    use super::super::test_support::{installed_service, put_node};
    use crate::{
        backend::DataStoreReadEndpoint,
        graphql::{
            AgentManager, SamplingPolicy, SharedAgentManager, TestSchema,
            customer::NetworksTargetAgentLookupKeysPair,
        },
    };

    const QUERY: &str = "{ dataStoreEndpoints { serverName port addrs } }";
    const ENDPOINT_FAILURE: &str = "no GraphQL port is allocated";

    /// Every `(hostname, instance)` an [`EndpointStub`] was asked about.
    #[derive(Default)]
    struct EndpointReads(Mutex<Vec<(String, u32)>>);

    impl EndpointReads {
        fn count(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    /// Answers the endpoint read per `(hostname, instance)` and records every
    /// pair it was asked about. A pair it has no answer for fails.
    ///
    /// The other methods panic: a test that reaches one is testing something
    /// this query does not do.
    struct EndpointStub {
        reads: Arc<EndpointReads>,
        answers: HashMap<(String, u32), DataStoreReadEndpoint>,
    }

    impl EndpointStub {
        fn boxed(
            answers: &[(&str, u32, DataStoreReadEndpoint)],
        ) -> (SharedAgentManager, Arc<EndpointReads>) {
            let reads = Arc::<EndpointReads>::default();
            let stub = Self {
                reads: Arc::clone(&reads),
                answers: answers
                    .iter()
                    .map(|(host, instance, endpoint)| {
                        ((host.to_string(), *instance), endpoint.clone())
                    })
                    .collect(),
            };
            (Arc::new(stub), reads)
        }
    }

    #[async_trait::async_trait]
    impl AgentManager for EndpointStub {
        async fn request_customer_data_deletion(
            &self,
            _targets: &[crate::customer_data_deletion::CustomerDataDeletionTarget],
        ) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn data_store_read_endpoint(
            &self,
            hostname: &str,
            instance: u32,
        ) -> Result<DataStoreReadEndpoint, anyhow::Error> {
            self.reads
                .0
                .lock()
                .unwrap()
                .push((hostname.to_string(), instance));
            match self.answers.get(&(hostname.to_string(), instance)) {
                Some(endpoint) => Ok(endpoint.clone()),
                None => Err(anyhow::anyhow!(ENDPOINT_FAILURE).context("resolving the endpoint")),
            }
        }

        async fn send_agent_specific_internal_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn send_agent_specific_allow_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn send_agent_specific_block_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn online_apps_by_host_id(
            &self,
        ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn broadcast_crusher_sampling_policy(
            &self,
            _sampling_policies: &[SamplingPolicy],
        ) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn capabilities(
            &self,
            _hostname: &str,
        ) -> Result<std::collections::BTreeSet<String>, anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn get_resource_usage(
            &self,
            _hostname: &str,
        ) -> Result<review_protocol::types::ResourceUsage, anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn ping(&self, _hostname: &str) -> Result<std::time::Duration, anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }

        async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the endpoint read only")
        }
    }

    fn endpoint(server_name: &str, port: u16, addrs: &[&str]) -> DataStoreReadEndpoint {
        DataStoreReadEndpoint {
            server_name: server_name.to_string(),
            port,
            addrs: addrs
                .iter()
                .map(|addr| addr.parse::<IpAddr>().unwrap())
                .collect(),
        }
    }

    /// A Data Store row numbered `instance`, installed and `RUNNING`.
    fn data_store(host: &str, instance: u32) -> review_database::ExternalService {
        installed_service(
            &format!("giganto{instance}@{host}"),
            ExternalServiceKind::DataStore,
            None,
            Some(instance),
        )
    }

    fn data_store_with(
        host: &str,
        instance: u32,
        lifecycle: Lifecycle,
    ) -> review_database::ExternalService {
        let mut service = data_store(host, instance);
        service.lifecycle = lifecycle;
        service
    }

    async fn schema_with(
        answers: &[(&str, u32, DataStoreReadEndpoint)],
    ) -> (TestSchema, Arc<EndpointReads>) {
        let (stub, reads) = EndpointStub::boxed(answers);
        (
            TestSchema::new_with_params(stub, None, "testuser").await,
            reads,
        )
    }

    async fn endpoints(schema: &TestSchema) -> Value {
        let res = schema.execute_as_system_admin(QUERY).await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        res.data.into_json().unwrap()["dataStoreEndpoints"].clone()
    }

    #[tokio::test]
    async fn lists_one_store() {
        let host = "host1.example.com";
        let (schema, reads) = schema_with(&[(
            host,
            1,
            endpoint("001.giganto.host1.example.com", 8443, &["10.0.0.1", "::1"]),
        )])
        .await;
        put_node(
            &schema.store(),
            "n1",
            Some(host),
            vec![],
            vec![data_store(host, 1)],
        );

        assert_eq!(
            endpoints(&schema).await,
            json!([{
                "serverName": "001.giganto.host1.example.com",
                "port": 8443,
                "addrs": ["10.0.0.1", "::1"],
            }])
        );
        assert_eq!(reads.count(), 1);
    }

    #[tokio::test]
    async fn no_data_store_row_is_empty_without_backend_call() {
        let host = "host1.example.com";
        let (schema, reads) = schema_with(&[]).await;
        let mut ti_container = installed_service(
            "ti@host1.example.com",
            ExternalServiceKind::TiContainer,
            None,
            Some(1),
        );
        // A non-`DATA_STORE` row stays absent even with an identity set.
        ti_container.installed_version = Some("1.0.0".to_string());
        ti_container.installed_commit = Some("abcdef".to_string());
        ti_container.lifecycle = Lifecycle::Running;
        put_node(
            &schema.store(),
            "n1",
            Some(host),
            vec![],
            vec![ti_container],
        );

        assert_eq!(endpoints(&schema).await, json!([]));
        assert_eq!(reads.count(), 0);
    }

    #[tokio::test]
    async fn lists_stores_of_other_customers() {
        let host = "host2.example.com";
        let (schema, _reads) = schema_with(&[(
            host,
            1,
            endpoint("001.giganto.host2.example.com", 8443, &["10.0.0.2"]),
        )])
        .await;
        let node = Node {
            id: u32::MAX,
            name: "n2".to_string(),
            name_draft: Some("n2".to_string()),
            profile: Some(NodeProfile {
                customer_id: 2,
                description: String::new(),
                hostname: host.to_string(),
            }),
            profile_draft: None,
            agents: vec![],
            external_services: vec![data_store(host, 1)],
            creation_time: Utc::now(),
        };
        schema.store().node_map().put(&node).unwrap();

        let res = schema
            .execute_as_scoped_user(QUERY, Role::SecurityMonitor, Some(vec![1]))
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap()["dataStoreEndpoints"],
            json!([{
                "serverName": "001.giganto.host2.example.com",
                "port": 8443,
                "addrs": ["10.0.0.2"],
            }])
        );
    }

    #[tokio::test]
    async fn sorts_by_server_name() {
        let (schema, _reads) = schema_with(&[
            (
                "zz.example.com",
                1,
                endpoint("001.giganto.zz.example.com", 8443, &["10.0.0.26"]),
            ),
            (
                "aa.example.com",
                1,
                endpoint("001.giganto.aa.example.com", 8444, &["10.0.0.1"]),
            ),
        ])
        .await;
        {
            let store = schema.store();
            put_node(
                &store,
                "a-node",
                Some("zz.example.com"),
                vec![],
                vec![data_store("zz.example.com", 1)],
            );
            put_node(
                &store,
                "b-node",
                Some("aa.example.com"),
                vec![],
                vec![data_store("aa.example.com", 1)],
            );
        }

        assert_eq!(
            endpoints(&schema).await,
            json!([
                {
                    "serverName": "001.giganto.aa.example.com",
                    "port": 8444,
                    "addrs": ["10.0.0.1"],
                },
                {
                    "serverName": "001.giganto.zz.example.com",
                    "port": 8443,
                    "addrs": ["10.0.0.26"],
                },
            ])
        );
    }

    #[tokio::test]
    async fn lists_every_installed_lifecycle() {
        for lifecycle in [
            Lifecycle::Installing,
            Lifecycle::Running,
            Lifecycle::Stopped,
            Lifecycle::Failed,
            Lifecycle::Unknown,
        ] {
            let host = "host1.example.com";
            let (schema, _reads) = schema_with(&[(
                host,
                1,
                endpoint("001.giganto.host1.example.com", 8443, &["10.0.0.1"]),
            )])
            .await;
            put_node(
                &schema.store(),
                "n1",
                Some(host),
                vec![],
                vec![data_store_with(host, 1, lifecycle)],
            );

            assert_eq!(
                endpoints(&schema).await,
                json!([{
                    "serverName": "001.giganto.host1.example.com",
                    "port": 8443,
                    "addrs": ["10.0.0.1"],
                }]),
                "lifecycle {lifecycle:?}"
            );
        }
    }

    #[tokio::test]
    async fn excludes_removing_and_not_installed() {
        for lifecycle in [Lifecycle::Removing, Lifecycle::NotInstalled] {
            let host = "host1.example.com";
            let (schema, reads) = schema_with(&[(
                host,
                1,
                endpoint("001.giganto.host1.example.com", 8443, &["10.0.0.1"]),
            )])
            .await;
            let service = data_store_with(host, 1, lifecycle);
            assert!(service.instance.is_some());
            assert!(service.installed_version.is_some());
            assert!(service.installed_commit.is_some());
            put_node(&schema.store(), "n1", Some(host), vec![], vec![service]);

            assert_eq!(
                endpoints(&schema).await,
                json!([]),
                "lifecycle {lifecycle:?}"
            );
            assert_eq!(reads.count(), 0, "lifecycle {lifecycle:?}");
        }
    }

    #[tokio::test]
    async fn excludes_row_without_instance() {
        let host = "host1.example.com";
        let (schema, reads) = schema_with(&[]).await;
        let mut service = installed_service(
            "giganto@host1.example.com",
            ExternalServiceKind::DataStore,
            None,
            None,
        );
        service.installed_version = Some("1.0.0".to_string());
        service.installed_commit = Some("abcdef".to_string());
        service.lifecycle = Lifecycle::Running;
        put_node(&schema.store(), "n1", Some(host), vec![], vec![service]);

        assert_eq!(endpoints(&schema).await, json!([]));
        assert_eq!(reads.count(), 0);
    }

    #[tokio::test]
    async fn excludes_row_without_version() {
        let host = "host1.example.com";
        let (schema, reads) = schema_with(&[]).await;
        let mut service = data_store(host, 1);
        service.installed_version = None;
        assert_eq!(service.lifecycle, Lifecycle::Running);
        put_node(&schema.store(), "n1", Some(host), vec![], vec![service]);

        assert_eq!(endpoints(&schema).await, json!([]));
        assert_eq!(reads.count(), 0);
    }

    #[tokio::test]
    async fn excludes_node_without_profile() {
        let (schema, reads) = schema_with(&[]).await;
        put_node(
            &schema.store(),
            "n1",
            None,
            vec![],
            vec![data_store("host1.example.com", 1)],
        );

        assert_eq!(endpoints(&schema).await, json!([]));
        assert_eq!(reads.count(), 0);
    }

    #[tokio::test]
    async fn backend_error_affects_only_its_element() {
        let (schema, reads) = schema_with(&[(
            "good.example.com",
            1,
            endpoint("001.giganto.good.example.com", 8443, &["10.0.0.1"]),
        )])
        .await;
        {
            let store = schema.store();
            put_node(
                &store,
                "good",
                Some("good.example.com"),
                vec![],
                vec![data_store("good.example.com", 1)],
            );
            put_node(
                &store,
                "bad",
                Some("bad.example.com"),
                vec![],
                vec![data_store("bad.example.com", 7)],
            );
        }

        assert_eq!(
            endpoints(&schema).await,
            json!([
                {
                    "serverName": "001.giganto.good.example.com",
                    "port": 8443,
                    "addrs": ["10.0.0.1"],
                },
                {
                    "serverName": "007.giganto.bad.example.com",
                    "port": 0,
                    "addrs": [],
                },
            ])
        );
        assert_eq!(reads.count(), 2);
    }

    /// An embedding without a Data Store plane keeps the trait's default,
    /// which refuses every read; the query still succeeds.
    #[tokio::test]
    async fn default_backend_yields_empty_endpoints() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            put_node(
                &store,
                "n1",
                Some("host1.example.com"),
                vec![],
                vec![data_store("host1.example.com", 1)],
            );
            put_node(
                &store,
                "n2",
                Some("host2.example.com"),
                vec![],
                vec![data_store("host2.example.com", 2)],
            );
        }

        assert_eq!(
            endpoints(&schema).await,
            json!([
                {
                    "serverName": "001.giganto.host1.example.com",
                    "port": 0,
                    "addrs": [],
                },
                {
                    "serverName": "002.giganto.host2.example.com",
                    "port": 0,
                    "addrs": [],
                },
            ])
        );
    }

    #[tokio::test]
    async fn refuses_unauthenticated() {
        let host = "host1.example.com";
        let (schema, reads) = schema_with(&[(
            host,
            1,
            endpoint("001.giganto.host1.example.com", 8443, &["10.0.0.1"]),
        )])
        .await;
        put_node(
            &schema.store(),
            "n1",
            Some(host),
            vec![],
            vec![data_store(host, 1)],
        );

        let res = schema.schema.execute(QUERY).await;
        assert_eq!(res.errors.len(), 1, "errors: {:?}", res.errors);
        assert_eq!(res.errors[0].message, "Forbidden");

        assert_eq!(reads.count(), 0);
    }
}
