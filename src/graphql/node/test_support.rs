use std::{collections::HashMap, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use review_database::{Role, types};
use roxy::ResourceUsage;

use crate::graphql::{AgentManager, SamplingPolicy, customer::NetworksTargetAgentLookupKeysPair};

pub(super) struct MockAgentManager {
    pub(super) online_apps_by_host_id: HashMap<String, Vec<(String, String)>>,
}

#[async_trait]
impl AgentManager for MockAgentManager {
    #[cfg(feature = "auth-mtls")]
    async fn request_customer_data_deletion(
        &self,
        _targets: &[crate::customer_data_deletion::CustomerDataDeletionTarget],
    ) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    async fn send_agent_specific_internal_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn send_agent_specific_allow_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        unimplemented!()
    }

    async fn send_agent_specific_block_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        unimplemented!()
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
        Ok(self.online_apps_by_host_id.clone())
    }

    async fn broadcast_crusher_sampling_policy(
        &self,
        _sampling_policies: &[SamplingPolicy],
    ) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    async fn capabilities(
        &self,
        _hostname: &str,
    ) -> Result<std::collections::BTreeSet<String>, anyhow::Error> {
        unimplemented!()
    }

    async fn get_process_list(&self, _hostname: &str) -> Result<Vec<roxy::Process>, anyhow::Error> {
        unimplemented!()
    }

    async fn get_resource_usage(
        &self,
        _hostname: &str,
    ) -> Result<roxy::ResourceUsage, anyhow::Error> {
        Ok(ResourceUsage {
            cpu_usage: 20.0,
            total_memory: 1000,
            used_memory: 100,
            disk_used_bytes: 100,
            disk_available_bytes: 900,
        })
    }

    async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    async fn ping(&self, _hostname: &str) -> Result<Duration, anyhow::Error> {
        Ok(Duration::from_micros(10))
    }

    async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        unimplemented!()
    }

    async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

pub(super) fn insert_apps(
    host: &str,
    apps: &[&str],
    map: &mut HashMap<String, Vec<(String, String)>>,
) {
    let entries = apps
        .iter()
        .map(|&app| (format!("{app}@{host}"), app.to_string()))
        .collect();
    map.insert(host.to_string(), entries);
}

pub(super) fn create_account_with_customers(
    store: &review_database::Store,
    username: &str,
    customer_ids: Option<Vec<u32>>,
) {
    let account = types::Account::new(
        username,
        "password",
        Role::SecurityAdministrator,
        "Test User".to_string(),
        "Testing".to_string(),
        None,
        None,
        None,
        None,
        customer_ids,
    )
    .expect("create account");
    store
        .account_map()
        .insert(&account)
        .expect("insert account");
}

pub(super) fn update_account_customers(
    store: &review_database::Store,
    username: &str,
    customer_ids: Option<Vec<u32>>,
) {
    let account_map = store.account_map();
    let _ = account_map.delete(username);
    create_account_with_customers(store, username, customer_ids);
}

pub(super) fn insert_active_node(
    store: &review_database::Store,
    name: &str,
    customer_id: u32,
    hostname: &str,
) -> u32 {
    let node = review_database::Node {
        id: u32::MAX,
        name: name.to_string(),
        name_draft: Some(name.to_string()),
        profile: Some(review_database::NodeProfile {
            customer_id,
            description: format!("Node for customer {customer_id}"),
            hostname: hostname.to_string(),
        }),
        profile_draft: None,
        agents: vec![],
        external_services: vec![],
        creation_time: Utc::now(),
    };
    store.node_map().put(&node).expect("insert node")
}

/// Returns an agent whose `config` and `draft` are both `config`, numbered
/// with `instance` as `REview`'s install path would number it.
pub(super) fn installed_agent(
    key: &str,
    kind: review_database::AgentKind,
    config: Option<&str>,
    instance: Option<u32>,
) -> review_database::Agent {
    review_database::Agent {
        node_id: u32::MAX,
        key: key.to_string(),
        kind,
        status: review_database::AgentStatus::Enabled,
        config: config.map(|c| c.to_string().try_into().expect("valid toml")),
        draft: config.map(|c| c.to_string().try_into().expect("valid toml")),
        installed_version: instance.map(|_| "1.0.0".to_string()),
        installed_commit: instance.map(|_| "abcdef".to_string()),
        lifecycle: if instance.is_some() {
            review_database::Lifecycle::Running
        } else {
            review_database::Lifecycle::NotInstalled
        },
        bound_addrs: vec![],
        instance,
    }
}

/// Returns an external service with `draft`, numbered with `instance`.
pub(super) fn installed_service(
    key: &str,
    kind: review_database::ExternalServiceKind,
    draft: Option<&str>,
    instance: Option<u32>,
) -> review_database::ExternalService {
    review_database::ExternalService {
        node_id: u32::MAX,
        key: key.to_string(),
        kind,
        status: review_database::ExternalServiceStatus::Enabled,
        draft: draft.map(|d| d.to_string().try_into().expect("valid toml")),
        installed_version: instance.map(|_| "1.0.0".to_string()),
        installed_commit: instance.map(|_| "abcdef".to_string()),
        lifecycle: if instance.is_some() {
            review_database::Lifecycle::Running
        } else {
            review_database::Lifecycle::NotInstalled
        },
        bound_addrs: vec![],
        instance,
    }
}

/// Stores a node whose `profile` and `profile_draft` both carry `hostname`,
/// or are both `None` when `hostname` is `None`.
pub(super) fn put_node(
    store: &review_database::Store,
    name: &str,
    hostname: Option<&str>,
    agents: Vec<review_database::Agent>,
    external_services: Vec<review_database::ExternalService>,
) -> u32 {
    let profile = hostname.map(|hostname| review_database::NodeProfile {
        customer_id: 0,
        description: "description".to_string(),
        hostname: hostname.to_string(),
    });
    let node = review_database::Node {
        id: u32::MAX,
        name: name.to_string(),
        name_draft: Some(name.to_string()),
        profile: profile.clone(),
        profile_draft: profile,
        agents,
        external_services,
        creation_time: Utc::now(),
    };
    store.node_map().put(&node).expect("insert node")
}

/// Reads a stored node, failing the test when it is missing.
pub(super) fn stored_node(store: &review_database::Store, id: u32) -> review_database::Node {
    store
        .node_map()
        .get_by_id(id)
        .expect("read node")
        .expect("node exists")
        .0
}

fn literal(value: &str) -> String {
    serde_json::to_string(value).expect("a string serializes")
}

fn optional_literal(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), literal)
}

fn profile_literal(profile: Option<&review_database::NodeProfile>) -> String {
    profile.map_or_else(
        || "null".to_string(),
        |p| {
            format!(
                "{{ customerId: \"{}\", description: {}, hostname: {} }}",
                p.customer_id,
                literal(&p.description),
                literal(&p.hostname)
            )
        },
    )
}

fn agent_kind(kind: review_database::AgentKind) -> String {
    async_graphql::InputType::to_value(&super::AgentKind::from(kind)).to_string()
}

fn service_kind(kind: review_database::ExternalServiceKind) -> String {
    async_graphql::InputType::to_value(&super::ExternalServiceKind::from(kind)).to_string()
}

fn status(status: review_database::AgentStatus) -> String {
    async_graphql::InputType::to_value(&super::AgentStatus::from(status)).to_string()
}

fn services_literal(services: &[review_database::ExternalService]) -> String {
    let services = services
        .iter()
        .map(|s| {
            format!(
                "{{ key: {}, kind: {}, status: {}, draft: {} }}",
                literal(&s.key),
                service_kind(s.kind),
                status(s.status),
                optional_literal(s.draft.as_ref().map(AsRef::as_ref))
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{services}]")
}

/// Renders `node` as a GraphQL `NodeInput` literal.
pub(super) fn node_input(node: &review_database::Node) -> String {
    let agents = node
        .agents
        .iter()
        .map(|a| {
            format!(
                "{{ key: {}, kind: {}, status: {}, config: {}, draft: {} }}",
                literal(&a.key),
                agent_kind(a.kind),
                status(a.status),
                optional_literal(a.config.as_ref().map(AsRef::as_ref)),
                optional_literal(a.draft.as_ref().map(AsRef::as_ref))
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{ name: {}, nameDraft: {}, profile: {}, profileDraft: {}, agents: [{agents}], \
         externalServices: {} }}",
        literal(&node.name),
        optional_literal(node.name_draft.as_deref()),
        profile_literal(node.profile.as_ref()),
        profile_literal(node.profile_draft.as_ref()),
        services_literal(&node.external_services)
    )
}

/// Renders `node` as a GraphQL `NodeDraftInput` literal, leaving out the
/// `agents` or `externalServices` argument when asked to.
pub(super) fn node_draft_input(
    node: &review_database::Node,
    with_agents: bool,
    with_services: bool,
) -> String {
    let mut fields = vec![
        format!(
            "nameDraft: {}",
            literal(node.name_draft.as_deref().unwrap_or(&node.name))
        ),
        format!(
            "profileDraft: {}",
            profile_literal(node.profile_draft.as_ref())
        ),
    ];
    if with_agents {
        let agents = node
            .agents
            .iter()
            .map(|a| {
                format!(
                    "{{ key: {}, kind: {}, status: {}, draft: {} }}",
                    literal(&a.key),
                    agent_kind(a.kind),
                    status(a.status),
                    optional_literal(a.draft.as_ref().map(AsRef::as_ref))
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        fields.push(format!("agents: [{agents}]"));
    }
    if with_services {
        fields.push(format!(
            "externalServices: {}",
            services_literal(&node.external_services)
        ));
    }
    format!("{{ {} }}", fields.join(", "))
}
