use std::{collections::HashMap, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use review_database::{Role, types};
use roxy::ResourceUsage;

use crate::graphql::{AgentManager, SamplingPolicy, customer::NetworksTargetAgentKeysPair};

pub(super) struct MockAgentManager {
    pub(super) online_apps_by_host_id: HashMap<String, Vec<(String, String)>>,
}

#[async_trait]
impl AgentManager for MockAgentManager {
    async fn send_agent_specific_internal_networks(
        &self,
        _networks: &[NetworksTargetAgentKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn send_agent_specific_allow_networks(
        &self,
        _networks: &[NetworksTargetAgentKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        unimplemented!()
    }

    async fn send_agent_specific_block_networks(
        &self,
        _networks: &[NetworksTargetAgentKeysPair],
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

    async fn update_config(&self, _agent_key: &str) -> Result<(), anyhow::Error> {
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
