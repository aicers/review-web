//! Exercises the allowlist and blocklist payloads of `AgentManager` from
//! outside the crate.
//!
//! The embedding application is the real implementer: it reads each list's
//! items and target lookup keys from the payload and converts them to the
//! engine protocol itself. An integration test is compiled as another crate,
//! so the constructors, the readers and the trait signatures have to work
//! from here.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Mutex,
    time::Duration,
};

use async_trait::async_trait;
use review_database::{HostNetworkGroup, NetworkListEntry, Store};
use review_web::{
    backend::{AgentManager, ResourceUsage},
    customer_data_deletion::CustomerDataDeletionTarget,
    graphql::{
        NetworkListItemsTargetAgentLookupKeysPair, NetworksTargetAgentLookupKeysPair,
        get_allow_networks, get_block_networks,
    },
};

const CUSTOMER_ID: u32 = 7;
/// Above 2^53, where a JSON number would lose precision.
const WIDE_ID: u64 = (1 << 53) + 1;
const HOG: &str = "hog";

/// One received payload: the target lookup keys and the `(id, name, group)`
/// of each item, in order.
type Received = (Vec<String>, Vec<(u64, String, HostNetworkGroup)>);

/// An implementer living outside the crate, as the embedding application
/// does, that reads every allowlist and blocklist payload it receives.
#[derive(Default)]
struct OutsideAgentManager {
    allow: Mutex<Vec<Received>>,
    block: Mutex<Vec<Received>>,
}

/// Reads each payload field by field, as an implementer converting the items
/// to its own protocol would.
fn read(pairs: &[NetworkListItemsTargetAgentLookupKeysPair]) -> Vec<Received> {
    pairs
        .iter()
        .map(|pair| {
            let items = pair
                .items()
                .iter()
                .map(|item| (item.id, item.name.clone(), item.group.clone()))
                .collect();
            (pair.target_agent_lookup_keys().to_vec(), items)
        })
        .collect()
}

fn sent_to(pairs: &[NetworkListItemsTargetAgentLookupKeysPair]) -> Vec<String> {
    pairs
        .iter()
        .flat_map(|pair| pair.target_agent_lookup_keys().iter().cloned())
        .collect()
}

#[async_trait]
impl AgentManager for OutsideAgentManager {
    async fn request_customer_data_deletion(
        &self,
        _targets: &[CustomerDataDeletionTarget],
    ) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn send_agent_specific_internal_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn send_agent_specific_allow_networks(
        &self,
        items: &[NetworkListItemsTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        self.allow
            .lock()
            .expect("no test thread panics while holding the lock")
            .extend(read(items));
        Ok(sent_to(items))
    }

    async fn send_agent_specific_block_networks(
        &self,
        items: &[NetworkListItemsTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        self.block
            .lock()
            .expect("no test thread panics while holding the lock")
            .extend(read(items));
        Ok(sent_to(items))
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
        Ok(HashMap::new())
    }

    async fn time_series_generation_policies_changed(
        &self,
        _generators: &[review_database::ModelInstance],
    ) {
    }

    async fn capabilities(&self, hostname: &str) -> Result<BTreeSet<String>, anyhow::Error> {
        anyhow::bail!("{hostname} is unreachable")
    }

    async fn get_resource_usage(&self, hostname: &str) -> Result<ResourceUsage, anyhow::Error> {
        anyhow::bail!("{hostname} is unreachable")
    }

    async fn halt(&self, hostname: &str) -> Result<(), anyhow::Error> {
        anyhow::bail!("{hostname} is unreachable")
    }

    async fn ping(&self, hostname: &str) -> Result<Duration, anyhow::Error> {
        anyhow::bail!("{hostname} is unreachable")
    }

    async fn reboot(&self, hostname: &str) -> Result<(), anyhow::Error> {
        anyhow::bail!("{hostname} is unreachable")
    }

    async fn update_config(&self, agent_lookup_key: &str) -> Result<(), anyhow::Error> {
        anyhow::bail!("{agent_lookup_key} is unreachable")
    }
}

fn group(hosts: &[&str], networks: &[&str]) -> HostNetworkGroup {
    HostNetworkGroup::new(
        hosts.iter().map(|h| h.parse().unwrap()).collect(),
        networks.iter().map(|n| n.parse().unwrap()).collect(),
        vec![],
    )
}

fn entry(id: u64, name: &str, group: HostNetworkGroup) -> NetworkListEntry {
    NetworkListEntry {
        id,
        name: name.to_string(),
        group,
    }
}

#[tokio::test]
async fn an_outside_agent_manager_reads_the_items_and_targets_of_both_lists() {
    let db_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
    // Not sorted by ID or name, so the order read back is the stored one.
    let allowlist = vec![
        entry(WIDE_ID, "partner", group(&["198.51.100.1"], &[])),
        entry(2, "office", group(&[], &["10.0.0.0/8"])),
    ];
    let blocklist = vec![entry(u64::MAX, "scanner", group(&["192.0.2.1"], &[]))];
    store
        .network_lists_map()
        .replace(CUSTOMER_ID, 1, allowlist, blocklist)
        .unwrap();

    let agent_lookup_keys = vec![
        "001.hog.node-01.customer.internal".to_string(),
        "001.piglet.node-01.customer.internal".to_string(),
        "002.hog.node-02.customer.internal".to_string(),
    ];
    let pair = |items| {
        NetworkListItemsTargetAgentLookupKeysPair::new(items, agent_lookup_keys.clone(), HOG)
    };
    let allow = pair(get_allow_networks(&store, CUSTOMER_ID).unwrap());
    let block = pair(get_block_networks(&store, CUSTOMER_ID).unwrap());
    // A customer with no stored lists is sent empty ones.
    let empty = pair(get_allow_networks(&store, CUSTOMER_ID + 1).unwrap());

    let manager = OutsideAgentManager::default();
    let agent_manager: &dyn AgentManager = &manager;
    let hogs = vec![
        "001.hog.node-01.customer.internal".to_string(),
        "002.hog.node-02.customer.internal".to_string(),
    ];
    assert_eq!(
        agent_manager
            .send_agent_specific_allow_networks(&[allow, empty])
            .await
            .unwrap(),
        [hogs.clone(), hogs.clone()].concat()
    );
    assert_eq!(
        agent_manager
            .send_agent_specific_block_networks(&[block])
            .await
            .unwrap(),
        hogs
    );

    assert_eq!(
        *manager.allow.lock().unwrap(),
        vec![
            (
                hogs.clone(),
                vec![
                    (
                        WIDE_ID,
                        "partner".to_string(),
                        group(&["198.51.100.1"], &[])
                    ),
                    (2, "office".to_string(), group(&[], &["10.0.0.0/8"])),
                ],
            ),
            (hogs.clone(), vec![]),
        ]
    );
    assert_eq!(
        *manager.block.lock().unwrap(),
        vec![(
            hogs,
            vec![(u64::MAX, "scanner".to_string(), group(&["192.0.2.1"], &[]))],
        )]
    );
}

#[test]
fn the_payload_round_trips_through_serde() {
    let pair = NetworkListItemsTargetAgentLookupKeysPair::new(
        vec![entry(WIDE_ID, "partner", group(&["198.51.100.1"], &[]))],
        vec!["001.hog.node-01.customer.internal".to_string()],
        HOG,
    );
    let decoded: NetworkListItemsTargetAgentLookupKeysPair =
        serde_json::from_str(&serde_json::to_string(&pair).unwrap()).unwrap();
    assert_eq!(decoded.items(), pair.items());
    assert_eq!(
        decoded.target_agent_lookup_keys(),
        pair.target_agent_lookup_keys()
    );
    assert_eq!(
        NetworkListItemsTargetAgentLookupKeysPair::default()
            .items()
            .len(),
        0
    );
}

/// The policies a generator is given are built and listed from outside the
/// crate, with review-protocol's types for the spec and review-web's slot and
/// window sizes, as the Central Manager converting them does.
#[test]
fn time_series_generation_policies_are_listed_and_read_outside_the_crate() {
    use review_protocol::types::{
        CounterpartScope, EndpointRole, GroupByUnit, Measure, RawEventKind, TimeSeriesTypeRef,
    };
    use review_web::graphql::{
        SlotSize, TimeSeriesGenerationPolicy, WindowSize,
        time_series_generation_policies_for_generator,
    };

    let db_dir = tempfile::tempdir().unwrap();
    let backup_dir = tempfile::tempdir().unwrap();
    let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
    let generator = review_database::ModelInstance {
        node_id: 0,
        agent_key: "crusher".to_string(),
    };
    let listed: Vec<TimeSeriesGenerationPolicy> =
        time_series_generation_policies_for_generator(&store, &generator).unwrap();
    assert_eq!(listed, Vec::new());

    let policy = TimeSeriesGenerationPolicy {
        id: 3,
        customer_id: CUSTOMER_ID,
        raw_event_kind: RawEventKind::Tls,
        measure: Measure::Count,
        group_by: Some(EndpointRole::Destination),
        group_by_unit: GroupByUnit::Ip,
        counterpart_scope: CounterpartScope::Any,
        slot_size: SlotSize::FiveMinutes,
        window_size: WindowSize::OneDay,
        utc_offset: 32_400,
        src_ip: None,
        dst_ip: None,
        sensors: vec!["piglet.a.example.com".to_string()],
        time_series_type: Some(TimeSeriesTypeRef {
            id: "server_daily_tls".to_string(),
            version: 1,
        }),
    };
    assert_eq!(policy.clone(), policy);
    assert_eq!(policy.sensors.len(), 1);
}
