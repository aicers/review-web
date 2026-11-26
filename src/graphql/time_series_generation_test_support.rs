//! Test support for time series generation policies: an `AgentManager` that
//! records the generators it is told about, and the nodes, generators, uses
//! and networks that policies need.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use review_database::{
    Agent, AgentKind, AgentStatus, CounterpartScope, EndpointRole, GroupByUnit, HostNetworkGroup,
    Lifecycle, Measure, ModelInstance, ModelMethod, NewTimeSeriesGenerationPolicy,
    NewTrainingDefinition, Node, NodeProfile, NodeUpdate, OwnedNetwork, RawEventKind, SlotSize,
    Store, TimeSeriesGenerationPolicy, TimeSeriesTypeRef, WindowSize, event::NetworkType,
};
use review_protocol::types::ResourceUsage;
use tempfile::TempDir;

use super::{
    AgentManager, SharedAgentManager,
    customer::{NetworkListItemsTargetAgentLookupKeysPair, NetworksTargetAgentLookupKeysPair},
    run_test_support::insert_data_store_node,
};

/// The agent key of the Time Series Generator of a node from
/// [`insert_generator_node`].
pub(super) const GENERATOR_KEY: &str = "crusher@test";
/// The agent key of the Sensor of a node from [`insert_generator_node`].
pub(super) const SENSOR_KEY: &str = "piglet@test";

/// Returns the sensor name of a node from [`insert_generator_node`].
pub(super) fn sensor_name(hostname: &str) -> String {
    format!("piglet.{hostname}")
}

/// Returns the Data Store name the generator of a node from
/// [`insert_generator_node`] is configured with.
pub(super) fn data_store_name(hostname: &str) -> String {
    format!("001.giganto.{hostname}")
}

/// Returns a Time Series Generator configuration naming the Data Store
/// `giganto_name`.
pub(super) fn generator_config(giganto_name: &str) -> String {
    format!("giganto_name = {giganto_name:?}\n")
}

fn agent(kind: AgentKind, key: &str, config: Option<String>) -> Agent {
    let config = config.map(|config| config.try_into().expect("a valid agent configuration"));
    Agent {
        node_id: u32::MAX,
        key: key.to_string(),
        kind,
        status: AgentStatus::Enabled,
        config: config.clone(),
        draft: config,
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

/// Stores the node `hostname` of `customer_id`, applied, with a Sensor
/// [`SENSOR_KEY`] and a Time Series Generator [`GENERATOR_KEY`] whose Data
/// Store is [`data_store_name`], and returns the generator.
pub(super) fn insert_generator_node(
    store: &Store,
    hostname: &str,
    customer_id: u32,
) -> ModelInstance {
    insert_generator_node_with(
        store,
        hostname,
        customer_id,
        Some(generator_config(&data_store_name(hostname))),
    )
}

/// Stores the node [`insert_generator_node`] stores, with `config` as the
/// generator's applied configuration and draft, and returns the generator.
pub(super) fn insert_generator_node_with(
    store: &Store,
    hostname: &str,
    customer_id: u32,
    config: Option<String>,
) -> ModelInstance {
    let profile = NodeProfile {
        customer_id,
        description: String::new(),
        hostname: hostname.to_string(),
    };
    let node = Node {
        id: u32::MAX,
        name: hostname.to_string(),
        name_draft: Some(hostname.to_string()),
        profile: Some(profile.clone()),
        profile_draft: Some(profile),
        agents: vec![
            // A draft equal to the config keeps an apply from removing it.
            agent(AgentKind::Sensor, SENSOR_KEY, Some(String::new())),
            agent(AgentKind::TimeSeriesGenerator, GENERATOR_KEY, config),
        ],
        external_services: vec![],
        creation_time: jiff::Timestamp::now(),
    };
    let node_id = store.node_map().put(&node).expect("insert generator node");
    ModelInstance {
        node_id,
        agent_key: GENERATOR_KEY.to_string(),
    }
}

/// The shape of a policy from [`insert_shaped_policy`].
#[derive(Clone, Copy)]
pub(super) struct PolicyShape {
    pub(super) raw_event_kind: RawEventKind,
    pub(super) measure: Measure,
    pub(super) group_by: Option<EndpointRole>,
    pub(super) group_by_unit: GroupByUnit,
    pub(super) counterpart_scope: CounterpartScope,
    pub(super) slot_size: SlotSize,
    pub(super) window_size: WindowSize,
    pub(super) utc_offset: i32,
}

impl Default for PolicyShape {
    /// An ungrouped `Conn` count, which needs no customer network.
    fn default() -> Self {
        Self {
            raw_event_kind: RawEventKind::Conn,
            measure: Measure::Count,
            group_by: None,
            group_by_unit: GroupByUnit::Ip,
            counterpart_scope: CounterpartScope::Any,
            slot_size: SlotSize::FifteenMinutes,
            window_size: WindowSize::OneDay,
            utc_offset: 0,
        }
    }
}

impl PolicyShape {
    /// The default shape grouped by `group_by`, which needs an internal
    /// network of the policy's customer; see [`insert_internal_network`].
    pub(super) fn grouped(group_by: EndpointRole) -> Self {
        Self {
            group_by: Some(group_by),
            ..Self::default()
        }
    }

    /// The shape of the daily TLS time-series types, `server_daily_tls` with
    /// [`EndpointRole::Destination`] and `host_daily_tls` with
    /// [`EndpointRole::Source`]: a 5-minute count of TLS events grouped by
    /// `group_by`, which needs an internal network of the policy's customer.
    pub(super) fn daily_tls(group_by: EndpointRole) -> Self {
        Self {
            raw_event_kind: RawEventKind::Tls,
            group_by: Some(group_by),
            slot_size: SlotSize::FiveMinutes,
            ..Self::default()
        }
    }
}

/// Returns a reference to the time-series type `id` at `version`.
pub(super) fn type_ref(id: &str, version: u32) -> TimeSeriesTypeRef {
    TimeSeriesTypeRef {
        id: id.to_string(),
        version,
    }
}

/// Stores `10.0.0.0/8` as the only network of `customer_id`, an `Intranet`
/// network, so its policies can group by an endpoint.
pub(super) fn insert_internal_network(store: &Store, customer_id: u32) {
    store_networks(store, customer_id, NetworkType::Intranet);
}

/// Stores `10.0.0.0/8` as the only network of `customer_id`, of
/// `network_type`.
pub(super) fn store_networks(store: &Store, customer_id: u32, network_type: NetworkType) {
    let network = OwnedNetwork {
        name: "office".to_string(),
        network_type,
        group: HostNetworkGroup::new(
            vec![],
            vec!["10.0.0.0/8".parse().expect("a valid network")],
            vec![],
        ),
    };
    let revision = store
        .customer_networks_map()
        .get(customer_id)
        .expect("read customer networks")
        .map_or(1, |set| set.revision + 1);
    store
        .customer_networks_map()
        .replace(customer_id, revision, vec![network])
        .expect("store customer networks");
}

/// Stores a draft policy `name` of `customer_id` reading `sensor`, and
/// returns its ID.
pub(super) fn insert_policy(store: &Store, name: &str, customer_id: u32, sensor: &str) -> u32 {
    insert_shaped_policy(store, name, customer_id, &[sensor], PolicyShape::default())
}

/// Stores a draft custom policy `name` of `customer_id` reading `sensors`
/// with `shape`, and returns its ID.
pub(super) fn insert_shaped_policy(
    store: &Store,
    name: &str,
    customer_id: u32,
    sensors: &[&str],
    shape: PolicyShape,
) -> u32 {
    insert_policy_of(store, name, customer_id, sensors, shape, None)
}

/// Stores a draft policy `name` of `customer_id` reading `sensors` with
/// `shape`, made from the time-series type `time_series_type` or custom with
/// `None`, and returns its ID. A type's policy must have the type's shape.
pub(super) fn insert_policy_of(
    store: &Store,
    name: &str,
    customer_id: u32,
    sensors: &[&str],
    shape: PolicyShape,
    time_series_type: Option<TimeSeriesTypeRef>,
) -> u32 {
    store
        .time_series_generation_policy_map()
        .insert(NewTimeSeriesGenerationPolicy {
            name: name.to_string(),
            raw_event_kind: shape.raw_event_kind,
            measure: shape.measure,
            group_by: shape.group_by,
            group_by_unit: shape.group_by_unit,
            counterpart_scope: shape.counterpart_scope,
            slot_size: shape.slot_size,
            window_size: shape.window_size,
            utc_offset: shape.utc_offset,
            src_ip: None,
            dst_ip: None,
            sensors: sensors.iter().map(ToString::to_string).collect(),
            time_series_type,
            customer_id,
        })
        .expect("insert policy")
}

/// Stores a policy `name` of `customer_id` with `shape`, reading the sensor
/// of the node of `generator` and assigned to it, and returns its ID.
pub(super) fn insert_assigned_policy(
    store: &Store,
    name: &str,
    customer_id: u32,
    generator: &ModelInstance,
    shape: PolicyShape,
) -> u32 {
    insert_assigned_policy_of(store, name, customer_id, generator, shape, None)
}

/// Stores a policy `name` of `customer_id` with `shape`, made from
/// `time_series_type` or custom with `None`, reading the sensor of the node
/// of `generator` and assigned to it, and returns its ID.
pub(super) fn insert_assigned_policy_of(
    store: &Store,
    name: &str,
    customer_id: u32,
    generator: &ModelInstance,
    shape: PolicyShape,
    time_series_type: Option<TimeSeriesTypeRef>,
) -> u32 {
    let (node, _, _) = store
        .node_map()
        .get_by_id(generator.node_id)
        .expect("read generator node")
        .expect("generator node exists");
    let hostname = node.profile.expect("generator node is applied").hostname;
    let id = insert_policy_of(
        store,
        name,
        customer_id,
        &[&sensor_name(&hostname)],
        shape,
        time_series_type,
    );
    store
        .time_series_generation_policy_map()
        .assign(id, Some(generator), true)
        .expect("assign policy");
    id
}

/// Replaces the applied configuration and the draft of the generator
/// `generator` with `config`, leaving its policies as they are.
pub(super) fn set_generator_config(
    store: &Store,
    generator: &ModelInstance,
    config: Option<String>,
) {
    let mut map = store.node_map();
    let (node, _, _) = map
        .get_by_id(generator.node_id)
        .expect("read generator node")
        .expect("generator node exists");
    let old = NodeUpdate::from(node.clone());
    let mut new = NodeUpdate::from(node);
    let config = config.map(|config| config.try_into().expect("a valid agent configuration"));
    for agent in &mut new.agents {
        if agent.key == generator.agent_key {
            agent.config.clone_from(&config);
            agent.draft.clone_from(&config);
        }
    }
    map.update(generator.node_id, &old, &new)
        .expect("update generator configuration");
}

/// Returns a timeseries training definition reading the policies `sources`
/// from the Data Store `server_name` at `address`, with `extra` top-level
/// lines.
pub(super) fn timeseries_definition(
    sources: &[u32],
    server_name: &str,
    address: &str,
    extra: &str,
) -> String {
    let sources: Vec<String> = sources.iter().map(ToString::to_string).collect();
    let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
    crate::graphql::training_test_support::custom_timeseries_definition(
        &sources,
        server_name,
        address,
        extra,
    )
}

/// Puts the policy `id` in use: the timeseries training definition `name` of
/// `customer_id`, on the engine instance `engine`, names it as a source.
pub(super) fn use_policy(
    store: &Store,
    name: &str,
    customer_id: u32,
    engine: &ModelInstance,
    id: u32,
) {
    store
        .insert_training_definition(NewTrainingDefinition {
            name: name.to_string(),
            customer_id,
            instance: engine.clone(),
            method: ModelMethod::Timeseries,
            raw_event_kind: "conn".to_string(),
            log_kind: None,
            sources: vec![id.to_string()],
            indicator: None,
            clustering_model_type: review_database::ClusteringModelTypeRef::Custom,
            definition: String::new(),
        })
        .expect("insert training definition");
}

/// The calls a [`DeliveryRecorder`] received when it received none.
pub(super) const NO_DELIVERIES: [Vec<ModelInstance>; 0] = [];

/// The calls of `time_series_generation_policies_changed` a [`DeliveryRecorder`] received,
/// in order.
#[derive(Clone, Default)]
pub(super) struct Deliveries(Arc<Mutex<Vec<Vec<ModelInstance>>>>);

impl Deliveries {
    /// Returns the generators of each call.
    pub(super) fn calls(&self) -> Vec<Vec<ModelInstance>> {
        self.0
            .lock()
            .expect("no test thread panics while holding the lock")
            .clone()
    }
}

/// An `AgentManager` that records every `time_series_generation_policies_changed` call,
/// reaching no generator, accepts every configuration update, and refuses
/// everything else.
pub(super) struct DeliveryRecorder {
    deliveries: Deliveries,
}

impl DeliveryRecorder {
    pub(super) fn boxed() -> (SharedAgentManager, Deliveries) {
        let deliveries = Deliveries::default();
        let manager = Self {
            deliveries: deliveries.clone(),
        };
        (Arc::new(manager), deliveries)
    }
}

#[async_trait]
impl AgentManager for DeliveryRecorder {
    async fn request_customer_data_deletion(
        &self,
        _targets: &[crate::customer_data_deletion::CustomerDataDeletionTarget],
    ) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn send_agent_specific_internal_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("no agent is connected")
    }

    async fn send_agent_specific_exclusion_list(
        &self,
        _networks: &[NetworkListItemsTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("no agent is connected")
    }

    async fn send_agent_specific_watchlist(
        &self,
        _networks: &[NetworkListItemsTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("no agent is connected")
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
        Ok(HashMap::new())
    }

    async fn time_series_generation_policies_changed(&self, generators: &[ModelInstance]) {
        self.deliveries
            .0
            .lock()
            .expect("no test thread panics while holding the lock")
            .push(generators.to_vec());
    }

    async fn capabilities(&self, _hostname: &str) -> Result<BTreeSet<String>, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn get_resource_usage(&self, _hostname: &str) -> Result<ResourceUsage, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn ping(&self, _hostname: &str) -> Result<Duration, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

/// The customer of the policies of a [`PolicyFixture`].
pub(super) const POLICY_CUSTOMER: u32 = 1;
/// The other customer of a [`PolicyFixture`].
pub(super) const OTHER_POLICY_CUSTOMER: u32 = 2;
/// An address of the first Data Store of a [`PolicyFixture`].
pub(super) const OWN_ADDRESS: &str = "10.0.0.5:38371";

/// A store with two Data Stores of [`POLICY_CUSTOMER`], a Time Series
/// Generator of each of [`POLICY_CUSTOMER`] and [`OTHER_POLICY_CUSTOMER`]
/// writing to the first, one of [`POLICY_CUSTOMER`] writing to the second,
/// and two policies of [`POLICY_CUSTOMER`] of the default shape assigned to
/// the first generator.
pub(super) struct PolicyFixture {
    _db: TempDir,
    _backup: TempDir,
    pub(super) store: Store,
    /// The first Data Store, on `store.example.com`.
    pub(super) server_name: String,
    /// The second Data Store, on `store2.example.com`.
    pub(super) other_server_name: String,
    /// The generator on `gen-a.example.com`.
    pub(super) generator: ModelInstance,
    /// The generator on `gen-a2.example.com`.
    pub(super) other_generator: ModelInstance,
    /// The generator on `gen-b.example.com`.
    pub(super) generator_b: ModelInstance,
    pub(super) assigned: [u32; 2],
}

impl PolicyFixture {
    pub(super) fn new() -> Self {
        let db = tempfile::tempdir().expect("create a database directory");
        let backup = tempfile::tempdir().expect("create a backup directory");
        let store = Store::new(db.path(), backup.path(), None).expect("open a store");
        let server_name = insert_data_store_node(&store, POLICY_CUSTOMER, "store.example.com");
        let other_server_name =
            insert_data_store_node(&store, POLICY_CUSTOMER, "store2.example.com");
        let generator = insert_generator_node_with(
            &store,
            "gen-a.example.com",
            POLICY_CUSTOMER,
            Some(generator_config(&server_name)),
        );
        let other_generator = insert_generator_node_with(
            &store,
            "gen-a2.example.com",
            POLICY_CUSTOMER,
            Some(generator_config(&other_server_name)),
        );
        let generator_b = insert_generator_node_with(
            &store,
            "gen-b.example.com",
            OTHER_POLICY_CUSTOMER,
            Some(generator_config(&server_name)),
        );
        let assigned = ["p1", "p2"].map(|name| {
            insert_assigned_policy(
                &store,
                name,
                POLICY_CUSTOMER,
                &generator,
                PolicyShape::default(),
            )
        });
        Self {
            _db: db,
            _backup: backup,
            store,
            server_name,
            other_server_name,
            generator,
            other_generator,
            generator_b,
            assigned,
        }
    }

    /// Returns a timeseries definition reading `sources` from the first Data
    /// Store at [`OWN_ADDRESS`].
    pub(super) fn definition(&self, sources: &[u32]) -> String {
        timeseries_definition(sources, &self.server_name, OWN_ADDRESS, "")
    }

    /// Stores a policy of [`POLICY_CUSTOMER`] of `shape` assigned to
    /// `generator`, and returns its ID.
    pub(super) fn assigned_policy(
        &self,
        name: &str,
        generator: &ModelInstance,
        shape: PolicyShape,
    ) -> u32 {
        insert_assigned_policy(&self.store, name, POLICY_CUSTOMER, generator, shape)
    }

    /// Closes the store, overwrites the row `key` of the table
    /// `column_family` with a value that does not decode, and opens the
    /// store again, so that reading that record fails while every other
    /// record reads as before.
    pub(super) fn with_undecodable_row(self, column_family: &str, key: &str) -> Self {
        self.with_row(column_family, key, &[0xff])
    }

    /// Closes the store, rewrites the stored policy `id` as `edit` changes
    /// it, bypassing every check of the policy table, and opens the store
    /// again. It stores what the table's writes refuse, such as a policy of
    /// a type version the catalog no longer has.
    pub(super) fn with_policy_edited(
        self,
        id: u32,
        edit: impl FnOnce(&mut TimeSeriesGenerationPolicy),
    ) -> Self {
        use bincode::Options;

        // The policy table's name in review-database, and its encoding.
        const POLICY_TABLE: &str = "time series generation policy";
        let mut policy = self
            .store
            .time_series_generation_policy_map()
            .get_by_id(id)
            .expect("read the policy")
            .expect("the policy exists");
        edit(&mut policy);
        let value = bincode::DefaultOptions::new()
            .serialize(&policy)
            .expect("a policy serializes");
        let name = policy.name.clone();
        let edited = self.with_row(POLICY_TABLE, &name, &value);
        assert_eq!(
            edited
                .store
                .time_series_generation_policy_map()
                .get_by_id(id)
                .expect("read the edited policy")
                .as_ref(),
            Some(&policy),
            "the edited policy reads back"
        );
        edited
    }

    /// Closes the store, overwrites the row `key` of the table
    /// `column_family` with `value`, and opens the store again.
    fn with_row(self, column_family: &str, key: &str, value: &[u8]) -> Self {
        const STATES_DIRECTORY: &str = "states.db";

        let Self {
            _db: db,
            _backup: backup,
            store,
            ..
        } = self;
        drop(store);
        {
            // Every column family of an existing database has to be opened
            // with it.
            let path = db.path().join(STATES_DIRECTORY);
            let options = rocksdb::Options::default();
            let column_families =
                rocksdb::DB::list_cf(&options, &path).expect("list the column families");
            let raw = rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open_cf(
                &options,
                &path,
                column_families,
            )
            .expect("open the closed store");
            let handle = raw.cf_handle(column_family).expect("the table exists");
            raw.put_cf(handle, key.as_bytes(), value)
                .expect("overwrite the row");
        }
        let store = Store::new(db.path(), backup.path(), None).expect("open the store again");
        Self {
            _db: db,
            _backup: backup,
            store,
            ..self
        }
    }
}
