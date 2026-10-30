//! Mapping between nodes and the sensor names their events carry.
//!
//! Under bootroot, Giganto names an event's sensor after the sensor's
//! service FQDN, `<service>.<hostname>.<domain>`, which is the node's
//! `profile.hostname` prefixed with the service name of its sensor agent
//! (for example `piglet.sensor.example.com`). The node hostname alone never
//! matches `Event.sensor`.

use std::collections::{HashMap, HashSet};

use async_graphql::Result;
use review_database::{AgentKind, Node, Store, event::Direction};

/// Returns the sensor names events emitted by the sensor agents of `node`
/// carry.
///
/// The names are derived from the applied profile only; a node without one,
/// or with an empty hostname, has none. A node with at least one
/// `Sensor`-kind agent, configured or not, yields
/// `<package id>.<hostname>`; several sensor instances on one node still
/// share that one name. `Agent.key` has no defined format and is not parsed.
#[must_use]
pub(crate) fn event_sensor_names(node: &Node) -> Vec<String> {
    let Some(profile) = node.profile.as_ref() else {
        return Vec::new();
    };
    if profile.hostname.is_empty() {
        return Vec::new();
    }
    let has_sensor = node
        .agents
        .iter()
        .any(|agent| agent.kind == AgentKind::Sensor);
    if !has_sensor {
        return Vec::new();
    }
    AgentKind::Sensor
        .package_id()
        .map(|service| vec![format!("{service}.{}", profile.hostname)])
        .unwrap_or_default()
}

/// Returns the source names of `node`: the names a training definition or an
/// engine document may list in its `sources` (RFC 0006 §4 "Source name").
///
/// They are the node's [`event_sensor_names`], plus
/// `<Log Collector package id>.<hostname>` when the node has an applied
/// profile with a non-empty hostname and at least one `LogCollector`-kind
/// agent, configured or not.
#[must_use]
pub(crate) fn source_names(node: &Node) -> Vec<String> {
    let mut names = event_sensor_names(node);
    let Some(profile) = node.profile.as_ref() else {
        return names;
    };
    if profile.hostname.is_empty() {
        return names;
    }
    let has_log_collector = node
        .agents
        .iter()
        .any(|agent| agent.kind == AgentKind::LogCollector);
    if has_log_collector && let Some(service) = AgentKind::LogCollector.package_id() {
        names.push(format!("{service}.{}", profile.hostname));
    }
    names
}

/// Returns the source names of every node whose applied profile belongs to
/// `customer_id`.
///
/// # Errors
///
/// Returns an error if a database iteration error occurs.
pub(crate) fn customer_source_names(store: &Store, customer_id: u32) -> Result<HashSet<String>> {
    let map = store.node_map();
    let mut names = HashSet::new();
    for entry in map.iter(Direction::Forward, None) {
        let node = entry
            .map_err(|e| async_graphql::Error::new(format!("failed to iterate nodes: {e}")))?;
        if node
            .profile
            .as_ref()
            .is_some_and(|profile| profile.customer_id == customer_id)
        {
            names.extend(source_names(&node));
        }
    }
    Ok(names)
}

/// Returns the [`event_sensor_names`] of every node whose applied profile
/// belongs to `customer_id`.
///
/// # Errors
///
/// Returns an error if a database iteration error occurs.
pub(crate) fn customer_sensor_names(store: &Store, customer_id: u32) -> Result<HashSet<String>> {
    let map = store.node_map();
    let mut names = HashSet::new();
    for entry in map.iter(Direction::Forward, None) {
        let node = entry
            .map_err(|e| async_graphql::Error::new(format!("failed to iterate nodes: {e}")))?;
        if node
            .profile
            .as_ref()
            .is_some_and(|profile| profile.customer_id == customer_id)
        {
            names.extend(event_sensor_names(&node));
        }
    }
    Ok(names)
}

/// Builds a map from event sensor names to the customer ID of the node that
/// emits them.
///
/// Only applied profiles are considered; draft-only nodes contribute nothing.
///
/// # Errors
///
/// Returns an error if a database iteration error occurs.
pub(crate) fn event_sensor_customer_id_map(store: &Store) -> Result<HashMap<String, u32>> {
    let map = store.node_map();
    let mut sensor_map = HashMap::<String, u32>::new();

    for entry in map.iter(Direction::Forward, None) {
        let node = entry
            .map_err(|e| async_graphql::Error::new(format!("failed to iterate nodes: {e}")))?;
        let Some(customer_id) = node.profile.as_ref().map(|profile| profile.customer_id) else {
            continue;
        };
        for name in event_sensor_names(&node) {
            sensor_map.insert(name, customer_id);
        }
    }

    Ok(sensor_map)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use review_database::{Agent, AgentStatus, Lifecycle, NodeProfile};

    use super::*;

    fn agent(kind: AgentKind, key: &str, config: Option<&str>) -> Agent {
        Agent {
            node_id: u32::MAX,
            key: key.to_string(),
            kind,
            status: AgentStatus::Enabled,
            config: config.and_then(|c| c.to_string().try_into().ok()),
            draft: None,
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

    fn profile(customer_id: u32, hostname: &str) -> NodeProfile {
        NodeProfile {
            customer_id,
            description: String::new(),
            hostname: hostname.to_string(),
        }
    }

    fn node(
        name: &str,
        profile: Option<NodeProfile>,
        profile_draft: Option<NodeProfile>,
        agents: Vec<Agent>,
    ) -> Node {
        Node {
            id: u32::MAX,
            name: name.to_string(),
            name_draft: Some(name.to_string()),
            profile,
            profile_draft,
            agents,
            external_services: vec![],
            creation_time: Utc::now(),
        }
    }

    #[test]
    fn sensor_agent_yields_service_fqdn() {
        let node = node(
            "sensor",
            Some(profile(1, "sensor.example.com")),
            None,
            vec![
                agent(AgentKind::Sensor, "001.piglet", Some("")),
                agent(AgentKind::SemiSupervised, "001.hog", Some("")),
            ],
        );
        assert_eq!(event_sensor_names(&node), vec!["piglet.sensor.example.com"]);
    }

    #[test]
    fn node_without_sensor_agent_yields_nothing() {
        let node = node(
            "hog-only",
            Some(profile(1, "sensor.example.com")),
            None,
            vec![agent(AgentKind::SemiSupervised, "001.hog", Some(""))],
        );
        assert_eq!(event_sensor_names(&node), Vec::<String>::new());
    }

    #[test]
    fn several_sensor_agents_yield_one_name() {
        let node = node(
            "dual",
            Some(profile(1, "dual.example.com")),
            None,
            vec![
                agent(AgentKind::Sensor, "001.piglet", Some("")),
                agent(AgentKind::Sensor, "002.piglet", Some("")),
            ],
        );
        assert_eq!(event_sensor_names(&node), vec!["piglet.dual.example.com"]);
    }

    #[test]
    fn agent_key_is_not_parsed() {
        let node = node(
            "odd-key",
            Some(profile(1, "odd.example.com")),
            None,
            vec![agent(AgentKind::Sensor, "sensor", Some(""))],
        );
        assert_eq!(event_sensor_names(&node), vec!["piglet.odd.example.com"]);
    }

    #[test]
    fn unconfigured_sensor_agent_still_yields_name() {
        let node = node(
            "no-config",
            Some(profile(1, "noconf.example.com")),
            None,
            vec![agent(AgentKind::Sensor, "001.piglet", None)],
        );
        assert_eq!(event_sensor_names(&node), vec!["piglet.noconf.example.com"]);
    }

    #[test]
    fn draft_only_profile_yields_nothing() {
        let node = node(
            "draft",
            None,
            Some(profile(1, "draft.example.com")),
            vec![agent(AgentKind::Sensor, "001.piglet", Some(""))],
        );
        assert_eq!(event_sensor_names(&node), Vec::<String>::new());
    }

    #[test]
    fn empty_hostname_yields_nothing() {
        let node = node(
            "empty",
            Some(profile(1, "")),
            None,
            vec![agent(AgentKind::Sensor, "001.piglet", Some(""))],
        );
        assert_eq!(event_sensor_names(&node), Vec::<String>::new());
    }

    #[test]
    fn hostname_case_is_preserved() {
        let node = node(
            "upper",
            Some(profile(1, "Sensor.Example.com")),
            None,
            vec![agent(AgentKind::Sensor, "001.piglet", Some(""))],
        );
        assert_eq!(event_sensor_names(&node), vec!["piglet.Sensor.Example.com"]);
    }

    #[test]
    fn source_names_of_a_sensor_node() {
        let node = node(
            "sensor",
            Some(profile(1, "sensor.example.com")),
            None,
            vec![agent(AgentKind::Sensor, "001.piglet", Some(""))],
        );
        assert_eq!(source_names(&node), vec!["piglet.sensor.example.com"]);
    }

    #[test]
    fn source_names_of_a_log_collector_node() {
        let node = node(
            "collector",
            Some(profile(1, "logs.example.com")),
            None,
            vec![
                agent(AgentKind::LogCollector, "001.reproduce", None),
                agent(AgentKind::LogCollector, "002.reproduce", Some("")),
            ],
        );
        assert_eq!(source_names(&node), vec!["reproduce.logs.example.com"]);
    }

    #[test]
    fn source_names_of_a_node_with_both() {
        let node = node(
            "both",
            Some(profile(1, "both.example.com")),
            None,
            vec![
                agent(AgentKind::LogCollector, "001.reproduce", Some("")),
                agent(AgentKind::Sensor, "001.piglet", None),
            ],
        );
        assert_eq!(
            source_names(&node),
            vec!["piglet.both.example.com", "reproduce.both.example.com"]
        );
    }

    #[test]
    fn source_names_need_an_applied_hostname() {
        let agents = vec![
            agent(AgentKind::LogCollector, "001.reproduce", Some("")),
            agent(AgentKind::Sensor, "001.piglet", Some("")),
        ];
        let empty = node("empty", Some(profile(1, "")), None, agents.clone());
        assert_eq!(source_names(&empty), Vec::<String>::new());
        let draft = node("draft", None, Some(profile(1, "draft.example.com")), agents);
        assert_eq!(source_names(&draft), Vec::<String>::new());
    }

    #[test]
    fn event_sensor_names_leave_out_log_collectors() {
        let node = node(
            "collector",
            Some(profile(1, "logs.example.com")),
            None,
            vec![agent(AgentKind::LogCollector, "001.reproduce", Some(""))],
        );
        assert_eq!(event_sensor_names(&node), Vec::<String>::new());
    }

    #[test]
    fn customer_source_names_cover_applied_nodes_of_the_customer() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        let nodes = [
            node(
                "a",
                Some(profile(1, "a.example.com")),
                None,
                vec![agent(AgentKind::Sensor, "001.piglet", Some(""))],
            ),
            node(
                "a-logs",
                Some(profile(1, "a-logs.example.com")),
                None,
                vec![agent(AgentKind::LogCollector, "001.reproduce", None)],
            ),
            node(
                "b",
                Some(profile(2, "b.example.com")),
                None,
                vec![
                    agent(AgentKind::Sensor, "001.piglet", Some("")),
                    agent(AgentKind::LogCollector, "001.reproduce", Some("")),
                ],
            ),
            node(
                "draft",
                None,
                Some(profile(1, "draft.example.com")),
                vec![agent(AgentKind::Sensor, "001.piglet", Some(""))],
            ),
        ];
        for node in &nodes {
            store.node_map().put(node).unwrap();
        }

        assert_eq!(
            customer_source_names(&store, 1).unwrap(),
            HashSet::from([
                "piglet.a.example.com".to_string(),
                "reproduce.a-logs.example.com".to_string(),
            ])
        );
        assert_eq!(
            customer_source_names(&store, 2).unwrap(),
            HashSet::from([
                "piglet.b.example.com".to_string(),
                "reproduce.b.example.com".to_string(),
            ])
        );
        assert!(customer_source_names(&store, 3).unwrap().is_empty());
    }

    #[test]
    fn customer_id_map_covers_applied_sensor_nodes_only() {
        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();
        let nodes = [
            node(
                "a",
                Some(profile(1, "a.example.com")),
                None,
                vec![
                    agent(AgentKind::Sensor, "001.piglet", Some("")),
                    agent(AgentKind::Sensor, "002.piglet", Some("")),
                ],
            ),
            node(
                "b",
                Some(profile(2, "b.example.com")),
                Some(profile(3, "b-next.example.com")),
                vec![agent(AgentKind::Sensor, "001.piglet", None)],
            ),
            node(
                "draft",
                None,
                Some(profile(4, "draft.example.com")),
                vec![agent(AgentKind::Sensor, "001.piglet", Some(""))],
            ),
            node(
                "hog-only",
                Some(profile(5, "hog.example.com")),
                None,
                vec![agent(AgentKind::SemiSupervised, "001.hog", Some(""))],
            ),
        ];
        for node in &nodes {
            store.node_map().put(node).unwrap();
        }

        let map = event_sensor_customer_id_map(&store).unwrap();
        let expected = HashMap::from([
            ("piglet.a.example.com".to_string(), 1),
            ("piglet.b.example.com".to_string(), 2),
        ]);
        assert_eq!(map, expected);
    }
}
