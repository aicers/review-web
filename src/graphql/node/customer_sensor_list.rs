use async_graphql::{
    Context, Object, Result, SimpleObject, StringNumber,
    connection::{Connection, Edge, EmptyFields, OpaqueCursor},
};
use review_database::event::Direction;

use super::super::customer_access::{is_member, users_customers};

/// A sensor agent that has been deployed (i.e. its `config` is set) on a node
/// belonging to a particular customer.
#[derive(SimpleObject)]
pub(super) struct Sensor {
    /// The ID of the owning customer.
    pub customer_id: i32,

    /// The agent key (e.g., `agent@hostname`).
    pub agent_key: String,

    /// The fully-qualified hostname of the host on which the sensor runs.
    pub host_fqdn: String,
}

pub(super) struct SensorTotalCount {
    count: usize,
}

#[Object]
impl SensorTotalCount {
    /// The total number of edges.
    async fn total_count(&self) -> StringNumber<usize> {
        StringNumber(self.count)
    }
}

/// Validates an optional list of `customerIds` against the caller's accessible
/// scope.
///
/// Returns:
/// - `Ok(None)` if the caller is unscoped (admin) and no filter was provided.
/// - `Ok(Some(ids))` with the deduplicated, sorted list of accessible
///   customer IDs to filter by.
///
/// # Errors
///
/// Returns an error if any provided ID is negative, the list is empty, the
/// user's customer scope cannot be determined, or any provided ID falls
/// outside the caller's accessible scope.
fn validate_customer_ids(
    ctx: &Context<'_>,
    customer_ids: Option<Vec<i32>>,
) -> Result<Option<Vec<u32>>> {
    let users_customers = users_customers(ctx)?;
    let Some(ids) = customer_ids else {
        return Ok(users_customers);
    };
    if ids.is_empty() {
        return Err("at least one ID value must be provided".into());
    }
    let mut parsed: Vec<u32> = Vec::with_capacity(ids.len());
    for id in ids {
        let id = u32::try_from(id).map_err(|_| "invalid customer ID")?;
        parsed.push(id);
    }
    parsed.sort_unstable();
    parsed.dedup();
    for id in &parsed {
        if !is_member(users_customers.as_deref(), *id) {
            return Err("Forbidden".into());
        }
    }
    Ok(Some(parsed))
}

fn collect_sensors(
    ctx: &Context<'_>,
    customer_ids: Option<&[u32]>,
) -> Result<Vec<(Vec<u8>, Sensor)>> {
    let store = crate::graphql::get_store(ctx)?;
    let map = store.node_map();
    let mut sensors: Vec<(Vec<u8>, Sensor)> = Vec::new();
    for entry in map.iter(Direction::Forward, None) {
        let node = entry.map_err(|_| "invalid value in database")?;
        let Some(profile) = node.profile.as_ref() else {
            continue;
        };
        if let Some(allowed) = customer_ids
            && !allowed.contains(&profile.customer_id)
        {
            continue;
        }
        let customer_id =
            i32::try_from(profile.customer_id).map_err(|_| "customer ID exceeds Int range")?;
        for agent in &node.agents {
            if agent.kind != review_database::AgentKind::Sensor {
                continue;
            }
            if agent.config.is_none() {
                continue;
            }
            sensors.push((
                agent.key.as_bytes().to_vec(),
                Sensor {
                    customer_id,
                    agent_key: agent.key.clone(),
                    host_fqdn: profile.hostname.clone(),
                },
            ));
        }
    }
    sensors.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(sensors)
}

pub(super) async fn load(
    ctx: &Context<'_>,
    customer_ids: Option<Vec<i32>>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Sensor, SensorTotalCount, EmptyFields>> {
    let scope = validate_customer_ids(ctx, customer_ids)?;
    let sensors = collect_sensors(ctx, scope.as_deref())?;
    let total = sensors.len();

    let after_bytes = after.as_ref().map(|c| c.0.as_slice());
    let before_bytes = before.as_ref().map(|c| c.0.as_slice());
    let mut window: Vec<(Vec<u8>, Sensor)> = sensors
        .into_iter()
        .filter(|(key, _)| {
            if let Some(after) = after_bytes
                && key.as_slice() <= after
            {
                return false;
            }
            if let Some(before) = before_bytes
                && key.as_slice() >= before
            {
                return false;
            }
            true
        })
        .collect();

    let (has_previous, has_next, edges) = if let Some(first) = first {
        let has_next = window.len() > first;
        if has_next {
            window.truncate(first);
        }
        (false, has_next, window)
    } else if let Some(last) = last {
        let has_previous = window.len() > last;
        let drop = window.len().saturating_sub(last);
        let edges: Vec<_> = window.drain(drop..).collect();
        (has_previous, false, edges)
    } else {
        (false, false, window)
    };

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        SensorTotalCount { count: total },
    );
    for (key, sensor) in edges {
        connection.edges.push(Edge::new(OpaqueCursor(key), sensor));
    }
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use review_database::{Agent, AgentKind, AgentStatus, Node, NodeProfile, Store};
    use serde_json::json;

    use crate::graphql::{Role, TestSchema};

    fn agent(kind: AgentKind, key: &str, config: Option<&str>, draft: Option<&str>) -> Agent {
        Agent {
            node: u32::MAX,
            key: key.to_string(),
            kind,
            status: AgentStatus::Enabled,
            config: config.and_then(|c| c.to_string().try_into().ok()),
            draft: draft.and_then(|d| d.to_string().try_into().ok()),
        }
    }

    fn insert_node(
        store: &Store,
        name: &str,
        profile: Option<NodeProfile>,
        profile_draft: Option<NodeProfile>,
        agents: Vec<Agent>,
    ) -> u32 {
        let node = Node {
            id: u32::MAX,
            name: name.to_string(),
            name_draft: Some(name.to_string()),
            profile,
            profile_draft,
            agents,
            external_services: vec![],
            creation_time: Utc::now(),
        };
        store.node_map().put(&node).expect("insert node")
    }

    fn profile(customer_id: u32, hostname: &str) -> NodeProfile {
        NodeProfile {
            customer_id,
            description: String::new(),
            hostname: hostname.to_string(),
        }
    }

    const QUERY: &str = r"{customerSensorList(first: 10) { totalCount edges { node { customerId agentKey hostFqdn } } } }";

    #[tokio::test]
    async fn admin_sees_all_sensors() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            // Sensor for customer 1, with config -> included.
            insert_node(
                &store,
                "node-1",
                Some(profile(1, "host1.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@host1.example.com",
                    Some(""),
                    Some("draft = 1"),
                )],
            );
            // Sensor for customer 2, with config -> included.
            insert_node(
                &store,
                "node-2",
                Some(profile(2, "host2.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@host2.example.com",
                    Some("k = 1"),
                    None,
                )],
            );
        }

        let res = schema.execute_as_system_admin(QUERY).await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let edges = data["customerSensorList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 2);
        assert_eq!(data["customerSensorList"]["totalCount"], json!("2"));
    }

    #[tokio::test]
    async fn excludes_sensor_without_config() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            // Sensor with config = None but draft = Some: must be excluded.
            insert_node(
                &store,
                "draft-only",
                Some(profile(1, "draft.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@draft.example.com",
                    None,
                    Some("draft = 1"),
                )],
            );
        }

        let res = schema.execute_as_system_admin(QUERY).await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let edges = data["customerSensorList"]["edges"].as_array().unwrap();
        assert!(edges.is_empty());
        assert_eq!(data["customerSensorList"]["totalCount"], json!("0"));
    }

    #[tokio::test]
    async fn includes_sensor_with_empty_config() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            // Sensor with config = Some(""): must be included (empty TOML is valid).
            insert_node(
                &store,
                "empty-config",
                Some(profile(7, "empty.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@empty.example.com",
                    Some(""),
                    None,
                )],
            );
        }

        let res = schema.execute_as_system_admin(QUERY).await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let edges = data["customerSensorList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["agentKey"], "piglet@empty.example.com");
        assert_eq!(edges[0]["node"]["customerId"], json!(7));
        assert_eq!(edges[0]["node"]["hostFqdn"], "empty.example.com");
    }

    #[tokio::test]
    async fn excludes_node_with_only_profile_draft() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            // profile = None, profile_draft = Some: must be excluded.
            insert_node(
                &store,
                "draft-profile",
                None,
                Some(profile(1, "draft-profile.example.com")),
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@draft-profile.example.com",
                    Some(""),
                    None,
                )],
            );
        }

        let res = schema.execute_as_system_admin(QUERY).await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let edges = data["customerSensorList"]["edges"].as_array().unwrap();
        assert!(edges.is_empty());
    }

    #[tokio::test]
    async fn excludes_non_sensor_agents() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            insert_node(
                &store,
                "mixed",
                Some(profile(1, "mixed.example.com")),
                None,
                vec![
                    agent(
                        AgentKind::Unsupervised,
                        "reconverge@mixed.example.com",
                        Some(""),
                        None,
                    ),
                    agent(
                        AgentKind::Sensor,
                        "piglet@mixed.example.com",
                        Some(""),
                        None,
                    ),
                ],
            );
        }

        let res = schema.execute_as_system_admin(QUERY).await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let edges = data["customerSensorList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["agentKey"], "piglet@mixed.example.com");
    }

    #[tokio::test]
    async fn scoped_user_sees_only_accessible_customers() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            insert_node(
                &store,
                "node-a",
                Some(profile(1, "a.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@a.example.com",
                    Some(""),
                    None,
                )],
            );
            insert_node(
                &store,
                "node-b",
                Some(profile(2, "b.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@b.example.com",
                    Some(""),
                    None,
                )],
            );
        }

        let res = schema
            .execute_as_scoped_user(QUERY, Role::SecurityAdministrator, Some(vec![1]))
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let edges = data["customerSensorList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["agentKey"], "piglet@a.example.com");
        assert_eq!(edges[0]["node"]["customerId"], json!(1));
    }

    #[tokio::test]
    async fn scoped_user_with_inaccessible_customer_id_is_forbidden() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            insert_node(
                &store,
                "node-a",
                Some(profile(1, "a.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@a.example.com",
                    Some(""),
                    None,
                )],
            );
        }

        let res = schema
            .execute_as_scoped_user(
                r"{customerSensorList(customerIds: [1, 2], first: 10) { totalCount edges { node { agentKey } } } }",
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn scoped_user_with_accessible_customer_ids_filter() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            insert_node(
                &store,
                "node-a",
                Some(profile(1, "a.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@a.example.com",
                    Some(""),
                    None,
                )],
            );
            insert_node(
                &store,
                "node-b",
                Some(profile(2, "b.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@b.example.com",
                    Some(""),
                    None,
                )],
            );
        }

        let res = schema
            .execute_as_scoped_user(
                r"{customerSensorList(customerIds: [2], first: 10) { totalCount edges { node { agentKey customerId } } } }",
                Role::SecurityAdministrator,
                Some(vec![1, 2]),
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let edges = data["customerSensorList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["agentKey"], "piglet@b.example.com");
        assert_eq!(edges[0]["node"]["customerId"], json!(2));
    }

    #[tokio::test]
    async fn admin_with_customer_ids_filter() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            insert_node(
                &store,
                "node-a",
                Some(profile(1, "a.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@a.example.com",
                    Some(""),
                    None,
                )],
            );
            insert_node(
                &store,
                "node-b",
                Some(profile(2, "b.example.com")),
                None,
                vec![agent(
                    AgentKind::Sensor,
                    "piglet@b.example.com",
                    Some(""),
                    None,
                )],
            );
        }

        let res = schema
            .execute_as_system_admin(
                r"{customerSensorList(customerIds: [1], first: 10) { totalCount edges { node { agentKey } } } }",
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let edges = data["customerSensorList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["agentKey"], "piglet@a.example.com");
    }
}
