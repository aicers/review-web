#![allow(clippy::fn_params_excessive_bools)]

use std::collections::HashMap;

use async_graphql::{
    Context, Error, Object, Result,
    connection::{Connection, Edge, EmptyFields, OpaqueCursor},
    types::ID,
};
use chrono::Utc;
use review_database::{Store, UniqueKey, event::Direction};
use tracing::info;

use super::{
    super::{Role, RoleGuard, customer_access},
    Node, NodeInput, NodeMutation, NodeQuery, NodeTotalCount, customer_sensor_list,
    customer_sensor_list::{Sensor, SensorTotalCount},
    gen_agent_lookup_key,
    input::{AgentDraftInput, ExternalServiceInput, NodeDraftInput},
    installed_guard,
};
use crate::{graphql::query_with_constraints, info_with_username};

#[Object]
impl NodeQuery {
    /// A list of nodes.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Node, NodeTotalCount, EmptyFields>> {
        info_with_username!(ctx, "Node list requested");
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// A node for the given ID.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Node> {
        let node = customer_access::load_accessible_node(ctx, &id)?;

        Ok(node.into())
    }

    /// A list of nodes that have at least one deployed sensor agent
    /// (`SENSOR`-kind agent with `config` set), scoped to customers the caller
    /// can access. Nodes whose `profile` is `None` are excluded.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn customer_sensor_list(
        &self,
        ctx: &Context<'_>,
        customer_ids: Option<Vec<i32>>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, Sensor, SensorTotalCount, EmptyFields>> {
        info_with_username!(ctx, "Customer sensor list requested");
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                customer_sensor_list::load(ctx, customer_ids, after, before, first, last).await
            },
        )
        .await
    }
}

#[Object]
impl NodeMutation {
    /// Inserts a new node, returning the ID of the new node.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    async fn insert_node(
        &self,
        ctx: &Context<'_>,
        name: String,
        customer_id: ID,
        description: String,
        hostname: String,
        agents: Vec<AgentDraftInput>,
        external_services: Vec<ExternalServiceInput>,
    ) -> Result<ID> {
        let store = crate::graphql::get_store(ctx)?;
        let users_customers = customer_access::users_customers(ctx)?;
        let map = store.node_map();
        let customer_id = customer_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid customer ID")?;

        // Check customer scoping - non-admin users can only create nodes for their customers
        if !customer_access::is_member(users_customers.as_deref(), customer_id) {
            return Err("Forbidden".into());
        }

        let agents: Vec<review_database::Agent> = agents
            .into_iter()
            .map(|new_agent| {
                let draft = match new_agent.draft {
                    Some(draft) => Some(draft.try_into().map_err(|_| {
                        Error::new(format!(
                            "Failed to convert the draft to TOML for the agent: {}",
                            new_agent.key
                        ))
                    })?),
                    None => None,
                };

                Ok::<_, Error>(review_database::Agent {
                    node_id: u32::MAX,
                    key: new_agent.key,
                    kind: new_agent.kind.into(),
                    status: new_agent.status.into(),
                    config: None,
                    draft,
                    installed_version: None,
                    installed_commit: None,
                    lifecycle: review_database::Lifecycle::NotInstalled,
                    bound_addrs: vec![],
                    instance: None,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let external_services: Vec<review_database::ExternalService> = external_services
            .into_iter()
            .map(|new_external_service| {
                let draft = match new_external_service.draft {
                    Some(draft) => Some(draft.try_into().map_err(|_| {
                        Error::new(format!(
                            "Failed to convert the draft to TOML for the external service: {}",
                            new_external_service.key
                        ))
                    })?),
                    None => None,
                };

                Ok::<_, Error>(review_database::ExternalService {
                    node_id: u32::MAX,
                    key: new_external_service.key,
                    kind: new_external_service.kind.into(),
                    status: new_external_service.status.into(),
                    draft,
                    installed_version: None,
                    installed_commit: None,
                    lifecycle: review_database::Lifecycle::NotInstalled,
                    bound_addrs: vec![],
                    instance: None,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let value = review_database::Node {
            id: u32::MAX,
            name: name.clone(),
            name_draft: Some(name),
            profile: None,
            profile_draft: Some(review_database::NodeProfile {
                customer_id,
                description,
                hostname: hostname.clone(),
            }),
            agents,
            external_services,
            creation_time: Utc::now(),
        };
        let id = map.put(&value)?;
        info_with_username!(ctx, "Node {} has been registered", value.name);
        Ok(ID(id.to_string()))
    }

    /// Removes nodes, returning the node keys that no longer exist.
    ///
    /// Validates all requested nodes before deleting any of them. Refuses the whole request when
    /// any requested node holds an installed instance, which only `removeService` removes, or
    /// lists a row that cannot be found.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_nodes(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx)?;
        let users_customers = customer_access::users_customers(ctx)?;
        let map = store.node_map();
        let ids = ids
            .into_iter()
            .map(|id| id.as_str().parse::<u32>().map_err(|_| "invalid ID".into()))
            .collect::<Result<Vec<u32>>>()?;

        let mut nodes = Vec::with_capacity(ids.len());
        for id in &ids {
            // Check customer scoping before removing
            let Some(entry) = map.get_by_id(*id)? else {
                return Err("no such node".into());
            };
            if !customer_access::can_access_node(users_customers.as_deref(), &entry.0) {
                return Err("Forbidden".into());
            }
            nodes.push(entry);
        }
        // Only `removeService` removes an installed instance, so a node that holds one, or whose
        // rows cannot all be read, is not removed.
        installed_guard::check_removal(
            nodes
                .iter()
                .map(|(node, agents, services)| (node, agents.as_slice(), services.as_slice())),
        )?;

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let (key, _invalid_agents, _invalid_external_services) = map.remove(id)?;

            let name = match String::from_utf8(key) {
                Ok(key) => key,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
            };
            info_with_username!(ctx, "Node {name} has been deleted");
            removed.push(name);
        }
        Ok(removed)
    }

    /// Updates the given node, returning the node ID that was updated.
    ///
    /// Refuses an update that would delete an installed instance's row or change its kind; such an
    /// instance is removed only with `removeService`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_node_draft(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: NodeInput,
        new: NodeDraftInput,
    ) -> Result<ID> {
        customer_access::load_accessible_node(ctx, &id)?;
        if let Some(profile_draft) = new.profile_draft.as_ref() {
            customer_access::check_customer_membership(ctx, &profile_draft.customer_id)?;
        }
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let store = crate::graphql::get_store(ctx)?;
        let mut map = store.node_map();

        let mut new = super::input::create_draft_update(&old, new)?;
        let mut old = old.try_into()?;
        let (stored, _, _) = map.get_by_id(i)?.ok_or("no such node")?;
        merge_installation_state(&stored, &mut old);
        merge_installation_state(&stored, &mut new);
        installed_guard::check_update(i, &stored.name, &old, &new)?;
        map.update(i, &old, &new)?;
        info_with_username!(ctx, "Node {:?} has been modified", old.name);
        Ok(id)
    }
}

pub(super) fn merge_installation_state(
    stored: &review_database::Node,
    update: &mut review_database::NodeUpdate,
) {
    for agent in &mut update.agents {
        if let Some(stored_agent) = stored.agents.iter().find(|stored| stored.key == agent.key) {
            agent.installed_version = stored_agent.installed_version.clone();
            agent.installed_commit = stored_agent.installed_commit.clone();
            agent.lifecycle = stored_agent.lifecycle;
            agent.bound_addrs.clone_from(&stored_agent.bound_addrs);
            agent.instance = stored_agent.instance;
        } else {
            agent.installed_version = None;
            agent.installed_commit = None;
            agent.lifecycle = review_database::Lifecycle::NotInstalled;
            agent.bound_addrs.clear();
            agent.instance = None;
        }
    }

    for service in &mut update.external_services {
        if let Some(stored_service) = stored
            .external_services
            .iter()
            .find(|stored| stored.key == service.key)
        {
            service.installed_version = stored_service.installed_version.clone();
            service.installed_commit = stored_service.installed_commit.clone();
            service.lifecycle = stored_service.lifecycle;
            service.bound_addrs.clone_from(&stored_service.bound_addrs);
            service.instance = stored_service.instance;
        } else {
            service.installed_version = None;
            service.installed_commit = None;
            service.lifecycle = review_database::Lifecycle::NotInstalled;
            service.bound_addrs.clear();
            service.instance = None;
        }
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, Node, NodeTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx)?;
    let users_customers = customer_access::users_customers(ctx)?;
    let map = store.node_map();
    let users_customers = users_customers.as_deref();

    // Apply customer filtering while collecting edges to keep pagination metadata consistent.
    let (nodes, has_previous, has_next) =
        super::super::process_load_edges_filtered(&map, after, before, first, last, None, |node| {
            customer_access::can_access_node(users_customers, node)
        });

    let nodes = nodes
        .into_iter()
        .map(|res| res.map_err(|e| format!("{e}").into()))
        .collect::<Result<Vec<_>>>()?;

    let mut connection = Connection::with_additional_fields(has_previous, has_next, NodeTotalCount);
    for node in nodes {
        let key = node.unique_key();
        connection
            .edges
            .push(Edge::new(OpaqueCursor(key.to_vec()), node.into()));
    }
    Ok(connection)
}

/// Returns a customer id and agent lookup keys for the node corresponding to that customer id.
///
/// # Errors
///
/// Returns an error if the node profile could not be retrieved.
pub fn agent_lookup_keys_by_customer_id(db: &Store) -> Result<HashMap<u32, Vec<String>>> {
    let map = db.node_map();
    let mut customer_id_hash = HashMap::new();

    for entry in map.iter(Direction::Forward, None) {
        let node = entry.map_err(|_| "invalid value in database")?;

        if let Some(node_profile) = &node.profile {
            let agent_lookup_keys = node
                .agents
                .iter()
                .map(|agent| gen_agent_lookup_key(&agent.key, &node_profile.hostname))
                .collect::<Vec<String>>();
            customer_id_hash
                .entry(node_profile.customer_id)
                .or_insert_with(Vec::new)
                .extend_from_slice(&agent_lookup_keys);
        }
    }
    Ok(customer_id_hash)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    #[cfg(feature = "auth-mtls")]
    use review_database as database;
    use serde_json::json;

    use super::super::test_support::{
        insert_active_node, installed_agent, installed_service, node_draft_input, put_node,
        stored_node, update_account_customers,
    };
    #[cfg(feature = "auth-mtls")]
    use super::agent_lookup_keys_by_customer_id;
    use crate::graphql::{Role, TestSchema};

    #[tokio::test]
    #[cfg(feature = "auth-mtls")]
    async fn agent_lookup_keys_by_customer_id_keeps_mtls_instances() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let node = database::Node {
            id: u32::MAX,
            name: "multi-instance".to_string(),
            name_draft: Some("multi-instance".to_string()),
            profile: Some(database::NodeProfile {
                customer_id: 7,
                description: String::new(),
                hostname: "node-01.customer.internal".to_string(),
            }),
            profile_draft: None,
            agents: vec![
                database::Agent {
                    node_id: u32::MAX,
                    key: "001.hog".to_string(),
                    kind: database::AgentKind::SemiSupervised,
                    status: database::AgentStatus::Enabled,
                    config: None,
                    draft: None,
                    installed_version: None,
                    installed_commit: None,
                    lifecycle: database::Lifecycle::NotInstalled,
                    bound_addrs: vec![],
                    instance: None,
                },
                database::Agent {
                    node_id: u32::MAX,
                    key: "002.hog".to_string(),
                    kind: database::AgentKind::SemiSupervised,
                    status: database::AgentStatus::Enabled,
                    config: None,
                    draft: None,
                    installed_version: None,
                    installed_commit: None,
                    lifecycle: database::Lifecycle::NotInstalled,
                    bound_addrs: vec![],
                    instance: None,
                },
                database::Agent {
                    node_id: u32::MAX,
                    key: "001.piglet".to_string(),
                    kind: database::AgentKind::Sensor,
                    status: database::AgentStatus::Enabled,
                    config: None,
                    draft: None,
                    installed_version: None,
                    installed_commit: None,
                    lifecycle: database::Lifecycle::NotInstalled,
                    bound_addrs: vec![],
                    instance: None,
                },
            ],
            external_services: vec![],
            creation_time: chrono::Utc::now(),
        };
        store.node_map().put(&node).expect("insert node");

        let mut lookup_keys = agent_lookup_keys_by_customer_id(&store)
            .expect("lookup keys")
            .remove(&7)
            .expect("customer lookup keys");
        lookup_keys.sort();

        assert_eq!(
            lookup_keys,
            vec![
                "001.hog.node-01.customer.internal",
                "001.piglet.node-01.customer.internal",
                "002.hog.node-01.customer.internal",
            ]
        );
    }

    // test scenario : insert node -> update node with different name -> remove node
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn node_crud() {
        let schema = TestSchema::new().await;

        // check empty
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "0"}}"#);

        // insert node
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                            draft: "test = 'toml'"
                        },
                        {
                            key: "sensor"
                            kind: SENSOR
                            status: ENABLED
                            draft: "test = 'toml'"
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // check node count after insert
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "1"}}"#);

        // check inserted node
        let res = schema
            .execute_as_system_admin(
                r#"{node(id: "0") {
                    id
                    name
                    nameDraft
                    profile {
                        customerId
                        description
                        hostname
                    }
                    profileDraft {
                        customerId
                        description
                        hostname
                    }
                    agents {
                        key
                        kind
                        status
                        config
                        draft
                    }
                    externalServices {
                        nodeId
                        key
                        kind
                        status
                        draft
                    }
                }}"#,
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "node": {
                    "id": "0",
                    "name": "admin node",
                    "nameDraft": "admin node",
                    "profile": null,
                    "profileDraft": {
                        "customerId": "0",
                        "description": "This is the admin node running review.",
                        "hostname": "admin.aice-security.com",
                    },
                    "agents": [{
                        "key": "unsupervised",
                        "kind": "UNSUPERVISED",
                        "status": "ENABLED",
                        "config": null,
                        "draft": "test = 'toml'"
                    },
                    {
                        "key": "sensor",
                        "kind": "SENSOR",
                        "status": "ENABLED",
                        "config": null,
                        "draft": "test = 'toml'"
                    }],
                    "externalServices": [],
                }
            })
        );

        // update node
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: null,
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                }
                            ],
                            externalServices: []
                        },
                        new: {
                            nameDraft: "AdminNode",
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    draft: "test = 'changed_toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    draft: "test = 'changed_toml'"
                                }
                            ],
                            externalServices: []
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node count after update
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "1"}}"#);

        // check updated node
        let res = schema
            .execute_as_system_admin(
                r#"{node(id: "0") {
                    id
                    name
                    nameDraft
                    profile {
                        customerId
                        description
                        hostname
                    }
                    profileDraft {
                        customerId
                        description
                        hostname
                    }
                    agents {
                        key
                        kind
                        status
                        config
                        draft
                    }
                    externalServices {
                        nodeId
                        key
                        kind
                        status
                        draft
                    }
                }}"#,
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "node": {
                    "id": "0",
                    "name": "admin node", // stays the same
                    "nameDraft": "AdminNode", // updated
                    "profile": null,
                    "profileDraft": {
                        "customerId": "0",
                        "description": "This is the admin node running review.",
                        "hostname": "admin.aice-security.com",
                    },
                    "agents": [{
                        "key": "unsupervised",
                        "kind": "UNSUPERVISED",
                        "status": "ENABLED",
                        "config": null,
                        "draft": "test = 'changed_toml'"
                    },
                    {
                        "key": "sensor",
                        "kind": "SENSOR",
                        "status": "ENABLED",
                        "config": null,
                        "draft": "test = 'changed_toml'"
                    }],
                    "externalServices": [],
                }
            })
        );

        // try reverting node, but it should succeed even though the node is an initial draft
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                updateNodeDraft(
                    id: "0"
                    old: {
                        name: "admin node",
                        nameDraft: "AdminNode",
                        profile: null
                        profileDraft: {
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                        }
                        agents: [
                            {
                                key: "unsupervised",
                                kind: "UNSUPERVISED",
                                status: "ENABLED",
                                config: null,
                                draft: null
                            },
                            {
                                key: "sensor",
                                kind: "SENSOR",
                                status: "ENABLED",
                                config: null,
                                draft: null
                            }
                        ],
                        externalServices: []
                    },
                    new: {
                        nameDraft: "admin node",
                        profileDraft: null,
                        agents: null,
                        externalServices: null,
                    }
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // remove node
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    removeNodes(ids: ["0"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNodes: ["admin node"]}"#);

        // check node count after remove
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "0"}}"#);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn node_installation_state_defaults_and_is_preserved_by_draft_updates() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node"
                        customerId: 0
                        description: "description"
                        hostname: "node.example.com"
                        agents: [{ key: "agent", kind: SENSOR, status: ENABLED, draft: "value = 'old'" }]
                        externalServices: [{
                            key: "service", kind: DATA_STORE, status: ENABLED, draft: "value = 'old'"
                        }]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // REView records an installed instance only on a node with an active
        // profile, so the profile is promoted before the install state is
        // seeded.
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNodeDraft(
                        id: "0"
                        node: {
                            name: "node"
                            nameDraft: "node"
                            profile: null
                            profileDraft: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            agents: [{
                                key: "agent", kind: SENSOR, status: ENABLED,
                                config: null, draft: "value = 'old'"
                            }]
                            externalServices: [{
                                key: "service", kind: DATA_STORE, status: ENABLED, draft: "value = 'old'"
                            }]
                        }
                    ) { id }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);

        let (installed_agent, installed_service) = {
            let store = schema.store();
            let (node, _, _) = store
                .node_map()
                .get_by_id(0)
                .expect("read inserted node")
                .expect("inserted node exists");
            let agent = node.agents.first().expect("one agent was inserted");
            assert_eq!(agent.installed_version, None);
            assert_eq!(agent.installed_commit, None);
            assert_eq!(agent.lifecycle, review_database::Lifecycle::NotInstalled);
            assert_eq!(agent.bound_addrs.len(), 0);
            assert_eq!(agent.instance, None);
            let service = node
                .external_services
                .first()
                .expect("one external service was inserted");
            assert_eq!(service.installed_version, None);
            assert_eq!(service.installed_commit, None);
            assert_eq!(service.lifecycle, review_database::Lifecycle::NotInstalled);
            assert_eq!(service.bound_addrs.len(), 0);
            assert_eq!(service.instance, None);

            let mut installed_agent = agent.clone();
            installed_agent.installed_version = Some("v1".to_string());
            installed_agent.installed_commit = Some("abcdef".to_string());
            installed_agent.lifecycle = review_database::Lifecycle::Running;
            installed_agent.bound_addrs = vec![("api".to_string(), "127.0.0.1:1000".to_string())];
            installed_agent.instance = Some(1);
            store
                .agents_map()
                .update(agent, &installed_agent)
                .expect("set agent installation state");

            let mut installed_service = service.clone();
            installed_service.installed_version = Some("v2".to_string());
            installed_service.installed_commit = Some("fedcba".to_string());
            installed_service.lifecycle = review_database::Lifecycle::Stopped;
            installed_service.bound_addrs = vec![("rpc".to_string(), "127.0.0.1:2000".to_string())];
            installed_service.instance = Some(2);
            store
                .external_service_map()
                .update(service, &installed_service)
                .expect("set external service installation state");
            (installed_agent, installed_service)
        };

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "node"
                            nameDraft: "node"
                            profile: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            profileDraft: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            agents: [{
                                key: "agent", kind: SENSOR, status: ENABLED,
                                config: "value = 'old'", draft: "value = 'old'"
                            }]
                            externalServices: [{
                                key: "service", kind: DATA_STORE, status: ENABLED, draft: "value = 'old'"
                            }]
                        }
                        new: {
                            nameDraft: "node"
                            profileDraft: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            agents: [{
                                key: "agent", kind: SENSOR, status: ENABLED, draft: "value = 'new'"
                            }]
                            externalServices: [{
                                key: "service", kind: DATA_STORE, status: ENABLED, draft: "value = 'new'"
                            }]
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        {
            let store = schema.store();
            let (updated, _, _) = store
                .node_map()
                .get_by_id(0)
                .expect("read updated node")
                .expect("updated node exists");
            let updated_agent = updated.agents.first().expect("agent remains installed");
            assert_eq!(
                updated_agent.installed_version,
                installed_agent.installed_version
            );
            assert_eq!(
                updated_agent.installed_commit,
                installed_agent.installed_commit
            );
            assert_eq!(updated_agent.lifecycle, installed_agent.lifecycle);
            assert_eq!(updated_agent.bound_addrs, installed_agent.bound_addrs);
            assert_eq!(updated_agent.instance, installed_agent.instance);
            let updated_service = updated
                .external_services
                .first()
                .expect("external service remains installed");
            assert_eq!(
                updated_service.installed_version,
                installed_service.installed_version
            );
            assert_eq!(
                updated_service.installed_commit,
                installed_service.installed_commit
            );
            assert_eq!(updated_service.lifecycle, installed_service.lifecycle);
            assert_eq!(updated_service.bound_addrs, installed_service.bound_addrs);
            assert_eq!(updated_service.instance, installed_service.instance);
        }

        // An entry added alongside stored ones takes the defaults while the
        // stored entries keep what the host reported. The added entry is
        // listed FIRST on purpose: matching stored state by position rather
        // than by key would then hand the stored agent's installed build to
        // the entry that was just added, which is what these assertions catch.
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "node"
                            nameDraft: "node"
                            profile: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            profileDraft: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            agents: [{
                                key: "agent", kind: SENSOR, status: ENABLED,
                                config: "value = 'old'", draft: "value = 'new'"
                            }]
                            externalServices: [{
                                key: "service", kind: DATA_STORE, status: ENABLED, draft: "value = 'new'"
                            }]
                        }
                        new: {
                            nameDraft: "node"
                            profileDraft: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            agents: [
                                { key: "added", kind: SENSOR, status: ENABLED, draft: "value = 'added'" },
                                { key: "agent", kind: SENSOR, status: ENABLED, draft: "value = 'new'" }
                            ]
                            externalServices: [
                                {
                                    key: "added", kind: DATA_STORE, status: ENABLED,
                                    draft: "value = 'added'"
                                },
                                {
                                    key: "service", kind: DATA_STORE, status: ENABLED,
                                    draft: "value = 'new'"
                                }
                            ]
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        {
            let store = schema.store();
            let (mixed, _, _) = store
                .node_map()
                .get_by_id(0)
                .expect("read node carrying both a stored and an added entry")
                .expect("node exists");

            let kept_agent = mixed
                .agents
                .iter()
                .find(|agent| agent.key == "agent")
                .expect("the installed agent survives the addition");
            assert_eq!(
                kept_agent.installed_version,
                installed_agent.installed_version
            );
            assert_eq!(
                kept_agent.installed_commit,
                installed_agent.installed_commit
            );
            assert_eq!(kept_agent.lifecycle, installed_agent.lifecycle);
            assert_eq!(kept_agent.bound_addrs, installed_agent.bound_addrs);
            assert_eq!(kept_agent.instance, installed_agent.instance);

            let added_agent = mixed
                .agents
                .iter()
                .find(|agent| agent.key == "added")
                .expect("the added agent is stored");
            assert_eq!(added_agent.installed_version, None);
            assert_eq!(added_agent.installed_commit, None);
            assert_eq!(
                added_agent.lifecycle,
                review_database::Lifecycle::NotInstalled
            );
            assert_eq!(added_agent.bound_addrs.len(), 0);
            assert_eq!(added_agent.instance, None);

            let kept_service = mixed
                .external_services
                .iter()
                .find(|service| service.key == "service")
                .expect("the installed external service survives the addition");
            assert_eq!(
                kept_service.installed_version,
                installed_service.installed_version
            );
            assert_eq!(
                kept_service.installed_commit,
                installed_service.installed_commit
            );
            assert_eq!(kept_service.lifecycle, installed_service.lifecycle);
            assert_eq!(kept_service.bound_addrs, installed_service.bound_addrs);
            assert_eq!(kept_service.instance, installed_service.instance);

            let added_service = mixed
                .external_services
                .iter()
                .find(|service| service.key == "added")
                .expect("the added external service is stored");
            assert_eq!(added_service.installed_version, None);
            assert_eq!(added_service.installed_commit, None);
            assert_eq!(
                added_service.lifecycle,
                review_database::Lifecycle::NotInstalled
            );
            assert_eq!(added_service.bound_addrs.len(), 0);
            assert_eq!(added_service.instance, None);
        }

        // Removing an entry leaves the installation state of the entries that
        // remain untouched.
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "node"
                            nameDraft: "node"
                            profile: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            profileDraft: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            agents: [
                                {
                                    key: "added", kind: SENSOR, status: ENABLED,
                                    config: null, draft: "value = 'added'"
                                },
                                {
                                    key: "agent", kind: SENSOR, status: ENABLED,
                                    config: "value = 'old'", draft: "value = 'new'"
                                }
                            ]
                            externalServices: [
                                {
                                    key: "added", kind: DATA_STORE, status: ENABLED,
                                    draft: "value = 'added'"
                                },
                                {
                                    key: "service", kind: DATA_STORE, status: ENABLED,
                                    draft: "value = 'new'"
                                }
                            ]
                        }
                        new: {
                            nameDraft: "node"
                            profileDraft: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            agents: [{
                                key: "agent", kind: SENSOR, status: ENABLED, draft: "value = 'new'"
                            }]
                            externalServices: [{
                                key: "service", kind: DATA_STORE, status: ENABLED, draft: "value = 'new'"
                            }]
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        {
            let store = schema.store();
            let (reduced, _, _) = store
                .node_map()
                .get_by_id(0)
                .expect("read node after the removal")
                .expect("node exists");

            assert_eq!(reduced.agents.len(), 1);
            assert_eq!(reduced.external_services.len(), 1);

            let remaining_agent = reduced.agents.first().expect("one agent remains");
            assert_eq!(remaining_agent.key, "agent");
            assert_eq!(
                remaining_agent.installed_version,
                installed_agent.installed_version
            );
            assert_eq!(
                remaining_agent.installed_commit,
                installed_agent.installed_commit
            );
            assert_eq!(remaining_agent.lifecycle, installed_agent.lifecycle);
            assert_eq!(remaining_agent.bound_addrs, installed_agent.bound_addrs);
            assert_eq!(remaining_agent.instance, installed_agent.instance);

            let remaining_service = reduced
                .external_services
                .first()
                .expect("one external service remains");
            assert_eq!(remaining_service.key, "service");
            assert_eq!(
                remaining_service.installed_version,
                installed_service.installed_version
            );
            assert_eq!(
                remaining_service.installed_commit,
                installed_service.installed_commit
            );
            assert_eq!(remaining_service.lifecycle, installed_service.lifecycle);
            assert_eq!(remaining_service.bound_addrs, installed_service.bound_addrs);
            assert_eq!(remaining_service.instance, installed_service.instance);
        }

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNodeDraft(
                        id: "0"
                        node: {
                            name: "node"
                            nameDraft: "node"
                            profile: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            profileDraft: {
                                customerId: 0, description: "description", hostname: "node.example.com"
                            }
                            agents: [{
                                key: "agent", kind: SENSOR, status: ENABLED,
                                config: "value = 'old'", draft: "value = 'new'"
                            }]
                            externalServices: [{
                                key: "service", kind: DATA_STORE, status: ENABLED, draft: "value = 'new'"
                            }]
                        }
                    ) { id }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);

        let store = schema.store();
        let (applied, _, _) = store
            .node_map()
            .get_by_id(0)
            .expect("read applied node")
            .expect("applied node exists");
        let applied_agent = applied.agents.first().expect("agent remains installed");
        assert_eq!(
            applied_agent.installed_version,
            installed_agent.installed_version
        );
        assert_eq!(
            applied_agent.installed_commit,
            installed_agent.installed_commit
        );
        assert_eq!(applied_agent.lifecycle, installed_agent.lifecycle);
        assert_eq!(applied_agent.bound_addrs, installed_agent.bound_addrs);
        assert_eq!(applied_agent.instance, installed_agent.instance);
        let applied_service = applied
            .external_services
            .first()
            .expect("external service remains installed");
        assert_eq!(
            applied_service.installed_version,
            installed_service.installed_version
        );
        assert_eq!(
            applied_service.installed_commit,
            installed_service.installed_commit
        );
        assert_eq!(applied_service.lifecycle, installed_service.lifecycle);
        assert_eq!(applied_service.bound_addrs, installed_service.bound_addrs);
        assert_eq!(applied_service.instance, installed_service.instance);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn update_node_name() {
        let schema = TestSchema::new().await;

        // check empty
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "0"}}"#);

        // insert node
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                        },
                        {
                            key: "sensor"
                            kind: SENSOR
                            status: ENABLED
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // check node count after insert
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "1"}}"#);

        // check inserted node
        let res = schema
            .execute_as_system_admin(
                r#"{node(id: "0") {
                    id
                    name
                    nameDraft
                    profile {
                        customerId
                        description
                        hostname
                    }
                    profileDraft {
                        customerId
                        description
                        hostname
                    }
                    agents {
                        key
                        kind
                        status
                    }
                    externalServices {
                        nodeId
                        key
                        kind
                        status
                        draft
                    }
                }}"#,
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "node": {
                    "id": "0",
                    "name": "admin node",
                    "nameDraft": "admin node",
                    "profile": null,
                    "profileDraft": {
                        "customerId": "0",
                        "description": "This is the admin node running review.",
                        "hostname": "admin.aice-security.com",
                    },
                    "agents": [{
                        "key": "unsupervised",
                        "kind": "UNSUPERVISED",
                        "status": "ENABLED",
                    },
                    {
                        "key": "sensor",
                        "kind": "SENSOR",
                        "status": "ENABLED",
                    }],
                    "externalServices": [],
                }
            })
        );

        // update node (update name, update profile_draft to null)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: null,
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    config: null,
                                    draft: null
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    config: null,
                                    draft: null
                                }
                            ],
                            externalServices: []
                        },
                        new: {
                            nameDraft: "AdminNode",
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    draft: null
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    draft: null
                                }
                            ],
                            externalServices: null
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node count after update
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "1"}}"#);

        // check updated node
        let res = schema
            .execute_as_system_admin(
                r#"{node(id: "0") {
                    id
                    name
                    nameDraft
                    profile {
                        customerId
                        description
                        hostname
                    }
                    profileDraft {
                        customerId
                        description
                        hostname
                    }

                }}"#,
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "node": {
                    "id": "0",
                    "name": "admin node", // stays the same
                    "nameDraft": "AdminNode", // updated
                    "profile": null,
                    "profileDraft": null, // updated
                }
            })
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn update_node_agents() {
        let schema = TestSchema::new().await;

        // Check initial node list (should be empty)
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "0"}}"#);

        // Insert node with unsupervised and semi-supervised agents
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "unsupervised",
                            kind: UNSUPERVISED,
                            status: ENABLED,
                            draft: ""
                        },
                        {
                            key: "semi-supervised",
                            kind: SEMI_SUPERVISED,
                            status: ENABLED,
                            draft: ""
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Check node count after insert
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "1"}}"#);

        // Remove the unsupervised agent
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                updateNodeDraft(
                    id: "0",
                    old: {
                        name: "admin node",
                        nameDraft: "admin node",
                        profile: null,
                        profileDraft: {
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                        },
                        agents: [
                            {
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: ENABLED,
                                draft: ""
                            },
                            {
                                key: "semi-supervised",
                                kind: SEMI_SUPERVISED,
                                status: ENABLED,
                                draft: ""
                            }
                        ],
                        externalServices: []
                    },
                    new: {
                        nameDraft: "admin node",
                        profileDraft: {
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                        },
                        agents: [
                            {
                                key: "semi-supervised",
                                kind: SEMI_SUPERVISED,
                                status: ENABLED,
                                draft: ""
                            }
                        ],
                        externalServices: null
                    }
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // Add a sensor agent
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                updateNodeDraft(
                    id: "0",
                    old: {
                        name: "admin node",
                        nameDraft: "admin node",
                        profile: null,
                        profileDraft: {
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                        },
                        agents: [
                            {
                                key: "semi-supervised",
                                kind: SEMI_SUPERVISED,
                                status: ENABLED,
                                draft: ""
                            }
                        ],
                        externalServices: []
                    },
                    new: {
                        nameDraft: "admin node",
                        profileDraft: {
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                        },
                        agents: [
                            {
                                key: "semi-supervised",
                                kind: SEMI_SUPERVISED,
                                status: ENABLED,
                                draft: ""
                            },
                            {
                                key: "sensor",
                                kind: SENSOR,
                                status: ENABLED,
                                draft: ""
                            }
                        ],
                        externalServices: null
                    }
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // Check final node state
        let res = schema
            .execute_as_system_admin(
                r#"{node(id: "0") {
                    id
                    name
                    nameDraft
                    profile {
                        customerId
                        description
                        hostname
                    }
                    profileDraft {
                        customerId
                        description
                        hostname
                    }
                    agents {
                        key
                        kind
                        status
                        config
                        draft
                    }
                    externalServices {
                        nodeId
                        key
                        kind
                        status
                        draft
                    }
                }
            }"#,
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "node": {
                    "id": "0",
                    "name": "admin node",
                    "nameDraft": "admin node",
                    "profile": null,
                    "profileDraft": {
                        "customerId": "0",
                        "description": "This is the admin node running review.",
                        "hostname": "admin.aice-security.com",
                    },
                    "agents": [
                        {
                            "key": "semi-supervised",
                            "kind": "SEMI_SUPERVISED",
                            "status": "ENABLED",
                            "config": null,
                            "draft": ""
                        },
                        {
                            "key": "sensor",
                            "kind": "SENSOR",
                            "status": "ENABLED",
                            "config": null,
                            "draft": ""
                        }
                    ],
                    "externalServices": [],
                }
            })
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn update_node_agents_with_outdated_old_value() {
        let schema = TestSchema::new().await;

        // Check initial node list (should be empty)
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "0"}}"#);

        // Insert node with unsupervised and semi-supervised agents
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "unsupervised",
                            kind: UNSUPERVISED,
                            status: ENABLED,
                            draft: ""
                        },
                        {
                            key: "semi-supervised",
                            kind: SEMI_SUPERVISED,
                            status: ENABLED,
                            draft: ""
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Check node count after insert
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "1"}}"#);

        // update node with an outdated agent old value
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                updateNodeDraft(
                    id: "0",
                    old: {
                        name: "admin node",
                        nameDraft: "admin node",
                        profile: null,
                        profileDraft: {
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                        },
                        agents: [
                            {
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: ENABLED,
                                draft: ""
                            },
                            {
                                key: "semi-supervised",
                                kind: SEMI_SUPERVISED,
                                status: ENABLED,
                                draft: "test=0"
                            }
                        ],
                        externalServices: []
                    },
                    new: {
                        nameDraft: "admin node",
                        profileDraft: {
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                        },
                        agents: [
                            {
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: ENABLED,
                                draft: ""
                            },
                            {
                                key: "semi-supervised",
                                kind: SEMI_SUPERVISED,
                                status: ENABLED,
                                draft: "test=1"
                            }
                        ],
                        externalServices: null
                    }
                )
            }"#,
            )
            .await;

        // assert error occurs
        assert_ne!(res.errors, Vec::new());

        // Check node state
        let res = schema
            .execute_as_system_admin(
                r#"{node(id: "0") {
                    id
                    name
                    nameDraft
                    profile {
                        customerId
                        description
                        hostname
                    }
                    profileDraft {
                        customerId
                        description
                        hostname
                    }
                    agents {
                        key
                        kind
                        status
                        config
                        draft
                    }
                    externalServices {
                        nodeId
                        key
                        kind
                        status
                        draft
                    }
                }
            }"#,
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "node": {
                    "id": "0",
                    "name": "admin node",
                    "nameDraft": "admin node",
                    "profile": null,
                    "profileDraft": {
                        "customerId": "0",
                        "description": "This is the admin node running review.",
                        "hostname": "admin.aice-security.com",
                    },
                    "agents": [
                        {
                            "key": "unsupervised",
                            "kind": "UNSUPERVISED",
                            "status": "ENABLED",
                            "config": null,
                            "draft": ""
                        },
                        {
                            "key": "semi-supervised",
                            "kind": "SEMI_SUPERVISED",
                            "status": "ENABLED",
                            "config": null,
                            "draft": ""
                        }
                    ],
                    "externalServices": [],
                }
            })
        );

        // update node with an outdated agent old value
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                updateNodeDraft(
                    id: "0",
                    old: {
                        name: "admin node",
                        nameDraft: "admin node",
                        profile: null,
                        profileDraft: {
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                        },
                        agents: [
                            {
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: UNKNOWN,
                                draft: ""
                            },
                            {
                                key: "semi-supervised",
                                kind: SEMI_SUPERVISED,
                                status: DISABLED,
                                draft: ""
                            }
                        ],
                        externalServices: []
                    },
                    new: {
                        nameDraft: "admin node",
                        profileDraft: {
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                        },
                        agents: [
                            {
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: RELOAD_FAILED,
                                draft: ""
                            },
                            {
                                key: "semi-supervised",
                                kind: SEMI_SUPERVISED,
                                status: RELOAD_FAILED,
                                draft: ""
                            }
                        ],
                        externalServices: null
                    }
                )
            }"#,
            )
            .await;

        // assert error occurs
        assert_ne!(res.errors, Vec::new());

        // Check node state
        let res = schema
            .execute_as_system_admin(
                r#"{node(id: "0") {
                    id
                    name
                    nameDraft
                    profile {
                        customerId
                        description
                        hostname
                    }
                    profileDraft {
                        customerId
                        description
                        hostname
                    }
                    agents {
                        key
                        kind
                        status
                        config
                        draft
                    }
                    externalServices {
                        nodeId
                        key
                        kind
                        status
                        draft
                    }
                }
            }"#,
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "node": {
                    "id": "0",
                    "name": "admin node",
                    "nameDraft": "admin node",
                    "profile": null,
                    "profileDraft": {
                        "customerId": "0",
                        "description": "This is the admin node running review.",
                        "hostname": "admin.aice-security.com",
                    },
                    "agents": [
                        {
                            "key": "unsupervised",
                            "kind": "UNSUPERVISED",
                            "status": "ENABLED",
                            "config": null,
                            "draft": ""
                        },
                        {
                            "key": "semi-supervised",
                            "kind": "SEMI_SUPERVISED",
                            "status": "ENABLED",
                            "config": null,
                            "draft": ""
                        }
                    ],
                    "externalServices": [],
                }
            })
        );
    }

    /// Test that admin users (`customer_ids` = None) can access all nodes
    #[tokio::test]
    async fn node_customer_scoping_read_admin_allowed() {
        let schema = TestSchema::new().await;

        // TestSchema already creates an admin account for "testuser" with customer_ids = None

        // Insert nodes with different customer_ids
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_1",
                        customerId: 1,
                        description: "Node for customer 1",
                        hostname: "host1.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2",
                        customerId: 2,
                        description: "Node for customer 2",
                        hostname: "host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "1"}"#);

        // Admin can read any node
        let res = schema
            .execute_as_system_admin(r#"{node(id: "0") { id name }}"#)
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({"node": {"id": "0", "name": "node_customer_1"}})
        );

        let res = schema
            .execute_as_system_admin(r#"{node(id: "1") { id name }}"#)
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({"node": {"id": "1", "name": "node_customer_2"}})
        );

        // Admin can list all nodes
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount edges{node{name}}}}")
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 2);
    }

    /// Test that scoped users can only access nodes matching their `customer_ids`
    #[tokio::test]
    async fn node_customer_scoping_read_allowed() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(&schema.store(), "node_customer_1", 1, "host1.example.com");
        let id1 = insert_active_node(&schema.store(), "node_customer_2", 2, "host2.example.com");
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);

        // Update account to be scoped to customer 1 only
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user can read node with matching customer_id
        let res = schema
            .execute_as_scoped_user(
                r#"{node(id: "0") { id name }}"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({"node": {"id": "0", "name": "node_customer_1"}})
        );
    }

    /// Test that scoped users are denied access to nodes not matching their `customer_ids`
    #[tokio::test]
    async fn node_customer_scoping_read_forbidden() {
        let schema = TestSchema::new().await;

        // TestSchema creates an admin account - insert nodes first

        // Insert node with customer_id 2 (as admin)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2",
                        customerId: 2,
                        description: "Node for customer 2",
                        hostname: "host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Update account to be scoped to customer 1 only
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user is denied read access to non-matching customer_id
        let res = schema
            .execute_as_scoped_user(
                r#"{node(id: "0") { id name }}"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Test that admin users can read draft-only nodes.
    #[tokio::test]
    async fn node_customer_scoping_draft_profile_read_admin_allowed() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2_draft_only",
                        customerId: 2,
                        description: "Draft-only node for customer 2",
                        hostname: "draft-host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"{node(id: "0") { id name }}"#)
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({"node": {"id": "0", "name": "node_customer_2_draft_only"}})
        );
    }

    /// Test that scoped users can access draft-only nodes matching their `customer_ids`.
    #[tokio::test]
    async fn node_customer_scoping_draft_profile_read_allowed() {
        let schema = TestSchema::new().await;

        // Insert node first; inserted nodes start as draft-only (`profile` = null).
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_1_draft_only",
                        customerId: 1,
                        description: "Draft-only node for customer 1",
                        hostname: "draft-host1.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user should be able to read a draft-only node for their customer.
        let res = schema
            .execute_as_scoped_user(
                r#"{node(id: "0") { id name }}"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({"node": {"id": "0", "name": "node_customer_1_draft_only"}})
        );
    }

    /// Test that scoped users cannot access draft-only nodes for other customers.
    #[tokio::test]
    async fn node_customer_scoping_draft_profile_read_forbidden() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2_draft_only",
                        customerId: 2,
                        description: "Draft-only node for customer 2",
                        hostname: "draft-host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r#"{node(id: "0") { id name }}"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Test that admin users can list all nodes.
    #[tokio::test]
    async fn node_customer_scoping_list_admin_allowed() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(
            &schema.store(),
            "node_customer_1_a",
            1,
            "host1a.example.com",
        );
        let id1 = insert_active_node(&schema.store(), "node_customer_2", 2, "host2.example.com");
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);

        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount edges{node{name}}}}")
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 2);
        assert_eq!(data["nodeList"]["totalCount"], json!("2"));
    }

    /// Test that node list returns only matching nodes for scoped users
    #[tokio::test]
    async fn node_customer_scoping_list_allowed() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(
            &schema.store(),
            "node_customer_1_a",
            1,
            "host1a.example.com",
        );
        let id1 = insert_active_node(&schema.store(), "node_customer_2", 2, "host2.example.com");
        let id2 = insert_active_node(
            &schema.store(),
            "node_customer_1_b",
            1,
            "host1b.example.com",
        );
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);

        // Update account to be scoped to customer 1 only
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user list only sees nodes with matching customer_id
        let res = schema
            .execute_as_scoped_user(
                r"{nodeList{edges{node{name}}}}",
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        // Should only see 2 nodes (both for customer 1)
        assert_eq!(edges.len(), 2);
        let names: Vec<&str> = edges
            .iter()
            .map(|e| e["node"]["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"node_customer_1_a"));
        assert!(names.contains(&"node_customer_1_b"));
        assert!(!names.contains(&"node_customer_2"));
    }

    /// Test that scoped users get an empty list when all nodes are out of scope.
    #[tokio::test]
    async fn node_customer_scoping_list_forbidden() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(&schema.store(), "node_customer_2", 2, "host2.example.com");
        assert_eq!(id0, 0);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r"{nodeList{totalCount edges{node{name}}}}",
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 0);
        assert_eq!(data["nodeList"]["totalCount"], json!("0"));
    }

    /// Tests that admin users can paginate over all nodes.
    #[tokio::test]
    async fn node_customer_scoping_pagination_admin_allowed() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(
            &schema.store(),
            "a_customer_2_node",
            2,
            "customer2.example.com",
        );
        let id1 = insert_active_node(
            &schema.store(),
            "b_customer_1_node",
            1,
            "customer1.example.com",
        );
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);

        let res = schema
            .execute_as_system_admin(
                r"{nodeList(first: 1){edges{node{name}} pageInfo{hasNextPage hasPreviousPage}}}",
            )
            .await;

        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["name"], "a_customer_2_node");
        assert_eq!(data["nodeList"]["pageInfo"]["hasNextPage"], json!(true));
        assert_eq!(
            data["nodeList"]["pageInfo"]["hasPreviousPage"],
            json!(false)
        );
    }

    /// Tests that pagination skips inaccessible nodes when fetching the first page.
    #[tokio::test]
    async fn node_customer_scoping_pagination_allowed() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(
            &schema.store(),
            "a_forbidden_node",
            2,
            "forbidden.example.com",
        );
        let id1 = insert_active_node(&schema.store(), "b_allowed_node", 1, "allowed.example.com");
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);

        // Scope the user to customer 1 only.
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r"{nodeList(first: 1){edges{node{name}} pageInfo{hasNextPage hasPreviousPage}}}",
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;

        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();

        // The first page must contain the first accessible node, not an empty page.
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["name"], "b_allowed_node");
        assert_eq!(data["nodeList"]["pageInfo"]["hasNextPage"], json!(false));
        assert_eq!(
            data["nodeList"]["pageInfo"]["hasPreviousPage"],
            json!(false)
        );
    }

    /// Tests that pagination returns no nodes when all nodes are inaccessible.
    #[tokio::test]
    async fn node_customer_scoping_pagination_forbidden() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(
            &schema.store(),
            "a_forbidden_node",
            2,
            "forbidden.example.com",
        );
        assert_eq!(id0, 0);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r"{nodeList(first: 1){edges{node{name}} pageInfo{hasNextPage hasPreviousPage}}}",
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 0);
        assert_eq!(data["nodeList"]["pageInfo"]["hasNextPage"], json!(false));
        assert_eq!(
            data["nodeList"]["pageInfo"]["hasPreviousPage"],
            json!(false)
        );
    }

    /// Test insert allowed for system administrators regardless of `customer_id`.
    #[tokio::test]
    async fn node_customer_scoping_insert_admin_allowed() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2",
                        customerId: 2,
                        description: "Node for customer 2",
                        hostname: "host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);
    }

    /// Test insert allowed for matching `customer_id`.
    #[tokio::test]
    async fn node_customer_scoping_insert_allowed() {
        let schema = TestSchema::new().await;

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    insertNode(
                        name: "node_customer_1",
                        customerId: 1,
                        description: "Node for customer 1",
                        hostname: "host1.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);
    }

    /// Test insert denied for non-matching `customer_id`
    #[tokio::test]
    async fn node_customer_scoping_insert_forbidden() {
        let schema = TestSchema::new().await;

        // Update the default admin account to be scoped to customer 1 only
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user cannot insert node for customer 2
        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2",
                        customerId: 2,
                        description: "Node for customer 2",
                        hostname: "host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Tests that totalCount includes all nodes for system administrators.
    #[tokio::test]
    async fn node_customer_scoping_total_count_admin_allowed() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(
            &schema.store(),
            "count_node_customer_1",
            1,
            "host1.example.com",
        );
        let id1 = insert_active_node(
            &schema.store(),
            "count_node_customer_2",
            2,
            "host2.example.com",
        );
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);

        let res = schema
            .execute_as_system_admin(r"{nodeList(first: 10){totalCount edges{node{name}}}}")
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );

        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 2);
        assert_eq!(data["nodeList"]["totalCount"], json!("2"));
    }

    /// Tests that totalCount is scoped to accessible customers.
    #[tokio::test]
    async fn node_customer_scoping_total_count_allowed() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(
            &schema.store(),
            "count_node_customer_1",
            1,
            "host1.example.com",
        );
        let id1 = insert_active_node(
            &schema.store(),
            "count_node_customer_2",
            2,
            "host2.example.com",
        );
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r"{nodeList(first: 10){totalCount edges{node{name}}}}",
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;

        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );

        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["name"], "count_node_customer_1");
        assert_eq!(data["nodeList"]["totalCount"], json!("1"));
    }

    /// Tests that totalCount is zero when all nodes are inaccessible.
    #[tokio::test]
    async fn node_customer_scoping_total_count_forbidden() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(
            &schema.store(),
            "count_node_customer_2",
            2,
            "host2.example.com",
        );
        assert_eq!(id0, 0);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r"{nodeList(first: 10){totalCount edges{node{name}}}}",
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );

        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 0);
        assert_eq!(data["nodeList"]["totalCount"], json!("0"));
    }

    /// Test update allowed for system administrators regardless of `customer_id`.
    #[tokio::test]
    async fn node_customer_scoping_update_admin_allowed() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2",
                        customerId: 2,
                        description: "Node for customer 2",
                        hostname: "host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "node_customer_2",
                            nameDraft: "node_customer_2",
                            profile: null,
                            profileDraft: {
                                customerId: 2,
                                description: "Node for customer 2",
                                hostname: "host2.example.com",
                            },
                            agents: [],
                            externalServices: []
                        },
                        new: {
                            nameDraft: "updated_by_admin",
                            profileDraft: null,
                            agents: null,
                            externalServices: null
                        }
                    )
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);
    }

    /// Test update allowed for matching `customer_id`.
    #[tokio::test]
    async fn node_customer_scoping_update_allowed() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_1",
                        customerId: 1,
                        description: "Node for customer 1",
                        hostname: "host1.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "node_customer_1",
                            nameDraft: "node_customer_1",
                            profile: null,
                            profileDraft: {
                                customerId: 1,
                                description: "Node for customer 1",
                                hostname: "host1.example.com",
                            },
                            agents: [],
                            externalServices: []
                        },
                        new: {
                            nameDraft: "updated_name",
                            profileDraft: null,
                            agents: null,
                            externalServices: null
                        }
                    )
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);
    }

    /// Test update denied for non-matching `customer_id`
    #[tokio::test]
    async fn node_customer_scoping_update_forbidden() {
        let schema = TestSchema::new().await;

        // TestSchema creates an admin account - insert nodes first

        // Insert node with customer 2 (as admin)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2",
                        customerId: 2,
                        description: "Node for customer 2",
                        hostname: "host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Update account to be scoped to customer 1 only
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user cannot update node with non-matching customer_id
        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "node_customer_2",
                            nameDraft: "node_customer_2",
                            profile: null,
                            profileDraft: {
                                customerId: 2,
                                description: "Node for customer 2",
                                hostname: "host2.example.com",
                            },
                            agents: [],
                            externalServices: []
                        },
                        new: {
                            nameDraft: "updated_name",
                            profileDraft: null,
                            agents: null,
                            externalServices: null
                        }
                    )
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Test update denied when a scoped user changes the draft customer to an inaccessible one.
    #[tokio::test]
    async fn node_customer_scoping_update_draft_customer_change_forbidden() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_1",
                        customerId: 1,
                        description: "Node for customer 1",
                        hostname: "host1.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "node_customer_1",
                            nameDraft: "node_customer_1",
                            profile: null,
                            profileDraft: {
                                customerId: 1,
                                description: "Node for customer 1",
                                hostname: "host1.example.com",
                            },
                            agents: [],
                            externalServices: []
                        },
                        new: {
                            nameDraft: "updated_name",
                            profileDraft: {
                                customerId: 2,
                                description: "Moved to customer 2",
                                hostname: "host2.example.com",
                            },
                            agents: null,
                            externalServices: null
                        }
                    )
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Test remove allowed for system administrators regardless of `customer_id`.
    #[tokio::test]
    async fn node_customer_scoping_remove_admin_allowed() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2",
                        customerId: 2,
                        description: "Node for customer 2",
                        hostname: "host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute_as_system_admin(r#"mutation { removeNodes(ids: ["0"]) }"#)
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(
            res.data.to_string(),
            r#"{removeNodes: ["node_customer_2"]}"#
        );
    }

    /// Test remove allowed for matching `customer_id`.
    #[tokio::test]
    async fn node_customer_scoping_remove_allowed() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_1",
                        customerId: 1,
                        description: "Node for customer 1",
                        hostname: "host1.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r#"mutation { removeNodes(ids: ["0"]) }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(
            res.data.to_string(),
            r#"{removeNodes: ["node_customer_1"]}"#
        );
    }

    /// Test remove denied for non-matching `customer_id`
    #[tokio::test]
    async fn node_customer_scoping_remove_forbidden() {
        let schema = TestSchema::new().await;

        // TestSchema creates an admin account - insert nodes first

        // Insert node with customer 2 (as admin)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_2",
                        customerId: 2,
                        description: "Node for customer 2",
                        hostname: "host2.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Update account to be scoped to customer 1 only
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user cannot remove node with non-matching customer_id
        let res = schema
            .execute_as_scoped_user(
                r#"mutation { removeNodes(ids: ["0"]) }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Test remove validates all IDs before deleting any nodes for scoped users.
    #[tokio::test]
    async fn node_customer_scoping_remove_forbidden_keeps_all_nodes() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(&schema.store(), "node_customer_1", 1, "host1.example.com");
        let id1 = insert_active_node(&schema.store(), "node_customer_2", 2, "host2.example.com");
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_as_scoped_user(
                r#"mutation { removeNodes(ids: ["0", "1"]) }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");

        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount edges{node{id name}}}}")
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": "2",
                    "edges": [
                        {"node": {"id": "0", "name": "node_customer_1"}},
                        {"node": {"id": "1", "name": "node_customer_2"}}
                    ]
                }
            })
        );
    }

    /// Test remove validates all IDs before deleting any nodes when a later ID is missing.
    #[tokio::test]
    async fn node_remove_missing_id_keeps_existing_nodes() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(&schema.store(), "node_customer_1", 1, "host1.example.com");
        assert_eq!(id0, 0);

        let res = schema
            .execute_as_system_admin(r#"mutation { removeNodes(ids: ["0", "999"]) }"#)
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "no such node");

        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount edges{node{id name}}}}")
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": "1",
                    "edges": [
                        {"node": {"id": "0", "name": "node_customer_1"}}
                    ]
                }
            })
        );
    }

    /// Test that system administrators remain unscoped even when account has empty `customer_ids`.
    #[tokio::test]
    async fn node_customer_scoping_empty_customers_admin_allowed() {
        let schema = TestSchema::new().await;

        let id0 = insert_active_node(&schema.store(), "some_node", 1, "host.example.com");
        assert_eq!(id0, 0);

        update_account_customers(&schema.store(), "testuser", Some(vec![]));

        let res = schema
            .execute_as_system_admin(r#"{node(id: "0") { id name }}"#)
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({"node": {"id": "0", "name": "some_node"}})
        );
    }

    /// Test that empty `customer_ids` means no access to any node
    #[tokio::test]
    async fn node_customer_scoping_empty_customers_forbidden() {
        let schema = TestSchema::new().await;

        // TestSchema creates an admin account - insert nodes first

        // Insert node (as admin)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "some_node",
                        customerId: 1,
                        description: "A node",
                        hostname: "host.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Update account to have empty customer list (no access)
        update_account_customers(&schema.store(), "testuser", Some(vec![]));

        // Scoped user with empty customers cannot read any node
        let res = schema
            .execute_as_scoped_user(
                r#"{node(id: "0") { id name }}"#,
                Role::SecurityAdministrator,
                Some(vec![]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");

        // List should be empty
        let res = schema
            .execute_as_scoped_user(
                r"{nodeList{edges{node{name}}}}",
                Role::SecurityAdministrator,
                Some(vec![]),
            )
            .await;
        assert_eq!(res.errors, Vec::new());
        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 0);
    }

    const INSTALLED_HOST: &str = "host1.example.com";

    /// Stores a node holding numbered agent `001.piglet` and numbered Giganto
    /// service `002.giganto`, next to unnumbered agent `hog` and unnumbered
    /// Giganto service `giganto`.
    fn put_installed_node(store: &review_database::Store, name: &str) -> u32 {
        put_installed_node_on(store, name, Some(INSTALLED_HOST))
    }

    fn put_installed_node_on(
        store: &review_database::Store,
        name: &str,
        hostname: Option<&str>,
    ) -> u32 {
        put_node(
            store,
            name,
            hostname,
            vec![
                installed_agent(
                    "001.piglet",
                    review_database::AgentKind::Sensor,
                    Some("a = 1"),
                    Some(1),
                ),
                installed_agent(
                    "hog",
                    review_database::AgentKind::SemiSupervised,
                    Some("b = 1"),
                    None,
                ),
            ],
            vec![
                installed_service(
                    "002.giganto",
                    review_database::ExternalServiceKind::DataStore,
                    Some(""),
                    Some(2),
                ),
                installed_service(
                    "giganto",
                    review_database::ExternalServiceKind::DataStore,
                    Some("c = 1"),
                    None,
                ),
            ],
        )
    }

    async fn update_draft(
        schema: &TestSchema,
        id: u32,
        old: &review_database::Node,
        new: &str,
    ) -> async_graphql::Response {
        schema
            .execute_as_system_admin(&format!(
                "mutation {{ updateNodeDraft(id: \"{id}\", old: {}, new: {new}) }}",
                super::super::test_support::node_input(old)
            ))
            .await
    }

    fn only_error(res: &async_graphql::Response) -> &str {
        assert_eq!(res.errors.len(), 1, "expected one error: {:?}", res.errors);
        &res.errors[0].message
    }

    #[tokio::test]
    async fn update_node_draft_refuses_dropping_a_numbered_row() {
        let schema = TestSchema::new().await;
        let id = put_installed_node(&schema.store(), "installed");
        let stored = stored_node(&schema.store(), id);

        let mut new = stored.clone();
        new.agents.retain(|a| a.key != "001.piglet");
        let res = update_draft(&schema, id, &stored, &node_draft_input(&new, true, true)).await;
        let err = only_error(&res);
        assert!(err.contains("Node \"installed\" (ID 0)"), "{err}");
        assert!(
            err.contains("delete installed instance rows 001.piglet"),
            "{err}"
        );
        assert!(err.contains("removeService"), "{err}");
        assert_eq!(stored_node(&schema.store(), id), stored);

        let mut new = stored.clone();
        new.external_services.retain(|s| s.key != "002.giganto");
        let res = update_draft(&schema, id, &stored, &node_draft_input(&new, true, true)).await;
        let err = only_error(&res);
        assert!(
            err.contains("delete installed instance rows 002.giganto"),
            "{err}"
        );
        assert_eq!(stored_node(&schema.store(), id), stored);
    }

    #[tokio::test]
    async fn update_node_draft_refuses_omitting_a_list_with_a_numbered_row() {
        let schema = TestSchema::new().await;
        let id = put_installed_node(&schema.store(), "installed");
        let stored = stored_node(&schema.store(), id);

        let res = update_draft(
            &schema,
            id,
            &stored,
            &node_draft_input(&stored, false, true),
        )
        .await;
        let err = only_error(&res);
        assert!(
            err.contains("delete installed instance rows 001.piglet"),
            "{err}"
        );
        assert!(!err.contains("hog"), "{err}");
        assert_eq!(stored_node(&schema.store(), id), stored);

        let res = update_draft(
            &schema,
            id,
            &stored,
            &node_draft_input(&stored, true, false),
        )
        .await;
        let err = only_error(&res);
        assert!(
            err.contains("delete installed instance rows 002.giganto"),
            "{err}"
        );
        assert_eq!(stored_node(&schema.store(), id), stored);
    }

    #[tokio::test]
    async fn update_node_draft_checks_each_list_on_its_own() {
        let schema = TestSchema::new().await;
        let id = put_node(
            &schema.store(),
            "service only",
            Some(INSTALLED_HOST),
            vec![installed_agent(
                "hog",
                review_database::AgentKind::SemiSupervised,
                Some("b = 1"),
                None,
            )],
            vec![installed_service(
                "002.giganto",
                review_database::ExternalServiceKind::DataStore,
                Some(""),
                Some(2),
            )],
        );
        let stored = stored_node(&schema.store(), id);

        let res = update_draft(
            &schema,
            id,
            &stored,
            &node_draft_input(&stored, false, true),
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let updated = stored_node(&schema.store(), id);
        assert_eq!(updated.agents.len(), 0);
        assert_eq!(updated.external_services, stored.external_services);
    }

    #[tokio::test]
    async fn update_node_draft_refuses_changing_a_numbered_rows_kind() {
        let schema = TestSchema::new().await;
        let id = put_installed_node(&schema.store(), "installed");
        let stored = stored_node(&schema.store(), id);

        let mut new = stored.clone();
        new.agents[0].kind = review_database::AgentKind::Unsupervised;
        let res = update_draft(&schema, id, &stored, &node_draft_input(&new, true, true)).await;
        let err = only_error(&res);
        assert!(
            err.contains("change the kind of installed instance rows 001.piglet"),
            "{err}"
        );
        assert!(err.contains("removeService"), "{err}");
        assert_eq!(stored_node(&schema.store(), id), stored);
    }

    #[tokio::test]
    async fn update_node_draft_keeps_numbered_rows_and_deletes_unnumbered_ones() {
        let schema = TestSchema::new().await;
        let id = put_installed_node(&schema.store(), "installed");
        let stored = stored_node(&schema.store(), id);

        let mut new = stored.clone();
        new.name_draft = Some("renamed".to_string());
        new.agents.retain(|a| a.key != "hog");
        new.external_services.retain(|s| s.key != "giganto");
        new.agents[0].draft = Some("a = 2".to_string().try_into().expect("valid toml"));
        let res = update_draft(&schema, id, &stored, &node_draft_input(&new, true, true)).await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);

        let updated = stored_node(&schema.store(), id);
        assert_eq!(updated.name_draft.as_deref(), Some("renamed"));
        assert_eq!(updated.agents.len(), 1);
        let agent = &updated.agents[0];
        assert_eq!(agent.key, "001.piglet");
        assert_eq!(agent.instance, Some(1));
        assert_eq!(agent.installed_version, stored.agents[0].installed_version);
        assert_eq!(
            agent.draft.as_ref().map(AsRef::as_ref),
            Some("a = 2"),
            "the numbered row's draft is still editable"
        );
        assert_eq!(updated.external_services.len(), 1);
        assert_eq!(updated.external_services[0].key, "002.giganto");
        assert_eq!(updated.external_services[0].instance, Some(2));
    }

    #[tokio::test]
    async fn update_node_draft_with_stale_old_reports_entry_changed() {
        let schema = TestSchema::new().await;
        let id = put_installed_node(&schema.store(), "installed");
        let stored = stored_node(&schema.store(), id);

        // `old` omits the numbered agent the store holds, so the check
        // cannot see it, and `new` leaves it out too.
        let mut stale = stored.clone();
        stale.agents.retain(|a| a.key != "001.piglet");
        let res = update_draft(&schema, id, &stale, &node_draft_input(&stale, true, true)).await;
        assert_eq!(only_error(&res), "entry changed");
        assert_eq!(stored_node(&schema.store(), id), stored);
    }

    #[tokio::test]
    async fn remove_nodes_refuses_a_node_holding_a_numbered_row() {
        let schema = TestSchema::new().await;
        let a = put_node(
            &schema.store(),
            "plain",
            Some("host0.example.com"),
            vec![installed_agent(
                "hog",
                review_database::AgentKind::SemiSupervised,
                Some("b = 1"),
                None,
            )],
            vec![],
        );
        let b = put_installed_node(&schema.store(), "installed");

        let res = schema
            .execute_as_system_admin(&format!(
                r#"mutation {{ removeNodes(ids: ["{a}", "{b}"]) }}"#
            ))
            .await;
        let err = only_error(&res);
        assert!(err.contains("Node \"installed\" (ID 1)"), "{err}");
        assert!(
            err.contains("holds installed instance rows 001.piglet, 002.giganto"),
            "{err}"
        );
        assert!(err.contains("removeService"), "{err}");
        assert!(!err.contains("plain"), "{err}");
        assert!(schema.store().node_map().get_by_id(a).unwrap().is_some());
        assert!(schema.store().node_map().get_by_id(b).unwrap().is_some());

        let res = schema
            .execute_as_system_admin(&format!(
                r#"mutation {{ removeNodes(ids: ["{b}", "999"]) }}"#
            ))
            .await;
        assert_eq!(only_error(&res), "no such node");

        let res = schema
            .execute_as_system_admin(&format!(r#"mutation {{ removeNodes(ids: ["{a}"]) }}"#))
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNodes: ["plain"]}"#);
        assert!(schema.store().node_map().get_by_id(a).unwrap().is_none());
    }

    #[tokio::test]
    async fn remove_nodes_without_hostname_reports_inconsistent_state() {
        let schema = TestSchema::new().await;
        let id = put_installed_node_on(&schema.store(), "hostless", None);

        let res = schema
            .execute_as_system_admin(&format!(r#"mutation {{ removeNodes(ids: ["{id}"]) }}"#))
            .await;
        let err = only_error(&res);
        assert!(
            err.contains("001.piglet (instance 1), 002.giganto (instance 2)"),
            "{err}"
        );
        assert!(err.contains("has no active hostname"), "{err}");
        assert!(err.contains("operator must investigate"), "{err}");
        assert!(!err.contains("removeService"), "{err}");
        assert!(schema.store().node_map().get_by_id(id).unwrap().is_some());
    }

    #[tokio::test]
    async fn remove_nodes_refuses_a_node_with_an_unreadable_row() {
        let schema = TestSchema::new().await;
        let id = put_node(
            &schema.store(),
            "unreadable",
            Some(INSTALLED_HOST),
            vec![
                installed_agent(
                    "hog",
                    review_database::AgentKind::SemiSupervised,
                    Some("b = 1"),
                    None,
                ),
                installed_agent(
                    "piglet",
                    review_database::AgentKind::Sensor,
                    Some("a = 1"),
                    None,
                ),
            ],
            vec![],
        );
        schema
            .store()
            .agents_map()
            .delete(id, "piglet")
            .expect("delete the agent row behind the node's back");
        let (_, invalid_agents, _) = schema.store().node_map().get_by_id(id).unwrap().unwrap();
        assert_eq!(invalid_agents, vec!["piglet".to_string()]);

        let res = schema
            .execute_as_system_admin(&format!(r#"mutation {{ removeNodes(ids: ["{id}"]) }}"#))
            .await;
        let err = only_error(&res);
        assert!(
            err.contains("Node \"unreadable\" (ID 0) is not removed"),
            "{err}"
        );
        assert!(err.contains("rows piglet that could not be found"), "{err}");
        assert!(err.contains("operator must investigate"), "{err}");
        assert!(!err.contains("removeService"), "{err}");
        assert!(!err.contains("holds installed"), "{err}");
        assert!(schema.store().node_map().get_by_id(id).unwrap().is_some());

        // A node that also holds a numbered row gets the actionable message,
        // listing the missing key as well.
        let installed =
            put_installed_node_on(&schema.store(), "installed", Some("host2.example.com"));
        schema
            .store()
            .agents_map()
            .delete(installed, "hog")
            .expect("delete the agent row behind the node's back");
        let res = schema
            .execute_as_system_admin(&format!(
                r#"mutation {{ removeNodes(ids: ["{installed}"]) }}"#
            ))
            .await;
        let err = only_error(&res);
        assert!(
            err.contains("holds installed instance rows 001.piglet"),
            "{err}"
        );
        assert!(err.contains("rows hog that could not be found"), "{err}");
        assert!(err.contains("removeService"), "{err}");
        assert!(
            schema
                .store()
                .node_map()
                .get_by_id(installed)
                .unwrap()
                .is_some()
        );
    }
}
