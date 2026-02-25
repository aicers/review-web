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
    Node, NodeInput, NodeMutation, NodeQuery, NodeTotalCount, gen_agent_key,
    input::{AgentDraftInput, ExternalServiceInput, NodeDraftInput},
};
use crate::{graphql::query_with_constraints, info_with_username};

/// Extracts the `customer_id` from a node.
///
/// Uses `profile.customer_id` if available (applied nodes),
/// falls back to `profile_draft.customer_id` for draft-only nodes.
fn node_customer_id(node: &review_database::Node) -> Option<u32> {
    node.profile
        .as_ref()
        .map(|p| p.customer_id)
        .or_else(|| node.profile_draft.as_ref().map(|p| p.customer_id))
}

/// Checks if the requester has access to the given node.
///
/// Returns `true` if:
/// - The requester is an admin (`users_customers` is `None`), or
/// - The node's `customer_id` is in the requester's customer list.
///
/// Returns `false` if the requester is not an admin and the node's
/// `customer_id` is not in their customer list, or if the node has no
/// `customer_id`.
pub(super) fn can_access_node(
    users_customers: Option<&[u32]>,
    node: &review_database::Node,
) -> bool {
    match users_customers {
        None => true, // Admin has access to all nodes
        Some(customers) => {
            // Non-admin: check if node's customer_id is in the user's customers
            node_customer_id(node).is_some_and(|cid| customers.contains(&cid))
        }
    }
}

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
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx)?;
        let users_customers = customer_access::users_customers(ctx)?;
        let map = store.node_map();
        let Some((node, _invalid_agents, _invalid_external_services)) = map.get_by_id(i)? else {
            return Err("no such node".into());
        };

        // Check customer scoping
        if !can_access_node(users_customers.as_deref(), &node) {
            return Err("Forbidden".into());
        }

        Ok(node.into())
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
                    node: u32::MAX,
                    key: new_agent.key,
                    kind: new_agent.kind.into(),
                    status: new_agent.status.into(),
                    config: None,
                    draft,
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
                    node: u32::MAX,
                    key: new_external_service.key,
                    kind: new_external_service.kind.into(),
                    status: new_external_service.status.into(),
                    draft,
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
    /// On error, some nodes may have been removed.
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

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

            // Check customer scoping before removing
            let Some((node, _, _)) = map.get_by_id(i)? else {
                return Err("no such node".into());
            };
            if !can_access_node(users_customers.as_deref(), &node) {
                return Err("Forbidden".into());
            }

            let (key, _invalid_agents, _invalid_external_services) = map.remove(i)?;

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
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_node_draft(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: NodeInput,
        new: NodeDraftInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let store = crate::graphql::get_store(ctx)?;
        let users_customers = customer_access::users_customers(ctx)?;
        let mut map = store.node_map();

        // Check customer scoping before updating
        let Some((node, _, _)) = map.get_by_id(i)? else {
            return Err("no such node".into());
        };
        if !can_access_node(users_customers.as_deref(), &node) {
            return Err("Forbidden".into());
        }

        let new = super::input::create_draft_update(&old, new)?;
        let old = old.try_into()?;
        map.update(i, &old, &new)?;
        info_with_username!(ctx, "Node {:?} has been modified", old.name);
        Ok(id)
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
            can_access_node(users_customers, node)
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

/// Returns a customer id and the agent key(agent@hostname) list for the node corresponding to
/// that customer id.
///
/// # Errors
///
/// Returns an error if the node profile could not be retrieved.
pub fn agent_keys_by_customer_id(db: &Store) -> Result<HashMap<u32, Vec<String>>> {
    let map = db.node_map();
    let mut customer_id_hash = HashMap::new();

    for entry in map.iter(Direction::Forward, None) {
        let node = entry.map_err(|_| "invalid value in database")?;

        if let Some(node_profile) = &node.profile {
            let agent_keys = node
                .agents
                .iter()
                .filter_map(|agent| gen_agent_key(agent.kind.into(), &node_profile.hostname).ok())
                .collect::<Vec<String>>();
            customer_id_hash
                .entry(node_profile.customer_id)
                .or_insert_with(Vec::new)
                .extend_from_slice(&agent_keys);
        }
    }
    Ok(customer_id_hash)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use review_database::{Role, types};
    use serde_json::json;

    use crate::graphql::TestSchema;

    /// Helper to create an account with specific `customer_ids`
    fn create_account_with_customers(
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

    /// Helper to update an existing account's `customer_ids`
    fn update_account_customers(
        store: &review_database::Store,
        username: &str,
        customer_ids: Option<Vec<u32>>,
    ) {
        let account_map = store.account_map();
        // Remove existing account
        let _ = account_map.delete(username);
        // Create new account with updated customer_ids
        create_account_with_customers(store, username, customer_ids);
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
                        node
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
                        node
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
                        node
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
                        node
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
        assert!(!res.errors.is_empty());

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
                        node
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
        assert!(!res.errors.is_empty());

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
                        node
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
    async fn node_customer_scoping_admin_access() {
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
    async fn node_customer_scoping_allowed_access() {
        let schema = TestSchema::new().await;

        // TestSchema creates an admin account - insert nodes first

        // Insert nodes with different customer_ids (as admin)
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

        // Update account to be scoped to customer 1 only
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user can read node with matching customer_id
        let res = schema
            .execute_with_guard(
                r#"{node(id: "0") { id name }}"#,
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
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
    async fn node_customer_scoping_denied_access() {
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
            .execute_with_guard(
                r#"{node(id: "0") { id name }}"#,
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Test that node list returns only matching nodes for scoped users
    #[tokio::test]
    async fn node_customer_scoping_list_filtering() {
        let schema = TestSchema::new().await;

        // TestSchema creates an admin account - insert nodes first

        // Insert nodes with different customer_ids (as admin)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_1_a",
                        customerId: 1,
                        description: "Node A for customer 1",
                        hostname: "host1a.example.com",
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

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node_customer_1_b",
                        customerId: 1,
                        description: "Node B for customer 1",
                        hostname: "host1b.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "2"}"#);

        // Update account to be scoped to customer 1 only
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user list only sees nodes with matching customer_id
        let res = schema
            .execute_with_guard(
                r"{nodeList{edges{node{name}}}}",
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
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

    /// Tests that pagination skips inaccessible nodes when fetching the first page.
    #[tokio::test]
    async fn node_customer_scoping_pagination_skips_inaccessible_prefix() {
        let schema = TestSchema::new().await;

        // Insert an inaccessible node that sorts first by name.
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "a_forbidden_node",
                        customerId: 2,
                        description: "Forbidden node",
                        hostname: "forbidden.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Insert an accessible node that sorts after the forbidden node.
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "b_allowed_node",
                        customerId: 1,
                        description: "Allowed node",
                        hostname: "allowed.example.com",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "1"}"#);

        // Scope the user to customer 1 only.
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_with_guard(
                r"{nodeList(first: 1){edges{node{name}} pageInfo{hasNextPage hasPreviousPage}}}",
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
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

    /// Test insert denied for non-matching `customer_id`
    #[tokio::test]
    async fn node_customer_scoping_insert_denied() {
        let schema = TestSchema::new().await;

        // Update the default admin account to be scoped to customer 1 only
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        // Scoped user cannot insert node for customer 2
        let res = schema
            .execute_with_guard(
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
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Tests that totalCount is scoped to accessible customers.
    #[tokio::test]
    async fn node_customer_scoping_total_count_should_be_scoped() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "count_node_customer_1",
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
                        name: "count_node_customer_2",
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

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));

        let res = schema
            .execute_with_guard(
                r"{nodeList(first: 10){totalCount edges{node{name}}}}",
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
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

    /// Test update denied for non-matching `customer_id`
    #[tokio::test]
    async fn node_customer_scoping_update_denied() {
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
            .execute_with_guard(
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
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Test remove denied for non-matching `customer_id`
    #[tokio::test]
    async fn node_customer_scoping_remove_denied() {
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
            .execute_with_guard(
                r#"mutation { removeNodes(ids: ["0"]) }"#,
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    /// Test that empty `customer_ids` means no access to any node
    #[tokio::test]
    async fn node_customer_scoping_empty_customers() {
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
            .execute_with_guard(
                r#"{node(id: "0") { id name }}"#,
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");

        // List should be empty
        let res = schema
            .execute_with_guard(
                r"{nodeList{edges{node{name}}}}",
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(res.errors.is_empty());
        let data = res.data.into_json().unwrap();
        let edges = data["nodeList"]["edges"].as_array().unwrap();
        assert!(edges.is_empty());
    }
}
