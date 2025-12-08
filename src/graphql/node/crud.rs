#![allow(clippy::fn_params_excessive_bools)]

use std::collections::HashMap;

use async_graphql::{
    Context, Error, Object, Result,
    connection::{Connection, EmptyFields, OpaqueCursor},
    types::ID,
};
use chrono::Utc;
use review_database::{Store, event::Direction};
use tracing::info;

use super::{
    super::{Role, RoleGuard},
    Node, NodeInput, NodeMutation, NodeQuery, NodeTotalCount, gen_agent_key,
    input::{AgentDraftInput, ExternalServiceInput, NodeDraftInput},
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
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx)?;
        let map = store.node_map();
        let Some((node, _invalid_agents, _invalid_external_services)) = map.get_by_id(i)? else {
            return Err("no such node".into());
        };
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
        let map = store.node_map();
        let customer_id = customer_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid customer ID")?;

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
        let map = store.node_map();

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
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
        let mut map = store.node_map();
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
    let map = store.node_map();
    super::super::load_edges(&map, after, before, first, last, NodeTotalCount)
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
    use serde_json::json;

    use crate::graphql::TestSchema;

    // test scenario : insert node -> update node with different name -> remove node
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn node_crud() {
        let schema = TestSchema::new().await;

        // check empty
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 0}}");

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
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

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
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

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
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 0}}");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn update_node_name() {
        let schema = TestSchema::new().await;

        // check empty
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 0}}");

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
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

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
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

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
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 0}}");

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
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

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
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 0}}");

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
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

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
}
