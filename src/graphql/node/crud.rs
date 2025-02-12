#![allow(clippy::fn_params_excessive_bools)]

use std::collections::HashMap;

use async_graphql::{
    connection::{Connection, EmptyFields, OpaqueCursor},
    types::ID,
    Context, Error, Object, Result,
};
use chrono::Utc;
use review_database::{Direction, Store};

use super::{
    super::{Role, RoleGuard},
    gen_agent_key,
    input::{AgentDraftInput, GigantoInput, NodeDraftInput},
    Node, NodeInput, NodeMutation, NodeQuery, NodeTotalCount,
};
use crate::graphql::query_with_constraints;

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

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.node_map();
        let Some((node, _invalid_agents)) = map.get_by_id(i)? else {
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
        giganto: Option<GigantoInput>,
    ) -> Result<ID> {
        let store = crate::graphql::get_store(ctx).await?;
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
            agents: agents.into_iter().map(Into::into).collect(),
            giganto: giganto.map(Into::into),
            creation_time: Utc::now(),
        };
        let id = map.put(value)?;
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.node_map();

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let (key, _invalid_agents) = map.remove(i)?;

            let name = match String::from_utf8(key) {
                Ok(key) => key,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
            };
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
        let store = crate::graphql::get_store(ctx).await?;
        let mut map = store.node_map();
        let new = super::input::create_draft_update(&old, new)?;
        let old = old.try_into()?;
        map.update(i, &old, &new)?;
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
    let store = crate::graphql::get_store(ctx).await?;
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
        let res = schema.execute(r"{nodeList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 0}}");

        // insert node
        let res = schema
            .execute(
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
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // check node count after insert
        let res = schema.execute(r"{nodeList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

        // check inserted node
        let res = schema
            .execute(
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
                    giganto {
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
                    "giganto": null
                }
            })
        );

        // update node
        let res = schema
            .execute(
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
                            giganto: null,
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
                            giganto: null,
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node count after update
        let res = schema.execute(r"{nodeList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

        // check updated node
        let res = schema
            .execute(
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
                }
            })
        );

        // try reverting node, but it should succeed even though the node is an initial draft
        let res = schema
            .execute(
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
                        giganto: null,
                    },
                    new: {
                        nameDraft: "admin node",
                        profileDraft: null,
                        agents: null,
                        giganto: null,
                    }
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // remove node
        let res = schema
            .execute(
                r#"mutation {
                    removeNodes(ids: ["0"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNodes: ["admin node"]}"#);

        // check node count after remove
        let res = schema.execute(r"{nodeList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 0}}");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn update_node_name() {
        let schema = TestSchema::new().await;

        // check empty
        let res = schema.execute(r"{nodeList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 0}}");

        // insert node
        let res = schema
            .execute(
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
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // check node count after insert
        let res = schema.execute(r"{nodeList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

        // check inserted node
        let res = schema
            .execute(
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
                    giganto {
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
                    "giganto": null
                }
            })
        );

        // update node (update name, update profile_draft to null)
        let res = schema
            .execute(
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
                            giganto: null,
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
                            giganto: null,
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node count after update
        let res = schema.execute(r"{nodeList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 1}}");

        // check updated node
        let res = schema
            .execute(
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
}
