#![allow(clippy::fn_params_excessive_bools)]

use async_graphql::{
    connection::{Connection, EmptyFields},
    types::ID,
    Context, Object, Result,
};
use chrono::Utc;
use review_database::{Direction, Store};
use tracing::error;

use super::{
    super::{Role, RoleGuard},
    input::{AgentInput, GigantoInput, NodeDraftInput},
    Node, NodeInput, NodeMutation, NodeQuery, NodeTotalCount,
};
use crate::graphql::{customer::broadcast_customer_networks, get_customer_networks, query};

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
    ) -> Result<Connection<String, Node, NodeTotalCount, EmptyFields>> {
        query(
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
        agents: Vec<AgentInput>,
        giganto: Option<GigantoInput>,
    ) -> Result<ID> {
        let (id, customer_id) = {
            let store = crate::graphql::get_store(ctx).await?;
            let map = store.node_map();
            let customer_id = customer_id
                .as_str()
                .parse::<u32>()
                .map_err(|_| "invalid customer ID")?;

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
            (id, customer_id)
        };
        if super::matches_manager_hostname(&hostname) {
            let store = crate::graphql::get_store(ctx).await?;

            if let Ok(networks) = get_customer_networks(&store, customer_id) {
                if let Err(e) = broadcast_customer_networks(ctx, &networks).await {
                    error!("failed to broadcast internal networks. {e:?}");
                }
            }
        }
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
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Node, NodeTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.node_map();
    super::super::load_edges(&map, after, before, first, last, NodeTotalCount)
}

/// Returns the customer id of review node.
///
/// # Errors
///
/// Returns an error if the node profile could not be retrieved.
#[allow(clippy::module_name_repetitions)]
pub fn get_customer_id_of_node(db: &Store) -> Result<Option<u32>> {
    let map = db.node_map();
    for entry in map.iter(Direction::Forward, None) {
        let node = entry.map_err(|_| "invalid value in database")?;

        if let Some(node_profile) = &node.profile {
            if super::matches_manager_hostname(&node_profile.hostname) {
                return Ok(Some(node_profile.customer_id));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use crate::graphql::TestSchema;

    // test scenario : insert node -> update node with different name -> remove node
    #[tokio::test]
    async fn node_crud() {
        let schema = TestSchema::new().await;

        // check empty
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);

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
                            key: "reconverge"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "piglet"
                            kind: PIGLET
                            status: ENABLED
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // check node count after insert
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 1}}"#);

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
                        "key": "reconverge",
                        "kind": "RECONVERGE",
                        "status": "ENABLED",
                    },
                    {
                        "key": "piglet",
                        "kind": "PIGLET",
                        "status": "ENABLED",
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
                                    key: "reconverge",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: null,
                                    draft: null
                                },
                                {
                                    key: "piglet",
                                    kind: "PIGLET",
                                    status: "ENABLED",
                                    config: null,
                                    draft: null
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
                                    key: "reconverge",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: null,
                                    draft: null
                                },
                                {
                                    key: "piglet",
                                    kind: "PIGLET",
                                    status: "ENABLED",
                                    config: null,
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
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 1}}"#);

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
                    "profileDraft": {
                        "customerId": "0",
                        "description": "This is the admin node running review.",
                        "hostname": "admin.aice-security.com",
                    },
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
                                key: "reconverge",
                                kind: "RECONVERGE",
                                status: "ENABLED",
                                config: null,
                                draft: null
                            },
                            {
                                key: "piglet",
                                kind: "PIGLET",
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
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);
    }

    #[tokio::test]
    async fn update_node_name() {
        let schema = TestSchema::new().await;

        // check empty
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);

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
                            key: "reconverge"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "piglet"
                            kind: PIGLET
                            status: ENABLED
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // check node count after insert
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 1}}"#);

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
                        "key": "reconverge",
                        "kind": "RECONVERGE",
                        "status": "ENABLED",
                    },
                    {
                        "key": "piglet",
                        "kind": "PIGLET",
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
                                    key: "reconverge",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: null,
                                    draft: null
                                },
                                {
                                    key: "piglet",
                                    kind: "PIGLET",
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
                                    key: "reconverge",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: null,
                                    draft: null
                                },
                                {
                                    key: "piglet",
                                    kind: "PIGLET",
                                    status: "ENABLED",
                                    config: null,
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
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 1}}"#);

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
