//! The configuration revisions of engine instances.

use async_graphql::{Context, ID, Object, Result, SimpleObject, StringNumber};
use review_database::ModelInstance;

use super::{Role, RoleGuard, customer_access, timestamp::Timestamp};

#[derive(Default)]
pub(super) struct ConfigRevisionQuery;

#[Object]
impl ConfigRevisionQuery {
    /// A configuration revision of the agent `agentKey` of node `nodeId`: the
    /// completed engine configuration document an apply stored, and when.
    ///
    /// Node access is checked as `node(id)` checks it, before any history is
    /// read: an unknown or removed node is refused with `no such node`, and a
    /// node outside the caller's customers with `Forbidden`. The scope is the
    /// node's current customer, so after a node moves to another customer,
    /// that customer's users read the revisions applied before the move.
    ///
    /// Returns null if the revision was never issued or its history was
    /// removed by a customer data deletion. Whether the agent still exists, or
    /// what kind it is now, is not checked.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn config_revision(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        agent_key: String,
        revision: StringNumber<u64>,
    ) -> Result<Option<ConfigRevision>> {
        let node = customer_access::load_accessible_node(ctx, &node_id)?;
        let instance = ModelInstance {
            node_id: node.id,
            agent_key,
        };
        let store = super::get_store(ctx)?;
        let Some(record) = store.config_revision_record(&instance, revision.0)? else {
            return Ok(None);
        };
        Ok(Some(ConfigRevision {
            node_id: ID(node.id.to_string()),
            agent_key: instance.agent_key,
            revision,
            applied_at: record.applied_at.into(),
            document: record.document,
        }))
    }
}

/// A configuration revision of an engine instance, as its history records
/// it.
#[derive(SimpleObject)]
pub(super) struct ConfigRevision {
    /// The ID of the node the instance runs on.
    node_id: ID,
    /// The key of the instance's agent.
    agent_key: String,
    /// The revision number.
    revision: StringNumber<u64>,
    /// When the apply that stored the revision was written.
    applied_at: Timestamp,
    /// The completed engine configuration document the revision stored.
    document: String,
}

#[cfg(test)]
mod tests {
    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
    use review_database::{
        Agent, AgentKind, AgentStatus, Lifecycle, Node, NodeProfile, NodeUpdate, Store,
        complete_engine_document,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::graphql::{Role, TestSchema};

    const KEY: &str = "001.hog";
    const FIRST: &str = "[detection_models.port_scan]\nenabled = false\n";
    const SECOND: &str = "[detection_models.port_scan]\nenabled = true\n";
    /// 2^53 + 1, the first integer a double cannot hold.
    const ABOVE_2_53: u64 = (1 << 53) + 1;

    fn agent(kind: AgentKind, config: Option<&str>) -> Agent {
        let config = config.map(|c| c.to_string().try_into().expect("valid TOML"));
        Agent {
            node_id: u32::MAX,
            key: KEY.to_string(),
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

    fn profile(customer_id: u32) -> NodeProfile {
        NodeProfile {
            customer_id,
            description: String::new(),
            hostname: "hog.example.com".to_string(),
        }
    }

    /// Stores a node of `customer_id` whose Semi-supervised Engine agent
    /// applied `FIRST`, recording revision 1, and returns its ID.
    fn put_node(store: &Store, customer_id: u32) -> u32 {
        store
            .node_map()
            .put(&Node {
                id: u32::MAX,
                name: "hog".to_string(),
                name_draft: Some("hog".to_string()),
                profile: Some(profile(customer_id)),
                profile_draft: Some(profile(customer_id)),
                agents: vec![agent(AgentKind::SemiSupervised, Some(FIRST))],
                external_services: vec![],
                creation_time: jiff::Timestamp::now(),
            })
            .expect("insert node")
    }

    /// Stores the node `id` as `edit` leaves it.
    fn update_node(store: &Store, id: u32, edit: impl FnOnce(&mut NodeUpdate)) {
        let mut map = store.node_map();
        let (node, _, _) = map.get_by_id(id).expect("read node").expect("node exists");
        let old = NodeUpdate::from(node.clone());
        let mut new = NodeUpdate::from(node);
        edit(&mut new);
        map.update(id, &old, &new).expect("update node");
    }

    fn query(node_id: u32, revision: &str) -> String {
        format!(
            "{{ configRevision(nodeId: \"{node_id}\", agentKey: \"{KEY}\", revision: \
             \"{revision}\") {{ nodeId agentKey revision appliedAt document }} }}"
        )
    }

    async fn read(
        schema: &TestSchema,
        node_id: u32,
        revision: &str,
        customers: Option<Vec<u32>>,
    ) -> async_graphql::Response {
        schema
            .execute_as_scoped_user(&query(node_id, revision), Role::SecurityMonitor, customers)
            .await
    }

    fn revision_of(res: async_graphql::Response) -> Value {
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        res.data.into_json().expect("JSON data")["configRevision"].clone()
    }

    fn refusal_of(res: &async_graphql::Response) -> String {
        assert_eq!(res.data, async_graphql::Value::Null, "{:?}", res.data);
        res.errors.first().expect("an error").message.clone()
    }

    fn completed(document: &str) -> String {
        complete_engine_document(
            AgentKind::SemiSupervised,
            document,
            &|_| None,
            &|_| None,
            review_database::CompletionMode::Apply,
        )
        .expect("completes")
    }

    /// Returns the `applied_at` of revision `revision` as GraphQL writes it.
    fn applied_at(schema: &TestSchema, id: u32, revision: u64) -> String {
        let instance = ModelInstance {
            node_id: id,
            agent_key: KEY.to_string(),
        };
        schema
            .store()
            .config_revision_record(&instance, revision)
            .expect("read history")
            .expect("revision exists")
            .applied_at
            .to_string()
    }

    #[tokio::test]
    async fn revisions_are_read_after_one_and_two_changing_applies() {
        let schema = TestSchema::new().await;
        let id = put_node(&schema.store(), 1);
        let first = json!({
            "nodeId": id.to_string(),
            "agentKey": KEY,
            "revision": "1",
            "appliedAt": applied_at(&schema, id, 1),
            "document": completed(FIRST),
        });
        assert_eq!(
            revision_of(read(&schema, id, "1", Some(vec![1])).await),
            first
        );
        assert_eq!(
            revision_of(read(&schema, id, "2", Some(vec![1])).await),
            Value::Null
        );

        update_node(&schema.store(), id, |node| {
            let config = Some(SECOND.to_string().try_into().expect("valid TOML"));
            node.agents.first_mut().expect("one agent").config = config;
        });
        assert_eq!(
            revision_of(read(&schema, id, "1", Some(vec![1])).await),
            first
        );
        assert_eq!(
            revision_of(read(&schema, id, "2", None).await),
            json!({
                "nodeId": id.to_string(),
                "agentKey": KEY,
                "revision": "2",
                "appliedAt": applied_at(&schema, id, 2),
                "document": completed(SECOND),
            })
        );
        assert_eq!(revision_of(read(&schema, id, "3", None).await), Value::Null);
        // A number above 2^53 is taken exactly, and was never issued.
        assert_eq!(
            revision_of(read(&schema, id, &ABOVE_2_53.to_string(), None).await),
            Value::Null
        );
        // A number that is not a u64 is refused as input.
        let res = read(&schema, id, "18446744073709551616", None).await;
        assert_eq!(res.data, async_graphql::Value::Null);
        assert_eq!(res.errors.len(), 1, "{:?}", res.errors);
    }

    struct RevisionQuery;

    #[Object]
    impl RevisionQuery {
        async fn revision(&self) -> ConfigRevision {
            ConfigRevision {
                node_id: ID("1".to_string()),
                agent_key: KEY.to_string(),
                revision: StringNumber(ABOVE_2_53),
                applied_at: jiff::Timestamp::UNIX_EPOCH.into(),
                document: String::new(),
            }
        }
    }

    #[tokio::test]
    async fn a_revision_above_2_53_is_written_exactly() {
        let schema = Schema::new(RevisionQuery, EmptyMutation, EmptySubscription);
        let res = schema.execute("{ revision { revision } }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().expect("JSON data"),
            json!({ "revision": { "revision": "9007199254740993" } })
        );
    }

    #[tokio::test]
    async fn the_guard_takes_the_node_roles() {
        let schema = TestSchema::new().await;
        let id = put_node(&schema.store(), 1);
        for role in [
            Role::SystemAdministrator,
            Role::SecurityAdministrator,
            Role::SecurityMonitor,
        ] {
            let res = schema
                .execute_as_scoped_user(&query(id, "1"), role, Some(vec![1]))
                .await;
            assert_eq!(revision_of(res)["revision"], "1", "{role:?}");
        }
        let res = schema
            .execute_as_scoped_user(&query(id, "1"), Role::SecurityManager, Some(vec![1]))
            .await;
        assert_eq!(refusal_of(&res), "Forbidden");
    }

    #[tokio::test]
    async fn an_unknown_or_removed_node_is_refused() {
        let schema = TestSchema::new().await;
        let id = put_node(&schema.store(), 1);
        assert_eq!(
            refusal_of(&read(&schema, id + 1, "1", None).await),
            "no such node"
        );
        schema.store().node_map().remove(id).expect("remove node");
        assert_eq!(
            refusal_of(&read(&schema, id, "1", None).await),
            "no such node"
        );
        assert_eq!(
            refusal_of(&read(&schema, id, "1", Some(vec![1])).await),
            "no such node"
        );
    }

    #[tokio::test]
    async fn the_scope_is_the_nodes_current_customer() {
        let schema = TestSchema::new().await;
        let id = put_node(&schema.store(), 1);
        assert_eq!(
            refusal_of(&read(&schema, id, "1", Some(vec![2])).await),
            "Forbidden"
        );

        // The node moves from customer 1 to 2; the revision stays recorded
        // under 1.
        update_node(&schema.store(), id, |node| {
            node.profile = Some(profile(2));
            node.profile_draft = Some(profile(2));
        });
        let revision = revision_of(read(&schema, id, "1", Some(vec![2])).await);
        assert_eq!(revision["document"], completed(FIRST));
        assert_eq!(
            refusal_of(&read(&schema, id, "1", Some(vec![1])).await),
            "Forbidden"
        );

        // Customer 1's data deletion removes the row; the node stays readable
        // to customer 2.
        schema
            .store()
            .remove_customer_config_history(1)
            .expect("remove history");
        assert_eq!(
            revision_of(read(&schema, id, "1", Some(vec![2])).await),
            Value::Null
        );
        let res = schema
            .execute_as_scoped_user(
                &format!("{{ node(id: \"{id}\") {{ id }} }}"),
                Role::SecurityMonitor,
                Some(vec![2]),
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
    }

    #[tokio::test]
    async fn a_revision_outlives_its_agent_and_its_kind() {
        let schema = TestSchema::new().await;
        let id = put_node(&schema.store(), 1);

        update_node(&schema.store(), id, |node| node.agents.clear());
        let revision = revision_of(read(&schema, id, "1", Some(vec![1])).await);
        assert_eq!(revision["document"], completed(FIRST));

        update_node(&schema.store(), id, |node| {
            node.agents = vec![agent(AgentKind::Sensor, Some("x = 1"))];
        });
        let revision = revision_of(read(&schema, id, "1", Some(vec![1])).await);
        assert_eq!(revision["document"], completed(FIRST));
    }
}
