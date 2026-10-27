//! Tests of what `applyNode` and `applyNodeDraft` do to the sampling policies
//! of the node's Time Series Generators and sensors.

use review_database::{ModelInstance, NodeProfile};

use super::test_support::{node_draft_input, node_input, stored_node};
use crate::graphql::{
    TestSchema,
    model_test_support::insert_engine_node,
    sampling_test_support::{
        Deliveries, DeliveryRecorder, NO_DELIVERIES, data_store_name, generator_config,
        insert_generator_node, insert_policy, sensor_name, use_policy,
    },
};

const MUTATIONS: [&str; 2] = ["applyNode", "applyNodeDraft"];

async fn recording_schema() -> (TestSchema, Deliveries) {
    let (agent_manager, deliveries) = DeliveryRecorder::boxed();
    let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;
    (schema, deliveries)
}

/// Edits the stored node's drafts through `updateNodeDraft`, as the node
/// dialog does before an apply, and returns the node it stored.
async fn stage(
    schema: &TestSchema,
    id: u32,
    edit: impl FnOnce(&mut review_database::Node),
) -> review_database::Node {
    let stored = stored_node(&schema.store(), id);
    let mut draft = stored.clone();
    edit(&mut draft);
    let res = schema
        .execute_as_system_admin(&format!(
            "mutation {{ updateNodeDraft(id: \"{id}\", old: {}, new: {}) }}",
            node_input(&stored),
            node_draft_input(&draft, true, true)
        ))
        .await;
    assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
    stored_node(&schema.store(), id)
}

async fn apply(
    schema: &TestSchema,
    mutation: &str,
    id: u32,
    node: &review_database::Node,
) -> async_graphql::Response {
    let selection = if mutation == "applyNodeDraft" {
        " { id }"
    } else {
        ""
    };
    schema
        .execute_as_system_admin(&format!(
            "mutation {{ {mutation}(id: \"{id}\", node: {}){selection} }}",
            node_input(node)
        ))
        .await
}

fn profile(customer_id: u32, hostname: &str) -> NodeProfile {
    NodeProfile {
        customer_id,
        description: String::new(),
        hostname: hostname.to_string(),
    }
}

/// Stores a fixed policy `name` of `customer_id` reading the sensor of
/// `sensor_host`, assigned to `generator`, and returns its ID.
fn assigned_policy(
    schema: &TestSchema,
    name: &str,
    customer_id: u32,
    sensor_host: &str,
    generator: &ModelInstance,
) -> u32 {
    let store = schema.store();
    let id = insert_policy(&store, name, customer_id, &sensor_name(sensor_host));
    store
        .sampling_policy_map()
        .assign(id, Some(generator), true)
        .expect("assign policy");
    id
}

fn data_store_of(schema: &TestSchema, id: u32) -> Option<String> {
    schema
        .store()
        .sampling_policy_map()
        .get_by_id(id)
        .expect("read policy")
        .expect("policy exists")
        .data_store
}

#[tokio::test]
async fn a_customer_or_hostname_change_tells_the_generators_involved() {
    for mutation in MUTATIONS {
        let (schema, deliveries) = recording_schema().await;
        // `generator` is on node G and reads the sensor of node S; `other`
        // reads only its own node's sensor.
        let generator = insert_generator_node(&schema.store(), "g.example.com", 1);
        let sensor = insert_generator_node(&schema.store(), "s.example.com", 1);
        let other = insert_generator_node(&schema.store(), "o.example.com", 1);
        assigned_policy(&schema, "on s", 1, "s.example.com", &generator);
        assigned_policy(&schema, "on o", 1, "o.example.com", &other);

        // A change that keeps the customer and hostname tells no generator.
        let node = stage(&schema, sensor.node_id, |node| {
            node.name_draft = Some("renamed".to_string());
        })
        .await;
        let res = apply(&schema, mutation, sensor.node_id, &node).await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        assert_eq!(deliveries.calls(), NO_DELIVERIES, "{mutation}");

        // The sensor's node changes hostname: the generator reading it is
        // told, but not the node's own generator, which holds nothing.
        let node = stage(&schema, sensor.node_id, |node| {
            node.profile_draft = Some(profile(1, "s2.example.com"));
        })
        .await;
        let res = apply(&schema, mutation, sensor.node_id, &node).await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        assert_eq!(deliveries.calls(), [vec![generator.clone()]], "{mutation}");

        // The generator's node changes customer.
        let node = stage(&schema, generator.node_id, |node| {
            node.profile_draft = Some(profile(2, "g.example.com"));
        })
        .await;
        let res = apply(&schema, mutation, generator.node_id, &node).await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        assert_eq!(
            deliveries.calls(),
            [vec![generator.clone()], vec![generator.clone()]],
            "{mutation}"
        );
    }
}

/// Changes the Data Store the generator of the node `generator` is on is
/// configured with to `giganto_name`, through `mutation`.
async fn change_data_store(
    schema: &TestSchema,
    mutation: &str,
    generator: &ModelInstance,
    giganto_name: &str,
) -> async_graphql::Response {
    change_data_store_and_profile(schema, mutation, generator, giganto_name, None).await
}

/// Changes the Data Store the generator of the node `generator` is on is
/// configured with to `giganto_name`, and the node's profile to `profile`
/// unless it is `None`, in one apply through `mutation`.
async fn change_data_store_and_profile(
    schema: &TestSchema,
    mutation: &str,
    generator: &ModelInstance,
    giganto_name: &str,
    profile: Option<NodeProfile>,
) -> async_graphql::Response {
    let node = stage(schema, generator.node_id, |node| {
        if profile.is_some() {
            node.profile_draft = profile;
        }
        let agent = node
            .agents
            .iter_mut()
            .find(|agent| agent.key == generator.agent_key)
            .expect("the generator is on the node");
        agent.draft = Some(
            generator_config(giganto_name)
                .try_into()
                .expect("a valid configuration"),
        );
    })
    .await;
    apply(schema, mutation, generator.node_id, &node).await
}

#[tokio::test]
async fn a_generator_holding_a_used_policy_keeps_its_data_store() {
    for mutation in MUTATIONS {
        let (schema, deliveries) = recording_schema().await;
        let generator = insert_generator_node(&schema.store(), "g.example.com", 1);
        let used = assigned_policy(&schema, "used", 1, "g.example.com", &generator);
        assigned_policy(&schema, "unused", 1, "g.example.com", &generator);
        let engine = insert_engine_node(&schema.store(), 1);
        use_policy(&schema.store(), "series", 1, &engine, used);
        let before = stored_node(&schema.store(), generator.node_id);

        let res = change_data_store(&schema, mutation, &generator, "002.giganto.x").await;
        assert_eq!(
            res.errors.first().expect("a refusal").message,
            "the Data Store of a Time Series Generator cannot change while a sampling policy \
             assigned to it is in use: sampling policy \"used\" of agent \"crusher@test\" is in \
             use by training definition \"series\"",
            "{mutation}"
        );
        let configs = |node: &review_database::Node| {
            node.agents
                .iter()
                .map(|agent| agent.config.clone())
                .collect::<Vec<_>>()
        };
        let after = stored_node(&schema.store(), generator.node_id);
        assert_eq!(configs(&after), configs(&before), "{mutation}");
        assert_eq!(
            data_store_of(&schema, used),
            Some(data_store_name("g.example.com"))
        );
        assert_eq!(deliveries.calls(), NO_DELIVERIES, "{mutation}");
    }
}

#[tokio::test]
async fn a_generator_holding_unused_policies_moves_them_to_its_new_data_store() {
    for mutation in MUTATIONS {
        let (schema, _) = recording_schema().await;
        let generator = insert_generator_node(&schema.store(), "g.example.com", 1);
        let policies = [
            assigned_policy(&schema, "first", 1, "g.example.com", &generator),
            assigned_policy(&schema, "second", 1, "g.example.com", &generator),
        ];
        // A policy of another generator stays where it is.
        let other = insert_generator_node(&schema.store(), "o.example.com", 1);
        let elsewhere = assigned_policy(&schema, "elsewhere", 1, "o.example.com", &other);

        let res = change_data_store(&schema, mutation, &generator, "002.giganto.x").await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        for id in policies {
            assert_eq!(
                data_store_of(&schema, id),
                Some("002.giganto.x".to_string()),
                "{mutation}"
            );
        }
        assert_eq!(
            data_store_of(&schema, elsewhere),
            Some(data_store_name("o.example.com"))
        );
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_data_store_change_its_policies_could_not_follow_is_refused() {
    for mutation in MUTATIONS {
        let (schema, deliveries) = recording_schema().await;
        let generator = insert_generator_node(&schema.store(), "g.example.com", 1);
        let own = assigned_policy(&schema, "own", 1, "g.example.com", &generator);
        // A policy reading another node's sensor follows a hostname change.
        insert_generator_node(&schema.store(), "s.example.com", 1);
        let elsewhere = assigned_policy(&schema, "elsewhere", 1, "s.example.com", &generator);
        let before = stored_node(&schema.store(), generator.node_id);

        // The new hostname drops the sensor name `own` reads.
        let res = change_data_store_and_profile(
            &schema,
            mutation,
            &generator,
            "002.giganto.x",
            Some(profile(1, "g2.example.com")),
        )
        .await;
        assert_eq!(
            res.errors.first().expect("a refusal").message,
            "the Data Store of a Time Series Generator cannot change while a sampling policy \
             assigned to it could not be assigned to it again to record the new Data Store: \
             sampling policy \"own\" of agent \"crusher@test\" reads \
             \"piglet.g.example.com\", which is not a sensor name of customer 1 after this \
             change; unassign the policy first, or change the Data Store in an apply that leaves \
             the profile as it is",
            "{mutation}"
        );

        // The new customer is not the policies' customer.
        let res = change_data_store_and_profile(
            &schema,
            mutation,
            &generator,
            "002.giganto.x",
            Some(profile(2, "g.example.com")),
        )
        .await;
        assert_eq!(
            res.errors.first().expect("a refusal").message,
            "the Data Store of a Time Series Generator cannot change while a sampling policy \
             assigned to it could not be assigned to it again to record the new Data Store: \
             sampling policy \"elsewhere\" of agent \"crusher@test\" belongs to customer 1, \
             and the node's customer becomes 2; sampling policy \"own\" of agent \
             \"crusher@test\" belongs to customer 1, and the node's customer becomes 2; \
             unassign the policy first, or change the Data Store in an apply that leaves the \
             profile as it is",
            "{mutation}"
        );
        let after = stored_node(&schema.store(), generator.node_id);
        assert_eq!(after.profile, before.profile, "{mutation}");
        assert_eq!(
            after.agents.iter().map(|a| &a.config).collect::<Vec<_>>(),
            before.agents.iter().map(|a| &a.config).collect::<Vec<_>>(),
            "{mutation}"
        );
        for id in [own, elsewhere] {
            assert_eq!(
                data_store_of(&schema, id),
                Some(data_store_name("g.example.com")),
                "{mutation}"
            );
        }
        assert_eq!(deliveries.calls(), NO_DELIVERIES, "{mutation}");

        // The Data Store first, then the hostname, as the refusal suggests.
        // The refused drafts are still staged, so the profile draft goes
        // back to the applied profile.
        let res = change_data_store_and_profile(
            &schema,
            mutation,
            &generator,
            "002.giganto.x",
            before.profile.clone(),
        )
        .await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        let node = stage(&schema, generator.node_id, |node| {
            node.profile_draft = Some(profile(1, "g2.example.com"));
        })
        .await;
        let res = apply(&schema, mutation, generator.node_id, &node).await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        for id in [own, elsewhere] {
            assert_eq!(
                data_store_of(&schema, id),
                Some("002.giganto.x".to_string()),
                "{mutation}"
            );
        }
        assert_eq!(deliveries.calls(), [vec![generator.clone()]], "{mutation}");

        // A hostname change that keeps every policy's sensor moves the Data
        // Store with it.
        let node = stage(&schema, generator.node_id, |node| {
            node.profile_draft = Some(profile(1, "g.example.com"));
        })
        .await;
        let res = apply(&schema, mutation, generator.node_id, &node).await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        let res = change_data_store_and_profile(
            &schema,
            mutation,
            &generator,
            "003.giganto.x",
            Some(profile(1, "g.example.com")),
        )
        .await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        for id in [own, elsewhere] {
            assert_eq!(
                data_store_of(&schema, id),
                Some("003.giganto.x".to_string()),
                "{mutation}"
            );
        }
    }
}
