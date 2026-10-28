//! Tests of the node writes refused while a customer's data deletion is
//! unfinished.
//!
//! The nodes have no numbered row, so the installed-instance guard, which
//! refuses a hostname change or a removal of a node holding one, never
//! answers first.

use review_database::NodeProfile;

use super::test_support::{insert_active_node, node_draft_input, node_input, stored_node};
use crate::graphql::{
    TestSchema,
    customer_deletion_guard::test_support::{
        assert_locked, assert_not_locked, put_completed_job, put_running_job, put_stopped_job,
    },
};

const HOST_A: &str = "a.example.com";
const HOST_B: &str = "b.example.com";
/// A host name customer 1's deletion saved after removing its node.
const SAVED: &str = "gone.example.com";

fn profile(customer_id: u32, hostname: &str) -> NodeProfile {
    NodeProfile {
        customer_id,
        description: String::new(),
        hostname: hostname.to_string(),
    }
}

/// Stores the drafts `edit` makes to node `id` through `updateNodeDraft`, and
/// returns the node it stored.
async fn stage(
    schema: &TestSchema,
    id: u32,
    edit: impl FnOnce(&mut review_database::Node),
) -> review_database::Node {
    let response = update_draft(schema, id, edit).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    stored_node(&schema.store(), id)
}

async fn update_draft(
    schema: &TestSchema,
    id: u32,
    edit: impl FnOnce(&mut review_database::Node),
) -> async_graphql::Response {
    let stored = stored_node(&schema.store(), id);
    let mut draft = stored.clone();
    edit(&mut draft);
    schema
        .execute_as_system_admin(&format!(
            "mutation {{ updateNodeDraft(id: \"{id}\", old: {}, new: {}) }}",
            node_input(&stored),
            node_draft_input(&draft, true, true)
        ))
        .await
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

async fn insert(schema: &TestSchema, customer_id: u32, hostname: &str) -> async_graphql::Response {
    schema
        .execute_as_system_admin(&format!(
            "mutation {{ insertNode(name: \"{hostname}\", customerId: \"{customer_id}\", \
             description: \"\", hostname: \"{hostname}\", agents: [], externalServices: []) }}"
        ))
        .await
}

async fn remove(schema: &TestSchema, id: u32) -> async_graphql::Response {
    schema
        .execute_as_system_admin(&format!("mutation {{ removeNodes(ids: [\"{id}\"]) }}"))
        .await
}

/// Returns the nodes of customers 1 and 2, each with its description edited
/// in its drafts so that an apply changes it.
async fn two_customers(schema: &TestSchema) -> (review_database::Node, review_database::Node) {
    let a = insert_active_node(&schema.store(), "a", 1, HOST_A);
    let b = insert_active_node(&schema.store(), "b", 2, HOST_B);
    let edit = |customer_id, hostname| {
        move |node: &mut review_database::Node| {
            let mut profile = profile(customer_id, hostname);
            profile.description = "edited".to_string();
            node.profile_draft = Some(profile);
        }
    };
    (
        stage(schema, a, edit(1, HOST_A)).await,
        stage(schema, b, edit(2, HOST_B)).await,
    )
}

#[tokio::test]
async fn a_running_deletion_refuses_the_customers_node_writes_only() {
    for mutation in ["applyNode", "applyNodeDraft"] {
        let schema = TestSchema::new().await;
        let (a, b) = two_customers(&schema).await;
        put_running_job(&schema.store(), 1, &[HOST_A]);

        assert_locked(&apply(&schema, mutation, a.id, &a).await);
        let response = apply(&schema, mutation, b.id, &b).await;
        assert!(
            response.errors.is_empty(),
            "{mutation}: {:?}",
            response.errors
        );
    }

    let schema = TestSchema::new().await;
    let (a, b) = two_customers(&schema).await;
    put_running_job(&schema.store(), 1, &[HOST_A]);
    assert_locked(
        &update_draft(&schema, a.id, |node| {
            node.name_draft = Some("renamed".to_string());
        })
        .await,
    );
    // A node of another customer cannot move to the customer either.
    assert_locked(
        &update_draft(&schema, b.id, |node| {
            node.profile_draft = Some(profile(1, HOST_B));
        })
        .await,
    );
    assert_locked(&insert(&schema, 1, "new.example.com").await);
    assert_locked(&remove(&schema, a.id).await);

    let response = insert(&schema, 2, "new.example.com").await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let response = remove(&schema, b.id).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
}

#[tokio::test]
async fn a_stopped_deletion_still_refuses_until_every_result_succeeds() {
    let schema = TestSchema::new().await;
    let a = insert_active_node(&schema.store(), "a", 1, HOST_A);
    let renamed = stage(&schema, a, |node| {
        node.profile_draft = Some(profile(1, "renamed.example.com"));
    })
    .await;
    put_stopped_job(&schema.store(), 1, &[HOST_A]);

    // A hostname change would free a saved name.
    assert_locked(&apply(&schema, "applyNode", a, &renamed).await);
    assert_locked(&remove(&schema, a).await);
    assert_locked(&insert(&schema, 1, "new.example.com").await);

    put_completed_job(&schema.store(), 1, &[HOST_A]);
    let response = apply(&schema, "applyNode", a, &renamed).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        stored_node(&schema.store(), a).profile,
        Some(profile(1, "renamed.example.com"))
    );
    let response = remove(&schema, a).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
}

#[tokio::test]
async fn a_node_moves_to_another_customer_before_any_job() {
    let schema = TestSchema::new().await;
    let a = insert_active_node(&schema.store(), "a", 1, HOST_A);
    let moved = stage(&schema, a, |node| {
        node.profile_draft = Some(profile(2, HOST_A));
    })
    .await;
    let response = apply(&schema, "applyNode", a, &moved).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        stored_node(&schema.store(), a).profile,
        Some(profile(2, HOST_A))
    );
}

#[tokio::test]
async fn a_saved_host_name_is_held_from_every_customer_while_the_job_is_stopped() {
    let schema = TestSchema::new().await;
    // Customer 1's nodes are gone, and its job stopped with their names saved.
    put_stopped_job(&schema.store(), 1, &[SAVED]);

    let response = insert(&schema, 2, SAVED).await;
    assert_locked(&response);
    // Neither the customer nor the job is named.
    assert_eq!(
        response.errors[0].message,
        "host name gone.example.com is held by a customer data deletion that has not \
         completed; choose another host name"
    );
    assert_not_locked(&insert(&schema, 2, "other.example.com").await);

    put_completed_job(&schema.store(), 1, &[SAVED]);
    let response = insert(&schema, 2, SAVED).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
}

#[tokio::test]
async fn a_saved_host_name_is_held_from_drafts_and_applies() {
    for mutation in ["applyNode", "applyNodeDraft"] {
        let schema = TestSchema::new().await;
        let b = insert_active_node(&schema.store(), "b", 2, HOST_B);
        let taking = stage(&schema, b, |node| {
            node.profile_draft = Some(profile(2, SAVED));
        })
        .await;
        put_stopped_job(&schema.store(), 1, &[SAVED]);

        assert_locked(
            &update_draft(&schema, b, |node| {
                node.name_draft = Some("renamed".to_string());
            })
            .await,
        );
        assert_locked(&apply(&schema, mutation, b, &taking).await);

        put_completed_job(&schema.store(), 1, &[SAVED]);
        let response = apply(&schema, mutation, b, &taking).await;
        assert!(
            response.errors.is_empty(),
            "{mutation}: {:?}",
            response.errors
        );
    }
}
