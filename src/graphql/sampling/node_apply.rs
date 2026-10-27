//! What an apply of a node does to the sampling policies of its Time Series
//! Generators and sensors.

use std::collections::HashSet;

use async_graphql::Result;
use review_database::{AgentKind, Iterable, ModelInstance, Store, event::Direction};
use tracing::error;

use super::list_uses;
use crate::graphql::customer_access::event_sensor_names;

/// The key of the Data Store name in a Time Series Generator's configuration.
const GIGANTO_NAME: &str = "giganto_name";

/// Returns the `giganto_name` of a Time Series Generator's configuration;
/// `None` if it has none or an empty one, as review-database records a
/// policy's Data Store.
fn data_store(agent: &review_database::Agent) -> Option<String> {
    let config = agent.config.as_ref()?;
    let table = config.as_ref().parse::<toml::Table>().ok()?;
    table
        .get(GIGANTO_NAME)?
        .as_str()
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

/// Returns the Time Series Generator agents of node `node_id` whose applied
/// Data Store an update from `stored` to `new` changes, refusing the update
/// while a policy assigned to one of them is in use, or could not be
/// assigned to it again once the update is stored.
///
/// A policy's series are kept in its Data Store, so a policy in use cannot
/// move to another one. An unused policy moves by being assigned to its
/// generator again after the update, which
/// [`refresh_data_stores`] does; that assignment checks the policy against
/// the node as updated, so an update that also moves the node to another
/// customer, or drops the sensor name the policy reads, is refused here
/// rather than leaving the policy's Data Store behind. The caller holds the
/// engine configuration lock from before this check until
/// [`refresh_data_stores`] returns, as every writer that checks uses does.
pub(in crate::graphql) fn check_data_store_changes(
    store: &Store,
    node_id: u32,
    stored: &review_database::Node,
    new: &review_database::NodeUpdate,
) -> Result<Vec<ModelInstance>> {
    let mut changed = Vec::new();
    let mut in_use = Vec::new();
    let mut unused = Vec::new();
    for agent in new
        .agents
        .iter()
        .filter(|agent| agent.kind == AgentKind::TimeSeriesGenerator)
    {
        let Some(applied) = stored
            .agents
            .iter()
            .find(|applied| applied.key == agent.key && applied.kind == agent.kind)
        else {
            continue;
        };
        if data_store(applied) == data_store(agent) {
            continue;
        }
        let instance = ModelInstance {
            node_id,
            agent_key: agent.key.clone(),
        };
        for policy in store.sampling_policies_assigned_to(&instance)? {
            let uses = store.sampling_policy_uses(policy.id)?;
            if uses.is_empty() {
                unused.push((&agent.key, policy));
            } else {
                in_use.push(format!(
                    "sampling policy {:?} of agent {:?} is in use by {}",
                    policy.name,
                    agent.key,
                    list_uses(&uses)
                ));
            }
        }
        changed.push(instance);
    }
    if !in_use.is_empty() {
        return Err(format!(
            "the Data Store of a Time Series Generator cannot change while a sampling policy \
             assigned to it is in use: {}",
            in_use.join("; ")
        )
        .into());
    }
    if unused.is_empty() {
        return Ok(changed);
    }

    let customer_id = new.profile.as_ref().map(|profile| profile.customer_id);
    let sensors = match customer_id {
        Some(customer_id) => sensor_names_after(store, stored, new, customer_id)?,
        None => HashSet::new(),
    };
    let unassignable: Vec<_> = unused
        .iter()
        .filter_map(|(agent_key, policy)| {
            let reason = match (policy.customer_id, customer_id) {
                (None, _) => "has no customer".to_string(),
                (Some(policy_customer), None) => format!(
                    "belongs to customer {policy_customer}, and the node has no customer after \
                     this change"
                ),
                (Some(policy_customer), Some(node_customer))
                    if policy_customer != node_customer =>
                {
                    format!(
                        "belongs to customer {policy_customer}, and the node's customer becomes \
                         {node_customer}"
                    )
                }
                (Some(policy_customer), Some(_)) => match &policy.node {
                    Some(node) if sensors.contains(node) => return None,
                    Some(node) => format!(
                        "reads {node:?}, which is not a sensor name of customer \
                         {policy_customer} after this change"
                    ),
                    None => "reads no sensor".to_string(),
                },
            };
            Some(format!(
                "sampling policy {:?} of agent {agent_key:?} {reason}",
                policy.name
            ))
        })
        .collect();
    if unassignable.is_empty() {
        Ok(changed)
    } else {
        Err(format!(
            "the Data Store of a Time Series Generator cannot change while a sampling policy \
             assigned to it could not be assigned to it again to record the new Data Store: \
             {}; unassign the policy first, or change the Data Store in an apply that leaves \
             the profile as it is",
            unassignable.join("; ")
        )
        .into())
    }
}

/// Returns the [`event_sensor_names`] of every node whose applied profile
/// belongs to `customer_id` once node `stored` is updated to `new`.
fn sensor_names_after(
    store: &Store,
    stored: &review_database::Node,
    new: &review_database::NodeUpdate,
    customer_id: u32,
) -> Result<HashSet<String>> {
    let mut names = HashSet::new();
    for entry in store.node_map().iter(Direction::Forward, None) {
        let node = entry?;
        if node.id != stored.id
            && node
                .profile
                .as_ref()
                .is_some_and(|profile| profile.customer_id == customer_id)
        {
            names.extend(event_sensor_names(&node));
        }
    }
    if new
        .profile
        .as_ref()
        .is_some_and(|profile| profile.customer_id == customer_id)
    {
        let mut updated = stored.clone();
        updated.profile.clone_from(&new.profile);
        updated.agents.clone_from(&new.agents);
        names.extend(event_sensor_names(&updated));
    }
    Ok(names)
}

/// Assigns each policy of each generator in `generators` to it again, which
/// records the generator's new Data Store as the policy's.
///
/// It runs after the node update that changed the Data Stores is stored, so
/// a failure is logged rather than returned. [`check_data_store_changes`]
/// has already refused every update an assignment here would refuse, so
/// only a storage failure is left; assigning the policy to the same agent
/// with `assignSamplingPolicy` records the Data Store then.
pub(in crate::graphql) fn refresh_data_stores(store: &Store, generators: &[ModelInstance]) {
    let map = store.sampling_policy_map();
    for generator in generators {
        let policies = match store.sampling_policies_assigned_to(generator) {
            Ok(policies) => policies,
            Err(e) => {
                error!(
                    "cannot read the sampling policies of agent {:?} of node {} to record its \
                     new Data Store; assign each policy to the agent again to record it: {e:#}",
                    generator.agent_key, generator.node_id
                );
                continue;
            }
        };
        for policy in policies {
            if let Err(e) = map.assign(policy.id, Some(generator), false) {
                error!(
                    "cannot record the new Data Store of agent {:?} of node {} for sampling \
                     policy {:?}; assign the policy to the agent again to record it: {e:#}",
                    generator.agent_key, generator.node_id, policy.name
                );
            }
        }
    }
}

/// Returns the generators that hold a policy whose `node` is one of
/// `sensor_names` or that is assigned to an agent of node `node_id`.
///
/// # Errors
///
/// Returns an error if the sampling policy database could not be read.
pub(in crate::graphql) fn generators_of_node(
    store: &Store,
    node_id: u32,
    sensor_names: &[String],
) -> Result<Vec<ModelInstance>> {
    let mut generators = Vec::new();
    for entry in store.sampling_policy_map().iter(Direction::Forward, None) {
        let policy = entry?;
        let Some(assignee) = policy.assignee else {
            continue;
        };
        let reads_node = policy
            .node
            .as_ref()
            .is_some_and(|node| sensor_names.contains(node));
        if (reads_node || assignee.node_id == node_id) && !generators.contains(&assignee) {
            generators.push(assignee);
        }
    }
    Ok(generators)
}
