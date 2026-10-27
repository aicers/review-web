//! Whether a sampling policy's series reach its Data Store (RFC 0006 §9,
//! G1).
//!
//! The Data Store reports a time-series source as served whether or not a
//! series exists, so only the Central Manager can tell that a policy's
//! series are not being produced: it knows whether the policy is assigned,
//! whether its generator is given it, and whether the generator is online.

use std::collections::{HashMap, HashSet, hash_map::Entry};

use async_graphql::{Context, Enum, Result, SimpleObject};
use review_database::{SamplingPolicy, Store};

use super::{policy_id, withholding_reason};
use crate::graphql::{
    SharedAgentManager, customer_access::customer_sensor_names, gen_agent_lookup_key, get_store,
};

/// Whether the series of a sampling policy are being produced, as far as the
/// Central Manager can tell.
///
/// An assigned policy whose generator is online has no window yet for up to
/// one period and the generator's grace after it is assigned, which is
/// normal and not told apart here.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(in crate::graphql) enum SamplingPolicyDelivery {
    /// The policy has no assignee.
    Unassigned,
    /// The policy is assigned, but its generator is not given it: the
    /// generator's node is not of the policy's customer, or the policy's
    /// `node` is not a sensor name of that customer.
    Withheld,
    /// The policy's generator is not connected.
    AssigneeOffline,
    /// The policy's generator is connected.
    AssigneeOnline,
}

/// The delivery of one source of a training definition or a detector.
#[derive(Clone, Debug, Eq, PartialEq, SimpleObject)]
pub(in crate::graphql) struct SourceDelivery {
    /// The source, as the definition or the detector names it.
    source: String,
    /// The delivery of the sampling policy the source names, or null for a
    /// source that is not a sampling policy.
    delivery: Option<SamplingPolicyDelivery>,
}

/// What the store tells of a policy's delivery.
enum Stored {
    /// The delivery, decided without asking the agent manager.
    Decided(SamplingPolicyDelivery),
    /// The policy is given to its generator, which is online if the hostname
    /// of its node lists its agent lookup key.
    Given {
        hostname: String,
        agent_lookup_key: String,
    },
}

/// Returns the delivery of `policy`.
///
/// # Errors
///
/// Returns an error if the store cannot be read or the agent manager cannot
/// tell which agents are online.
pub(in crate::graphql) async fn policy_delivery(
    ctx: &Context<'_>,
    policy: &SamplingPolicy,
) -> Result<SamplingPolicyDelivery> {
    let stored = {
        let store = get_store(ctx)?;
        stored_delivery(&store, policy, &mut HashMap::new())?
    };
    let mut resolved = resolve(ctx, vec![Some(stored)]).await?;
    Ok(resolved
        .pop()
        .flatten()
        .expect("one delivery is resolved for each stored one"))
}

/// Returns the delivery of each of `sources`, in order, read for the
/// customer `customer_id`.
///
/// A source is a sampling policy only if `timeseries`, the method of the
/// definition or the model of the detector naming it is timeseries, and it
/// is the decimal ID of a policy of the customer; any other source has no
/// delivery.
///
/// # Errors
///
/// Returns an error if the store cannot be read or the agent manager cannot
/// tell which agents are online.
pub(in crate::graphql) async fn source_deliveries(
    ctx: &Context<'_>,
    customer_id: u32,
    sources: &[String],
    timeseries: bool,
) -> Result<Vec<SourceDelivery>> {
    let stored = if timeseries {
        let store = get_store(ctx)?;
        let map = store.sampling_policy_map();
        let mut sensors = HashMap::new();
        let mut stored = Vec::with_capacity(sources.len());
        for source in sources {
            let policy = match policy_id(source) {
                Some(id) => map
                    .get_by_id(id)?
                    .filter(|policy| policy.customer_id == Some(customer_id)),
                None => None,
            };
            stored.push(match policy {
                Some(policy) => Some(stored_delivery(&store, &policy, &mut sensors)?),
                None => None,
            });
        }
        stored
    } else {
        sources.iter().map(|_| None).collect()
    };
    let deliveries = resolve(ctx, stored).await?;
    Ok(sources
        .iter()
        .zip(deliveries)
        .map(|(source, delivery)| SourceDelivery {
            source: source.clone(),
            delivery,
        })
        .collect())
}

/// Reads what the store tells of the delivery of `policy`.
///
/// `sensors` caches the sensor names of each customer read so far.
fn stored_delivery(
    store: &Store,
    policy: &SamplingPolicy,
    sensors: &mut HashMap<u32, HashSet<String>>,
) -> Result<Stored> {
    let Some(assignee) = policy.assignee.as_ref() else {
        return Ok(Stored::Decided(SamplingPolicyDelivery::Unassigned));
    };
    let profile = store
        .node_map()
        .get_by_id(assignee.node_id)?
        .and_then(|(node, _, _)| node.profile);
    let customer_id = profile.as_ref().map(|profile| profile.customer_id);
    let none = HashSet::new();
    let customer_sensors = match customer_id {
        Some(customer_id) => match sensors.entry(customer_id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(customer_sensor_names(store, customer_id)?),
        },
        None => &none,
    };
    if withholding_reason(policy, customer_id, customer_sensors).is_some() {
        return Ok(Stored::Decided(SamplingPolicyDelivery::Withheld));
    }
    let hostname = profile.map(|profile| profile.hostname).unwrap_or_default();
    let agent_lookup_key = gen_agent_lookup_key(&assignee.agent_key, &hostname);
    Ok(Stored::Given {
        hostname,
        agent_lookup_key,
    })
}

/// Resolves each of `stored`, asking the agent manager which agents are
/// online only if one of them needs it. Call it with no store guard held.
async fn resolve(
    ctx: &Context<'_>,
    stored: Vec<Option<Stored>>,
) -> Result<Vec<Option<SamplingPolicyDelivery>>> {
    let online = if stored
        .iter()
        .any(|stored| matches!(stored, Some(Stored::Given { .. })))
    {
        ctx.data::<SharedAgentManager>()?
            .online_apps_by_host_id()
            .await
            .map_err(|e| format!("cannot tell which agents are online: {e:#}"))?
    } else {
        HashMap::new()
    };
    Ok(stored
        .into_iter()
        .map(|stored| {
            stored.map(|stored| match stored {
                Stored::Decided(delivery) => delivery,
                Stored::Given {
                    hostname,
                    agent_lookup_key,
                } => {
                    let is_online = online
                        .get(&hostname)
                        .is_some_and(|apps| apps.iter().any(|(key, _)| *key == agent_lookup_key));
                    if is_online {
                        SamplingPolicyDelivery::AssigneeOnline
                    } else {
                        SamplingPolicyDelivery::AssigneeOffline
                    }
                }
            })
        })
        .collect())
}
