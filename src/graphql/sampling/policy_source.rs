//! The source rule of the timeseries method (RFC 0006 §9, G1): a timeseries
//! training definition, and a detector of a timeseries model, read the
//! series of sampling policies, named by their decimal IDs.
//!
//! Every source must be an assigned policy of the customer, all sources must
//! have one shape, and they must all be kept in the one Data Store the
//! definition or the detector reads. The caller holds the engine
//! configuration lock, as every writer that checks a source does.

use review_database::{SamplingInterval, SamplingKind, SamplingPeriod, SamplingPolicy, Store};

use super::generator_data_store;
use crate::graphql::refusal::{RefusalCode, refusal};

/// What a policy's series look like: two policies of one shape give slot
/// vectors of the same length and meaning, on the same scale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::graphql) struct Shape {
    kind: SamplingKind,
    column: Option<u32>,
    interval: SamplingInterval,
    period: SamplingPeriod,
    offset: i32,
}

impl Shape {
    fn of(policy: &SamplingPolicy) -> Self {
        Self {
            kind: policy.kind,
            column: policy.column,
            interval: policy.interval,
            period: policy.period,
            offset: policy.offset,
        }
    }

    /// Returns the name of the first attribute in which `other` differs from
    /// this shape, or `None` if it does not.
    fn difference(&self, other: &Self) -> Option<&'static str> {
        if self.kind != other.kind {
            Some("kind")
        } else if self.column != other.column {
            Some("column")
        } else if self.interval != other.interval {
            Some("interval")
        } else if self.period != other.period {
            Some("period")
        } else if self.offset != other.offset {
            Some("offset")
        } else {
            None
        }
    }
}

/// The shape every source of a detector must have, and what it was taken
/// from, for the refusal's message.
#[derive(Clone, Debug)]
pub(in crate::graphql) struct ReferenceShape {
    shape: Shape,
    /// Describes the policies the shape is theirs, such as `the sampling
    /// policies model "m" was trained on`.
    origin: String,
}

/// A refusal of the source rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::graphql) struct SourceRefusal {
    /// `SOURCE_NOT_ALLOWED`, `SOURCES_INCOMPATIBLE` or
    /// `DATA_STORE_NOT_INSTALLED`.
    pub(in crate::graphql) code: RefusalCode,
    pub(in crate::graphql) message: String,
    /// The index of the offending source, or `None` when the refusal is of
    /// `data_store.server_name`.
    pub(in crate::graphql) source: Option<usize>,
    pub(in crate::graphql) value: String,
}

impl SourceRefusal {
    /// Returns the refusal as a GraphQL error whose `field` is `prefix`
    /// followed by the offending key, `sources[<j>]` or
    /// `data_store.server_name`.
    #[must_use]
    pub(in crate::graphql) fn into_error(self, prefix: &str) -> async_graphql::Error {
        let field = match self.source {
            Some(j) => format!("{prefix}sources[{j}]"),
            None => format!("{prefix}data_store.server_name"),
        };
        refusal(self.code, self.message, &field, self.value)
    }
}

/// Returns the shape of the policies the model `model` was trained on, its
/// `trained_sources`, as the shape of the first of them that is stored; `None`
/// if none is.
///
/// The policies a model's `trained_sources` names are in use while the model
/// exists, so none of them can be deleted, and a fixed policy's shape never
/// changes. A model with none stored is one trained before its sources were
/// recorded.
///
/// # Errors
///
/// Returns an error if the store cannot be read.
pub(in crate::graphql) fn trained_shape(
    store: &Store,
    model: &str,
    trained_sources: &[String],
) -> anyhow::Result<Option<ReferenceShape>> {
    let map = store.sampling_policy_map();
    for source in trained_sources {
        let Some(id) = policy_id(source) else {
            continue;
        };
        if let Some(policy) = map.get_by_id(id)? {
            return Ok(Some(ReferenceShape {
                shape: Shape::of(&policy),
                origin: format!("the sampling policies model {model:?} was trained on"),
            }));
        }
    }
    Ok(None)
}

/// Applies the source rule of the timeseries method to `sources`, read from
/// the Data Store `server_name` for the customer `customer_id`, with the
/// engine configuration lock held.
///
/// In this order:
///
/// 1. Every source is the decimal ID of a sampling policy of the customer
///    that has an assignee; otherwise `SOURCE_NOT_ALLOWED` at the source.
/// 2. Every source has the shape of `reference`, or with none, of the first
///    source: the same kind, column, interval, period and offset; otherwise
///    `SOURCES_INCOMPATIBLE` at the first source that differs.
/// 3. Every source's assignee has a non-empty `giganto_name` in its applied
///    configuration; otherwise `DATA_STORE_NOT_INSTALLED` at
///    `data_store.server_name`.
/// 4. `server_name` is every source's stored `data_store` and its
///    assignee's applied `giganto_name`; otherwise `SOURCES_INCOMPATIBLE` at
///    `data_store.server_name`.
///
/// Returns `Some` refusal, or `None` if the rule holds.
///
/// # Errors
///
/// Returns an error if the store cannot be read.
pub(in crate::graphql) fn check_policy_sources(
    store: &Store,
    customer_id: u32,
    sources: &[String],
    reference: Option<&ReferenceShape>,
    server_name: &str,
) -> anyhow::Result<Option<SourceRefusal>> {
    let map = store.sampling_policy_map();
    let mut policies = Vec::with_capacity(sources.len());
    for (j, source) in sources.iter().enumerate() {
        let not_allowed = |message: String| SourceRefusal {
            code: RefusalCode::SourceNotAllowed,
            message,
            source: Some(j),
            value: source.clone(),
        };
        let policy = match policy_id(source) {
            Some(id) => map.get_by_id(id)?,
            None => None,
        };
        let Some(policy) = policy.filter(|policy| policy.customer_id == Some(customer_id)) else {
            return Ok(Some(not_allowed(format!(
                "{source:?} is not a sampling policy of customer {customer_id}"
            ))));
        };
        if policy.assignee.is_none() {
            return Ok(Some(not_allowed(format!(
                "sampling policy {} has no assignee",
                policy.id
            ))));
        }
        policies.push(policy);
    }

    let first = policies.first().map(|policy| ReferenceShape {
        shape: Shape::of(policy),
        origin: format!("sampling policy {}", policy.id),
    });
    if let Some(reference) = reference.or(first.as_ref()) {
        for (j, policy) in policies.iter().enumerate() {
            if let Some(attribute) = reference.shape.difference(&Shape::of(policy)) {
                return Ok(Some(SourceRefusal {
                    code: RefusalCode::SourcesIncompatible,
                    message: format!(
                        "sampling policy {} differs in {attribute} from {}",
                        policy.id, reference.origin
                    ),
                    source: Some(j),
                    value: sources.get(j).cloned().unwrap_or_default(),
                }));
            }
        }
    }

    let mut generators = Vec::with_capacity(policies.len());
    for policy in &policies {
        match applied_giganto_name(store, policy)? {
            Some(giganto_name) => generators.push(giganto_name),
            None => {
                return Ok(Some(SourceRefusal {
                    code: RefusalCode::DataStoreNotInstalled,
                    message: format!(
                        "the Time Series Generator of sampling policy {} has no applied Data \
                         Store",
                        policy.id
                    ),
                    source: None,
                    value: server_name.to_string(),
                }));
            }
        }
    }

    for (policy, giganto_name) in policies.iter().zip(&generators) {
        let message = if policy.data_store.as_deref() != Some(server_name) {
            format!(
                "sampling policy {} keeps its series in Data Store {:?}, not {server_name:?}",
                policy.id,
                policy.data_store.as_deref().unwrap_or_default()
            )
        } else if giganto_name != server_name {
            format!(
                "the Time Series Generator of sampling policy {} writes to Data Store \
                 {giganto_name:?}, not {server_name:?}",
                policy.id
            )
        } else {
            continue;
        };
        return Ok(Some(SourceRefusal {
            code: RefusalCode::SourcesIncompatible,
            message,
            source: None,
            value: server_name.to_string(),
        }));
    }
    Ok(None)
}

/// Returns the ID a source names if it is a decimal ID in canonical form,
/// the form a policy's uses are found by.
#[must_use]
pub(in crate::graphql) fn policy_id(source: &str) -> Option<u32> {
    source
        .parse::<u32>()
        .ok()
        .filter(|id| id.to_string() == source)
}

/// Returns the non-empty `giganto_name` in the applied configuration of the
/// assignee of `policy`; `None` if it has no assignee, its agent is gone, or
/// its applied configuration has none.
fn applied_giganto_name(store: &Store, policy: &SamplingPolicy) -> anyhow::Result<Option<String>> {
    let Some(assignee) = policy.assignee.as_ref() else {
        return Ok(None);
    };
    let Some((node, _, _)) = store.node_map().get_by_id(assignee.node_id)? else {
        return Ok(None);
    };
    Ok(node
        .agents
        .iter()
        .find(|agent| agent.key == assignee.agent_key)
        .and_then(generator_data_store))
}
