//! The source rule of the timeseries method (RFC 0006 §9, G1): a timeseries
//! training definition, and a detector of a timeseries model, read the
//! series of time series generation policies, named by their decimal IDs.
//!
//! Every source must be an assigned policy of the customer, all sources must
//! have one shape, a definition or model of a time-series type reads only
//! policies of that type and version, a custom definition's keys must equal
//! its sources' values, and they must all be kept in the one Data Store the
//! definition or the detector reads. The caller holds the engine
//! configuration lock, as every writer that checks a source does.

use review_database::{
    ClusteringModelTypeRef, CounterpartScope, EndpointRole, GroupByUnit, Measure, RawEventKind,
    SlotSize, Store, TimeSeriesGenerationPolicy, WindowSize, time_series_type,
};

use super::generator_data_store;
use crate::graphql::refusal::{RefusalCode, refusal};

/// What a policy's series look like: two policies of one shape give slot
/// vectors of the same length and meaning, on the same scale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::graphql) struct Shape {
    raw_event_kind: RawEventKind,
    measure: Measure,
    group_by: Option<EndpointRole>,
    group_by_unit: GroupByUnit,
    counterpart_scope: CounterpartScope,
    slot_size: SlotSize,
    window_size: WindowSize,
    utc_offset: i32,
}

impl Shape {
    fn of(policy: &TimeSeriesGenerationPolicy) -> Self {
        Self {
            raw_event_kind: policy.raw_event_kind,
            measure: policy.measure,
            group_by: policy.group_by,
            group_by_unit: policy.group_by_unit,
            counterpart_scope: policy.counterpart_scope,
            slot_size: policy.slot_size,
            window_size: policy.window_size,
            utc_offset: policy.utc_offset,
        }
    }

    /// Returns the name of the first field in which `other` differs from
    /// this shape, or `None` if it does not.
    fn difference(&self, other: &Self) -> Option<&'static str> {
        if self.raw_event_kind != other.raw_event_kind {
            Some("raw_event_kind")
        } else if self.measure != other.measure {
            Some("measure")
        } else if self.group_by != other.group_by {
            Some("group_by")
        } else if self.group_by_unit != other.group_by_unit {
            Some("group_by_unit")
        } else if self.counterpart_scope != other.counterpart_scope {
            Some("counterpart_scope")
        } else if self.slot_size != other.slot_size {
            Some("slot_size")
        } else if self.window_size != other.window_size {
            Some("window_size")
        } else if self.utc_offset != other.utc_offset {
            Some("utc_offset")
        } else {
            None
        }
    }
}

/// The shape every source must have.
#[derive(Clone, Copy, Debug)]
pub(in crate::graphql) enum ShapeReference<'a> {
    /// The shape of the first source: a definition whose model is not yet
    /// trained on time series generation policies.
    FirstSource,
    /// The shape of the policies the model `name` was trained on, as
    /// [`trained_shape`] reads it; `None` if none of them is stored, and the
    /// shape is then unknown.
    Model { name: &'a str, shape: Option<Shape> },
}

/// The keys of a custom timeseries definition that must equal the values of
/// its source policies, as the definition writes them.
#[derive(Clone, Copy, Debug)]
pub(in crate::graphql) struct CustomKeys<'a> {
    /// The definition's `raw_event_kind`.
    pub(in crate::graphql) raw_event_kind: &'a str,
    /// The definition's `group_by`, `source` or `destination`; `None` when
    /// absent.
    pub(in crate::graphql) group_by: Option<&'a str>,
    /// The definition's `slot_size`, in seconds; `None` when absent.
    pub(in crate::graphql) slot_size: Option<u64>,
}

/// The key of a refusal of the source rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::graphql) enum SourceField {
    /// The source at this index, `sources[<j>]`.
    Source(usize),
    /// A key of the definition, such as `group_by`.
    Key(&'static str),
    /// `data_store.server_name`.
    DataStore,
}

/// A refusal of the source rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::graphql) struct SourceRefusal {
    /// `SOURCE_NOT_ALLOWED`, `SOURCES_INCOMPATIBLE` or
    /// `DATA_STORE_NOT_INSTALLED`.
    pub(in crate::graphql) code: RefusalCode,
    pub(in crate::graphql) message: String,
    /// The offending key.
    pub(in crate::graphql) field: SourceField,
    pub(in crate::graphql) value: String,
}

impl SourceRefusal {
    /// Returns the refusal as a GraphQL error whose `field` is `prefix`
    /// followed by the offending key: `sources[<j>]`, a definition key or
    /// `data_store.server_name`.
    #[must_use]
    pub(in crate::graphql) fn into_error(self, prefix: &str) -> async_graphql::Error {
        let field = match self.field {
            SourceField::Source(j) => format!("{prefix}sources[{j}]"),
            SourceField::Key(key) => format!("{prefix}{key}"),
            SourceField::DataStore => format!("{prefix}data_store.server_name"),
        };
        refusal(self.code, self.message, &field, self.value)
    }
}

/// Returns the id and version of the time-series type `model_type` names,
/// or `None` if it is `Custom` or names no time-series type, such as a
/// clustering model type.
#[must_use]
pub(in crate::graphql) fn time_series_type_of(
    model_type: &ClusteringModelTypeRef,
) -> Option<(&str, u32)> {
    match model_type {
        ClusteringModelTypeRef::Catalog { id, version } if time_series_type(id).is_some() => {
            Some((id.as_str(), *version))
        }
        ClusteringModelTypeRef::Catalog { .. } | ClusteringModelTypeRef::Custom => None,
    }
}

/// Returns the shape of the policies the model `name` was trained on, its
/// `trained_sources`, as the shape of the first of them that is stored, or
/// with none stored, as an unknown shape.
///
/// The policies a model's `trained_sources` names are in use while the model
/// exists, so none of them can be deleted, and a fixed policy's shape never
/// changes. A model with none stored is one trained before its sources were
/// recorded.
///
/// # Errors
///
/// Returns an error if the store cannot be read.
pub(in crate::graphql) fn trained_shape<'a>(
    store: &Store,
    name: &'a str,
    trained_sources: &[String],
) -> anyhow::Result<ShapeReference<'a>> {
    let map = store.time_series_generation_policy_map();
    let mut shape = None;
    for source in trained_sources {
        let Some(id) = policy_id(source) else {
            continue;
        };
        if let Some(policy) = map.get_by_id(id)? {
            shape = Some(Shape::of(&policy));
            break;
        }
    }
    Ok(ShapeReference::Model { name, shape })
}

/// Applies the source rule of the timeseries method to `sources`, read from
/// the Data Store `server_name` for the customer `customer_id`, with the
/// engine configuration lock held.
///
/// `model_type` is the clustering model type of the definition, or for a
/// detector the type its model recorded. `custom_keys` are the keys of a
/// custom definition, and `None` for a definition of a catalog type and for
/// a detector, which has no such keys.
///
/// In this order:
///
/// 1. Every source is the decimal ID of a time series generation policy of
///    the customer that has an assignee; otherwise `SOURCE_NOT_ALLOWED` at
///    the source.
/// 2. Every source has the shape `reference` gives: the same raw event
///    kind, measure, grouping endpoint, grouping unit, counterpart scope,
///    slot size, window size and UTC offset; otherwise
///    `SOURCES_INCOMPATIBLE` at the first source that differs. A model whose
///    shape is unknown gives none a source can have, so any source is
///    refused with `SOURCES_INCOMPATIBLE` at `sources[0]`.
/// 3. When `model_type` names a time-series type, every source policy was
///    made from that type at that version; otherwise `SOURCES_INCOMPATIBLE`
///    at the first source that was not, a custom policy, one of another
///    type and one of another version of the type alike.
/// 4. With `custom_keys`, its `raw_event_kind`, `group_by` and `slot_size`,
///    in that order, equal the source policies' raw event kind, grouping
///    endpoint (absent exactly when the policies are not grouped) and slot
///    size in seconds; otherwise `SOURCES_INCOMPATIBLE` at the first key
///    that differs, with the definition's value, empty when absent.
/// 5. Every source's assignee has a non-empty `giganto_name` in its applied
///    configuration; otherwise `DATA_STORE_NOT_INSTALLED` at
///    `data_store.server_name`.
/// 6. `server_name` is every source's stored `data_store` and its
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
    reference: ShapeReference<'_>,
    model_type: &ClusteringModelTypeRef,
    custom_keys: Option<CustomKeys<'_>>,
    server_name: &str,
) -> anyhow::Result<Option<SourceRefusal>> {
    let map = store.time_series_generation_policy_map();
    let mut policies = Vec::with_capacity(sources.len());
    for (j, source) in sources.iter().enumerate() {
        let not_allowed = |message: String| SourceRefusal {
            code: RefusalCode::SourceNotAllowed,
            message,
            field: SourceField::Source(j),
            value: source.clone(),
        };
        let policy = match policy_id(source) {
            Some(id) => map.get_by_id(id)?,
            None => None,
        };
        let Some(policy) = policy.filter(|policy| policy.customer_id == customer_id) else {
            return Ok(Some(not_allowed(format!(
                "{source:?} is not a time series generation policy of customer {customer_id}"
            ))));
        };
        if policy.assignee.is_none() {
            return Ok(Some(not_allowed(format!(
                "time series generation policy {} has no assignee",
                policy.id
            ))));
        }
        policies.push(policy);
    }

    if let Some(refused) = check_shape(&policies, sources, reference) {
        return Ok(Some(refused));
    }
    if let Some(refused) = check_type(&policies, sources, model_type) {
        return Ok(Some(refused));
    }
    if let Some(keys) = custom_keys
        && let Some(refused) = check_custom_keys(&policies, keys)
    {
        return Ok(Some(refused));
    }

    let mut generators = Vec::with_capacity(policies.len());
    for policy in &policies {
        match applied_giganto_name(store, policy)? {
            Some(giganto_name) => generators.push(giganto_name),
            None => {
                return Ok(Some(SourceRefusal {
                    code: RefusalCode::DataStoreNotInstalled,
                    message: format!(
                        "the Time Series Generator of time series generation policy {} has no \
                         applied Data Store",
                        policy.id
                    ),
                    field: SourceField::DataStore,
                    value: server_name.to_string(),
                }));
            }
        }
    }

    for (policy, giganto_name) in policies.iter().zip(&generators) {
        let message = if policy.data_store.as_deref() != Some(server_name) {
            format!(
                "time series generation policy {} keeps its series in Data Store {:?}, not \
                 {server_name:?}",
                policy.id,
                policy.data_store.as_deref().unwrap_or_default()
            )
        } else if giganto_name != server_name {
            format!(
                "the Time Series Generator of time series generation policy {} writes to Data \
                 Store {giganto_name:?}, not {server_name:?}",
                policy.id
            )
        } else {
            continue;
        };
        return Ok(Some(SourceRefusal {
            code: RefusalCode::SourcesIncompatible,
            message,
            field: SourceField::DataStore,
            value: server_name.to_string(),
        }));
    }
    Ok(None)
}

/// Returns the refusal of step 2 of [`check_policy_sources`] for the
/// `policies` the `sources` name, in order; `None` if every one has the shape
/// `reference` gives.
fn check_shape(
    policies: &[TimeSeriesGenerationPolicy],
    sources: &[String],
    reference: ShapeReference<'_>,
) -> Option<SourceRefusal> {
    let (shape, origin) = match reference {
        ShapeReference::FirstSource => {
            let first = policies.first()?;
            (
                Shape::of(first),
                format!("time series generation policy {}", first.id),
            )
        }
        ShapeReference::Model {
            name,
            shape: Some(shape),
        } => (
            shape,
            format!("the time series generation policies model {name:?} was trained on"),
        ),
        ShapeReference::Model { name, shape: None } => {
            let first = sources.first()?;
            return Some(SourceRefusal {
                code: RefusalCode::SourcesIncompatible,
                message: format!(
                    "none of the time series generation policies model {name:?} was trained on \
                     is stored, so the shape its sources must have is unknown"
                ),
                field: SourceField::Source(0),
                value: first.clone(),
            });
        }
    };
    let (j, policy, attribute) = policies.iter().enumerate().find_map(|(j, policy)| {
        shape
            .difference(&Shape::of(policy))
            .map(|attribute| (j, policy, attribute))
    })?;
    Some(SourceRefusal {
        code: RefusalCode::SourcesIncompatible,
        message: format!(
            "time series generation policy {} differs in {attribute} from {origin}",
            policy.id
        ),
        field: SourceField::Source(j),
        value: sources.get(j).cloned().unwrap_or_default(),
    })
}

/// Returns the refusal of step 3 of [`check_policy_sources`] for the
/// `policies` the `sources` name, in order; `None` if `model_type` names no
/// time-series type or every policy was made from it at its version.
fn check_type(
    policies: &[TimeSeriesGenerationPolicy],
    sources: &[String],
    model_type: &ClusteringModelTypeRef,
) -> Option<SourceRefusal> {
    let (id, version) = time_series_type_of(model_type)?;
    let (j, policy) = policies.iter().enumerate().find(|(_, policy)| {
        policy
            .time_series_type
            .as_ref()
            .is_none_or(|of| of.id != id || of.version != version)
    })?;
    let made_from = match &policy.time_series_type {
        Some(of) => format!("time-series type {:?} version {}", of.id, of.version),
        None => "no time-series type".to_string(),
    };
    Some(SourceRefusal {
        code: RefusalCode::SourcesIncompatible,
        message: format!(
            "time series generation policy {} was made from {made_from}, not time-series type \
             {id:?} version {version}",
            policy.id
        ),
        field: SourceField::Source(j),
        value: sources.get(j).cloned().unwrap_or_default(),
    })
}

/// Returns the refusal of step 4 of [`check_policy_sources`] for the
/// `policies` a custom definition with the keys `keys` reads; `None` if
/// every key equals their values. The policies have one shape, so the first
/// one's values are theirs.
fn check_custom_keys(
    policies: &[TimeSeriesGenerationPolicy],
    keys: CustomKeys<'_>,
) -> Option<SourceRefusal> {
    let policy = policies.first()?;
    let raw_event_kind = raw_event_kind_name(policy.raw_event_kind);
    let group_by = policy.group_by.map(endpoint_role_name);
    let slot_size = slot_seconds(policy.slot_size);
    let (key, value, expected) = if Some(keys.raw_event_kind) != raw_event_kind {
        (
            "raw_event_kind",
            keys.raw_event_kind.to_string(),
            format!("raw event kind {:?}", raw_event_kind.unwrap_or_default()),
        )
    } else if keys.group_by != group_by {
        (
            "group_by",
            keys.group_by.unwrap_or_default().to_string(),
            match group_by {
                Some(role) => format!("its series grouped by {role:?}"),
                None => "its series not grouped".to_string(),
            },
        )
    } else if keys.slot_size != Some(slot_size) {
        (
            "slot_size",
            keys.slot_size.map_or_default(|s| s.to_string()),
            format!("slot size {slot_size}"),
        )
    } else {
        return None;
    };
    Some(SourceRefusal {
        code: RefusalCode::SourcesIncompatible,
        message: format!(
            "{key} differs from time series generation policy {}, which has {expected}",
            policy.id
        ),
        field: SourceField::Key(key),
        value,
    })
}

/// Returns the snake-case name of `kind`, as a training definition's
/// `raw_event_kind` writes it, if it is a network kind, the only kinds a
/// time series generation policy counts.
fn raw_event_kind_name(kind: RawEventKind) -> Option<&'static str> {
    Some(match kind {
        RawEventKind::Bootp => "bootp",
        RawEventKind::Conn => "conn",
        RawEventKind::DceRpc => "dce_rpc",
        RawEventKind::Dhcp => "dhcp",
        RawEventKind::Dns => "dns",
        RawEventKind::Ftp => "ftp",
        RawEventKind::Http => "http",
        RawEventKind::Icmp => "icmp",
        RawEventKind::Kerberos => "kerberos",
        RawEventKind::Ldap => "ldap",
        RawEventKind::MalformedDns => "malformed_dns",
        RawEventKind::Mqtt => "mqtt",
        RawEventKind::Nfs => "nfs",
        RawEventKind::Ntlm => "ntlm",
        RawEventKind::Radius => "radius",
        RawEventKind::Rdp => "rdp",
        RawEventKind::Smb => "smb",
        RawEventKind::Smtp => "smtp",
        RawEventKind::Ssh => "ssh",
        RawEventKind::Tls => "tls",
        _ => return None,
    })
}

/// Returns the name of `role`, as a training definition's `group_by` writes
/// it.
fn endpoint_role_name(role: EndpointRole) -> &'static str {
    match role {
        EndpointRole::Source => "source",
        EndpointRole::Destination => "destination",
    }
}

/// Returns the length of a slot of `size`, in seconds, as a training
/// definition's `slot_size` writes it.
fn slot_seconds(size: SlotSize) -> u64 {
    match size {
        SlotSize::FiveMinutes => 300,
        SlotSize::TenMinutes => 600,
        SlotSize::FifteenMinutes => 900,
        SlotSize::ThirtyMinutes => 1800,
        SlotSize::OneHour => 3600,
    }
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
fn applied_giganto_name(
    store: &Store,
    policy: &TimeSeriesGenerationPolicy,
) -> anyhow::Result<Option<String>> {
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
