mod arrival;
mod body;
mod detail;
mod detection;
mod group;
#[cfg(test)]
// The tests hold the store's read guard while running queries that only read
// it too, so the guard cannot block them.
#[allow(clippy::await_holding_lock)]
mod tests;

use std::{cmp, collections::HashMap, sync::Arc};

use anyhow::{Context as AnyhowContext, anyhow, bail};
use async_graphql::{
    Context, ID, InputObject, Object, Result, StringNumber, Subscription,
    connection::{Connection, Edge, EmptyFields},
    resolver_utils::EnumType,
};
use futures::channel::mpsc::{UnboundedSender, unbounded};
use futures_util::stream::Stream;
use num_traits::FromPrimitive;
use review_database::{
    self as database, IndexedTable, MAX_RAW_EVENT_KEYS, RawEventKey, Store, StoredDetectionEvent,
    TriagePolicyInput as DbTriagePolicyInput,
    event::{Direction, EventDb, EventFilter, EventIterator, InternalNetworks, InvalidEvent},
    types::{Endpoint, EventCategory, HostNetworkGroup},
};
use review_protocol::types as protocol;
use tokio::time;
use tracing::{error, warn};

use self::arrival::DetectionEventArrivalPage;
use self::detection::DetectionEvent;
pub(super) use self::detection::{EndpointRole, ThreatRole};
pub(super) use self::group::EventGroupQuery;
use super::{
    Role, RoleGuard,
    customer::HostNetworkGroupInput,
    filter::{DetectionModel, FlowKind, LearningMethod, RawEventKind, TrafficDirection},
    timestamp::Timestamp,
    triage::{PacketAttrInput, ResponseInput, ScoreConditionInput},
};
use crate::{error_with_caller, graphql::query, warn_with_caller};

const DEFAULT_CONNECTION_SIZE: usize = 100;
const DEFAULT_EVENT_FETCH_INTERVAL_SECS: u64 = 20;
const DEFAULT_EVENT_STUCK_CHECK_INTERVAL_SECS: u64 = 300;
const ADD_TIME_FOR_NEXT_COMPARE: i64 = 1;

#[derive(Default)]
pub(super) struct EventStream;

#[derive(Default)]
pub(super) struct EventQuery;

#[Subscription]
impl EventStream {
    /// A stream of detection events with timestamp on or after `start`.
    ///
    /// Each detection model is tracked on its own: a poll delivers, in key
    /// order, every event whose time is at or after its model's next-delivery
    /// time, and delivering an event moves only that model's time, to just
    /// past the event's time.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_stream(
        &self,
        ctx: &Context<'_>,
        start: Timestamp,
        #[graphql(
            desc = "The fetch interval in seconds, from 1 to 86400 (one day) inclusive. Omitted or null values use 20 seconds.",
            validator(
                minimum = 1,
                custom = "|value: &u64| async_graphql::validators::maximum(value, super::MAX_STREAM_FETCH_INTERVAL_SECS)"
            )
        )]
        fetch_interval: Option<u64>,
        event_stuck_check_interval: Option<u64>,
    ) -> Result<impl Stream<Item = DetectionEvent> + use<>> {
        use std::sync::RwLock;
        let start = timestamp_nanos(start.into())?;
        let store = ctx.data::<Arc<RwLock<Store>>>()?.clone();
        let fetch_interval_secs = fetch_interval.unwrap_or(DEFAULT_EVENT_FETCH_INTERVAL_SECS);
        let caller = crate::auth::Caller(ctx.data_opt::<crate::auth::MtlsIdentity>()).to_string();
        let role = ctx
            .data_opt::<super::RoleGuard>()
            .map(|super::RoleGuard::Role(role)| *role);
        let (tx, rx) = unbounded();
        tokio::spawn(async move {
            let fetch = fetch_events(
                store,
                start,
                tx,
                fetch_interval_secs,
                event_stuck_check_interval,
            )
            .await;
            if let Err(e) = fetch {
                error_with_caller!(caller: caller, role: role, "Failed to fetch events: {e:?}");
            }
        });
        Ok(rx)
    }
}

/// How far an event stream has delivered, per detection model.
struct StreamProgress {
    /// The time below which no event is scanned for unless some model's
    /// next-delivery time is still below it; the stuck check raises it.
    floor: i64,
    /// The next-delivery time of each detection model, in epoch nanoseconds.
    next: HashMap<protocol::DetectionModel, i64>,
}

impl StreamProgress {
    /// Starts every detection model, and the floor, at `start`.
    fn new(start: i64) -> Self {
        let next = DetectionModel::items()
            .iter()
            .map(|item| (protocol::DetectionModel::from(item.value), start))
            .collect();
        Self { floor: start, next }
    }

    /// Raises every model stuck at the floor to the smallest next-delivery
    /// time above it, and the floor with them, if any model is above it.
    fn advance_stuck(&mut self) {
        let floor = self.floor;
        let Some(raised) = self.next.values().copied().filter(|&t| t > floor).min() else {
            return;
        };
        for time in self.next.values_mut() {
            if *time == floor {
                *time = raised;
            }
        }
        self.floor = raised;
    }

    /// Returns the earliest next-delivery time, from which a poll scans.
    fn scan_start(&self) -> i64 {
        self.next.values().copied().min().unwrap_or(self.floor)
    }

    /// Delivers, in key order, every visible record at or after its model's
    /// next-delivery time, moving that model's time just past each one.
    fn poll(
        &mut self,
        events: &EventDb<'_>,
        mut deliver: impl FnMut(i128, StoredDetectionEvent) -> Result<()>,
    ) -> Result<()> {
        let start_key = i128::from(self.scan_start()) << 64;
        for item in events.iter_from(start_key, Direction::Forward) {
            let (key, record) = item.map_err(|e| format!("Failed to read EventDb: {e:?}"))?;
            let event_time = i64::try_from(key >> 64)?;
            let Some(next) = self.next.get_mut(&record.event().detection_model) else {
                continue;
            };
            if event_time >= *next {
                *next = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                deliver(key, record)?;
            }
        }
        Ok(())
    }
}

async fn fetch_events(
    store: Arc<std::sync::RwLock<Store>>,
    start_time: i64,
    tx: UnboundedSender<DetectionEvent>,
    fetch_interval_secs: u64,
    event_stuck_check_interval: Option<u64>,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(fetch_interval_secs));
    let stuck_check_interval =
        event_stuck_check_interval.unwrap_or(DEFAULT_EVENT_STUCK_CHECK_INTERVAL_SECS);
    let mut last_stuck_check = std::time::Instant::now();
    let mut progress = StreamProgress::new(start_time);

    loop {
        itv.tick().await;

        if last_stuck_check.elapsed().as_secs() >= stuck_check_interval {
            progress.advance_stuck();
            last_stuck_check = std::time::Instant::now();
        }

        let db = store
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        progress.poll(&db.events(), |key, record| {
            tx.unbounded_send(DetectionEvent::new(key, record))?;
            Ok(())
        })?;
    }
}

#[Object]
impl EventQuery {
    /// Looks up a single detection event by its opaque `id`.
    ///
    /// `id` is the value previously returned from `DetectionEvent.id`.
    /// Decoding the `id` is internal; consumers must not parse it.
    ///
    /// Returns `null` when no event with the given `id` exists, or when the
    /// caller's customer/sensor scope does not include the event. The same
    /// role guard and tenant scoping used by `eventList` apply here.
    ///
    /// IDs are stable for as long as the event is retained under the current
    /// storage key format. Retention drop or a future key-format migration
    /// may invalidate them.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event(&self, ctx: &Context<'_>, id: ID) -> Result<Option<DetectionEvent>> {
        load_event(ctx, &id).await
    }

    /// A list of detection events with timestamp on or after `start` and
    /// before `end`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_list(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DetectionEvent, EventTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(ctx, &filter, after, before, first, last).await
            },
        )
        .await
    }

    /// A list of detection events that pass the standard filter, with
    /// optional inline triage scoring.
    ///
    /// Unlike `eventList`, this resolver returns every event passing the
    /// standard filter regardless of whether any triage policy matched.
    /// When `triage.policies` is supplied, matching policies attach their
    /// scores via `triageScores`; events that score nothing keep
    /// `triageScores: null` and remain in the connection. The cursor
    /// pagination contract matches `eventList`.
    // Eight parameters mirror the cursor-pagination shape used by other event
    // resolvers; the additional `triage` argument is what brings the count to
    // eight. Splitting it would obscure the GraphQL signature.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_list_with_triage(
        &self,
        ctx: &Context<'_>,
        filter: EventStandardFilterInput,
        triage: Option<EventTriageInput>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, DetectionEvent, EventTotalCount, EmptyFields>> {
        let policies = triage
            .as_ref()
            .and_then(|t| t.policies.as_deref())
            .map(convert_event_triage_policies)
            .transpose()?
            .unwrap_or_default();
        let filter = EventListFilterInput::from(filter);
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_with_triage(ctx, &filter, &policies, after, before, first, last).await
            },
        )
        .await
    }

    /// Reads the detection events of the sensors of `customerId`, in the
    /// order they arrived, from after the cursor `after`.
    ///
    /// An event belongs to the customer as it does for `eventList`: through
    /// its sensor, or, for a time-series event without a sensor, through the
    /// sensors of its policy. No other condition applies; `policies` only
    /// scores the events and never removes one.
    ///
    /// One call scans at most 10,000 arrival index rows and returns at most
    /// `first` events (1 to 100, 100 when absent). `cursor` is the last row
    /// scanned, not the last event returned, so it moves forward across rows
    /// of other customers too; pass it as `after` to read on. A late event,
    /// stored after events with later detection times, is read after them.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn detection_events_by_arrival(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "The customer whose events to read.")] customer_id: ID,
        #[graphql(desc = "The `cursor` of a previous page, or absent to read from the start.")]
        after: Option<String>,
        #[graphql(desc = "The most events to return, from 1 to 100. Absent means 100.")]
        first: Option<i32>,
        #[graphql(
            desc = "Triage policies to score each returned event against, as in `eventListWithTriage`."
        )]
        policies: Option<Vec<EventTriagePolicyInput>>,
    ) -> Result<DetectionEventArrivalPage> {
        arrival::load_by_arrival(
            ctx,
            &customer_id,
            after.as_deref(),
            first,
            policies.as_deref(),
        )
    }

    /// The detection time of the earliest stored detection event, of any
    /// customer, or null when none is stored.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn oldest_detection_event_time(&self, ctx: &Context<'_>) -> Result<Option<Timestamp>> {
        arrival::oldest_event_time(ctx)
    }

    /// Returns, for each raw event key and at its position, every detection
    /// event, of any detection model, whose target is the raw event of that
    /// kind, sensor and time.
    ///
    /// A key with no match, or whose sensor is outside the caller's sensor
    /// scope, gets an empty list. More than 1000 keys is an error.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn detection_events_by_raw_event_keys(
        &self,
        ctx: &Context<'_>,
        keys: Vec<RawEventKeyInput>,
    ) -> Result<Vec<Vec<DetectionEvent>>> {
        if keys.len() > MAX_RAW_EVENT_KEYS {
            return Err(format!(
                "{} raw event keys exceed the maximum of {MAX_RAW_EVENT_KEYS}",
                keys.len()
            )
            .into());
        }
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let store = crate::graphql::get_store(ctx)?;
        let scope = sensors_for_user(ctx, &store)?;
        let keys: Vec<RawEventKey> = keys.into_iter().map(Into::into).collect();
        let found = store.events().find_by_raw_event_keys(&keys).map_err(|e| {
            error_with_caller!(ctx, "Failed to look up events by raw event keys: {e:#}");
            async_graphql::Error::new("failed to read events")
        })?;
        Ok(keys
            .iter()
            .zip(found)
            .map(|(key, records)| {
                if scope
                    .as_ref()
                    .is_some_and(|sensors| !sensors.contains(&key.sensor))
                {
                    return Vec::new();
                }
                records
                    .into_iter()
                    .map(|(key, record)| DetectionEvent::new(key, record))
                    .collect()
            })
            .collect())
    }
}

/// A raw event, named by its kind, the name of its sensor and its time.
#[derive(InputObject)]
struct RawEventKeyInput {
    raw_event_kind: RawEventKind,
    /// The sensor name, as a detection event's `sensor` holds it.
    sensor: String,
    /// The time of the raw event, its Giganto key timestamp.
    time: Timestamp,
}

impl From<RawEventKeyInput> for RawEventKey {
    fn from(input: RawEventKeyInput) -> Self {
        Self {
            raw_event_kind: input.raw_event_kind.into(),
            sensor: input.sensor,
            time: input.time.into(),
        }
    }
}

/// An endpoint of a network flow. One of `predefined`, `side`, and `custom` is
/// required. Set `negate` to `true` to negate the endpoint. By default, the
/// endpoint is not negated.
#[derive(Clone, InputObject)]
pub(super) struct EndpointInput {
    pub(super) direction: Option<TrafficDirection>,
    pub(super) predefined: Option<ID>,
    pub(super) custom: Option<HostNetworkGroupInput>,
}

/// Encodes an event's storage key as an opaque GraphQL `ID`.
///
/// The encoding is opaque to consumers; do not parse it on the client side.
/// IDs are stable for as long as the event is retained under the current
/// storage key format.
pub(super) fn opaque_event_id(key: i128) -> ID {
    ID::from(key.to_string())
}

fn parse_event_id(id: &ID) -> Result<i128> {
    id.as_str()
        .parse::<i128>()
        .map_err(|_| "invalid event id".into())
}

#[derive(Default, InputObject)]
struct EventListFilterInput {
    start: Option<Timestamp>,
    end: Option<Timestamp>,
    /// Selects an event when some listed endpoint's network contains one of
    /// its originator-side addresses (`FROM`), responder-side addresses
    /// (`TO`), or either. The originator side is a raw event body's
    /// originator address, or a subject's related IPs observed as the
    /// source; the responder side is the body's responder address, or the
    /// related IPs observed as the destination. A host subject's IP is on
    /// both sides, and a body without both addresses has none.
    endpoints: Option<Vec<EndpointInput>>,
    directions: Option<Vec<FlowKind>>,
    source: Option<String>,
    destination: Option<String>,
    keywords: Option<Vec<String>>,
    /// Selects only an event whose sensor is set and belongs to one of the
    /// listed nodes.
    sensors: Option<Vec<ID>>,
    os: Option<Vec<ID>>,
    devices: Option<Vec<ID>>,
    hostnames: Option<Vec<String>>,
    user_ids: Option<Vec<String>>,
    user_names: Option<Vec<String>>,
    user_departments: Option<Vec<String>>,
    /// Filters by the two-letter country codes recorded on events. `"ZZ"`
    /// selects events whose country could not be determined, and `"XX"`
    /// selects events recorded without country information.
    countries: Option<Vec<String>>,
    /// Selects an event whose category is listed; a null entry selects an
    /// event with no category.
    categories: Option<Vec<Option<u8>>>,
    /// Selects an event exactly when its detection model is listed, so an
    /// empty list selects nothing.
    detection_models: Option<Vec<DetectionModel>>,
    /// Selects an event exactly when its raw event kind is listed, so an
    /// empty list selects nothing.
    raw_event_kinds: Option<Vec<RawEventKind>>,
    /// Selects an event whose detection model has one of the listed learning
    /// methods.
    learning_methods: Option<Vec<LearningMethod>>,
    /// The inclusive lower bound on an event's score.
    score_min: Option<f64>,
    /// The inclusive upper bound on an event's score.
    score_max: Option<f64>,
}

/// Standard event filter for `eventListWithTriage`. It has the same fields as
/// `EventListFilterInput`; triage policies are passed exclusively via the
/// separate `triage` argument as inline data.
#[derive(Clone, InputObject)]
struct EventStandardFilterInput {
    start: Option<Timestamp>,
    end: Option<Timestamp>,
    /// Selects an event when some listed endpoint's network contains one of
    /// its originator-side addresses (`FROM`), responder-side addresses
    /// (`TO`), or either. The originator side is a raw event body's
    /// originator address, or a subject's related IPs observed as the
    /// source; the responder side is the body's responder address, or the
    /// related IPs observed as the destination. A host subject's IP is on
    /// both sides, and a body without both addresses has none.
    endpoints: Option<Vec<EndpointInput>>,
    directions: Option<Vec<FlowKind>>,
    source: Option<String>,
    destination: Option<String>,
    keywords: Option<Vec<String>>,
    /// Selects only an event whose sensor is set and belongs to one of the
    /// listed nodes.
    sensors: Option<Vec<ID>>,
    os: Option<Vec<ID>>,
    devices: Option<Vec<ID>>,
    hostnames: Option<Vec<String>>,
    user_ids: Option<Vec<String>>,
    user_names: Option<Vec<String>>,
    user_departments: Option<Vec<String>>,
    /// Filters by the two-letter country codes recorded on events. `"ZZ"`
    /// selects events whose country could not be determined, and `"XX"`
    /// selects events recorded without country information.
    countries: Option<Vec<String>>,
    /// Selects an event whose category is listed; a null entry selects an
    /// event with no category.
    categories: Option<Vec<Option<u8>>>,
    /// Selects an event exactly when its detection model is listed, so an
    /// empty list selects nothing.
    detection_models: Option<Vec<DetectionModel>>,
    /// Selects an event exactly when its raw event kind is listed, so an
    /// empty list selects nothing.
    raw_event_kinds: Option<Vec<RawEventKind>>,
    /// Selects an event whose detection model has one of the listed learning
    /// methods.
    learning_methods: Option<Vec<LearningMethod>>,
    /// The inclusive lower bound on an event's score.
    score_min: Option<f64>,
    /// The inclusive upper bound on an event's score.
    score_max: Option<f64>,
}

#[derive(InputObject)]
struct EventTriageInput {
    policies: Option<Vec<EventTriagePolicyInput>>,
}

/// Inline triage policy input for `eventListWithTriage` and
/// `detectionEventsByArrival`.
///
/// `id` is constrained to non-negative `i32` (`0..=i32::MAX`) and is echoed
/// back unchanged as `TriageScore.policyId`.
#[derive(InputObject)]
struct EventTriagePolicyInput {
    id: i32,
    packet_attr: Vec<PacketAttrInput>,
    score: Vec<ScoreConditionInput>,
    response: Vec<ResponseInput>,
}

struct TriageScore<'a> {
    inner: &'a database::event::TriageScore,
}

#[Object]
impl TriageScore<'_> {
    async fn policy_id(&self) -> ID {
        ID(self.inner.policy_id.to_string())
    }

    async fn score(&self) -> f64 {
        self.inner.score
    }
}

impl<'a> From<&'a database::event::TriageScore> for TriageScore<'a> {
    fn from(inner: &'a database::event::TriageScore) -> Self {
        Self { inner }
    }
}

struct EventTotalCount {
    start: Option<jiff::Timestamp>,
    end: Option<jiff::Timestamp>,
    filter: EventFilter,
}

#[Object]
impl EventTotalCount {
    /// The total number of events.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        if empty_time_range(self.start, self.end)? {
            return Ok(StringNumber(0));
        }
        let store = crate::graphql::get_store(ctx)?;
        let events = store.events();
        let iter = if let Some(start) = self.start {
            events.iter_from(event_key_prefix(start)?, Direction::Forward)
        } else {
            events.iter_forward()
        };
        let last = latest(self.end)?;

        let mut count = 0;
        for item in iter {
            let Some((key, event)) = readable_event(ctx, item)? else {
                continue;
            };
            if key > last {
                break;
            }
            if event.matches(&self.filter)?.0 {
                count += 1;
            }
        }
        Ok(StringNumber(count))
    }
}

fn from_filter_input(
    ctx: &Context<'_>,
    store: &Store,
    input: &EventListFilterInput,
) -> anyhow::Result<EventFilter> {
    let networks = if let Some(endpoints_input) = &input.endpoints {
        let map = store.network_map();
        Some(convert_endpoint_input(&map, endpoints_input)?)
    } else {
        None
    };

    let directions = if let Some(directions) = &input.directions {
        Some((directions.clone(), internal_networks(store)?))
    } else {
        None
    };

    let source = if let Some(addr) = &input.source {
        Some(
            addr.parse()
                .map_err(|_| anyhow!("invalid source IP address"))?,
        )
    } else {
        None
    };

    let destination = if let Some(addr) = &input.destination {
        Some(
            addr.parse()
                .map_err(|_| anyhow!("invalid destination IP address"))?,
        )
    } else {
        None
    };

    let countries = if let Some(countries_input) = &input.countries {
        let mut countries = Vec::with_capacity(countries_input.len());
        for country in countries_input {
            countries.push(
                country
                    .as_bytes()
                    .try_into()
                    .context("invalid country code")?,
            );
        }
        Some(countries)
    } else {
        None
    };

    let categories = if let Some(categories_input) = &input.categories {
        let mut categories = Vec::with_capacity(categories_input.len());
        for category in categories_input {
            categories.push(
                category
                    .map(|c| EventCategory::from_u8(c).ok_or_else(|| anyhow!("Invalid category")))
                    .transpose()?,
            );
        }
        Some(categories)
    } else {
        None
    };

    let detection_models = input
        .detection_models
        .as_ref()
        .map(|v| v.iter().map(|&model| model.into()).collect());

    let raw_event_kinds = input
        .raw_event_kinds
        .as_ref()
        .map(|v| v.iter().map(|&kind| kind.into()).collect());

    let sensors = if let Some(sensors_input) = &input.sensors {
        let scope = crate::graphql::customer_access::users_customers(ctx)
            .map_err(|e| anyhow!("{}", e.message))?;
        let map = store.node_map();
        Some(convert_sensors(&map, sensors_input, scope.as_deref())?)
    } else {
        // The caller's scope comes from `CustomerIds`, which
        // `sensors_for_user` reads.
        sensors_for_user(ctx, store).map_err(|e| anyhow!("{}", e.message))?
    };
    // A header-less time-series event is selected through the sensors of
    // the policy its time-series id names.
    let sensors = match sensors {
        Some(sensors) => Some((sensors, store.time_series_policy_sensors()?)),
        None => None,
    };

    Ok(EventFilter::new(
        networks,
        directions
            .map(|(kinds, group)| (kinds.into_iter().map(Into::into).collect::<Vec<_>>(), group)),
        source,
        destination,
        countries,
        categories,
        detection_models,
        raw_event_kinds,
        input
            .learning_methods
            .as_ref()
            .map(|v| v.iter().map(|v| (*v).into()).collect()),
        sensors,
        input.score_min,
        input.score_max,
        None,
    ))
}

fn convert_endpoint_input(
    network_map: &IndexedTable<database::Network>,
    endpoints: &[EndpointInput],
) -> anyhow::Result<Vec<Endpoint>> {
    let mut networks = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        if let Some(id) = &endpoint.predefined {
            if endpoint.custom.is_some() {
                bail!("only one of `predefined` and `custom` should be provided");
            }
            let i = id
                .as_str()
                .parse::<u32>()
                .context(format!("invalid ID: {}", id.as_str()))?;
            let Some(network) = network_map.get_by_id(i)? else {
                bail!("no such network")
            };
            networks.push(Endpoint {
                direction: endpoint.direction.map(Into::into),
                network: network.networks,
            });
        } else if let Some(custom) = &endpoint.custom {
            let network = custom.try_into()?;
            networks.push(Endpoint {
                direction: endpoint.direction.map(Into::into),
                network,
            });
        } else {
            bail!("one of `predefined` and `custom` must be specified");
        }
    }
    Ok(networks)
}

/// Returns the networks each event is tested against for `directions`: the
/// addresses internal to its own customer, found through the node its sensor
/// belongs to. An address is internal when the narrowest network of the
/// customer that contains it is an `Intranet` or `Gateway` network, so an
/// `Extranet` network nested inside an `Intranet` network is outside.
///
/// An event whose sensor maps to no node has no internal network, so it
/// matches no direction.
fn internal_networks(store: &Store) -> anyhow::Result<InternalNetworks> {
    use std::collections::{HashMap, hash_map::Entry};

    let sensor_customers = crate::graphql::customer_access::event_sensor_customer_id_map(store)
        .map_err(|e| anyhow!("{}", e.message))?;
    let table = store.customer_networks_map();
    let mut by_customer = HashMap::<u32, Vec<HostNetworkGroup>>::new();
    let mut by_sensor = HashMap::with_capacity(sensor_customers.len());
    for (sensor, customer_id) in sensor_customers {
        let groups = match by_customer.entry(customer_id) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let groups = table
                    .get(customer_id)?
                    .map_or_default(|set| set.internal_groups());
                entry.insert(groups).clone()
            }
        };
        by_sensor.insert(sensor, groups);
    }
    Ok(InternalNetworks::PerSensor(by_sensor))
}

fn convert_sensors(
    map: &database::NodeTable,
    sensors: &[ID],
    users_customers: Option<&[u32]>,
) -> anyhow::Result<Vec<String>> {
    let mut converted_sensors: Vec<String> = Vec::with_capacity(sensors.len());
    for id in sensors {
        let i = id
            .as_str()
            .parse::<u32>()
            .context(format!("invalid ID: {}", id.as_str()))?;
        let Some((node, _invalid_agents, _invalid_external_services)) = map.get_by_id(i)? else {
            bail!("no such sensor")
        };

        if let Some(allowed) = users_customers {
            let customer_id = node
                .profile
                .as_ref()
                .map(|profile| profile.customer_id)
                .ok_or_else(|| anyhow!("Forbidden"))?;
            if !allowed.contains(&customer_id) {
                bail!("Forbidden");
            }
        }

        converted_sensors.extend(crate::graphql::customer_access::event_sensor_names(&node));
    }
    Ok(converted_sensors)
}

/// Returns the event sensor names the caller is allowed to see, or `None` for
/// unscoped (administrator) callers.
///
/// A sensor name that maps to no node, such as one left behind in stored
/// events by a removed node, is never accessible to a scoped caller.
fn sensors_for_user(ctx: &Context<'_>, store: &Store) -> Result<Option<Vec<String>>> {
    let Some(customer_ids) = crate::graphql::customer_access::users_customers(ctx)? else {
        return Ok(None);
    };
    if customer_ids.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let sensors = crate::graphql::customer_access::event_sensor_customer_id_map(store)?
        .into_iter()
        .filter(|(_, customer_id)| customer_ids.contains(customer_id))
        .map(|(sensor, _)| sensor)
        .collect::<Vec<_>>();
    Ok(Some(sensors))
}

async fn load_event(ctx: &Context<'_>, id: &ID) -> Result<Option<DetectionEvent>> {
    let key = parse_event_id(id)?;
    let store = crate::graphql::get_store(ctx)?;

    // Derive the caller's allowed sensors via the shared customer-access
    // helper, which reads the request's `CustomerIds`. SystemAdministrator
    // (no customer_ids) sees every sensor; everyone else is restricted to
    // sensors owned by their accessible customers.
    let sensors = match sensors_for_user(ctx, &store)? {
        Some(sensors) => Some((sensors, store.time_series_policy_sensors()?)),
        None => None,
    };
    let filter = EventFilter::new(
        None, None, None, None, None, None, None, None, None, sensors, None, None, None,
    );

    let db = store.events();
    let mut iter = db.iter_from(key, Direction::Forward);
    let Some(item) = iter.next() else {
        return Ok(None);
    };
    let Some((found_key, event)) = readable_event(ctx, item)? else {
        return Ok(None);
    };
    if found_key != key {
        return Ok(None);
    }

    let (matched, _) = event.matches(&filter).map_err(|e| format!("{e}"))?;
    if !matched {
        return Ok(None);
    }
    Ok(Some(DetectionEvent::new(found_key, event)))
}

async fn load(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, DetectionEvent, EventTotalCount, EmptyFields>> {
    load_with_triage(ctx, filter, &[], after, before, first, last).await
}

fn earliest(start: Option<jiff::Timestamp>) -> Result<i128> {
    start
        .map(event_key_prefix)
        .transpose()
        .map(|start| start.unwrap_or(i128::MIN))
}

fn latest(end: Option<jiff::Timestamp>) -> Result<i128> {
    if let Some(end) = end {
        Ok(event_key_prefix(end)?.saturating_sub(1))
    } else {
        Ok(i128::MAX)
    }
}

fn event_range(
    start: Option<jiff::Timestamp>,
    end: Option<jiff::Timestamp>,
    after: Option<&str>,
    before: Option<&str>,
) -> Result<Option<(i128, i128)>> {
    let mut earliest = earliest(start)?;
    if let Some(after) = after {
        let Some(after) = earliest_after(after)? else {
            return Ok(None);
        };
        earliest = cmp::max(earliest, after);
    }

    let mut latest = if let Some(end) = end {
        let Some(end) = event_key_prefix(end)?.checked_sub(1) else {
            return Ok(None);
        };
        end
    } else {
        i128::MAX
    };
    if let Some(before) = before {
        let Some(before) = latest_before(before)? else {
            return Ok(None);
        };
        latest = cmp::min(latest, before);
    }

    Ok((earliest <= latest).then_some((earliest, latest)))
}

fn empty_time_range(start: Option<jiff::Timestamp>, end: Option<jiff::Timestamp>) -> Result<bool> {
    let Some(end) = end else {
        return Ok(false);
    };
    Ok(earliest(start)? >= event_key_prefix(end)?)
}

fn timestamp_nanos(timestamp: jiff::Timestamp) -> Result<i64> {
    i64::try_from(timestamp.as_nanosecond())
        .map_err(|_| "event timestamp is outside the supported nanosecond range".into())
}

fn event_key_prefix(timestamp: jiff::Timestamp) -> Result<i128> {
    Ok(i128::from(timestamp_nanos(timestamp)?) << 64)
}

fn earliest_after(after: &str) -> Result<Option<i128>> {
    let after = after
        .parse::<i128>()
        .map_err(|_| "invalid cursor `after`")?;
    Ok(after.checked_add(1))
}

fn latest_before(before: &str) -> Result<Option<i128>> {
    let before = before
        .parse::<i128>()
        .map_err(|_| "invalid cursor `before`")?;
    Ok(before.checked_sub(1))
}

fn is_event_read_failure(error: &InvalidEvent) -> bool {
    matches!(error, InvalidEvent::Iteration(_))
}

fn readable_event(
    ctx: &Context<'_>,
    item: std::result::Result<(i128, StoredDetectionEvent), InvalidEvent>,
) -> anyhow::Result<Option<(i128, StoredDetectionEvent)>> {
    match item {
        Ok(event) => Ok(Some(event)),
        Err(e) if is_event_read_failure(&e) => {
            error_with_caller!(ctx, "Failed to read events: {e:?}");
            Err(anyhow!("failed to read events"))
        }
        Err(e) => {
            warn_with_caller!(ctx, "Invalid event: {e:?}");
            Ok(None)
        }
    }
}

impl From<EventStandardFilterInput> for EventListFilterInput {
    fn from(input: EventStandardFilterInput) -> Self {
        Self {
            start: input.start,
            end: input.end,
            endpoints: input.endpoints,
            directions: input.directions,
            source: input.source,
            destination: input.destination,
            keywords: input.keywords,
            sensors: input.sensors,
            os: input.os,
            devices: input.devices,
            hostnames: input.hostnames,
            user_ids: input.user_ids,
            user_names: input.user_names,
            user_departments: input.user_departments,
            countries: input.countries,
            categories: input.categories,
            detection_models: input.detection_models,
            raw_event_kinds: input.raw_event_kinds,
            learning_methods: input.learning_methods,
            score_min: input.score_min,
            score_max: input.score_max,
        }
    }
}

fn convert_event_triage_policies(
    policies: &[EventTriagePolicyInput],
) -> anyhow::Result<Vec<DbTriagePolicyInput>> {
    let now = jiff::Timestamp::now();
    let mut result = Vec::with_capacity(policies.len());
    for policy in policies {
        let id: u32 = policy
            .id
            .try_into()
            .map_err(|_| anyhow!("triage policy id must be non-negative"))?;
        result.push(DbTriagePolicyInput {
            id,
            name: id.to_string(),
            creation_time: now,
            packet_attr: policy.packet_attr.iter().map(Into::into).collect(),
            score: policy.score.iter().map(Into::into).collect(),
            response: policy.response.iter().map(Into::into).collect(),
        });
    }
    Ok(result)
}

/// Loads a page of the events `filter` selects, scoring each against
/// `policies` when there are any. An event no policy qualifies for stays in
/// the page with no triage scores.
async fn load_with_triage(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    policies: &[DbTriagePolicyInput],
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, DetectionEvent, EventTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx)?;

    let start = filter.start.map(Into::into);
    let end = filter.end.map(Into::into);
    let event_filter = from_filter_input(ctx, &store, filter)?;
    let db = store.events();
    let bounds = if empty_time_range(start, end)? {
        None
    } else {
        event_range(start, end, after.as_deref(), before.as_deref())?
    };
    let (events, has_previous, has_next) = if let Some((earliest, latest)) = bounds {
        if let Some(last) = last {
            let iter = db.iter_from(latest, Direction::Reverse);
            let (events, has_more) = iter_to_events(
                ctx,
                iter,
                earliest,
                cmp::Ordering::is_ge,
                last,
                &event_filter,
                policies,
            )
            .map_err(|e| format!("{e}"))?;
            (events.into_iter().rev().collect(), has_more, false)
        } else {
            let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
            let iter = db.iter_from(earliest, Direction::Forward);
            let (events, has_more) = iter_to_events(
                ctx,
                iter,
                latest,
                cmp::Ordering::is_le,
                first,
                &event_filter,
                policies,
            )
            .map_err(|e| format!("{e}"))?;
            (events, false, has_more)
        }
    } else {
        (Vec::new(), false, false)
    };

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        EventTotalCount {
            start,
            end,
            filter: event_filter,
        },
    );
    connection.edges.extend(
        events
            .into_iter()
            .map(|(k, ev)| Edge::new(k.to_string(), ev)),
    );
    Ok(connection)
}

fn iter_to_events(
    ctx: &Context<'_>,
    iter: EventIterator,
    to: i128,
    cond: fn(cmp::Ordering) -> bool,
    len: usize,
    filter: &EventFilter,
    policies: &[DbTriagePolicyInput],
) -> anyhow::Result<(Vec<(i128, DetectionEvent)>, bool)> {
    let mut events = Vec::new();
    let mut exceeded = false;
    for item in iter {
        let Some((key, event)) = readable_event(ctx, item)? else {
            continue;
        };
        if !(cond)(key.cmp(&to)) {
            break;
        }
        if !event.matches(filter)?.0 {
            continue;
        }
        let scores = if policies.is_empty() {
            None
        } else {
            Some(event.score_against_policies(policies)).filter(|scores| !scores.is_empty())
        };
        events.push((key, DetectionEvent::with_triage_scores(key, event, scores)));
        exceeded = events.len() > len;
        if exceeded {
            break;
        }
    }
    if exceeded {
        events.pop();
    }
    Ok((events, exceeded))
}
