mod group;

pub(super) use self::group::EventGroupQuery;
use super::{
    customer::{Customer, HostNetworkGroupInput},
    filter::{FlowKind, LearningMethod, TrafficDirection},
    network::Network,
    Role, RoleGuard,
};
use anyhow::{anyhow, bail, Context as AnyhowContext};
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    Context, InputObject, Object, Result, Union, ID,
};
use bincode::Options;
use chrono::{DateTime, Utc};
use review_database::{
    self as database, find_ip_country,
    types::{Endpoint, EventCategory, FromKeyValue, HostNetworkGroup},
    Direction, EventFilter, EventIterator, IndexedMap, IndexedMultimap, IterableMap, Store,
};
use std::{
    cmp,
    net::IpAddr,
    num::NonZeroU8,
    sync::{Arc, Mutex},
};
use tracing::warn;

const DEFAULT_CONNECTION_SIZE: usize = 100;

#[derive(Default)]
pub(super) struct EventQuery;

#[Object]
impl EventQuery {
    /// A list of events with timestamp on or after `start` and before `end`.
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
    ) -> Result<Connection<String, Event, EventTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(ctx, &filter, after, before, first, last)
            },
        )
        .await
    }
}

/// An endpoint of a network flow. One of `predefined`, `side`, and `custom` is
/// required. Set `negate` to `true` to negate the endpoint. By default, the
/// endpoint is not negated.
#[derive(InputObject)]
pub(super) struct EndpointInput {
    pub(super) direction: Option<TrafficDirection>,
    pub(super) predefined: Option<ID>,
    pub(super) custom: Option<HostNetworkGroupInput>,
}

/// An event to report.
#[derive(Union)]
enum Event {
    /// DNS requests and responses that convey unusual host names.
    DnsCovertChannel(DnsCovertChannel),

    /// HTTP-related threats.
    HttpThreat(HttpThreat),

    /// Brute force attacks against RDP, attempting to guess passwords.
    RdpBruteForce(RdpBruteForce),

    /// Multiple HTTP sessions with the same source and destination that occur within a short time.
    /// This is a sign of a possible unauthorized communication channel.
    RepeatedHttpSessions(RepeatedHttpSessions),

    /// An HTTP connection to a Tor exit node.
    TorConnection(TorConnection),

    /// DGA (Domain Generation Algorithm) generated hostname in HTTP request message
    DomainGenerationAlgorithm(DomainGenerationAlgorithm),
}

impl From<database::Event> for Event {
    fn from(event: database::Event) -> Self {
        match event {
            database::Event::DnsCovertChannel(event) => Event::DnsCovertChannel(event.into()),
            database::Event::HttpThreat(event) => Event::HttpThreat(event.into()),
            database::Event::RdpBruteForce(event) => Event::RdpBruteForce(event.into()),
            database::Event::RepeatedHttpSessions(event) => {
                Event::RepeatedHttpSessions(event.into())
            }
            database::Event::TorConnection(event) => Event::TorConnection(event.into()),
            database::Event::DomainGenerationAlgorithm(event) => {
                Event::DomainGenerationAlgorithm(event.into())
            }
        }
    }
}

#[derive(InputObject)]
struct EventListFilterInput {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    customers: Option<Vec<ID>>,
    endpoints: Option<Vec<EndpointInput>>,
    directions: Option<Vec<FlowKind>>,
    source: Option<String>,
    destination: Option<String>,
    keywords: Option<Vec<String>>,
    network_tags: Option<Vec<ID>>,
    sensors: Option<Vec<ID>>,
    os: Option<Vec<ID>>,
    devices: Option<Vec<ID>>,
    host_names: Option<Vec<String>>,
    user_ids: Option<Vec<String>>,
    user_names: Option<Vec<String>>,
    user_departments: Option<Vec<String>>,
    countries: Option<Vec<String>>,
    categories: Option<Vec<u8>>,
    levels: Option<Vec<u8>>,
    kinds: Option<Vec<String>>,
    learning_methods: Option<Vec<LearningMethod>>,
    confidence: Option<f32>,
    triage_policies: Option<Vec<ID>>,
}

struct TriageScore<'a> {
    inner: &'a database::TriageScore,
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

impl<'a> From<&'a database::TriageScore> for TriageScore<'a> {
    fn from(inner: &'a database::TriageScore) -> Self {
        Self { inner }
    }
}

fn country_code(ctx: &Context<'_>, addr: IpAddr) -> String {
    if let Ok(mutex) = ctx.data::<Arc<Mutex<ip2location::DB>>>() {
        let Ok(mut locator) = mutex.lock() else {
            return "ZZ".to_string();
        };
        find_ip_country(&mut locator, addr)
    } else {
        "ZZ".to_string()
    }
}

struct DnsCovertChannel {
    inner: database::DnsCovertChannel,
}

#[Object]
impl DnsCovertChannel {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn query(&self) -> &str {
        &self.inner.query
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::DnsCovertChannel> for DnsCovertChannel {
    fn from(inner: database::DnsCovertChannel) -> Self {
        Self { inner }
    }
}

fn find_ip_customer(map: &IndexedMap, addr: IpAddr) -> Result<Option<Customer>> {
    for (key, value) in map.iter_forward()? {
        let customer = database::Customer::from_key_value(key.as_ref(), value.as_ref())?;
        if customer.networks.iter().any(|n| n.contains(addr)) {
            return Ok(Some(customer.into()));
        }
    }
    Ok(None)
}

fn find_ip_network(map: &IndexedMultimap, addr: IpAddr) -> Result<Option<Network>> {
    for (key, value) in map.iter_forward()? {
        let network = database::Network::from_key_value(key.as_ref(), value.as_ref())?;
        if network.networks.contains(addr) {
            return Ok(Some(network.into()));
        }
    }
    Ok(None)
}

struct HttpThreat {
    inner: database::HttpThreat,
}

#[Object]
impl HttpThreat {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn method(&self) -> &str {
        &self.inner.method
    }

    async fn host(&self) -> &str {
        &self.inner.host
    }

    async fn content(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.inner.method,
            self.inner.host,
            self.inner.uri,
            self.inner.referer,
            self.inner.status_code,
            self.inner.user_agent
        )
    }

    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    async fn version(&self) -> &str {
        &self.inner.version
    }

    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    async fn request_len(&self) -> usize {
        self.inner.request_len
    }

    async fn response_len(&self) -> usize {
        self.inner.response_len
    }

    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    async fn username(&self) -> &str {
        &self.inner.username
    }

    async fn password(&self) -> &str {
        &self.inner.password
    }

    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    async fn rule_id(&self) -> u32 {
        self.inner.rule_id
    }

    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    async fn cluster_id(&self) -> usize {
        self.inner.cluster_id
    }

    async fn attack_kind(&self) -> &str {
        &self.inner.attack_kind
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::HttpThreat> for HttpThreat {
    fn from(inner: database::HttpThreat) -> Self {
        Self { inner }
    }
}

struct RdpBruteForce {
    inner: database::RdpBruteForce,
}

#[Object]
impl RdpBruteForce {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::RdpBruteForce> for RdpBruteForce {
    fn from(inner: database::RdpBruteForce) -> Self {
        Self { inner }
    }
}

struct RepeatedHttpSessions {
    inner: database::RepeatedHttpSessions,
}

#[Object]
impl RepeatedHttpSessions {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    async fn src_port(&self) -> String {
        self.inner.src_port.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    async fn dst_port(&self) -> String {
        self.inner.dst_port.to_string()
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::RepeatedHttpSessions> for RepeatedHttpSessions {
    fn from(inner: database::RepeatedHttpSessions) -> Self {
        Self { inner }
    }
}

struct TorConnection {
    inner: database::TorConnection,
}

#[Object]
impl TorConnection {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    async fn src_port(&self) -> String {
        self.inner.src_port.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    async fn dst_port(&self) -> String {
        self.inner.dst_port.to_string()
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::TorConnection> for TorConnection {
    fn from(inner: database::TorConnection) -> Self {
        Self { inner }
    }
}

struct DomainGenerationAlgorithm {
    inner: database::DomainGenerationAlgorithm,
}

#[Object]
impl DomainGenerationAlgorithm {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let map = ctx.data::<Arc<Store>>()?.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let map = ctx.data::<Arc<Store>>()?.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn host(&self) -> &str {
        &self.inner.host
    }

    async fn method(&self) -> &str {
        &self.inner.method
    }

    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    async fn version(&self) -> &str {
        &self.inner.version
    }

    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    async fn request_len(&self) -> usize {
        self.inner.request_len
    }

    async fn response_len(&self) -> usize {
        self.inner.response_len
    }

    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    async fn username(&self) -> &str {
        &self.inner.username
    }

    async fn password(&self) -> &str {
        &self.inner.password
    }

    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::DomainGenerationAlgorithm> for DomainGenerationAlgorithm {
    fn from(inner: database::DomainGenerationAlgorithm) -> Self {
        Self { inner }
    }
}

struct EventTotalCount {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    filter: EventFilter,
}

#[Object]
impl EventTotalCount {
    /// The total number of events.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let db = ctx.data::<Arc<Store>>()?;
        let events = db.events();
        let locator = if self.filter.has_country() {
            if let Ok(mutex) = ctx.data::<Arc<Mutex<ip2location::DB>>>() {
                Some(Arc::clone(mutex))
            } else {
                return Err("unable to locate IP address".into());
            }
        } else {
            None
        };
        let iter = self.start.map_or_else(
            || events.iter_forward(),
            |start| {
                let start = i128::from(start.timestamp_nanos()) << 64;
                events.iter_from(start, Direction::Forward)
            },
        );
        let last = if let Some(end) = self.end {
            let end = i128::from(end.timestamp_nanos()) << 64;
            if end == 0 {
                return Ok(0);
            }
            end - 1
        } else {
            i128::MAX
        };

        let mut count = 0;
        for item in iter {
            let (key, event) = match item {
                Ok(kv) => kv,
                Err(e) => {
                    warn!("invalid event: {:?}", e);
                    continue;
                }
            };
            if key > last {
                break;
            }
            if !event.matches(locator.clone(), &self.filter)?.0 {
                continue;
            }
            count += 1;
        }
        Ok(count)
    }
}

#[allow(clippy::too_many_lines)]
fn from_filter_input(
    store: &Arc<Store>,
    input: &EventListFilterInput,
) -> anyhow::Result<EventFilter> {
    let customers = if let Some(customers_input) = input.customers.as_deref() {
        let map = store.customer_map();
        Some(convert_customer_input(&map, customers_input)?)
    } else {
        None
    };

    let networks = if let Some(endpoints_input) = &input.endpoints {
        let map = store.network_map();
        Some(convert_endpoint_input(&map, endpoints_input)?)
    } else {
        None
    };

    let directions = if let Some(directions) = &input.directions {
        let map = store.customer_map();
        Some((directions.clone(), internal_customer_networks(&map)?))
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
            categories.push(EventCategory::try_from(*category).map_err(|e| anyhow!(e))?);
        }
        Some(categories)
    } else {
        None
    };

    let levels = if let Some(levels_input) = &input.levels {
        let mut levels = Vec::with_capacity(levels_input.len());
        for level in levels_input {
            levels.push(NonZeroU8::new(*level).ok_or_else(|| anyhow!("invalid level"))?);
        }
        Some(levels)
    } else {
        None
    };

    let kinds = if let Some(kinds_input) = &input.kinds {
        let mut kinds = Vec::with_capacity(kinds_input.len());
        for kind in kinds_input {
            kinds.push(kind.as_str().to_lowercase());
        }
        Some(kinds)
    } else {
        None
    };

    let sensors = if let Some(sensors_input) = &input.sensors {
        let map = store.node_map();
        Some(convert_sensors(&map, sensors_input)?)
    } else {
        None
    };

    let triage_policies = if let Some(triage_policies) = &input.triage_policies {
        let map = store.triage_policy_map();
        Some(convert_triage_input(&map, triage_policies)?)
    } else {
        None
    };

    Ok(EventFilter::new(
        customers,
        networks,
        directions
            .map(|(kinds, group)| (kinds.into_iter().map(Into::into).collect::<Vec<_>>(), group)),
        source,
        destination,
        countries,
        categories,
        levels,
        kinds,
        input
            .learning_methods
            .as_ref()
            .map(|v| v.iter().map(|v| (*v).into()).collect()),
        sensors,
        input.confidence,
        triage_policies,
    ))
}

fn convert_customer_input(
    map: &IndexedMap,
    customer_ids: &[ID],
) -> anyhow::Result<Vec<database::Customer>> {
    let codec = bincode::DefaultOptions::new();
    let mut customers = Vec::with_capacity(customer_ids.len());
    for id in customer_ids {
        let i = id
            .as_str()
            .parse::<u32>()
            .context(format!("invalid ID: {}", id.as_str()))?;
        let Some(value) = map.get_by_id(i)? else {
            bail!("no such customer")
        };
        customers.push(
            codec
                .deserialize(value.as_ref())
                .context("invalid value in database")?,
        );
    }
    Ok(customers)
}

fn convert_endpoint_input(
    network_map: &IndexedMultimap,
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
            let Some((key, value)) = network_map.get_kv_by_id(i)? else {
                bail!("no such network")
            };
            networks.push(Endpoint {
                direction: endpoint.direction.map(Into::into),
                network: database::Network::from_key_value(key.as_ref(), value.as_ref())
                    .context("invalid value in database")?
                    .networks,
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

fn internal_customer_networks(map: &IndexedMap) -> anyhow::Result<Vec<HostNetworkGroup>> {
    let mut customer_networks = Vec::new();
    let codec = bincode::DefaultOptions::new();
    for (_, value) in map.iter_forward()? {
        let customer: database::Customer = codec
            .deserialize(value.as_ref())
            .context("invalid customer in database")?;
        for network in customer.networks {
            if network.network_type == database::NetworkType::Intranet
                || network.network_type == database::NetworkType::Gateway
            {
                customer_networks.push(network.network_group);
            }
        }
    }
    Ok(customer_networks)
}

fn convert_sensors(map: &IndexedMap, sensors: &[ID]) -> anyhow::Result<Vec<String>> {
    let codec = bincode::DefaultOptions::new();
    let mut converted_sensors: Vec<String> = Vec::with_capacity(sensors.len());
    for id in sensors {
        let i = id
            .as_str()
            .parse::<u32>()
            .context(format!("invalid ID: {}", id.as_str()))?;
        let Some(value) = map.get_by_id(i)? else {
            bail!("no such sensor")
        };
        let value: super::node::Node = codec
            .deserialize(value.as_ref())
            .context("invalid value in database")?;

        converted_sensors.push(value.hostname.clone());
    }
    Ok(converted_sensors)
}

fn convert_triage_input(
    map: &IndexedMap,
    triage_policy_ids: &[ID],
) -> anyhow::Result<Vec<database::TriagePolicy>> {
    let codec = bincode::DefaultOptions::new();
    let mut triage_policies = Vec::with_capacity(triage_policy_ids.len());
    for id in triage_policy_ids {
        let i = id
            .as_str()
            .parse::<u32>()
            .context(format!("invalid ID: {}", id.as_str()))?;
        let Some(value) = map.get_by_id(i)? else {
            bail!("no such customer")
        };
        triage_policies.push(
            codec
                .deserialize(value.as_ref())
                .context("invalid value in database")?,
        );
    }
    Ok(triage_policies)
}

fn load(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Event, EventTotalCount, EmptyFields>> {
    let store = ctx.data::<Arc<Store>>()?;
    let start = filter.start;
    let end = filter.end;
    let mut filter = from_filter_input(store, filter)?;
    filter.moderate_kinds();
    let db = store.events();
    let (events, has_previous, has_next) = if let Some(last) = last {
        let iter = db.iter_from(latest(end, before)?, Direction::Reverse);
        let to = earliest(start, after)?;
        let (events, has_more) = iter_to_events(ctx, iter, to, cmp::Ordering::is_ge, last, &filter)
            .map_err(|e| format!("{e}"))?;
        (events.into_iter().rev().collect(), has_more, false)
    } else {
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let iter = db.iter_from(earliest(start, after)?, Direction::Forward);
        let to = latest(end, before)?;
        let (events, has_more) =
            iter_to_events(ctx, iter, to, cmp::Ordering::is_le, first, &filter)
                .map_err(|e| format!("{e}"))?;
        (events, false, has_more)
    };

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        EventTotalCount { start, end, filter },
    );
    connection.edges.extend(
        events
            .into_iter()
            .map(|(k, ev)| Edge::new(k.to_string(), ev)),
    );
    Ok(connection)
}

fn earliest(start: Option<DateTime<Utc>>, after: Option<String>) -> Result<i128> {
    let earliest = if let Some(start) = start {
        let start = i128::from(start.timestamp_nanos()) << 64;
        if let Some(after) = after {
            cmp::max(start, earliest_after(&after)?)
        } else {
            start
        }
    } else if let Some(after) = after {
        earliest_after(&after)?
    } else {
        0
    };
    Ok(earliest)
}

fn latest(end: Option<DateTime<Utc>>, before: Option<String>) -> Result<i128> {
    let latest = if let Some(end) = end {
        let end = i128::from(end.timestamp_nanos()) << 64;
        if end == 0 {
            return Err("invalid time `end`".into());
        }
        let end = end - 1;
        if let Some(before) = before {
            cmp::min(end, latest_before(&before)?)
        } else {
            end
        }
    } else if let Some(before) = before {
        latest_before(&before)?
    } else {
        i128::MAX
    };
    Ok(latest)
}

fn earliest_after(after: &str) -> Result<i128> {
    let after = after
        .parse::<i128>()
        .map_err(|_| "invalid cursor `after`")?;
    if after == i128::MAX {
        return Err("invalid cursor `after`".into());
    }
    Ok(after + 1)
}

fn latest_before(before: &str) -> Result<i128> {
    let before = before
        .parse::<i128>()
        .map_err(|_| "invalid cursor `before`")?;
    if before == 0 {
        return Err("invalid cursor `before`".into());
    }
    Ok(before - 1)
}

fn iter_to_events(
    ctx: &Context<'_>,
    iter: EventIterator,
    to: i128,
    cond: fn(cmp::Ordering) -> bool,
    len: usize,
    filter: &EventFilter,
) -> anyhow::Result<(Vec<(i128, Event)>, bool)> {
    let mut events = Vec::new();
    let mut exceeded = false;
    let locator = if filter.has_country() {
        if let Ok(mutex) = ctx.data::<Arc<Mutex<ip2location::DB>>>() {
            Some(Arc::clone(mutex))
        } else {
            bail!("unable to locate IP address");
        }
    } else {
        None
    };

    for item in iter {
        let (key, mut event) = match item {
            Ok(kv) => kv,
            Err(e) => {
                warn!("invalid event: {:?}", e);
                continue;
            }
        };
        if !(cond)(key.cmp(&to)) {
            break;
        }
        let triage_score = {
            let matches = event.matches(locator.clone(), filter)?;
            if !matches.0 {
                continue;
            }
            matches.1
        };
        if let Some(triage_score) = triage_score {
            event.set_triage_scores(triage_score);
        }
        events.push((key, event.into()));
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

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;
    use chrono::{DateTime, NaiveDate, Utc};
    use review_database::{event::DnsEventFields, EventKind, EventMessage};
    use std::net::Ipv4Addr;

    /// Creates an event message at `timestamp` with the given source and
    /// destination `IPv4` addresses.
    fn event_message_at(timestamp: DateTime<Utc>, src: u32, dst: u32) -> EventMessage {
        let fields = DnsEventFields {
            source: "collector1".to_string(),
            session_end_time: timestamp,
            src_addr: Ipv4Addr::from(src).into(),
            src_port: 10000,
            dst_addr: Ipv4Addr::from(dst).into(),
            dst_port: 53,
            proto: 17,
            query: "domain".into(),
            answer: Vec::new(),
            trans_id: 0,
            rtt: 0,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: Vec::new(),
            confidence: 0.8,
        };
        EventMessage {
            time: timestamp,
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    #[tokio::test]
    async fn event_list() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                "{eventList(filter: {}){edges{node{... on DnsCovertChannel{query}}}totalCount}}",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            "{eventList: {edges: [],totalCount: 0}}"
        );

        let db = schema.event_database();
        let ts1 = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts1, 1, 2)).unwrap();
        let ts2 = NaiveDate::from_ymd_opt(2018, 1, 27)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts2, 3, 4)).unwrap();
        let ts3 = NaiveDate::from_ymd_opt(2018, 1, 28)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts3, 5, 6)).unwrap();
        let query = format!(
            "{{ \
                eventList(filter: {{ start:\"{}\", end:\"{}\" }}) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ time }} }} }} \
                    totalCount \
                }} \
            }}",
            ts2, ts3
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829+00:00"}}],totalCount: 1}}"#
        );
    }

    #[tokio::test]
    async fn total_count() {
        let timestamps: Vec<_> = [
            (2018, 1, 26, 18, 30, 9, 453_829),
            (2018, 1, 27, 18, 30, 9, 453_829),
            (2018, 1, 28, 18, 30, 9, 453_829),
        ]
        .into_iter()
        .map(|(y, m, d, h, min, s, micro)| {
            NaiveDate::from_ymd_opt(y, m, d)
                .unwrap()
                .and_hms_micro_opt(h, min, s, micro)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
        })
        .collect();
        let src_dst: Vec<_> = vec![(1, 2), (3, 1), (2, 3)];
        let schema = TestSchema::new().await;
        let db = schema.event_database();
        timestamps
            .iter()
            .zip(src_dst.into_iter())
            .for_each(|(ts, (src, dst))| {
                db.put(&event_message_at(*ts, src, dst)).unwrap();
            });

        let _ = schema
            .execute(
                r#"mutation {
                    insertCustomer(
                        name: "c0",
                        description: "",
                        networks: [
                            {
                                name: "n0",
                                description: "",
                                networkType: INTRANET,
                                networkGroup: {
                                    hosts: ["0.0.0.1"],
                                    networks: [],
                                    ranges: []
                                }
                            }
                        ])
                }"#,
            )
            .await;
        let query = format!(
            "{{ \
                        eventList(filter: {{ start:\"{}\", end:\"{}\", customers: [0], }}) {{ \
                            edges {{ node {{... on DnsCovertChannel {{ time }} }} }} \
                            totalCount \
                        }} \
                    }}",
            timestamps[0], timestamps[2]
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {time: "2018-01-26T18:30:09.453829+00:00"}},{node: {time: "2018-01-27T18:30:09.453829+00:00"}}],totalCount: 2}}"#
        );
        let query = format!(
            "{{ \
                    eventList(filter: {{ start:\"{}\", end:\"{}\", customers: [0], }}) {{ \
                        edges {{ node {{... on DnsCovertChannel {{ time }} }} }} \
                        totalCount \
                    }} \
                }}",
            timestamps[1], timestamps[2]
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829+00:00"}}],totalCount: 1}}"#
        );
    }

    #[tokio::test]
    async fn filter_by_customer() {
        let schema = TestSchema::new().await;
        let db = schema.event_database();
        let ts1 = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts1, 1, 2)).unwrap();
        let ts2 = NaiveDate::from_ymd_opt(2018, 1, 27)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts2, 3, 4)).unwrap();
        let ts3 = NaiveDate::from_ymd_opt(2018, 1, 28)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        let res = schema
            .execute(
                r#"mutation {
                    insertCustomer(
                        name: "c0",
                        description: "",
                        networks: [
                            {
                                name: "n0",
                                description: "",
                                networkType: INTRANET,
                                networkGroup: {
                                    hosts: ["0.0.0.1"],
                                    networks: [],
                                    ranges: []
                                }
                            }
                        ])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);
        let query = format!(
            "{{ \
                eventList(filter: {{ start:\"{}\", end:\"{}\", customers: [0] }}) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ srcAddr }} }} }} \
                }} \
            }}",
            ts1, ts3
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {srcAddr: "0.0.0.1"}}]}}"#
        );
    }

    #[tokio::test]
    async fn filter_by_direction() {
        let schema = TestSchema::new().await;
        let db = schema.event_database();
        let ts1 = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts1, 1, 2)).unwrap();
        let ts2 = NaiveDate::from_ymd_opt(2018, 1, 27)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts2, 3, 4)).unwrap();
        let ts3 = NaiveDate::from_ymd_opt(2018, 1, 28)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        let res = schema
            .execute(
                r#"mutation {
                    insertCustomer(
                        name: "c0",
                        description: "",
                        networks: [
                            {
                                name: "n0",
                                description: "",
                                networkType: INTRANET,
                                networkGroup: {
                                    hosts: ["0.0.0.1"],
                                    networks: [],
                                    ranges: []
                                }
                            }
                        ])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);
        let query = format!(
            "{{ \
                eventList(filter: {{
                    start:\"{}\",
                    end:\"{}\",
                    directions: [\"OUTBOUND\"],
                }}) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ srcAddr }} }} }} \
                }} \
            }}",
            ts1, ts3
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {srcAddr: "0.0.0.1"}}]}}"#
        );
    }

    #[tokio::test]
    async fn filter_by_network() {
        let schema = TestSchema::new().await;
        let db = schema.event_database();
        let ts1 = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts1, 1, 2)).unwrap();
        let ts2 = NaiveDate::from_ymd_opt(2018, 1, 27)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts2, 3, 4)).unwrap();
        let ts3 = NaiveDate::from_ymd_opt(2018, 1, 28)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        let res = schema
            .execute(
                r#"mutation {
                    insertNetwork(
                        name: "n0",
                        description: "",
                        networks: {
                            hosts: ["0.0.0.4"],
                            networks: [],
                            ranges: []
                        },
                        customerIds: [],
                        tagIds: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);
        let query = format!(
            "{{ \
                eventList(filter: {{
                    start:\"{}\",
                    end:\"{}\",
                    endpoints: [{{predefined: \"0\"}}]
                }}) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ srcAddr }} }} }} \
                }} \
            }}",
            ts1, ts3
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {srcAddr: "0.0.0.3"}}]}}"#
        );
    }
}
