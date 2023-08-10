mod conn;
mod dns;
mod ftp;
mod group;
mod http;
mod ldap;
mod rdp;

pub(super) use self::group::EventGroupQuery;
use self::{
    conn::BlockListConn, conn::ExternalDdos, conn::MultiHostPortScan, conn::PortScan,
    dns::BlockListDns, dns::CryptocurrencyMiningPool, dns::DnsCovertChannel, ftp::FtpBruteForce,
    ftp::FtpPlainText, http::DomainGenerationAlgorithm, http::HttpThreat, http::NonBrowser,
    http::RepeatedHttpSessions, http::TorConnection, ldap::LdapBruteForce, ldap::LdapPlainText,
    rdp::RdpBruteForce,
};
use super::{
    customer::{Customer, HostNetworkGroupInput},
    filter::{FlowKind, LearningMethod, TrafficDirection},
    network::Network,
    Role, RoleGuard,
};
use anyhow::{anyhow, bail, Context as AnyhowContext};
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    Context, InputObject, Object, Result, Subscription, Union, ID,
};
use bincode::Options;
use chrono::{DateTime, Utc};
use futures::channel::mpsc::{unbounded, UnboundedSender};
use futures_util::stream::Stream;
use num_traits::FromPrimitive;
use review_database::{
    self as database,
    event::RecordType,
    find_ip_country,
    types::{Endpoint, EventCategory, FromKeyValue, HostNetworkGroup},
    Direction, EventFilter, EventIterator, EventKind, IndexedMap, IndexedMultimap, IterableMap,
    Store,
};
use std::{
    cmp,
    net::IpAddr,
    num::NonZeroU8,
    sync::{Arc, Mutex},
};
use tokio::time;
use tracing::{error, warn};

const DEFAULT_CONNECTION_SIZE: usize = 100;
const DEFAULT_EVENT_FETCH_TIME: u64 = 20;
const ADD_TIME_FOR_NEXT_COMPARE: i64 = 1;

#[derive(Default)]
pub(super) struct EventStream;

#[derive(Default)]
pub(super) struct EventQuery;

#[Subscription]
impl EventStream {
    /// A stream of events with timestamp on.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_stream(
        &self,
        ctx: &Context<'_>,
        start: DateTime<Utc>,
        fetch_interval: Option<u64>,
    ) -> Result<impl Stream<Item = Event>> {
        use tokio::sync::RwLock;
        let store = ctx.data::<Arc<RwLock<Store>>>()?.clone();
        let fetch_time = if let Some(fetch_time) = fetch_interval {
            fetch_time
        } else {
            DEFAULT_EVENT_FETCH_TIME
        };
        let (tx, rx) = unbounded();
        tokio::spawn(async move {
            let store = store.read().await;

            if let Err(e) = fetch_events(&store, start.timestamp_nanos(), tx, fetch_time).await {
                error!("{e:?}");
            }
        });
        Ok(rx)
    }
}

#[allow(clippy::too_many_lines)]
async fn fetch_events(
    db: &Store,
    start_time: i64,
    tx: UnboundedSender<Event>,
    fecth_time: u64,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(fecth_time));
    let mut dns_covert_time = start_time;
    let mut http_threat_time = start_time;
    let mut rdp_brute_time = start_time;
    let mut repeat_http_time = start_time;
    let mut tor_time = start_time;
    let mut dga_time = start_time;
    let mut ftp_brute_time = start_time;
    let mut ftp_plain_time = start_time;
    let mut port_scan_time = start_time;
    let mut multi_host_time = start_time;
    let mut ldap_brute_time = start_time;
    let mut ldap_plain_time = start_time;
    let mut non_browser_time = start_time;
    let mut external_ddos_time = start_time;
    let mut cryptocurrency_time = start_time;
    let mut block_list_conn_time = start_time;
    let mut block_list_dns_time = start_time;

    loop {
        itv.tick().await;

        // Select the minimum time for DB search
        let start = dns_covert_time.min(
            http_threat_time.min(
                rdp_brute_time.min(
                    repeat_http_time.min(
                        tor_time.min(
                            dga_time.min(
                                ftp_brute_time.min(
                                    ftp_plain_time.min(
                                        port_scan_time.min(
                                            multi_host_time.min(
                                                ldap_brute_time.min(
                                                    ldap_plain_time.min(
                                                        non_browser_time.min(
                                                            external_ddos_time
                                                                .min(cryptocurrency_time)
                                                                .min(block_list_conn_time)
                                                                .min(block_list_dns_time),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        );

        // Fetch event iterator based on time
        let start = i128::from(start) << 64;
        let events = db.events();
        let iter = events.iter_from(start, Direction::Forward);

        // Check for new data per event and send events that meet the conditions
        for event in iter {
            let (key, value) = event.map_err(|e| format!("Failed to read EventDb: {e:?}"))?;
            let event_time = i64::try_from(key >> 64)?;
            let kind = (key & 0xffff_ffff_0000_0000) >> 32;
            let Some(event_kind) = EventKind::from_i128(kind) else {
                return Err(anyhow!("Failed to convert event_kind: Invalid Event key").into());
            };

            match event_kind {
                EventKind::DnsCovertChannel => {
                    if event_time >= dns_covert_time {
                        tx.unbounded_send(value.into())?;
                        dns_covert_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::HttpThreat => {
                    if event_time >= http_threat_time {
                        tx.unbounded_send(value.into())?;
                        http_threat_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::RdpBruteForce => {
                    if event_time >= rdp_brute_time {
                        tx.unbounded_send(value.into())?;
                        rdp_brute_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::RepeatedHttpSessions => {
                    if event_time >= repeat_http_time {
                        tx.unbounded_send(value.into())?;
                        repeat_http_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::TorConnection => {
                    if event_time >= tor_time {
                        tx.unbounded_send(value.into())?;
                        tor_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::DomainGenerationAlgorithm => {
                    if event_time >= dga_time {
                        tx.unbounded_send(value.into())?;
                        dga_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::FtpBruteForce => {
                    if event_time >= ftp_brute_time {
                        tx.unbounded_send(value.into())?;
                        ftp_brute_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::FtpPlainText => {
                    if event_time >= ftp_plain_time {
                        tx.unbounded_send(value.into())?;
                        ftp_plain_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::PortScan => {
                    if event_time >= port_scan_time {
                        tx.unbounded_send(value.into())?;
                        port_scan_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::MultiHostPortScan => {
                    if event_time >= multi_host_time {
                        tx.unbounded_send(value.into())?;
                        multi_host_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::NonBrowser => {
                    if event_time >= non_browser_time {
                        tx.unbounded_send(value.into())?;
                        non_browser_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::LdapBruteForce => {
                    if event_time >= ldap_brute_time {
                        tx.unbounded_send(value.into())?;
                        ldap_brute_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::LdapPlainText => {
                    if event_time >= ldap_plain_time {
                        tx.unbounded_send(value.into())?;
                        ldap_plain_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::ExternalDdos => {
                    if event_time >= external_ddos_time {
                        tx.unbounded_send(value.into())?;
                        external_ddos_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::CryptocurrencyMiningPool => {
                    if event_time >= cryptocurrency_time {
                        tx.unbounded_send(value.into())?;
                        cryptocurrency_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlockListConn => {
                    if event_time >= block_list_conn_time {
                        tx.unbounded_send(value.into())?;
                        block_list_conn_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlockListDns => {
                    if event_time >= block_list_dns_time {
                        tx.unbounded_send(value.into())?;
                        block_list_dns_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::Log => continue,
            }
        }
    }
}

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
                load(ctx, &filter, after, before, first, last).await
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

    /// Brute force attacks against FTP.
    FtpBruteForce(FtpBruteForce),

    /// Plain text password is used for the FTP connection.
    FtpPlainText(FtpPlainText),

    /// Large number of connection attempts are made to multiple ports
    /// on the same destination from the same source.
    PortScan(PortScan),

    /// Specific host inside attempts to connect to a specific port on multiple host inside.
    MultiHostPortScan(MultiHostPortScan),

    /// multiple internal host attempt a DDOS attack against a specific external host.
    ExternalDdos(ExternalDdos),

    /// Non-browser user agent detected in HTTP request message.
    NonBrowser(NonBrowser),

    /// Brute force attacks against LDAP.
    LdapBruteForce(LdapBruteForce),

    /// Plain text password is used for the LDAP connection.
    LdapPlainText(LdapPlainText),

    /// An event that occurs when it is determined that there is a connection to a cryptocurrency mining network
    CryptocurrencyMiningPool(CryptocurrencyMiningPool),

    BlockListConn(BlockListConn),

    BlockListDns(BlockListDns),
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
            database::Event::FtpBruteForce(event) => Event::FtpBruteForce(event.into()),
            database::Event::FtpPlainText(event) => Event::FtpPlainText(event.into()),
            database::Event::PortScan(event) => Event::PortScan(event.into()),
            database::Event::MultiHostPortScan(event) => Event::MultiHostPortScan(event.into()),
            database::Event::ExternalDdos(event) => Event::ExternalDdos(event.into()),
            database::Event::NonBrowser(event) => Event::NonBrowser(event.into()),
            database::Event::LdapBruteForce(event) => Event::LdapBruteForce(event.into()),
            database::Event::LdapPlainText(event) => Event::LdapPlainText(event.into()),
            database::Event::CryptocurrencyMiningPool(event) => {
                Event::CryptocurrencyMiningPool(event.into())
            }
            database::Event::BlockList(record_type) => match record_type {
                RecordType::Conn(event) => Event::BlockListConn(event.into()),
                RecordType::Dns(event) => Event::BlockListDns(event.into()),
            },
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

struct EventTotalCount {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    filter: EventFilter,
}

#[Object]
impl EventTotalCount {
    /// The total number of events.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        let events = store.events();
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
fn from_filter_input(store: &Store, input: &EventListFilterInput) -> anyhow::Result<EventFilter> {
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

async fn load(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Event, EventTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;

    let start = filter.start;
    let end = filter.end;
    let mut filter = from_filter_input(&store, filter)?;
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
    use futures_util::StreamExt;
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

        let store = schema.store().await;
        let db = store.events();
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
        let store = schema.store().await;
        let db = store.events();
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
        let store = schema.store().await;
        let db = store.events();
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
        let store = schema.store().await;
        let db = store.events();
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
        let store = schema.store().await;
        let db = store.events();
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

    #[tokio::test]
    async fn event_stream() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let db = store.events();
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
        let query = r#"
        subscription {
            eventStream(start:"2018-01-28T00:00:00.000000000Z"){
              __typename
              ... on DnsCovertChannel{
                srcAddr,
              }
            }
        }
        "#;
        let mut stream = schema.execute_stream(&query).await;
        let res = stream.next().await;
        assert_eq!(
            res.unwrap().data.to_string(),
            r#"{eventStream: {__typename: "DnsCovertChannel",srcAddr: "0.0.0.5"}}"#
        );
    }
}
