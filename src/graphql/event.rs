mod bootp;
mod conn;
mod dcerpc;
mod dhcp;
mod dns;
mod ftp;
mod group;
mod http;
mod kerberos;
mod ldap;
mod log;
mod mqtt;
mod network;
mod nfs;
mod ntlm;
mod rdp;
mod smb;
mod smtp;
mod ssh;
mod sysmon;
mod tls;

use std::{cmp, net::IpAddr, num::NonZeroU8, sync::Arc};

use anyhow::{Context as AnyhowContext, anyhow, bail};
use async_graphql::{
    Context, Enum, ID, InputObject, Interface, Object, Result, Subscription,
    connection::{Connection, Edge, EmptyFields},
};
use chrono::{DateTime, Utc};
use futures::channel::mpsc::{UnboundedSender, unbounded};
use futures_util::stream::Stream;
use num_traits::FromPrimitive;
use review_database::{
    self as database, AgentKind, EventKind, IndexedTable, Iterable, Store,
    event::{Direction, EventFilter, EventIterator, RecordType},
    find_ip_country,
    types::{Endpoint, EventCategory, HostNetworkGroup},
};
use tokio::time;
use tracing::{error, warn};

pub(super) use self::group::EventGroupQuery;
use self::{
    bootp::BlocklistBootp,
    conn::{BlocklistConn, ExternalDdos, MultiHostPortScan, PortScan, TorConnectionConn},
    dcerpc::BlocklistDceRpc,
    dhcp::BlocklistDhcp,
    dns::{BlocklistDns, CryptocurrencyMiningPool, DnsCovertChannel, LockyRansomware},
    ftp::{BlocklistFtp, FtpBruteForce, FtpPlainText},
    http::{
        BlocklistHttp, DomainGenerationAlgorithm, HttpThreat, NonBrowser, RepeatedHttpSessions,
        TorConnection,
    },
    kerberos::BlocklistKerberos,
    ldap::{BlocklistLdap, LdapBruteForce, LdapPlainText},
    log::ExtraThreat,
    mqtt::BlocklistMqtt,
    network::NetworkThreat,
    nfs::BlocklistNfs,
    ntlm::BlocklistNtlm,
    rdp::{BlocklistRdp, RdpBruteForce},
    smb::BlocklistSmb,
    smtp::BlocklistSmtp,
    ssh::BlocklistSsh,
    sysmon::WindowsThreat,
    tls::{BlocklistTls, SuspiciousTlsTraffic},
};
use super::{
    Role, RoleGuard,
    customer::{Customer, HostNetworkGroupInput},
    filter::{FlowKind, LearningMethod, TrafficDirection},
    network::Network,
    triage::ThreatCategory,
};
use crate::{error_with_username, graphql::query, warn_with_username};

const DEFAULT_CONNECTION_SIZE: usize = 100;
const DEFAULT_EVENT_FETCH_TIME: u64 = 20;
const ADD_TIME_FOR_NEXT_COMPARE: i64 = 1;

/// Threat level.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
pub(super) enum ThreatLevel {
    Low,
    Medium,
}

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
        event_stuck_check_interval: Option<u64>,
    ) -> Result<impl Stream<Item = Event> + use<>> {
        use tokio::sync::RwLock;
        let store = ctx.data::<Arc<RwLock<Store>>>()?.clone();
        let fetch_time = if let Some(fetch_time) = fetch_interval {
            fetch_time
        } else {
            DEFAULT_EVENT_FETCH_TIME
        };
        let username = ctx
            .data::<String>()
            .cloned()
            .unwrap_or("<unknown user>".to_string());
        let (tx, rx) = unbounded();
        tokio::spawn(async move {
            let store = store.read().await;
            let fetch = fetch_events(
                &store,
                start.timestamp_nanos_opt().unwrap_or_default(),
                tx,
                fetch_time,
                event_stuck_check_interval,
            )
            .await;
            if let Err(e) = fetch {
                error_with_username!(username: username, "Failed to fetch events: {e:?}");
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
    event_stuck_check_interval: Option<u64>,
) -> Result<()> {
    let mut itv = time::interval(time::Duration::from_secs(fecth_time));
    let mut iter_time_key = start_time;
    let stuck_check_interval = event_stuck_check_interval.unwrap_or(300); // Default 5 minutes in seconds
    let mut last_stuck_check = std::time::Instant::now();
    let mut dns_covert_time = start_time;
    let mut http_threat_time = start_time;
    let mut rdp_brute_time = start_time;
    let mut repeat_http_time = start_time;
    let mut tor_time = start_time;
    let mut tor_connection_conn_time = start_time;
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
    let mut blocklist_bootp_time = start_time;
    let mut blocklist_conn_time = start_time;
    let mut blocklist_dhcp_time = start_time;
    let mut blocklist_dns_time = start_time;
    let mut blocklist_dcerpc_time = start_time;
    let mut blocklist_ftp_time = start_time;
    let mut blocklist_http_time = start_time;
    let mut blocklist_kerberos_time = start_time;
    let mut blocklist_ldap_time = start_time;
    let mut blocklist_mqtt_time = start_time;
    let mut blocklist_nfs_time = start_time;
    let mut blocklist_ntlm_time = start_time;
    let mut blocklist_rdp_time = start_time;
    let mut blocklist_smb_time = start_time;
    let mut blocklist_smtp_time = start_time;
    let mut blocklist_ssh_time = start_time;
    let mut blocklist_tls_time = start_time;
    let mut windows_threat_time = start_time;
    let mut network_threat_time = start_time;
    let mut extra_threat_time = start_time;
    let mut locky_ransomware_time = start_time;
    let mut suspicious_tls_time = start_time;

    loop {
        itv.tick().await;

        // Check if we need to advance stuck event time variables
        if last_stuck_check.elapsed().as_secs() >= stuck_check_interval {
            // Collect all event time variables
            let event_times = vec![
                dns_covert_time,
                http_threat_time,
                rdp_brute_time,
                repeat_http_time,
                tor_time,
                tor_connection_conn_time,
                dga_time,
                ftp_brute_time,
                ftp_plain_time,
                port_scan_time,
                multi_host_time,
                ldap_brute_time,
                ldap_plain_time,
                non_browser_time,
                external_ddos_time,
                cryptocurrency_time,
                blocklist_bootp_time,
                blocklist_conn_time,
                blocklist_dhcp_time,
                blocklist_dns_time,
                blocklist_dcerpc_time,
                blocklist_ftp_time,
                blocklist_http_time,
                blocklist_kerberos_time,
                blocklist_ldap_time,
                blocklist_mqtt_time,
                blocklist_nfs_time,
                blocklist_ntlm_time,
                blocklist_rdp_time,
                blocklist_smb_time,
                blocklist_smtp_time,
                blocklist_ssh_time,
                blocklist_tls_time,
                windows_threat_time,
                network_threat_time,
                extra_threat_time,
                locky_ransomware_time,
                suspicious_tls_time,
            ];

            // Find the minimum time greater than iter_time_key
            if let Some(min_time_key) = event_times
                .iter()
                .filter(|&&time| time > iter_time_key)
                .min()
                .copied()
            {
                // Update any event time variables that are stuck at iter_time_key
                if dns_covert_time == iter_time_key {
                    dns_covert_time = min_time_key;
                }
                if http_threat_time == iter_time_key {
                    http_threat_time = min_time_key;
                }
                if rdp_brute_time == iter_time_key {
                    rdp_brute_time = min_time_key;
                }
                if repeat_http_time == iter_time_key {
                    repeat_http_time = min_time_key;
                }
                if tor_time == iter_time_key {
                    tor_time = min_time_key;
                }
                if tor_connection_conn_time == iter_time_key {
                    tor_connection_conn_time = min_time_key;
                }
                if dga_time == iter_time_key {
                    dga_time = min_time_key;
                }
                if ftp_brute_time == iter_time_key {
                    ftp_brute_time = min_time_key;
                }
                if ftp_plain_time == iter_time_key {
                    ftp_plain_time = min_time_key;
                }
                if port_scan_time == iter_time_key {
                    port_scan_time = min_time_key;
                }
                if multi_host_time == iter_time_key {
                    multi_host_time = min_time_key;
                }
                if ldap_brute_time == iter_time_key {
                    ldap_brute_time = min_time_key;
                }
                if ldap_plain_time == iter_time_key {
                    ldap_plain_time = min_time_key;
                }
                if non_browser_time == iter_time_key {
                    non_browser_time = min_time_key;
                }
                if external_ddos_time == iter_time_key {
                    external_ddos_time = min_time_key;
                }
                if cryptocurrency_time == iter_time_key {
                    cryptocurrency_time = min_time_key;
                }
                if blocklist_bootp_time == iter_time_key {
                    blocklist_bootp_time = min_time_key;
                }
                if blocklist_conn_time == iter_time_key {
                    blocklist_conn_time = min_time_key;
                }
                if blocklist_dhcp_time == iter_time_key {
                    blocklist_dhcp_time = min_time_key;
                }
                if blocklist_dns_time == iter_time_key {
                    blocklist_dns_time = min_time_key;
                }
                if blocklist_dcerpc_time == iter_time_key {
                    blocklist_dcerpc_time = min_time_key;
                }
                if blocklist_ftp_time == iter_time_key {
                    blocklist_ftp_time = min_time_key;
                }
                if blocklist_http_time == iter_time_key {
                    blocklist_http_time = min_time_key;
                }
                if blocklist_kerberos_time == iter_time_key {
                    blocklist_kerberos_time = min_time_key;
                }
                if blocklist_ldap_time == iter_time_key {
                    blocklist_ldap_time = min_time_key;
                }
                if blocklist_mqtt_time == iter_time_key {
                    blocklist_mqtt_time = min_time_key;
                }
                if blocklist_nfs_time == iter_time_key {
                    blocklist_nfs_time = min_time_key;
                }
                if blocklist_ntlm_time == iter_time_key {
                    blocklist_ntlm_time = min_time_key;
                }
                if blocklist_rdp_time == iter_time_key {
                    blocklist_rdp_time = min_time_key;
                }
                if blocklist_smb_time == iter_time_key {
                    blocklist_smb_time = min_time_key;
                }
                if blocklist_smtp_time == iter_time_key {
                    blocklist_smtp_time = min_time_key;
                }
                if blocklist_ssh_time == iter_time_key {
                    blocklist_ssh_time = min_time_key;
                }
                if blocklist_tls_time == iter_time_key {
                    blocklist_tls_time = min_time_key;
                }
                if windows_threat_time == iter_time_key {
                    windows_threat_time = min_time_key;
                }
                if network_threat_time == iter_time_key {
                    network_threat_time = min_time_key;
                }
                if extra_threat_time == iter_time_key {
                    extra_threat_time = min_time_key;
                }
                if locky_ransomware_time == iter_time_key {
                    locky_ransomware_time = min_time_key;
                }
                if suspicious_tls_time == iter_time_key {
                    suspicious_tls_time = min_time_key;
                }

                // Update iter_time_key to the new minimum time
                iter_time_key = min_time_key;
            }

            last_stuck_check = std::time::Instant::now();
        }

        // Select the minimum time for DB search
        let start = dns_covert_time
            .min(http_threat_time)
            .min(rdp_brute_time)
            .min(repeat_http_time)
            .min(tor_time)
            .min(tor_connection_conn_time)
            .min(dga_time)
            .min(ftp_brute_time)
            .min(ftp_plain_time)
            .min(port_scan_time)
            .min(multi_host_time)
            .min(ldap_brute_time)
            .min(ldap_plain_time)
            .min(non_browser_time)
            .min(external_ddos_time)
            .min(cryptocurrency_time)
            .min(blocklist_bootp_time)
            .min(blocklist_conn_time)
            .min(blocklist_dhcp_time)
            .min(blocklist_dns_time)
            .min(blocklist_dcerpc_time)
            .min(blocklist_ftp_time)
            .min(blocklist_http_time)
            .min(blocklist_kerberos_time)
            .min(blocklist_ldap_time)
            .min(blocklist_mqtt_time)
            .min(blocklist_nfs_time)
            .min(blocklist_ntlm_time)
            .min(blocklist_rdp_time)
            .min(blocklist_smb_time)
            .min(blocklist_smtp_time)
            .min(blocklist_ssh_time)
            .min(blocklist_tls_time)
            .min(windows_threat_time)
            .min(network_threat_time)
            .min(extra_threat_time)
            .min(locky_ransomware_time)
            .min(suspicious_tls_time);

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
                EventKind::TorConnectionConn => {
                    if event_time >= tor_connection_conn_time {
                        tx.unbounded_send(value.into())?;
                        tor_connection_conn_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
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
                EventKind::BlocklistBootp => {
                    if event_time >= blocklist_bootp_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_bootp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistConn => {
                    if event_time >= blocklist_conn_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_conn_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistDhcp => {
                    if event_time >= blocklist_dhcp_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_dhcp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistDns => {
                    if event_time >= blocklist_dns_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_dns_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistDceRpc => {
                    if event_time >= blocklist_dcerpc_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_dcerpc_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistFtp => {
                    if event_time >= blocklist_ftp_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_ftp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistHttp => {
                    if event_time >= blocklist_http_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_http_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistKerberos => {
                    if event_time >= blocklist_kerberos_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_kerberos_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistLdap => {
                    if event_time >= blocklist_ldap_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_ldap_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistMqtt => {
                    if event_time >= blocklist_mqtt_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_mqtt_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistNfs => {
                    if event_time >= blocklist_nfs_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_nfs_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistNtlm => {
                    if event_time >= blocklist_ntlm_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_ntlm_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistRdp => {
                    if event_time >= blocklist_rdp_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_rdp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistSmb => {
                    if event_time >= blocklist_smb_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_smb_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistSmtp => {
                    if event_time >= blocklist_smtp_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_smtp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistSsh => {
                    if event_time >= blocklist_ssh_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_ssh_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::BlocklistTls => {
                    if event_time >= blocklist_tls_time {
                        tx.unbounded_send(value.into())?;
                        blocklist_tls_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::WindowsThreat => {
                    if event_time >= windows_threat_time {
                        tx.unbounded_send(value.into())?;
                        windows_threat_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::NetworkThreat => {
                    if event_time >= network_threat_time {
                        tx.unbounded_send(value.into())?;
                        network_threat_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::ExtraThreat => {
                    if event_time >= extra_threat_time {
                        tx.unbounded_send(value.into())?;
                        extra_threat_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::LockyRansomware => {
                    if event_time >= locky_ransomware_time {
                        tx.unbounded_send(value.into())?;
                        locky_ransomware_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
                EventKind::SuspiciousTlsTraffic => {
                    if event_time >= suspicious_tls_time {
                        tx.unbounded_send(value.into())?;
                        suspicious_tls_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                    }
                }
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

/// Common interface for all event types.
#[derive(Interface)]
#[graphql(
    field(name = "time", ty = "DateTime<Utc>"),
    field(name = "sensor", ty = "&str"),
    field(name = "confidence", ty = "f32"),
    field(name = "category", ty = "Option<ThreatCategory>"),
    field(name = "level", ty = "ThreatLevel"),
    field(name = "triage_scores", ty = "Option<Vec<TriageScore<'_>>>")
)]
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

    /// A connection-level Tor connection detection.
    TorConnectionConn(TorConnectionConn),

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

    BlocklistConn(BlocklistConn),

    BlocklistDns(BlocklistDns),

    BlocklistDceRpc(BlocklistDceRpc),

    BlocklistFtp(BlocklistFtp),

    BlocklistHttp(BlocklistHttp),

    BlocklistKerberos(BlocklistKerberos),

    BlocklistLdap(BlocklistLdap),

    BlocklistMqtt(BlocklistMqtt),

    BlocklistNfs(BlocklistNfs),

    BlocklistNtlm(BlocklistNtlm),

    BlocklistRdp(BlocklistRdp),

    BlocklistSmb(BlocklistSmb),

    BlocklistSmtp(BlocklistSmtp),

    BlocklistSsh(BlocklistSsh),

    BlocklistTls(BlocklistTls),

    WindowsThreat(WindowsThreat),

    NetworkThreat(NetworkThreat),

    ExtraThreat(ExtraThreat),

    LockyRansomware(LockyRansomware),

    BlocklistBootp(BlocklistBootp),

    BlocklistDhcp(BlocklistDhcp),

    SuspiciousTlsTraffic(SuspiciousTlsTraffic),
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
            database::Event::TorConnectionConn(event) => Event::TorConnectionConn(event.into()),
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
            database::Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(event) => Event::BlocklistBootp(event.into()),
                RecordType::Conn(event) => Event::BlocklistConn(event.into()),
                RecordType::Dhcp(event) => Event::BlocklistDhcp(event.into()),
                RecordType::Dns(event) => Event::BlocklistDns(event.into()),
                RecordType::DceRpc(event) => Event::BlocklistDceRpc(event.into()),
                RecordType::Ftp(event) => Event::BlocklistFtp(event.into()),
                RecordType::Http(event) => Event::BlocklistHttp(event.into()),
                RecordType::Kerberos(event) => Event::BlocklistKerberos(event.into()),
                RecordType::Ldap(event) => Event::BlocklistLdap(event.into()),
                RecordType::Mqtt(event) => Event::BlocklistMqtt(event.into()),
                RecordType::Nfs(event) => Event::BlocklistNfs(event.into()),
                RecordType::Ntlm(event) => Event::BlocklistNtlm(event.into()),
                RecordType::Rdp(event) => Event::BlocklistRdp(event.into()),
                RecordType::Smb(event) => Event::BlocklistSmb(event.into()),
                RecordType::Smtp(event) => Event::BlocklistSmtp(event.into()),
                RecordType::Ssh(event) => Event::BlocklistSsh(event.into()),
                RecordType::Tls(event) => Event::BlocklistTls(event.into()),
            },
            database::Event::WindowsThreat(event) => Event::WindowsThreat(event.into()),
            database::Event::NetworkThreat(event) => Event::NetworkThreat(event.into()),
            database::Event::ExtraThreat(event) => Event::ExtraThreat(event.into()),
            database::Event::LockyRansomware(event) => Event::LockyRansomware(event.into()),
            database::Event::SuspiciousTlsTraffic(event) => {
                Event::SuspiciousTlsTraffic(event.into())
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
    hostnames: Option<Vec<String>>,
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

fn country_code(ctx: &Context<'_>, addr: IpAddr) -> String {
    ctx.data::<ip2location::DB>()
        .map_or_else(|_| "ZZ".to_string(), |l| find_ip_country(l, addr))
}

fn find_ip_customer(
    map: &IndexedTable<database::Customer>,
    addr: IpAddr,
) -> Result<Option<Customer>> {
    for entry in map.iter(Direction::Forward, None) {
        let customer = entry?;
        if customer.networks.iter().any(|n| n.contains(addr)) {
            return Ok(Some(customer.into()));
        }
    }
    Ok(None)
}

fn find_ip_network(map: &IndexedTable<database::Network>, addr: IpAddr) -> Result<Option<Network>> {
    for entry in map.iter(Direction::Forward, None) {
        let network = entry?;
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
            Some(
                ctx.data::<ip2location::DB>()
                    .map_err(|_| "unable to locate IP address")?,
            )
        } else {
            None
        };
        let iter = self.start.map_or_else(
            || events.iter_forward(),
            |start| {
                let start = i128::from(start.timestamp_nanos_opt().unwrap_or_default()) << 64;
                events.iter_from(start, Direction::Forward)
            },
        );
        let last = if let Some(end) = self.end {
            let end = end
                .timestamp_nanos_opt()
                .map_or(i128::MAX, |e| i128::from(e) << 64);
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
                    warn_with_username!(ctx, "Invalid event: {:?}", e);
                    continue;
                }
            };
            if key > last {
                break;
            }
            if !event.matches(locator, &self.filter)?.0 {
                continue;
            }
            count += 1;
        }
        Ok(count)
    }
}

#[allow(clippy::too_many_lines)]
fn from_filter_input(
    ctx: &Context<'_>,
    store: &Store,
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
            categories.push(
                EventCategory::from_u8(*category).ok_or_else(|| anyhow!("Invalid category"))?,
            );
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
        match ctx
            .data::<String>()
            .ok()
            .and_then(|username| store.account_map().get(username).ok())
            .flatten()
            .and_then(|account| account.customer_ids)
        {
            None => {
                // A SystemAdministrator can view all sensor events.
                None
            }
            Some(customer_ids) => {
                if customer_ids.is_empty() {
                    Some(Vec::new())
                } else {
                    Some(
                        store
                            .node_map()
                            .iter(Direction::Forward, None)
                            .filter_map(Result::ok)
                            .filter(|node| {
                                node.agents
                                    .iter()
                                    .any(|agent| agent.kind == AgentKind::Sensor)
                                    && node.profile.as_ref().is_some_and(|profile| {
                                        customer_ids.contains(&profile.customer_id)
                                    })
                            })
                            .filter_map(|node| node.profile.map(|profile| profile.hostname))
                            .collect::<Vec<_>>(),
                    )
                }
            }
        }
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
    map: &IndexedTable<database::Customer>,
    customer_ids: &[ID],
) -> anyhow::Result<Vec<database::Customer>> {
    let mut customers = Vec::with_capacity(customer_ids.len());
    for id in customer_ids {
        let i = id
            .as_str()
            .parse::<u32>()
            .context(format!("invalid ID: {}", id.as_str()))?;
        let Some(c) = map.get_by_id(i)? else {
            bail!("no such customer")
        };
        customers.push(c);
    }
    Ok(customers)
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

fn internal_customer_networks(
    map: &IndexedTable<database::Customer>,
) -> anyhow::Result<Vec<HostNetworkGroup>> {
    let mut customer_networks = Vec::new();
    for entry in map.iter(Direction::Forward, None) {
        let customer: database::Customer = entry?;
        for network in customer.networks {
            if network.network_type == database::event::NetworkType::Intranet
                || network.network_type == database::event::NetworkType::Gateway
            {
                customer_networks.push(network.network_group);
            }
        }
    }
    Ok(customer_networks)
}

fn convert_sensors(map: &database::NodeTable, sensors: &[ID]) -> anyhow::Result<Vec<String>> {
    let mut converted_sensors: Vec<String> = Vec::with_capacity(sensors.len());
    for id in sensors {
        let i = id
            .as_str()
            .parse::<u32>()
            .context(format!("invalid ID: {}", id.as_str()))?;
        let Some((node, _invalid_agents, _invalid_external_services)) = map.get_by_id(i)? else {
            bail!("no such sensor")
        };

        if let Some(node_profile) = node.profile
            && !node_profile.hostname.is_empty()
        {
            converted_sensors.push(node_profile.hostname.clone());
        }
    }
    Ok(converted_sensors)
}

fn convert_triage_input(
    map: &IndexedTable<database::TriagePolicy>,
    triage_policy_ids: &[ID],
) -> anyhow::Result<Vec<database::TriagePolicy>> {
    let mut triage_policies = Vec::with_capacity(triage_policy_ids.len());
    for id in triage_policy_ids {
        let i = id
            .as_str()
            .parse::<u32>()
            .context(format!("invalid ID: {}", id.as_str()))?;
        let Some(policy) = map.get_by_id(i)? else {
            bail!("no such customer")
        };
        triage_policies.push(policy);
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
    let mut filter = from_filter_input(ctx, &store, filter)?;
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
        let start = i128::from(start.timestamp_nanos_opt().unwrap_or_default()) << 64;
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
        let end = end
            .timestamp_nanos_opt()
            .map_or(i128::MAX, |s| i128::from(s) << 64);
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
        Some(
            ctx.data::<ip2location::DB>()
                .map_err(|_| anyhow!("unable to locate IP address"))?,
        )
    } else {
        None
    };

    for item in iter {
        let (key, mut event) = match item {
            Ok(kv) => kv,
            Err(e) => {
                warn_with_username!(ctx, "Invalid event: {:?}", e);
                continue;
            }
        };
        if !(cond)(key.cmp(&to)) {
            break;
        }
        let triage_score = {
            let matches = event.matches(locator, filter)?;
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
    use std::net::Ipv4Addr;

    use chrono::{DateTime, NaiveDate, Utc};
    use futures_util::StreamExt;
    use review_database::{
        EventCategory, EventKind, EventMessage,
        event::{BlocklistBootpFields, BlocklistDhcpFields, BlocklistTlsFields, DnsEventFields},
    };

    use crate::graphql::TestSchema;

    /// Creates an event message at `timestamp` with the given sensor and
    /// destination `IPv4` addresses.
    fn event_message_at(timestamp: DateTime<Utc>, src: u32, dst: u32) -> EventMessage {
        let fields = DnsEventFields {
            sensor: "sensor1".to_string(),
            start_time: timestamp,
            end_time: timestamp,
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
            category: Some(EventCategory::CommandAndControl),
        };
        EventMessage {
            time: timestamp,
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    #[tokio::test]
    async fn event_level_and_learning_method() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let db = store.events();
        let ts = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts, 1, 2)).unwrap();

        let query = format!(
            "{{ \
                eventList(filter: {{start:\"{ts}\"}}) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ level, learningMethod }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r"{eventList: {edges: [{node: {level: MEDIUM, learningMethod: SEMI_SUPERVISED}}]}}"
        );
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
            "{eventList: {edges: [], totalCount: 0}}"
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
                eventList(filter: {{ start:\"{ts2}\", end:\"{ts3}\" }}) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ time }} }} }} \
                    totalCount \
                }} \
            }}"
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829+00:00"}}], totalCount: 1}}"#
        );
    }

    #[tokio::test]
    async fn filter_by_categories_and_sensors() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(
                "{eventList(filter: {}){edges{node{... on DnsCovertChannel{query}}}totalCount}}",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            "{eventList: {edges: [], totalCount: 0}}"
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "sensor1",
                        customerId: 0,
                        description: "This is the sensor node",
                        hostname: "sensor1",
                        agents: [{
                            key: "sensor"
                            kind: SENSOR
                            status: ENABLED
                        }],
                        externalServices: [],
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);
        let _ = schema
            .execute(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "sensor1",
                            nameDraft: "sensor1",
                            profile: null,
                            profileDraft: {
                                customerId: 0,
                                description: "This is the sensor node",
                                hostname: "sensor1",
                            }
                            agents: [
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED"
                                }
                            ],
                            externalServices: []
                        }
                    )
                }"#,
            )
            .await;

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
                eventList( \
                    filter: {{ \
                        start:\"{ts2}\", end:\"{ts3}\", \
                        categories: 7, \
                        sensors: [0], \
                    }}, \
                ) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ time, sensor }} }} }} \
                    totalCount \
                }} \
            }}"
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829+00:00", sensor: "sensor1"}}], totalCount: 1}}"#
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
            r#"{eventList: {edges: [{node: {time: "2018-01-26T18:30:09.453829+00:00"}}, {node: {time: "2018-01-27T18:30:09.453829+00:00"}}], totalCount: 2}}"#
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
            r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829+00:00"}}], totalCount: 1}}"#
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
                eventList(filter: {{ start:\"{ts1}\", end:\"{ts3}\", customers: [0] }}) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ srcAddr }} }} }} \
                }} \
            }}"
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
                    start:\"{ts1}\",
                    end:\"{ts3}\",
                    directions: [\"OUTBOUND\"],
                }}) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ srcAddr }} }} }} \
                }} \
            }}"
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
                    start:\"{ts1}\",
                    end:\"{ts3}\",
                    endpoints: [{{predefined: \"0\"}}]
                }}) {{ \
                    edges {{ node {{... on DnsCovertChannel {{ srcAddr }} }} }} \
                }} \
            }}"
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
        let mut stream = schema.execute_stream(query).await;
        let res = stream.next().await;
        assert_eq!(
            res.unwrap().data.to_string(),
            r#"{eventStream: {__typename: "DnsCovertChannel", srcAddr: "0.0.0.5"}}"#
        );
    }

    #[tokio::test]
    async fn event_list_blocklist_dhcp() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = BlocklistDhcpFields {
            sensor: "sensor1".to_string(),
            src_addr: Ipv4Addr::LOCALHOST.into(),
            src_port: 68,
            dst_addr: Ipv4Addr::new(127, 0, 0, 2).into(),
            dst_port: 67,
            proto: 17,
            start_time: 10,
            end_time: 100,
            msg_type: 1,
            ciaddr: Ipv4Addr::new(127, 0, 0, 5).into(),
            yiaddr: Ipv4Addr::new(127, 0, 0, 6).into(),
            siaddr: Ipv4Addr::new(127, 0, 0, 7).into(),
            giaddr: Ipv4Addr::new(127, 0, 0, 8).into(),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0).into(),
            router: vec![Ipv4Addr::LOCALHOST.into()],
            domain_name_server: vec![Ipv4Addr::LOCALHOST.into()],
            req_ip_addr: Ipv4Addr::new(127, 0, 0, 100).into(),
            lease_time: 100,
            server_id: Ipv4Addr::LOCALHOST.into(),
            param_req_list: vec![1, 2, 3],
            message: "message".to_string(),
            renewal_time: 100,
            rebinding_time: 200,
            class_id: vec![4, 5, 6],
            client_id_type: 1,
            client_id: vec![7, 8, 9],
            category: Some(EventCategory::InitialAccess),
            confidence: 0.8,
        };

        let message = EventMessage {
            time: timestamp,
            kind: EventKind::BlocklistDhcp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        db.put(&message).unwrap();

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
                                    hosts: ["127.0.0.1"],
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
                    start:\"{timestamp}\"
                    customers: [0],
                    directions: [\"OUTBOUND\"],
                }}) {{ \
                    edges {{ node {{... on BlocklistDhcp {{ srcAddr,giaddr,reqIpAddr,classId,clientId }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {srcAddr: "127.0.0.1", giaddr: "127.0.0.8", reqIpAddr: "127.0.0.100", classId: "04:05:06", clientId: "07:08:09"}}]}}"#
        );
    }

    #[tokio::test]
    async fn event_list_blocklist_bootp() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = BlocklistBootpFields {
            sensor: "sensor1".to_string(),
            src_addr: Ipv4Addr::LOCALHOST.into(),
            src_port: 68,
            dst_addr: Ipv4Addr::new(127, 0, 0, 2).into(),
            dst_port: 67,
            proto: 17,
            start_time: 10,
            end_time: 100,
            op: 1,
            htype: 2,
            hops: 1,
            xid: 1,
            ciaddr: Ipv4Addr::new(127, 0, 0, 5).into(),
            yiaddr: Ipv4Addr::new(127, 0, 0, 6).into(),
            siaddr: Ipv4Addr::new(127, 0, 0, 7).into(),
            giaddr: Ipv4Addr::new(127, 0, 0, 8).into(),
            chaddr: vec![1, 2, 3, 4, 5, 6],
            sname: "server_name".to_string(),
            file: "boot_file_name".to_string(),
            category: Some(EventCategory::InitialAccess),
            confidence: 0.8,
        };

        let message = EventMessage {
            time: timestamp,
            kind: EventKind::BlocklistBootp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        db.put(&message).unwrap();

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
                                    hosts: ["127.0.0.2"],
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
                    start:\"{timestamp}\"
                    customers: [0],
                    directions: [\"INBOUND\"],
                }}) {{ \
                    edges {{ node {{... on BlocklistBootp {{ srcAddr,ciaddr,chaddr }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {srcAddr: "127.0.0.1", ciaddr: "127.0.0.5", chaddr: "01:02:03:04:05:06"}}]}}"#
        );
    }

    #[tokio::test]
    async fn event_list_locky_ransomware() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = DnsEventFields {
            sensor: "sensor1".to_string(),
            start_time: timestamp,
            end_time: timestamp,
            src_addr: Ipv4Addr::from(1).into(),
            src_port: 10000,
            dst_addr: Ipv4Addr::from(2).into(),
            dst_port: 53,
            proto: 17,
            query: "domain".into(),
            answer: Vec::new(),
            trans_id: 0,
            rtt: 10,
            qclass: 0,
            qtype: 0,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: false,
            ra_flag: false,
            ttl: Vec::new(),
            confidence: 0.8,
            category: Some(EventCategory::CommandAndControl),
        };
        let message = EventMessage {
            time: timestamp,
            kind: EventKind::LockyRansomware,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        db.put(&message).unwrap();
        let query = format!(
            "{{ \
                eventList(filter: {{
                    start:\"{timestamp}\"
                }}) {{ \
                    edges {{ node {{... on LockyRansomware {{ srcAddr,rtt,query }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {srcAddr: "0.0.0.1", rtt: "10", query: "domain"}}]}}"#
        );
    }

    #[tokio::test]
    async fn event_list_suspicious_tls_traffic() {
        let schema = TestSchema::new().await;
        let store = schema.store().await;
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = BlocklistTlsFields {
            sensor: "sensor1".to_string(),
            src_addr: Ipv4Addr::from(1).into(),
            src_port: 10000,
            dst_addr: Ipv4Addr::from(2).into(),
            dst_port: 443,
            proto: 6,
            start_time: timestamp.timestamp_nanos_opt().unwrap(),
            end_time: timestamp.timestamp_nanos_opt().unwrap(),
            server_name: "example.com".into(),
            alpn_protocol: "h2".into(),
            ja3: "ja3".into(),
            version: "TLSv1.2".into(),
            client_cipher_suites: vec![1234],
            client_extensions: vec![5678],
            cipher: 1234,
            extensions: vec![5678],
            ja3s: "ja3s".into(),
            serial: "serial".into(),
            subject_country: "US".into(),
            subject_org_name: "org".into(),
            subject_common_name: "common".into(),
            validity_not_before: timestamp.timestamp_nanos_opt().unwrap(),
            validity_not_after: timestamp.timestamp_nanos_opt().unwrap(),
            subject_alt_name: "alt".into(),
            issuer_country: "US".into(),
            issuer_org_name: "org".into(),
            issuer_org_unit_name: "unit".into(),
            issuer_common_name: "common".into(),
            last_alert: 3,
            confidence: 0.8,
            category: Some(EventCategory::CommandAndControl),
        };

        let message = EventMessage {
            time: timestamp,
            kind: EventKind::SuspiciousTlsTraffic,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        db.put(&message).unwrap();
        let query = format!(
            "{{ \
                eventList(filter: {{
                    start:\"{timestamp}\"
                }}) {{ \
                    edges {{ node {{... on SuspiciousTlsTraffic {{ srcAddr,cipher,subjectCountry,confidence }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {srcAddr: "0.0.0.1", cipher: 1234, subjectCountry: "US", confidence: 0.800000011920929}}]}}"#
        );
    }
}
