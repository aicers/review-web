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
mod malformed_dns;
mod mqtt;
mod network;
mod nfs;
mod ntlm;
mod radius;
mod rdp;
mod smb;
mod smtp;
mod ssh;
mod sysmon;
mod tls;
mod unusual_destination_pattern;

use std::{cmp, collections::BinaryHeap, net::IpAddr, sync::Arc};

use anyhow::{Context as AnyhowContext, anyhow, bail};
use async_graphql::{
    Context, Enum, ID, InputObject, Interface, Object, Result, StringNumber, Subscription,
    connection::{Connection, Edge, EmptyFields},
};
use chrono::{DateTime, Utc};
use database::ThreatLevel as DatabaseThreatLevel;
use futures::channel::mpsc::{UnboundedSender, unbounded};
use futures_util::stream::Stream;
use num_traits::FromPrimitive;
use review_database::{
    self as database, AgentKind, EventKind, ExclusionReason, IndexedTable, Iterable, Store,
    TriageExclusion, TriagePolicyInput as DbTriagePolicyInput,
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
    malformed_dns::BlocklistMalformedDns,
    mqtt::BlocklistMqtt,
    network::NetworkThreat,
    nfs::BlocklistNfs,
    ntlm::BlocklistNtlm,
    radius::BlocklistRadius,
    rdp::{BlocklistRdp, RdpBruteForce},
    smb::BlocklistSmb,
    smtp::BlocklistSmtp,
    ssh::BlocklistSsh,
    sysmon::WindowsThreat,
    tls::{BlocklistTls, SuspiciousTlsTraffic},
    unusual_destination_pattern::UnusualDestinationPattern,
};
use super::{
    Role, RoleGuard,
    customer::{Customer, HostNetworkGroupInput},
    filter::{FlowKind, LearningMethod, TrafficDirection},
    network::Network,
    triage::{ConfidenceInput, PacketAttrInput, ResponseInput, ThreatCategory},
};
use crate::{error_with_username, graphql::query, warn_with_username};

const DEFAULT_CONNECTION_SIZE: usize = 100;
const DEFAULT_EVENT_FETCH_TIME: u64 = 20;
const ADD_TIME_FOR_NEXT_COMPARE: i64 = 1;
const DEFAULT_TRIAGE_LIST_COUNT: usize = 100;

/// Threat level.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "DatabaseThreatLevel")]
pub(super) enum ThreatLevel {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
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
        use std::sync::RwLock;
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
            let fetch = fetch_events(
                store,
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
    store: Arc<std::sync::RwLock<Store>>,
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
    let mut blocklist_malformed_dns_time = start_time;
    let mut blocklist_mqtt_time = start_time;
    let mut blocklist_nfs_time = start_time;
    let mut blocklist_ntlm_time = start_time;
    let mut blocklist_radius_time = start_time;
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
    let mut unusual_destination_pattern_time = start_time;

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
                blocklist_malformed_dns_time,
                blocklist_mqtt_time,
                blocklist_nfs_time,
                blocklist_ntlm_time,
                blocklist_radius_time,
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
                unusual_destination_pattern_time,
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
                if blocklist_malformed_dns_time == iter_time_key {
                    blocklist_malformed_dns_time = min_time_key;
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
                if blocklist_radius_time == iter_time_key {
                    blocklist_radius_time = min_time_key;
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
                if unusual_destination_pattern_time == iter_time_key {
                    unusual_destination_pattern_time = min_time_key;
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
            .min(blocklist_malformed_dns_time)
            .min(blocklist_mqtt_time)
            .min(blocklist_nfs_time)
            .min(blocklist_ntlm_time)
            .min(blocklist_radius_time)
            .min(blocklist_rdp_time)
            .min(blocklist_smb_time)
            .min(blocklist_smtp_time)
            .min(blocklist_ssh_time)
            .min(blocklist_tls_time)
            .min(windows_threat_time)
            .min(network_threat_time)
            .min(extra_threat_time)
            .min(locky_ransomware_time)
            .min(suspicious_tls_time)
            .min(unusual_destination_pattern_time);

        // Fetch event iterator based on time
        let start_key = i128::from(start) << 64;
        let db = store
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        let events = db.events();
        let iter = events.iter_from(start_key, Direction::Forward);

        // Check for new data per event and send events that meet the conditions
        for event in iter {
            let (key, value) = event.map_err(|e| format!("Failed to read EventDb: {e:?}"))?;
            let event_time = i64::try_from(key >> 64)?;
            let kind = (key & 0xffff_ffff_0000_0000) >> 32;
            let Some(event_kind) = EventKind::from_i128(kind) else {
                return Err(anyhow!("Failed to convert event_kind: Invalid Event key").into());
            };

            match event_kind {
                EventKind::DnsCovertChannel if event_time >= dns_covert_time => {
                    tx.unbounded_send((key, value).into())?;
                    dns_covert_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::HttpThreat if event_time >= http_threat_time => {
                    tx.unbounded_send((key, value).into())?;
                    http_threat_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::RdpBruteForce if event_time >= rdp_brute_time => {
                    tx.unbounded_send((key, value).into())?;
                    rdp_brute_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::RepeatedHttpSessions if event_time >= repeat_http_time => {
                    tx.unbounded_send((key, value).into())?;
                    repeat_http_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::TorConnection if event_time >= tor_time => {
                    tx.unbounded_send((key, value).into())?;
                    tor_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::TorConnectionConn if event_time >= tor_connection_conn_time => {
                    tx.unbounded_send((key, value).into())?;
                    tor_connection_conn_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::DomainGenerationAlgorithm if event_time >= dga_time => {
                    tx.unbounded_send((key, value).into())?;
                    dga_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::FtpBruteForce if event_time >= ftp_brute_time => {
                    tx.unbounded_send((key, value).into())?;
                    ftp_brute_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::FtpPlainText if event_time >= ftp_plain_time => {
                    tx.unbounded_send((key, value).into())?;
                    ftp_plain_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::PortScan if event_time >= port_scan_time => {
                    tx.unbounded_send((key, value).into())?;
                    port_scan_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::MultiHostPortScan if event_time >= multi_host_time => {
                    tx.unbounded_send((key, value).into())?;
                    multi_host_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::NonBrowser if event_time >= non_browser_time => {
                    tx.unbounded_send((key, value).into())?;
                    non_browser_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::LdapBruteForce if event_time >= ldap_brute_time => {
                    tx.unbounded_send((key, value).into())?;
                    ldap_brute_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::LdapPlainText if event_time >= ldap_plain_time => {
                    tx.unbounded_send((key, value).into())?;
                    ldap_plain_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::ExternalDdos if event_time >= external_ddos_time => {
                    tx.unbounded_send((key, value).into())?;
                    external_ddos_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::CryptocurrencyMiningPool if event_time >= cryptocurrency_time => {
                    tx.unbounded_send((key, value).into())?;
                    cryptocurrency_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistBootp if event_time >= blocklist_bootp_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_bootp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistConn if event_time >= blocklist_conn_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_conn_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistDhcp if event_time >= blocklist_dhcp_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_dhcp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistDns if event_time >= blocklist_dns_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_dns_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistDceRpc if event_time >= blocklist_dcerpc_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_dcerpc_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistFtp if event_time >= blocklist_ftp_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_ftp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistHttp if event_time >= blocklist_http_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_http_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistKerberos if event_time >= blocklist_kerberos_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_kerberos_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistLdap if event_time >= blocklist_ldap_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_ldap_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistMalformedDns if event_time >= blocklist_malformed_dns_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_malformed_dns_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistMqtt if event_time >= blocklist_mqtt_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_mqtt_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistNfs if event_time >= blocklist_nfs_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_nfs_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistNtlm if event_time >= blocklist_ntlm_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_ntlm_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistRadius if event_time >= blocklist_radius_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_radius_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistRdp if event_time >= blocklist_rdp_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_rdp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistSmb if event_time >= blocklist_smb_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_smb_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistSmtp if event_time >= blocklist_smtp_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_smtp_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistSsh if event_time >= blocklist_ssh_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_ssh_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::BlocklistTls if event_time >= blocklist_tls_time => {
                    tx.unbounded_send((key, value).into())?;
                    blocklist_tls_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::WindowsThreat if event_time >= windows_threat_time => {
                    tx.unbounded_send((key, value).into())?;
                    windows_threat_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::NetworkThreat if event_time >= network_threat_time => {
                    tx.unbounded_send((key, value).into())?;
                    network_threat_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::ExtraThreat if event_time >= extra_threat_time => {
                    tx.unbounded_send((key, value).into())?;
                    extra_threat_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::LockyRansomware if event_time >= locky_ransomware_time => {
                    tx.unbounded_send((key, value).into())?;
                    locky_ransomware_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::SuspiciousTlsTraffic if event_time >= suspicious_tls_time => {
                    tx.unbounded_send((key, value).into())?;
                    suspicious_tls_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                EventKind::UnusualDestinationPattern
                    if event_time >= unusual_destination_pattern_time =>
                {
                    tx.unbounded_send((key, value).into())?;
                    unusual_destination_pattern_time = event_time + ADD_TIME_FOR_NEXT_COMPARE;
                }
                _ => {}
            }
        }
    }
}

#[Object]
impl EventQuery {
    /// Looks up a single event by its opaque `id`.
    ///
    /// `id` is the value previously returned from `Event.id`. Decoding the
    /// `id` is internal; consumers must not parse it.
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
    async fn event(&self, ctx: &Context<'_>, id: ID) -> Result<Option<Event>> {
        load_event(ctx, &id).await
    }

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

    /// A list of detection events sorted by triage policy score in descending
    /// order.
    ///
    /// Returns events that have triage scores applied based on the specified
    /// triage policies. Each event is sorted by its highest triage score, and
    /// only the top `count` events are returned.
    ///
    /// # Arguments
    ///
    /// * `filter` - Event filtering criteria, including triage policies to apply
    /// * `count` - Maximum number of events to return (defaults to 100)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The database connection fails
    /// * The filter parameters are invalid
    /// * An event cannot be processed
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_triage_list(
        &self,
        ctx: &Context<'_>,
        filter: EventListFilterInput,
        count: Option<usize>,
    ) -> Result<Vec<Event>> {
        load_triage_list(ctx, &filter, count).await
    }

    /// A list of events that pass the standard filter, with optional inline
    /// triage scoring and exclusions.
    ///
    /// Unlike `eventList`, this resolver returns every event passing the
    /// standard filter regardless of whether any triage policy matched.
    /// When `triage.policies` is supplied, matching policies attach their
    /// scores via `triageScores`; events that score nothing keep
    /// `triageScores: null` and remain in the connection. When
    /// `triage.exclusions` is supplied, matching events are removed from
    /// the connection. The cursor pagination contract matches `eventList`.
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
    ) -> Result<Connection<String, Event, EventTotalCount, EmptyFields>> {
        let policies = triage
            .as_ref()
            .and_then(|t| t.policies.as_deref())
            .map(convert_event_triage_policies)
            .transpose()?
            .unwrap_or_default();
        let exclusions = triage
            .as_ref()
            .and_then(|t| t.exclusions.as_deref())
            .map(convert_event_triage_exclusions)
            .transpose()?
            .unwrap_or_default();
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_with_triage(
                    ctx,
                    &filter,
                    &policies,
                    &exclusions,
                    after,
                    before,
                    first,
                    last,
                )
                .await
            },
        )
        .await
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

/// Common interface for all event types.
#[derive(Interface)]
#[graphql(
    field(name = "id", ty = "ID"),
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

    BlocklistMalformedDns(BlocklistMalformedDns),

    BlocklistMqtt(BlocklistMqtt),

    BlocklistNfs(BlocklistNfs),

    BlocklistNtlm(BlocklistNtlm),

    BlocklistRadius(BlocklistRadius),

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

    /// An event indicating an unusual pattern of connections to multiple
    /// destination IP addresses.
    UnusualDestinationPattern(UnusualDestinationPattern),
}

impl From<(i128, database::Event)> for Event {
    fn from((key, event): (i128, database::Event)) -> Self {
        match event {
            database::Event::DnsCovertChannel(event) => {
                Event::DnsCovertChannel((key, event).into())
            }
            database::Event::HttpThreat(event) => Event::HttpThreat((key, event).into()),
            database::Event::RdpBruteForce(event) => Event::RdpBruteForce((key, event).into()),
            database::Event::RepeatedHttpSessions(event) => {
                Event::RepeatedHttpSessions((key, event).into())
            }
            database::Event::TorConnection(event) => Event::TorConnection((key, event).into()),
            database::Event::TorConnectionConn(event) => {
                Event::TorConnectionConn((key, event).into())
            }
            database::Event::DomainGenerationAlgorithm(event) => {
                Event::DomainGenerationAlgorithm((key, event).into())
            }
            database::Event::FtpBruteForce(event) => Event::FtpBruteForce((key, event).into()),
            database::Event::FtpPlainText(event) => Event::FtpPlainText((key, event).into()),
            database::Event::PortScan(event) => Event::PortScan((key, event).into()),
            database::Event::MultiHostPortScan(event) => {
                Event::MultiHostPortScan((key, event).into())
            }
            database::Event::ExternalDdos(event) => Event::ExternalDdos((key, event).into()),
            database::Event::NonBrowser(event) => Event::NonBrowser((key, event).into()),
            database::Event::LdapBruteForce(event) => Event::LdapBruteForce((key, event).into()),
            database::Event::LdapPlainText(event) => Event::LdapPlainText((key, event).into()),
            database::Event::CryptocurrencyMiningPool(event) => {
                Event::CryptocurrencyMiningPool((key, event).into())
            }
            database::Event::Blocklist(record_type) => match record_type {
                RecordType::Bootp(event) => Event::BlocklistBootp((key, event).into()),
                RecordType::Conn(event) => Event::BlocklistConn((key, event).into()),
                RecordType::Dhcp(event) => Event::BlocklistDhcp((key, event).into()),
                RecordType::Dns(event) => Event::BlocklistDns((key, event).into()),
                RecordType::DceRpc(event) => Event::BlocklistDceRpc((key, event).into()),
                RecordType::Ftp(event) => Event::BlocklistFtp((key, event).into()),
                RecordType::Http(event) => Event::BlocklistHttp((key, event).into()),
                RecordType::Kerberos(event) => Event::BlocklistKerberos((key, event).into()),
                RecordType::Ldap(event) => Event::BlocklistLdap((key, event).into()),
                RecordType::MalformedDns(event) => {
                    Event::BlocklistMalformedDns((key, event).into())
                }
                RecordType::Mqtt(event) => Event::BlocklistMqtt((key, event).into()),
                RecordType::Nfs(event) => Event::BlocklistNfs((key, event).into()),
                RecordType::Ntlm(event) => Event::BlocklistNtlm((key, event).into()),
                RecordType::Radius(event) => Event::BlocklistRadius((key, event).into()),
                RecordType::Rdp(event) => Event::BlocklistRdp((key, event).into()),
                RecordType::Smb(event) => Event::BlocklistSmb((key, event).into()),
                RecordType::Smtp(event) => Event::BlocklistSmtp((key, event).into()),
                RecordType::Ssh(event) => Event::BlocklistSsh((key, event).into()),
                RecordType::Tls(event) => Event::BlocklistTls((key, event).into()),
                RecordType::UnusualDestinationPattern(event) => {
                    Event::UnusualDestinationPattern((key, event).into())
                }
            },
            database::Event::WindowsThreat(event) => Event::WindowsThreat((key, event).into()),
            database::Event::NetworkThreat(event) => Event::NetworkThreat((key, event).into()),
            database::Event::ExtraThreat(event) => Event::ExtraThreat((key, event).into()),
            database::Event::LockyRansomware(event) => Event::LockyRansomware((key, event).into()),
            database::Event::SuspiciousTlsTraffic(event) => {
                Event::SuspiciousTlsTraffic((key, event).into())
            }
        }
    }
}

#[derive(Default, InputObject)]
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
    categories: Option<Vec<Option<u8>>>,
    levels: Option<Vec<ThreatLevel>>,
    kinds: Option<Vec<String>>,
    learning_methods: Option<Vec<LearningMethod>>,
    confidence_min: Option<f32>,
    confidence_max: Option<f32>,
    triage_policies: Option<Vec<ID>>,
}

/// Standard event filter for `eventListWithTriage`. Identical to
/// `EventListFilterInput` minus `triagePolicies`: triage policies are passed
/// exclusively via the separate `triage` argument as inline data.
#[derive(Clone, InputObject)]
struct EventStandardFilterInput {
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
    categories: Option<Vec<Option<u8>>>,
    levels: Option<Vec<ThreatLevel>>,
    kinds: Option<Vec<String>>,
    learning_methods: Option<Vec<LearningMethod>>,
    confidence_min: Option<f32>,
    confidence_max: Option<f32>,
}

#[derive(InputObject)]
struct EventTriageInput {
    policies: Option<Vec<EventTriagePolicyInput>>,
    exclusions: Option<Vec<EventTriageExclusionInput>>,
}

/// Inline triage policy input for `eventListWithTriage`.
///
/// `id` is constrained to non-negative `i32` (`0..=i32::MAX`) and is echoed
/// back unchanged as `TriageScore.policyId`.
#[derive(InputObject)]
struct EventTriagePolicyInput {
    id: i32,
    packet_attr: Vec<PacketAttrInput>,
    confidence: Vec<ConfidenceInput>,
    response: Vec<ResponseInput>,
}

/// Inline exclusion input for `eventListWithTriage`.
///
/// All four fields are nullable at the schema level; an object with no
/// populated field is rejected by the resolver. When more than one field is
/// populated the object is flattened into independent `TriageExclusion`
/// values that are OR-combined with the rest.
#[derive(InputObject)]
struct EventTriageExclusionInput {
    ip_address: Option<HostNetworkGroupInput>,
    domain: Option<Vec<String>>,
    hostname: Option<Vec<String>>,
    uri: Option<Vec<String>>,
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
    exclusions: Vec<TriageExclusion>,
}

#[Object]
impl EventTotalCount {
    /// The total number of events.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;
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
                return Ok(StringNumber(0));
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
            if !self.exclusions.is_empty() && event.matches_exclusion(&self.exclusions) {
                continue;
            }
            count += 1;
        }
        Ok(StringNumber(count))
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
                category
                    .map(|c| EventCategory::from_u8(c).ok_or_else(|| anyhow!("Invalid category")))
                    .transpose()?,
            );
        }
        Some(categories)
    } else {
        None
    };

    let levels = input
        .levels
        .as_ref()
        .map(|v| v.iter().map(|l| DatabaseThreatLevel::from(*l)).collect());

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
        let scope = crate::graphql::customer_access::users_customers(ctx)
            .map_err(|e| anyhow!("{}", e.message))?;
        let map = store.node_map();
        Some(convert_sensors(&map, sensors_input, scope.as_deref())?)
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

    let triage_policies: Option<Vec<review_database::TriagePolicyInput>> =
        if let Some(triage_policies) = &input.triage_policies {
            let map = store.triage_policy_map();
            let triage_policies = convert_triage_input(&map, triage_policies)?;

            let exclusion_reason_map = store.triage_exclusion_reason_map();
            let triage_result = triage_policies
                .iter()
                .map(|policy| {
                    let policy = policy.clone();
                    let exclusion_reasons = policy
                        .triage_exclusion_id
                        .iter()
                        .filter_map(|id| exclusion_reason_map.get_by_id(*id).ok().flatten())
                        .map(|reason| reason.exclusion_reason)
                        .collect::<Vec<_>>();
                    policy.into_input_with_exclusion_reason(exclusion_reasons)
                })
                .collect::<Vec<_>>();
            Some(triage_result)
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
        input.confidence_min,
        input.confidence_max,
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

/// Returns the list of sensor hostnames the caller is allowed to see, or
/// `None` for unscoped (administrator) callers.
fn sensors_for_user(ctx: &Context<'_>, store: &Store) -> Result<Option<Vec<String>>> {
    let Some(customer_ids) = crate::graphql::customer_access::users_customers(ctx)? else {
        return Ok(None);
    };
    if customer_ids.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let sensors = store
        .node_map()
        .iter(Direction::Forward, None)
        .filter_map(Result::ok)
        .filter(|node| {
            node.agents
                .iter()
                .any(|agent| agent.kind == AgentKind::Sensor)
                && node
                    .profile
                    .as_ref()
                    .is_some_and(|profile| customer_ids.contains(&profile.customer_id))
        })
        .filter_map(|node| node.profile.map(|profile| profile.hostname))
        .collect::<Vec<_>>();
    Ok(Some(sensors))
}

async fn load_event(ctx: &Context<'_>, id: &ID) -> Result<Option<Event>> {
    let key = parse_event_id(id)?;
    let store = crate::graphql::get_store(ctx)?;

    // Derive the caller's allowed sensors via the shared customer-access
    // helper, which handles both auth-jwt (username -> account) and
    // auth-mtls (`CustomerIds` data) request contexts. SystemAdministrator
    // (no customer_ids) sees every sensor; everyone else is restricted to
    // sensors owned by their accessible customers.
    let sensors = sensors_for_user(ctx, &store)?;
    let mut filter = EventFilter::new(
        None, None, None, None, None, None, None, None, None, None, sensors, None, None, None,
    );
    filter.moderate_kinds();

    let db = store.events();
    let mut iter = db.iter_from(key, Direction::Forward);
    let Some(item) = iter.next() else {
        return Ok(None);
    };
    let (found_key, mut event) = match item {
        Ok(kv) => kv,
        Err(e) => {
            warn_with_username!(ctx, "Invalid event: {:?}", e);
            return Ok(None);
        }
    };
    if found_key != key {
        return Ok(None);
    }

    let locator = if filter.has_country() {
        Some(
            ctx.data::<ip2location::DB>()
                .map_err(|_| "unable to locate IP address")?,
        )
    } else {
        None
    };
    let (matched, triage_score) = event
        .matches(locator, &filter)
        .map_err(|e| format!("{e}"))?;
    if !matched {
        return Ok(None);
    }
    if let Some(triage_score) = triage_score {
        event.set_triage_scores(triage_score);
    }
    Ok(Some((found_key, event).into()))
}

async fn load(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Event, EventTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx)?;

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
        EventTotalCount {
            start,
            end,
            filter,
            exclusions: Vec::new(),
        },
    );
    connection.edges.extend(
        events
            .into_iter()
            .map(|(k, ev)| Edge::new(k.to_string(), ev)),
    );
    Ok(connection)
}

/// Loads events sorted by triage policy score in descending order.
///
/// This function retrieves events that match the given filter, calculates
/// their triage scores based on the specified triage policies, and returns
/// them sorted by their highest triage score. Only events with triage scores
/// are included in the result.
///
/// # Arguments
///
/// * `ctx` - GraphQL context
/// * `filter` - Event filtering criteria
/// * `count` - Maximum number of events to return (defaults to [`DEFAULT_TRIAGE_LIST_COUNT`])
///
/// # Errors
///
/// Returns an error if:
/// * The database store cannot be accessed
/// * The filter parameters are invalid
/// * An event cannot be processed or matched against the filter
async fn load_triage_list(
    ctx: &Context<'_>,
    filter: &EventListFilterInput,
    count: Option<usize>,
) -> Result<Vec<Event>> {
    let store = crate::graphql::get_store(ctx)?;
    let count = count.unwrap_or(DEFAULT_TRIAGE_LIST_COUNT);

    let start_key = filter
        .start
        .map(|t| i128::from(t.timestamp_nanos_opt().unwrap_or_default()) << 64)
        .unwrap_or_default();
    let end_key = filter.end.map_or(i128::MAX, |t| {
        let end = t
            .timestamp_nanos_opt()
            .map_or(i128::MAX, |t| i128::from(t) << 64);
        if end > 0 { end - 1 } else { 0 }
    });
    let mut filter = from_filter_input(ctx, &store, filter)?;
    filter.moderate_kinds();
    let db = store.events();

    let iter = db.iter_from(start_key, Direction::Forward);
    let locator = if filter.has_country() {
        Some(
            ctx.data::<ip2location::DB>()
                .map_err(|_| "unable to locate IP address")?,
        )
    } else {
        None
    };

    // Use a binary heap to efficiently maintain only the top `count` events
    // This prevents OOM issues with large datasets
    let mut heap = BinaryHeap::new();

    for item in iter {
        let (key, mut event) = match item {
            Ok(kv) => kv,
            Err(e) => {
                warn_with_username!(ctx, "Invalid event: {:?}", e);
                continue;
            }
        };

        if key > end_key {
            break;
        }

        let triage_score = {
            let matches = event.matches(locator, &filter)?;
            if !matches.0 {
                continue;
            }
            matches.1
        };

        // Only include events with triage scores
        if let Some(triage_score) = triage_score
            && !triage_score.is_empty()
        {
            // Find the highest score for this event
            let max_score = triage_score
                .iter()
                .map(|s| s.score)
                .max_by(|a, b| a.partial_cmp(b).unwrap_or(cmp::Ordering::Equal))
                .unwrap_or(0.0);

            event.set_triage_scores(triage_score);
            let event_priority = event_priority(&event);
            let scored_event = ScoredEvent {
                score: max_score,
                priority: event_priority,
                key,
                event,
            };

            heap.push(scored_event);

            // Keep only top `count` events to prevent OOM
            if heap.len() > count {
                heap.pop();
            }
        }
    }

    // Extract events from heap in descending order
    let result: Vec<Event> = heap
        .into_sorted_vec()
        .into_iter()
        .map(|scored| (scored.key, scored.event).into())
        .collect();
    Ok(result)
}

/// Represents an event with its triage score and priority for sorting.
struct ScoredEvent {
    score: f64,
    priority: u8,
    key: i128,
    event: database::Event,
}

impl PartialEq for ScoredEvent {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score && self.priority == other.priority
    }
}

impl Eq for ScoredEvent {}

impl PartialOrd for ScoredEvent {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoredEvent {
    // Sorting logic for BinaryHeap (min-heap behavior):
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Primary sort: lower scores are ranked higher
        other
            .score
            .partial_cmp(&self.score)
            .unwrap_or(cmp::Ordering::Equal)
            // Secondary sort: higher priority values (i.e., lower importance) are ranked higher.
            .then_with(|| self.priority.cmp(&other.priority))
    }
}

/// Assigns a priority value to an event based on its type and characteristics.
///
/// Priority order (lower value = higher priority):
/// 1. `HttpThreat` with `cluster_id` = `None`
/// 2. `DnsCovertChannel`
/// 3. `DomainGenerationAlgorithm`
/// 4. `LockyRansomware`
/// 5. `HttpThreat` with `cluster_id` = `Some`
/// 6. Other detection events
fn event_priority(event: &database::Event) -> u8 {
    match event {
        database::Event::HttpThreat(http_threat) => {
            if http_threat.cluster_id.is_none() {
                0 // Highest priority
            } else {
                4 // Lower priority when cluster_id is present
            }
        }
        database::Event::DnsCovertChannel(_) => 1,
        database::Event::DomainGenerationAlgorithm(_) => 2,
        database::Event::LockyRansomware(_) => 3,
        _ => 5, // All other events have lowest priority
    }
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
        events.push((key, (key, event).into()));
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

impl From<EventStandardFilterInput> for EventListFilterInput {
    fn from(input: EventStandardFilterInput) -> Self {
        Self {
            start: input.start,
            end: input.end,
            customers: input.customers,
            endpoints: input.endpoints,
            directions: input.directions,
            source: input.source,
            destination: input.destination,
            keywords: input.keywords,
            network_tags: input.network_tags,
            sensors: input.sensors,
            os: input.os,
            devices: input.devices,
            hostnames: input.hostnames,
            user_ids: input.user_ids,
            user_names: input.user_names,
            user_departments: input.user_departments,
            countries: input.countries,
            categories: input.categories,
            levels: input.levels,
            kinds: input.kinds,
            learning_methods: input.learning_methods,
            confidence_min: input.confidence_min,
            confidence_max: input.confidence_max,
            triage_policies: None,
        }
    }
}

fn convert_event_triage_policies(
    policies: &[EventTriagePolicyInput],
) -> anyhow::Result<Vec<DbTriagePolicyInput>> {
    let now = Utc::now();
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
            triage_exclusion: Vec::new(),
            packet_attr: policy.packet_attr.iter().map(Into::into).collect(),
            confidence: policy.confidence.iter().map(Into::into).collect(),
            response: policy.response.iter().map(Into::into).collect(),
        });
    }
    Ok(result)
}

fn convert_event_triage_exclusions(
    exclusions: &[EventTriageExclusionInput],
) -> anyhow::Result<Vec<TriageExclusion>> {
    let mut result = Vec::new();
    for exclusion in exclusions {
        let mut populated = false;
        if let Some(group) = &exclusion.ip_address
            && !(group.hosts.is_empty() && group.networks.is_empty() && group.ranges.is_empty())
        {
            populated = true;
            let host_network_group: HostNetworkGroup = group.try_into()?;
            result.push(TriageExclusion::from(ExclusionReason::IpAddress(
                host_network_group,
            )));
        }
        if let Some(domains) = &exclusion.domain
            && !domains.is_empty()
        {
            populated = true;
            result.push(TriageExclusion::from(ExclusionReason::Domain(
                domains.clone(),
            )));
        }
        if let Some(hostnames) = &exclusion.hostname
            && !hostnames.is_empty()
        {
            populated = true;
            result.push(TriageExclusion::from(ExclusionReason::Hostname(
                hostnames.clone(),
            )));
        }
        if let Some(uris) = &exclusion.uri
            && !uris.is_empty()
        {
            populated = true;
            result.push(TriageExclusion::from(ExclusionReason::Uri(uris.clone())));
        }
        if !populated {
            bail!("triage exclusion must have at least one populated field");
        }
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn load_with_triage(
    ctx: &Context<'_>,
    filter: &EventStandardFilterInput,
    policies: &[DbTriagePolicyInput],
    exclusions: &[TriageExclusion],
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Event, EventTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx)?;

    let start = filter.start;
    let end = filter.end;
    let list_filter: EventListFilterInput = filter.clone().into();
    let mut event_filter = from_filter_input(ctx, &store, &list_filter)?;
    event_filter.moderate_kinds();
    let db = store.events();
    let (events, has_previous, has_next) = if let Some(last) = last {
        let iter = db.iter_from(latest(end, before)?, Direction::Reverse);
        let to = earliest(start, after)?;
        let (events, has_more) = iter_to_events_with_triage(
            ctx,
            iter,
            to,
            cmp::Ordering::is_ge,
            last,
            &event_filter,
            policies,
            exclusions,
        )
        .map_err(|e| format!("{e}"))?;
        (events.into_iter().rev().collect(), has_more, false)
    } else {
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let iter = db.iter_from(earliest(start, after)?, Direction::Forward);
        let to = latest(end, before)?;
        let (events, has_more) = iter_to_events_with_triage(
            ctx,
            iter,
            to,
            cmp::Ordering::is_le,
            first,
            &event_filter,
            policies,
            exclusions,
        )
        .map_err(|e| format!("{e}"))?;
        (events, false, has_more)
    };

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        EventTotalCount {
            start,
            end,
            filter: event_filter,
            exclusions: exclusions.to_vec(),
        },
    );
    connection.edges.extend(
        events
            .into_iter()
            .map(|(k, ev)| Edge::new(k.to_string(), ev)),
    );
    Ok(connection)
}

#[allow(clippy::too_many_arguments)]
fn iter_to_events_with_triage(
    ctx: &Context<'_>,
    iter: EventIterator,
    to: i128,
    cond: fn(cmp::Ordering) -> bool,
    len: usize,
    filter: &EventFilter,
    policies: &[DbTriagePolicyInput],
    exclusions: &[TriageExclusion],
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
        if !event.matches(locator, filter)?.0 {
            continue;
        }
        if !exclusions.is_empty() && event.matches_exclusion(exclusions) {
            continue;
        }
        if !policies.is_empty() {
            let scores = event.score_against_policies(policies);
            if !scores.is_empty() {
                event.set_triage_scores(scores);
            }
        }
        events.push((key, (key, event).into()));
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
#[allow(clippy::await_holding_lock)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::{DateTime, NaiveDate, Utc};
    use futures_util::StreamExt;
    use review_database::{
        self as database, EventCategory, EventKind, EventMessage,
        event::{
            BlocklistBootpFields, BlocklistConnFields, BlocklistDceRpcFields, BlocklistDhcpFields,
            BlocklistDnsFields, BlocklistKerberosFields, BlocklistMqttFields, BlocklistNfsFields,
            BlocklistNtlmFields, BlocklistRdpFields, BlocklistSmbFields, BlocklistSmtpFields,
            BlocklistSshFields, BlocklistTlsFields, DnsEventFields,
            UnusualDestinationPatternFields,
        },
    };

    use crate::graphql::{Role, TestSchema};

    /// Creates an event message at `timestamp` with the given sensor and
    /// destination `IPv4` addresses.
    fn event_message_at(timestamp: DateTime<Utc>, src: u32, dst: u32) -> EventMessage {
        event_message_with_category(
            timestamp,
            src,
            dst,
            Some(EventCategory::CommandAndControl),
            "sensor1",
        )
    }

    fn event_message_with_category(
        timestamp: DateTime<Utc>,
        src: u32,
        dst: u32,
        category: Option<EventCategory>,
        sensor: &str,
    ) -> EventMessage {
        let fields = DnsEventFields {
            sensor: sensor.to_string(),
            start_time: timestamp.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_addr: Ipv4Addr::from(src).into(),
            orig_port: 10000,
            resp_addr: Ipv4Addr::from(dst).into(),
            resp_port: 53,
            proto: 17,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
            category,
        };
        EventMessage {
            time: timestamp,
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&fields).expect("serializable"),
        }
    }

    #[tokio::test]
    async fn event_lookup_by_id_returns_matching_event() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let ts = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let key = db.put(&event_message_at(ts, 1, 2)).unwrap();
        drop(store);

        let query = format!(
            "{{ event(id: \"{key}\") {{ id, ... on DnsCovertChannel {{ time, query }} }} }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            format!(
                r#"{{event: {{id: "{key}", time: "2018-01-26T18:30:09.453829+00:00", query: "domain"}}}}"#
            )
        );
    }

    #[tokio::test]
    async fn event_lookup_unknown_id_returns_null() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin("{ event(id: \"0\") { id } }")
            .await;
        assert_eq!(res.data.to_string(), r"{event: null}");
    }

    #[tokio::test]
    async fn event_lookup_invalid_id_errors() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin("{ event(id: \"not-a-number\") { id } }")
            .await;
        assert!(!res.errors.is_empty());
    }

    #[tokio::test]
    async fn event_lookup_id_matches_event_list_cursor() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let ts = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts, 1, 2)).unwrap();
        drop(store);

        let res = schema
            .execute_as_system_admin("{ eventList(filter: {}) { edges { cursor, node { id } } } }")
            .await;
        let s = res.data.to_string();
        let cursor_pos = s.find("cursor: \"").expect("cursor present");
        let cursor_start = cursor_pos + "cursor: \"".len();
        let cursor_end = cursor_start + s[cursor_start..].find('"').unwrap();
        let cursor = &s[cursor_start..cursor_end];
        let id_pos = s.find("id: \"").expect("id present");
        let id_start = id_pos + "id: \"".len();
        let id_end = id_start + s[id_start..].find('"').unwrap();
        let id = &s[id_start..id_end];
        assert_eq!(cursor, id);
    }

    #[tokio::test]
    async fn event_lookup_respects_tenant_scope() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
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
            .execute_as_system_admin(
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

        let store = schema.store();
        let db = store.events();
        let ts = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let key = db.put(&event_message_at(ts, 1, 2)).unwrap();
        drop(store);

        let query =
            format!("{{ event(id: \"{key}\") {{ ... on DnsCovertChannel {{ sensor }} }} }}");

        // Scoped user assigned to customer 0 (which owns sensor1) can see it.
        let res = schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![0]))
            .await;
        assert_eq!(res.data.to_string(), r#"{event: {sensor: "sensor1"}}"#);

        // Scoped user assigned to customer 1 (not owning sensor1) cannot.
        let res = schema
            .execute_as_scoped_user(&query, Role::SecurityMonitor, Some(vec![1]))
            .await;
        assert_eq!(res.data.to_string(), r"{event: null}");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn event_lookup_resolves_each_blocklist_kind() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let base = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        let conn_ts = base;
        let conn_key = db
            .put(&EventMessage {
                time: conn_ts,
                kind: EventKind::BlocklistConn,
                fields: bincode::serialize(&BlocklistConnFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 1).into(),
                    orig_port: 1000,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 2).into(),
                    resp_port: 80,
                    proto: 6,
                    conn_state: "S0".to_string(),
                    start_time: conn_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    service: "http".to_string(),
                    orig_bytes: 0,
                    resp_bytes: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    confidence: 0.7,
                    category: Some(EventCategory::InitialAccess),
                })
                .unwrap(),
            })
            .unwrap();

        let dns_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 1)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let dns_key = db
            .put(&EventMessage {
                time: dns_ts,
                kind: EventKind::BlocklistDns,
                fields: bincode::serialize(&BlocklistDnsFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 3).into(),
                    orig_port: 50000,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 4).into(),
                    resp_port: 53,
                    proto: 17,
                    start_time: dns_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    query: "evil.example.com".to_string(),
                    answer: vec!["1.2.3.4".to_string()],
                    trans_id: 1,
                    rtt: 0,
                    qclass: 1,
                    qtype: 1,
                    rcode: 0,
                    aa_flag: false,
                    tc_flag: false,
                    rd_flag: true,
                    ra_flag: true,
                    ttl: vec![60],
                    confidence: 0.7,
                    category: Some(EventCategory::CommandAndControl),
                })
                .unwrap(),
            })
            .unwrap();

        let dcerpc_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 2)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let dcerpc_key = db
            .put(&EventMessage {
                time: dcerpc_ts,
                kind: EventKind::BlocklistDceRpc,
                fields: bincode::serialize(&BlocklistDceRpcFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 5).into(),
                    orig_port: 1024,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 6).into(),
                    resp_port: 135,
                    proto: 6,
                    start_time: dcerpc_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    context: Vec::new(),
                    request: Vec::new(),
                    confidence: 0.7,
                    category: Some(EventCategory::LateralMovement),
                })
                .unwrap(),
            })
            .unwrap();

        let kerberos_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 3)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let kerberos_key = db
            .put(&EventMessage {
                time: kerberos_ts,
                kind: EventKind::BlocklistKerberos,
                fields: bincode::serialize(&BlocklistKerberosFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 7).into(),
                    orig_port: 1025,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 8).into(),
                    resp_port: 88,
                    proto: 6,
                    start_time: kerberos_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    client_time: 0,
                    server_time: 0,
                    error_code: 0,
                    client_realm: "REALM".to_string(),
                    cname_type: 1,
                    cname: vec!["alice".to_string()],
                    realm: "REALM".to_string(),
                    sname_type: 2,
                    sname: vec!["krbtgt".to_string()],
                    confidence: 0.7,
                    category: Some(EventCategory::LateralMovement),
                })
                .unwrap(),
            })
            .unwrap();

        let mqtt_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 4)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let mqtt_key = db
            .put(&EventMessage {
                time: mqtt_ts,
                kind: EventKind::BlocklistMqtt,
                fields: bincode::serialize(&BlocklistMqttFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 9).into(),
                    orig_port: 1026,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 10).into(),
                    resp_port: 1883,
                    proto: 6,
                    start_time: mqtt_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    protocol: "MQTT".to_string(),
                    version: 4,
                    client_id: "client".to_string(),
                    connack_reason: 0,
                    subscribe: vec!["topic".to_string()],
                    suback_reason: vec![0],
                    confidence: 0.7,
                    category: Some(EventCategory::CommandAndControl),
                })
                .unwrap(),
            })
            .unwrap();

        let nfs_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 5)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let nfs_key = db
            .put(&EventMessage {
                time: nfs_ts,
                kind: EventKind::BlocklistNfs,
                fields: bincode::serialize(&BlocklistNfsFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 11).into(),
                    orig_port: 1027,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 12).into(),
                    resp_port: 2049,
                    proto: 6,
                    start_time: nfs_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    read_files: vec!["/etc/passwd".to_string()],
                    write_files: vec![],
                    confidence: 0.7,
                    category: Some(EventCategory::Collection),
                })
                .unwrap(),
            })
            .unwrap();

        let ntlm_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 6)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let ntlm_key = db
            .put(&EventMessage {
                time: ntlm_ts,
                kind: EventKind::BlocklistNtlm,
                fields: bincode::serialize(&BlocklistNtlmFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 13).into(),
                    orig_port: 1028,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 14).into(),
                    resp_port: 445,
                    proto: 6,
                    start_time: ntlm_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    protocol: "NTLM".to_string(),
                    username: "alice".to_string(),
                    hostname: "host".to_string(),
                    domainname: "domain".to_string(),
                    success: "true".to_string(),
                    confidence: 0.7,
                    category: Some(EventCategory::CredentialAccess),
                })
                .unwrap(),
            })
            .unwrap();

        let rdp_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 7)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let rdp_key = db
            .put(&EventMessage {
                time: rdp_ts,
                kind: EventKind::BlocklistRdp,
                fields: bincode::serialize(&BlocklistRdpFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 15).into(),
                    orig_port: 1029,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 16).into(),
                    resp_port: 3389,
                    proto: 6,
                    start_time: rdp_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    cookie: "cookie".to_string(),
                    confidence: 0.7,
                    category: Some(EventCategory::LateralMovement),
                })
                .unwrap(),
            })
            .unwrap();

        let smb_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 8)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let smb_key = db
            .put(&EventMessage {
                time: smb_ts,
                kind: EventKind::BlocklistSmb,
                fields: bincode::serialize(&BlocklistSmbFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 17).into(),
                    orig_port: 1030,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 18).into(),
                    resp_port: 445,
                    proto: 6,
                    start_time: smb_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    command: 1,
                    path: "/share".to_string(),
                    service: "IPC".to_string(),
                    file_name: "file".to_string(),
                    file_size: 0,
                    resource_type: 0,
                    fid: 0,
                    create_time: 0,
                    access_time: 0,
                    write_time: 0,
                    change_time: 0,
                    confidence: 0.7,
                    category: Some(EventCategory::Collection),
                })
                .unwrap(),
            })
            .unwrap();

        let smtp_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 9)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let smtp_key = db
            .put(&EventMessage {
                time: smtp_ts,
                kind: EventKind::BlocklistSmtp,
                fields: bincode::serialize(&BlocklistSmtpFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 19).into(),
                    orig_port: 1031,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 20).into(),
                    resp_port: 25,
                    proto: 6,
                    start_time: smtp_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    mailfrom: "alice@example.com".to_string(),
                    date: "2026-04-01".to_string(),
                    from: "alice".to_string(),
                    to: "bob".to_string(),
                    subject: "subject".to_string(),
                    agent: "agent".to_string(),
                    state: "state".to_string(),
                    confidence: 0.7,
                    category: Some(EventCategory::Exfiltration),
                })
                .unwrap(),
            })
            .unwrap();

        let ssh_ts = NaiveDate::from_ymd_opt(2026, 4, 1)
            .unwrap()
            .and_hms_opt(0, 0, 10)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let ssh_key = db
            .put(&EventMessage {
                time: ssh_ts,
                kind: EventKind::BlocklistSsh,
                fields: bincode::serialize(&BlocklistSshFields {
                    sensor: "sensor1".to_string(),
                    orig_addr: Ipv4Addr::new(10, 0, 0, 21).into(),
                    orig_port: 1032,
                    resp_addr: Ipv4Addr::new(10, 0, 0, 22).into(),
                    resp_port: 22,
                    proto: 6,
                    start_time: ssh_ts.timestamp_nanos_opt().unwrap(),
                    duration: 0,
                    orig_pkts: 0,
                    resp_pkts: 0,
                    orig_l2_bytes: 0,
                    resp_l2_bytes: 0,
                    client: "OpenSSH".to_string(),
                    server: "OpenSSH".to_string(),
                    cipher_alg: "aes".to_string(),
                    mac_alg: "hmac".to_string(),
                    compression_alg: "none".to_string(),
                    kex_alg: "kex".to_string(),
                    host_key_alg: "rsa".to_string(),
                    hassh_algorithms: "h".to_string(),
                    hassh: "h".to_string(),
                    hassh_server_algorithms: "h".to_string(),
                    hassh_server: "h".to_string(),
                    client_shka: "s".to_string(),
                    server_shka: "s".to_string(),
                    confidence: 0.7,
                    category: Some(EventCategory::LateralMovement),
                })
                .unwrap(),
            })
            .unwrap();

        drop(store);

        let cases = [
            (conn_key, "BlocklistConn"),
            (dns_key, "BlocklistDns"),
            (dcerpc_key, "BlocklistDceRpc"),
            (kerberos_key, "BlocklistKerberos"),
            (mqtt_key, "BlocklistMqtt"),
            (nfs_key, "BlocklistNfs"),
            (ntlm_key, "BlocklistNtlm"),
            (rdp_key, "BlocklistRdp"),
            (smb_key, "BlocklistSmb"),
            (smtp_key, "BlocklistSmtp"),
            (ssh_key, "BlocklistSsh"),
        ];
        for (key, typename) in cases {
            let query = format!("{{ event(id: \"{key}\") {{ id __typename }} }}");
            let res = schema.execute_as_system_admin(&query).await;
            assert_eq!(
                res.data.to_string(),
                format!(r#"{{event: {{id: "{key}", __typename: "{typename}"}}}}"#)
            );
        }
    }

    #[tokio::test]
    async fn event_level_and_learning_method() {
        let schema = TestSchema::new().await;
        let store = schema.store();
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
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r"{eventList: {edges: [{node: {level: MEDIUM, learningMethod: SEMI_SUPERVISED}}]}}"
        );
    }

    #[tokio::test]
    async fn event_list() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(
                "{eventList(filter: {}){edges{node{... on DnsCovertChannel{query}}}totalCount}}",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [], totalCount: "0"}}"#
        );

        let store = schema.store();
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
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829+00:00"}}], totalCount: "1"}}"#
        );
    }

    #[tokio::test]
    async fn filter_by_categories_and_sensors() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(
                "{eventList(filter: {}){edges{node{... on DnsCovertChannel{query}}}totalCount}}",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [], totalCount: "0"}}"#
        );

        let res = schema
            .execute_as_system_admin(
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
            .execute_as_system_admin(
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

        let store = schema.store();
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
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829+00:00", sensor: "sensor1"}}], totalCount: "1"}}"#
        );
    }

    #[tokio::test]
    async fn explicit_sensors_outside_scope_returns_forbidden() {
        let schema = TestSchema::new().await;

        // Insert and apply a sensor node owned by customer 0.
        let _ = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "sensor1",
                        customerId: 0,
                        description: "",
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
        let _ = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "sensor1",
                            nameDraft: "sensor1",
                            profile: null,
                            profileDraft: {
                                customerId: 0,
                                description: "",
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

        // Caller scoped to customer 1 (out of scope for sensor node 0) must be
        // rejected when supplying `sensors: [0]`.
        let res = schema
            .execute_as_scoped_user(
                "{ eventList(filter: { sensors: [0] }) { edges { node { ... on DnsCovertChannel { sensor } } } totalCount } }",
                Role::SecurityMonitor,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1, "errors: {:?}", res.errors);
        assert!(
            res.errors[0].message.contains("Forbidden"),
            "message: {}",
            res.errors[0].message
        );

        // Caller scoped to customer 0 (in scope) succeeds.
        let res = schema
            .execute_as_scoped_user(
                "{ eventList(filter: { sensors: [0] }) { totalCount } }",
                Role::SecurityMonitor,
                Some(vec![0]),
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
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
        let store = schema.store();
        let db = store.events();
        timestamps
            .iter()
            .zip(src_dst.into_iter())
            .for_each(|(ts, (src, dst))| {
                db.put(&event_message_at(*ts, src, dst)).unwrap();
            });

        let _ = schema
            .execute_as_system_admin(
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
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {time: "2018-01-26T18:30:09.453829+00:00"}}, {node: {time: "2018-01-27T18:30:09.453829+00:00"}}], totalCount: "2"}}"#
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
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {time: "2018-01-27T18:30:09.453829+00:00"}}], totalCount: "1"}}"#
        );
    }

    #[tokio::test]
    async fn filter_by_customer() {
        let schema = TestSchema::new().await;
        let store = schema.store();
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
            .execute_as_system_admin(
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
                    edges {{ node {{... on DnsCovertChannel {{ origAddr }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {origAddr: "0.0.0.1"}}]}}"#
        );
    }

    #[tokio::test]
    async fn filter_by_direction() {
        let schema = TestSchema::new().await;
        let store = schema.store();
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
            .execute_as_system_admin(
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
                    edges {{ node {{... on DnsCovertChannel {{ origAddr }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {origAddr: "0.0.0.1"}}]}}"#
        );
    }

    #[tokio::test]
    async fn filter_by_network() {
        let schema = TestSchema::new().await;
        let store = schema.store();
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
            .execute_as_system_admin(
                r#"mutation {
                    insertNetwork(
                        name: "n0",
                        description: "",
                        networks: {
                            hosts: ["0.0.0.4"],
                            networks: [],
                            ranges: []
                        },
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
                    edges {{ node {{... on DnsCovertChannel {{ origAddr }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {origAddr: "0.0.0.3"}}]}}"#
        );
    }

    #[tokio::test]
    async fn filter_by_unknown_category() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();

        let ts1 = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_micro_opt(0, 0, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_with_category(
            ts1,
            1,
            2,
            Some(EventCategory::InitialAccess), //category = 2
            "s1",
        ))
        .unwrap();

        let ts2 = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_micro_opt(0, 0, 1, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_with_category(ts2, 3, 4, None, "s2"))
            .unwrap();

        // 1. Filter by unknown category
        let query = r"{ eventList(filter: { categories: [null] }) { edges { node { ... on DnsCovertChannel { sensor } } } totalCount } }";
        let res = schema.execute_as_system_admin(query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {sensor: "s2"}}], totalCount: "1"}}"#
        );

        // 2. Filter by a specific category (InitialAccess = 2)
        let query = r"{ eventList(filter: { categories: [2] }) { edges { node { ... on DnsCovertChannel { sensor } } } totalCount } }";
        let res = schema.execute_as_system_admin(query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {sensor: "s1"}}], totalCount: "1"}}"#
        );

        // 3. Filter by both specific and unknown categories
        let query = r"{ eventList(filter: { categories: [2, null] }) { edges { node { ... on DnsCovertChannel { sensor } } } totalCount } }";
        let res = schema.execute_as_system_admin(query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventList: {edges: [{node: {sensor: "s1"}}, {node: {sensor: "s2"}}], totalCount: "2"}}"#
        );
    }

    #[tokio::test]
    async fn event_stream() {
        let schema = TestSchema::new().await;
        let store = schema.store();
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
                origAddr,
              }
            }
        }
        "#;
        let mut stream = schema.execute_stream(query).await;
        let res = stream.next().await;
        assert_eq!(
            res.unwrap().data.to_string(),
            r#"{eventStream: {__typename: "DnsCovertChannel", origAddr: "0.0.0.5"}}"#
        );
    }

    #[tokio::test]
    async fn event_list_blocklist_dhcp() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = BlocklistDhcpFields {
            sensor: "sensor1".to_string(),
            orig_addr: Ipv4Addr::LOCALHOST.into(),
            orig_port: 68,
            resp_addr: Ipv4Addr::new(127, 0, 0, 2).into(),
            resp_port: 67,
            proto: 17,
            start_time: timestamp.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
            options: vec![(53, vec![1]), (61, vec![7, 8, 9])],
            category: Some(EventCategory::InitialAccess),
            confidence: 0.8,
        };

        let message = EventMessage {
            time: timestamp,
            kind: EventKind::BlocklistDhcp,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let key = db.put(&message).unwrap();

        let res = schema
            .execute_as_system_admin(
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
                    edges {{ node {{ id, ... on BlocklistDhcp {{ origAddr,giaddr,reqIpAddr,classId,clientId,options {{ code,value }} }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            format!(
                r#"{{eventList: {{edges: [{{node: {{id: "{key}", origAddr: "127.0.0.1", giaddr: "127.0.0.8", reqIpAddr: "127.0.0.100", classId: "04:05:06", clientId: "07:08:09", options: [{{code: 53, value: [1]}}, {{code: 61, value: [7, 8, 9]}}]}}}}]}}}}"#
            )
        );

        let lookup_query =
            format!("{{ event(id: \"{key}\") {{ id, ... on BlocklistDhcp {{ origAddr }} }} }}");
        let res = schema.execute_as_system_admin(&lookup_query).await;
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{event: {{id: "{key}", origAddr: "127.0.0.1"}}}}"#)
        );
    }

    #[tokio::test]
    async fn event_list_blocklist_bootp() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = BlocklistBootpFields {
            sensor: "sensor1".to_string(),
            orig_addr: Ipv4Addr::LOCALHOST.into(),
            orig_port: 68,
            resp_addr: Ipv4Addr::new(127, 0, 0, 2).into(),
            resp_port: 67,
            proto: 17,
            start_time: timestamp.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
        let key = db.put(&message).unwrap();

        let res = schema
            .execute_as_system_admin(
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
                    edges {{ node {{ id, ... on BlocklistBootp {{ origAddr,ciaddr,chaddr }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            format!(
                r#"{{eventList: {{edges: [{{node: {{id: "{key}", origAddr: "127.0.0.1", ciaddr: "127.0.0.5", chaddr: "01:02:03:04:05:06"}}}}]}}}}"#
            )
        );

        let lookup_query =
            format!("{{ event(id: \"{key}\") {{ id, ... on BlocklistBootp {{ origAddr }} }} }}");
        let res = schema.execute_as_system_admin(&lookup_query).await;
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{event: {{id: "{key}", origAddr: "127.0.0.1"}}}}"#)
        );
    }

    #[tokio::test]
    async fn event_list_locky_ransomware() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = DnsEventFields {
            sensor: "sensor1".to_string(),
            start_time: timestamp.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_addr: Ipv4Addr::from(1).into(),
            orig_port: 10000,
            resp_addr: Ipv4Addr::from(2).into(),
            resp_port: 53,
            proto: 17,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
        let key = db.put(&message).unwrap();
        let query = format!(
            "{{ \
                eventList(filter: {{
                    start:\"{timestamp}\"
                }}) {{ \
                    edges {{ node {{ id, ... on LockyRansomware {{ origAddr,rtt,query }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            format!(
                r#"{{eventList: {{edges: [{{node: {{id: "{key}", origAddr: "0.0.0.1", rtt: "10", query: "domain"}}}}]}}}}"#
            )
        );

        let lookup_query =
            format!("{{ event(id: \"{key}\") {{ id, ... on LockyRansomware {{ origAddr }} }} }}");
        let res = schema.execute_as_system_admin(&lookup_query).await;
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{event: {{id: "{key}", origAddr: "0.0.0.1"}}}}"#)
        );
    }

    #[tokio::test]
    async fn event_list_suspicious_tls_traffic() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = BlocklistTlsFields {
            sensor: "sensor1".to_string(),
            orig_addr: Ipv4Addr::from(1).into(),
            orig_port: 10000,
            resp_addr: Ipv4Addr::from(2).into(),
            resp_port: 443,
            proto: 6,
            start_time: timestamp.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
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
        let key = db.put(&message).unwrap();
        let query = format!(
            "{{ \
                eventList(filter: {{
                    start:\"{timestamp}\"
                }}) {{ \
                    edges {{ node {{ id, ... on SuspiciousTlsTraffic {{ origAddr,cipher,subjectCountry,confidence }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            format!(
                r#"{{eventList: {{edges: [{{node: {{id: "{key}", origAddr: "0.0.0.1", cipher: 1234, subjectCountry: "US", confidence: 0.800000011920929}}}}]}}}}"#
            )
        );

        let lookup_query = format!(
            "{{ event(id: \"{key}\") {{ id, ... on SuspiciousTlsTraffic {{ origAddr }} }} }}"
        );
        let res = schema.execute_as_system_admin(&lookup_query).await;
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{event: {{id: "{key}", origAddr: "0.0.0.1"}}}}"#)
        );
    }

    #[tokio::test]
    async fn event_list_blocklist_radius() {
        use review_database::event::BlocklistRadiusFields;

        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = BlocklistRadiusFields {
            sensor: "sensor1".to_string(),
            orig_addr: Ipv4Addr::LOCALHOST.into(),
            orig_port: 1812,
            resp_addr: Ipv4Addr::new(127, 0, 0, 2).into(),
            resp_port: 1812,
            proto: 17,
            start_time: timestamp.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            id: 1,
            code: 1,
            resp_code: 2,
            auth: "authenticator".to_string(),
            resp_auth: "response_authenticator".to_string(),
            user_name: vec![0x75, 0x73, 0x65, 0x72],
            user_passwd: vec![0x70, 0x61, 0x73, 0x73],
            chap_passwd: vec![0x63, 0x68, 0x61, 0x70],
            nas_ip: Ipv4Addr::new(192, 168, 1, 1).into(),
            nas_port: 5000,
            state: vec![0x73, 0x74, 0x61, 0x74, 0x65],
            nas_id: vec![0x6e, 0x61, 0x73],
            nas_port_type: 15,
            message: "RADIUS message".to_string(),
            confidence: 0.9,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: timestamp,
            kind: EventKind::BlocklistRadius,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let key = db.put(&message).unwrap();

        let res = schema
            .execute_as_system_admin(
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
                    edges {{ node {{ id, ... on BlocklistRadius {{ origAddr,nasIp,userName,message }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            format!(
                r#"{{eventList: {{edges: [{{node: {{id: "{key}", origAddr: "127.0.0.1", nasIp: "192.168.1.1", userName: "75:73:65:72", message: "RADIUS message"}}}}]}}}}"#
            )
        );

        let lookup_query =
            format!("{{ event(id: \"{key}\") {{ id, ... on BlocklistRadius {{ origAddr }} }} }}");
        let res = schema.execute_as_system_admin(&lookup_query).await;
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{event: {{id: "{key}", origAddr: "127.0.0.1"}}}}"#)
        );
    }

    #[tokio::test]
    async fn event_list_blocklist_malformed_dns() {
        use review_database::event::BlocklistMalformedDnsFields;

        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let fields = BlocklistMalformedDnsFields {
            sensor: "sensor1".to_string(),
            orig_addr: Ipv4Addr::LOCALHOST.into(),
            orig_port: 53000,
            resp_addr: Ipv4Addr::new(127, 0, 0, 2).into(),
            resp_port: 53,
            proto: 17,
            start_time: timestamp.timestamp_nanos_opt().unwrap(),
            duration: 1,
            orig_pkts: 2,
            resp_pkts: 3,
            orig_l2_bytes: 40,
            resp_l2_bytes: 60,
            trans_id: 42,
            flags: 0b1010,
            question_count: 1,
            answer_count: 1,
            authority_count: 0,
            additional_count: 0,
            query_count: 1,
            resp_count: 1,
            query_bytes: 20,
            resp_bytes: 40,
            query_body: vec![vec![0xde, 0xad]],
            resp_body: vec![vec![0xca, 0xfe]],
            confidence: 0.9,
            category: Some(EventCategory::InitialAccess),
        };

        let message = EventMessage {
            time: timestamp,
            kind: EventKind::BlocklistMalformedDns,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        let key = db.put(&message).unwrap();

        let res = schema
            .execute_as_system_admin(
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
                    edges {{ node {{ id, ... on BlocklistMalformedDns {{ origAddr,respAddr,transId,queryBody,respBody }} }} }} \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            format!(
                r#"{{eventList: {{edges: [{{node: {{id: "{key}", origAddr: "127.0.0.1", respAddr: "127.0.0.2", transId: 42, queryBody: ["de:ad"], respBody: ["ca:fe"]}}}}]}}}}"#
            )
        );

        let lookup_query = format!(
            "{{ event(id: \"{key}\") {{ id, ... on BlocklistMalformedDns {{ origAddr }} }} }}"
        );
        let res = schema.execute_as_system_admin(&lookup_query).await;
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{event: {{id: "{key}", origAddr: "127.0.0.1"}}}}"#)
        );
    }

    /// Basic smoke test for the eventTriageList GraphQL API.
    ///
    /// This test validates that:
    /// 1. The eventTriageList GraphQL API endpoint exists and accepts the correct parameters
    /// 2. The API returns a valid response structure without errors
    /// 3. The triagePolicies filter parameter is accepted
    ///
    /// Note: Full integration testing of triage policy matching requires more complex setup
    /// involving review-database internals. This test provides basic API validation.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn event_triage_list() {
        use review_database::event::{
            DgaFields, DnsEventFields, HttpEventFields, HttpThreatFields,
        };

        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let triage_map = store.triage_policy_map();

        let base_ts = NaiveDate::from_ymd_opt(2024, 1, 1)
            .unwrap()
            .and_hms_micro_opt(0, 0, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        // 1. Insert multiple detection events
        // Event 1: Unlabeled Outlier(cluster_id = None) - Score 0.9
        let unlabeled_outlier = HttpThreatFields {
            time: base_ts,
            start_time: base_ts.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            sensor: "sensor1".to_string(),
            orig_addr: Ipv4Addr::new(192, 168, 1, 1).into(),
            orig_port: 10001,
            resp_addr: Ipv4Addr::new(10, 0, 0, 1).into(),
            resp_port: 80,
            proto: 6,
            method: "GET".to_string(),
            host: "unlabeled.com".to_string(),
            uri: "/malware".to_string(),
            referer: String::new(),
            version: "HTTP/1.1".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: "text/html".to_string(),
            cache_control: String::new(),
            filenames: vec![],
            mime_types: vec![],
            body: vec![],
            state: String::new(),
            db_name: String::new(),
            rule_id: 0,
            matched_to: String::new(),
            cluster_id: None,
            attack_kind: String::new(),
            confidence: 1.0,
            category: Some(EventCategory::CommandAndControl),
        };
        db.put(&EventMessage {
            time: base_ts,
            kind: EventKind::HttpThreat,
            fields: bincode::serialize(&unlabeled_outlier).unwrap(),
        })
        .unwrap();

        // Event 2: HttpThreat(cluster_id = Some) - Score 0.9
        let http_threat_fields = HttpThreatFields {
            time: base_ts,
            start_time: base_ts.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            sensor: "sensor1".to_string(),
            orig_addr: Ipv4Addr::new(192, 168, 1, 1).into(),
            orig_port: 10001,
            resp_addr: Ipv4Addr::new(10, 0, 0, 1).into(),
            resp_port: 80,
            proto: 6,
            method: "GET".to_string(),
            host: "http_threat.com".to_string(),
            uri: "/malware".to_string(),
            referer: String::new(),
            version: "HTTP/1.1".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: "text/html".to_string(),
            cache_control: String::new(),
            filenames: vec![],
            mime_types: vec![],
            body: vec![],
            state: String::new(),
            db_name: String::new(),
            rule_id: 0,
            matched_to: String::new(),
            cluster_id: Some(1005),
            attack_kind: String::new(),
            confidence: 1.0,
            category: Some(EventCategory::CommandAndControl),
        };
        db.put(&EventMessage {
            time: base_ts,
            kind: EventKind::HttpThreat,
            fields: bincode::serialize(&http_threat_fields).unwrap(),
        })
        .unwrap();

        // Event 3: DnsCovertChannel - Score 0.9
        // Same score as HttpThreat, but different type.
        // We need to check which one comes first.
        let dns_fields = DnsEventFields {
            sensor: "sensor1".to_string(),
            start_time: base_ts.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            orig_addr: Ipv4Addr::new(192, 168, 1, 2).into(),
            orig_port: 10002,
            resp_addr: Ipv4Addr::new(8, 8, 8, 8).into(),
            resp_port: 53,
            proto: 17,
            query: "covert.example.com".to_string(),
            answer: vec![],
            trans_id: 1234,
            rtt: 10,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![],
            confidence: 1.0,
            category: Some(EventCategory::CommandAndControl),
        };
        db.put(&EventMessage {
            time: base_ts,
            kind: EventKind::DnsCovertChannel,
            fields: bincode::serialize(&dns_fields).unwrap(),
        })
        .unwrap();

        // Event 4: DomainGenerationAlgorithm - Score 0.8
        let dga_fields = DgaFields {
            start_time: base_ts.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            sensor: "sensor1".to_string(),
            orig_addr: Ipv4Addr::new(192, 168, 1, 3).into(),
            orig_port: 10003,
            resp_addr: Ipv4Addr::new(10, 0, 0, 2).into(),
            resp_port: 80,
            proto: 6,
            host: "dga.com".to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
            referer: String::new(),
            version: "HTTP/1.1".to_string(),
            user_agent: "Bot".to_string(),
            request_len: 50,
            response_len: 50,
            status_code: 404,
            status_msg: "Not Found".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: String::new(),
            cache_control: String::new(),
            filenames: vec![],
            mime_types: vec![],
            body: vec![],
            state: String::new(),
            confidence: 0.8,
            category: Some(EventCategory::InitialAccess),
        };
        db.put(&EventMessage {
            time: base_ts,
            kind: EventKind::DomainGenerationAlgorithm,
            fields: bincode::serialize(&dga_fields).unwrap(),
        })
        .unwrap();

        // Event 5: LockyRansomware - Score 0.8
        // Same score as DomainGenerationAlgorithm, but different type.
        // We need to check which one comes first.
        let locky_fields = DnsEventFields {
            sensor: "sensor1".to_string(),
            start_time: base_ts.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            orig_addr: Ipv4Addr::new(192, 168, 1, 4).into(),
            orig_port: 10004,
            resp_addr: Ipv4Addr::new(8, 8, 8, 8).into(),
            resp_port: 53,
            proto: 17,
            query: "locky.example.com".to_string(),
            answer: vec![],
            trans_id: 5678,
            rtt: 10,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![],
            confidence: 0.8,
            category: Some(EventCategory::InitialAccess),
        };
        db.put(&EventMessage {
            time: base_ts,
            kind: EventKind::LockyRansomware,
            fields: bincode::serialize(&locky_fields).unwrap(),
        })
        .unwrap();

        // Event 6: NonBrowser - Score 0.5
        let non_browser_fields = HttpEventFields {
            start_time: base_ts.timestamp_nanos_opt().unwrap(),
            duration: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_l2_bytes: 0,
            resp_l2_bytes: 0,
            sensor: "sensor1".to_string(),
            orig_addr: Ipv4Addr::new(192, 168, 1, 5).into(),
            orig_port: 10005,
            resp_addr: Ipv4Addr::new(10, 0, 0, 3).into(),
            resp_port: 8080,
            proto: 6,
            host: "api.com".to_string(),
            method: "POST".to_string(),
            uri: "/api".to_string(),
            referer: String::new(),
            version: "HTTP/1.1".to_string(),
            user_agent: "curl".to_string(),
            request_len: 20,
            response_len: 20,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: "application/json".to_string(),
            cache_control: String::new(),
            filenames: vec![],
            mime_types: vec![],
            body: vec![],
            state: String::new(),
            confidence: 0.5,
            category: Some(EventCategory::Discovery),
        };
        db.put(&EventMessage {
            time: base_ts,
            kind: EventKind::NonBrowser,
            fields: bincode::serialize(&non_browser_fields).unwrap(),
        })
        .unwrap();

        // 2. Insert triage policies
        let policy = database::TriagePolicy {
            id: 0,
            name: "Test Policy".to_string(),
            triage_exclusion_id: Vec::new(),
            packet_attr: Vec::new(),
            confidence: vec![
                database::Confidence {
                    threat_category: Some(database::EventCategory::CommandAndControl),
                    threat_kind: "dns covert channel".to_string(),
                    confidence: 0.0,
                    weight: Some(0.9),
                },
                database::Confidence {
                    threat_category: Some(database::EventCategory::CommandAndControl),
                    threat_kind: "http threat".to_string(),
                    confidence: 0.0,
                    weight: Some(0.9),
                },
                database::Confidence {
                    threat_category: Some(database::EventCategory::InitialAccess),
                    threat_kind: "dga".to_string(),
                    confidence: 0.0,
                    weight: Some(0.8),
                },
                database::Confidence {
                    threat_category: Some(database::EventCategory::InitialAccess),
                    threat_kind: "locky ransomware".to_string(),
                    confidence: 0.0,
                    weight: Some(0.8),
                },
                database::Confidence {
                    threat_category: Some(database::EventCategory::Discovery),
                    threat_kind: "non browser".to_string(),
                    confidence: 0.0,
                    weight: Some(0.5),
                },
            ],
            response: [database::Response {
                minimum_score: 0.3,
                kind: database::ResponseKind::Manual,
            }]
            .to_vec(),
            creation_time: base_ts,
            customer_id: None,
        };
        let policy_id = triage_map.put(policy).unwrap();

        // 3. Invoke eventTriageList
        let query = format!(
            r#"{{
                eventTriageList(filter: {{
                    start: "2024-01-01T00:00:00Z",
                    end: "2024-01-02T00:00:00Z",
                    triagePolicies: ["{policy_id}"]
                }}, count: 10) {{
                    __typename
                    ... on HttpThreat {{ origAddr, clusterId }}
                    ... on DnsCovertChannel {{ origAddr }}
                    ... on DomainGenerationAlgorithm {{ origAddr }}
                    ... on LockyRansomware {{ origAddr }}
                    ... on NonBrowser {{ origAddr }}
                }}
            }}"#
        );
        let res = schema.execute_as_system_admin(&query).await;

        // 4. Validate query results
        assert!(res.errors.is_empty(), "Errors: {:?}", res.errors);
        let json: serde_json::Value =
            serde_json::to_value(&res.data).expect("serializable response data");
        let events = json["eventTriageList"]
            .as_array()
            .expect("eventTriageList should be an array");
        assert_eq!(events.len(), 6);

        // Expected order of triaged events:
        // 1. Score 0.9: Unlabeled Outlier vs HttpThreat vs DnsCovertChannel.
        //    Priority:
        //    - HttpThreat(cluster_id = None)  ← treated as the unlabeled outlier
        //    - DnsCovertChannel
        //    - HttpThreat(cluster_id = Some(_))
        // 2. Score 0.8: DomainGenerationAlgorithm vs LockyRansomware.
        //    Priority:
        //    - DomainGenerationAlgorithm
        //    - LockyRansomware
        // 3. Score 0.5: NonBrowser.

        // first event should be unlabeled outlier (cluster_id = None)
        let cluster_id = events
            .first()
            .and_then(|event| event["clusterId"].as_str())
            .unwrap();
        assert_eq!(cluster_id, "", "first event should be unlabeled outlier");

        // Validate the full ordering matches the score/priority contract described
        let actual_order: Vec<&str> = events
            .iter()
            .map(|event| event["__typename"].as_str().expect("typename string"))
            .collect();
        let expected_order = vec![
            "HttpThreat",
            "DnsCovertChannel",
            "HttpThreat",
            "DomainGenerationAlgorithm",
            "LockyRansomware",
            "NonBrowser",
        ];
        assert_eq!(
            actual_order, expected_order,
            "events should be sorted by score and priority"
        );
    }

    #[tokio::test]
    async fn event_list_unusual_destination_pattern() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let timestamp = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 9, 453_829)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let start_time = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 0, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let end_time = NaiveDate::from_ymd_opt(2018, 1, 26)
            .unwrap()
            .and_hms_micro_opt(18, 30, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        let fields = UnusualDestinationPatternFields {
            sensor: "sensor1".to_string(),
            start_time: start_time.timestamp_nanos_opt().unwrap(),
            end_time: end_time.timestamp_nanos_opt().unwrap(),
            destination_ips: vec![
                Ipv4Addr::new(192, 168, 1, 1).into(),
                Ipv4Addr::new(192, 168, 1, 2).into(),
                Ipv4Addr::new(192, 168, 1, 3).into(),
            ],
            count: 150,
            expected_mean: 50.0,
            std_deviation: 20.0,
            z_score: 5.0,
            confidence: 0.85,
            category: Some(EventCategory::Reconnaissance),
        };

        let message = EventMessage {
            time: timestamp,
            kind: EventKind::UnusualDestinationPattern,
            fields: bincode::serialize(&fields).expect("serializable"),
        };
        db.put(&message).unwrap();

        let query = format!(
            "{{ \
                eventList(filter: {{ start:\"{timestamp}\" }}) {{ \
                    edges {{ \
                        node {{ \
                            ... on UnusualDestinationPattern {{ \
                                sensor \
                                respAddrs \
                                count \
                                expectedMean \
                                stdDeviation \
                                zScore \
                                confidence \
                                level \
                                learningMethod \
                            }} \
                        }} \
                    }} \
                    totalCount \
                }} \
            }}"
        );
        let res = schema.execute_as_system_admin(&query).await;
        let data = res.data.to_string();
        assert!(data.contains("sensor1"));
        assert!(data.contains("192.168.1.1"));
        assert!(data.contains("192.168.1.2"));
        assert!(data.contains("192.168.1.3"));
        assert!(data.contains("count: 150"));
        assert!(data.contains("expectedMean: 50.0"));
        assert!(data.contains("stdDeviation: 20.0"));
        assert!(data.contains("zScore: 5.0"));
        assert!(data.contains("confidence: 0.85"));
        assert!(data.contains("level: MEDIUM"));
        assert!(data.contains("learningMethod: SEMI_SUPERVISED"));
        assert!(data.contains(r#"totalCount: "1""#));
    }

    #[tokio::test]
    async fn event_list_with_triage_matches_event_list_cursor_semantics() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let timestamps: Vec<_> = (0u32..5)
            .map(|i| {
                NaiveDate::from_ymd_opt(2026, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 0, i)
                    .unwrap()
                    .and_local_timezone(Utc)
                    .unwrap()
            })
            .collect();
        for (i, ts) in timestamps.iter().enumerate() {
            let src = u32::try_from(i + 1).unwrap();
            db.put(&event_message_at(*ts, src, src + 100)).unwrap();
        }
        let start_ts = timestamps[0];

        let event_list_query = format!(
            "{{ eventList(filter: {{ start:\"{start_ts}\" }}, first: 3) {{ \
                edges {{ cursor node {{... on DnsCovertChannel {{ time }} }} }} \
                pageInfo {{ hasNextPage hasPreviousPage }} \
            }} }}",
        );
        let event_list_res = schema.execute_as_system_admin(&event_list_query).await;
        let event_list_data = event_list_res.data.to_string();

        let with_triage_query = format!(
            "{{ eventListWithTriage(filter: {{ start:\"{start_ts}\" }}, first: 3) {{ \
                edges {{ cursor node {{... on DnsCovertChannel {{ time }} }} }} \
                pageInfo {{ hasNextPage hasPreviousPage }} \
            }} }}",
        );
        let with_triage_res = schema.execute_as_system_admin(&with_triage_query).await;
        let with_triage_data = with_triage_res.data.to_string();

        let normalized_event_list = event_list_data.replacen("eventList", "eventListWithTriage", 1);
        assert_eq!(normalized_event_list, with_triage_data);
    }

    #[tokio::test]
    async fn event_list_with_triage_rejects_negative_policy_id() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let ts = NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts, 1, 2)).unwrap();

        let query = format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{ts}\" }}, \
                triage: {{ \
                    policies: [{{ \
                        id: -1, \
                        packetAttr: [], \
                        confidence: [], \
                        response: [] \
                    }}] \
                }} \
            ) {{ totalCount }} }}",
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert!(
            !res.errors.is_empty(),
            "expected error for negative policy id"
        );
        assert!(
            res.errors
                .iter()
                .any(|e| e.message.contains("non-negative")),
            "expected non-negative error, got {:?}",
            res.errors,
        );
    }

    #[tokio::test]
    async fn event_list_with_triage_policy_non_match_preserves_event() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let ts = NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts, 1, 2)).unwrap();

        // Policy with very high minimum_score so the event scores nothing.
        let query = format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{ts}\" }}, \
                triage: {{ \
                    policies: [{{ \
                        id: 7, \
                        packetAttr: [], \
                        confidence: [], \
                        response: [{{ minimumScore: 999.0, kind: MANUAL }}] \
                    }}] \
                }} \
            ) {{ \
                edges {{ node {{... on DnsCovertChannel {{ triageScores {{ policyId }} }} }} }} \
                totalCount \
            }} }}",
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventListWithTriage: {edges: [{node: {triageScores: null}}], totalCount: "1"}}"#
        );
    }

    #[tokio::test]
    async fn event_list_with_triage_inline_exclusion_cuts() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let ts = NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        // The default DnsCovertChannel test event has `query: "domain"`,
        // which `TriageExclusion::Domain(["domain"])` matches via its regex.
        db.put(&event_message_at(ts, 1, 2)).unwrap();

        let query = format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{ts}\" }}, \
                triage: {{ exclusions: [{{ domain: [\"domain\"] }}] }} \
            ) {{ \
                edges {{ node {{... on DnsCovertChannel {{ time }} }} }} \
                totalCount \
            }} }}",
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{eventListWithTriage: {edges: [], totalCount: "0"}}"#
        );
    }

    #[tokio::test]
    async fn event_list_with_triage_first_plus_one_on_surviving_events() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        // Insert 4 excluded events, then 2 surviving events.
        let mut idx = 0u32;
        let ts = |seconds: u32| {
            NaiveDate::from_ymd_opt(2026, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, seconds)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
        };
        for _ in 0..4 {
            // The default `event_message_at` builder uses `query: "domain"`,
            // matched by `TriageExclusion::Domain(["domain"])`.
            db.put(&event_message_at(ts(idx), idx + 1, idx + 100))
                .unwrap();
            idx += 1;
        }
        // Insert surviving events with a different query string.
        for _ in 0..2 {
            let fields = DnsEventFields {
                sensor: "sensor1".to_string(),
                start_time: ts(idx).timestamp_nanos_opt().unwrap(),
                duration: 0,
                orig_addr: Ipv4Addr::from(idx + 1).into(),
                orig_port: 10000,
                resp_addr: Ipv4Addr::from(idx + 100).into(),
                resp_port: 53,
                proto: 17,
                orig_pkts: 0,
                resp_pkts: 0,
                orig_l2_bytes: 0,
                resp_l2_bytes: 0,
                query: "survivor".into(),
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
            db.put(&EventMessage {
                time: ts(idx),
                kind: EventKind::DnsCovertChannel,
                fields: bincode::serialize(&fields).expect("serializable"),
            })
            .unwrap();
            idx += 1;
        }
        let start_ts = ts(0);

        // Request first=1 with exclusion that cuts the first 4. The resolver
        // must keep scanning and return the 5th event with hasNextPage=true.
        let query = format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{start_ts}\" }}, \
                triage: {{ exclusions: [{{ domain: [\"domain\"] }}] }}, \
                first: 1 \
            ) {{ \
                edges {{ node {{... on DnsCovertChannel {{ time query }} }} }} \
                pageInfo {{ hasNextPage }} \
                totalCount \
            }} }}",
        );
        let res = schema.execute_as_system_admin(&query).await;
        let data = res.data.to_string();
        assert!(data.contains(r#"query: "survivor""#), "got: {data}");
        assert!(data.contains("hasNextPage: true"), "got: {data}");
        assert!(data.contains(r#"totalCount: "2""#), "got: {data}");
    }

    #[tokio::test]
    async fn event_list_with_triage_schema_rejects_filter_triage_policies() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(
                r#"{ eventListWithTriage(filter: { triagePolicies: ["1"] }) { totalCount } }"#,
            )
            .await;
        assert!(!res.errors.is_empty(), "expected schema validation error");
    }

    #[tokio::test]
    async fn event_list_with_triage_exclusion_flattens_and_rejects_empty() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let ts = NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        db.put(&event_message_at(ts, 1, 2)).unwrap();

        // Single multi-field exclusion: ipAddress (no match) + domain (matches).
        let query_combined = format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{ts}\" }}, \
                triage: {{ exclusions: [{{ \
                    ipAddress: {{ hosts: [\"99.99.99.99\"], networks: [], ranges: [] }}, \
                    domain: [\"domain\"] \
                }}] }} \
            ) {{ totalCount }} }}",
        );
        let res_combined = schema.execute_as_system_admin(&query_combined).await;
        assert_eq!(
            res_combined.data.to_string(),
            r#"{eventListWithTriage: {totalCount: "0"}}"#
        );

        // Equivalent two-element list.
        let query_split = format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{ts}\" }}, \
                triage: {{ exclusions: [ \
                    {{ ipAddress: {{ hosts: [\"99.99.99.99\"], networks: [], ranges: [] }} }}, \
                    {{ domain: [\"domain\"] }} \
                ] }} \
            ) {{ totalCount }} }}",
        );
        let res_split = schema.execute_as_system_admin(&query_split).await;
        assert_eq!(
            res_split.data.to_string(),
            r#"{eventListWithTriage: {totalCount: "0"}}"#
        );

        // Empty exclusion is rejected.
        let query_empty = format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{ts}\" }}, \
                triage: {{ exclusions: [{{}}] }} \
            ) {{ totalCount }} }}",
        );
        let res_empty = schema.execute_as_system_admin(&query_empty).await;
        assert!(
            !res_empty.errors.is_empty(),
            "expected error for empty exclusion"
        );

        // An ipAddress group with all sub-fields empty is also treated as no
        // populated field and rejected.
        let query_empty_group = format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{ts}\" }}, \
                triage: {{ exclusions: [{{ \
                    ipAddress: {{ hosts: [], networks: [], ranges: [] }} \
                }}] }} \
            ) {{ totalCount }} }}",
        );
        let res_empty_group = schema.execute_as_system_admin(&query_empty_group).await;
        assert!(
            !res_empty_group.errors.is_empty(),
            "expected error for exclusion with empty ipAddress group"
        );
    }

    #[tokio::test]
    async fn event_list_with_triage_total_count_matches_surviving() {
        let schema = TestSchema::new().await;
        let store = schema.store();
        let db = store.events();
        let mut idx = 0u32;
        let ts = |seconds: u32| {
            NaiveDate::from_ymd_opt(2026, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, seconds)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
        };
        // 3 events with default query "domain" (excluded), 2 with "survivor".
        for _ in 0..3 {
            db.put(&event_message_at(ts(idx), idx + 1, idx + 100))
                .unwrap();
            idx += 1;
        }
        for _ in 0..2 {
            let fields = DnsEventFields {
                sensor: "sensor1".to_string(),
                start_time: ts(idx).timestamp_nanos_opt().unwrap(),
                duration: 0,
                orig_addr: Ipv4Addr::from(idx + 1).into(),
                orig_port: 10000,
                resp_addr: Ipv4Addr::from(idx + 100).into(),
                resp_port: 53,
                proto: 17,
                orig_pkts: 0,
                resp_pkts: 0,
                orig_l2_bytes: 0,
                resp_l2_bytes: 0,
                query: "survivor".into(),
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
            db.put(&EventMessage {
                time: ts(idx),
                kind: EventKind::DnsCovertChannel,
                fields: bincode::serialize(&fields).expect("serializable"),
            })
            .unwrap();
            idx += 1;
        }
        let start_ts = ts(0);

        let query = format!(
            "{{ eventListWithTriage( \
                filter: {{ start:\"{start_ts}\" }}, \
                triage: {{ exclusions: [{{ domain: [\"domain\"] }}] }}, \
                first: 100 \
            ) {{ \
                edges {{ node {{... on DnsCovertChannel {{ time }} }} }} \
                totalCount \
            }} }}",
        );
        let res = schema.execute_as_system_admin(&query).await;
        let data = res.data.to_string();
        assert!(data.contains(r#"totalCount: "2""#), "got: {data}");
        // Both surviving events should be in edges (count of "time:" occurrences = 2).
        assert_eq!(data.matches("time:").count(), 2, "got: {data}");
    }
}
