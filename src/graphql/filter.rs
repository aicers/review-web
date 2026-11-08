use anyhow::anyhow;
use async_graphql::Enum;
use num_traits::ToPrimitive;
use review_database::{self as database};

/// Traffic flow direction.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::event::FlowKind")]
pub(super) enum FlowKind {
    Inbound,
    Outbound,
    Internal,
}

/// Learning method.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::event::LearningMethod")]
pub(super) enum LearningMethod {
    Unsupervised,
    SemiSupervised,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(remote = "database::event::TrafficDirection")]
pub(super) enum TrafficDirection {
    From,
    To,
}

/// The kind of a detected event.
///
/// A `kinds` filter matches an event exactly when its kind is one of the
/// listed values.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(super) enum EventKind {
    DnsCovertChannel,
    HttpThreat,
    RdpBruteForce,
    RepeatedHttpSessions,
    ExtraThreat,
    TorConnection,
    DomainGenerationAlgorithm,
    FtpBruteForce,
    FtpPlainText,
    PortScan,
    MultiHostPortScan,
    NonBrowser,
    LdapBruteForce,
    LdapPlainText,
    ExternalDdos,
    CryptocurrencyMiningPool,
    BlocklistConn,
    BlocklistDns,
    BlocklistDceRpc,
    BlocklistFtp,
    BlocklistHttp,
    BlocklistKerberos,
    BlocklistLdap,
    BlocklistMqtt,
    BlocklistNfs,
    BlocklistNtlm,
    BlocklistRdp,
    BlocklistSmb,
    BlocklistSmtp,
    BlocklistSsh,
    BlocklistTls,
    WindowsThreat,
    NetworkThreat,
    LockyRansomware,
    SuspiciousTlsTraffic,
    BlocklistBootp,
    BlocklistDhcp,
    TorConnectionConn,
    BlocklistRadius,
    BlocklistMalformedDns,
    UnusualDestinationPattern,
}

impl From<EventKind> for database::EventKind {
    fn from(kind: EventKind) -> Self {
        match kind {
            EventKind::DnsCovertChannel => Self::DnsCovertChannel,
            EventKind::HttpThreat => Self::HttpThreat,
            EventKind::RdpBruteForce => Self::RdpBruteForce,
            EventKind::RepeatedHttpSessions => Self::RepeatedHttpSessions,
            EventKind::ExtraThreat => Self::ExtraThreat,
            EventKind::TorConnection => Self::TorConnection,
            EventKind::DomainGenerationAlgorithm => Self::DomainGenerationAlgorithm,
            EventKind::FtpBruteForce => Self::FtpBruteForce,
            EventKind::FtpPlainText => Self::FtpPlainText,
            EventKind::PortScan => Self::PortScan,
            EventKind::MultiHostPortScan => Self::MultiHostPortScan,
            EventKind::NonBrowser => Self::NonBrowser,
            EventKind::LdapBruteForce => Self::LdapBruteForce,
            EventKind::LdapPlainText => Self::LdapPlainText,
            EventKind::ExternalDdos => Self::ExternalDdos,
            EventKind::CryptocurrencyMiningPool => Self::CryptocurrencyMiningPool,
            EventKind::BlocklistConn => Self::BlocklistConn,
            EventKind::BlocklistDns => Self::BlocklistDns,
            EventKind::BlocklistDceRpc => Self::BlocklistDceRpc,
            EventKind::BlocklistFtp => Self::BlocklistFtp,
            EventKind::BlocklistHttp => Self::BlocklistHttp,
            EventKind::BlocklistKerberos => Self::BlocklistKerberos,
            EventKind::BlocklistLdap => Self::BlocklistLdap,
            EventKind::BlocklistMqtt => Self::BlocklistMqtt,
            EventKind::BlocklistNfs => Self::BlocklistNfs,
            EventKind::BlocklistNtlm => Self::BlocklistNtlm,
            EventKind::BlocklistRdp => Self::BlocklistRdp,
            EventKind::BlocklistSmb => Self::BlocklistSmb,
            EventKind::BlocklistSmtp => Self::BlocklistSmtp,
            EventKind::BlocklistSsh => Self::BlocklistSsh,
            EventKind::BlocklistTls => Self::BlocklistTls,
            EventKind::WindowsThreat => Self::WindowsThreat,
            EventKind::NetworkThreat => Self::NetworkThreat,
            EventKind::LockyRansomware => Self::LockyRansomware,
            EventKind::SuspiciousTlsTraffic => Self::SuspiciousTlsTraffic,
            EventKind::BlocklistBootp => Self::BlocklistBootp,
            EventKind::BlocklistDhcp => Self::BlocklistDhcp,
            EventKind::TorConnectionConn => Self::TorConnectionConn,
            EventKind::BlocklistRadius => Self::BlocklistRadius,
            EventKind::BlocklistMalformedDns => Self::BlocklistMalformedDns,
            EventKind::UnusualDestinationPattern => Self::UnusualDestinationPattern,
        }
    }
}

impl TryFrom<database::EventKind> for EventKind {
    type Error = anyhow::Error;

    fn try_from(kind: database::EventKind) -> Result<Self, Self::Error> {
        Ok(match kind {
            database::EventKind::DnsCovertChannel => Self::DnsCovertChannel,
            database::EventKind::HttpThreat => Self::HttpThreat,
            database::EventKind::RdpBruteForce => Self::RdpBruteForce,
            database::EventKind::RepeatedHttpSessions => Self::RepeatedHttpSessions,
            database::EventKind::ExtraThreat => Self::ExtraThreat,
            database::EventKind::TorConnection => Self::TorConnection,
            database::EventKind::DomainGenerationAlgorithm => Self::DomainGenerationAlgorithm,
            database::EventKind::FtpBruteForce => Self::FtpBruteForce,
            database::EventKind::FtpPlainText => Self::FtpPlainText,
            database::EventKind::PortScan => Self::PortScan,
            database::EventKind::MultiHostPortScan => Self::MultiHostPortScan,
            database::EventKind::NonBrowser => Self::NonBrowser,
            database::EventKind::LdapBruteForce => Self::LdapBruteForce,
            database::EventKind::LdapPlainText => Self::LdapPlainText,
            database::EventKind::ExternalDdos => Self::ExternalDdos,
            database::EventKind::CryptocurrencyMiningPool => Self::CryptocurrencyMiningPool,
            database::EventKind::BlocklistConn => Self::BlocklistConn,
            database::EventKind::BlocklistDns => Self::BlocklistDns,
            database::EventKind::BlocklistDceRpc => Self::BlocklistDceRpc,
            database::EventKind::BlocklistFtp => Self::BlocklistFtp,
            database::EventKind::BlocklistHttp => Self::BlocklistHttp,
            database::EventKind::BlocklistKerberos => Self::BlocklistKerberos,
            database::EventKind::BlocklistLdap => Self::BlocklistLdap,
            database::EventKind::BlocklistMqtt => Self::BlocklistMqtt,
            database::EventKind::BlocklistNfs => Self::BlocklistNfs,
            database::EventKind::BlocklistNtlm => Self::BlocklistNtlm,
            database::EventKind::BlocklistRdp => Self::BlocklistRdp,
            database::EventKind::BlocklistSmb => Self::BlocklistSmb,
            database::EventKind::BlocklistSmtp => Self::BlocklistSmtp,
            database::EventKind::BlocklistSsh => Self::BlocklistSsh,
            database::EventKind::BlocklistTls => Self::BlocklistTls,
            database::EventKind::WindowsThreat => Self::WindowsThreat,
            database::EventKind::NetworkThreat => Self::NetworkThreat,
            database::EventKind::LockyRansomware => Self::LockyRansomware,
            database::EventKind::SuspiciousTlsTraffic => Self::SuspiciousTlsTraffic,
            database::EventKind::BlocklistBootp => Self::BlocklistBootp,
            database::EventKind::BlocklistDhcp => Self::BlocklistDhcp,
            database::EventKind::TorConnectionConn => Self::TorConnectionConn,
            database::EventKind::BlocklistRadius => Self::BlocklistRadius,
            database::EventKind::BlocklistMalformedDns => Self::BlocklistMalformedDns,
            database::EventKind::UnusualDestinationPattern => Self::UnusualDestinationPattern,
            // `database::EventKind` is `#[non_exhaustive]`; a kind added
            // upstream reaches this arm until it is mapped above.
            other => {
                return Err(anyhow!(
                    "unmapped event kind discriminant {}",
                    other
                        .to_u32()
                        .map_or_else(|| format!("{other:?}"), |n| n.to_string())
                ));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use async_graphql::resolver_utils::EnumType;
    use num_traits::FromPrimitive;
    use review_database as database;

    use super::EventKind;

    #[test]
    fn every_database_event_kind_round_trips() {
        let mut mapped = 0;
        for n in 0..=255_u32 {
            let Some(kind) = database::EventKind::from_u32(n) else {
                continue;
            };
            let graphql = EventKind::try_from(kind)
                .unwrap_or_else(|e| panic!("discriminant {n} is not mapped: {e}"));
            assert_eq!(database::EventKind::from(graphql), kind);
            mapped += 1;
        }
        assert_eq!(mapped, EventKind::items().len());
    }
}
