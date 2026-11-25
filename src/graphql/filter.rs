use async_graphql::Enum;
use review_database::{self as database};
use review_protocol::types as protocol;

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

/// The detection model that produced a detection event.
///
/// A `detectionModels` filter matches an event exactly when its detection
/// model is one of the listed values.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "protocol::DetectionModel")]
pub(super) enum DetectionModel {
    WatchlistMatch,
    CryptocurrencyMiningPool,
    LockyRansomware,
    SuspiciousTlsTraffic,
    PortScan,
    MultiHostPortScan,
    ExternalDdos,
    RdpBruteForce,
    FtpBruteForce,
    LdapBruteForce,
    RepeatedHttpSessions,
    FtpPlainText,
    LdapPlainText,
    NonBrowser,
    TorExitNode,
    DomainGenerationAlgorithm,
    DnsCovertChannel,
    UnusualDestinationPattern,
    LabelDbMatch,
    FarOutlier,
    WindowOutlier,
}

/// The kind of the raw event a detection event is about.
///
/// A `rawEventKinds` filter matches an event exactly when its raw event kind
/// is one of the listed values.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "protocol::RawEventKind")]
pub(super) enum RawEventKind {
    Conn,
    Dns,
    Http,
    Rdp,
    Smtp,
    Ntlm,
    Kerberos,
    Ssh,
    DceRpc,
    Ftp,
    Mqtt,
    Ldap,
    Tls,
    Smb,
    Nfs,
    Bootp,
    Dhcp,
    Radius,
    MalformedDns,
    Icmp,
    ProcessCreate,
    FileCreateTime,
    NetworkConnect,
    ProcessTerminate,
    ImageLoad,
    FileCreate,
    RegistryValueSet,
    RegistryKeyRename,
    FileCreateStreamHash,
    PipeEvent,
    DnsQuery,
    FileDelete,
    ProcessTamper,
    FileDeleteDetected,
    Netflow5,
    Netflow9,
}

#[cfg(test)]
mod tests {
    use async_graphql::resolver_utils::EnumType;
    use review_protocol::types as protocol;

    use super::{DetectionModel, RawEventKind};

    #[test]
    fn every_detection_model_round_trips() {
        let mut mapped = 0;
        for n in 0..=u32::from(u16::MAX) {
            let Ok(model) = protocol::DetectionModel::try_from(n) else {
                continue;
            };
            let graphql = DetectionModel::from(model);
            assert_eq!(protocol::DetectionModel::from(graphql), model);
            mapped += 1;
        }
        assert_eq!(mapped, DetectionModel::items().len());
    }

    #[test]
    fn every_raw_event_kind_round_trips() {
        let mut mapped = 0;
        for n in 0..=u32::from(u16::MAX) {
            let Ok(kind) = protocol::RawEventKind::try_from(n) else {
                continue;
            };
            let graphql = RawEventKind::from(kind);
            assert_eq!(protocol::RawEventKind::from(graphql), kind);
            mapped += 1;
        }
        assert_eq!(mapped, RawEventKind::items().len());
    }
}
