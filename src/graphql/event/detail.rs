//! The GraphQL types of detection event details, one per review-protocol
//! `Detail` variant.
//!
//! A variant holding a struct exposes every field of that struct; a variant
//! holding nothing exposes only its detection model. An integer type wider
//! than a signed 32-bit integer is a `StringNumber`.

use async_graphql::{Object, SimpleObject, StringNumber, Union};
use review_protocol::types as protocol;

use super::detection::EndpointRole;
use crate::graphql::filter::DetectionModel;

/// What a detection model found, as its own detail.
#[derive(Union)]
pub(super) enum Detail<'a> {
    WatchlistMatch(WatchlistMatchDetail<'a>),
    CryptocurrencyMiningPool(CryptocurrencyMiningPoolDetail<'a>),
    LockyRansomware(LockyRansomwareDetail),
    SuspiciousTlsTraffic(SuspiciousTlsTrafficDetail),
    PortScan(PortScanDetail<'a>),
    MultiHostPortScan(MultiHostPortScanDetail<'a>),
    ExternalDdos(ExternalDdosDetail<'a>),
    RdpBruteForce(RdpBruteForceDetail<'a>),
    FtpBruteForce(FtpBruteForceDetail<'a>),
    LdapBruteForce(LdapBruteForceDetail<'a>),
    RepeatedHttpSessions(RepeatedHttpSessionsDetail<'a>),
    FtpPlainText(FtpPlainTextDetail),
    LdapPlainText(LdapPlainTextDetail),
    NonBrowser(NonBrowserDetail),
    TorExitNode(TorExitNodeDetail),
    DomainGenerationAlgorithm(DomainGenerationAlgorithmDetail),
    DnsCovertChannel(DnsCovertChannelDetail),
    UnusualDestinationPattern(UnusualDestinationPatternDetail<'a>),
}

impl<'a> From<&'a protocol::Detail> for Detail<'a> {
    fn from(detail: &'a protocol::Detail) -> Self {
        // No wildcard arm: a detail added to review-protocol must be mapped.
        match detail {
            protocol::Detail::WatchlistMatch(detail) => {
                Self::WatchlistMatch(WatchlistMatchDetail(detail))
            }
            protocol::Detail::CryptocurrencyMiningPool(detail) => {
                Self::CryptocurrencyMiningPool(CryptocurrencyMiningPoolDetail(detail))
            }
            protocol::Detail::LockyRansomware => Self::LockyRansomware(LockyRansomwareDetail),
            protocol::Detail::SuspiciousTlsTraffic => {
                Self::SuspiciousTlsTraffic(SuspiciousTlsTrafficDetail)
            }
            protocol::Detail::PortScan(detail) => Self::PortScan(PortScanDetail(detail)),
            protocol::Detail::MultiHostPortScan(detail) => {
                Self::MultiHostPortScan(MultiHostPortScanDetail(detail))
            }
            protocol::Detail::ExternalDdos(detail) => {
                Self::ExternalDdos(ExternalDdosDetail(detail))
            }
            protocol::Detail::RdpBruteForce(detail) => {
                Self::RdpBruteForce(RdpBruteForceDetail(detail))
            }
            protocol::Detail::FtpBruteForce(detail) => {
                Self::FtpBruteForce(FtpBruteForceDetail(detail))
            }
            protocol::Detail::LdapBruteForce(detail) => {
                Self::LdapBruteForce(LdapBruteForceDetail(detail))
            }
            protocol::Detail::RepeatedHttpSessions(detail) => {
                Self::RepeatedHttpSessions(RepeatedHttpSessionsDetail(detail))
            }
            protocol::Detail::FtpPlainText => Self::FtpPlainText(FtpPlainTextDetail),
            protocol::Detail::LdapPlainText => Self::LdapPlainText(LdapPlainTextDetail),
            protocol::Detail::NonBrowser => Self::NonBrowser(NonBrowserDetail),
            protocol::Detail::TorExitNode => Self::TorExitNode(TorExitNodeDetail),
            protocol::Detail::DomainGenerationAlgorithm => {
                Self::DomainGenerationAlgorithm(DomainGenerationAlgorithmDetail)
            }
            protocol::Detail::DnsCovertChannel => Self::DnsCovertChannel(DnsCovertChannelDetail),
            protocol::Detail::UnusualDestinationPattern(detail) => {
                Self::UnusualDestinationPattern(UnusualDestinationPatternDetail(detail))
            }
        }
    }
}

/// The detail of a `WatchlistMatch` detection event.
pub(super) struct WatchlistMatchDetail<'a>(&'a protocol::WatchlistMatchDetail);

#[Object]
impl WatchlistMatchDetail<'_> {
    async fn entry_id(&self) -> StringNumber<u64> {
        StringNumber(self.0.entry_id)
    }

    async fn matched_side(&self) -> EndpointRole {
        self.0.matched_side.into()
    }

    async fn raw_event_count(&self) -> StringNumber<u64> {
        StringNumber(self.0.raw_event_count)
    }

    async fn truncated_related_ips(&self) -> StringNumber<u64> {
        StringNumber(self.0.truncated_related_ips)
    }

    async fn closed_early(&self) -> bool {
        self.0.closed_early
    }
}

/// The detail of a `CryptocurrencyMiningPool` detection event.
pub(super) struct CryptocurrencyMiningPoolDetail<'a>(&'a protocol::CryptocurrencyMiningPoolDetail);

#[Object]
impl CryptocurrencyMiningPoolDetail<'_> {
    async fn coins(&self) -> &[String] {
        &self.0.coins
    }
}

/// The detail of a `LockyRansomware` detection event, which carries nothing but its
/// detection model.
pub(super) struct LockyRansomwareDetail;

#[Object]
impl LockyRansomwareDetail {
    /// The detection model, always `LOCKY_RANSOMWARE`.
    async fn detection_model(&self) -> DetectionModel {
        DetectionModel::LockyRansomware
    }
}

/// The detail of a `SuspiciousTlsTraffic` detection event, which carries nothing but its
/// detection model.
pub(super) struct SuspiciousTlsTrafficDetail;

#[Object]
impl SuspiciousTlsTrafficDetail {
    /// The detection model, always `SUSPICIOUS_TLS_TRAFFIC`.
    async fn detection_model(&self) -> DetectionModel {
        DetectionModel::SuspiciousTlsTraffic
    }
}

/// The detail of a `PortScan` detection event.
pub(super) struct PortScanDetail<'a>(&'a protocol::PortScanDetail);

#[Object]
impl PortScanDetail<'_> {
    async fn resp_ports(&self) -> &[u16] {
        &self.0.resp_ports
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }
}

/// The detail of a `MultiHostPortScan` detection event.
pub(super) struct MultiHostPortScanDetail<'a>(&'a protocol::MultiHostPortScanDetail);

#[Object]
impl MultiHostPortScanDetail<'_> {
    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn truncated_related_ips(&self) -> StringNumber<u64> {
        StringNumber(self.0.truncated_related_ips)
    }
}

/// The detail of a `ExternalDdos` detection event.
pub(super) struct ExternalDdosDetail<'a>(&'a protocol::ExternalDdosDetail);

#[Object]
impl ExternalDdosDetail<'_> {
    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn truncated_related_ips(&self) -> StringNumber<u64> {
        StringNumber(self.0.truncated_related_ips)
    }
}

/// The detail of a `RdpBruteForce` detection event.
pub(super) struct RdpBruteForceDetail<'a>(&'a protocol::RdpBruteForceDetail);

#[Object]
impl RdpBruteForceDetail<'_> {
    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn truncated_related_ips(&self) -> StringNumber<u64> {
        StringNumber(self.0.truncated_related_ips)
    }
}

/// The detail of a `FtpBruteForce` detection event.
pub(super) struct FtpBruteForceDetail<'a>(&'a protocol::FtpBruteForceDetail);

#[Object]
impl FtpBruteForceDetail<'_> {
    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn user_list(&self) -> &[String] {
        &self.0.user_list
    }

    async fn is_internal(&self) -> bool {
        self.0.is_internal
    }
}

/// The detail of a `LdapBruteForce` detection event.
pub(super) struct LdapBruteForceDetail<'a>(&'a protocol::LdapBruteForceDetail);

#[Object]
impl LdapBruteForceDetail<'_> {
    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }

    async fn user_pw_list(&self) -> Vec<LdapCredential<'_>> {
        self.0
            .user_pw_list
            .iter()
            .map(|(user, password)| LdapCredential { user, password })
            .collect()
    }
}

/// The detail of a `RepeatedHttpSessions` detection event.
pub(super) struct RepeatedHttpSessionsDetail<'a>(&'a protocol::RepeatedHttpSessionsDetail);

#[Object]
impl RepeatedHttpSessionsDetail<'_> {
    async fn orig_port(&self) -> u16 {
        self.0.orig_port
    }

    async fn resp_port(&self) -> u16 {
        self.0.resp_port
    }

    async fn proto(&self) -> u8 {
        self.0.proto
    }
}

/// The detail of a `FtpPlainText` detection event, which carries nothing but its
/// detection model.
pub(super) struct FtpPlainTextDetail;

#[Object]
impl FtpPlainTextDetail {
    /// The detection model, always `FTP_PLAIN_TEXT`.
    async fn detection_model(&self) -> DetectionModel {
        DetectionModel::FtpPlainText
    }
}

/// The detail of a `LdapPlainText` detection event, which carries nothing but its
/// detection model.
pub(super) struct LdapPlainTextDetail;

#[Object]
impl LdapPlainTextDetail {
    /// The detection model, always `LDAP_PLAIN_TEXT`.
    async fn detection_model(&self) -> DetectionModel {
        DetectionModel::LdapPlainText
    }
}

/// The detail of a `NonBrowser` detection event, which carries nothing but its
/// detection model.
pub(super) struct NonBrowserDetail;

#[Object]
impl NonBrowserDetail {
    /// The detection model, always `NON_BROWSER`.
    async fn detection_model(&self) -> DetectionModel {
        DetectionModel::NonBrowser
    }
}

/// The detail of a `TorExitNode` detection event, which carries nothing but its
/// detection model.
pub(super) struct TorExitNodeDetail;

#[Object]
impl TorExitNodeDetail {
    /// The detection model, always `TOR_EXIT_NODE`.
    async fn detection_model(&self) -> DetectionModel {
        DetectionModel::TorExitNode
    }
}

/// The detail of a `DomainGenerationAlgorithm` detection event, which carries nothing but its
/// detection model.
pub(super) struct DomainGenerationAlgorithmDetail;

#[Object]
impl DomainGenerationAlgorithmDetail {
    /// The detection model, always `DOMAIN_GENERATION_ALGORITHM`.
    async fn detection_model(&self) -> DetectionModel {
        DetectionModel::DomainGenerationAlgorithm
    }
}

/// The detail of a `DnsCovertChannel` detection event, which carries nothing but its
/// detection model.
pub(super) struct DnsCovertChannelDetail;

#[Object]
impl DnsCovertChannelDetail {
    /// The detection model, always `DNS_COVERT_CHANNEL`.
    async fn detection_model(&self) -> DetectionModel {
        DetectionModel::DnsCovertChannel
    }
}

/// The detail of a `UnusualDestinationPattern` detection event.
pub(super) struct UnusualDestinationPatternDetail<'a>(
    &'a protocol::UnusualDestinationPatternDetail,
);

#[Object]
impl UnusualDestinationPatternDetail<'_> {
    async fn count(&self) -> StringNumber<u64> {
        StringNumber(self.0.count)
    }

    async fn expected_mean(&self) -> f64 {
        self.0.expected_mean
    }

    async fn std_deviation(&self) -> f64 {
        self.0.std_deviation
    }

    async fn z_score(&self) -> f64 {
        self.0.z_score
    }

    async fn truncated_related_ips(&self) -> StringNumber<u64> {
        StringNumber(self.0.truncated_related_ips)
    }
}

/// A user name and password an LDAP brute-force attempt used.
#[derive(SimpleObject)]
pub(super) struct LdapCredential<'a> {
    /// The user name.
    user: &'a str,
    /// The password.
    password: &'a str,
}
