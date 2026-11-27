//! The GraphQL types of detection event details, one per review-protocol
//! `Detail` variant.
//!
//! A variant holding a struct exposes every field of that struct; a variant
//! holding nothing exposes only its detection model. An integer type wider
//! than a signed 32-bit integer is a `StringNumber`.

use async_graphql::{Object, SimpleObject, StringNumber, Union};
use review_protocol::types as protocol;

use super::detection::EndpointRole;
use crate::graphql::{filter::DetectionModel, timestamp::Timestamp};

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
    LabelDbMatch(LabelDbMatchDetail<'a>),
    FarOutlier(FarOutlierDetail<'a>),
    WindowOutlier(WindowOutlierDetail<'a>),
    EtSignature(EtSignatureDetail<'a>),
    EtPolicySignature(EtPolicySignatureDetail<'a>),
    SigmaSignature(SigmaSignatureDetail<'a>),
}

impl<'a> From<&'a protocol::Detail> for Detail<'a> {
    fn from(detail: &'a protocol::Detail) -> Self {
        // No wildcard arm: a detail added to review-protocol must be mapped.
        match detail {
            protocol::Detail::EtSignature(detail) => Self::EtSignature(EtSignatureDetail(detail)),
            protocol::Detail::EtPolicySignature(detail) => {
                Self::EtPolicySignature(EtPolicySignatureDetail(detail))
            }
            protocol::Detail::SigmaSignature(detail) => {
                Self::SigmaSignature(SigmaSignatureDetail(detail))
            }
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
            protocol::Detail::LabelDbMatch(detail) => {
                Self::LabelDbMatch(LabelDbMatchDetail(detail))
            }
            protocol::Detail::FarOutlier(detail) => Self::FarOutlier(FarOutlierDetail(detail)),
            protocol::Detail::WindowOutlier(detail) => {
                Self::WindowOutlier(WindowOutlierDetail(detail))
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

/// The detail of a `LabelDbMatch` detection event.
pub(super) struct LabelDbMatchDetail<'a>(&'a protocol::LabelDbMatchDetail);

/// The detail of a `LabelDbMatch` detection event: the label DB rule a raw
/// event matched.
#[Object]
impl LabelDbMatchDetail<'_> {
    /// The name of the label DB that holds the matched rule.
    async fn label_db(&self) -> &str {
        &self.0.label_db
    }

    /// The matched rule's id within `labelDb`.
    async fn rule_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.rule_id)
    }

    /// The matched rule's name.
    async fn rule_name(&self) -> &str {
        &self.0.rule_name
    }

    /// The signature that matched.
    async fn matched_to(&self) -> &str {
        &self.0.matched_to
    }

    /// The cluster of the round that the raw event belongs to.
    async fn cluster_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.cluster_id)
    }

    /// The rule's confidence, 0–1; null when the rule has none.
    async fn rule_confidence(&self) -> Option<f32> {
        self.0.rule_confidence
    }

    /// How well the rule matched, 0–1.
    async fn match_score(&self) -> f32 {
        self.0.match_score
    }
}

/// The detail of a `FarOutlier` detection event, one field per form of the
/// measure; exactly one is non-null.
pub(super) struct FarOutlierDetail<'a>(&'a protocol::FarOutlierDetail);

/// The detail of a `FarOutlier` detection event, one field per form of the
/// measure; exactly one is non-null.
#[Object]
impl FarOutlierDetail<'_> {
    /// The prefix-approach form; non-null exactly for that form.
    async fn prefix(&self) -> Option<FarOutlierPrefixDetail<'_>> {
        // No wildcard arm: a form added to review-protocol must be mapped.
        match self.0 {
            protocol::FarOutlierDetail::Prefix {
                nearest_cluster_id,
                nearest_signature,
                matched_tokens,
                prefix_len,
                diverged_token,
                pattern_count,
                truncated_in_pattern,
            } => Some(FarOutlierPrefixDetail {
                nearest_cluster_id: *nearest_cluster_id,
                nearest_signature: nearest_signature.as_deref(),
                matched_tokens: *matched_tokens,
                prefix_len: *prefix_len,
                diverged_token: diverged_token.as_deref(),
                pattern_count: *pattern_count,
                truncated_in_pattern: *truncated_in_pattern,
            }),
        }
    }
}

/// The prefix-approach form of a `FarOutlier` detail, measured against the
/// best prefix.
pub(super) struct FarOutlierPrefixDetail<'a> {
    nearest_cluster_id: Option<u32>,
    nearest_signature: Option<&'a str>,
    matched_tokens: u32,
    prefix_len: u32,
    diverged_token: Option<&'a str>,
    pattern_count: u64,
    truncated_in_pattern: u64,
}

/// The prefix-approach form of a `FarOutlier` detail, measured against the
/// best prefix.
#[Object]
impl FarOutlierPrefixDetail<'_> {
    /// The cluster of the best prefix; null when there is no cluster prefix.
    async fn nearest_cluster_id(&self) -> Option<StringNumber<u32>> {
        self.nearest_cluster_id.map(StringNumber)
    }

    /// The signature of the best prefix's cluster; null when there is no
    /// cluster prefix.
    async fn nearest_signature(&self) -> Option<&str> {
        self.nearest_signature
    }

    /// The number of leading tokens of the outlier's pattern equal to the
    /// best prefix's, which is also the 0-based position where they diverge.
    async fn matched_tokens(&self) -> StringNumber<u32> {
        StringNumber(self.matched_tokens)
    }

    /// The best prefix's length in tokens.
    async fn prefix_len(&self) -> StringNumber<u32> {
        StringNumber(self.prefix_len)
    }

    /// The outlier's token at the position `matchedTokens` names; null when
    /// the pattern has no token there.
    async fn diverged_token(&self) -> Option<&str> {
        self.diverged_token
    }

    /// The number of the round's raw events with this pattern.
    async fn pattern_count(&self) -> StringNumber<u64> {
        StringNumber(self.pattern_count)
    }

    /// The number of this pattern's detection events dropped by the
    /// per-pattern cap.
    async fn truncated_in_pattern(&self) -> StringNumber<u64> {
        StringNumber(self.truncated_in_pattern)
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

/// The detail of a `WindowOutlier` detection event: a window of a time
/// series that lies far from every cluster of the model.
pub(super) struct WindowOutlierDetail<'a>(&'a protocol::WindowOutlierDetail);

/// The detail of a `WindowOutlier` detection event: a window of a time
/// series that lies far from every cluster of the model.
#[Object]
impl WindowOutlierDetail<'_> {
    /// The time series the window belongs to, `<policy id>/<IP>`.
    async fn time_series_id(&self) -> &str {
        &self.0.time_series_id
    }

    /// The start of the window that is the outlier.
    async fn window_start(&self) -> Timestamp {
        self.0.window_start.into()
    }

    /// The cluster whose centroid is nearest to the window.
    async fn nearest_cluster_id(&self) -> StringNumber<u32> {
        StringNumber(self.0.nearest_cluster_id)
    }

    /// The Euclidean distance from the window, after the time-series type's
    /// input transform, to the centroid of the nearest cluster.
    async fn distance(&self) -> f64 {
        self.0.distance
    }

    /// At most 3 slots of the window that differ most from the centroid.
    async fn top_slots(&self) -> Vec<SlotDeviation<'_>> {
        self.0.top_slots.iter().map(SlotDeviation).collect()
    }

    /// The number of `WindowOutlier` detections of this round and this
    /// policy that the per-round output cap cut.
    async fn truncated(&self) -> StringNumber<u64> {
        StringNumber(self.0.truncated)
    }

    /// The number of sessions in the detection's time window that were not
    /// requested as PCAP because of the PCAP request cap; null when the
    /// engine could not look the sessions up.
    async fn pcap_truncated(&self) -> Option<StringNumber<u64>> {
        self.0.pcap_truncated.map(StringNumber)
    }
}

/// One slot of a `WindowOutlier` window and how far it lies from the nearest
/// centroid.
pub(super) struct SlotDeviation<'a>(&'a protocol::SlotDeviation);

/// One slot of a `WindowOutlier` window and how far it lies from the nearest
/// centroid.
#[Object]
impl SlotDeviation<'_> {
    /// The start of the slot.
    async fn slot_start(&self) -> Timestamp {
        self.0.slot_start.into()
    }

    /// The slot's value, before the time-series type's input transform.
    async fn value(&self) -> f64 {
        self.0.value
    }

    /// The nearest centroid's value for this slot, with the input transform
    /// reversed.
    async fn centroid_value(&self) -> f64 {
        self.0.centroid_value
    }
}

// The union needs distinct object names for the three models even though the
// protocol shares their payload. Borrow the event just like the other details.
macro_rules! signature_detail {
    ($name:ident) => {
        pub(super) struct $name<'a>(&'a protocol::SignatureMatchDetail);

        #[Object]
        impl $name<'_> {
            async fn source(&self) -> crate::graphql::signature::SignatureSource {
                self.0.source.into()
            }
            async fn source_version(&self) -> &str {
                &self.0.source_version
            }
            async fn converter_version(&self) -> &str {
                &self.0.converter_version
            }
            async fn rule_id(&self) -> &str {
                &self.0.rule_id
            }
            async fn rule_revision(&self) -> Option<&str> {
                self.0.rule_revision.as_deref()
            }
            async fn rule_title(&self) -> &str {
                &self.0.rule_title
            }
            async fn classification(&self) -> Option<&str> {
                self.0.classification.as_deref()
            }
            async fn techniques(&self) -> &[String] {
                &self.0.techniques
            }
            async fn severity(&self) -> &str {
                &self.0.severity
            }
            async fn author(&self) -> Option<&str> {
                self.0.author.as_deref()
            }
            async fn matched_fields(&self) -> &[String] {
                &self.0.matched_fields
            }
            async fn home_net_fallback(&self) -> bool {
                self.0.home_net_fallback
            }
            async fn event_channel(&self) -> Option<&str> {
                self.0.event_channel.as_deref()
            }
            async fn event_id(&self) -> Option<StringNumber<u32>> {
                self.0.event_id.map(StringNumber)
            }
        }
    };
}

signature_detail!(EtSignatureDetail);
signature_detail!(EtPolicySignatureDetail);
signature_detail!(SigmaSignatureDetail);
