//! Point-in-time resolve: the subject an IP address names at a site, at a
//! time or over a window.

use async_graphql::{Context, Enum, InputObject, Object, Result, Union, types::ID};
use review_database::{
    DAI_RESOLVE_MAX_ITEMS, DaiComparedValue, DaiDecidingBinding, DaiEvidenceRef, DaiExplanation,
    DaiGapCause, DaiResolveAnswer, DaiResolveError, DaiResolveItem, DaiResolveItemError,
    DaiResolveWhen,
};

use super::{
    DaiObservationKind, accessible_customer, dai_refusal, nanos, parse_ip, request_time, timestamp,
};
use crate::graphql::{Role, RoleGuard, timestamp::Timestamp};

#[derive(Default)]
pub(super) struct DaiResolveQuery;

#[Object]
impl DaiResolveQuery {
    /// Resolves each of `items` to the subject its IP address names at its
    /// site, at its time or over its window, and returns one outcome per
    /// item, in order: an answer, or the item's own error.
    ///
    /// An item gives exactly one of `at`, or both `from` and `to`, a closed
    /// window. An item without `site` is resolved at the customer's one site
    /// in use, which a multi-site customer does not have. More than 1,000
    /// items refuse the whole call. With `withExplanation`, each answer
    /// carries the bindings that decided it and the causes of an evidence
    /// gap.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_resolve(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        items: Vec<DaiResolveItemInput>,
        #[graphql(default = false)] with_explanation: bool,
    ) -> Result<Vec<DaiResolveOutcome>> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        if items.len() > DAI_RESOLVE_MAX_ITEMS {
            return Err(DaiResolveError::TooManyItems { count: items.len() }
                .to_string()
                .into());
        }
        let now = request_time(ctx)?;
        // The items that parse go to review-database; each one that does not
        // keeps its place with its own failure.
        let mut valid: Vec<DaiResolveItem> = Vec::with_capacity(items.len());
        let failures: Vec<Option<DaiResolveItemFailure>> = items
            .into_iter()
            .map(|item| match item.parse() {
                Ok(item) => {
                    valid.push(item);
                    None
                }
                Err(failure) => Some(failure),
            })
            .collect();
        let store = crate::graphql::get_store(ctx)?;
        let mut answers = store
            .dai_resolve(customer_id, &valid, with_explanation, now)
            .map_err(dai_refusal)?
            .into_iter();
        failures
            .into_iter()
            .map(|failure| match failure {
                Some(failure) => Ok(DaiResolveOutcome::Error(failure)),
                None => match answers.next() {
                    Some(Ok(inner)) => Ok(DaiResolveOutcome::Answer(DaiResolveSubject { inner })),
                    Some(Err(error)) => Ok(DaiResolveOutcome::Error(error.into())),
                    None => Err("review-database answered fewer items than it was given".into()),
                },
            })
            .collect()
    }
}

/// One item to resolve: an IP address at a site, at a time or over a closed
/// window.
#[derive(InputObject)]
struct DaiResolveItemInput {
    /// The site token; null for the customer's one site in use, which only a
    /// customer that is not multi-site has.
    site: Option<String>,
    /// The IP address.
    ip: String,
    /// The time; given alone, without `from` and `to`.
    at: Option<Timestamp>,
    /// The start of the window; given with `to` and without `at`.
    from: Option<Timestamp>,
    /// The end of the window, inclusive; given with `from` and without
    /// `at`.
    to: Option<Timestamp>,
}

impl DaiResolveItemInput {
    /// Returns the item review-database takes, or the item's error.
    fn parse(self) -> Result<DaiResolveItem, DaiResolveItemFailure> {
        let ip = parse_ip(&self.ip, "ip").map_err(|message| DaiResolveItemFailure {
            code: DaiResolveItemErrorCode::InvalidIp,
            message,
        })?;
        let invalid_time = |message: String| DaiResolveItemFailure {
            code: DaiResolveItemErrorCode::InvalidTime,
            message,
        };
        let when = match (self.at, self.from, self.to) {
            (Some(at), None, None) => DaiResolveWhen::At(nanos(at, "at").map_err(invalid_time)?),
            (None, Some(from), Some(to)) => DaiResolveWhen::Window {
                from: nanos(from, "from").map_err(invalid_time)?,
                to: nanos(to, "to").map_err(invalid_time)?,
            },
            _ => {
                return Err(invalid_time(
                    "an item gives exactly one of `at`, or both `from` and `to`".to_string(),
                ));
            }
        };
        Ok(DaiResolveItem {
            site: self.site,
            ip,
            when,
        })
    }
}

/// The outcome of one resolve item.
#[derive(Union)]
enum DaiResolveOutcome {
    Answer(DaiResolveSubject),
    Error(DaiResolveItemFailure),
}

/// Why one resolve item has no answer.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
enum DaiResolveItemErrorCode {
    /// The site token is not one of the customer's sites.
    UnknownSite,
    /// The item has no site token and the customer is multi-site.
    SiteRequired,
    /// The item has no site token and the customer has no site at all.
    NoSite,
    /// The window's `from` is after its `to`.
    InvertedWindow,
    /// The IP address does not parse.
    InvalidIp,
    /// The item gives neither `at` nor a window, or both, or only one end of
    /// the window, or a time outside the years 1677 to 2262.
    InvalidTime,
}

/// The error of one resolve item, which fails only that item.
struct DaiResolveItemFailure {
    code: DaiResolveItemErrorCode,
    message: String,
}

impl From<DaiResolveItemError> for DaiResolveItemFailure {
    fn from(error: DaiResolveItemError) -> Self {
        let code = match error {
            DaiResolveItemError::UnknownSite { .. } => DaiResolveItemErrorCode::UnknownSite,
            DaiResolveItemError::SiteRequired => DaiResolveItemErrorCode::SiteRequired,
            DaiResolveItemError::NoSite => DaiResolveItemErrorCode::NoSite,
            DaiResolveItemError::InvertedWindow { .. } => DaiResolveItemErrorCode::InvertedWindow,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

#[Object(name = "DaiResolveItemError")]
impl DaiResolveItemFailure {
    /// Why the item has no answer.
    async fn code(&self) -> DaiResolveItemErrorCode {
        self.code
    }

    /// The cause, in words.
    async fn message(&self) -> &str {
        &self.message
    }
}

/// The kind of a resolve answer.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiSubjectKind")]
enum DaiSubjectKind {
    /// One device.
    Device,
    /// No device: the IP address itself.
    #[graphql(name = "IP_SUBJECT")]
    Ip,
    /// Two or more devices over the window.
    Ambiguous,
    /// The evidence for the site does not reach the time yet, or the time
    /// lies in a range skipped by the catch-up limit.
    EvidenceGap,
}

/// What decided a resolve answer: the kind of the observation that started
/// a binding, or the device an operator fixed at the address.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
enum DaiEvidenceSource {
    DhcpLease,
    DhcpServer,
    Kerberos,
    Ntlm,
    Service,
    SoftwareString,
    DnsName,
    IpActivity,
    /// The device an operator fixed at the address.
    OperatorFixedIp,
}

impl From<review_database::DaiEvidenceSource> for DaiEvidenceSource {
    fn from(source: review_database::DaiEvidenceSource) -> Self {
        use review_protocol::types::DaiObservationKind as Kind;

        match source {
            review_database::DaiEvidenceSource::OperatorFixedIp => Self::OperatorFixedIp,
            review_database::DaiEvidenceSource::Observation(kind) => match kind {
                Kind::DhcpLease => Self::DhcpLease,
                Kind::DhcpServer => Self::DhcpServer,
                Kind::Kerberos => Self::Kerberos,
                Kind::Ntlm => Self::Ntlm,
                Kind::Service => Self::Service,
                Kind::SoftwareString => Self::SoftwareString,
                Kind::DnsName => Self::DnsName,
                Kind::IpActivity => Self::IpActivity,
            },
        }
    }
}

/// The answer to one resolve item.
struct DaiResolveSubject {
    inner: DaiResolveAnswer,
}

#[Object(name = "DaiResolveAnswer")]
impl DaiResolveSubject {
    /// The kind of the answer.
    async fn kind(&self) -> DaiSubjectKind {
        self.inner.kind.into()
    }

    /// The subject id the evidence so far gives, also for an evidence gap:
    /// `dev:<device id>` when it selects exactly one device, the current id
    /// after merges; otherwise `ip:<site token>/<IP>` for a multi-site
    /// customer with device account identification on and the IP in one of
    /// its Intranet or Gateway networks, else `ip:<IP>`.
    async fn subject_id(&self) -> &str {
        &self.inner.subject
    }

    /// The token of the site the item was resolved at.
    async fn site(&self) -> &str {
        &self.inner.site
    }

    /// The current ids of the devices the evidence gives, in id order.
    async fn device_ids(&self) -> Vec<ID> {
        self.inner
            .devices
            .iter()
            .map(|device| ID(device.to_string()))
            .collect()
    }

    /// The distinct sources of the bindings and the fixed IP that decided
    /// the answer; empty for an IP subject.
    async fn evidence_sources(&self) -> Vec<DaiEvidenceSource> {
        self.inner
            .evidence_sources
            .iter()
            .map(|source| (*source).into())
            .collect()
    }

    /// The explanation; null unless `withExplanation` was set.
    async fn explanation(&self) -> Option<DaiResolveExplanation<'_>> {
        self.inner
            .explanation
            .as_ref()
            .map(|inner| DaiResolveExplanation { inner })
    }
}

/// The explanation of a resolve answer.
struct DaiResolveExplanation<'a> {
    inner: &'a DaiExplanation,
}

#[Object(name = "DaiExplanation")]
impl DaiResolveExplanation<'_> {
    /// The bindings that decided the answer, in start order.
    async fn bindings(&self) -> Vec<DaiResolveBinding<'_>> {
        self.inner
            .bindings
            .iter()
            .map(|inner| DaiResolveBinding { inner })
            .collect()
    }

    /// The causes of an evidence gap; empty if there is none.
    async fn gap_causes(&self) -> Vec<DaiEvidenceGapCause> {
        self.inner.gap_causes.iter().map(Into::into).collect()
    }
}

/// A binding that decided a resolve answer.
struct DaiResolveBinding<'a> {
    inner: &'a DaiDecidingBinding,
}

#[Object(name = "DaiDecidingBinding")]
impl DaiResolveBinding<'_> {
    /// The current id of the binding's device.
    async fn device_id(&self) -> ID {
        ID(self.inner.device.to_string())
    }

    async fn start(&self) -> Timestamp {
        timestamp(self.inner.start)
    }

    /// The effective end; null while the binding is open.
    async fn end(&self) -> Option<Timestamp> {
        self.inner.end.map(timestamp)
    }

    /// Whether `end` is an estimate, the last strong evidence time plus the
    /// inactivity time, rather than a stored close.
    async fn end_estimated(&self) -> bool {
        self.inner.end_estimated
    }

    /// The kind of the observation that started the binding.
    async fn evidence_kind(&self) -> Option<DaiObservationKind> {
        self.inner.evidence_kind.map(Into::into)
    }

    /// Up to 10 evidence rows at the address last seen within the binding
    /// and at or before the time (within the window), newest first.
    async fn evidence(&self) -> Vec<DaiResolveEvidence<'_>> {
        self.inner
            .evidence
            .iter()
            .map(|inner| DaiResolveEvidence { inner })
            .collect()
    }
}

/// An evidence row of an explanation: the kind, last seen time and sensor
/// of an observation applied at the address, and nothing of its body.
struct DaiResolveEvidence<'a> {
    inner: &'a DaiEvidenceRef,
}

#[Object(name = "DaiEvidenceRef")]
impl DaiResolveEvidence<'_> {
    async fn kind(&self) -> DaiObservationKind {
        self.inner.kind.into()
    }

    async fn time(&self) -> Timestamp {
        timestamp(self.inner.last_seen)
    }

    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }
}

/// A cause of an evidence gap.
#[derive(Union)]
#[graphql(name = "DaiGapCause")]
enum DaiEvidenceGapCause {
    AfterComparedTime(DaiAfterComparedTime),
    SkippedByCatchup(DaiSkippedByCatchup),
}

impl From<&DaiGapCause> for DaiEvidenceGapCause {
    fn from(cause: &DaiGapCause) -> Self {
        match cause {
            DaiGapCause::AfterComparedTime {
                sensor,
                value,
                time,
            } => {
                let (value, kind) = match value {
                    DaiComparedValue::Cursor(kind) => (DaiComparedValueKind::Cursor, Some(*kind)),
                    DaiComparedValue::EarliestPending(kind) => {
                        (DaiComparedValueKind::EarliestPending, Some(*kind))
                    }
                    DaiComparedValue::LastRecordTime => {
                        (DaiComparedValueKind::LastRecordTime, None)
                    }
                    DaiComparedValue::ResolverPoint => (DaiComparedValueKind::ResolverPoint, None),
                };
                Self::AfterComparedTime(DaiAfterComparedTime {
                    sensor: sensor.clone(),
                    value,
                    kind: kind.map(Into::into),
                    time: *time,
                })
            }
            DaiGapCause::SkippedByCatchup {
                sensor,
                kind,
                start,
                end,
            } => Self::SkippedByCatchup(DaiSkippedByCatchup {
                sensor: sensor.clone(),
                kind: (*kind).into(),
                start: *start,
                end: *end,
            }),
        }
    }
}

/// The value of a sensor that set its site's compared time.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(name = "DaiComparedValue")]
enum DaiComparedValueKind {
    /// The cursor of the sensor's pair of `kind`.
    Cursor,
    /// The earliest pending slot start of the sensor's pair of `kind`.
    EarliestPending,
    /// The sensor's last received record time.
    LastRecordTime,
    /// The sensor's resolver point.
    ResolverPoint,
}

/// The time (a window's end) is after its site's compared time: the
/// evidence for the site does not reach it yet.
struct DaiAfterComparedTime {
    sensor: String,
    value: DaiComparedValueKind,
    kind: Option<DaiObservationKind>,
    time: i64,
}

#[Object]
impl DaiAfterComparedTime {
    /// The sensor whose value set the compared time.
    async fn sensor(&self) -> &str {
        &self.sensor
    }

    /// Which value of the sensor it was.
    async fn value(&self) -> DaiComparedValueKind {
        self.value
    }

    /// The observation kind of a cursor or an earliest pending slot; null
    /// for the other values.
    async fn kind(&self) -> Option<DaiObservationKind> {
        self.kind
    }

    /// The compared time.
    async fn time(&self) -> Timestamp {
        timestamp(self.time)
    }
}

/// The time (a part of the window) lies in a range the sensor's pair of the
/// kind skipped by the catch-up limit, `[start, end)`.
struct DaiSkippedByCatchup {
    sensor: String,
    kind: DaiObservationKind,
    start: i64,
    end: i64,
}

#[Object]
impl DaiSkippedByCatchup {
    async fn sensor(&self) -> &str {
        &self.sensor
    }

    async fn kind(&self) -> DaiObservationKind {
        self.kind
    }

    async fn start(&self) -> Timestamp {
        timestamp(self.start)
    }

    /// The end of the skipped range, exclusive.
    async fn end(&self) -> Timestamp {
        timestamp(self.end)
    }
}

#[cfg(test)]
mod tests {
    use review_protocol::types::DaiObservationKind as Kind;

    use super::*;

    #[test]
    fn each_observation_kind_names_its_own_evidence_source() {
        let pairs = [
            (Kind::DhcpLease, DaiEvidenceSource::DhcpLease),
            (Kind::DhcpServer, DaiEvidenceSource::DhcpServer),
            (Kind::Kerberos, DaiEvidenceSource::Kerberos),
            (Kind::Ntlm, DaiEvidenceSource::Ntlm),
            (Kind::Service, DaiEvidenceSource::Service),
            (Kind::SoftwareString, DaiEvidenceSource::SoftwareString),
            (Kind::DnsName, DaiEvidenceSource::DnsName),
            (Kind::IpActivity, DaiEvidenceSource::IpActivity),
        ];
        for (kind, source) in pairs {
            let mapped =
                DaiEvidenceSource::from(review_database::DaiEvidenceSource::Observation(kind));
            assert!(mapped == source);
        }
        assert!(
            DaiEvidenceSource::from(review_database::DaiEvidenceSource::OperatorFixedIp)
                == DaiEvidenceSource::OperatorFixedIp
        );
    }
}
