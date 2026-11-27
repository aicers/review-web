//! The collection status of device identification and the candidate
//! unregistered internal ranges.

use async_graphql::{Context, Enum, Object, Result, SimpleObject, StringNumber, types::ID};
use ipnet::IpNet;
use review_database::{
    DaiCatchupGap, DaiCollectionStatus, DaiCursorLag, DaiDailyCount, DaiIgnoredRange,
    DaiKindReceipt, DaiRangeCandidate, DaiSensorCollection, DaiSiteCollection,
};

use super::{
    DaiObservationKind, accessible_customer, dai_refusal, request_time, timestamp,
    writable_customer,
};
use crate::graphql::{Role, RoleGuard, timestamp::Timestamp};

/// The number of nanoseconds in a second.
const NANOS_PER_SEC: i64 = 1_000_000_000;
/// The number of seconds in a day.
const SECS_PER_DAY: i64 = 86_400;

#[derive(Default)]
pub(super) struct DaiCollectionQuery;

#[Object]
impl DaiCollectionQuery {
    /// The customer's device identification collection status now.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_collection_status(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
    ) -> Result<DaiCollection> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        let now = request_time(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let inner = store
            .dai_collection_status(customer_id, now)
            .map_err(dai_refusal)?;
        Ok(DaiCollection { inner })
    }

    /// The customer's candidate unregistered internal ranges now, the
    /// ignored ones left out.
    ///
    /// A candidate is accepted by adding it to the customer's networks with
    /// `replaceCustomerNetworks`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_range_candidates(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
    ) -> Result<Vec<DaiRangeCandidateEntry>> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        let now = request_time(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        Ok(store
            .dai_range_candidates(customer_id, now)
            .map_err(dai_refusal)?
            .into_iter()
            .map(|inner| DaiRangeCandidateEntry { inner })
            .collect())
    }

    /// The ranges the customer ignores, ordered by range.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_ignored_ranges(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
    ) -> Result<Vec<DaiIgnoredRangeEntry>> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        let store = crate::graphql::get_store(ctx)?;
        Ok(store
            .dai_ignored_ranges(customer_id)
            .map_err(dai_refusal)?
            .into_iter()
            .map(|inner| DaiIgnoredRangeEntry { inner })
            .collect())
    }
}

#[derive(Default)]
pub(super) struct DaiCollectionMutation;

#[Object]
impl DaiCollectionMutation {
    /// Ignores the candidate range `range` for the customer, recording the
    /// time and `account`, and returns the range normalized to its network
    /// address.
    ///
    /// `account` is the account name of the user who ignores the range, as
    /// the caller knows it; it is stored trimmed, and an empty one is
    /// refused. Ignoring a range already ignored changes nothing.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn ignore_dai_range_candidate(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        range: String,
        account: String,
    ) -> Result<String> {
        let (customer_id, _lock, store) = writable_customer(ctx, &customer_id).await?;
        let range = parse_range(&range)?;
        let account = account.trim();
        if account.is_empty() {
            return Err("the account that ignores the range must not be empty".into());
        }
        let now = request_time(ctx)?;
        let range = store
            .ignore_dai_range(customer_id, range, account, now)
            .map_err(dai_refusal)?;
        Ok(range.to_string())
    }

    /// Stops ignoring the range `range` for the customer, and returns
    /// whether it was ignored.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn unignore_dai_range_candidate(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        range: String,
    ) -> Result<bool> {
        let (customer_id, _lock, store) = writable_customer(ctx, &customer_id).await?;
        let range = parse_range(&range)?;
        store
            .unignore_dai_range(customer_id, range)
            .map_err(dai_refusal)
    }
}

/// Parses `text` as an IP network.
fn parse_range(text: &str) -> Result<IpNet> {
    text.trim()
        .parse()
        .map_err(|_| format!("range {text:?} is not an IP network").into())
}

/// Returns the UTC date `date`, days since the UNIX epoch, as `YYYY-MM-DD`.
fn date_text(date: i32) -> Result<String> {
    let start = jiff::Timestamp::from_second(i64::from(date) * SECS_PER_DAY)
        .map_err(|_| format!("date {date} is outside the supported range"))?;
    Ok(start.strftime("%Y-%m-%d").to_string())
}

/// The customer's collection status.
struct DaiCollection {
    inner: DaiCollectionStatus,
}

#[Object(name = "DaiCollectionStatus")]
impl DaiCollection {
    /// Each stored site, in token order.
    async fn sites(&self) -> Vec<DaiSiteCollectionEntry<'_>> {
        self.inner
            .sites
            .iter()
            .map(|inner| DaiSiteCollectionEntry { inner })
            .collect()
    }

    /// Each sensor of the customer, in name order.
    async fn sensors(&self) -> Vec<DaiSensorCollectionEntry<'_>> {
        self.inner
            .sensors
            .iter()
            .map(|inner| DaiSensorCollectionEntry { inner })
            .collect()
    }

    /// The catch-up gaps of the customer's sensors still stored, ordered by
    /// sensor, kind and start.
    async fn catchup_gaps(&self) -> Vec<DaiCatchupGapEntry<'_>> {
        self.inner
            .catchup_gaps
            .iter()
            .map(|inner| DaiCatchupGapEntry { inner })
            .collect()
    }

    /// The slots skipped by the catch-up limit, per date.
    async fn skipped_by_catchup(&self) -> Result<Vec<DaiDateCount>> {
        daily(&self.inner.skipped_by_catchup)
    }

    /// The relay DHCP observations whose site could not be determined, per
    /// date.
    async fn relay_site_unknown(&self) -> Result<Vec<DaiDateCount>> {
        daily(&self.inner.relay_site_unknown)
    }

    /// The observations filtered at receipt, per date.
    async fn filtered_at_receipt(&self) -> Result<Vec<DaiDateCount>> {
        daily(&self.inner.filtered_at_receipt)
    }

    /// The observations deleted before they were applied, per date.
    async fn not_applied(&self) -> Result<Vec<DaiDateCount>> {
        daily(&self.inner.not_applied)
    }

    /// The number of candidate unregistered ranges.
    async fn candidate_ranges(&self) -> StringNumber<usize> {
        StringNumber(self.inner.candidate_ranges)
    }
}

/// A count of a UTC date.
#[derive(SimpleObject)]
struct DaiDateCount {
    /// The UTC date, as `YYYY-MM-DD`.
    date: String,
    count: StringNumber<u64>,
}

fn daily(counts: &[DaiDailyCount]) -> Result<Vec<DaiDateCount>> {
    counts
        .iter()
        .map(|count| {
            Ok(DaiDateCount {
                date: date_text(count.date)?,
                count: StringNumber(count.count),
            })
        })
        .collect()
}

/// The collection state of a site.
struct DaiSiteCollectionEntry<'a> {
    inner: &'a DaiSiteCollection,
}

#[Object(name = "DaiSiteCollection")]
impl DaiSiteCollectionEntry<'_> {
    /// The site's active query configuration, progress and counts.
    async fn active_query(&self) -> super::active_query::DaiSiteActiveQuery<'_> {
        super::active_query::DaiSiteActiveQuery {
            inner: &self.inner.active_query,
        }
    }

    /// The site token.
    async fn site(&self) -> &str {
        &self.inner.site
    }

    /// The latest receipt of each of DHCP, Kerberos and NTLM, in that order.
    async fn receipts(&self) -> Vec<DaiReceiptEntry<'_>> {
        self.inner
            .receipts
            .iter()
            .map(|inner| DaiReceiptEntry { inner })
            .collect()
    }

    /// The site's sensors left out of the evidence gap because they
    /// received no record in the last 24 hours, in name order.
    async fn quiet_sensors(&self) -> &[String] {
        &self.inner.quiet_sensors
    }

    /// The sensor and kind pairs of the site left out of the evidence gap
    /// because their first send has not finished.
    async fn unsent_pairs(&self) -> Vec<DaiSensorKind> {
        self.inner
            .unsent_pairs
            .iter()
            .map(|(sensor, kind)| DaiSensorKind {
                sensor: sensor.clone(),
                kind: (*kind).into(),
            })
            .collect()
    }
}

/// A sensor and an observation kind.
#[derive(SimpleObject)]
struct DaiSensorKind {
    sensor: String,
    kind: DaiObservationKind,
}

/// The latest receipt of a kind's observations at a site.
struct DaiReceiptEntry<'a> {
    inner: &'a DaiKindReceipt,
}

#[Object(name = "DaiKindReceipt")]
impl DaiReceiptEntry<'_> {
    async fn kind(&self) -> DaiObservationKind {
        self.inner.kind.into()
    }

    /// The latest time a send carrying observations of the kind finished for
    /// one of the site's sensors; null if none ever did.
    async fn time(&self) -> Option<Timestamp> {
        self.inner.time.map(timestamp)
    }

    /// The sensor of that send.
    async fn sensor(&self) -> Option<&str> {
        self.inner.sensor.as_deref()
    }
}

/// The collection state of a sensor.
struct DaiSensorCollectionEntry<'a> {
    inner: &'a DaiSensorCollection,
}

#[Object(name = "DaiSensorCollection")]
impl DaiSensorCollectionEntry<'_> {
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// The sensor's current site; null if the customer has no default site.
    async fn site(&self) -> Option<&str> {
        self.inner.site.as_deref()
    }

    /// The time of the last record received from the sensor.
    async fn last_record_time(&self) -> Option<Timestamp> {
        self.inner.last_record_time.map(timestamp)
    }

    /// The cursor of each kind with one, in kind order.
    async fn cursors(&self) -> Vec<DaiCursorEntry<'_>> {
        self.inner
            .cursors
            .iter()
            .map(|inner| DaiCursorEntry { inner })
            .collect()
    }
}

/// The cursor of a sensor's kind and how far it lags.
struct DaiCursorEntry<'a> {
    inner: &'a DaiCursorLag,
}

#[Object(name = "DaiCursorLag")]
impl DaiCursorEntry<'_> {
    async fn kind(&self) -> DaiObservationKind {
        self.inner.kind.into()
    }

    /// The slot boundary up to which every slot of the kind is stored.
    async fn cursor(&self) -> Timestamp {
        timestamp(self.inner.cursor)
    }

    /// Now minus the cursor, in whole seconds.
    async fn lag_secs(&self) -> StringNumber<i64> {
        StringNumber(self.inner.lag / NANOS_PER_SEC)
    }
}

/// A range a sensor's kind skipped by the catch-up limit, `[start, end)`.
struct DaiCatchupGapEntry<'a> {
    inner: &'a DaiCatchupGap,
}

#[Object(name = "DaiCatchupGap")]
impl DaiCatchupGapEntry<'_> {
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    async fn kind(&self) -> DaiObservationKind {
        self.inner.kind.into()
    }

    async fn start(&self) -> Timestamp {
        timestamp(self.inner.start)
    }

    /// The end, exclusive.
    async fn end(&self) -> Timestamp {
        timestamp(self.inner.end)
    }
}

/// The evidence a range count comes from.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_protocol::types::DaiRangeEvidence")]
enum DaiRangeEvidence {
    /// The sensor's own records.
    Sensor,
}

/// The number of values of a candidate range from one evidence.
#[derive(SimpleObject)]
struct DaiRangeEvidenceCount {
    evidence: DaiRangeEvidence,
    /// The number of (sensor, date) values of the range in the window.
    count: StringNumber<u64>,
}

/// A candidate unregistered internal range of a customer.
struct DaiRangeCandidateEntry {
    inner: DaiRangeCandidate,
}

#[Object(name = "DaiRangeCandidate")]
impl DaiRangeCandidateEntry {
    /// The range, as a network address.
    async fn range(&self) -> String {
        self.inner.range.to_string()
    }

    /// The largest number of distinct addresses one sensor saw in the range
    /// on one date of the window.
    async fn seen_addrs(&self) -> StringNumber<u64> {
        StringNumber(self.inner.seen_addrs)
    }

    /// Whether `seenAddrs` is a lower bound.
    async fn seen_addrs_at_least(&self) -> bool {
        self.inner.seen_addrs_at_least
    }

    /// The number of values of the range per evidence; every evidence is
    /// listed.
    async fn values(&self) -> Vec<DaiRangeEvidenceCount> {
        self.inner
            .values
            .iter()
            .map(|(evidence, count)| DaiRangeEvidenceCount {
                evidence: (*evidence).into(),
                count: StringNumber(*count),
            })
            .collect()
    }

    /// The first UTC date of the window with a value, as `YYYY-MM-DD`.
    async fn first_date(&self) -> Result<String> {
        date_text(self.inner.first_date)
    }

    /// The last UTC date of the window with a value, as `YYYY-MM-DD`.
    async fn last_date(&self) -> Result<String> {
        date_text(self.inner.last_date)
    }

    /// The tokens of the sites the contributing sensors were in, sorted.
    async fn sites(&self) -> &[String] {
        &self.inner.sites
    }

    /// Whether the range lies within `100.64.0.0/10`.
    async fn cgnat(&self) -> bool {
        self.inner.cgnat
    }
}

/// A range a customer ignores.
struct DaiIgnoredRangeEntry {
    inner: DaiIgnoredRange,
}

#[Object(name = "DaiIgnoredRange")]
impl DaiIgnoredRangeEntry {
    /// The range, as a network address.
    async fn range(&self) -> String {
        self.inner.range.to_string()
    }

    /// When it was ignored.
    async fn ignored_at(&self) -> Timestamp {
        timestamp(self.inner.ignored_at)
    }

    /// The name of the account that ignored it.
    async fn account(&self) -> &str {
        &self.inner.account
    }
}
