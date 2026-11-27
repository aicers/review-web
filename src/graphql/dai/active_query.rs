//! Active query configuration and display-only answers.

use std::borrow::Cow;

use async_graphql::{
    Context, Enum, ID, InputObject, Object, Result, SimpleObject, StringNumber, Union,
};
use ipnet::IpNet;
use review_database as db;

use super::{accessible_customer, dai_refusal, parse_ip, timestamp, writable_customer_gated};
use crate::graphql::{Role, RoleGuard, timestamp::Timestamp};

/// The store's packet rate for an unstored default site.
const ACTIVE_QUERY_DEFAULT_RATE: u32 = 20;

/// The four active query kinds in stored order.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiActiveQueryKind")]
enum DaiActiveQueryKind {
    Ptr,
    Nbns,
    Mdns,
    Ssdp,
}

/// Why an IP is not currently being queried.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiActiveQueryStatus")]
enum DaiActiveQueryStatus {
    QueriesOff,
    NotQueryTarget,
    NotQueriedYet,
}

/// Whether active queries are enabled at a site.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiActiveQuerySiteState")]
enum DaiActiveQuerySiteState {
    CustomerOff,
    NoQueryRanges,
    On,
}

/// The variant of a query result, without its value.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
enum DaiActiveQueryResult {
    Value,
    NoName,
    NoResponse,
    NotSent,
}

impl<T> From<&db::DaiActiveQueryResult<T>> for DaiActiveQueryResult {
    fn from(value: &db::DaiActiveQueryResult<T>) -> Self {
        match value {
            db::DaiActiveQueryResult::Value(_) => Self::Value,
            db::DaiActiveQueryResult::NoName => Self::NoName,
            db::DaiActiveQueryResult::NoResponse => Self::NoResponse,
            db::DaiActiveQueryResult::NotSent => Self::NotSent,
        }
    }
}

#[derive(Default)]
pub(super) struct DaiActiveQueryQuery;

#[Object]
impl DaiActiveQueryQuery {
    /// The active query settings of each customer, in the requested order.
    /// One inaccessible customer refuses the whole call.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_active_query_settings(
        &self,
        ctx: &Context<'_>,
        customer_ids: Vec<ID>,
    ) -> Result<Vec<DaiActiveQuerySettings>> {
        let customers = customer_ids
            .iter()
            .map(|id| accessible_customer(ctx, id))
            .collect::<Result<Vec<_>>>()?;
        let store = crate::graphql::get_store(ctx)?;
        customers
            .into_iter()
            .map(|customer_id| {
                let inner = store
                    .dai_active_query_settings(customer_id)
                    .map_err(dai_refusal)?;
                Ok(DaiActiveQuerySettings { customer_id, inner })
            })
            .collect()
    }

    /// Every site's active query settings, in token order. An unstored
    /// default site is listed first with a null token, without writing it.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_active_query_sites(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
    ) -> Result<Vec<DaiActiveQuerySite>> {
        let customer = accessible_customer(ctx, &customer_id)?;
        let store = crate::graphql::get_store(ctx)?;
        let mut sites: Vec<_> = store
            .dai_active_query_sites(customer)
            .map_err(dai_refusal)?
            .into_iter()
            .map(|inner| DaiActiveQuerySite { inner })
            .collect();
        if !store
            .dai_sites(customer)
            .map_err(dai_refusal)?
            .iter()
            .any(|site| site.is_default)
        {
            sites.insert(
                0,
                DaiActiveQuerySite {
                    inner: db::DaiActiveQuerySite {
                        token: String::new(),
                        query_ranges: Vec::new(),
                        dns_servers: Vec::new(),
                        rate: ACTIVE_QUERY_DEFAULT_RATE,
                        revision: 0,
                    },
                },
            );
        }
        Ok(sites)
    }

    /// The IP's whole active answer history, including no-name and
    /// no-response rows and removed sites, in the store's order.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_active_answers(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        site: String,
        ip: String,
    ) -> Result<Vec<DaiActiveAnswer<'static>>> {
        let customer = accessible_customer(ctx, &customer_id)?;
        let ip = parse_ip(&ip, "ip")?;
        let store = crate::graphql::get_store(ctx)?;
        Ok(store
            .dai_active_answers(customer, &site, ip)
            .map_err(dai_refusal)?
            .into_iter()
            .map(DaiActiveAnswer::from)
            .collect())
    }
}

#[derive(Default)]
pub(super) struct DaiActiveQueryMutation;

#[Object]
impl DaiActiveQueryMutation {
    /// Replaces the customer's active query settings at the given revision.
    /// Refused during customer deletion. Waits for packets checked against
    /// earlier settings before storing and responding.
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn update_dai_active_query_settings(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        revision: StringNumber<u64>,
        input: DaiActiveQuerySettingsInput,
    ) -> Result<DaiActiveQuerySettings> {
        let (customer_id, _lock, _send, store) = writable_customer_gated(ctx, &customer_id).await?;
        let ranges = parse_ranges(&input.excluded_ranges, "excludedRanges")?;
        let inner = store
            .set_dai_active_query_settings(customer_id, revision.0, input.enabled, &ranges)
            .map_err(dai_refusal)?;
        Ok(DaiActiveQuerySettings { customer_id, inner })
    }

    /// Replaces a site's active query settings at the given revision.
    /// A null token ensures the default site before writing; an empty token
    /// is passed unchanged. Refused during customer deletion. Waits for
    /// packets checked against earlier settings before storing and responding.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn update_dai_active_query_site(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        token: Option<String>,
        revision: StringNumber<u64>,
        input: DaiActiveQuerySiteInput,
    ) -> Result<DaiActiveQuerySite> {
        let (customer, _lock, _send, store) = writable_customer_gated(ctx, &customer_id).await?;
        let ranges = parse_ranges(&input.query_ranges, "queryRanges")?;
        let dns = input
            .dns_servers
            .iter()
            .map(|ip| parse_ip(ip, "dnsServers"))
            .collect::<Result<Vec<_>, _>>()?;
        let rate = u32::try_from(input.rate).map_err(|_| "rate must not be negative")?;
        let token = match token {
            Some(token) => token,
            None => store.ensure_default_site(customer).map_err(dai_refusal)?,
        };
        let inner = store
            .set_dai_active_query_site(customer, &token, revision.0, &ranges, &dns, rate)
            .map_err(dai_refusal)?;
        Ok(DaiActiveQuerySite { inner })
    }
}

fn parse_ranges(texts: &[String], field: &str) -> Result<Vec<IpNet>> {
    texts
        .iter()
        .map(|text| {
            text.trim()
                .parse()
                .map_err(|_| format!("{field} {text:?} is not a CIDR network").into())
        })
        .collect()
}

/// The settable active query settings of a customer.
#[derive(InputObject)]
struct DaiActiveQuerySettingsInput {
    enabled: bool,
    excluded_ranges: Vec<String>,
}

/// The settable active query settings of a site.
#[derive(InputObject)]
struct DaiActiveQuerySiteInput {
    query_ranges: Vec<String>,
    dns_servers: Vec<String>,
    rate: i32,
}

struct DaiActiveQuerySettings {
    customer_id: u32,
    inner: db::DaiActiveQuerySettings,
}

#[Object]
impl DaiActiveQuerySettings {
    async fn customer_id(&self) -> ID {
        ID(self.customer_id.to_string())
    }
    async fn enabled(&self) -> bool {
        self.inner.enabled
    }
    async fn excluded_ranges(&self) -> Vec<String> {
        self.inner
            .excluded_ranges
            .iter()
            .map(ToString::to_string)
            .collect()
    }
    async fn revision(&self) -> StringNumber<u64> {
        StringNumber(self.inner.revision)
    }
}

struct DaiActiveQuerySite {
    inner: db::DaiActiveQuerySite,
}

#[Object]
impl DaiActiveQuerySite {
    async fn token(&self) -> Option<&str> {
        (!self.inner.token.is_empty()).then_some(self.inner.token.as_str())
    }
    async fn query_ranges(&self) -> Vec<String> {
        self.inner
            .query_ranges
            .iter()
            .map(ToString::to_string)
            .collect()
    }
    async fn dns_servers(&self) -> Vec<String> {
        self.inner
            .dns_servers
            .iter()
            .map(ToString::to_string)
            .collect()
    }
    async fn rate(&self) -> u32 {
        self.inner.rate
    }
    async fn revision(&self) -> StringNumber<u64> {
        StringNumber(self.inner.revision)
    }
}

#[derive(SimpleObject)]
struct DaiActiveQueryPtr<'a> {
    names: &'a [String],
}
#[derive(SimpleObject)]
struct DaiActiveQueryNoName {
    kind: DaiActiveQueryKind,
}
#[derive(SimpleObject)]
struct DaiActiveQueryNoResponse {
    kind: DaiActiveQueryKind,
}
#[derive(SimpleObject)]
struct DaiActiveQuerySsdpResponses<'a> {
    responses: Vec<DaiActiveQuerySsdp<'a>>,
}

/// A display-only active answer or a sent query without a name.
#[derive(Union)]
enum DaiActiveAnswerValue<'a> {
    Ptr(DaiActiveQueryPtr<'a>),
    Nbns(DaiActiveQueryNbns<'a>),
    Mdns(DaiActiveQueryMdns<'a>),
    Ssdp(DaiActiveQuerySsdpResponses<'a>),
    NoName(DaiActiveQueryNoName),
    NoResponse(DaiActiveQueryNoResponse),
}

pub(super) struct DaiActiveAnswer<'a> {
    inner: Cow<'a, db::DaiActiveAnswer>,
}

impl From<db::DaiActiveAnswer> for DaiActiveAnswer<'static> {
    fn from(inner: db::DaiActiveAnswer) -> Self {
        Self {
            inner: Cow::Owned(inner),
        }
    }
}

impl<'a> From<&'a db::DaiActiveAnswer> for DaiActiveAnswer<'a> {
    fn from(inner: &'a db::DaiActiveAnswer) -> Self {
        Self {
            inner: Cow::Borrowed(inner),
        }
    }
}

#[Object]
impl DaiActiveAnswer<'_> {
    async fn kind(&self) -> DaiActiveQueryKind {
        self.inner.kind.into()
    }
    async fn first_seen(&self) -> Timestamp {
        timestamp(self.inner.first_seen)
    }
    async fn last_seen(&self) -> Timestamp {
        timestamp(self.inner.last_seen)
    }
    async fn value(&self) -> Result<DaiActiveAnswerValue<'_>> {
        use db::{DaiActiveQueryResult as R, DaiActiveQueryValue as V};
        Ok(match &self.inner.value {
            R::Value(V::Ptr(names)) => DaiActiveAnswerValue::Ptr(DaiActiveQueryPtr { names }),
            R::Value(V::Nbns(inner)) => DaiActiveAnswerValue::Nbns(DaiActiveQueryNbns { inner }),
            R::Value(V::Mdns(inner)) => DaiActiveAnswerValue::Mdns(DaiActiveQueryMdns { inner }),
            R::Value(V::Ssdp(responses)) => {
                DaiActiveAnswerValue::Ssdp(DaiActiveQuerySsdpResponses {
                    responses: responses
                        .iter()
                        .map(|inner| DaiActiveQuerySsdp { inner })
                        .collect(),
                })
            }
            R::NoName => DaiActiveAnswerValue::NoName(DaiActiveQueryNoName {
                kind: self.inner.kind.into(),
            }),
            R::NoResponse => DaiActiveAnswerValue::NoResponse(DaiActiveQueryNoResponse {
                kind: self.inner.kind.into(),
            }),
            R::NotSent => return Err("an active answer cannot contain NotSent".into()),
        })
    }
}

struct DaiActiveQueryNbns<'a> {
    inner: &'a db::DaiActiveQueryNbns,
}
#[Object]
impl DaiActiveQueryNbns<'_> {
    async fn computer_name(&self) -> Option<&str> {
        self.inner.computer_name.as_deref()
    }
    async fn workgroup_or_domain(&self) -> Option<&str> {
        self.inner.workgroup_or_domain.as_deref()
    }
    async fn mac(&self) -> Option<String> {
        self.inner.mac.as_ref().map(|mac| {
            mac.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
    }
}
struct DaiActiveQueryMdns<'a> {
    inner: &'a db::DaiActiveQueryMdns,
}
#[Object]
impl DaiActiveQueryMdns<'_> {
    async fn host_name(&self) -> Option<&str> {
        self.inner.host_name.as_deref()
    }
    async fn service_types(&self) -> &[String] {
        &self.inner.service_types
    }
}
struct DaiActiveQuerySsdp<'a> {
    inner: &'a db::DaiActiveQuerySsdp,
}
#[Object]
impl DaiActiveQuerySsdp<'_> {
    async fn st(&self) -> Option<&str> {
        (!self.inner.st.is_empty()).then_some(self.inner.st.as_str())
    }
    async fn usn(&self) -> Option<&str> {
        (!self.inner.usn.is_empty()).then_some(self.inner.usn.as_str())
    }
    async fn server(&self) -> Option<&str> {
        (!self.inner.server.is_empty()).then_some(self.inner.server.as_str())
    }
}

pub(super) struct DaiIpActiveQuery<'a> {
    pub(super) inner: &'a db::DaiIpActiveQuery,
}
#[Object]
impl DaiIpActiveQuery<'_> {
    async fn status(&self) -> Option<DaiActiveQueryStatus> {
        self.inner.status.map(Into::into)
    }
    async fn last_query(&self) -> Option<Timestamp> {
        self.inner.last_query.map(timestamp)
    }
    async fn kinds(&self) -> Vec<DaiIpActiveKind<'_>> {
        self.inner
            .kinds
            .iter()
            .map(|inner| DaiIpActiveKind { inner })
            .collect()
    }
}
struct DaiIpActiveKind<'a> {
    inner: &'a db::DaiIpActiveKind,
}
#[Object]
impl DaiIpActiveKind<'_> {
    async fn kind(&self) -> DaiActiveQueryKind {
        self.inner.kind.into()
    }
    async fn answer(&self) -> Option<DaiActiveAnswer<'_>> {
        self.inner.answer.as_ref().map(DaiActiveAnswer::from)
    }
    async fn last_result(&self) -> Option<DaiActiveQueryResult> {
        self.inner.last_result.as_ref().map(Into::into)
    }
}

pub(super) struct DaiSiteActiveQuery<'a> {
    pub(super) inner: &'a db::DaiSiteActiveQuery,
}
#[Object]
impl DaiSiteActiveQuery<'_> {
    async fn state(&self) -> DaiActiveQuerySiteState {
        self.inner.state.into()
    }
    async fn no_dns_servers(&self) -> bool {
        self.inner.no_dns_servers
    }
    async fn last_query(&self) -> Option<Timestamp> {
        self.inner.last_query.map(timestamp)
    }
    async fn kinds(&self) -> Vec<DaiActiveQueryKindCounts<'_>> {
        self.inner
            .kinds
            .iter()
            .map(|inner| DaiActiveQueryKindCounts { inner })
            .collect()
    }
    async fn waiting_ips(&self) -> usize {
        self.inner.waiting_ips
    }
    async fn waiting_ips_over_limit(&self) -> bool {
        self.inner.waiting_ips_over_limit
    }
}
struct DaiActiveQueryKindCounts<'a> {
    inner: &'a db::DaiActiveQueryKindCounts,
}
#[Object]
impl DaiActiveQueryKindCounts<'_> {
    async fn kind(&self) -> DaiActiveQueryKind {
        self.inner.kind.into()
    }
    async fn sent_today(&self) -> StringNumber<u64> {
        StringNumber(self.inner.sent_today)
    }
    async fn answered_today(&self) -> StringNumber<u64> {
        StringNumber(self.inner.answered_today)
    }
    async fn sent_last_30_days(&self) -> StringNumber<u64> {
        StringNumber(self.inner.sent_last_30_days)
    }
    async fn answered_last_30_days(&self) -> StringNumber<u64> {
        StringNumber(self.inner.answered_last_30_days)
    }
}
