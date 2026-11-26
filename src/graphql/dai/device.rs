//! The device reads: the device list, the IP device rows, the device detail
//! and search.

use std::net::IpAddr;

use async_graphql::{
    Context, Enum, InputObject, Object, Result, SimpleObject, StringNumber, Union,
    connection::{Connection, Edge, EmptyFields, OpaqueCursor},
    types::ID,
};
use ipnet::IpNet;
use review_database::{
    DaiBindingSpan, DaiCurrentIp, DaiDeviceAlias, DaiDeviceBinding, DaiDeviceChange,
    DaiDeviceDetail, DaiDeviceFilter, DaiDeviceIdentifier, DaiDeviceListRow, DaiDeviceName,
    DaiFieldChange, DaiIpDeviceFilter, DaiIpDeviceRow, DaiPage, DaiPageDirection, DaiPageRequest,
    DaiSearchMatch, DaiSearchTarget, DaiService, DaiSoftware, DaiTimeRange,
};

use super::{
    DaiActivity, DaiObservationKind, DaiVerdict, accessible_customer, dai_refusal, nanos,
    parse_device_id, request_time, timestamp,
};
use crate::graphql::{Role, RoleGuard, query_with_constraints, timestamp::Timestamp};

/// A page of a DAI listing as review-web asks for it: the key to start
/// after or before, the direction and the size.
struct PageRequest {
    from: Option<Vec<u8>>,
    direction: DaiPageDirection,
    limit: usize,
}

impl PageRequest {
    /// Returns the page the connection arguments select.
    fn new(
        after: Option<OpaqueCursor<Vec<u8>>>,
        before: Option<OpaqueCursor<Vec<u8>>>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Self {
        match (after, before, first, last) {
            (_, Some(before), _, Some(last)) => Self {
                from: Some(before.0),
                direction: DaiPageDirection::Backward,
                limit: last,
            },
            (None, None, None, Some(last)) => Self {
                from: None,
                direction: DaiPageDirection::Backward,
                limit: last,
            },
            (after, _, first, _) => Self {
                from: after.map(|cursor| cursor.0),
                direction: DaiPageDirection::Forward,
                limit: first.unwrap_or_default(),
            },
        }
    }

    /// Returns review-database's page request starting at the key `from`
    /// decodes to.
    fn with_key<K>(&self, from: Option<K>) -> DaiPageRequest<K> {
        DaiPageRequest {
            from,
            direction: self.direction,
            limit: self.limit,
        }
    }

    /// Returns the connection of `page`, each row with the cursor `cursor`
    /// gives it.
    fn connection<T, N>(
        &self,
        page: DaiPage<T>,
        cursor: impl Fn(&T) -> Vec<u8>,
        node: impl Fn(T) -> N,
    ) -> Connection<OpaqueCursor<Vec<u8>>, N, DaiTotalCount, EmptyFields>
    where
        N: async_graphql::OutputType,
    {
        let (has_previous, has_next) = match self.direction {
            DaiPageDirection::Forward => (self.from.is_some(), page.has_more),
            DaiPageDirection::Backward => (page.has_more, self.from.is_some()),
        };
        let mut connection = Connection::with_additional_fields(
            has_previous,
            has_next,
            DaiTotalCount {
                total_count: StringNumber(page.total),
            },
        );
        connection.edges.extend(
            page.rows
                .into_iter()
                .map(|row| Edge::new(OpaqueCursor(cursor(&row)), node(row))),
        );
        connection
    }
}

/// The number of rows of a DAI listing.
#[derive(SimpleObject)]
struct DaiTotalCount {
    /// The number of rows that match the filter, on every page.
    total_count: StringNumber<usize>,
}

/// Returns the text a cursor holds as a string.
fn cursor_text(cursor: &[u8]) -> Result<&str> {
    std::str::from_utf8(cursor).map_err(|_| "invalid cursor".into())
}

/// Returns the cursor of an IP device row at (`site`, `ip`).
fn ip_device_cursor(site: &str, ip: IpAddr) -> Vec<u8> {
    format!("{site}/{ip}").into_bytes()
}

/// Returns the (site, IP) an IP device row cursor holds.
fn ip_device_key(cursor: &[u8]) -> Result<(String, IpAddr)> {
    let (site, ip) = cursor_text(cursor)?
        .split_once('/')
        .ok_or("invalid cursor")?;
    let ip = ip.parse().map_err(|_| "invalid cursor")?;
    Ok((site.to_string(), ip))
}

#[derive(Default)]
pub(super) struct DaiDeviceQuery;

#[Object]
impl DaiDeviceQuery {
    /// The customer's devices that match `filter`, ordered by device id.
    ///
    /// Each row carries the device's current IPs, the bindings in effect
    /// now, or, for a device with none, its binding with the latest start.
    /// The site and network filters match a device one of whose current IPs
    /// (or, with none, whose latest binding) is at a listed site and in the
    /// network; the seen range matches a device whose first-to-last seen
    /// range overlaps it.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)] // The customer, the filter and the connection arguments.
    async fn dai_devices(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        filter: Option<DaiDeviceFilterInput>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, DaiDevice, DaiTotalCount, EmptyFields>> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        let filter = filter.map(DaiDeviceFilterInput::parse).transpose()?;
        let now = request_time(ctx)?;
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let request = PageRequest::new(after, before, first, last);
                let from = request
                    .from
                    .as_deref()
                    .map(|cursor| parse_device_id(cursor_text(cursor)?))
                    .transpose()?;
                let store = crate::graphql::get_store(ctx)?;
                let page = store
                    .dai_devices(
                        customer_id,
                        &filter.unwrap_or_default(),
                        &request.with_key(from),
                        now,
                    )
                    .map_err(|e| dai_refusal(&e))?;
                Ok::<_, async_graphql::Error>(request.connection(
                    page,
                    |row| row.device.to_string().into_bytes(),
                    |inner| DaiDevice { inner },
                ))
            },
        )
        .await
    }

    /// The customer's IP device rows that match `filter`, ordered by site and
    /// IP.
    ///
    /// An IP device row is an IP address seen in the last 30 days at whose
    /// last seen time no device binding is in effect at its site and IP. It
    /// is not a device and is not counted as one.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)] // The customer, the filter and the connection arguments.
    async fn dai_ip_only_devices(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        filter: Option<DaiIpDeviceFilterInput>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, DaiIpDevice, DaiTotalCount, EmptyFields>> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        let filter = filter.map(DaiIpDeviceFilterInput::parse).transpose()?;
        let now = request_time(ctx)?;
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let request = PageRequest::new(after, before, first, last);
                let from = request.from.as_deref().map(ip_device_key).transpose()?;
                let store = crate::graphql::get_store(ctx)?;
                let page = store
                    .dai_ip_only_devices(
                        customer_id,
                        &filter.unwrap_or_default(),
                        &request.with_key(from),
                        now,
                    )
                    .map_err(|e| dai_refusal(&e))?;
                Ok::<_, async_graphql::Error>(request.connection(
                    page,
                    |row| ip_device_cursor(&row.site, row.ip),
                    |inner| DaiIpDevice { inner },
                ))
            },
        )
        .await
    }

    /// The device `deviceId` names, in detail, or null if it names no device
    /// of the customer. An old id, one a merge made an alias, returns the
    /// current device.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_device(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        device_id: ID,
    ) -> Result<Option<DaiDeviceDetails>> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        let device = parse_device_id(&device_id)?;
        let now = request_time(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        Ok(store
            .dai_device(customer_id, device, now)
            .map_err(|e| dai_refusal(&e))?
            .map(|inner| DaiDeviceDetails { inner }))
    }

    /// Searches the customer's devices and IP device rows for `text`.
    ///
    /// `text` matches an IP address (the devices bound or fixed to it, and
    /// its IP device rows), a MAC as `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`
    /// or `aabb.ccdd.eeff` in any case, an operator asset id, a current or
    /// old device id, and a case-insensitive substring of a device name.
    /// Accounts are not searched. At most 100 matches are returned, with
    /// `truncated` set if there were more.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_search(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        text: String,
    ) -> Result<DaiSearchResult> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        let now = request_time(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let result = store
            .dai_search(customer_id, &text, now)
            .map_err(|e| dai_refusal(&e))?;
        Ok(DaiSearchResult {
            matches: result.matches.into_iter().map(Into::into).collect(),
            truncated: result.truncated,
        })
    }
}

/// A closed time range, both ends included.
#[derive(InputObject)]
struct DaiTimeRangeInput {
    from: Timestamp,
    to: Timestamp,
}

impl DaiTimeRangeInput {
    fn parse(self) -> Result<DaiTimeRange, String> {
        Ok(DaiTimeRange {
            from: nanos(self.from, "from")?,
            to: nanos(self.to, "to")?,
        })
    }
}

/// Parses `text` as an IP network, naming `field` in the error.
fn parse_network(text: &str, field: &str) -> Result<IpNet, String> {
    let text = text.trim();
    text.parse::<IpNet>()
        .or_else(|_| text.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| format!("{field} {text:?} is not an IP network"))
}

/// The filter of the device list; each field absent matches every device.
#[derive(InputObject)]
struct DaiDeviceFilterInput {
    /// The site tokens.
    sites: Option<Vec<String>>,
    verdicts: Option<Vec<DaiVerdict>>,
    activities: Option<Vec<DaiActivity>>,
    /// An IP network, such as `10.0.0.0/24`.
    network: Option<String>,
    /// Matches a device whose first-to-last seen range overlaps it; a device
    /// never observed never matches it.
    seen: Option<DaiTimeRangeInput>,
}

impl DaiDeviceFilterInput {
    fn parse(self) -> Result<DaiDeviceFilter, String> {
        Ok(DaiDeviceFilter {
            sites: self.sites,
            verdicts: self
                .verdicts
                .map(|verdicts| verdicts.into_iter().map(Into::into).collect()),
            activities: self
                .activities
                .map(|activities| activities.into_iter().map(Into::into).collect()),
            network: self
                .network
                .as_deref()
                .map(|network| parse_network(network, "network"))
                .transpose()?,
            seen: self.seen.map(DaiTimeRangeInput::parse).transpose()?,
        })
    }
}

/// The filter of the IP device rows; each field absent matches every row.
#[derive(InputObject)]
struct DaiIpDeviceFilterInput {
    /// The site tokens.
    sites: Option<Vec<String>>,
    /// An IP network, such as `10.0.0.0/24`.
    network: Option<String>,
    /// Matches a row whose first-to-last seen range overlaps it.
    seen: Option<DaiTimeRangeInput>,
}

impl DaiIpDeviceFilterInput {
    fn parse(self) -> Result<DaiIpDeviceFilter, String> {
        Ok(DaiIpDeviceFilter {
            sites: self.sites,
            network: self
                .network
                .as_deref()
                .map(|network| parse_network(network, "network"))
                .transpose()?,
            seen: self.seen.map(DaiTimeRangeInput::parse).transpose()?,
        })
    }
}

/// A row of the device list.
struct DaiDevice {
    inner: DaiDeviceListRow,
}

#[Object]
impl DaiDevice {
    async fn device_id(&self) -> ID {
        ID(self.inner.device.to_string())
    }

    async fn verdict(&self) -> DaiVerdict {
        self.inner.verdict.into()
    }

    async fn activity(&self) -> DaiActivity {
        self.inner.activity.into()
    }

    async fn representative_name(&self) -> Option<&str> {
        self.inner.representative_name.as_deref()
    }

    /// Null for a device no observation has applied to.
    async fn first_seen(&self) -> Option<Timestamp> {
        self.inner.first_seen.map(timestamp)
    }

    /// Null for a device no observation has applied to.
    async fn last_seen(&self) -> Option<Timestamp> {
        self.inner.last_seen.map(timestamp)
    }

    /// The bindings in effect now, ordered by site, IP and start.
    async fn current_ips(&self) -> Vec<DaiCurrentIpEntry<'_>> {
        self.inner
            .current_ips
            .iter()
            .map(|inner| DaiCurrentIpEntry { inner })
            .collect()
    }

    /// The binding with the latest start, for a device with no current IP
    /// that has a binding.
    async fn latest_binding(&self) -> Option<DaiBindingSpanEntry<'_>> {
        self.inner
            .latest_binding
            .as_ref()
            .map(|inner| DaiBindingSpanEntry { inner })
    }
}

/// An IP address a device holds now.
struct DaiCurrentIpEntry<'a> {
    inner: &'a DaiCurrentIp,
}

#[Object(name = "DaiCurrentIp")]
impl DaiCurrentIpEntry<'_> {
    async fn site(&self) -> &str {
        &self.inner.site
    }

    async fn ip(&self) -> String {
        self.inner.ip.to_string()
    }

    /// The start of the binding in effect now.
    async fn start(&self) -> Timestamp {
        timestamp(self.inner.start)
    }
}

/// A binding of a device.
struct DaiBindingSpanEntry<'a> {
    inner: &'a DaiBindingSpan,
}

#[Object(name = "DaiBindingSpan")]
impl DaiBindingSpanEntry<'_> {
    async fn site(&self) -> &str {
        &self.inner.site
    }

    async fn ip(&self) -> String {
        self.inner.ip.to_string()
    }

    async fn start(&self) -> Timestamp {
        timestamp(self.inner.start)
    }

    /// The effective end; null while the binding is open.
    async fn end(&self) -> Option<Timestamp> {
        self.inner.end.map(timestamp)
    }

    /// Whether `end` is an estimate rather than a stored close.
    async fn end_estimated(&self) -> bool {
        self.inner.end_estimated
    }
}

/// An IP device row: an address seen with no device binding in effect at its
/// last seen time. It is not a device.
struct DaiIpDevice {
    inner: DaiIpDeviceRow,
}

#[Object]
impl DaiIpDevice {
    async fn site(&self) -> &str {
        &self.inner.site
    }

    async fn ip(&self) -> String {
        self.inner.ip.to_string()
    }

    async fn first_seen(&self) -> Timestamp {
        timestamp(self.inner.first_seen)
    }

    async fn last_seen(&self) -> Timestamp {
        timestamp(self.inner.last_seen)
    }
}

/// The kind of a strong identifier of a device.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiIdentifierKind")]
pub(super) enum DaiIdentifierKind {
    /// A MAC address, as lowercase colon-separated hex.
    Mac,
    /// An operator asset id, as imported.
    OperatorAssetId,
    /// A machine account, as `<CNAME>@<REALM>` ASCII-uppercased.
    MachineAccount,
}

/// The source of a name of a device.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiNameSource")]
enum DaiNameSource {
    /// A DNS name resolved to the device's address.
    Dns,
    /// A DHCP hostname.
    Dhcp,
    /// A name an operator set.
    Operator,
}

/// How a device came to be.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiOrigin")]
enum DaiOrigin {
    /// Created by an observation.
    Observation,
    /// Created by an operator import.
    Import,
}

/// Why a device id became an alias of another.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiAliasReason")]
enum DaiAliasReason {
    /// The device was merged into the current one.
    Merged,
    /// An import replaced the device by the current one.
    Imported,
}

/// The kind of a device change.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiChangeKind")]
enum DaiChangeKind {
    Created,
    Changed,
    Merged,
    Split,
}

/// The operation of a changed field.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiChangeOp")]
enum DaiChangeOp {
    Set,
    Add,
    Remove,
}

/// What made a device change.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
enum DaiChangeSource {
    /// An observation, of `observationKind`.
    Observation,
    /// An operator import.
    Import,
    /// Another operator operation.
    Operator,
    /// Retention.
    Expiry,
}

/// The side of a software string.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_protocol::types::DaiSide")]
enum DaiSide {
    Client,
    Server,
}

/// Where a software string came from.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_protocol::types::DaiSoftwareSource")]
enum DaiSoftwareSource {
    /// An SSH version string.
    Ssh,
    /// An HTTP `User-Agent` header.
    HttpUserAgent,
    /// A TLS certificate subject.
    TlsCertSubject,
}

/// A device in detail.
struct DaiDeviceDetails {
    inner: DaiDeviceDetail,
}

#[Object(name = "DaiDeviceDetail")]
impl DaiDeviceDetails {
    /// The id asked for.
    async fn requested_id(&self) -> ID {
        ID(self.inner.requested.to_string())
    }

    /// The current device id.
    async fn device_id(&self) -> ID {
        ID(self.inner.device.to_string())
    }

    /// Whether the id asked for is an old id followed through its alias.
    async fn alias_followed(&self) -> bool {
        self.inner.alias_followed
    }

    /// The strong identifiers the device holds, machine accounts included,
    /// in the order they were added.
    async fn identifiers(&self) -> Vec<DaiIdentifierEntry<'_>> {
        self.inner
            .identifiers
            .iter()
            .map(|inner| DaiIdentifierEntry { inner })
            .collect()
    }

    async fn names(&self) -> Vec<DaiNameEntry<'_>> {
        self.inner
            .names
            .iter()
            .map(|inner| DaiNameEntry { inner })
            .collect()
    }

    async fn representative_name(&self) -> Option<&str> {
        self.inner.representative_name.as_deref()
    }

    /// Whether the device was seen serving DHCP.
    async fn was_dhcp_server(&self) -> bool {
        self.inner.was_dhcp_server
    }

    async fn verdict(&self) -> DaiVerdict {
        self.inner.verdict.into()
    }

    async fn activity(&self) -> DaiActivity {
        self.inner.activity.into()
    }

    async fn origin(&self) -> DaiOrigin {
        self.inner.origin.into()
    }

    /// The operator asset id.
    async fn asset_id(&self) -> Option<&str> {
        self.inner.operator_asset_id.as_deref()
    }

    /// The operator memo; empty for none.
    async fn memo(&self) -> &str {
        &self.inner.memo
    }

    /// The device version, incremented by every substantive change.
    async fn version(&self) -> StringNumber<u64> {
        StringNumber(self.inner.version)
    }

    /// Null for a device no observation has applied to.
    async fn first_seen(&self) -> Option<Timestamp> {
        self.inner.first_seen.map(timestamp)
    }

    /// Null for a device no observation has applied to.
    async fn last_seen(&self) -> Option<Timestamp> {
        self.inner.last_seen.map(timestamp)
    }

    /// The addresses an operator fixed to the device.
    async fn fixed_ips(&self) -> Vec<DaiSiteIp> {
        self.inner
            .fixed_ips
            .iter()
            .map(|(site, ip)| DaiSiteIp {
                site: site.clone(),
                ip: ip.to_string(),
            })
            .collect()
    }

    /// Every binding of the device, newest start first.
    async fn ip_history(&self) -> Vec<DaiIpHistoryEntry<'_>> {
        self.inner
            .ip_history
            .iter()
            .map(|inner| DaiIpHistoryEntry { inner })
            .collect()
    }

    /// The services, ordered by port and protocol.
    async fn services(&self) -> Vec<DaiServiceEntry<'_>> {
        self.inner
            .services
            .iter()
            .map(|inner| DaiServiceEntry { inner })
            .collect()
    }

    async fn software(&self) -> Vec<DaiSoftwareEntry<'_>> {
        self.inner
            .software
            .iter()
            .map(|inner| DaiSoftwareEntry { inner })
            .collect()
    }

    /// The change history, in version order.
    async fn changes(&self) -> Vec<DaiChangeEntry<'_>> {
        self.inner
            .changes
            .iter()
            .map(|inner| DaiChangeEntry { inner })
            .collect()
    }

    /// The old ids aliased to the device, ordered by time and then id.
    async fn aliases(&self) -> Vec<DaiAliasEntry<'_>> {
        self.inner
            .aliases
            .iter()
            .map(|inner| DaiAliasEntry { inner })
            .collect()
    }
}

/// An IP address at a site.
#[derive(SimpleObject)]
struct DaiSiteIp {
    /// The site token.
    site: String,
    ip: String,
}

/// A strong identifier of a device.
struct DaiIdentifierEntry<'a> {
    inner: &'a DaiDeviceIdentifier,
}

#[Object(name = "DaiDeviceIdentifier")]
impl DaiIdentifierEntry<'_> {
    async fn kind(&self) -> DaiIdentifierKind {
        self.inner.identifier.kind.into()
    }

    /// The value, in the form its kind describes.
    async fn value(&self) -> &str {
        &self.inner.identifier.value
    }

    /// When the identifier was last confirmed.
    async fn last_confirmed(&self) -> Option<Timestamp> {
        self.inner.last_confirmed.map(timestamp)
    }
}

/// A name of a device.
struct DaiNameEntry<'a> {
    inner: &'a DaiDeviceName,
}

#[Object(name = "DaiDeviceName")]
impl DaiNameEntry<'_> {
    async fn value(&self) -> &str {
        &self.inner.value
    }

    async fn source(&self) -> DaiNameSource {
        self.inner.source.into()
    }

    async fn last_seen(&self) -> Timestamp {
        timestamp(self.inner.last_seen)
    }
}

/// A binding in a device's IP history.
struct DaiIpHistoryEntry<'a> {
    inner: &'a DaiDeviceBinding,
}

#[Object(name = "DaiDeviceBinding")]
impl DaiIpHistoryEntry<'_> {
    async fn site(&self) -> &str {
        &self.inner.site
    }

    async fn ip(&self) -> String {
        self.inner.ip.to_string()
    }

    async fn start(&self) -> Timestamp {
        timestamp(self.inner.start)
    }

    /// The effective end; null while the binding is open.
    async fn end(&self) -> Option<Timestamp> {
        self.inner.end.map(timestamp)
    }

    /// Whether `end` is an estimate rather than a stored close.
    async fn end_estimated(&self) -> bool {
        self.inner.end_estimated
    }

    /// The kind of the observation that started the binding.
    async fn evidence_kind(&self) -> Option<DaiObservationKind> {
        self.inner.evidence_kind.map(Into::into)
    }
}

/// A service of a device.
struct DaiServiceEntry<'a> {
    inner: &'a DaiService,
}

#[Object(name = "DaiService")]
impl DaiServiceEntry<'_> {
    async fn port(&self) -> u16 {
        self.inner.port
    }

    /// The IP protocol number.
    async fn protocol(&self) -> u8 {
        self.inner.protocol
    }

    /// Whether the service was seen used by a client outside the customer's
    /// networks.
    async fn external_client(&self) -> bool {
        self.inner.external_client
    }

    async fn first_seen(&self) -> Timestamp {
        timestamp(self.inner.first_seen)
    }

    async fn last_seen(&self) -> Timestamp {
        timestamp(self.inner.last_seen)
    }

    /// Whether an operator removed it.
    async fn removed(&self) -> bool {
        self.inner.removed
    }

    /// Whether it was last seen more than 30 days ago.
    async fn not_seen(&self) -> bool {
        self.inner.not_seen
    }
}

/// A software string of a device.
struct DaiSoftwareEntry<'a> {
    inner: &'a DaiSoftware,
}

#[Object(name = "DaiSoftware")]
impl DaiSoftwareEntry<'_> {
    async fn side(&self) -> DaiSide {
        self.inner.side.into()
    }

    async fn source(&self) -> DaiSoftwareSource {
        self.inner.source.into()
    }

    async fn text(&self) -> &str {
        &self.inner.text
    }

    async fn first_seen(&self) -> Timestamp {
        timestamp(self.inner.first_seen)
    }

    async fn last_seen(&self) -> Timestamp {
        timestamp(self.inner.last_seen)
    }
}

/// An entry of a device's change history.
struct DaiChangeEntry<'a> {
    inner: &'a DaiDeviceChange,
}

#[Object(name = "DaiDeviceChange")]
impl DaiChangeEntry<'_> {
    /// The device version the change made.
    async fn version(&self) -> StringNumber<u64> {
        StringNumber(self.inner.version)
    }

    async fn kind(&self) -> DaiChangeKind {
        self.inner.kind.into()
    }

    /// The other device of a merge or a split, as its current id.
    async fn related_device_id(&self) -> Option<ID> {
        self.inner
            .related_device
            .map(|device| ID(device.to_string()))
    }

    /// The fields the change changed.
    async fn fields(&self) -> Vec<DaiFieldChangeEntry<'_>> {
        self.inner
            .fields
            .iter()
            .map(|inner| DaiFieldChangeEntry { inner })
            .collect()
    }

    async fn time(&self) -> Timestamp {
        timestamp(self.inner.time)
    }

    /// What made the change.
    async fn source(&self) -> DaiChangeSource {
        match self.inner.source {
            review_database::DaiChangeSource::Observation(_) => DaiChangeSource::Observation,
            review_database::DaiChangeSource::Import => DaiChangeSource::Import,
            review_database::DaiChangeSource::Operator => DaiChangeSource::Operator,
            review_database::DaiChangeSource::Expiry => DaiChangeSource::Expiry,
        }
    }

    /// The observation kind of a change an observation made.
    async fn observation_kind(&self) -> Option<DaiObservationKind> {
        match self.inner.source {
            review_database::DaiChangeSource::Observation(kind) => kind.map(Into::into),
            _ => None,
        }
    }
}

/// A field a device change changed.
struct DaiFieldChangeEntry<'a> {
    inner: &'a DaiFieldChange,
}

#[Object(name = "DaiFieldChange")]
impl DaiFieldChangeEntry<'_> {
    /// The field.
    async fn path(&self) -> &str {
        &self.inner.path
    }

    async fn op(&self) -> DaiChangeOp {
        self.inner.op.into()
    }

    /// The value before, as JSON text; `null` for none.
    async fn before(&self) -> &str {
        &self.inner.before
    }

    /// The value after, as JSON text; `null` for none.
    async fn after(&self) -> &str {
        &self.inner.after
    }
}

/// An old device id that now names the device.
struct DaiAliasEntry<'a> {
    inner: &'a DaiDeviceAlias,
}

#[Object(name = "DaiDeviceAlias")]
impl DaiAliasEntry<'_> {
    /// The old id.
    async fn device_id(&self) -> ID {
        ID(self.inner.device.to_string())
    }

    /// When it became an alias.
    async fn time(&self) -> Timestamp {
        timestamp(self.inner.time)
    }

    async fn reason(&self) -> DaiAliasReason {
        self.inner.reason.into()
    }
}

/// What a search text matched.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiSearchMatchKind")]
enum DaiSearchMatchKind {
    /// An IP address.
    Ip,
    /// A MAC address.
    Mac,
    /// An operator asset id.
    AssetId,
    /// A current device id.
    DeviceId,
    /// An old device id.
    OldDeviceId,
    /// A substring of a device name.
    Name,
}

/// The result of a search.
struct DaiSearchResult {
    matches: Vec<DaiSearchHit>,
    truncated: bool,
}

#[Object]
impl DaiSearchResult {
    /// At most 100 matches.
    async fn matches(&self) -> &[DaiSearchHit] {
        &self.matches
    }

    /// Whether more matches were found than returned.
    async fn truncated(&self) -> bool {
        self.truncated
    }
}

/// One search match.
struct DaiSearchHit {
    matched: DaiSearchMatchKind,
    target: DaiSearchTargetEntry,
}

impl From<DaiSearchMatch> for DaiSearchHit {
    fn from(hit: DaiSearchMatch) -> Self {
        Self {
            matched: hit.matched.into(),
            target: match hit.target {
                DaiSearchTarget::Device(device) => DaiSearchTargetEntry::Device(DaiSearchDevice {
                    device_id: ID(device.to_string()),
                }),
                DaiSearchTarget::IpDevice {
                    site,
                    ip,
                    last_seen,
                } => DaiSearchTargetEntry::IpDevice(DaiSearchIpDevice {
                    site,
                    ip: ip.to_string(),
                    last_seen,
                }),
            },
        }
    }
}

#[Object(name = "DaiSearchMatch")]
impl DaiSearchHit {
    /// What the text matched.
    async fn matched(&self) -> DaiSearchMatchKind {
        self.matched
    }

    /// The device or the IP device row the match names.
    async fn target(&self) -> &DaiSearchTargetEntry {
        &self.target
    }
}

/// What a search match names.
#[derive(Union)]
#[graphql(name = "DaiSearchTarget")]
enum DaiSearchTargetEntry {
    Device(DaiSearchDevice),
    IpDevice(DaiSearchIpDevice),
}

/// A device a search matched.
#[derive(SimpleObject)]
struct DaiSearchDevice {
    /// The current device id.
    device_id: ID,
}

/// An IP device row a search matched.
struct DaiSearchIpDevice {
    site: String,
    ip: String,
    last_seen: i64,
}

#[Object]
impl DaiSearchIpDevice {
    async fn site(&self) -> &str {
        &self.site
    }

    async fn ip(&self) -> &str {
        &self.ip
    }

    async fn last_seen(&self) -> Timestamp {
        timestamp(self.last_seen)
    }
}
