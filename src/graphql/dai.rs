//! Device identification (DAI): the settings, sites and relay sites of each
//! customer, point-in-time resolve, the device list and the IP device rows,
//! the device detail and search, the operator device operations, the
//! collection status and the candidate unregistered ranges.
//!
//! Every rule is review-database's: each resolver checks the caller and the
//! input it parses, calls the `Store::dai_*` method that holds the rule, and
//! maps the answer or the refusal to the GraphQL contract. Times are the
//! `DateTime` scalar, nanoseconds since the UNIX epoch in review-database;
//! "now" is the time of the request.
//!
//! Reads are allowed to the four roles, writes to the two administrator
//! roles. Every field takes a customer id and checks the caller's membership
//! of it before anything else, and every write is refused with
//! `CUSTOMER_DELETION_IN_PROGRESS` while that customer's data deletion is
//! unfinished.

mod collection;
mod device;
mod operator;
mod resolve;
mod settings;
mod site;
#[cfg(test)]
mod tests;

use std::{fmt::Display, net::IpAddr, str::FromStr, sync::RwLockReadGuard};

use async_graphql::{
    Context, Enum, ErrorExtensions, MergedObject, Name, Result, Value, indexmap::IndexMap,
    types::ID,
};
use review_database::{DaiConfigError, DaiDeviceError, DaiResolveError, Store};

use super::customer_access::check_customer_membership;
use super::customer_deletion_guard;
use super::customer_network::{parse_customer_id, stale_revision};
use crate::graphql::timestamp::Timestamp;

/// The `extensions.code` of a time series generation policy refused because
/// its sensors span two sites.
pub(super) const SENSORS_SPAN_SITES: &str = "SENSORS_SPAN_SITES";
/// The `extensions.code` of a site change refused because it would make an
/// existing time series generation policy span two sites.
const SITE_CHANGE_BREAKS_POLICY: &str = "SITE_CHANGE_BREAKS_POLICY";

/// The device identification queries.
#[derive(MergedObject, Default)]
pub(super) struct DaiQuery(
    settings::DaiSettingsQuery,
    site::DaiSiteQuery,
    resolve::DaiResolveQuery,
    device::DaiDeviceQuery,
    collection::DaiCollectionQuery,
);

/// The device identification mutations.
#[derive(MergedObject, Default)]
pub(super) struct DaiMutation(
    settings::DaiSettingsMutation,
    site::DaiSiteMutation,
    operator::DaiOperatorMutation,
    collection::DaiCollectionMutation,
);

/// The kind of a DAI observation.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "review_protocol::types::DaiObservationKind")]
enum DaiObservationKind {
    DhcpLease,
    DhcpServer,
    Kerberos,
    Ntlm,
    Service,
    SoftwareString,
    DnsName,
    IpActivity,
}

/// The operator's verdict on a device.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiVerdict")]
enum DaiVerdict {
    /// Seen by observation only.
    Observed,
    /// Confirmed by an operator.
    Confirmed,
    /// Ignored by an operator.
    Ignored,
}

/// Whether a device is seen.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::DaiActivity")]
enum DaiActivity {
    /// Seen within the last 90 days, or not expired yet.
    Active,
    /// Not seen for 90 days; set by retention only.
    NotSeen,
    /// Hidden by an operator.
    Hidden,
}

/// Returns the customer id `customer_id` names after checking that the
/// caller may access it.
///
/// # Errors
///
/// Returns `Forbidden` for a caller scoped to other customers, and an error
/// for an id that is not a customer id.
fn accessible_customer(ctx: &Context<'_>, customer_id: &ID) -> Result<u32> {
    check_customer_membership(ctx, customer_id)?;
    parse_customer_id(customer_id)
}

/// Returns the customer id `customer_id` names and the store, after checking
/// that the caller may access the customer and that its data deletion is not
/// unfinished, for a write.
///
/// The membership is checked before the store is read.
///
/// # Errors
///
/// Returns `Forbidden` for a caller scoped to other customers,
/// `CUSTOMER_DELETION_IN_PROGRESS` while the customer's data deletion is
/// unfinished, and an error for an id that is not a customer id.
fn writable_customer<'a>(
    ctx: &'a Context<'a>,
    customer_id: &ID,
) -> Result<(u32, RwLockReadGuard<'a, Store>)> {
    let customer_id = accessible_customer(ctx, customer_id)?;
    let store = crate::graphql::get_store(ctx)?;
    customer_deletion_guard::check_customers(&store, [customer_id])?;
    Ok((customer_id, store))
}

/// The time of the request a test sets, in nanoseconds since the UNIX
/// epoch, in place of the clock.
#[cfg(test)]
#[derive(Clone, Copy)]
struct RequestTime(i64);

/// Returns the time of the request, in nanoseconds since the UNIX epoch.
///
/// # Errors
///
/// Returns an error if the clock is outside the range of an `i64` of
/// nanoseconds, years 1677 to 2262.
fn request_time(ctx: &Context<'_>) -> Result<i64> {
    #[cfg(test)]
    if let Some(RequestTime(now)) = ctx.data_opt::<RequestTime>() {
        return Ok(*now);
    }
    #[cfg(not(test))]
    let _ = ctx;
    i64::try_from(jiff::Timestamp::now().as_nanosecond())
        .map_err(|_| "the clock is outside the range of the device identification times".into())
}

/// Returns the `DateTime` of `nanos`, nanoseconds since the UNIX epoch.
fn timestamp(nanos: i64) -> Timestamp {
    jiff::Timestamp::from_nanosecond(i128::from(nanos))
        .expect("every i64 of nanoseconds, years 1677 to 2262, is within jiff's range")
        .into()
}

/// Returns the nanoseconds since the UNIX epoch of `time`.
///
/// # Errors
///
/// Returns an error naming `field` if `time` is outside the range of an
/// `i64` of nanoseconds, years 1677 to 2262.
fn nanos(time: Timestamp, field: &str) -> Result<i64, String> {
    i64::try_from(time.as_nanosecond())
        .map_err(|_| format!("{field} {time} is outside the years 1677 to 2262"))
}

/// Parses `text` as an IP address, naming `field` in the error.
fn parse_ip(text: &str, field: &str) -> Result<IpAddr, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{field} {text:?} is not an IP address"))
}

/// Parses `id` as a device id.
///
/// The device id type is review-database's, inferred from where the value
/// is used.
fn parse_device_id<T>(id: &str) -> Result<T>
where
    T: FromStr,
    T::Err: Display,
{
    id.trim()
        .parse()
        .map_err(|e| format!("{id:?} is not a device id: {e}").into())
}

/// Maps a refusal of a DAI write or read to the error a resolver returns,
/// passing every other error through with its context.
fn dai_refusal(error: &anyhow::Error) -> async_graphql::Error {
    if let Some(refusal) = error.downcast_ref::<DaiConfigError>() {
        return match refusal {
            DaiConfigError::StaleRevision { stored } => stale_revision(*stored),
            DaiConfigError::PolicyWouldSpanSites { policies } => {
                site_change_breaks_policy(refusal.to_string(), policies)
            }
            _ => refusal.to_string().into(),
        };
    }
    if let Some(refusal) = error.downcast_ref::<DaiDeviceError>() {
        return refusal.to_string().into();
    }
    if let Some(refusal) = error.downcast_ref::<DaiResolveError>() {
        return refusal.to_string().into();
    }
    format!("{error:#}").into()
}

/// Returns the `SENSORS_SPAN_SITES` refusal of a time series generation
/// policy whose sensors fall in each of `sites`, a site token with the
/// policy's sensors in it.
///
/// The `sites` extension lists one `{ site, sensors }` per site, in token
/// order, its sensors sorted.
pub(super) fn sensors_span_sites(
    message: String,
    sites: &[(String, Vec<String>)],
) -> async_graphql::Error {
    let mut sites = sites.to_vec();
    sites.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
    let sites: Vec<Value> = sites
        .into_iter()
        .map(|(site, mut sensors)| {
            sensors.sort_unstable();
            object([
                ("site", Value::from(site)),
                (
                    "sensors",
                    Value::List(sensors.into_iter().map(Value::from).collect()),
                ),
            ])
        })
        .collect();
    async_graphql::Error::new(message).extend_with(|_, extensions| {
        extensions.set("code", SENSORS_SPAN_SITES);
        extensions.set("sites", Value::List(sites));
    })
}

/// Returns the `SITE_CHANGE_BREAKS_POLICY` refusal of a site change that
/// would make each of `policies`, an id and a name, span two sites.
///
/// The `policies` extension lists one `{ id, name }` per policy, sorted by
/// id, the id as decimal text.
fn site_change_breaks_policy(message: String, policies: &[(u32, String)]) -> async_graphql::Error {
    let mut policies = policies.to_vec();
    policies.sort_unstable_by_key(|(id, _)| *id);
    let policies: Vec<Value> = policies
        .into_iter()
        .map(|(id, name)| {
            object([
                ("id", Value::from(id.to_string())),
                ("name", Value::from(name)),
            ])
        })
        .collect();
    async_graphql::Error::new(message).extend_with(|_, extensions| {
        extensions.set("code", SITE_CHANGE_BREAKS_POLICY);
        extensions.set("policies", Value::List(policies));
    })
}

/// Returns the object value of `fields`.
fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(name, value)| (Name::new(name), value))
            .collect::<IndexMap<_, _>>(),
    )
}
