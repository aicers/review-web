//! The device identification sites and the DHCP relay site table of each
//! customer.

use std::collections::BTreeSet;

use async_graphql::{Context, InputObject, Object, Result, StringNumber, types::ID};
use review_database::{DaiRelaySite, Store};

use super::{accessible_customer, dai_refusal, parse_ip, writable_customer};
use crate::graphql::customer_access::customer_sensor_names;
use crate::graphql::{Role, RoleGuard};

#[derive(Default)]
pub(super) struct DaiSiteQuery;

#[Object]
impl DaiSiteQuery {
    /// Every site of the customer, in token order.
    ///
    /// The default site lists the customer's sensors that are in no other
    /// site. A customer whose default site is not stored yet lists one
    /// unsaved default site with a null token, and nothing is written.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_sites(&self, ctx: &Context<'_>, customer_id: ID) -> Result<Vec<DaiSite>> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        let store = crate::graphql::get_store(ctx)?;
        let mut sites = store.dai_sites(customer_id).map_err(|e| dai_refusal(&e))?;
        if !sites.iter().any(|site| site.is_default) {
            sites.insert(
                0,
                review_database::DaiSite {
                    token: String::new(),
                    name: String::new(),
                    sensors: Vec::new(),
                    is_default: true,
                },
            );
        }
        let listed: BTreeSet<String> = sites
            .iter()
            .filter(|site| !site.is_default)
            .flat_map(|site| site.sensors.iter().cloned())
            .collect();
        let unlisted = || -> Result<Vec<String>> {
            let mut sensors: Vec<String> = customer_sensor_names(&store, customer_id)?
                .into_iter()
                .filter(|sensor| !listed.contains(sensor))
                .collect();
            sensors.sort_unstable();
            Ok(sensors)
        };
        sites
            .into_iter()
            .map(|site| {
                let sensors = if site.is_default {
                    unlisted()?
                } else {
                    site.sensors
                };
                Ok(DaiSite {
                    token: (!site.token.is_empty()).then_some(site.token),
                    name: site.name,
                    is_default: site.is_default,
                    sensors,
                })
            })
            .collect()
    }

    /// The customer's DHCP relay site table and its revision.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn dai_relay_sites(&self, ctx: &Context<'_>, customer_id: ID) -> Result<DaiRelaySites> {
        let customer_id = accessible_customer(ctx, &customer_id)?;
        let store = crate::graphql::get_store(ctx)?;
        let table = store
            .dai_relay_sites(customer_id)
            .map_err(|e| dai_refusal(&e))?;
        Ok(DaiRelaySites {
            revision: table.revision,
            entries: table.entries.into_iter().map(Into::into).collect(),
        })
    }
}

#[derive(Default)]
pub(super) struct DaiSiteMutation;

#[Object]
impl DaiSiteMutation {
    /// Creates a site of the customer named `name` listing `sensors`, and
    /// returns it.
    ///
    /// The customer's default site is created first if it has none. The
    /// name is non-empty, unique within the customer, and contains none of
    /// `|`, `;`, `,` and `"`. Each listed sensor must be a sensor of the
    /// customer that no other site lists, and moves out of the default site
    /// from the next 5-minute boundary after the write. A change that would
    /// make a time series generation policy of the customer read sensors of
    /// two sites is refused with the error code
    /// `SITE_CHANGE_BREAKS_POLICY`, whose `policies` extension lists each
    /// such policy as `{ id, name }`, sorted by id.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn create_dai_site(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        name: String,
        sensors: Vec<String>,
    ) -> Result<DaiSite> {
        let (customer_id, store) = writable_customer(ctx, &customer_id)?;
        let token = store
            .create_dai_site(customer_id, &name, &sensors)
            .map_err(|e| dai_refusal(&e))?;
        stored_site(&store, customer_id, &token)
    }

    /// Replaces the name and the sensors of the customer's site `token`, and
    /// returns it.
    ///
    /// The default site cannot be changed. A sensor added moves out of the
    /// default site, and one removed returns to it, from the next 5-minute
    /// boundary after the write. Otherwise checked as `createDaiSite`.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_dai_site(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        token: String,
        name: String,
        sensors: Vec<String>,
    ) -> Result<DaiSite> {
        let (customer_id, store) = writable_customer(ctx, &customer_id)?;
        store
            .update_dai_site(customer_id, &token, &name, &sensors)
            .map_err(|e| dai_refusal(&e))?;
        stored_site(&store, customer_id, &token)
    }

    /// Removes the customer's site `token`, and returns the token.
    ///
    /// The default site, a site that lists sensors, a site the relay site
    /// table names, and a site a sensor is still assigned to, in effect or
    /// scheduled, cannot be removed.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_dai_site(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        token: String,
    ) -> Result<String> {
        let (customer_id, store) = writable_customer(ctx, &customer_id)?;
        store
            .remove_dai_site(customer_id, &token)
            .map_err(|e| dai_refusal(&e))?;
        Ok(token)
    }

    /// Replaces the customer's whole DHCP relay site table with `entries`,
    /// given the stored relay table `revision`, and returns the new
    /// revision.
    ///
    /// An entry whose `giaddr` is `0.0.0.0` or `::`, two entries with the
    /// same DHCP server IP and `giaddr`, or an entry naming a token that is
    /// not one of the customer's sites, is refused. A `revision` other than
    /// the stored one is refused with the error code `STALE_REVISION`, whose
    /// `storedRevision` extension holds the stored revision.
    ///
    /// Refused with `CUSTOMER_DELETION_IN_PROGRESS` while a data deletion of
    /// the customer is unfinished.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn replace_dai_relay_sites(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        revision: StringNumber<u64>,
        entries: Vec<DaiRelaySiteInput>,
    ) -> Result<StringNumber<u64>> {
        let (customer_id, store) = writable_customer(ctx, &customer_id)?;
        let entries = entries
            .into_iter()
            .map(|entry| {
                Ok(DaiRelaySite {
                    dhcp_server: parse_ip(&entry.dhcp_server, "dhcpServer")?,
                    giaddr: parse_ip(&entry.giaddr, "giaddr")?,
                    site: entry.site,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let revision = store
            .replace_dai_relay_sites(customer_id, revision.0, &entries)
            .map_err(|e| dai_refusal(&e))?;
        Ok(StringNumber(revision))
    }
}

/// Returns the customer's stored site `token`, which is not the default
/// site.
fn stored_site(store: &Store, customer_id: u32, token: &str) -> Result<DaiSite> {
    let site = store
        .dai_site(customer_id, token)
        .map_err(|e| dai_refusal(&e))?
        .ok_or_else(|| format!("site {token:?} was removed by another write"))?;
    Ok(DaiSite {
        token: Some(site.token),
        name: site.name,
        is_default: site.is_default,
        sensors: site.sensors,
    })
}

/// A site of a customer: a part of its network in which an IP address names
/// one device at a time.
struct DaiSite {
    token: Option<String>,
    name: String,
    is_default: bool,
    sensors: Vec<String>,
}

#[Object]
impl DaiSite {
    /// The 8 characters of `[a-z0-9]` assigned to the site at its creation;
    /// null for a default site that is not stored yet.
    async fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// The display name; empty for the default site only.
    async fn name(&self) -> &str {
        &self.name
    }

    /// Whether this is the customer's default site.
    async fn is_default(&self) -> bool {
        self.is_default
    }

    /// The names of the sensors in the site. The default site has the
    /// customer's sensors that no other site lists.
    async fn sensors(&self) -> &[String] {
        &self.sensors
    }
}

/// A customer's DHCP relay site table.
struct DaiRelaySites {
    revision: u64,
    entries: Vec<DaiRelaySiteEntry>,
}

#[Object]
impl DaiRelaySites {
    /// The relay site table revision.
    async fn revision(&self) -> StringNumber<u64> {
        StringNumber(self.revision)
    }

    /// The entries, ordered by DHCP server IP and then `giaddr`, IPv4 before
    /// IPv6.
    async fn entries(&self) -> &[DaiRelaySiteEntry] {
        &self.entries
    }
}

/// An entry of a relay site table: the site of the hosts whose DHCP traffic
/// the relay `giaddr` forwards to `dhcpServer`.
struct DaiRelaySiteEntry {
    inner: DaiRelaySite,
}

impl From<DaiRelaySite> for DaiRelaySiteEntry {
    fn from(inner: DaiRelaySite) -> Self {
        Self { inner }
    }
}

#[Object(name = "DaiRelaySite")]
impl DaiRelaySiteEntry {
    /// The DHCP server the relay forwards to.
    async fn dhcp_server(&self) -> String {
        self.inner.dhcp_server.to_string()
    }

    /// The relay agent address.
    async fn giaddr(&self) -> String {
        self.inner.giaddr.to_string()
    }

    /// The token of the site.
    async fn site(&self) -> &str {
        &self.inner.site
    }
}

/// An entry of a relay site table to store.
#[derive(InputObject)]
struct DaiRelaySiteInput {
    /// The DHCP server the relay forwards to.
    dhcp_server: String,
    /// The relay agent address; never `0.0.0.0` or `::`.
    giaddr: String,
    /// The token of one of the customer's sites.
    site: String,
}
