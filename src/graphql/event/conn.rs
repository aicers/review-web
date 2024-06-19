use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{country_code, find_ip_customer, find_ip_network, TriageScore};
use crate::graphql::{customer::Customer, network::Network};

#[allow(clippy::module_name_repetitions)]
pub(super) struct PortScan {
    inner: database::PortScan,
}

#[Object]
impl PortScan {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn dst_ports(&self) -> Vec<u16> {
        self.inner.dst_ports.clone()
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    async fn last_time(&self) -> DateTime<Utc> {
        self.inner.last_time
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::PortScan> for PortScan {
    fn from(inner: database::PortScan) -> Self {
        Self { inner }
    }
}

pub(super) struct MultiHostPortScan {
    inner: database::MultiHostPortScan,
}

#[Object]
impl MultiHostPortScan {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn dst_addrs(&self) -> Vec<String> {
        self.inner
            .dst_addrs
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_countries(&self, ctx: &Context<'_>) -> Vec<String> {
        self.inner
            .dst_addrs
            .iter()
            .map(|dst_addr| country_code(ctx, *dst_addr))
            .collect()
    }

    async fn dst_customers(&self, ctx: &Context<'_>) -> Result<Vec<Option<Customer>>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        let mut customers = vec![];
        for dst_addr in &self.inner.dst_addrs {
            customers.push(find_ip_customer(&map, *dst_addr)?);
        }
        Ok(customers)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(
            &map,
            *self
                .inner
                .dst_addrs
                .first()
                .expect("has value with internal network"),
        )
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    async fn last_time(&self) -> DateTime<Utc> {
        self.inner.last_time
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::MultiHostPortScan> for MultiHostPortScan {
    fn from(inner: database::MultiHostPortScan) -> Self {
        Self { inner }
    }
}

pub(super) struct ExternalDdos {
    inner: database::ExternalDdos,
}

#[Object]
impl ExternalDdos {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn src_addrs(&self) -> Vec<String> {
        self.inner
            .src_addrs
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_countries(&self, ctx: &Context<'_>) -> Vec<String> {
        self.inner
            .src_addrs
            .iter()
            .map(|src_addr| country_code(ctx, *src_addr))
            .collect()
    }

    async fn src_customers(&self, ctx: &Context<'_>) -> Result<Vec<Option<Customer>>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        let mut customers = vec![];
        for src_addr in &self.inner.src_addrs {
            customers.push(find_ip_customer(&map, *src_addr)?);
        }
        Ok(customers)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(
            &map,
            *self
                .inner
                .src_addrs
                .first()
                .expect("has value with internal network"),
        )
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    async fn last_time(&self) -> DateTime<Utc> {
        self.inner.last_time
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::ExternalDdos> for ExternalDdos {
    fn from(inner: database::ExternalDdos) -> Self {
        Self { inner }
    }
}

pub(super) struct BlockListConn {
    inner: database::BlockListConn,
}

#[Object]
impl BlockListConn {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn conn_state(&self) -> String {
        self.inner.conn_state.clone()
    }

    async fn duration(&self) -> i64 {
        self.inner.duration
    }

    async fn service(&self) -> String {
        self.inner.service.clone()
    }

    async fn orig_bytes(&self) -> u64 {
        self.inner.orig_bytes
    }

    async fn resp_bytes(&self) -> u64 {
        self.inner.resp_bytes
    }

    async fn orig_pkts(&self) -> u64 {
        self.inner.orig_pkts
    }

    async fn resp_pkts(&self) -> u64 {
        self.inner.resp_pkts
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::BlockListConn> for BlockListConn {
    fn from(inner: database::BlockListConn) -> Self {
        Self { inner }
    }
}
