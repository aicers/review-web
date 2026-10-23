//! Rules shared by the Unsupervised Engine training definitions and engine
//! documents.
//!
//! The Data Store rule (RFC 0006 §5.3, §5.7) decides whether a `[data_store]`
//! table may be stored. It runs in two steps around the engine configuration
//! lock: [`data_store_addrs`] asks the agent manager, before the lock is
//! taken, for the addresses of the Data Store the request itself names; once
//! the lock is held, [`check_data_store`] reads everything stored that the
//! decision depends on and combines it with those addresses.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

use async_graphql::Context;
use review_database::{ExternalServiceConfig, Store};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{
    SharedAgentManager,
    node::listed_rows,
    refusal::{RefusalCode, refusal},
};

/// The key of a Data Store configuration that holds its publish address.
const PUBLISH_SRV_ADDR: &str = "publish_srv_addr";

/// The Data Store a model reads its events from: the definition's
/// `[data_store]` and an engine document's `[detectors.data_store]`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DataStore {
    /// The address the engine dials, `ip:port`.
    pub(crate) address: SocketAddr,
    /// The name of the Data Store, `<instance:03>.giganto.<hostname>`.
    pub(crate) server_name: String,
}

impl DataStore {
    /// Returns the `(server_name, address)` pair the Data Store rule keeps.
    #[must_use]
    pub(crate) fn pair(&self) -> (String, SocketAddr) {
        (self.server_name.clone(), self.address)
    }
}

/// A refusal of the Data Store rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataStoreRefusal {
    /// `DATA_STORE_NOT_INSTALLED` or `ADDRESS_OVERRIDE_FORBIDDEN`.
    pub(crate) code: RefusalCode,
    /// The offending key of the `[data_store]` table: `server_name` or
    /// `address`.
    pub(crate) key: &'static str,
}

impl DataStoreRefusal {
    /// Returns the refusal as a GraphQL error whose `field` is `prefix`
    /// followed by the offending key, such as `data_store.address`.
    #[must_use]
    pub(crate) fn into_error(self, prefix: &str, data_store: &DataStore) -> async_graphql::Error {
        let field = format!("{prefix}{}", self.key);
        if self.code == RefusalCode::DataStoreNotInstalled {
            refusal(
                self.code,
                format!(
                    "{:?} is not an installed Data Store",
                    data_store.server_name
                ),
                &field,
                data_store.server_name.as_str(),
            )
        } else {
            refusal(
                self.code,
                format!(
                    "{} is not an address of Data Store {:?}; only a System Administrator \
                     may set another",
                    data_store.address, data_store.server_name
                ),
                &field,
                data_store.address.to_string(),
            )
        }
    }
}

/// Returns the IP addresses the agent manager resolves for the Data Store
/// `server_name` names, before the engine configuration lock is taken.
///
/// `server_name` must come from the request itself, which cannot change. The
/// addresses are advisory runtime state no lock covers. A `server_name` that
/// is not `<instance:03>.giganto.<hostname>` makes no call and yields none;
/// a failed lookup is logged and yields none.
pub(crate) async fn data_store_addrs(ctx: &Context<'_>, server_name: &str) -> Vec<IpAddr> {
    let Some((hostname, instance)) = parse_server_name(server_name) else {
        return Vec::new();
    };
    let agent_manager = match ctx.data::<SharedAgentManager>() {
        Ok(agent_manager) => agent_manager,
        Err(e) => {
            warn!("cannot look up the addresses of Data Store {server_name:?}: {e:?}");
            return Vec::new();
        }
    };
    match agent_manager
        .data_store_read_endpoint(hostname, instance)
        .await
    {
        Ok(endpoint) => endpoint.addrs,
        Err(e) => {
            warn!("cannot look up the addresses of Data Store {server_name:?}: {e:#}");
            Vec::new()
        }
    }
}

/// Applies the Data Store rule, with the engine configuration lock held.
///
/// `server_name` must be `<instance:03>.giganto.<hostname>` and an installed
/// Data Store, as `dataStoreEndpoints` lists them. `address` must then be one of the Data Store's own addresses,
/// each of `addrs` (from [`data_store_addrs`]) with the port of
/// `publish_srv_addr` in the Data Store's stored draft, unless `system_admin`
/// or the pair is among `kept`. A Data Store whose draft is absent or has no
/// parsable top-level `publish_srv_addr` has no own addresses.
///
/// Returns `Some` refusal, or `None` if the rule holds.
///
/// # Errors
///
/// Returns an error if the store cannot be read.
pub(crate) fn check_data_store(
    store: &Store,
    data_store: &DataStore,
    addrs: &[IpAddr],
    kept: &HashSet<(String, SocketAddr)>,
    system_admin: bool,
) -> anyhow::Result<Option<DataStoreRefusal>> {
    let not_installed = DataStoreRefusal {
        code: RefusalCode::DataStoreNotInstalled,
        key: "server_name",
    };
    // A listed row can compose a name that is not canonical, such as
    // `001.giganto.` on a node whose applied hostname is empty. Neither a
    // System Administrator nor a kept pair exempts a name from this rule.
    if parse_server_name(&data_store.server_name).is_none() {
        return Ok(Some(not_installed));
    }
    let rows = listed_rows(store)
        .map_err(|e| anyhow::anyhow!("cannot list Data Stores: {}", e.message))?;
    let Some(row) = rows
        .into_iter()
        .find(|row| row.server_name() == data_store.server_name)
    else {
        return Ok(Some(not_installed));
    };
    if system_admin || kept.contains(&data_store.pair()) {
        return Ok(None);
    }
    let own = row
        .draft
        .as_ref()
        .and_then(publish_port)
        .is_some_and(|port| {
            addrs
                .iter()
                .any(|&ip| SocketAddr::new(ip, port) == data_store.address)
        });
    if own {
        Ok(None)
    } else {
        Ok(Some(DataStoreRefusal {
            code: RefusalCode::AddressOverrideForbidden,
            key: "address",
        }))
    }
}

/// Returns the hostname and the instance number `server_name` names, if it is
/// `<instance:03>.giganto.<hostname>`.
fn parse_server_name(server_name: &str) -> Option<(&str, u32)> {
    let (instance, rest) = server_name.split_once('.')?;
    let hostname = rest.strip_prefix("giganto.")?;
    let number = instance.parse::<u32>().ok()?;
    if hostname.is_empty() || format!("{number:03}") != instance {
        return None;
    }
    Some((hostname, number))
}

/// Returns the port of the top-level `publish_srv_addr` of a Data Store's
/// configuration, if it has a parsable one.
fn publish_port(config: &ExternalServiceConfig) -> Option<u16> {
    let table = config.as_ref().parse::<toml::Table>().ok()?;
    table
        .get(PUBLISH_SRV_ADDR)?
        .as_str()?
        .parse::<SocketAddr>()
        .ok()
        .map(|addr| addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_parses_only_in_canonical_form() {
        assert_eq!(
            parse_server_name("001.giganto.host.example.com"),
            Some(("host.example.com", 1))
        );
        assert_eq!(parse_server_name("1234.giganto.host"), Some(("host", 1234)));
        for invalid in [
            "1.giganto.host",
            "001.giganto.",
            "001.piglet.host",
            "abc.giganto.host",
            "001giganto.host",
            "",
        ] {
            assert_eq!(parse_server_name(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn publish_port_reads_the_top_level_key() {
        let config = |text: &str| ExternalServiceConfig::try_from(text.to_string()).unwrap();
        assert_eq!(
            publish_port(&config("publish_srv_addr = \"0.0.0.0:38371\"\n")),
            Some(38_371)
        );
        assert_eq!(
            publish_port(&config("[nested]\npublish_srv_addr = \"0.0.0.0:38371\"\n")),
            None
        );
        assert_eq!(
            publish_port(&config("publish_srv_addr = \"not an address\"\n")),
            None
        );
        assert_eq!(publish_port(&config("publish_srv_addr = 38371\n")), None);
    }
}
