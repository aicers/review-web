//! The allowlist and blocklist of each customer, keyed by customer ID.
//!
//! The network lists table holds a copy of every customer's allowlist and
//! blocklist as the writer last sent them, and is the source of the lists hog
//! receives.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use async_graphql::{Context, InputObject, Object, Result, StringNumber, types::ID};
use chrono::{DateTime, Utc};
use review_database::{self as database, NetworkListReplaceOutcome, Store};
use tracing::{error, info};

use super::customer::{
    HostNetworkGroup, HostNetworkGroupInput, NetworksTargetAgentLookupKeysPair,
    send_agent_specific_allow_networks, send_agent_specific_block_networks,
};
use super::customer_access::check_customer_membership;
use super::customer_network::{
    hog_agent_lookup_keys, parse_customer_id, stale_revision, validate_group,
};
use super::node::SEMI_SUPERVISED_AGENT;
use super::{Role, RoleGuard};
use crate::{error_with_username, info_with_username};

/// The most entries one list of one customer may hold.
const MAX_ENTRIES_PER_LIST: usize = 256;

/// The lock that orders every write and every push of the network lists,
/// one per schema.
///
/// Whoever writes a customer's lists, or reads them to push them, holds it
/// until the push is sent. A push is only sent when something changed, so a
/// push overtaken by a newer one would leave hog with a stale list that no
/// later write repairs.
///
/// A push is addressed to the nodes that belong to its customer when it is
/// read, but a node may move to another customer while the push is on its
/// way, and on again before the first move has sent anything. Each move is
/// stored before it takes the lock, then sends its customer's lists under it,
/// so one lock for all customers puts every move's lists after every push
/// read before the move was stored; per-customer locks would order only the
/// customers each move names, not the rest of the chain.
#[derive(Default)]
pub(crate) struct NetworkListsLock {
    mutex: tokio::sync::Mutex<()>,
    /// How many operations hold or wait for the lock.
    #[cfg(test)]
    users: std::sync::atomic::AtomicUsize,
}

impl NetworkListsLock {
    /// Returns how many operations hold or wait for the lock.
    #[cfg(test)]
    pub(super) fn users(&self) -> usize {
        self.users.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The guard of a held [`NetworkListsLock`].
pub(super) struct NetworkListsGuard<'a> {
    _guard: tokio::sync::MutexGuard<'a, ()>,
    #[cfg(test)]
    _user: LockUser<'a>,
}

/// Counts an operation among the users of a [`NetworkListsLock`] from before
/// it waits for the lock until it releases it or stops waiting.
#[cfg(test)]
struct LockUser<'a>(&'a std::sync::atomic::AtomicUsize);

#[cfg(test)]
impl<'a> LockUser<'a> {
    fn new(users: &'a std::sync::atomic::AtomicUsize) -> Self {
        users.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(users)
    }
}

#[cfg(test)]
impl Drop for LockUser<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Waits for the network lists to be free and locks them.
///
/// # Errors
///
/// Returns an error if the schema holds no [`NetworkListsLock`].
pub(super) async fn lock_network_lists<'a>(ctx: &Context<'a>) -> Result<NetworkListsGuard<'a>> {
    let lock = ctx.data::<Arc<NetworkListsLock>>()?;
    #[cfg(test)]
    let user = LockUser::new(&lock.users);
    let guard = lock.mutex.lock().await;
    Ok(NetworkListsGuard {
        _guard: guard,
        #[cfg(test)]
        _user: user,
    })
}

/// Returns the merged allowlist of a customer, or an empty group if none is
/// stored for it.
///
/// # Errors
///
/// Returns an error if the stored row could not be read or decoded.
pub fn get_allow_networks(db: &Store, customer_id: u32) -> Result<database::HostNetworkGroup> {
    Ok(db
        .network_lists_map()
        .get(customer_id)?
        .map(|set| set.merged_allowlist())
        .unwrap_or_default())
}

/// Returns the merged blocklist of a customer, or an empty group if none is
/// stored for it.
///
/// # Errors
///
/// Returns an error if the stored row could not be read or decoded.
pub fn get_block_networks(db: &Store, customer_id: u32) -> Result<database::HostNetworkGroup> {
    Ok(db
        .network_lists_map()
        .get(customer_id)?
        .map(|set| set.merged_blocklist())
        .unwrap_or_default())
}

#[derive(Default)]
pub(super) struct NetworkListQuery;

#[Object]
impl NetworkListQuery {
    /// The allowlist and blocklist of the customer, or null if none were
    /// stored for it.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn network_lists(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
    ) -> Result<Option<NetworkListSet>> {
        check_customer_membership(ctx, &customer_id)?;
        let customer_id = parse_customer_id(&customer_id)?;
        let store = crate::graphql::get_store(ctx)?;
        Ok(store
            .network_lists_map()
            .get(customer_id)?
            .map(|inner| NetworkListSet { customer_id, inner }))
    }
}

#[derive(Default)]
pub(super) struct NetworkListMutation;

#[Object]
impl NetworkListMutation {
    /// Replaces the allowlist and blocklist of the customer, returning the
    /// stored revision.
    ///
    /// `allowlist` and `blocklist` are the customer's full lists; empty lists
    /// are stored as such. A `revision` lower than the stored one is refused
    /// with the error code `STALE_REVISION`, whose `storedRevision` extension
    /// holds the stored revision.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn replace_network_lists(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        revision: StringNumber<u64>,
        allowlist: Vec<NetworkListEntryInput>,
        blocklist: Vec<NetworkListEntryInput>,
    ) -> Result<StringNumber<u64>> {
        check_customer_membership(ctx, &customer_id)?;
        let customer_id = parse_customer_id(&customer_id)?;
        let StringNumber(revision) = revision;
        let allowlist = validate_list(NetworkList::Allowlist, allowlist)?;
        let blocklist = validate_list(NetworkList::Blocklist, blocklist)?;

        let set = database::NetworkListSet {
            revision,
            allowlist,
            blocklist,
            updated_at: Utc::now(),
        };
        let merged = (set.merged_allowlist(), set.merged_blocklist());
        let _lock = lock_network_lists(ctx).await?;
        let pushes = {
            let store = crate::graphql::get_store(ctx)?;
            let outcome = store.network_lists_map().replace(
                customer_id,
                revision,
                set.allowlist,
                set.blocklist,
            )?;
            let previous = match outcome {
                NetworkListReplaceOutcome::Written { previous } => previous,
                NetworkListReplaceOutcome::Stale { stored } => return Err(stale_revision(stored)),
            };
            info_with_username!(
                ctx,
                "Network lists of customer {customer_id} have been replaced at revision {revision}"
            );
            hog_pushes(ctx, &store, customer_id, previous.as_ref(), merged)
        };
        send_pushes(ctx, customer_id, pushes).await;

        Ok(StringNumber(revision))
    }

    /// Removes the allowlist and blocklist of the customer, returning whether
    /// any were stored.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_network_lists(&self, ctx: &Context<'_>, customer_id: ID) -> Result<bool> {
        check_customer_membership(ctx, &customer_id)?;
        let customer_id = parse_customer_id(&customer_id)?;

        let _lock = lock_network_lists(ctx).await?;
        let pushes = {
            let store = crate::graphql::get_store(ctx)?;
            let Some(removed) = store.network_lists_map().remove(customer_id)? else {
                return Ok(false);
            };
            info_with_username!(
                ctx,
                "Network lists of customer {customer_id} have been removed"
            );
            hog_pushes(ctx, &store, customer_id, Some(&removed), Default::default())
        };
        send_pushes(ctx, customer_id, pushes).await;

        Ok(true)
    }
}

/// The allowlist and blocklist of a customer.
struct NetworkListSet {
    customer_id: u32,
    inner: database::NetworkListSet,
}

#[Object]
impl NetworkListSet {
    /// The ID of the customer.
    async fn customer_id(&self) -> ID {
        ID(self.customer_id.to_string())
    }

    /// The writer's revision of this set.
    async fn revision(&self) -> StringNumber<u64> {
        StringNumber(self.inner.revision)
    }

    /// The entries of the allowlist.
    async fn allowlist(&self) -> Vec<NetworkListEntry<'_>> {
        self.inner
            .allowlist
            .iter()
            .map(|inner| NetworkListEntry { inner })
            .collect()
    }

    /// The entries of the blocklist.
    async fn blocklist(&self) -> Vec<NetworkListEntry<'_>> {
        self.inner
            .blocklist
            .iter()
            .map(|inner| NetworkListEntry { inner })
            .collect()
    }

    /// The time when this set was last written.
    async fn updated_at(&self) -> DateTime<Utc> {
        self.inner.updated_at
    }
}

/// An entry of a customer's allowlist or blocklist.
struct NetworkListEntry<'a> {
    inner: &'a database::NetworkListEntry,
}

#[Object]
impl NetworkListEntry<'_> {
    /// The name of the entry, unique within its list.
    async fn name(&self) -> &str {
        &self.inner.name
    }

    /// The hosts, networks and ranges of the entry.
    async fn network_group(&self) -> HostNetworkGroup<'_> {
        (&self.inner.group).into()
    }
}

#[derive(InputObject)]
struct NetworkListEntryInput {
    name: String,
    network_group: HostNetworkGroupInput,
}

/// One of a customer's two lists.
#[derive(Clone, Copy)]
enum NetworkList {
    Allowlist,
    Blocklist,
}

impl fmt::Display for NetworkList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allowlist => "allowlist",
            Self::Blocklist => "blocklist",
        })
    }
}

/// Checks the whole of `entries` and converts it, so that one invalid entry
/// rejects the call before anything is written.
///
/// # Errors
///
/// Returns an error, naming `list`, if there are too many entries, a name is
/// empty or repeated, or a network group is empty, too large, unparsable, or
/// holds a range that ends before it starts or mixes address families.
fn validate_list(
    list: NetworkList,
    entries: Vec<NetworkListEntryInput>,
) -> Result<Vec<database::NetworkListEntry>> {
    if entries.len() > MAX_ENTRIES_PER_LIST {
        return Err(format!(
            "too many {list} entries: at most {MAX_ENTRIES_PER_LIST} are allowed per customer"
        )
        .into());
    }
    let mut names = HashSet::with_capacity(entries.len());
    for entry in &entries {
        if entry.name.trim().is_empty() {
            return Err(format!("{list} entry name must not be empty").into());
        }
        if !names.insert(entry.name.as_str()) {
            return Err(format!("duplicate {list} entry name {:?}", entry.name).into());
        }
    }

    entries
        .into_iter()
        .map(|entry| {
            let group = validate_group(&entry.network_group)
                .map_err(|e| format!("{list} entry {:?}: {e}", entry.name))?;
            Ok(database::NetworkListEntry {
                name: entry.name,
                group,
            })
        })
        .collect()
}

/// Returns the pushes that bring the customer's hog agents from `previous` to
/// the merged `(allowlist, blocklist)` in `current`: one for each list whose
/// merged group changed, to the hog agents of the customer's nodes.
///
/// An absent `previous` counts as two empty lists. A push only swaps hog's
/// filter, so a list whose merged group is unchanged is skipped only because
/// there is nothing to send.
fn hog_pushes(
    ctx: &Context<'_>,
    store: &Store,
    customer_id: u32,
    previous: Option<&database::NetworkListSet>,
    current: (database::HostNetworkGroup, database::HostNetworkGroup),
) -> Vec<(NetworkList, NetworksTargetAgentLookupKeysPair)> {
    let (previous_allowlist, previous_blocklist) = previous
        .map(|set| (set.merged_allowlist(), set.merged_blocklist()))
        .unwrap_or_default();
    let (allowlist, blocklist) = current;
    let changed: Vec<_> = [
        (NetworkList::Allowlist, allowlist, previous_allowlist),
        (NetworkList::Blocklist, blocklist, previous_blocklist),
    ]
    .into_iter()
    .filter(|(_, current, previous)| current != previous)
    .map(|(list, current, _)| (list, current))
    .collect();
    if changed.is_empty() {
        return Vec::new();
    }

    let Some(agent_lookup_keys) = hog_agent_lookup_keys(ctx, store, customer_id, "network lists")
    else {
        return Vec::new();
    };
    changed
        .into_iter()
        .map(|(list, group)| {
            (
                list,
                NetworksTargetAgentLookupKeysPair::new(
                    group,
                    agent_lookup_keys.clone(),
                    SEMI_SUPERVISED_AGENT,
                ),
            )
        })
        .collect()
}

/// Sends `pushes`, logging a failure rather than returning it: the lists are
/// already stored, and hog pulls them again when it reconnects.
async fn send_pushes(
    ctx: &Context<'_>,
    customer_id: u32,
    pushes: Vec<(NetworkList, NetworksTargetAgentLookupKeysPair)>,
) {
    for (list, push) in pushes {
        let sent = match list {
            NetworkList::Allowlist => send_agent_specific_allow_networks(ctx, &[push]).await,
            NetworkList::Blocklist => send_agent_specific_block_networks(ctx, &[push]).await,
        };
        if let Err(e) = sent {
            error_with_username!(
                ctx,
                "Failed to send the {list} of customer {customer_id} to its agents: {e:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use review_database::{HostNetworkGroup, NetworkListEntry};
    use serde_json::{Value, json};

    use super::{get_allow_networks, get_block_networks};
    use crate::graphql::{
        Role, TestSchema,
        push_test_support::{
            Push, PushKind, failing_schema, group, insert_node, paused_schema, recording_schema,
        },
    };

    fn replace(customer_id: &str, revision: &str, allowlist: &str, blocklist: &str) -> String {
        format!(
            r#"mutation {{ replaceNetworkLists(customerId: "{customer_id}", revision: "{revision}", allowlist: [{allowlist}], blocklist: [{blocklist}]) }}"#
        )
    }

    fn entry(name: &str, group: &str) -> String {
        format!(r#"{{ name: "{name}", networkGroup: {group} }}"#)
    }

    fn query(customer_id: &str) -> String {
        format!(
            r#"{{ networkLists(customerId: "{customer_id}") {{
                customerId revision updatedAt
                allowlist {{ name networkGroup {{ hosts networks ranges {{ start end }} }} }}
                blocklist {{ name networkGroup {{ hosts networks ranges {{ start end }} }} }}
            }} }}"#
        )
    }

    fn remove(customer_id: &str) -> String {
        format!(r#"mutation {{ removeNetworkLists(customerId: "{customer_id}") }}"#)
    }

    const OFFICE: &str = r#"{ hosts: [], networks: ["10.0.0.0/8"], ranges: [] }"#;
    const SCANNER: &str = r#"{ hosts: ["192.0.2.1"], networks: [], ranges: [] }"#;

    fn stored_entry(name: &str, group: HostNetworkGroup) -> NetworkListEntry {
        NetworkListEntry {
            name: name.to_string(),
            group,
        }
    }

    fn data(res: async_graphql::Response) -> Value {
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        res.data.into_json().unwrap()
    }

    fn error_message(res: &async_graphql::Response) -> &str {
        assert_eq!(res.errors.len(), 1, "errors: {:?}", res.errors);
        &res.errors[0].message
    }

    #[tokio::test]
    async fn security_administrator_manages_own_customer_without_customer_or_node() {
        let schema = TestSchema::new().await;
        let as_admin = |query: String| {
            let schema = &schema;
            async move {
                schema
                    .execute_as_scoped_user(&query, Role::SecurityAdministrator, Some(vec![7]))
                    .await
            }
        };

        let res = as_admin(query("7")).await;
        assert_eq!(data(res), json!({ "networkLists": null }));

        let allowlist = [
            entry("office", OFFICE),
            entry(
                "partner",
                r#"{ hosts: ["2001:db8::1"], networks: [], ranges: [{ start: "192.168.1.1", end: "192.168.1.9" }] }"#,
            ),
        ]
        .join(", ");
        let res = as_admin(replace("7", "3", &allowlist, &entry("office", SCANNER))).await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "3" }));

        let res = as_admin(query("7")).await;
        let mut value = data(res);
        assert!(value["networkLists"]["updatedAt"].is_string());
        value["networkLists"]
            .as_object_mut()
            .unwrap()
            .remove("updatedAt");
        assert_eq!(
            value,
            json!({ "networkLists": {
                "customerId": "7",
                "revision": "3",
                "allowlist": [
                    { "name": "office", "networkGroup": {
                        "hosts": [], "networks": ["10.0.0.0/8"], "ranges": [] } },
                    { "name": "partner", "networkGroup": {
                        "hosts": ["2001:db8::1"], "networks": [],
                        "ranges": [{ "start": "192.168.1.1", "end": "192.168.1.9" }] } },
                ],
                "blocklist": [
                    { "name": "office", "networkGroup": {
                        "hosts": ["192.0.2.1"], "networks": [], "ranges": [] } },
                ],
            } })
        );

        let res = as_admin(remove("7")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        let res = as_admin(remove("7")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": false }));
        let res = as_admin(query("7")).await;
        assert_eq!(data(res), json!({ "networkLists": null }));
    }

    #[tokio::test]
    async fn other_customer_is_forbidden() {
        let schema = TestSchema::new().await;
        schema
            .store()
            .network_lists_map()
            .replace(8, 1, vec![], vec![])
            .unwrap();
        for query in [query("8"), replace("8", "2", "", ""), remove("8")] {
            let res = schema
                .execute_as_scoped_user(&query, Role::SecurityAdministrator, Some(vec![7]))
                .await;
            assert_eq!(error_message(&res), "Forbidden", "query: {query}");
        }
        let stored = schema.store().network_lists_map().get(8).unwrap();
        assert_eq!(stored.map(|set| set.revision), Some(1));
    }

    #[tokio::test]
    async fn monitor_and_manager_are_refused() {
        let schema = TestSchema::new().await;
        schema
            .store()
            .network_lists_map()
            .replace(7, 1, vec![], vec![])
            .unwrap();
        for role in [Role::SecurityMonitor, Role::SecurityManager] {
            for query in [query("7"), replace("7", "2", "", ""), remove("7")] {
                let res = schema
                    .execute_as_scoped_user(&query, role, Some(vec![7]))
                    .await;
                assert_eq!(
                    error_message(&res),
                    "Forbidden",
                    "{role:?} was not refused: {query}"
                );
            }
        }
        let stored = schema.store().network_lists_map().get(7).unwrap();
        assert_eq!(stored.map(|set| set.revision), Some(1));
    }

    #[tokio::test]
    async fn system_administrator_manages_any_customer() {
        let schema = TestSchema::new().await;
        for customer_id in ["0", "8", "4294967295"] {
            let res = schema
                .execute_as_scoped_user(
                    &replace(customer_id, "1", &entry("office", OFFICE), ""),
                    Role::SystemAdministrator,
                    None,
                )
                .await;
            assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));
            let res = schema
                .execute_as_scoped_user(
                    &format!(r#"{{ networkLists(customerId: "{customer_id}") {{ customerId }} }}"#),
                    Role::SystemAdministrator,
                    None,
                )
                .await;
            assert_eq!(
                data(res),
                json!({ "networkLists": { "customerId": customer_id } })
            );
            let res = schema
                .execute_as_scoped_user(&remove(customer_id), Role::SystemAdministrator, None)
                .await;
            assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        }
    }

    #[tokio::test]
    async fn customer_id_must_be_a_u32() {
        let schema = TestSchema::new().await;
        for customer_id in ["x", "-1", "4294967296"] {
            for query in [
                query(customer_id),
                replace(customer_id, "1", "", ""),
                remove(customer_id),
            ] {
                let res = schema.execute_as_system_admin(&query).await;
                assert_eq!(error_message(&res), "invalid customer ID", "query: {query}");
            }
        }
    }

    #[tokio::test]
    async fn stale_revision_is_refused_and_pushes_nothing() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");

        let res = schema
            .execute_as_system_admin(&replace("7", "5", &entry("office", OFFICE), ""))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "5" }));
        assert_eq!((pushes.allow().len(), pushes.block().len()), (1, 0));
        let before = schema.store().network_lists_map().get(7).unwrap();

        let res = schema
            .execute_as_system_admin(&replace("7", "4", "", &entry("scanner", SCANNER)))
            .await;
        assert_eq!(error_message(&res), "stale revision");
        let error = serde_json::to_value(&res.errors[0]).unwrap();
        assert_eq!(
            error["extensions"],
            json!({ "code": "STALE_REVISION", "storedRevision": "5" })
        );
        assert_eq!(schema.store().network_lists_map().get(7).unwrap(), before);
        assert_eq!((pushes.allow().len(), pushes.block().len()), (1, 0));

        // An equal revision overwrites the row.
        let res = schema
            .execute_as_system_admin(&replace("7", "5", "", &entry("scanner", SCANNER)))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "5" }));
        assert_eq!((pushes.allow().len(), pushes.block().len()), (2, 1));

        // So does a higher one.
        let res = schema
            .execute_as_system_admin(&replace("7", "6", "", ""))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "6" }));
        let stored = schema.store().network_lists_map().get(7).unwrap().unwrap();
        assert_eq!(
            (
                stored.revision,
                stored.allowlist.len(),
                stored.blocklist.len()
            ),
            (6, 0, 0)
        );
        assert_eq!((pushes.allow().len(), pushes.block().len()), (2, 2));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one case table covering every validation rule
    async fn invalid_lists_are_refused_and_nothing_is_written() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");

        let too_many_entries = (0..257)
            .map(|i| entry(&format!("n{i}"), OFFICE))
            .collect::<Vec<_>>()
            .join(", ");
        let too_many_hosts = (0..1025)
            .map(|i| format!(r#""10.0.{}.{}""#, i / 256, i % 256))
            .collect::<Vec<_>>()
            .join(", ");
        let invalid_entries = [
            (
                too_many_entries,
                "too many {} entries: at most 256 are allowed per customer",
            ),
            (entry("  ", OFFICE), "{} entry name must not be empty"),
            (
                [entry("office", OFFICE), entry("office", SCANNER)].join(", "),
                "duplicate {} entry name \"office\"",
            ),
            (
                entry(
                    "office",
                    r#"{ hosts: ["10.0.0.256"], networks: [], ranges: [] }"#,
                ),
                "{} entry \"office\": invalid host address",
            ),
            (
                entry("office", r"{ hosts: [], networks: [], ranges: [] }"),
                "{} entry \"office\": network group must not be empty",
            ),
            (
                entry(
                    "office",
                    &format!("{{ hosts: [{too_many_hosts}], networks: [], ranges: [] }}"),
                ),
                "{} entry \"office\": too many entries: at most 1024 hosts, networks and ranges \
                 are allowed per network",
            ),
            (
                entry(
                    "office",
                    r#"{ hosts: [], networks: [], ranges: [{ start: "10.0.0.9", end: "10.0.0.1" }] }"#,
                ),
                "{} entry \"office\": range 10.0.0.9 - 10.0.0.1 ends before it starts",
            ),
            (
                entry(
                    "office",
                    r#"{ hosts: [], networks: [], ranges: [{ start: "10.0.0.1", end: "::1" }] }"#,
                ),
                "{} entry \"office\": range 10.0.0.1 - ::1 mixes IPv4 and IPv6 addresses",
            ),
        ];
        let valid = entry("valid", SCANNER);
        for (entries, expected) in &invalid_entries {
            for (list, query) in [
                ("allowlist", replace("7", "1", entries, &valid)),
                ("blocklist", replace("7", "1", &valid, entries)),
            ] {
                let expected = expected.replace("{}", list);
                let res = schema.execute_as_system_admin(&query).await;
                let message = error_message(&res);
                assert!(
                    message.starts_with(&expected),
                    "expected {expected:?}, got {message:?}"
                );
                assert!(schema.store().network_lists_map().get(7).unwrap().is_none());
            }
        }
        // The allowlist is checked first.
        let res = schema
            .execute_as_system_admin(&replace("7", "1", &entry(" ", OFFICE), &entry("", OFFICE)))
            .await;
        assert_eq!(
            error_message(&res),
            "allowlist entry name must not be empty"
        );
        assert_eq!(pushes.allow(), Vec::<Push>::new());
        assert_eq!(pushes.block(), Vec::<Push>::new());

        // The limits themselves are accepted, and a name may be in both lists.
        let max_entries = (0..256)
            .map(|i| entry(&format!("n{i}"), OFFICE))
            .collect::<Vec<_>>()
            .join(", ");
        let res = schema
            .execute_as_system_admin(&replace("7", "1", &max_entries, &max_entries))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));
        let max_hosts = (0..1024)
            .map(|i| format!(r#""10.0.{}.{}""#, i / 256, i % 256))
            .collect::<Vec<_>>()
            .join(", ");
        let max_group = entry(
            "office",
            &format!("{{ hosts: [{max_hosts}], networks: [], ranges: [] }}"),
        );
        let res = schema
            .execute_as_system_admin(&replace("7", "2", &max_group, &max_group))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "2" }));
    }

    #[tokio::test]
    async fn empty_lists_and_extreme_revisions_are_stored() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(&replace("7", "0", "", ""))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "0" }));
        let stored = schema.store().network_lists_map().get(7).unwrap().unwrap();
        assert_eq!(
            (
                stored.revision,
                stored.allowlist.len(),
                stored.blocklist.len()
            ),
            (0, 0, 0)
        );

        let max = u64::MAX.to_string();
        let res = schema
            .execute_as_system_admin(&replace("7", &max, "", ""))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": max }));
        let res = schema
            .execute_as_system_admin(r#"{ networkLists(customerId: "7") { revision } }"#)
            .await;
        assert_eq!(
            data(res),
            json!({ "networkLists": { "revision": u64::MAX.to_string() } })
        );
    }

    #[tokio::test]
    async fn replace_pushes_only_changed_lists_to_the_customers_hog_agents() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7a.example.com");
        insert_node(&schema, 7, "n7b.example.com");
        insert_node(&schema, 8, "n8.example.com");
        let n7 = vec![
            "001.hog.n7a.example.com".to_string(),
            "001.hog.n7b.example.com".to_string(),
        ];

        // A first write with an allowlist only pushes the allowlist.
        let allowlist = [
            entry("office", OFFICE),
            entry(
                "edge",
                r#"{ hosts: ["192.168.0.1"], networks: ["2001:db8::/32"], ranges: [{ start: "172.16.0.1", end: "172.16.0.9" }] }"#,
            ),
        ]
        .join(", ");
        let res = schema
            .execute_as_scoped_user(
                &replace("7", "1", &allowlist, ""),
                Role::SecurityAdministrator,
                Some(vec![7]),
            )
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));
        let merged = group(
            &["192.168.0.1"],
            &["10.0.0.0/8", "2001:db8::/32"],
            &[("172.16.0.1", "172.16.0.9")],
        );
        assert_eq!(pushes.allow(), vec![vec![(n7.clone(), merged)]]);
        assert_eq!(pushes.block(), Vec::<Push>::new());
        assert_eq!(pushes.internal(), Vec::<Push>::new());

        // Renaming the entries and splitting them differently pushes nothing.
        let renamed = [
            entry(
                "a",
                r#"{ hosts: ["192.168.0.1"], networks: ["10.0.0.0/8"], ranges: [] }"#,
            ),
            entry(
                "b",
                r#"{ hosts: [], networks: ["2001:db8::/32", "10.0.0.0/8"], ranges: [{ start: "172.16.0.1", end: "172.16.0.9" }] }"#,
            ),
        ]
        .join(", ");
        let res = schema
            .execute_as_system_admin(&replace("7", "2", &renamed, ""))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "2" }));
        assert_eq!((pushes.allow().len(), pushes.block().len()), (1, 0));

        // A blocklist change pushes only the blocklist.
        let res = schema
            .execute_as_system_admin(&replace("7", "3", &renamed, &entry("scanner", SCANNER)))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "3" }));
        assert_eq!(pushes.allow().len(), 1);
        assert_eq!(
            pushes.block(),
            vec![vec![(n7.clone(), group(&["192.0.2.1"], &[], &[]))]]
        );
        assert_eq!(pushes.internal(), Vec::<Push>::new());
    }

    #[tokio::test]
    async fn remove_pushes_empty_groups_for_non_empty_lists() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");
        insert_node(&schema, 8, "n8.example.com");
        let n7 = vec!["001.hog.n7.example.com".to_string()];
        {
            let store = schema.store();
            let lists = store.network_lists_map();
            lists
                .replace(
                    7,
                    1,
                    vec![stored_entry("office", group(&[], &["10.0.0.0/8"], &[]))],
                    vec![],
                )
                .unwrap();
            lists
                .replace(
                    8,
                    1,
                    vec![stored_entry("office", group(&[], &["10.0.0.0/8"], &[]))],
                    vec![stored_entry("scanner", group(&["192.0.2.1"], &[], &[]))],
                )
                .unwrap();
        }

        let res = schema.execute_as_system_admin(&remove("7")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        assert_eq!(
            pushes.allow(),
            vec![vec![(n7.clone(), HostNetworkGroup::default())]]
        );
        assert_eq!(pushes.block(), Vec::<Push>::new());

        // Nothing was removed, so nothing is pushed.
        let res = schema.execute_as_system_admin(&remove("7")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": false }));
        assert_eq!((pushes.allow().len(), pushes.block().len()), (1, 0));

        // Both lists were non-empty, so both are pushed.
        let res = schema.execute_as_system_admin(&remove("8")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        let n8 = vec!["001.hog.n8.example.com".to_string()];
        assert_eq!(
            pushes.allow()[1],
            vec![(n8.clone(), HostNetworkGroup::default())]
        );
        assert_eq!(
            pushes.block(),
            vec![vec![(n8, HostNetworkGroup::default())]]
        );
        assert_eq!(pushes.internal(), Vec::<Push>::new());
    }

    #[tokio::test]
    async fn customer_without_hog_agents_gets_no_push() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 8, "n8.example.com");

        let res = schema
            .execute_as_system_admin(&replace(
                "7",
                "1",
                &entry("office", OFFICE),
                &entry("scanner", SCANNER),
            ))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));
        let res = schema.execute_as_system_admin(&remove("7")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        assert_eq!(pushes.allow(), Vec::<Push>::new());
        assert_eq!(pushes.block(), Vec::<Push>::new());
    }

    #[tokio::test]
    async fn failed_push_does_not_fail_the_mutation() {
        let (schema, pushes) = failing_schema().await;
        insert_node(&schema, 7, "n7.example.com");

        let res = schema
            .execute_as_system_admin(&replace(
                "7",
                "1",
                &entry("office", OFFICE),
                &entry("scanner", SCANNER),
            ))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));
        let stored = schema.store().network_lists_map().get(7).unwrap();
        assert_eq!(stored.map(|set| set.revision), Some(1));

        let res = schema.execute_as_system_admin(&remove("7")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        assert!(schema.store().network_lists_map().get(7).unwrap().is_none());
        assert_eq!((pushes.allow().len(), pushes.block().len()), (2, 2));
    }

    #[tokio::test]
    async fn concurrent_replaces_push_in_the_order_they_were_stored() {
        const CUSTOMER: u32 = 7;
        let (schema, pushes, pause) = paused_schema(PushKind::Allow).await;
        insert_node(&schema, CUSTOMER, "n.example.com");
        let target = vec!["001.hog.n.example.com".to_string()];
        let office = group(&[], &["10.0.0.0/8"], &[]);
        let scanner = group(&["192.0.2.1"], &[], &[]);
        let id = CUSTOMER.to_string();
        let older = replace(&id, "5", &entry("a", OFFICE), &entry("b", SCANNER));
        let newer = replace(&id, "6", &entry("a", SCANNER), &entry("b", OFFICE));
        let newer_done = AtomicBool::new(false);

        let (older_res, newer_res, ()) = tokio::join!(
            schema.execute_as_system_admin(&older),
            async {
                // Starts once the older replace is paused in its allowlist push.
                pause.entered.notified().await;
                let res = schema.execute_as_system_admin(&newer).await;
                newer_done.store(true, Ordering::SeqCst);
                res
            },
            async {
                // Waits until the newer replace waits for the lock, or has
                // finished without waiting for it.
                while schema.network_lists_lock_users() < 2 && !newer_done.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
                assert_eq!(pushes.allow(), vec![vec![(target.clone(), office.clone())]]);
                assert_eq!(pushes.block(), Vec::<Push>::new());
                pause.release.notify_one();
            },
        );

        assert_eq!(data(older_res), json!({ "replaceNetworkLists": "5" }));
        assert_eq!(data(newer_res), json!({ "replaceNetworkLists": "6" }));
        assert_eq!(
            pushes.allow(),
            vec![
                vec![(target.clone(), office.clone())],
                vec![(target.clone(), scanner.clone())],
            ]
        );
        assert_eq!(
            pushes.block(),
            vec![vec![(target.clone(), scanner)], vec![(target, office)]]
        );
        let stored = schema.store().network_lists_map().get(CUSTOMER).unwrap();
        assert_eq!(stored.map(|set| set.revision), Some(6));
        assert_eq!(schema.network_lists_lock_users(), 0);
    }

    /// Returns what `get_allow_networks` and `get_block_networks` return for
    /// the customer.
    fn served(schema: &TestSchema, customer_id: u32) -> (HostNetworkGroup, HostNetworkGroup) {
        let store = schema.store();
        (
            get_allow_networks(&store, customer_id).unwrap(),
            get_block_networks(&store, customer_id).unwrap(),
        )
    }

    #[tokio::test]
    async fn get_allow_and_block_networks_read_the_network_lists_table() {
        let schema = TestSchema::new().await;
        assert_eq!(served(&schema, 0), Default::default());

        let allowlist = [
            entry("office", r#"{ hosts: ["192.168.0.1"], networks: [], ranges: [] }"#),
            entry(
                "partner",
                r#"{ hosts: [], networks: ["172.16.0.0/12"], ranges: [{ start: "10.1.0.1", end: "10.1.0.9" }] }"#,
            ),
        ]
        .join(", ");
        let res = schema
            .execute_as_system_admin(&replace("0", "1", &allowlist, &entry("scanner", SCANNER)))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));
        assert_eq!(
            served(&schema, 0),
            (
                group(
                    &["192.168.0.1"],
                    &["172.16.0.0/12"],
                    &[("10.1.0.1", "10.1.0.9")]
                ),
                group(&["192.0.2.1"], &[], &[]),
            )
        );
        assert_eq!(served(&schema, 1), Default::default());

        let res = schema.execute_as_system_admin(&remove("0")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        assert_eq!(served(&schema, 0), Default::default());
    }
}
