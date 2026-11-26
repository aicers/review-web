//! The exclusion list and watchlist of each customer, keyed by customer ID.
//!
//! The network lists table holds a copy of every customer's exclusion list and
//! watchlist as the writer last sent them, and is the source of the lists hog
//! receives.
//!
//! The exclusion counts of a customer are read from the engine instance
//! records: how many raw events each engine kind excluded for each
//! exclusion-list entry, per UTC day.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use async_graphql::{Context, InputObject, Object, Result, SimpleObject, StringNumber, types::ID};
use review_database::{self as database, NetworkListReplaceOutcome, Store};
use tracing::{error, info};

use super::customer::{
    HostNetworkGroup, HostNetworkGroupInput, NetworkListItemsTargetAgentLookupKeysPair,
    send_agent_specific_exclusion_list, send_agent_specific_watchlist,
};
use super::customer_access::check_customer_membership;
use super::customer_network::{
    hog_agent_lookup_keys, parse_customer_id, stale_revision, validate_group,
};
use super::node::{AgentKind, SEMI_SUPERVISED_AGENT};
use super::{Role, RoleGuard};
use crate::graphql::timestamp::Timestamp;
use crate::{error_with_caller, info_with_caller};

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

/// Returns the exclusion list items of a customer, with their IDs, names and
/// groups, in stored order, or an empty vector if none is stored for it.
///
/// # Errors
///
/// Returns an error if the stored row could not be read or decoded.
pub fn get_exclusion_list(db: &Store, customer_id: u32) -> Result<Vec<database::NetworkListEntry>> {
    Ok(db.network_lists_map().exclusion_list_items(customer_id)?)
}

/// Returns the watchlist items of a customer, with their IDs, names and
/// groups, in stored order, or an empty vector if none is stored for it.
///
/// # Errors
///
/// Returns an error if the stored row could not be read or decoded.
pub fn get_watchlist(db: &Store, customer_id: u32) -> Result<Vec<database::NetworkListEntry>> {
    Ok(db.network_lists_map().watchlist_items(customer_id)?)
}

#[derive(Default)]
pub(super) struct NetworkListQuery;

#[Object]
impl NetworkListQuery {
    /// The exclusion list and watchlist of the customer, or null if none were
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

    /// The raw events the customer's engines excluded, summed per engine
    /// kind, exclusion-list entry and UTC day, ordered by engine kind, then
    /// entry, then day.
    ///
    /// `SEMI_SUPERVISED` counts are of the raw events the Semi-supervised
    /// Engine (hog) skipped before detection; `UNSUPERVISED` counts are of the
    /// raw events the Unsupervised Engine's detectors removed from their
    /// detection results. The two count different things and are never added
    /// together, so an entry and day can have one count of each. A customer
    /// with no reported counts gets an empty list.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn exclusion_counts(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
    ) -> Result<Vec<ExclusionCount>> {
        check_customer_membership(ctx, &customer_id)?;
        let customer_id = parse_customer_id(&customer_id)?;
        let store = crate::graphql::get_store(ctx)?;
        Ok(store
            .engine_exclusion_totals(customer_id)?
            .into_iter()
            .map(ExclusionCount::from)
            .collect())
    }
}

/// The raw events one engine kind excluded for one exclusion-list entry on
/// one UTC day, summed over the customer's engine instances.
#[derive(SimpleObject)]
struct ExclusionCount {
    /// The ID of the exclusion-list entry.
    entry_id: StringNumber<u64>,
    /// The UTC day the counted raw events fall on, as `YYYY-MM-DD`.
    day: String,
    /// The engine kind that excluded the raw events: `SEMI_SUPERVISED` or
    /// `UNSUPERVISED`.
    engine: AgentKind,
    /// The number of raw events excluded.
    count: StringNumber<u64>,
}

impl From<database::EngineExclusionTotal> for ExclusionCount {
    fn from(total: database::EngineExclusionTotal) -> Self {
        Self {
            entry_id: StringNumber(total.entry),
            day: total.day.to_string(),
            engine: total.engine.into(),
            count: StringNumber(total.count),
        }
    }
}

#[derive(Default)]
pub(super) struct NetworkListMutation;

#[Object]
impl NetworkListMutation {
    /// Replaces the exclusion list and watchlist of the customer, returning
    /// the stored revision.
    ///
    /// `exclusionList` and `watchlist` are the customer's full lists; empty
    /// lists are stored as such. A `revision` lower than the stored one is
    /// refused with the error code `STALE_REVISION`, whose `storedRevision`
    /// extension holds the stored revision.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn replace_network_lists(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        revision: StringNumber<u64>,
        exclusion_list: Vec<NetworkListEntryInput>,
        watchlist: Vec<NetworkListEntryInput>,
    ) -> Result<StringNumber<u64>> {
        check_customer_membership(ctx, &customer_id)?;
        let customer_id = parse_customer_id(&customer_id)?;
        let StringNumber(revision) = revision;
        let exclusion_list = validate_list(NetworkList::ExclusionList, exclusion_list)?;
        let watchlist = validate_list(NetworkList::Watchlist, watchlist)?;

        let _lock = lock_network_lists(ctx).await?;
        let pushes = {
            let store = crate::graphql::get_store(ctx)?;
            let outcome = store.network_lists_map().replace(
                customer_id,
                revision,
                exclusion_list.clone(),
                watchlist.clone(),
            )?;
            let previous = match outcome {
                NetworkListReplaceOutcome::Written { previous } => previous,
                NetworkListReplaceOutcome::Stale { stored } => return Err(stale_revision(stored)),
            };
            info_with_caller!(
                ctx,
                "Network lists of customer {customer_id} have been replaced at revision {revision}"
            );
            hog_pushes(
                ctx,
                &store,
                customer_id,
                previous.as_ref(),
                (exclusion_list, watchlist),
            )
        };
        send_pushes(ctx, customer_id, pushes).await;

        Ok(StringNumber(revision))
    }

    /// Removes the exclusion list and watchlist of the customer, returning
    /// whether any were stored.
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
            info_with_caller!(
                ctx,
                "Network lists of customer {customer_id} have been removed"
            );
            hog_pushes(ctx, &store, customer_id, Some(&removed), Default::default())
        };
        send_pushes(ctx, customer_id, pushes).await;

        Ok(true)
    }
}

/// The exclusion list and watchlist of a customer.
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

    /// The entries of the exclusion list.
    async fn exclusion_list(&self) -> Vec<NetworkListEntry<'_>> {
        self.inner
            .exclusion_list
            .iter()
            .map(|inner| NetworkListEntry { inner })
            .collect()
    }

    /// The entries of the watchlist.
    async fn watchlist(&self) -> Vec<NetworkListEntry<'_>> {
        self.inner
            .watchlist
            .iter()
            .map(|inner| NetworkListEntry { inner })
            .collect()
    }

    /// The time when this set was last written.
    async fn updated_at(&self) -> Timestamp {
        self.inner.updated_at.into()
    }
}

/// An entry of a customer's exclusion list or watchlist.
struct NetworkListEntry<'a> {
    inner: &'a database::NetworkListEntry,
}

#[Object]
impl NetworkListEntry<'_> {
    /// The writer's ID of the entry, unique within its list, as it was given.
    async fn id(&self) -> StringNumber<u64> {
        StringNumber(self.inner.id)
    }

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
    /// The writer's ID of the entry, unique within its list and stored as
    /// given. The same ID may appear in both the exclusion list and the
    /// watchlist.
    id: StringNumber<u64>,
    name: String,
    network_group: HostNetworkGroupInput,
}

/// One of a customer's two lists.
#[derive(Clone, Copy)]
enum NetworkList {
    ExclusionList,
    Watchlist,
}

impl fmt::Display for NetworkList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ExclusionList => "exclusion list",
            Self::Watchlist => "watchlist",
        })
    }
}

/// Checks the whole of `entries` and converts it, so that one invalid entry
/// rejects the call before anything is written.
///
/// # Errors
///
/// Returns an error, naming `list`, if there are too many entries, an ID is
/// repeated, a name is empty or repeated, or a network group is empty, too
/// large, unparsable, or holds a range that ends before it starts or mixes
/// address families.
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
    let mut ids = HashSet::with_capacity(entries.len());
    let mut names = HashSet::with_capacity(entries.len());
    for entry in &entries {
        if entry.name.trim().is_empty() {
            return Err(format!("{list} entry name must not be empty").into());
        }
        if !names.insert(entry.name.as_str()) {
            return Err(format!("duplicate {list} entry name {:?}", entry.name).into());
        }
        let StringNumber(id) = entry.id;
        if !ids.insert(id) {
            return Err(format!("duplicate {list} entry id {id}").into());
        }
    }

    entries
        .into_iter()
        .map(|entry| {
            let group = validate_group(&entry.network_group)
                .map_err(|e| format!("{list} entry {:?}: {e}", entry.name))?;
            Ok(database::NetworkListEntry {
                id: entry.id.0,
                name: entry.name,
                group,
            })
        })
        .collect()
}

/// The items of the exclusion list and the watchlist, in that order.
type ListItems = (
    Vec<database::NetworkListEntry>,
    Vec<database::NetworkListEntry>,
);

/// Returns the pushes that bring the customer's hog agents from `previous` to
/// the `(exclusion_list, watchlist)` items in `current`: one for each list
/// whose items changed, to the hog agents of the customer's nodes.
///
/// Items are compared by ID, name and group, in order, so a list whose entries
/// were only renamed, renumbered or reordered is pushed too: hog names the
/// entry it matched by its ID. An absent `previous` counts as two empty lists.
/// A push carries the list's full items, so a list whose items are unchanged
/// is skipped only because there is nothing to send.
fn hog_pushes(
    ctx: &Context<'_>,
    store: &Store,
    customer_id: u32,
    previous: Option<&database::NetworkListSet>,
    current: ListItems,
) -> Vec<(NetworkList, NetworkListItemsTargetAgentLookupKeysPair)> {
    let no_items: &[database::NetworkListEntry] = &[];
    let (previous_exclusion_list, previous_watchlist) = previous
        .map_or((no_items, no_items), |set| {
            (set.exclusion_list.as_slice(), set.watchlist.as_slice())
        });
    let (exclusion_list, watchlist) = current;
    let changed: Vec<_> = [
        (
            NetworkList::ExclusionList,
            exclusion_list,
            previous_exclusion_list,
        ),
        (NetworkList::Watchlist, watchlist, previous_watchlist),
    ]
    .into_iter()
    .filter(|(_, current, previous)| current.as_slice() != *previous)
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
        .map(|(list, items)| {
            (
                list,
                NetworkListItemsTargetAgentLookupKeysPair::new(
                    items,
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
    pushes: Vec<(NetworkList, NetworkListItemsTargetAgentLookupKeysPair)>,
) {
    for (list, push) in pushes {
        let sent = match list {
            NetworkList::ExclusionList => send_agent_specific_exclusion_list(ctx, &[push]).await,
            NetworkList::Watchlist => send_agent_specific_watchlist(ctx, &[push]).await,
        };
        if let Err(e) = sent {
            error_with_caller!(
                ctx,
                "Failed to send the {list} of customer {customer_id} to its agents: {e:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use review_database::{
        AgentKind, DetectorState, DetectorStatus, EngineDetectorRef, EngineDocumentRefs,
        EngineDocumentWrite, HostNetworkGroup, NetworkListEntry, NodeUpdate, Store,
    };
    use review_protocol::types::{EngineExclusionReport, ExcludedCount};
    use serde_json::{Value, json};

    use super::{get_exclusion_list, get_watchlist};
    use crate::graphql::{
        Role, TestSchema,
        model_test_support::TestModel,
        push_test_support::{
            ItemsPush, Push, PushKind, failing_schema, group, insert_node, paused_schema,
            recording_schema,
        },
        run_test_support::{insert_agent_node, insert_engine_instance},
    };

    fn replace(customer_id: &str, revision: &str, exclusion_list: &str, watchlist: &str) -> String {
        format!(
            r#"mutation {{ replaceNetworkLists(customerId: "{customer_id}", revision: "{revision}", exclusionList: [{exclusion_list}], watchlist: [{watchlist}]) }}"#
        )
    }

    /// Returns the ID the tests give the entry named `name`, so that entries
    /// with distinct names get distinct IDs.
    fn entry_id(name: &str) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        name.bytes().fold(FNV_OFFSET, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
        })
    }

    fn entry(name: &str, group: &str) -> String {
        entry_with_id(entry_id(name), name, group)
    }

    fn entry_with_id(id: u64, name: &str, group: &str) -> String {
        format!(r#"{{ id: "{id}", name: "{name}", networkGroup: {group} }}"#)
    }

    fn query(customer_id: &str) -> String {
        format!(
            r#"{{ networkLists(customerId: "{customer_id}") {{
                customerId revision updatedAt
                exclusionList {{ name networkGroup {{ hosts networks ranges {{ start end }} }} }}
                watchlist {{ name networkGroup {{ hosts networks ranges {{ start end }} }} }}
            }} }}"#
        )
    }

    fn remove(customer_id: &str) -> String {
        format!(r#"mutation {{ removeNetworkLists(customerId: "{customer_id}") }}"#)
    }

    fn counts(customer_id: &str) -> String {
        format!(
            r#"{{ exclusionCounts(customerId: "{customer_id}") {{ entryId day engine count }} }}"#
        )
    }

    const OFFICE: &str = r#"{ hosts: [], networks: ["10.0.0.0/8"], ranges: [] }"#;
    const SCANNER: &str = r#"{ hosts: ["192.0.2.1"], networks: [], ranges: [] }"#;

    fn stored_entry(name: &str, group: HostNetworkGroup) -> NetworkListEntry {
        stored_entry_with_id(entry_id(name), name, group)
    }

    fn stored_entry_with_id(id: u64, name: &str, group: HostNetworkGroup) -> NetworkListEntry {
        NetworkListEntry {
            id,
            name: name.to_string(),
            group,
        }
    }

    fn office() -> HostNetworkGroup {
        group(&[], &["10.0.0.0/8"], &[])
    }

    fn scanner() -> HostNetworkGroup {
        group(&["192.0.2.1"], &[], &[])
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

        let exclusion_list = [
            entry("office", OFFICE),
            entry(
                "partner",
                r#"{ hosts: ["2001:db8::1"], networks: [], ranges: [{ start: "192.168.1.1", end: "192.168.1.9" }] }"#,
            ),
        ]
        .join(", ");
        let res = as_admin(replace(
            "7",
            "3",
            &exclusion_list,
            &entry("office", SCANNER),
        ))
        .await;
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
                "exclusionList": [
                    { "name": "office", "networkGroup": {
                        "hosts": [], "networks": ["10.0.0.0/8"], "ranges": [] } },
                    { "name": "partner", "networkGroup": {
                        "hosts": ["2001:db8::1"], "networks": [],
                        "ranges": [{ "start": "192.168.1.1", "end": "192.168.1.9" }] } },
                ],
                "watchlist": [
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
        for query in [
            query("8"),
            replace("8", "2", "", ""),
            remove("8"),
            counts("8"),
        ] {
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
            for query in [
                query("7"),
                replace("7", "2", "", ""),
                remove("7"),
                counts("7"),
            ] {
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
                counts(customer_id),
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
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (1, 0)
        );
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
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (1, 0)
        );

        // An equal revision overwrites the row.
        let res = schema
            .execute_as_system_admin(&replace("7", "5", "", &entry("scanner", SCANNER)))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "5" }));
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (2, 1)
        );

        // So does a higher one.
        let res = schema
            .execute_as_system_admin(&replace("7", "6", "", ""))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "6" }));
        let stored = schema.store().network_lists_map().get(7).unwrap().unwrap();
        assert_eq!(
            (
                stored.revision,
                stored.exclusion_list.len(),
                stored.watchlist.len()
            ),
            (6, 0, 0)
        );
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (2, 2)
        );
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
                ("exclusion list", replace("7", "1", entries, &valid)),
                ("watchlist", replace("7", "1", &valid, entries)),
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
        // The exclusion list is checked first.
        let res = schema
            .execute_as_system_admin(&replace("7", "1", &entry(" ", OFFICE), &entry("", OFFICE)))
            .await;
        assert_eq!(
            error_message(&res),
            "exclusion list entry name must not be empty"
        );
        assert_eq!(pushes.exclusion_list(), Vec::<ItemsPush>::new());
        assert_eq!(pushes.watchlist(), Vec::<ItemsPush>::new());

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
                stored.exclusion_list.len(),
                stored.watchlist.len()
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

        // A first write with an exclusion list only pushes the exclusion list.
        let exclusion_list = [
            entry("office", OFFICE),
            entry(
                "edge",
                r#"{ hosts: ["192.168.0.1"], networks: ["2001:db8::/32"], ranges: [{ start: "172.16.0.1", end: "172.16.0.9" }] }"#,
            ),
        ]
        .join(", ");
        let res = schema
            .execute_as_scoped_user(
                &replace("7", "1", &exclusion_list, ""),
                Role::SecurityAdministrator,
                Some(vec![7]),
            )
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));
        let items = vec![
            stored_entry("office", office()),
            stored_entry(
                "edge",
                group(
                    &["192.168.0.1"],
                    &["2001:db8::/32"],
                    &[("172.16.0.1", "172.16.0.9")],
                ),
            ),
        ];
        assert_eq!(pushes.exclusion_list(), vec![vec![(n7.clone(), items)]]);
        assert_eq!(pushes.watchlist(), Vec::<ItemsPush>::new());
        assert_eq!(pushes.internal(), Vec::<Push>::new());

        // Renaming the entries and splitting them differently covers the same
        // addresses, but hog names the entry it matched, so it is pushed.
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
        let renamed_items = vec![
            stored_entry("a", group(&["192.168.0.1"], &["10.0.0.0/8"], &[])),
            stored_entry(
                "b",
                group(
                    &[],
                    &["2001:db8::/32", "10.0.0.0/8"],
                    &[("172.16.0.1", "172.16.0.9")],
                ),
            ),
        ];
        assert_eq!(
            pushes.exclusion_list().get(1),
            Some(&vec![(n7.clone(), renamed_items)])
        );
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (2, 0)
        );

        // A watchlist change pushes only the watchlist.
        let res = schema
            .execute_as_system_admin(&replace("7", "3", &renamed, &entry("scanner", SCANNER)))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "3" }));
        assert_eq!(pushes.exclusion_list().len(), 2);
        assert_eq!(
            pushes.watchlist(),
            vec![vec![(n7.clone(), vec![stored_entry("scanner", scanner())])]]
        );
        assert_eq!(pushes.internal(), Vec::<Push>::new());
    }

    #[tokio::test]
    async fn remove_pushes_empty_item_lists_for_non_empty_lists() {
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
            pushes.exclusion_list(),
            vec![vec![(n7.clone(), Vec::new())]]
        );
        assert_eq!(pushes.watchlist(), Vec::<ItemsPush>::new());

        // Nothing was removed, so nothing is pushed.
        let res = schema.execute_as_system_admin(&remove("7")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": false }));
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (1, 0)
        );

        // Both lists were non-empty, so both are pushed.
        let res = schema.execute_as_system_admin(&remove("8")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        let n8 = vec!["001.hog.n8.example.com".to_string()];
        assert_eq!(
            pushes.exclusion_list().get(1),
            Some(&vec![(n8.clone(), Vec::new())])
        );
        assert_eq!(pushes.watchlist(), vec![vec![(n8, Vec::new())]]);
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
        // A changing replacement does not push either.
        let res = schema
            .execute_as_system_admin(&replace(
                "7",
                "2",
                &entry("partner", SCANNER),
                &entry("botnet", OFFICE),
            ))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "2" }));
        let res = schema.execute_as_system_admin(&remove("7")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        assert_eq!(pushes.exclusion_list(), Vec::<ItemsPush>::new());
        assert_eq!(pushes.watchlist(), Vec::<ItemsPush>::new());
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
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (2, 2)
        );
    }

    #[tokio::test]
    async fn concurrent_replaces_push_in_the_order_they_were_stored() {
        const CUSTOMER: u32 = 7;
        let (schema, pushes, pause) = paused_schema(PushKind::ExclusionList).await;
        insert_node(&schema, CUSTOMER, "n.example.com");
        let target = vec!["001.hog.n.example.com".to_string()];
        let older_exclusion_list = vec![stored_entry("a", office())];
        let older_watchlist = vec![stored_entry("b", scanner())];
        let newer_exclusion_list = vec![stored_entry("a", scanner())];
        let newer_watchlist = vec![stored_entry("b", office())];
        let id = CUSTOMER.to_string();
        let older = replace(&id, "5", &entry("a", OFFICE), &entry("b", SCANNER));
        let newer = replace(&id, "6", &entry("a", SCANNER), &entry("b", OFFICE));
        let newer_done = AtomicBool::new(false);

        let (older_res, newer_res, ()) = tokio::join!(
            schema.execute_as_system_admin(&older),
            async {
                // Starts once the older replace is paused in its exclusion
                // list push.
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
                assert_eq!(
                    pushes.exclusion_list(),
                    vec![vec![(target.clone(), older_exclusion_list.clone())]]
                );
                assert_eq!(pushes.watchlist(), Vec::<ItemsPush>::new());
                pause.release.notify_one();
            },
        );

        assert_eq!(data(older_res), json!({ "replaceNetworkLists": "5" }));
        assert_eq!(data(newer_res), json!({ "replaceNetworkLists": "6" }));
        assert_eq!(
            pushes.exclusion_list(),
            vec![
                vec![(target.clone(), older_exclusion_list)],
                vec![(target.clone(), newer_exclusion_list)],
            ]
        );
        assert_eq!(
            pushes.watchlist(),
            vec![
                vec![(target.clone(), older_watchlist)],
                vec![(target, newer_watchlist)],
            ]
        );
        let stored = schema.store().network_lists_map().get(CUSTOMER).unwrap();
        assert_eq!(stored.map(|set| set.revision), Some(6));
        assert_eq!(schema.network_lists_lock_users(), 0);
    }

    /// Returns what `get_exclusion_list` and `get_watchlist` return for
    /// the customer.
    fn served(
        schema: &TestSchema,
        customer_id: u32,
    ) -> (Vec<NetworkListEntry>, Vec<NetworkListEntry>) {
        let store = schema.store();
        (
            get_exclusion_list(&store, customer_id).unwrap(),
            get_watchlist(&store, customer_id).unwrap(),
        )
    }

    #[tokio::test]
    async fn get_exclusion_list_and_watchlist_read_the_network_lists_table() {
        let schema = TestSchema::new().await;
        assert_eq!(served(&schema, 0), Default::default());

        let exclusion_list = [
            entry("office", r#"{ hosts: ["192.168.0.1"], networks: [], ranges: [] }"#),
            entry(
                "partner",
                r#"{ hosts: [], networks: ["172.16.0.0/12"], ranges: [{ start: "10.1.0.1", end: "10.1.0.9" }] }"#,
            ),
        ]
        .join(", ");
        let res = schema
            .execute_as_system_admin(&replace(
                "0",
                "1",
                &exclusion_list,
                &entry("scanner", SCANNER),
            ))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));
        // Each reader returns the items of its own list, in stored order.
        assert_eq!(
            served(&schema, 0),
            (
                vec![
                    stored_entry("office", group(&["192.168.0.1"], &[], &[])),
                    stored_entry(
                        "partner",
                        group(&[], &["172.16.0.0/12"], &[("10.1.0.1", "10.1.0.9")]),
                    ),
                ],
                vec![stored_entry("scanner", scanner())],
            )
        );
        assert_eq!(served(&schema, 1), Default::default());

        // The order is the replacement's, not a sorted one.
        let reordered = [
            entry(
                "partner",
                r#"{ hosts: [], networks: ["172.16.0.0/12"], ranges: [] }"#,
            ),
            entry(
                "office",
                r#"{ hosts: ["192.168.0.1"], networks: [], ranges: [] }"#,
            ),
        ]
        .join(", ");
        let res = schema
            .execute_as_system_admin(&replace("0", "2", "", &reordered))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "2" }));
        assert_eq!(
            served(&schema, 0),
            (
                Vec::new(),
                vec![
                    stored_entry("partner", group(&[], &["172.16.0.0/12"], &[])),
                    stored_entry("office", group(&["192.168.0.1"], &[], &[])),
                ],
            )
        );

        let res = schema.execute_as_system_admin(&remove("0")).await;
        assert_eq!(data(res), json!({ "removeNetworkLists": true }));
        assert_eq!(served(&schema, 0), Default::default());
    }

    #[tokio::test]
    async fn entry_without_id_is_refused() {
        let schema = TestSchema::new().await;
        let no_id = format!(r#"{{ name: "office", networkGroup: {OFFICE} }}"#);
        let res = schema
            .execute_as_system_admin(&replace("7", "1", &no_id, ""))
            .await;
        assert!(!res.errors.is_empty(), "expected an error, got {res:?}");
        let res = schema.execute_as_system_admin(&query("7")).await;
        assert_eq!(data(res), json!({ "networkLists": null }));
    }

    #[tokio::test]
    async fn duplicate_id_within_a_list_is_refused_and_nothing_is_stored() {
        let schema = TestSchema::new().await;
        for (exclusion_list, watchlist, list) in [
            (
                [
                    entry_with_id(4, "office", OFFICE),
                    entry_with_id(4, "scanner", SCANNER),
                ]
                .join(", "),
                String::new(),
                "exclusion list",
            ),
            (
                String::new(),
                [
                    entry_with_id(9, "office", OFFICE),
                    entry_with_id(9, "scanner", SCANNER),
                ]
                .join(", "),
                "watchlist",
            ),
        ] {
            let res = schema
                .execute_as_system_admin(&replace("7", "1", &exclusion_list, &watchlist))
                .await;
            let message = error_message(&res);
            assert!(
                message.starts_with(&format!("duplicate {list} entry id ")),
                "unexpected error: {message}"
            );
        }
        let res = schema.execute_as_system_admin(&query("7")).await;
        assert_eq!(data(res), json!({ "networkLists": null }));
        assert!(schema.store().network_lists_map().get(7).unwrap().is_none());
    }

    #[tokio::test]
    async fn ids_are_stored_verbatim_and_may_repeat_across_lists() {
        // Above 2^53, where a JSON number would lose precision.
        const WIDE_ID: u64 = (1 << 53) + 1;

        let schema = TestSchema::new().await;
        let exclusion_list = [
            entry_with_id(WIDE_ID, "office", OFFICE),
            entry_with_id(u64::MAX, "partner", SCANNER),
        ]
        .join(", ");
        let watchlist = entry_with_id(WIDE_ID, "scanner", SCANNER);
        let res = schema
            .execute_as_system_admin(&replace("7", "1", &exclusion_list, &watchlist))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));

        let stored = schema.store().network_lists_map().get(7).unwrap().unwrap();
        assert_eq!(
            stored
                .exclusion_list
                .iter()
                .map(|e| e.id)
                .collect::<Vec<_>>(),
            [WIDE_ID, u64::MAX]
        );
        assert_eq!(
            stored.watchlist.iter().map(|e| e.id).collect::<Vec<_>>(),
            [WIDE_ID]
        );

        let res = schema
            .execute_as_system_admin(
                r#"{ networkLists(customerId: "7") { exclusionList { id name } watchlist { id name } } }"#,
            )
            .await;
        assert_eq!(
            data(res),
            json!({ "networkLists": {
                "exclusionList": [
                    { "id": WIDE_ID.to_string(), "name": "office" },
                    { "id": u64::MAX.to_string(), "name": "partner" },
                ],
                "watchlist": [{ "id": WIDE_ID.to_string(), "name": "scanner" }],
            } })
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one step per kind of item change
    async fn replace_pushes_a_list_whose_items_change_in_name_id_or_order_only() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");
        let n7 = vec!["001.hog.n7.example.com".to_string()];
        let watchlist = entry_with_id(3, "scanner", SCANNER);
        let send = |revision: &'static str, exclusion_list: String, watchlist: String| {
            let schema = &schema;
            async move {
                schema
                    .execute_as_system_admin(&replace("7", revision, &exclusion_list, &watchlist))
                    .await
            }
        };

        let res = send(
            "1",
            [
                entry_with_id(1, "office", OFFICE),
                entry_with_id(2, "partner", SCANNER),
            ]
            .join(", "),
            watchlist.clone(),
        )
        .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (1, 1)
        );

        // Only a name changes.
        let res = send(
            "2",
            [
                entry_with_id(1, "main office", OFFICE),
                entry_with_id(2, "partner", SCANNER),
            ]
            .join(", "),
            watchlist.clone(),
        )
        .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "2" }));
        assert_eq!(
            pushes.exclusion_list().last(),
            Some(&vec![(
                n7.clone(),
                vec![
                    stored_entry_with_id(1, "main office", office()),
                    stored_entry_with_id(2, "partner", scanner()),
                ]
            )])
        );
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (2, 1)
        );

        // Only an ID changes.
        let res = send(
            "3",
            [
                entry_with_id(10, "main office", OFFICE),
                entry_with_id(2, "partner", SCANNER),
            ]
            .join(", "),
            watchlist.clone(),
        )
        .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "3" }));
        assert_eq!(
            pushes.exclusion_list().last(),
            Some(&vec![(
                n7.clone(),
                vec![
                    stored_entry_with_id(10, "main office", office()),
                    stored_entry_with_id(2, "partner", scanner()),
                ]
            )])
        );
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (3, 1)
        );

        // Only the order changes.
        let reordered = [
            entry_with_id(2, "partner", SCANNER),
            entry_with_id(10, "main office", OFFICE),
        ]
        .join(", ");
        let res = send("4", reordered.clone(), watchlist.clone()).await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "4" }));
        assert_eq!(
            pushes.exclusion_list().last(),
            Some(&vec![(
                n7.clone(),
                vec![
                    stored_entry_with_id(2, "partner", scanner()),
                    stored_entry_with_id(10, "main office", office()),
                ]
            )])
        );
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (4, 1)
        );

        // Identical items in the same order push nothing, even at a new
        // revision.
        let res = send("5", reordered.clone(), watchlist.clone()).await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "5" }));
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (4, 1)
        );

        // A change to the watchlist alone pushes only the watchlist.
        let res = send(
            "6",
            reordered.clone(),
            entry_with_id(3, "scanners", SCANNER),
        )
        .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "6" }));
        assert_eq!(
            pushes.watchlist().last(),
            Some(&vec![(
                n7.clone(),
                vec![stored_entry_with_id(3, "scanners", scanner())]
            )])
        );
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (4, 2)
        );

        // A stale replacement that would change both lists pushes nothing.
        let res = send("5", entry_with_id(4, "other", OFFICE), String::new()).await;
        assert_eq!(error_message(&res), "stale revision");
        assert_eq!(
            (pushes.exclusion_list().len(), pushes.watchlist().len()),
            (4, 2)
        );
    }

    #[tokio::test]
    async fn pushed_ids_are_the_ids_given() {
        // Above 2^53, where a JSON number would lose precision.
        const WIDE_ID: u64 = (1 << 53) + 1;

        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");
        let exclusion_list = [
            entry_with_id(WIDE_ID, "office", OFFICE),
            entry_with_id(u64::MAX, "partner", SCANNER),
        ]
        .join(", ");
        let watchlist = entry_with_id(WIDE_ID, "scanner", SCANNER);
        let res = schema
            .execute_as_system_admin(&replace("7", "1", &exclusion_list, &watchlist))
            .await;
        assert_eq!(data(res), json!({ "replaceNetworkLists": "1" }));

        let ids = |pushes: Vec<ItemsPush>| -> Vec<Vec<u64>> {
            pushes
                .into_iter()
                .flatten()
                .map(|(_, items)| items.into_iter().map(|item| item.id).collect())
                .collect()
        };
        assert_eq!(ids(pushes.exclusion_list()), vec![vec![WIDE_ID, u64::MAX]]);
        assert_eq!(ids(pushes.watchlist()), vec![vec![WIDE_ID]]);
    }

    #[test]
    fn get_exclusion_list_and_watchlist_fail_on_an_undecodable_row() {
        const CUSTOMER_ID: u32 = 7;
        const STATES_DIRECTORY: &str = "states.db";
        const NETWORK_LISTS_COLUMN_FAMILY: &str = "network lists";

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        {
            // Match review-database's layout and write an undecodable row.
            // Close the raw database before Store opens it and creates the
            // remaining tables.
            let mut options = rocksdb::Options::default();
            options.create_if_missing(true);
            options.create_missing_column_families(true);
            let db = rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open_cf(
                &options,
                db_dir.path().join(STATES_DIRECTORY),
                [NETWORK_LISTS_COLUMN_FAMILY],
            )
            .unwrap();
            let column_family = db.cf_handle(NETWORK_LISTS_COLUMN_FAMILY).unwrap();
            db.put_cf(column_family, CUSTOMER_ID.to_be_bytes(), [0xff])
                .unwrap();
        }
        let store = Store::new(db_dir.path(), backup_dir.path(), None).unwrap();

        assert!(get_exclusion_list(&store, CUSTOMER_ID).is_err());
        assert!(get_watchlist(&store, CUSTOMER_ID).is_err());
        // Another customer's row is not read.
        assert_eq!(get_exclusion_list(&store, CUSTOMER_ID + 1).unwrap(), []);
        assert_eq!(get_watchlist(&store, CUSTOMER_ID + 1).unwrap(), []);
    }

    #[tokio::test]
    async fn old_argument_names_are_refused_and_nothing_is_stored_or_pushed() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");

        let office = entry("office", OFFICE);
        let scanner = entry("scanner", SCANNER);
        for query in [
            format!(
                r#"mutation {{ replaceNetworkLists(customerId: "7", revision: "1", allowlist: [{office}], blocklist: [{scanner}]) }}"#
            ),
            format!(
                r#"mutation {{ replaceNetworkLists(customerId: "7", revision: "1", allowlist: [{office}], watchlist: [{scanner}]) }}"#
            ),
            format!(
                r#"mutation {{ replaceNetworkLists(customerId: "7", revision: "1", exclusionList: [{office}], blocklist: [{scanner}]) }}"#
            ),
        ] {
            let res = schema.execute_as_system_admin(&query).await;
            assert!(!res.errors.is_empty(), "expected a refusal: {query}");
            assert!(
                res.errors.iter().any(|e| {
                    e.message.contains("Unknown argument \"allowlist\"")
                        || e.message.contains("Unknown argument \"blocklist\"")
                }),
                "unexpected errors: {:?}",
                res.errors
            );
        }
        for query in [
            r#"{ networkLists(customerId: "7") { allowlist { id } } }"#,
            r#"{ networkLists(customerId: "7") { blocklist { id } } }"#,
        ] {
            let res = schema.execute_as_system_admin(query).await;
            assert!(!res.errors.is_empty(), "expected a refusal: {query}");
        }
        assert!(schema.store().network_lists_map().get(7).unwrap().is_none());
        assert_eq!(pushes.exclusion_list(), Vec::<ItemsPush>::new());
        assert_eq!(pushes.watchlist(), Vec::<ItemsPush>::new());
    }

    const DAY_1: jiff::civil::Date = jiff::civil::date(2026, 11, 3);
    const DAY_2: jiff::civil::Date = jiff::civil::date(2026, 11, 4);
    /// Above 2^53, where a JSON number would lose precision.
    const WIDE: u64 = (1 << 53) + 1;

    fn excluded(entry: u64, day: jiff::civil::Date, count: u64) -> ExcludedCount {
        ExcludedCount { entry, day, count }
    }

    /// Stores a node of `customer_id` with a hog instance that reported
    /// `counts`.
    fn insert_hog_report(
        store: &Store,
        customer_id: u32,
        hostname: &str,
        counts: Vec<ExcludedCount>,
    ) {
        let hog = insert_agent_node(
            store,
            customer_id,
            hostname,
            "001.hog",
            AgentKind::SemiSupervised,
            Some(1),
        );
        store
            .set_engine_exclusion_report(&hog, &EngineExclusionReport { counts })
            .unwrap();
    }

    /// Stores a node of `customer_id` with an Unsupervised Engine instance
    /// whose detectors `1..` reported the `excluded` counts of `statuses`, one
    /// status per detector.
    fn insert_reconverge_statuses(
        store: &Store,
        customer_id: u32,
        hostname: &str,
        statuses: Vec<Vec<ExcludedCount>>,
    ) {
        let instance = insert_engine_instance(store, customer_id, hostname, "001.reconverge");
        let detectors: Vec<(i32, String)> = (1..)
            .zip(&statuses)
            .map(|(id, _)| (id, format!("model-{hostname}-{id}")))
            .collect();
        for (_, model) in &detectors {
            TestModel {
                instance: instance.clone(),
                ..TestModel::new(model, customer_id)
            }
            .replace(store);
        }
        let mut map = store.node_map();
        let (node, _, _) = map
            .get_by_id(instance.node_id)
            .expect("read engine node")
            .expect("engine node exists");
        let update = NodeUpdate::from(node);
        let document = EngineDocumentWrite {
            agent_key: instance.agent_key.clone(),
            applied: Some(EngineDocumentRefs {
                detectors: detectors
                    .iter()
                    .map(|(id, model)| EngineDetectorRef {
                        id: *id,
                        model: model.clone(),
                        sources: vec![],
                        indicator: None,
                    })
                    .collect(),
            }),
            pending: None,
        };
        map.update_with_engine_documents(instance.node_id, &update, &update, &[document])
            .expect("write engine document references");
        for ((id, _), excluded) in detectors.iter().zip(statuses) {
            let status = DetectorStatus {
                state: DetectorState::Running,
                finished_at: None,
                outcome: None,
                reason: None,
                events: 0,
                sources: vec![],
                detection_models: vec![],
                excluded,
                reported_at: jiff::Timestamp::UNIX_EPOCH,
            };
            store.set_detector_status(&instance, *id, &status).unwrap();
        }
    }

    #[tokio::test]
    async fn exclusion_counts_return_each_engines_totals_in_stored_order() {
        let schema = TestSchema::new().await;
        {
            let store = schema.store();
            // Customer 7 has two hog instances and one Unsupervised Engine
            // instance with two detectors; entry 5 on DAY_1 is counted by both
            // kinds.
            insert_hog_report(
                &store,
                7,
                "hog-7a.example.com",
                vec![
                    excluded(5, DAY_2, 3),
                    excluded(5, DAY_1, 10),
                    excluded(2, DAY_1, 4),
                ],
            );
            insert_hog_report(
                &store,
                7,
                "hog-7b.example.com",
                vec![excluded(5, DAY_1, 1), excluded(WIDE, DAY_1, WIDE)],
            );
            insert_reconverge_statuses(
                &store,
                7,
                "engine-7.example.com",
                vec![
                    vec![excluded(5, DAY_1, 6)],
                    vec![excluded(5, DAY_1, 2), excluded(9, DAY_2, 1)],
                ],
            );
            // Customer 8's counts are not customer 7's.
            insert_hog_report(
                &store,
                8,
                "hog-8.example.com",
                vec![excluded(5, DAY_1, 100)],
            );
            insert_reconverge_statuses(
                &store,
                8,
                "engine-8.example.com",
                vec![vec![excluded(5, DAY_1, 200)]],
            );
        }

        let expected = json!({ "exclusionCounts": [
            { "entryId": "5", "day": "2026-11-03", "engine": "UNSUPERVISED", "count": "8" },
            { "entryId": "9", "day": "2026-11-04", "engine": "UNSUPERVISED", "count": "1" },
            { "entryId": "2", "day": "2026-11-03", "engine": "SEMI_SUPERVISED", "count": "4" },
            { "entryId": "5", "day": "2026-11-03", "engine": "SEMI_SUPERVISED", "count": "11" },
            { "entryId": "5", "day": "2026-11-04", "engine": "SEMI_SUPERVISED", "count": "3" },
            { "entryId": WIDE.to_string(), "day": "2026-11-03", "engine": "SEMI_SUPERVISED",
              "count": WIDE.to_string() },
        ] });
        let res = schema.execute_as_system_admin(&counts("7")).await;
        assert_eq!(data(res), expected);
        let res = schema
            .execute_as_scoped_user(&counts("7"), Role::SecurityAdministrator, Some(vec![7]))
            .await;
        assert_eq!(data(res), expected);

        let res = schema.execute_as_system_admin(&counts("8")).await;
        assert_eq!(
            data(res),
            json!({ "exclusionCounts": [
                { "entryId": "5", "day": "2026-11-03", "engine": "UNSUPERVISED", "count": "200" },
                { "entryId": "5", "day": "2026-11-03", "engine": "SEMI_SUPERVISED", "count": "100" },
            ] })
        );

        // A customer with no reports, with or without nodes, gets nothing.
        insert_node(&schema, 9, "n9.example.com");
        for customer_id in ["9", "10"] {
            let res = schema.execute_as_system_admin(&counts(customer_id)).await;
            assert_eq!(data(res), json!({ "exclusionCounts": [] }));
        }
    }
}
