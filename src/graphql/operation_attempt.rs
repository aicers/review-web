//! The read surface over `review`'s operation-attempt ledger.
//!
//! The inline install-state fields say what a host has installed; they cannot
//! say whether an update is in flight, or whether the one that just ran
//! succeeded, failed or rolled back. A rolled-back update and an update that
//! never ran both end at the old version with `lifecycle = RUNNING`, and the
//! attempt record is the only thing that tells them apart.
//!
//! This crate reads the ledger and never writes it. `review` owns every
//! transition, so nothing here calls `upsert`, `delete`, `sweep_expired` or
//! `prune`.

use async_graphql::{Context, Enum, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database::{self as database, Store, event::Direction};

use super::{Role, RoleGuard, customer_access, install_state, node::deploy::bind_package_class};
use crate::backend::{CORE_PACKAGE_IDS, MODULE_PACKAGE_IDS};

/// The refusal message every role and customer-scope rejection in this crate
/// carries.
const FORBIDDEN: &str = "Forbidden";

/// The root of the operation-attempt queries.
#[derive(Default)]
pub(super) struct OperationAttemptQuery;

/// The operator's intent for an attempt.
///
/// It mirrors `review_database::OperationAction` one variant for one variant.
/// The stored enum carries no fallback variant, so this one invents no
/// `UNKNOWN`: a variant added upstream stops the `remote` conversion — and so
/// this crate — from compiling, which is the point.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::OperationAction")]
pub(crate) enum OperationAction {
    Install,
    Update,
    Remove,
    Onboard,
}

/// How far `review` has driven an attempt.
///
/// It mirrors `review_database::OperationPhase`, and is coarse for the same
/// reason the stored enum is: the fine verify/enroll/start sub-steps belong to
/// the host agent and are not recorded.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::OperationPhase")]
pub(crate) enum OperationPhase {
    Pending,
    Dispatched,
    AwaitingReport,
    Completed,
}

/// The terminal result of an attempt.
///
/// It mirrors `review_database::OperationOutcome`. `ROLLED_BACK` is what
/// distinguishes an update that put the previous build back from one that
/// never ran, which the installed version alone cannot.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::OperationOutcome")]
pub(crate) enum OperationOutcome {
    Succeeded,
    Failed,
    RolledBack,
    Cancelled,
}

/// The compensation an attempt still owes.
///
/// It mirrors `review_database::OperationCleanupState`, and it is an enum
/// rather than a human-readable reason: the two states are different things to
/// say and different things to do, so a UI has to branch on the variant, and
/// server-composed English could be neither localised nor branched on.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::OperationCleanupState")]
pub(crate) enum OperationCleanupState {
    PendingDeregister,
    PendingIdentityTeardown,
}

/// Which tier may read one attempt.
///
/// The decision is the row's, taken from its `action` and its `target` and
/// never from anything the caller said.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptAccess {
    /// `SystemAdministrator` alone, with no host-scoped check. There is no
    /// customer mapping to scope an onboarding or a control-plane package by,
    /// and an unrecognised target takes this side rather than the weaker one.
    SystemAdministratorOnly,
    /// Either administrator tier, scoped to the host the row names.
    HostScoped,
}

/// Returns which tier may read an attempt with this `action` and `target`.
///
/// The four branches are the whole rule, and each one exists so that reading
/// an operation is never looser than starting it:
///
/// - an `Onboard` attempt names a host that is not a node yet and carries no
///   target, so there is nothing to classify and nothing to scope by, and
///   `onboardHost` is `SystemAdministrator`-only;
/// - a core package-id matches `updateCoreComponent`, which gets no customer
///   scoping precisely because it is control-plane;
/// - a module package-id is customer-scoped against the host the row names;
/// - anything else, `bootroot` and any target this build does not recognise
///   included, takes the stricter side, so a target added upstream is not
///   readable by the weaker tier until someone decides it should be.
fn required_access(action: database::OperationAction, target: &str) -> AttemptAccess {
    if action == database::OperationAction::Onboard {
        return AttemptAccess::SystemAdministratorOnly;
    }
    if CORE_PACKAGE_IDS.contains(&target) {
        return AttemptAccess::SystemAdministratorOnly;
    }
    if MODULE_PACKAGE_IDS.contains(&target) {
        return AttemptAccess::HostScoped;
    }
    AttemptAccess::SystemAdministratorOnly
}

/// Returns whether the caller is a system administrator.
///
/// It is read from the guard the request carries, which the role floor on
/// every resolver here has already narrowed to one of the two administrator
/// tiers.
fn is_system_administrator(ctx: &Context<'_>) -> bool {
    ctx.data_opt::<RoleGuard>() == Some(&RoleGuard::new(Role::SystemAdministrator))
}

/// Returns `value` unless it is the empty string.
///
/// Three fields of the record are non-optional `String`s carrying the empty
/// string where the value does not exist. That encoding does not cross this
/// API: `""` is a placeholder the rest of the system refuses, so it renders as
/// `null`.
fn non_empty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

/// One operation `review` recorded in the attempt ledger.
///
/// It is the same record on every path — the top-level lookup, the in-flight
/// list and the inline latest attempt — because a caller holding one wants its
/// phase and its deadline as much as its id, and a slimmer second type would
/// force a follow-up query per row for fields already in hand.
pub(crate) struct OperationAttempt {
    inner: database::OperationAttempt,
}

impl From<database::OperationAttempt> for OperationAttempt {
    fn from(inner: database::OperationAttempt) -> Self {
        Self { inner }
    }
}

#[Object]
impl OperationAttempt {
    /// The idempotency key of the operation, which for an install is the
    /// client's own request key.
    ///
    /// It is a `String` and not an `ID`: the value is client-minted and
    /// compared byte for byte by the ledger, and `ID` coerces an input integer
    /// to a string, which is a way for one key to arrive as two.
    async fn id(&self) -> &str {
        &self.inner.idempotency_key
    }

    /// The operator's intent.
    async fn action(&self) -> OperationAction {
        self.inner.action.into()
    }

    /// How far `review` has driven the attempt.
    async fn phase(&self) -> OperationPhase {
        self.inner.phase.into()
    }

    /// The terminal result, or null while the attempt is still running.
    ///
    /// Null here is where "not terminal yet" lives; it is not a result of its
    /// own.
    async fn outcome(&self) -> Option<OperationOutcome> {
        self.inner.outcome.map(Into::into)
    }

    /// The host the operation applies to.
    async fn host(&self) -> &str {
        &self.inner.host
    }

    /// The package-id the operation targets, or null for an attempt that
    /// targets no package.
    ///
    /// An `ONBOARD` attempt is the null case: it brings a host under
    /// management and installs nothing.
    async fn target(&self) -> Option<&str> {
        non_empty(&self.inner.target)
    }

    /// The instance number the operation concerns, rendered as a decimal
    /// string.
    ///
    /// It is a `StringNumber` rather than an `Int` because the stored number
    /// is a `u32`, whose upper half has no valid `Int` representation — and
    /// because a client reads an instance here and hands it straight back to a
    /// mutation, so one value must not cross this API under two scalars. Null
    /// means the attempt names no instance: an onboarding, or an install still
    /// choosing one.
    async fn instance(&self) -> Option<StringNumber<u32>> {
        self.inner.instance.map(StringNumber)
    }

    /// The version the build selector resolved to, or null for an attempt that
    /// resolved no build.
    ///
    /// Null together with `resolvedCommit` or not at all: the two are one
    /// build identity, and half of one can be compared against nothing.
    async fn resolved_version(&self) -> Option<String> {
        self.resolved_identity().0
    }

    /// The commit the build selector resolved to, or null for an attempt that
    /// resolved no build.
    ///
    /// Null together with `resolvedVersion` or not at all.
    async fn resolved_commit(&self) -> Option<String> {
        self.resolved_identity().1
    }

    /// The compensation the attempt still owes, or null when it owes nothing.
    ///
    /// It is a read field and nothing more: this surface makes an owed
    /// teardown visible, and offers no way to force one.
    async fn cleanup_owed(&self) -> Option<OperationCleanupState> {
        self.inner.cleanup_state.map(Into::into)
    }

    /// When the attempt began.
    async fn started_at(&self) -> DateTime<Utc> {
        self.inner.started_at
    }

    /// The absolute deadline the attempt carries.
    ///
    /// An attempt past it that `review` has not yet swept is still
    /// non-terminal and still reported: expiry is `review`'s to act on, and
    /// this is what lets a client age the row itself.
    async fn expires_at(&self) -> DateTime<Utc> {
        self.inner.expires_at
    }
}

impl OperationAttempt {
    /// Returns the resolved build identity, both halves or neither.
    ///
    /// The pairing is [`install_state::paired_identity`]'s, which is the same
    /// rule the installed identity follows on the read path: two answers to
    /// one question would be two contracts.
    fn resolved_identity(&self) -> (Option<String>, Option<String>) {
        install_state::paired_identity(
            non_empty(&self.inner.resolved_version),
            non_empty(&self.inner.resolved_commit),
        )
    }
}

#[Object]
impl OperationAttemptQuery {
    /// Returns the operation attempt held under `id`, or null if none is.
    ///
    /// `id` is the attempt's idempotency key, which for an install is the
    /// request key the client minted. That is the point of accepting an id
    /// rather than a server-issued handle: a client whose install response was
    /// lost can still ask what became of it.
    ///
    /// A null answer means the id names no row, and a caller is free to read
    /// it as indeterminate. A refusal is not that: it is a field error beside
    /// a null, so the two can never be confused.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller may not read the attempt the row
    /// describes, or if the ledger cannot be read.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn operation_attempt(
        &self,
        ctx: &Context<'_>,
        id: String,
    ) -> Result<Option<OperationAttempt>> {
        // The id is client-minted and the host is discovered by reading the
        // row, so the host-scoped check cannot run before the ledger read. The
        // role floor above has no such problem and runs first.
        let attempt = {
            let store = super::get_store(ctx)?;
            let map = store.operation_attempt_map();
            map.get(&id)?
        };
        let Some(attempt) = attempt else {
            return Ok(None);
        };
        match required_access(attempt.action, &attempt.target) {
            AttemptAccess::SystemAdministratorOnly => {
                if !is_system_administrator(ctx) {
                    return Err(FORBIDDEN.into());
                }
            }
            AttemptAccess::HostScoped => {
                customer_access::check_hostname_access(ctx, &attempt.host)?;
            }
        }
        Ok(Some(attempt.into()))
    }

    /// Returns the non-terminal install attempts for `(host, target)`.
    ///
    /// An install still in flight has no service row — one is created only on
    /// terminal success — so a running install is invisible to the inline
    /// fields and needs this query. It is keyed on the pair rather than the
    /// triple because no caller knows the instance number before the install
    /// succeeds, and it answers with a list because two installs of one module
    /// on one host may legitimately run at once. A pair with none answers with
    /// the empty list, never null.
    ///
    /// The order is `startedAt` ascending, tie-broken by `id`, so the response
    /// is deterministic; the record scan order is idempotency-key order, which
    /// is arbitrary. That order is display only and selects nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller has no access to `host`, if `target` is
    /// not a module package-id, or if the ledger cannot be read.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn in_flight_installs(
        &self,
        ctx: &Context<'_>,
        host: String,
        target: String,
    ) -> Result<Vec<OperationAttempt>> {
        customer_access::check_hostname_access(ctx, &host)?;
        // The class binding is `deploy`'s single comparison site rather than a
        // second one here: one target must not have two classes.
        bind_package_class(&target, &MODULE_PACKAGE_IDS)?;

        let store = super::get_store(ctx)?;
        let map = store.operation_attempt_map();
        // No lookup on this table is keyed on the pair — the non-terminal
        // index needs an instance and is not reachable from here — so the
        // records are scanned. A decode failure is propagated rather than
        // skipped, so a corrupt row cannot quietly shrink the answer.
        let mut attempts = Vec::new();
        for row in map.iter(Direction::Forward, None) {
            let row = row?;
            if row.action == database::OperationAction::Install
                && !row.is_terminal()
                && row.host == host
                && row.target == target
            {
                attempts.push(row);
            }
        }
        attempts.sort_unstable_by(|left, right| {
            left.started_at
                .cmp(&right.started_at)
                .then_with(|| left.idempotency_key.cmp(&right.idempotency_key))
        });
        Ok(attempts.into_iter().map(Into::into).collect())
    }
}

/// Returns the current attempt for `(host, target, instance)`, or `None` if
/// the triple has none.
///
/// "Current" is `review-database`'s three-step lookup and is never derived
/// here: it answers with a non-terminal attempt if there is one, otherwise the
/// single row that still owes a cleanup, otherwise the row the latest pointer
/// names — and only that crate can read the pointer, which lives in a column
/// family of its own. Ordering rows by key or timestamp here would report a
/// superseded attempt as current whenever newer work still owes a teardown.
///
/// # Errors
///
/// Returns an error if the store is missing from the GraphQL context or the
/// ledger cannot be read.
pub(super) fn latest_attempt(
    ctx: &Context<'_>,
    host: &str,
    target: &str,
    instance: Option<u32>,
) -> Result<Option<OperationAttempt>> {
    let store = super::get_store(ctx)?;
    Ok(store
        .operation_attempt_map()
        .latest_attempt(host, target, instance)?
        .map(Into::into))
}

/// Returns the current attempt for a node entry's own triple, or `None` if it
/// has none.
///
/// The triple comes off the entry and never off the request: the host is the
/// node's own hostname, `instance` is the entry's own number, and `target` is
/// the package-id the entry's kind maps to. Keying on the triple is what keeps
/// one instance's card from showing a sibling's outcome.
///
/// An entry whose kind maps to no package-id has no target to look one up
/// under, and answers `None` without reading the ledger, without raising and
/// without logging — the same entry whose `lifecycle` is null for the same
/// reason. So does one whose node carries no applied profile, and therefore no
/// hostname to key on.
///
/// # Errors
///
/// Returns an error if the store is missing from the GraphQL context or the
/// node map or the ledger cannot be read.
pub(super) fn latest_attempt_for_node_entry(
    ctx: &Context<'_>,
    node_id: u32,
    package_id: Option<&str>,
    instance: Option<u32>,
) -> Result<Option<OperationAttempt>> {
    let Some(target) = package_id else {
        return Ok(None);
    };
    let store = super::get_store(ctx)?;
    let Some(host) = node_hostname(&store, node_id)? else {
        return Ok(None);
    };
    Ok(store
        .operation_attempt_map()
        .latest_attempt(&host, target, instance)?
        .map(Into::into))
}

/// Returns the hostname of the node `node_id` names, or `None` if there is no
/// such node or it carries no applied profile.
fn node_hostname(store: &Store, node_id: u32) -> Result<Option<String>> {
    let Some((node, _, _)) = store.node_map().get_by_id(node_id)? else {
        return Ok(None);
    };
    Ok(node.profile.map(|profile| profile.hostname))
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};
    use review_database::{
        Agent, AgentKind, AgentStatus, CoreComponent, ExternalService, ExternalServiceKind,
        ExternalServiceStatus, Lifecycle, Node, NodeProfile, OperationAction,
        OperationAttempt as Record, OperationCleanupState, OperationOutcome, OperationPhase,
        OperationRetryPolicy, Role, Store,
    };
    use serde_json::json;

    use super::{AttemptAccess, required_access};
    use crate::graphql::TestSchema;

    /// The fields of an attempt, as every query test below asks for them.
    const ATTEMPT_FIELDS: &str = "id action phase outcome host target instance resolvedVersion \
                                  resolvedCommit cleanupOwed startedAt expiresAt";

    /// The digest an install attempt carries.
    ///
    /// Its only use in the ledger is equality against a resubmitted request, so
    /// a fixed one stands in for a real transcript here.
    const INSTALL_INTENT: [u8; 32] = [7; 32];

    /// The customer the seeded node belongs to.
    const CUSTOMER: u32 = 7;

    /// A customer no seeded node belongs to.
    const OTHER_CUSTOMER: u32 = 8;

    const HOST: &str = "host1.example.com";

    /// Returns a fixed instant `offset` seconds past a fixed epoch.
    fn instant(offset: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + offset, 0)
            .single()
            .expect("a fixed timestamp is representable")
    }

    /// Returns a non-terminal attempt in its dispatched phase.
    fn attempt(
        key: &str,
        action: OperationAction,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> Record {
        Record {
            idempotency_key: key.to_string(),
            host: host.to_string(),
            target: target.to_string(),
            instance,
            action,
            // The ledger admits a digest under `INSTALL` and refuses one under
            // every other action, so this follows the action rather than being
            // a parameter of its own.
            install_intent: (action == OperationAction::Install).then_some(INSTALL_INTENT),
            package_digest: "digest".to_string(),
            resolved_version: "1.2.0".to_string(),
            resolved_commit: "abcabc".to_string(),
            phase: OperationPhase::Dispatched,
            cleanup_state: None,
            started_at: instant(0),
            retry_policy: OperationRetryPolicy {
                max_attempts: 3,
                attempts_made: 0,
                backoff_seconds: 1,
            },
            outcome: None,
            finalized_at: None,
            expires_at: instant(3_600),
            backup_id: None,
            pre_update_version: None,
        }
    }

    /// Returns `attempt` finished with `outcome`.
    ///
    /// The finalization instant is stamped exactly when the attempt owes no
    /// compensation, which is what the ledger accepts and what moves the
    /// latest pointer.
    fn finished(mut attempt: Record, outcome: OperationOutcome) -> Record {
        attempt.phase = OperationPhase::Completed;
        attempt.outcome = Some(outcome);
        attempt.finalized_at = attempt.cleanup_state.is_none().then(|| instant(60));
        attempt
    }

    /// Writes `attempt` to the ledger through the entry point its action takes.
    ///
    /// An install is created under its request key, and every other action is
    /// written straight; a re-write of either carries the row forward.
    fn seed(store: &Store, attempt: &Record) {
        let map = store.operation_attempt_map();
        if attempt.install_intent.is_some()
            && map.get(&attempt.idempotency_key).expect("read").is_none()
        {
            map.create_or_resolve(attempt).expect("seed install");
        } else {
            map.upsert(attempt).expect("seed attempt");
        }
    }

    fn insert_node(
        store: &Store,
        name: &str,
        hostname: &str,
        customer_id: u32,
        agents: Vec<Agent>,
        external_services: Vec<ExternalService>,
    ) -> u32 {
        let node = Node {
            id: u32::MAX,
            name: name.to_string(),
            name_draft: Some(name.to_string()),
            profile: Some(NodeProfile {
                customer_id,
                description: String::new(),
                hostname: hostname.to_string(),
            }),
            profile_draft: None,
            agents,
            external_services,
            creation_time: Utc::now(),
        };
        store.node_map().put(&node).expect("insert node")
    }

    fn agent(key: &str, kind: AgentKind, instance: Option<u32>) -> Agent {
        Agent {
            node_id: u32::MAX,
            key: key.to_string(),
            kind,
            status: AgentStatus::Enabled,
            config: None,
            draft: None,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::Running,
            bound_addrs: Vec::new(),
            instance,
        }
    }

    fn external_service(
        key: &str,
        kind: ExternalServiceKind,
        instance: Option<u32>,
    ) -> ExternalService {
        ExternalService {
            node_id: u32::MAX,
            key: key.to_string(),
            kind,
            status: ExternalServiceStatus::Enabled,
            draft: None,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::Running,
            bound_addrs: Vec::new(),
            instance,
        }
    }

    fn insert_core_component(store: &Store, component: &str, host: &str) {
        let row = CoreComponent {
            component: component.to_string(),
            host: host.to_string(),
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::Running,
            installer_managed: component == "bootroot",
        };
        store
            .core_component_map()
            .insert(&row)
            .expect("insert core component");
    }

    fn attempt_query(id: &str) -> String {
        format!("{{ operationAttempt(id: \"{id}\") {{ {ATTEMPT_FIELDS} }} }}")
    }

    fn in_flight_query(host: &str, target: &str) -> String {
        format!(
            "{{ inFlightInstalls(host: \"{host}\", target: \"{target}\") {{ {ATTEMPT_FIELDS} }} }}"
        )
    }

    /// The four branches of the row-derived tier, and which of them consults
    /// the host at all.
    ///
    /// This is where "no hostname lookup for an onboarding or a core
    /// component" is pinned: `HostScoped` is the only answer whose resolver
    /// arm calls `check_hostname_access`, and it is reached by the module
    /// package-ids alone.
    #[test]
    fn the_row_derives_the_tier_and_the_stricter_side_wins() {
        for target in ["piglet", "giganto", "hog", "reconverge", "crusher"] {
            assert_eq!(
                required_access(OperationAction::Update, target),
                AttemptAccess::HostScoped,
                "{target}"
            );
        }
        for target in [
            "review",
            "aice-web-next",
            "roxyd",
            "bootroot",
            "nonesuch",
            "",
        ] {
            assert_eq!(
                required_access(OperationAction::Update, target),
                AttemptAccess::SystemAdministratorOnly,
                "{target}"
            );
        }
        // An onboarding takes the stricter side whatever its target reads as,
        // and the one it carries is empty.
        assert_eq!(
            required_access(OperationAction::Onboard, ""),
            AttemptAccess::SystemAdministratorOnly
        );
        assert_eq!(
            required_access(OperationAction::Onboard, "hog"),
            AttemptAccess::SystemAdministratorOnly
        );
    }

    /// The attempt comes back under the key the client minted, with no
    /// server-issued handle in between.
    #[tokio::test]
    async fn an_attempt_is_read_under_the_key_it_was_submitted_with() {
        const KEY: &str = "11111111-1111-4111-8111-111111111111";
        let schema = TestSchema::new().await;
        seed(
            &schema.store(),
            &attempt(KEY, OperationAction::Install, HOST, "hog", Some(3)),
        );

        let res = schema.execute_as_system_admin(&attempt_query(KEY)).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let found = &data["operationAttempt"];
        assert_eq!(found["id"], json!(KEY));
        assert_eq!(found["action"], json!("INSTALL"));
        assert_eq!(found["phase"], json!("DISPATCHED"));
        assert_eq!(found["outcome"], json!(null));
        assert_eq!(found["host"], json!(HOST));
        assert_eq!(found["target"], json!("hog"));
        assert_eq!(found["instance"], json!("3"));
        assert_eq!(found["resolvedVersion"], json!("1.2.0"));
        assert_eq!(found["resolvedCommit"], json!("abcabc"));
        assert_eq!(found["cleanupOwed"], json!(null));
        assert_eq!(found["startedAt"], json!("2023-11-14T22:13:20+00:00"));
        assert_eq!(found["expiresAt"], json!("2023-11-14T23:13:20+00:00"));
    }

    /// A null for an id the ledger does not hold and a null for a refusal are
    /// told apart by the `errors` entry, and by nothing else.
    #[tokio::test]
    async fn a_refusal_carries_an_error_and_a_missing_row_does_not() {
        const MISSING: &str = "99999999-9999-4999-8999-999999999999";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        seed(
            &schema.store(),
            &attempt("core-1", OperationAction::Update, HOST, "roxyd", None),
        );

        let missing = schema
            .execute_as_system_admin(&attempt_query(MISSING))
            .await;
        assert!(missing.errors.is_empty(), "{:?}", missing.errors);
        assert_eq!(
            missing.data.into_json().unwrap()["operationAttempt"],
            json!(null)
        );

        let refused = schema
            .execute_as_scoped_user(
                &attempt_query("core-1"),
                Role::SecurityAdministrator,
                Some(vec![CUSTOMER]),
            )
            .await;
        assert_eq!(refused.errors.len(), 1, "{:?}", refused.errors);
        assert_eq!(refused.errors[0].message, "Forbidden");
        assert_eq!(
            refused.data.into_json().unwrap()["operationAttempt"],
            json!(null)
        );
    }

    /// The role floor refuses the two lower roles whatever they are scoped to
    /// and whether or not the id names a row.
    #[tokio::test]
    async fn the_role_floor_refuses_the_lower_roles() {
        const KEY: &str = "22222222-2222-4222-8222-222222222222";
        const MISSING: &str = "33333333-3333-4333-8333-333333333333";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        seed(
            &schema.store(),
            &attempt(KEY, OperationAction::Install, HOST, "hog", Some(1)),
        );

        for role in [Role::SecurityManager, Role::SecurityMonitor] {
            for id in [KEY, MISSING] {
                let res = schema
                    .execute_as_scoped_user(&attempt_query(id), role, Some(vec![CUSTOMER]))
                    .await;
                assert_eq!(res.errors.len(), 1, "{role:?} {id}");
                assert_eq!(res.errors[0].message, "Forbidden", "{role:?} {id}");
            }
            let res = schema
                .execute_as_scoped_user(&in_flight_query(HOST, "hog"), role, Some(vec![CUSTOMER]))
                .await;
            assert_eq!(res.errors.len(), 1, "{role:?}");
            assert_eq!(res.errors[0].message, "Forbidden", "{role:?}");
        }
    }

    /// The row's own action and target decide the tier, and a security
    /// administrator reaches none of the four stricter cases.
    #[tokio::test]
    async fn the_stricter_rows_are_read_by_the_system_administrator_alone() {
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        let rows = [
            ("onboard-1", OperationAction::Onboard, ""),
            ("core-1", OperationAction::Update, "roxyd"),
            ("core-2", OperationAction::Update, "review"),
            ("core-3", OperationAction::Update, "aice-web-next"),
            ("boot-1", OperationAction::Update, "bootroot"),
            ("other-1", OperationAction::Update, "nonesuch"),
        ];
        for (key, action, target) in rows {
            seed(&schema.store(), &attempt(key, action, HOST, target, None));
        }

        for (key, _, target) in rows {
            let refused = schema
                .execute_as_scoped_user(
                    &attempt_query(key),
                    Role::SecurityAdministrator,
                    Some(vec![CUSTOMER]),
                )
                .await;
            assert_eq!(refused.errors.len(), 1, "{target}");
            assert_eq!(refused.errors[0].message, "Forbidden", "{target}");

            let allowed = schema.execute_as_system_admin(&attempt_query(key)).await;
            assert!(allowed.errors.is_empty(), "{target}: {:?}", allowed.errors);
            assert_eq!(
                allowed.data.into_json().unwrap()["operationAttempt"]["id"],
                json!(key)
            );
        }
    }

    /// An onboarding names a host that is not a node yet, and is still read.
    ///
    /// The hostname check could answer nothing for such a host, which is why
    /// the onboarding branch does not run it.
    #[tokio::test]
    async fn an_onboarding_of_an_unknown_host_is_read() {
        let schema = TestSchema::new().await;
        seed(
            &schema.store(),
            &attempt("onboard-1", OperationAction::Onboard, "newhost", "", None),
        );

        let res = schema
            .execute_as_system_admin(&attempt_query("onboard-1"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let found = &res.data.into_json().unwrap()["operationAttempt"];
        assert_eq!(found["host"], json!("newhost"));
        assert_eq!(found["action"], json!("ONBOARD"));
    }

    /// The record's empty strings are absences, and cross as `null`.
    #[tokio::test]
    async fn the_empty_strings_render_as_null() {
        let schema = TestSchema::new().await;
        let mut row = attempt("onboard-1", OperationAction::Onboard, "newhost", "", None);
        row.resolved_version = String::new();
        row.resolved_commit = String::new();
        seed(&schema.store(), &row);

        let res = schema
            .execute_as_system_admin(&attempt_query("onboard-1"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let found = &res.data.into_json().unwrap()["operationAttempt"];
        assert_eq!(found["target"], json!(null));
        assert_eq!(found["resolvedVersion"], json!(null));
        assert_eq!(found["resolvedCommit"], json!(null));
        assert_eq!(found["instance"], json!(null));
    }

    /// Half a build identity names no build, so neither half is reported.
    #[tokio::test]
    async fn a_half_resolved_identity_reports_neither_half() {
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        let mut row = attempt("half-1", OperationAction::Update, HOST, "roxyd", None);
        row.resolved_commit = String::new();
        seed(&schema.store(), &row);

        let res = schema
            .execute_as_system_admin(&attempt_query("half-1"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let found = &res.data.into_json().unwrap()["operationAttempt"];
        assert_eq!(found["resolvedVersion"], json!(null));
        assert_eq!(found["resolvedCommit"], json!(null));
    }

    /// The owed compensation is the mirrored enum, and null where none is
    /// owed.
    #[tokio::test]
    async fn the_owed_cleanup_renders_as_the_enum() {
        let schema = TestSchema::new().await;
        let owed = [
            (
                "cleanup-1",
                1,
                Some(OperationCleanupState::PendingDeregister),
                json!("PENDING_DEREGISTER"),
            ),
            (
                "cleanup-2",
                2,
                Some(OperationCleanupState::PendingIdentityTeardown),
                json!("PENDING_IDENTITY_TEARDOWN"),
            ),
            ("cleanup-3", 3, None, json!(null)),
        ];
        for (key, instance, state, _) in &owed {
            let mut row = attempt(key, OperationAction::Remove, HOST, "roxyd", Some(*instance));
            row.cleanup_state = *state;
            seed(&schema.store(), &finished(row, OperationOutcome::Failed));
        }

        for (key, _, _, rendered) in owed {
            let res = schema.execute_as_system_admin(&attempt_query(key)).await;
            assert!(res.errors.is_empty(), "{key}: {:?}", res.errors);
            assert_eq!(
                res.data.into_json().unwrap()["operationAttempt"]["cleanupOwed"],
                rendered,
                "{key}"
            );
        }
    }

    /// The instance crosses as a decimal string, so the upper half of a `u32`
    /// survives the trip.
    #[tokio::test]
    async fn the_instance_crosses_as_a_string_number() {
        let schema = TestSchema::new().await;
        seed(
            &schema.store(),
            &attempt(
                "wide-1",
                OperationAction::Update,
                HOST,
                "roxyd",
                Some(u32::MAX),
            ),
        );
        seed(
            &schema.store(),
            &attempt("wide-2", OperationAction::Update, HOST, "roxyd", None),
        );

        let res = schema
            .execute_as_system_admin(&attempt_query("wide-1"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap()["operationAttempt"]["instance"],
            json!("4294967295")
        );

        let res = schema
            .execute_as_system_admin(&attempt_query("wide-2"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap()["operationAttempt"]["instance"],
            json!(null)
        );
    }

    /// A running install has no service row, and is reachable only here.
    ///
    /// The two seeded attempts are ordered against each other by `startedAt`
    /// and not by the key the scan returns them under, which is the reverse.
    #[tokio::test]
    async fn in_flight_installs_lists_the_running_installs_in_order() {
        const FIRST: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        const SECOND: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);

        let empty = schema
            .execute_as_system_admin(&in_flight_query(HOST, "hog"))
            .await;
        assert!(empty.errors.is_empty(), "{:?}", empty.errors);
        assert_eq!(
            empty.data.into_json().unwrap()["inFlightInstalls"],
            json!([])
        );

        let first = attempt(FIRST, OperationAction::Install, HOST, "hog", Some(1));
        let mut second = attempt(SECOND, OperationAction::Install, HOST, "hog", Some(2));
        second.started_at = instant(30);
        seed(&schema.store(), &first);
        seed(&schema.store(), &second);

        let res = schema
            .execute_as_system_admin(&in_flight_query(HOST, "hog"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let listed = data["inFlightInstalls"].as_array().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["id"], json!(FIRST));
        assert_eq!(listed[1]["id"], json!(SECOND));

        seed(
            &schema.store(),
            &finished(first, OperationOutcome::Succeeded),
        );
        let res = schema
            .execute_as_system_admin(&in_flight_query(HOST, "hog"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let listed = data["inFlightInstalls"].as_array().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["id"], json!(SECOND));
    }

    /// Only a non-terminal install for the pair is listed.
    #[tokio::test]
    async fn in_flight_installs_lists_nothing_else() {
        const TERMINAL: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        seed(
            &schema.store(),
            &attempt("onboard-1", OperationAction::Onboard, HOST, "", None),
        );
        seed(
            &schema.store(),
            &attempt("update-1", OperationAction::Update, HOST, "hog", Some(1)),
        );
        seed(
            &schema.store(),
            &attempt("remove-1", OperationAction::Remove, HOST, "hog", Some(2)),
        );
        let terminal = attempt(TERMINAL, OperationAction::Install, HOST, "hog", Some(3));
        seed(&schema.store(), &terminal);
        seed(
            &schema.store(),
            &finished(terminal, OperationOutcome::RolledBack),
        );

        let res = schema
            .execute_as_system_admin(&in_flight_query(HOST, "hog"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(res.data.into_json().unwrap()["inFlightInstalls"], json!([]));
    }

    /// The pair the caller asked for is the pair it is answered for.
    ///
    /// A running install on another host, and one of another module on this
    /// host, are both rows the scan walks past and neither is listed.
    #[tokio::test]
    async fn in_flight_installs_answers_for_the_pair_it_was_asked_for() {
        const MINE: &str = "0aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const ELSEWHERE: &str = "0bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        const ANOTHER_TARGET: &str = "0ccccccc-cccc-4ccc-8ccc-cccccccccccc";
        const OTHER_HOST: &str = "host2.example.com";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        insert_node(
            &schema.store(),
            "node2",
            OTHER_HOST,
            CUSTOMER,
            vec![],
            vec![],
        );
        seed(
            &schema.store(),
            &attempt(MINE, OperationAction::Install, HOST, "hog", Some(1)),
        );
        seed(
            &schema.store(),
            &attempt(
                ELSEWHERE,
                OperationAction::Install,
                OTHER_HOST,
                "hog",
                Some(1),
            ),
        );
        seed(
            &schema.store(),
            &attempt(
                ANOTHER_TARGET,
                OperationAction::Install,
                HOST,
                "piglet",
                Some(1),
            ),
        );

        let res = schema
            .execute_as_system_admin(&in_flight_query(HOST, "hog"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let listed = data["inFlightInstalls"].as_array().unwrap();
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0]["id"], json!(MINE));
    }

    /// Two installs that began in the same instant are still ordered, because
    /// the id breaks the tie and the scan order is not an order at all.
    #[tokio::test]
    async fn in_flight_installs_breaks_a_tie_on_the_id() {
        const EARLIER: &str = "1aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const LATER: &str = "2bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        // Seeded in the reverse of the order they must come back in, and both
        // under the instant `attempt` stamps.
        seed(
            &schema.store(),
            &attempt(LATER, OperationAction::Install, HOST, "hog", Some(2)),
        );
        seed(
            &schema.store(),
            &attempt(EARLIER, OperationAction::Install, HOST, "hog", Some(1)),
        );

        let res = schema
            .execute_as_system_admin(&in_flight_query(HOST, "hog"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let listed = data["inFlightInstalls"].as_array().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0]["startedAt"], listed[1]["startedAt"]);
        assert_eq!(listed[0]["id"], json!(EARLIER));
        assert_eq!(listed[1]["id"], json!(LATER));
    }

    /// A target outside the five module package-ids is refused, so observation
    /// is no looser than action.
    #[tokio::test]
    async fn in_flight_installs_refuses_a_non_module_target() {
        const KEY: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        // A row the scan would have found, so the refusal is the class check
        // and not an empty ledger.
        seed(
            &schema.store(),
            &attempt(KEY, OperationAction::Install, HOST, "review", None),
        );

        for target in ["review", "roxyd", "bootroot", "nonesuch"] {
            let res = schema
                .execute_as_system_admin(&in_flight_query(HOST, target))
                .await;
            assert_eq!(res.errors.len(), 1, "{target}");
            assert_eq!(
                res.errors[0].message,
                format!("{target} is not one of the package-ids this operation accepts"),
                "{target}"
            );
        }
    }

    /// A scoped caller reaches only the hosts of its own customers, on both
    /// queries — the argument's host here, and the row's host there.
    #[tokio::test]
    async fn a_scoped_caller_is_held_to_its_own_hosts() {
        const KEY: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        seed(
            &schema.store(),
            &attempt(KEY, OperationAction::Install, HOST, "hog", Some(1)),
        );

        let allowed = schema
            .execute_as_scoped_user(
                &attempt_query(KEY),
                Role::SecurityAdministrator,
                Some(vec![CUSTOMER]),
            )
            .await;
        assert!(allowed.errors.is_empty(), "{:?}", allowed.errors);
        assert_eq!(
            allowed.data.into_json().unwrap()["operationAttempt"]["id"],
            json!(KEY)
        );

        let refused = schema
            .execute_as_scoped_user(
                &attempt_query(KEY),
                Role::SecurityAdministrator,
                Some(vec![OTHER_CUSTOMER]),
            )
            .await;
        assert_eq!(refused.errors.len(), 1, "{:?}", refused.errors);
        assert_eq!(refused.errors[0].message, "Forbidden");

        let refused = schema
            .execute_as_scoped_user(
                &in_flight_query(HOST, "hog"),
                Role::SecurityAdministrator,
                Some(vec![OTHER_CUSTOMER]),
            )
            .await;
        assert_eq!(refused.errors.len(), 1, "{:?}", refused.errors);
        assert_eq!(refused.errors[0].message, "Forbidden");

        // The host-scoped check runs before the module-class one, so a caller
        // outside the host's customer is told nothing about the target it
        // named.
        let refused = schema
            .execute_as_scoped_user(
                &in_flight_query(HOST, "roxyd"),
                Role::SecurityAdministrator,
                Some(vec![OTHER_CUSTOMER]),
            )
            .await;
        assert_eq!(refused.errors.len(), 1, "{:?}", refused.errors);
        assert_eq!(refused.errors[0].message, "Forbidden");
    }

    /// The inline field takes the three steps `review-database` takes, in that
    /// order: a running attempt, then one still owing a teardown, then the row
    /// the latest pointer names.
    #[tokio::test]
    async fn the_inline_attempt_takes_the_three_steps_in_order() {
        let schema = TestSchema::new().await;
        let node_id = insert_node(
            &schema.store(),
            "node1",
            HOST,
            CUSTOMER,
            vec![agent("hog1", AgentKind::SemiSupervised, Some(1))],
            vec![],
        );
        let query = format!(
            "{{ node(id: \"{node_id}\") {{ agents {{ latestOperationAttempt {{ id cleanupOwed }} }} }} }}"
        );

        let discharged = finished(
            attempt("done-1", OperationAction::Update, HOST, "hog", Some(1)),
            OperationOutcome::Succeeded,
        );
        seed(&schema.store(), &discharged);
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(
            data["node"]["agents"][0]["latestOperationAttempt"]["id"],
            json!("done-1")
        );

        let mut owing = attempt("owing-1", OperationAction::Remove, HOST, "hog", Some(1));
        owing.cleanup_state = Some(OperationCleanupState::PendingDeregister);
        seed(&schema.store(), &finished(owing, OperationOutcome::Failed));
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let found = &data["node"]["agents"][0]["latestOperationAttempt"];
        assert_eq!(found["id"], json!("owing-1"));
        assert_eq!(found["cleanupOwed"], json!("PENDING_DEREGISTER"));

        seed(
            &schema.store(),
            &attempt("running-1", OperationAction::Update, HOST, "hog", Some(1)),
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(
            data["node"]["agents"][0]["latestOperationAttempt"]["id"],
            json!("running-1")
        );
    }

    /// The lookup keys on the triple, so one instance never shows a sibling's
    /// attempt.
    #[tokio::test]
    async fn the_inline_attempt_keys_on_the_instance() {
        let schema = TestSchema::new().await;
        let node_id = insert_node(
            &schema.store(),
            "node1",
            HOST,
            CUSTOMER,
            vec![
                agent("hog1", AgentKind::SemiSupervised, Some(1)),
                agent("hog2", AgentKind::SemiSupervised, Some(2)),
            ],
            vec![],
        );
        seed(
            &schema.store(),
            &attempt("inst-1", OperationAction::Update, HOST, "hog", Some(1)),
        );
        seed(
            &schema.store(),
            &attempt("inst-2", OperationAction::Update, HOST, "hog", Some(2)),
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{node_id}\") {{ agents {{ key instance latestOperationAttempt {{ id instance }} }} }} }}"
            ))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let agents = data["node"]["agents"].as_array().unwrap();
        assert_eq!(agents.len(), 2);
        for entry in agents {
            let expected = match entry["instance"].as_str() {
                Some("1") => "inst-1",
                Some("2") => "inst-2",
                other => panic!("unexpected instance {other:?}"),
            };
            assert_eq!(entry["latestOperationAttempt"]["id"], json!(expected));
        }
    }

    /// A node carrying only a draft profile has no hostname to key on, and its
    /// entries answer null rather than falling back to the drafted one.
    ///
    /// The draft is what the node *would* be called once applied; the ledger
    /// records an attempt under the name the host answers to now, so reading
    /// one under the draft would report another host's work.
    #[tokio::test]
    async fn the_inline_attempt_is_null_for_a_node_with_no_applied_profile() {
        const DRAFTED: &str = "drafted.example.com";
        let schema = TestSchema::new().await;
        let node = Node {
            id: u32::MAX,
            name: "node1".to_string(),
            name_draft: Some("node1".to_string()),
            profile: None,
            profile_draft: Some(NodeProfile {
                customer_id: CUSTOMER,
                description: String::new(),
                hostname: DRAFTED.to_string(),
            }),
            agents: vec![agent("hog1", AgentKind::SemiSupervised, Some(1))],
            external_services: Vec::new(),
            creation_time: Utc::now(),
        };
        let node_id = schema.store().node_map().put(&node).expect("insert node");
        // An attempt under the drafted hostname, which a lookup that fell back
        // to the draft would find.
        seed(
            &schema.store(),
            &attempt("draft-1", OperationAction::Update, DRAFTED, "hog", Some(1)),
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{node_id}\") {{ agents {{ latestOperationAttempt {{ id }} }} }} }}"
            ))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        assert_eq!(
            data["node"]["agents"][0]["latestOperationAttempt"],
            json!(null)
        );
    }

    /// An entry whose kind maps to no package-id has no target to look an
    /// attempt up under, and answers null without raising.
    #[tokio::test]
    async fn the_inline_attempt_is_null_for_an_entry_with_no_package() {
        let schema = TestSchema::new().await;
        let node_id = insert_node(
            &schema.store(),
            "node1",
            HOST,
            CUSTOMER,
            vec![],
            vec![
                external_service("ti1", ExternalServiceKind::TiContainer, Some(1)),
                external_service("store1", ExternalServiceKind::DataStore, Some(1)),
            ],
        );
        // An attempt under the empty target, which a lookup that fell through
        // to one would find.
        seed(
            &schema.store(),
            &attempt("empty-1", OperationAction::Update, HOST, "", Some(1)),
        );
        seed(
            &schema.store(),
            &attempt("store-1", OperationAction::Update, HOST, "giganto", Some(1)),
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{node_id}\") {{ externalServices {{ key latestOperationAttempt {{ id }} }} }} }}"
            ))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let services = data["node"]["externalServices"].as_array().unwrap();
        for entry in services {
            match entry["key"].as_str() {
                Some("ti1") => assert_eq!(entry["latestOperationAttempt"], json!(null)),
                Some("store1") => {
                    assert_eq!(entry["latestOperationAttempt"]["id"], json!("store-1"));
                }
                other => panic!("unexpected entry {other:?}"),
            }
        }
    }

    /// A core-component entry looks its attempt up under its own component and
    /// no instance.
    #[tokio::test]
    async fn the_inline_attempt_of_a_core_component_carries_no_instance() {
        let schema = TestSchema::new().await;
        insert_core_component(&schema.store(), "roxyd", HOST);
        seed(
            &schema.store(),
            &attempt("core-1", OperationAction::Update, HOST, "roxyd", None),
        );
        // The same component and host under an instance number, which a
        // lookup keyed on anything but the component's own triple would find.
        seed(
            &schema.store(),
            &attempt("core-2", OperationAction::Update, HOST, "roxyd", Some(1)),
        );

        let res = schema
            .execute_as_system_admin(
                "{ coreComponentList { component host latestOperationAttempt { id instance } } }",
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let rows = data["coreComponentList"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["latestOperationAttempt"]["id"], json!("core-1"));
        assert_eq!(rows[0]["latestOperationAttempt"]["instance"], json!(null));
    }
}
