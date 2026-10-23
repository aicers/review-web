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

/// Why an attempt that ended `FAILED` failed, as a closed remedy group.
///
/// It mirrors `review_database::OperationFailureKind` one variant for one
/// variant and in the stored order. It names the remedy an operator can act
/// on rather than the cause, which stays in `review`'s log, and it is set on a
/// `FAILED` attempt and on no other. The stored enum carries no fallback
/// variant — `OTHER` is a kind of its own, not an unknown — so this one
/// invents no `UNKNOWN`, and a kind appended upstream stops this crate from
/// compiling until it is mirrored here.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::OperationFailureKind")]
pub(crate) enum OperationFailureKind {
    HostDiskSpace,
    HostAgentUnsupported,
    HostNotPrepared,
    UnmanagedInstance,
    ServiceFailed,
    NotApplied,
    TrustAnchorRefused,
    BuildNotServable,
    NoConfirmation,
    Other,
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
///
/// The two membership questions are asked through [`bind_package_class`], the
/// crate's single class-comparison site, so this tiering and the mutations
/// that refuse on the same lists cannot drift apart. Only the helper's verdict
/// is read here: its refusal message names a request that was rejected, and
/// nothing was rejected on this path — a target in neither list is answered,
/// with the stricter tier.
fn required_access(action: database::OperationAction, target: &str) -> AttemptAccess {
    if action == database::OperationAction::Onboard {
        return AttemptAccess::SystemAdministratorOnly;
    }
    if bind_package_class(target, &CORE_PACKAGE_IDS).is_ok() {
        return AttemptAccess::SystemAdministratorOnly;
    }
    if bind_package_class(target, &MODULE_PACKAGE_IDS).is_ok() {
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

    /// Why an attempt that ended `FAILED` failed, as a closed remedy group.
    ///
    /// It is non-null exactly when `outcome` is `FAILED`, and null otherwise,
    /// a running attempt included. It names what an operator can do about the
    /// failure and no more; the detail of what went wrong is in the log.
    async fn failure_kind(&self) -> Option<OperationFailureKind> {
        self.inner.failure_kind.map(Into::into)
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
    /// The install attempts of the hosts' operational log collectors are left
    /// out, as [`operator_installs`] describes: node cards read this for an
    /// operator's install, which must never show a system install of the same
    /// `(host, reproduce)`.
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
        let keep = in_flight_install_of(&host, &target);
        let mut candidates = Vec::new();
        for row in map.iter(Direction::Forward, None) {
            let row = row?;
            if keep(&row) {
                candidates.push(row);
            }
        }
        let mut attempts = operator_installs(&store, candidates, keep)?;
        attempts.sort_unstable_by(request_order);
        Ok(attempts.into_iter().map(Into::into).collect())
    }

    /// Returns the latest install attempt for `(host, target)`, whatever its
    /// phase or outcome, or null if the pair has none.
    ///
    /// "Latest" is the greatest `(startedAt, id)`, the order
    /// `inFlightInstalls` lists by. The answer reads by its outcome: a null
    /// `outcome` means the install is still running, as `inFlightInstalls`
    /// also says; `SUCCEEDED` means the instance's service row is there or
    /// about to be; and `FAILED`, `ROLLED_BACK` or `CANCELLED` is how the last
    /// install of the module on the host ended, with `failureKind` and
    /// `cleanupOwed` as the attempt carries them.
    ///
    /// A failed first install leaves no service row — one is created only on
    /// terminal success — so no inline attempt reaches it, and this query is
    /// the only way to find it without its id. The next install of the pair
    /// supersedes it, so the answer clears itself and a history of failures
    /// never shows more than one.
    ///
    /// Ordering rows by request is right here, although the inline latest
    /// attempt refuses to: that field answers "the current attempt of an
    /// instance", where a superseded attempt may still owe a teardown and
    /// remains current until it is discharged. This query answers "the last
    /// install request for the pair", and request order is exactly that. A
    /// row that still owes cleanup is returned with `cleanupOwed` set, not
    /// hidden.
    ///
    /// The install attempts of the hosts' operational log collectors are left
    /// out, as [`operator_installs`] describes, before the latest is chosen:
    /// node cards read this for an operator's install, which must never show a
    /// system install of the same `(host, reproduce)`, nor be hidden by one.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller has no access to `host`, if `target` is
    /// not a module package-id, or if the ledger cannot be read.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn latest_install(
        &self,
        ctx: &Context<'_>,
        host: String,
        target: String,
    ) -> Result<Option<OperationAttempt>> {
        customer_access::check_hostname_access(ctx, &host)?;
        bind_package_class(&target, &MODULE_PACKAGE_IDS)?;

        let store = super::get_store(ctx)?;
        let map = store.operation_attempt_map();
        // Scanned for the reason `inFlightInstalls` scans, and with a decode
        // failure propagated for the same one. Every matching candidate is
        // kept rather than a running maximum, because the maximum is only
        // known once the system installs are left out.
        let keep = install_of(&host, &target);
        let mut candidates = Vec::new();
        for row in map.iter(Direction::Forward, None) {
            let row = row?;
            if keep(&row) {
                candidates.push(row);
            }
        }
        Ok(operator_installs(&store, candidates, keep)?
            .into_iter()
            .max_by(request_order)
            .map(Into::into))
    }
}

/// Returns the predicate `latestInstall` selects its candidates by: an install
/// of `target` on `host`, whatever its phase.
fn install_of<'a>(
    host: &'a str,
    target: &'a str,
) -> impl Fn(&database::OperationAttempt) -> bool + 'a {
    move |row| {
        row.action == database::OperationAction::Install && row.host == host && row.target == target
    }
}

/// Returns the predicate `inFlightInstalls` selects its candidates by: a
/// non-terminal install of `target` on `host`.
fn in_flight_install_of<'a>(
    host: &'a str,
    target: &'a str,
) -> impl Fn(&database::OperationAttempt) -> bool + 'a {
    let install = install_of(host, target);
    move |row| install(row) && !row.is_terminal()
}

/// Returns the operator's install attempts among `candidates`, each as the
/// ledger holds it now and still matching `keep`.
///
/// The install attempts of the hosts' operational log collectors are left
/// out. A system log collector is a `reproduce` instance `REview` installs on
/// every host for itself, and node cards read `inFlightInstalls` and
/// `latestInstall` for an operator's Log Collector install, which must never
/// show a system install of the same `(host, reproduce)`, nor the reverse.
///
/// The system installs are recognized by their keys: every install key a
/// system log collector row holds is read once and excluded. Install keys are
/// fresh and never reused. A system install's key is written before its
/// attempt, and removed in the same transaction that prunes the attempt, so
/// re-reading each remaining candidate by its key closes the race with a
/// prune that runs between the candidates' scan and the key-set read: a
/// system attempt whose key was removed before the key-set read is absent on
/// re-read and is dropped, and a key removed after that read was already in
/// the excluded set. The re-read record, not the scanned copy, is what `keep`
/// is applied to and what is returned.
///
/// # Errors
///
/// Returns an error if the install keys or any candidate cannot be read. A
/// failed read is never answered as an empty list.
fn operator_installs(
    store: &Store,
    candidates: Vec<database::OperationAttempt>,
    keep: impl Fn(&database::OperationAttempt) -> bool,
) -> Result<Vec<database::OperationAttempt>> {
    let system_keys = store.system_log_collector_map().install_keys()?;
    let map = store.operation_attempt_map();
    let mut attempts = Vec::new();
    for candidate in candidates {
        if system_keys.contains(&candidate.idempotency_key) {
            continue;
        }
        if let Some(row) = map.get(&candidate.idempotency_key)?
            && keep(&row)
        {
            attempts.push(row);
        }
    }
    Ok(attempts)
}

/// Orders two attempts by when they were requested: `started_at`, tie-broken
/// by the idempotency key so that the order is total.
fn request_order(
    left: &database::OperationAttempt,
    right: &database::OperationAttempt,
) -> std::cmp::Ordering {
    left.started_at
        .cmp(&right.started_at)
        .then_with(|| left.idempotency_key.cmp(&right.idempotency_key))
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
    use chrono::{DateTime, TimeDelta, TimeZone, Utc};
    use review_database::{
        Agent, AgentKind, AgentStatus, CoreComponent, ExternalService, ExternalServiceKind,
        ExternalServiceStatus, Lifecycle, Node, NodeProfile, OperationAction,
        OperationAttempt as Record, OperationCleanupState, OperationFailureKind, OperationOutcome,
        OperationPhase, OperationRetentionBound, OperationRetryPolicy, Role, Store,
    };
    use serde_json::json;

    use super::{AttemptAccess, required_access};
    use crate::graphql::TestSchema;

    /// The fields of an attempt, as every query test below asks for them.
    const ATTEMPT_FIELDS: &str = "id action phase outcome failureKind host target instance \
                                  resolvedVersion resolvedCommit cleanupOwed startedAt expiresAt";

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
            config_template: None,
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
            failure_kind: None,
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
    /// latest pointer. A failure kind is set exactly when the outcome is
    /// `Failed`, which the ledger also demands; the kind is `Other` here, and
    /// [`failed`] picks another.
    fn finished(mut attempt: Record, outcome: OperationOutcome) -> Record {
        attempt.phase = OperationPhase::Completed;
        attempt.outcome = Some(outcome);
        attempt.failure_kind =
            (outcome == OperationOutcome::Failed).then_some(OperationFailureKind::Other);
        attempt.finalized_at = attempt.cleanup_state.is_none().then(|| instant(60));
        attempt
    }

    /// Returns `attempt` finished `Failed` with `kind`.
    fn failed(attempt: Record, kind: OperationFailureKind) -> Record {
        let mut attempt = finished(attempt, OperationOutcome::Failed);
        attempt.failure_kind = Some(kind);
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

    fn latest_install_query(host: &str, target: &str) -> String {
        format!(
            "{{ latestInstall(host: \"{host}\", target: \"{target}\") {{ {ATTEMPT_FIELDS} }} }}"
        )
    }

    /// Returns the `latestInstall` answer for `(host, target)` as a system
    /// administrator, asserting that it carries no error.
    async fn latest_install(schema: &TestSchema, host: &str, target: &str) -> serde_json::Value {
        let res = schema
            .execute_as_system_admin(&latest_install_query(host, target))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        res.data.into_json().unwrap()["latestInstall"].take()
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
        for target in [
            "piglet",
            "giganto",
            "hog",
            "reconverge",
            "crusher",
            "reproduce",
        ] {
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
            "bootroot-agent",
            "bootroot-remote",
            "bootler-security",
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
        assert_eq!(found["failureKind"], json!(null));
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

    /// An attempt on any of the programs a join host's operator places is a
    /// core attempt: a System Administrator reads it, and a Security
    /// Administrator scoped to the host's customer is refused it.
    #[tokio::test]
    async fn a_join_host_program_attempt_is_for_a_system_administrator_only() {
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        for target in ["bootroot-agent", "bootroot-remote", "bootler-security"] {
            let key = format!("core-{target}");
            seed(
                &schema.store(),
                &attempt(&key, OperationAction::Update, HOST, target, None),
            );

            let res = schema.execute_as_system_admin(&attempt_query(&key)).await;
            assert!(res.errors.is_empty(), "{target}: {:?}", res.errors);
            assert_eq!(
                res.data.into_json().unwrap()["operationAttempt"]["target"],
                json!(target)
            );

            let refused = schema
                .execute_as_scoped_user(
                    &attempt_query(&key),
                    Role::SecurityAdministrator,
                    Some(vec![CUSTOMER]),
                )
                .await;
            assert_eq!(refused.errors.len(), 1, "{target}: {:?}", refused.errors);
            assert_eq!(refused.errors[0].message, "Forbidden", "{target}");
            assert_eq!(
                refused.data.into_json().unwrap()["operationAttempt"],
                json!(null),
                "{target}"
            );
        }
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
            seed(
                &schema.store(),
                &failed(row, OperationFailureKind::ServiceFailed),
            );
        }

        for (key, _, _, rendered) in owed {
            let res = schema.execute_as_system_admin(&attempt_query(key)).await;
            assert!(res.errors.is_empty(), "{key}: {:?}", res.errors);
            let data = res.data.into_json().unwrap();
            let found = &data["operationAttempt"];
            assert_eq!(found["cleanupOwed"], rendered, "{key}");
            // An owed teardown and the failure kind are independent fields.
            assert_eq!(found["failureKind"], json!("SERVICE_FAILED"), "{key}");
        }
    }

    /// A `FAILED` attempt reads back the kind it was stored with, every one of
    /// the ten, under its SDL name.
    #[tokio::test]
    async fn a_failed_attempt_carries_its_failure_kind() {
        let schema = TestSchema::new().await;
        let kinds = [
            (OperationFailureKind::HostDiskSpace, "HOST_DISK_SPACE"),
            (
                OperationFailureKind::HostAgentUnsupported,
                "HOST_AGENT_UNSUPPORTED",
            ),
            (OperationFailureKind::HostNotPrepared, "HOST_NOT_PREPARED"),
            (
                OperationFailureKind::UnmanagedInstance,
                "UNMANAGED_INSTANCE",
            ),
            (OperationFailureKind::ServiceFailed, "SERVICE_FAILED"),
            (OperationFailureKind::NotApplied, "NOT_APPLIED"),
            (
                OperationFailureKind::TrustAnchorRefused,
                "TRUST_ANCHOR_REFUSED",
            ),
            (OperationFailureKind::BuildNotServable, "BUILD_NOT_SERVABLE"),
            (OperationFailureKind::NoConfirmation, "NO_CONFIRMATION"),
            (OperationFailureKind::Other, "OTHER"),
        ];
        for (instance, (kind, _)) in (1..).zip(kinds) {
            let key = format!("failed-{instance}");
            let row = attempt(&key, OperationAction::Update, HOST, "roxyd", Some(instance));
            seed(&schema.store(), &failed(row, kind));
        }

        for (instance, (_, rendered)) in (1..).zip(kinds) {
            let key = format!("failed-{instance}");
            let res = schema.execute_as_system_admin(&attempt_query(&key)).await;
            assert!(res.errors.is_empty(), "{rendered}: {:?}", res.errors);
            let data = res.data.into_json().unwrap();
            let found = &data["operationAttempt"];
            assert_eq!(found["outcome"], json!("FAILED"), "{rendered}");
            assert_eq!(found["failureKind"], json!(rendered));
        }
    }

    /// A failed onboarding carries its kind like any other attempt.
    #[tokio::test]
    async fn a_failed_onboarding_carries_its_failure_kind() {
        let schema = TestSchema::new().await;
        let row = attempt("onboard-1", OperationAction::Onboard, "newhost", "", None);
        seed(
            &schema.store(),
            &failed(row, OperationFailureKind::HostNotPrepared),
        );

        let res = schema
            .execute_as_system_admin(&attempt_query("onboard-1"))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let found = &res.data.into_json().unwrap()["operationAttempt"];
        assert_eq!(found["action"], json!("ONBOARD"));
        assert_eq!(found["failureKind"], json!("HOST_NOT_PREPARED"));
    }

    /// Every attempt that did not end `FAILED`, a running one included,
    /// carries no failure kind.
    #[tokio::test]
    async fn an_attempt_that_did_not_fail_carries_no_failure_kind() {
        let schema = TestSchema::new().await;
        let ended = [
            ("succeeded-1", 1, OperationOutcome::Succeeded, "SUCCEEDED"),
            (
                "rolled-back-1",
                2,
                OperationOutcome::RolledBack,
                "ROLLED_BACK",
            ),
            ("cancelled-1", 3, OperationOutcome::Cancelled, "CANCELLED"),
        ];
        for (key, instance, outcome, _) in ended {
            let row = attempt(key, OperationAction::Update, HOST, "roxyd", Some(instance));
            seed(&schema.store(), &finished(row, outcome));
        }
        seed(
            &schema.store(),
            &attempt("running-1", OperationAction::Update, HOST, "roxyd", Some(4)),
        );

        let expected = ended
            .iter()
            .map(|(key, _, _, rendered)| (*key, json!(rendered)))
            .chain([("running-1", json!(null))]);
        for (key, outcome) in expected {
            let res = schema.execute_as_system_admin(&attempt_query(key)).await;
            assert!(res.errors.is_empty(), "{key}: {:?}", res.errors);
            let data = res.data.into_json().unwrap();
            let found = &data["operationAttempt"];
            assert_eq!(found["outcome"], outcome, "{key}");
            assert_eq!(found["failureKind"], json!(null), "{key}");
        }
    }

    /// The inline latest attempt is the same record as the top-level one, and
    /// carries the failure kind too.
    #[tokio::test]
    async fn the_inline_attempt_carries_the_failure_kind() {
        let schema = TestSchema::new().await;
        let node_id = insert_node(
            &schema.store(),
            "node1",
            HOST,
            CUSTOMER,
            vec![agent("hog1", AgentKind::SemiSupervised, Some(1))],
            vec![],
        );
        seed(
            &schema.store(),
            &failed(
                attempt("failed-1", OperationAction::Update, HOST, "hog", Some(1)),
                OperationFailureKind::TrustAnchorRefused,
            ),
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{node_id}\") {{ agents {{ latestOperationAttempt {{ id outcome failureKind }} }} }} }}"
            ))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let found = &data["node"]["agents"][0]["latestOperationAttempt"];
        assert_eq!(found["id"], json!("failed-1"));
        assert_eq!(found["outcome"], json!("FAILED"));
        assert_eq!(found["failureKind"], json!("TRUST_ANCHOR_REFUSED"));
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

    /// A target outside the module package-ids is refused, so observation
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

    /// A pair with no install attempt answers null, not an error.
    #[tokio::test]
    async fn latest_install_is_null_for_a_pair_with_none() {
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);

        assert_eq!(latest_install(&schema, HOST, "hog").await, json!(null));
    }

    /// A running install is the latest install, and reads as running.
    #[tokio::test]
    async fn latest_install_returns_a_running_install() {
        const KEY: &str = "0aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        seed(
            &schema.store(),
            &attempt(KEY, OperationAction::Install, HOST, "hog", None),
        );

        let found = latest_install(&schema, HOST, "hog").await;
        assert_eq!(found["id"], json!(KEY));
        assert_eq!(found["action"], json!("INSTALL"));
        assert_eq!(found["phase"], json!("DISPATCHED"));
        assert_eq!(found["outcome"], json!(null));
        assert_eq!(found["failureKind"], json!(null));
        assert_eq!(found["host"], json!(HOST));
        assert_eq!(found["target"], json!("hog"));
    }

    /// An install that failed after an earlier one succeeded is the answer,
    /// with its failure kind.
    ///
    /// The keys run the other way from the instants, so the scan meets the
    /// failed install first and the answer is chosen by `startedAt`.
    #[tokio::test]
    async fn latest_install_returns_a_failure_after_a_success() {
        const SUCCEEDED: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        const FAILED: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        let succeeded = attempt(SUCCEEDED, OperationAction::Install, HOST, "hog", Some(1));
        seed(&schema.store(), &succeeded);
        seed(
            &schema.store(),
            &finished(succeeded, OperationOutcome::Succeeded),
        );
        let mut failure = attempt(FAILED, OperationAction::Install, HOST, "hog", Some(2));
        failure.started_at = instant(30);
        seed(&schema.store(), &failure);
        seed(
            &schema.store(),
            &failed(failure, OperationFailureKind::HostNotPrepared),
        );

        let found = latest_install(&schema, HOST, "hog").await;
        assert_eq!(found["id"], json!(FAILED));
        assert_eq!(found["phase"], json!("COMPLETED"));
        assert_eq!(found["outcome"], json!("FAILED"));
        assert_eq!(found["failureKind"], json!("HOST_NOT_PREPARED"));
        assert_eq!(found["cleanupOwed"], json!(null));
    }

    /// A failed install that still owes its teardown is returned, with the
    /// teardown it owes, rather than hidden.
    #[tokio::test]
    async fn latest_install_returns_a_failure_that_owes_cleanup() {
        const KEY: &str = "0aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        let mut failure = attempt(KEY, OperationAction::Install, HOST, "giganto", Some(1));
        seed(&schema.store(), &failure);
        failure.cleanup_state = Some(OperationCleanupState::PendingDeregister);
        seed(
            &schema.store(),
            &failed(failure, OperationFailureKind::ServiceFailed),
        );

        let found = latest_install(&schema, HOST, "giganto").await;
        assert_eq!(found["id"], json!(KEY));
        assert_eq!(found["outcome"], json!("FAILED"));
        assert_eq!(found["failureKind"], json!("SERVICE_FAILED"));
        assert_eq!(found["cleanupOwed"], json!("PENDING_DEREGISTER"));
    }

    /// A newer install of the pair supersedes a failed one, whatever state
    /// the newer one is in.
    #[tokio::test]
    async fn latest_install_is_superseded_by_a_newer_install() {
        const FAILED: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        const NEWER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        let failure = attempt(FAILED, OperationAction::Install, HOST, "hog", Some(1));
        seed(&schema.store(), &failure);
        seed(
            &schema.store(),
            &failed(failure, OperationFailureKind::Other),
        );
        assert_eq!(
            latest_install(&schema, HOST, "hog").await["id"],
            json!(FAILED)
        );

        let mut newer = attempt(NEWER, OperationAction::Install, HOST, "hog", None);
        newer.started_at = instant(120);
        seed(&schema.store(), &newer);

        let found = latest_install(&schema, HOST, "hog").await;
        assert_eq!(found["id"], json!(NEWER));
        assert_eq!(found["outcome"], json!(null));
        assert_eq!(found["failureKind"], json!(null));
    }

    /// Two installs that began in the same instant are told apart by the id,
    /// and the greater one is the latest.
    #[tokio::test]
    async fn latest_install_breaks_a_tie_on_the_id() {
        const LESSER: &str = "1aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const GREATER: &str = "2bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        // Both under the instant `attempt` stamps. The scan meets the lesser
        // key first, so an answer that kept the first of a tie would be wrong.
        seed(
            &schema.store(),
            &attempt(GREATER, OperationAction::Install, HOST, "hog", Some(2)),
        );
        seed(
            &schema.store(),
            &attempt(LESSER, OperationAction::Install, HOST, "hog", Some(1)),
        );

        assert_eq!(
            latest_install(&schema, HOST, "hog").await["id"],
            json!(GREATER)
        );
    }

    /// Attempts of other actions, and installs on another host or of another
    /// target, are never the answer, however recent.
    #[tokio::test]
    async fn latest_install_ignores_other_actions_hosts_and_targets() {
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
        let mine = attempt(MINE, OperationAction::Install, HOST, "hog", Some(1));
        seed(&schema.store(), &mine);
        seed(
            &schema.store(),
            &failed(mine, OperationFailureKind::BuildNotServable),
        );
        let newer = [
            ("update-1", OperationAction::Update, HOST, "hog", Some(1)),
            ("remove-1", OperationAction::Remove, HOST, "hog", Some(2)),
            ("onboard-1", OperationAction::Onboard, HOST, "", None),
            (ELSEWHERE, OperationAction::Install, OTHER_HOST, "hog", None),
            (
                ANOTHER_TARGET,
                OperationAction::Install,
                HOST,
                "piglet",
                None,
            ),
        ];
        for (offset, (key, action, host, target, instance)) in (1..).zip(newer) {
            let mut row = attempt(key, action, host, target, instance);
            row.started_at = instant(offset * 60);
            seed(&schema.store(), &row);
        }

        let found = latest_install(&schema, HOST, "hog").await;
        assert_eq!(found["id"], json!(MINE));
        assert_eq!(found["outcome"], json!("FAILED"));
        assert_eq!(found["failureKind"], json!("BUILD_NOT_SERVABLE"));

        // The other pairs are answered with their own installs.
        assert_eq!(
            latest_install(&schema, OTHER_HOST, "hog").await["id"],
            json!(ELSEWHERE)
        );
        assert_eq!(
            latest_install(&schema, HOST, "piglet").await["id"],
            json!(ANOTHER_TARGET)
        );
        assert_eq!(latest_install(&schema, HOST, "giganto").await, json!(null));
    }

    /// A non-module target is refused with the error `inFlightInstalls`
    /// gives, even where the ledger holds an install of it.
    #[tokio::test]
    async fn latest_install_refuses_a_non_module_target() {
        const KEY: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        seed(
            &schema.store(),
            &attempt(KEY, OperationAction::Install, HOST, "review", None),
        );

        for target in ["review", "roxyd", "bootroot", "nonesuch"] {
            let res = schema
                .execute_as_system_admin(&latest_install_query(HOST, target))
                .await;
            assert_eq!(res.errors.len(), 1, "{target}");
            assert_eq!(
                res.errors[0].message,
                format!("{target} is not one of the package-ids this operation accepts"),
                "{target}"
            );
            assert_eq!(
                res.data.into_json().unwrap()["latestInstall"],
                json!(null),
                "{target}"
            );
        }
    }

    /// `latestInstall` holds a caller to the role floor and to its own
    /// customers' hosts, as `inFlightInstalls` does.
    #[tokio::test]
    async fn latest_install_refuses_a_caller_without_access() {
        const KEY: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        seed(
            &schema.store(),
            &attempt(KEY, OperationAction::Install, HOST, "hog", Some(1)),
        );

        let allowed = schema
            .execute_as_scoped_user(
                &latest_install_query(HOST, "hog"),
                Role::SecurityAdministrator,
                Some(vec![CUSTOMER]),
            )
            .await;
        assert!(allowed.errors.is_empty(), "{:?}", allowed.errors);
        assert_eq!(
            allowed.data.into_json().unwrap()["latestInstall"]["id"],
            json!(KEY)
        );

        // The host-scoped check runs before the module-class one, so a caller
        // outside the host's customer is told nothing about the target it
        // named.
        for target in ["hog", "roxyd"] {
            let refused = schema
                .execute_as_scoped_user(
                    &latest_install_query(HOST, target),
                    Role::SecurityAdministrator,
                    Some(vec![OTHER_CUSTOMER]),
                )
                .await;
            assert_eq!(refused.errors.len(), 1, "{target}: {:?}", refused.errors);
            assert_eq!(refused.errors[0].message, "Forbidden", "{target}");
        }

        for role in [Role::SecurityManager, Role::SecurityMonitor] {
            let refused = schema
                .execute_as_scoped_user(
                    &latest_install_query(HOST, "hog"),
                    role,
                    Some(vec![CUSTOMER]),
                )
                .await;
            assert_eq!(refused.errors.len(), 1, "{role:?}");
            assert_eq!(refused.errors[0].message, "Forbidden", "{role:?}");
        }
    }

    /// Returns the ids `inFlightInstalls` lists for `(host, target)` as a
    /// system administrator, asserting that it carries no error.
    async fn in_flight_ids(schema: &TestSchema, host: &str, target: &str) -> Vec<String> {
        let res = schema
            .execute_as_system_admin(&in_flight_query(host, target))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        res.data.into_json().unwrap()["inFlightInstalls"]
            .as_array()
            .expect("a list")
            .iter()
            .map(|attempt| attempt["id"].as_str().expect("an id").to_string())
            .collect()
    }

    /// A system log collector's install never shows on either install query,
    /// while it runs or once it finished, and never hides an operator's
    /// install of the same `(host, reproduce)`.
    ///
    /// The system install is requested after the operator's, so a query that
    /// still counted it would answer it as the latest.
    #[tokio::test]
    async fn the_install_queries_leave_out_a_system_install() {
        const SYSTEM: &str = "0aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const OPERATOR: &str = "0bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);

        // The key is written before its attempt, as review writes it.
        schema
            .store()
            .system_log_collector_map()
            .append_install_key(HOST, SYSTEM, None)
            .expect("append the system install key");
        let mut system = attempt(SYSTEM, OperationAction::Install, HOST, "reproduce", Some(1));
        system.started_at = instant(30);
        seed(&schema.store(), &system);

        assert_eq!(
            in_flight_ids(&schema, HOST, "reproduce").await,
            Vec::<String>::new()
        );
        assert_eq!(
            latest_install(&schema, HOST, "reproduce").await,
            json!(null)
        );

        seed(
            &schema.store(),
            &finished(system, OperationOutcome::Succeeded),
        );
        schema
            .store()
            .system_log_collector_map()
            .record_install(SYSTEM, 1, "1.2.0", "abcabc")
            .expect("record the system install");

        assert_eq!(
            in_flight_ids(&schema, HOST, "reproduce").await,
            Vec::<String>::new()
        );
        assert_eq!(
            latest_install(&schema, HOST, "reproduce").await,
            json!(null)
        );

        let operator = attempt(
            OPERATOR,
            OperationAction::Install,
            HOST,
            "reproduce",
            Some(2),
        );
        seed(&schema.store(), &operator);

        assert_eq!(
            in_flight_ids(&schema, HOST, "reproduce").await,
            vec![OPERATOR.to_string()]
        );
        let found = latest_install(&schema, HOST, "reproduce").await;
        assert_eq!(found["id"], json!(OPERATOR));
        assert_eq!(found["outcome"], json!(null));

        seed(
            &schema.store(),
            &finished(operator, OperationOutcome::Succeeded),
        );

        assert_eq!(
            in_flight_ids(&schema, HOST, "reproduce").await,
            Vec::<String>::new()
        );
        let found = latest_install(&schema, HOST, "reproduce").await;
        assert_eq!(found["id"], json!(OPERATOR));
        assert_eq!(found["outcome"], json!("SUCCEEDED"));
    }

    /// Both a running system install and a running operator install: only
    /// the operator's is answered.
    #[tokio::test]
    async fn the_install_queries_answer_the_operator_install_beside_a_running_system_one() {
        const SYSTEM: &str = "0aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const OPERATOR: &str = "0bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        schema
            .store()
            .system_log_collector_map()
            .append_install_key(HOST, SYSTEM, None)
            .expect("append the system install key");
        let mut system = attempt(SYSTEM, OperationAction::Install, HOST, "reproduce", Some(1));
        system.started_at = instant(30);
        seed(&schema.store(), &system);
        seed(
            &schema.store(),
            &attempt(
                OPERATOR,
                OperationAction::Install,
                HOST,
                "reproduce",
                Some(2),
            ),
        );

        assert_eq!(
            in_flight_ids(&schema, HOST, "reproduce").await,
            vec![OPERATOR.to_string()]
        );
        assert_eq!(
            latest_install(&schema, HOST, "reproduce").await["id"],
            json!(OPERATOR)
        );
    }

    /// With no system log collector row, an operator's `reproduce` install is
    /// answered as before.
    #[tokio::test]
    async fn the_install_queries_are_unchanged_without_system_rows() {
        const OPERATOR: &str = "0bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let schema = TestSchema::new().await;
        insert_node(&schema.store(), "node1", HOST, CUSTOMER, vec![], vec![]);
        seed(
            &schema.store(),
            &attempt(
                OPERATOR,
                OperationAction::Install,
                HOST,
                "reproduce",
                Some(2),
            ),
        );

        assert_eq!(
            in_flight_ids(&schema, HOST, "reproduce").await,
            vec![OPERATOR.to_string()]
        );
        assert_eq!(
            latest_install(&schema, HOST, "reproduce").await["id"],
            json!(OPERATOR)
        );
    }

    /// A system candidate the scan copied while it ran, whose attempt and key
    /// were pruned before the key-set read, is kept by neither query's
    /// predicates: its key is gone from the excluded set, and the re-read
    /// finds no attempt.
    #[tokio::test]
    async fn a_system_candidate_pruned_after_the_scan_is_not_returned() {
        const SYSTEM: &str = "0aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const LATER: &str = "0ccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let schema = TestSchema::new().await;
        let store = schema.store();
        store
            .system_log_collector_map()
            .append_install_key(HOST, SYSTEM, None)
            .expect("append the system install key");
        let system = attempt(SYSTEM, OperationAction::Install, HOST, "reproduce", Some(1));
        seed(&store, &system);

        // The copy the candidate scan made while the install ran.
        let copied = store
            .operation_attempt_map()
            .get(SYSTEM)
            .expect("read")
            .expect("the attempt is there");

        seed(&store, &finished(system, OperationOutcome::Succeeded));
        // `prune` keeps the attempt the latest pointer names for its triple,
        // so a later attempt of the same triple takes the pointer off the
        // system install.
        let later = attempt(LATER, OperationAction::Update, HOST, "reproduce", Some(1));
        seed(&store, &later);
        seed(&store, &finished(later, OperationOutcome::Succeeded));
        let removed = store
            .operation_attempt_map()
            .prune(
                OperationRetentionBound {
                    max_age: TimeDelta::zero(),
                    max_terminal_per_triple: 1,
                },
                instant(120),
            )
            .expect("prune");
        assert_eq!(removed, 1);
        assert!(
            store
                .operation_attempt_map()
                .get(SYSTEM)
                .expect("read")
                .is_none()
        );
        assert!(
            store
                .system_log_collector_map()
                .install_keys()
                .expect("read the install keys")
                .is_empty()
        );

        let in_flight = super::operator_installs(
            &store,
            vec![copied.clone()],
            super::in_flight_install_of(HOST, "reproduce"),
        )
        .expect("the post-scan read");
        assert_eq!(in_flight, Vec::<Record>::new());
        let latest =
            super::operator_installs(&store, vec![copied], super::install_of(HOST, "reproduce"))
                .expect("the post-scan read");
        assert_eq!(latest, Vec::<Record>::new());
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
            "{{ node(id: \"{node_id}\") {{ agents {{ latestOperationAttempt {{ id cleanupOwed failureKind }} }} }} }}"
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
        seed(
            &schema.store(),
            &failed(owing, OperationFailureKind::NotApplied),
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let found = &data["node"]["agents"][0]["latestOperationAttempt"];
        assert_eq!(found["id"], json!("owing-1"));
        assert_eq!(found["cleanupOwed"], json!("PENDING_DEREGISTER"));
        assert_eq!(found["failureKind"], json!("NOT_APPLIED"));

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

    /// A Security Monitor reads the inline attempt on its own customer's node
    /// through `nodeList`, and the list carries no other customer's node.
    #[tokio::test]
    async fn a_security_monitor_reads_the_inline_attempt_on_its_own_node() {
        const OTHER_HOST: &str = "host2.example.com";
        let schema = TestSchema::new().await;
        insert_node(
            &schema.store(),
            "node1",
            HOST,
            1,
            vec![agent("hog1", AgentKind::SemiSupervised, Some(1))],
            vec![],
        );
        insert_node(
            &schema.store(),
            "node2",
            OTHER_HOST,
            2,
            vec![agent("hog1", AgentKind::SemiSupervised, Some(1))],
            vec![],
        );
        seed(
            &schema.store(),
            &attempt("own-1", OperationAction::Update, HOST, "hog", Some(1)),
        );
        seed(
            &schema.store(),
            &attempt(
                "other-1",
                OperationAction::Update,
                OTHER_HOST,
                "hog",
                Some(1),
            ),
        );

        let res = schema
            .execute_as_scoped_user(
                "{ nodeList { edges { node { name agents { key latestOperationAttempt { id } } } } } }",
                Role::SecurityMonitor,
                Some(vec![1]),
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "edges": [{
                        "node": {
                            "name": "node1",
                            "agents": [{
                                "key": "hog1",
                                "latestOperationAttempt": {"id": "own-1"}
                            }]
                        }
                    }]
                }
            })
        );
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
