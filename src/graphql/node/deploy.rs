//! The immediate package-deployment and host-onboarding mutations.
//!
//! These are immediate actions and never ride the configuration draft: the
//! resolver authorizes, validates the shape of what was submitted, makes one
//! call through [`PackageDeployer`](crate::backend::PackageDeployer) or
//! [`HostOnboarder`](crate::backend::HostOnboarder), and renders what comes
//! back.
//!
//! Nothing here reads a store or the attempt ledger. Which instance an install
//! allocates, whether an instance exists, how single-flight derives its key and
//! what a repeated request key resolves to are all review's answers, reached
//! through that one call.

use async_graphql::{
    Context, Enum, InputObject, Object, Result, SimpleObject, StringNumber, Union,
};
use review_database::{BuildSelector, RequestKeyError};
use tracing::info;

use super::{
    super::{BoxedHostOnboarder, BoxedPackageDeployer, Role, RoleGuard, customer_access},
    DeployMutation,
    bind_addr::{
        BindAddrInput, HostOccupancyUnavailable, HostPortOccupied, PortAllocationConflict,
        host_occupancy_unavailable, host_port_occupied, port_allocation_conflict,
    },
};
use crate::{
    backend::{
        self, BindAddrInput as BackendBindAddrInput, DeployError,
        HostOnboardingTicket as BackendHostOnboardingTicket, MODULE_PACKAGE_IDS, OperationId,
    },
    info_with_username,
};

/// The byte length of a `UUIDv4` in canonical hyphenated form.
const UUID_LEN: usize = 36;

/// What an apply does with a host it could not finish.
//
// It exists solely to reach the SDL.
// `review_protocol::types::node::FailurePolicy` is the type
// `crate::backend::PackageDeployer` accepts, and it is foreign, so the orphan
// rule bars an `async_graphql::Enum` derive on it; this declaration carries no
// variant it does not and no behaviour beyond the total two-arm conversion into
// it. That conversion is the one the `remote` attribute derives, so a variant
// added upstream stops this compiling rather than silently going unmapped.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_protocol::types::node::FailurePolicy")]
pub(crate) enum FailurePolicy {
    /// Put the build that was there back.
    Rollback,
    /// Leave the failure standing for an operator to look at.
    Hold,
}

/// Whether the apply finished or was accepted for later reconciliation.
///
/// A client must not read `ACCEPTED` as done: it means the apply tore down its
/// own response channel and the true outcome is reconciled later, which is what
/// an operation query is for.
// It mirrors `crate::backend::DeployOutcome` through the derived conversion, for
// the same reason as `FailurePolicy` above.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "crate::backend::DeployOutcome")]
pub(crate) enum DeployDisposition {
    /// The agent finished the apply and reported a terminal outcome.
    Applied,
    /// A self-disrupting apply answered before the swap tore the response
    /// channel down, so the true outcome is reconciled later.
    Accepted,
}

/// The build the operator asked for: exactly one field is set.
///
/// GraphQL has no input union, so the two alternatives cross as nullable
/// fields and a submission setting both or neither is refused.
// [`build_selector`] is what enforces that rule, and past that conversion no
// representation carrying both or neither exists.
#[derive(InputObject)]
pub(crate) struct BuildSelectorInput {
    /// A version, which review turns into a build.
    version: Option<String>,
    /// An exact commit.
    commit: Option<String>,
}

/// The install was accepted, and this is the operation to poll.
#[derive(SimpleObject)]
pub(crate) struct InstallServiceSuccess {
    /// The attempt's durable identity, which for an install is the submitted
    /// `requestKey`.
    operation_id: String,
    /// Whether the apply finished or was accepted for later reconciliation.
    disposition: DeployDisposition,
}

/// The update was accepted, and this is the operation to poll.
#[derive(SimpleObject)]
pub(crate) struct UpdateServiceSuccess {
    /// The attempt's durable identity.
    operation_id: String,
    /// Whether the apply finished or was accepted for later reconciliation.
    disposition: DeployDisposition,
}

/// The removal was accepted, and this is the operation to poll.
///
/// It carries no disposition because `remove` returns only an id.
#[derive(SimpleObject)]
pub(crate) struct RemoveServiceSuccess {
    /// The attempt's durable identity.
    operation_id: String,
}

/// A core-component update was accepted, and this is the operation to poll.
#[derive(SimpleObject)]
pub(crate) struct UpdateCoreComponentSuccess {
    /// The attempt's durable identity.
    operation_id: String,
    /// Whether the apply finished or was accepted for later reconciliation.
    disposition: DeployDisposition,
}

/// What `updateCoreComponent` answers with.
#[derive(Union)]
pub(crate) enum UpdateCoreComponentResult {
    Success(UpdateCoreComponentSuccess),
    CleanupPending(CleanupPending),
}

/// The one-time credential and command for bringing a host under management.
#[derive(SimpleObject)]
pub(crate) struct HostOnboardingTicket {
    /// The onboarding operation to poll.
    operation_id: String,
    /// The live one-time credential the operator supplies to the host.
    token: String,
    /// The one-liner the operator runs on the host.
    command: String,
    /// The granted absolute deadline at which the token expires.
    expires_at: jiff::Timestamp,
}

/// The request key already names an attempt submitted with a different
/// request.
///
/// It is non-retryable: the same submission produces the same refusal. A
/// repeat carrying the *same* request is not this — it is a success carrying
/// the first call's operation id.
#[derive(SimpleObject)]
pub(crate) struct RequestKeyReused {
    /// The key as submitted.
    request_key: String,
}

/// A teardown is still owed on the target, so a new operation on it cannot
/// start.
///
/// It is a mutation result rather than a read field because a client that read
/// the owed cleanup a moment earlier can still lose the race, and the
/// operation id is what lets a screen point at the cleanup instead of saying
/// "try again later".
#[derive(SimpleObject)]
pub(crate) struct CleanupPending {
    /// The host the teardown is owed on.
    host: String,
    /// The package-id the teardown is owed for.
    target: String,
    /// The instance the teardown is owed for. It is null when the refused
    /// install never allocated one.
    instance: Option<StringNumber<u32>>,
    /// The operation that owes it.
    operation_id: String,
}

/// What `installService` answers with.
// Every other refusal — the guard, the per-host check, the class binding, a
// malformed request key, a malformed selector, an unparseable bind address,
// and every `DeployError` variant outside this list — is an ordinary GraphQL
// error. None of them is a state the install form renders.
#[derive(Union)]
pub(crate) enum InstallServiceResult {
    Success(InstallServiceSuccess),
    PortAllocationConflict(PortAllocationConflict),
    HostPortOccupied(HostPortOccupied),
    HostOccupancyUnavailable(HostOccupancyUnavailable),
    RequestKeyReused(RequestKeyReused),
    CleanupPending(CleanupPending),
}

/// What `updateService` answers with.
///
/// An update allocates nothing, so neither bind-address conflict and no
/// request-key refusal is reachable from it.
#[derive(Union)]
pub(crate) enum UpdateServiceResult {
    Success(UpdateServiceSuccess),
    CleanupPending(CleanupPending),
}

/// What `removeService` answers with.
#[derive(Union)]
pub(crate) enum RemoveServiceResult {
    Success(RemoveServiceSuccess),
    CleanupPending(CleanupPending),
}

/// Refuses a target outside `permitted`, naming it, as an ordinary GraphQL
/// error.
///
/// The permitted set is a parameter rather than a hard-wired constant because
/// the guard tier and the package class are bound together at the resolver:
/// the module mutations pass [`MODULE_PACKAGE_IDS`] and the core-component
/// mutations pass `CORE_PACKAGE_IDS`, so one comparison site answers for both
/// tiers. A second site is how one target comes to have two classes.
///
/// `bootroot` is in neither list and is therefore refused everywhere.
///
/// # Errors
///
/// Returns an error naming `target` if `permitted` does not contain it.
pub(crate) fn bind_package_class(target: &str, permitted: &[&str]) -> Result<()> {
    if permitted.contains(&target) {
        Ok(())
    } else {
        Err(format!("{target} is not one of the package-ids this operation accepts").into())
    }
}

/// Refuses both-set and neither-set, as an ordinary GraphQL error.
///
/// This is the only [`BuildSelectorInput`] conversion in the crate, so the
/// "exactly one field set" rule has exactly one enforcement point and nothing
/// downstream can hold a selector that breaks it.
///
/// # Errors
///
/// Returns an error if both `version` and `commit` are set, or neither is.
pub(crate) fn build_selector(input: BuildSelectorInput) -> Result<BuildSelector> {
    match (input.version, input.commit) {
        (Some(version), None) => Ok(BuildSelector::Version(version)),
        (None, Some(commit)) => Ok(BuildSelector::Commit(commit)),
        (Some(_), Some(_)) => {
            Err("buildSelector sets both version and commit; exactly one is required".into())
        }
        (None, None) => {
            Err("buildSelector sets neither version nor commit; exactly one is required".into())
        }
    }
}

/// Returns whether `key` is a `UUIDv4` in canonical hyphenated form, which is
/// lowercase.
///
/// Lowercase is part of the rule rather than a nicety: review keys the attempt
/// ledger on the submitted byte string, so accepting uppercase would let one
/// UUID arrive as two request keys, each finding no row under the other and
/// each starting its own install.
//
// This restates `review-database`'s private `fn is_uuid_v4` — `d220eb9`,
// `src/tables/operation_attempt.rs:521`, which is the same rule at the same
// line under the `698254e` revision this crate pins — rule for rule, so the
// two can be compared side by side. It is restated rather than called because
// upstream declares it without `pub` and leaves it out of the `src/tables.rs`
// re-export list; its public callers, `Table::resolve_request_key` and
// `Table::create_or_resolve`, each read or write the ledger, and this layer
// does not cross that boundary.
fn is_uuid_v4(key: &str) -> bool {
    if key.len() != UUID_LEN {
        return false;
    }
    let bytes = key.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
        } else if !matches!(byte, b'0'..=b'9' | b'a'..=b'f') {
            return false;
        }
    }
    // The version nibble is `4`, and the variant nibble is one of `8`, `9`,
    // `a` or `b`.
    bytes.get(14) == Some(&b'4') && matches!(bytes.get(19), Some(b'8' | b'9' | b'a' | b'b'))
}

/// Refuses a request key that is not a canonical `UUIDv4`, in the ledger's own
/// words.
///
/// A missing or malformed key is refused and never defaulted: a default would
/// silently restore the collision the key exists to prevent. The refusal is an
/// ordinary GraphQL error rather than a union member because malformedness is
/// decidable here from the string alone, before anything is attempted, while
/// reuse is review's answer about its own ledger.
fn check_request_key(request_key: &str) -> Result<()> {
    if is_uuid_v4(request_key) {
        Ok(())
    } else {
        Err(RequestKeyError::MalformedRequestKey {
            request_key: request_key.to_string(),
        }
        .to_string()
        .into())
    }
}

/// Converts the submitted bind addresses, parsing each address.
///
/// The list is preserved in order and multiplicity, with each `listener_key`
/// byte for byte: review refuses a duplicate listener key at its own boundary
/// and can only refuse what reaches it, so nothing here sorts, deduplicates or
/// folds the list into a map. What the parse does not preserve is the textual
/// spelling of an address, because `[::1]:80` and `[0:0:0:0:0:0:0:1]:80` are
/// one `SocketAddr` and only one spelling can come back out.
fn bind_addrs(submitted: Option<Vec<BindAddrInput>>) -> Result<Option<Vec<BackendBindAddrInput>>> {
    submitted
        .map(|list| {
            list.into_iter()
                .map(|entry| BackendBindAddrInput::try_from(entry).map_err(Into::into))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()
}

/// Builds the [`CleanupPending`] member from the payload of
/// [`DeployError::CleanupPending`].
///
/// The parameter list is that variant's payload verbatim, so a field added to
/// the variant stops the call sites compiling rather than being dropped.
fn cleanup_pending(
    host: String,
    target: String,
    instance: Option<u32>,
    operation_id: OperationId,
) -> CleanupPending {
    CleanupPending {
        host,
        target,
        instance: instance.map(StringNumber),
        operation_id: operation_id.into_inner(),
    }
}

#[Object]
impl DeployMutation {
    /// Installs `target` on `host` as a newly allocated instance and returns
    /// the operation to poll.
    ///
    /// It takes no `instance`: review picks the next free instance number and
    /// this instance's addresses, which is why the mutation instead carries a
    /// client-minted `requestKey` that becomes the attempt's durable
    /// idempotency key. The client generates that key once per install the
    /// operator initiated, so a double-click carries the same value — and
    /// comes back as the same success — while a deliberate "add another
    /// instance" carries a new one.
    ///
    /// `bindAddrs` is optional. Absent means "no listening addresses to set",
    /// which is every component review's catalog does not list.
    // The argument list is the mutation's published contract, so it is not a
    // parameter count to reduce: folding the six into an input object would
    // change the schema.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn install_service(
        &self,
        ctx: &Context<'_>,
        host: String,
        target: String,
        build_selector: BuildSelectorInput,
        #[graphql(default_with = "FailurePolicy::Rollback")] on_failure: FailurePolicy,
        bind_addrs: Option<Vec<BindAddrInput>>,
        request_key: String,
    ) -> Result<InstallServiceResult> {
        customer_access::check_hostname_access(ctx, &host)?;
        bind_package_class(&target, &MODULE_PACKAGE_IDS)?;
        check_request_key(&request_key)?;
        let selector = self::build_selector(build_selector)?;
        let addrs = self::bind_addrs(bind_addrs)?;

        let deployer = ctx.data::<BoxedPackageDeployer>()?;
        // The request is recorded before the call rather than after it, so a
        // privileged operation a scoped operator asked for is in the log
        // whatever review answers: a refusal is exactly the case an audit
        // reads back.
        info_with_username!(ctx, "Install of {target} requested on {host}");
        match deployer
            .install(
                &host,
                &target,
                selector,
                on_failure.into(),
                addrs,
                &request_key,
            )
            .await
        {
            Ok((outcome, operation_id)) => {
                Ok(InstallServiceResult::Success(InstallServiceSuccess {
                    operation_id: operation_id.into_inner(),
                    disposition: outcome.into(),
                }))
            }
            Err(DeployError::PortAllocationConflict {
                host,
                transport,
                port,
                owner,
            }) => Ok(InstallServiceResult::PortAllocationConflict(
                port_allocation_conflict(host, transport, port, owner),
            )),
            Err(DeployError::HostPortOccupied {
                listener_key,
                transport,
                port,
            }) => Ok(InstallServiceResult::HostPortOccupied(host_port_occupied(
                listener_key,
                transport,
                port,
            ))),
            Err(DeployError::HostOccupancyUnavailable { host, reason }) => {
                Ok(InstallServiceResult::HostOccupancyUnavailable(
                    host_occupancy_unavailable(host, reason),
                ))
            }
            Err(DeployError::RequestKey(RequestKeyError::RequestKeyReused { request_key })) => {
                Ok(InstallServiceResult::RequestKeyReused(RequestKeyReused {
                    request_key,
                }))
            }
            Err(DeployError::CleanupPending {
                host,
                target,
                instance,
                operation_id,
            }) => Ok(InstallServiceResult::CleanupPending(cleanup_pending(
                host,
                target,
                instance,
                operation_id,
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Updates the build of an existing instance and returns the operation to
    /// poll.
    ///
    /// The identity already exists, so nothing is allocated or registered
    /// here. `instance` is the number the UI read from the row it acted on,
    /// never typed by an operator; whether it names an instance that exists is
    /// review's answer, and this resolver performs no existence check of its
    /// own.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_service(
        &self,
        ctx: &Context<'_>,
        host: String,
        target: String,
        instance: StringNumber<u32>,
        build_selector: BuildSelectorInput,
        #[graphql(default_with = "FailurePolicy::Rollback")] on_failure: FailurePolicy,
    ) -> Result<UpdateServiceResult> {
        customer_access::check_hostname_access(ctx, &host)?;
        bind_package_class(&target, &MODULE_PACKAGE_IDS)?;
        let selector = self::build_selector(build_selector)?;

        let deployer = ctx.data::<BoxedPackageDeployer>()?;
        // Logged before the call, for the same reason as in `install_service`.
        info_with_username!(ctx, "Update of {target} requested on {host}");
        match deployer
            .update(
                &host,
                &target,
                Some(instance.0),
                selector,
                on_failure.into(),
            )
            .await
        {
            Ok((outcome, operation_id)) => Ok(UpdateServiceResult::Success(UpdateServiceSuccess {
                operation_id: operation_id.into_inner(),
                disposition: outcome.into(),
            })),
            Err(DeployError::CleanupPending {
                host,
                target,
                instance,
                operation_id,
            }) => Ok(UpdateServiceResult::CleanupPending(cleanup_pending(
                host,
                target,
                instance,
                operation_id,
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes an existing instance and returns the operation to poll.
    ///
    /// Confirming the removal with the operator is a UI concern.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_service(
        &self,
        ctx: &Context<'_>,
        host: String,
        target: String,
        instance: StringNumber<u32>,
    ) -> Result<RemoveServiceResult> {
        customer_access::check_hostname_access(ctx, &host)?;
        bind_package_class(&target, &MODULE_PACKAGE_IDS)?;

        let deployer = ctx.data::<BoxedPackageDeployer>()?;
        // Logged before the call, for the same reason as in `install_service`.
        info_with_username!(ctx, "Removal of {target} requested on {host}");
        match deployer.remove(&host, &target, Some(instance.0)).await {
            Ok(operation_id) => Ok(RemoveServiceResult::Success(RemoveServiceSuccess {
                operation_id: operation_id.into_inner(),
            })),
            Err(DeployError::CleanupPending {
                host,
                target,
                instance,
                operation_id,
            }) => Ok(RemoveServiceResult::CleanupPending(cleanup_pending(
                host,
                target,
                instance,
                operation_id,
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Updates a control-plane component and returns the operation to poll.
    /// Core components have no instance dimension. Registry existence and a
    /// singleton component's fixed host are review's answers, reached through
    /// the one backend call rather than checked against a second source here.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn update_core_component(
        &self,
        ctx: &Context<'_>,
        component: String,
        host: String,
        build_selector: BuildSelectorInput,
        #[graphql(default_with = "FailurePolicy::Rollback")] on_failure: FailurePolicy,
    ) -> Result<UpdateCoreComponentResult> {
        bind_package_class(&component, &backend::CORE_PACKAGE_IDS)?;
        let selector = self::build_selector(build_selector)?;

        let deployer = ctx.data::<BoxedPackageDeployer>()?;
        info_with_username!(ctx, "Update of {component} requested on {host}");
        match deployer
            .update(&host, &component, None, selector, on_failure.into())
            .await
        {
            Ok((outcome, operation_id)) => Ok(UpdateCoreComponentResult::Success(
                UpdateCoreComponentSuccess {
                    operation_id: operation_id.into_inner(),
                    disposition: outcome.into(),
                },
            )),
            Err(DeployError::CleanupPending {
                host,
                target,
                instance,
                operation_id,
            }) => Ok(UpdateCoreComponentResult::CleanupPending(cleanup_pending(
                host,
                target,
                instance,
                operation_id,
            ))),
            Err(e) => Err(e.into()),
        }
    }

    /// Starts onboarding a host and returns its one-time ticket.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn onboard_host(&self, ctx: &Context<'_>, host: String) -> Result<HostOnboardingTicket> {
        let onboarder = ctx.data::<BoxedHostOnboarder>()?;
        let (ticket, operation_id): (BackendHostOnboardingTicket, OperationId) =
            onboarder.onboard_host(&host).await?;
        let (token, command, expires_at) = ticket.into_parts();
        info_with_username!(ctx, "Host onboarding token issued for {host}");
        Ok(HostOnboardingTicket {
            operation_id: operation_id.into_inner(),
            token: token.expose(),
            command,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Write},
        net::SocketAddr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use assert_json_diff::assert_json_eq;
    use chrono::Utc;
    use review_database::{
        Agent, AgentKind, AgentStatus, BuildSelector, Lifecycle, ListenerBinding,
        ListenerTransport, Node, NodeProfile, PortOwner, RequestKeyError, Role,
    };
    use review_protocol::types::node::{
        BootstrapMaterial, DeliveryMode, FailurePolicy as BackendFailurePolicy, PackageState,
    };
    use serde_json::json;
    use tracing_subscriber::fmt::MakeWriter;

    use super::{BuildSelectorInput, bind_package_class, build_selector, is_uuid_v4};
    use crate::{
        backend::{
            BindAddrInput as BackendBindAddrInput, BuildId, CORE_PACKAGE_IDS, DeployError,
            DeployOutcome, HostOnboarder, HostOnboardingTicket as BackendHostOnboardingTicket,
            JoinToken, MODULE_PACKAGE_IDS, OperationId, PackageDeployer,
        },
        graphql::{
            BoxedHostOnboarder, BoxedPackageDeployer, Mutation, Query, RoleGuard, Schema,
            Subscription, TestSchema,
        },
    };

    /// A canonical `UUIDv4`, which is what a client mints per install.
    const REQUEST_KEY: &str = "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e";

    /// The operation id the stub answers an update or a removal with. An
    /// install answers with the submitted key instead, which is what review
    /// does.
    const OPERATION_ID: &str = "11111111-2222-4333-8444-555555555555";

    const ONBOARD_OPERATION_ID: &str = "99999999-8888-4777-8666-555555555555";
    const JOIN_TOKEN: &str = "one-time-token-that-must-stay-secret";
    const ONBOARD_COMMAND: &str = "roxyd join --token-file /run/review/token";
    const EXPIRES_AT_SECOND: i64 = 1_700_000_123;

    /// The key a `RequestKeyReused` refusal carries. It is deliberately not
    /// [`REQUEST_KEY`], so a resolver that rendered its own argument instead of
    /// the variant's field would fail the assertion.
    const REUSED_KEY: &str = "cccccccc-dddd-4eee-8fff-000000000001";

    /// The targets outside the module class every mutation must refuse.
    const FOREIGN_TARGETS: [&str; 4] = ["roxyd", "review", "aice-web-next", "bootroot"];

    #[derive(Clone, Debug, PartialEq)]
    struct InstallCall {
        host: String,
        target: String,
        selector: BuildSelector,
        on_failure: BackendFailurePolicy,
        bind_addrs: Option<Vec<BackendBindAddrInput>>,
        request_key: String,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct UpdateCall {
        host: String,
        target: String,
        instance: Option<u32>,
        selector: BuildSelector,
        on_failure: BackendFailurePolicy,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct RemoveCall {
        host: String,
        target: String,
        instance: Option<u32>,
    }

    /// Every deployment call the stub was asked to make, in order.
    #[derive(Default)]
    struct Calls {
        installs: Mutex<Vec<InstallCall>>,
        updates: Mutex<Vec<UpdateCall>>,
        removes: Mutex<Vec<RemoveCall>>,
    }

    impl Calls {
        fn installs(&self) -> Vec<InstallCall> {
            self.installs.lock().unwrap().clone()
        }

        fn updates(&self) -> Vec<UpdateCall> {
            self.updates.lock().unwrap().clone()
        }

        fn removes(&self) -> Vec<RemoveCall> {
            self.removes.lock().unwrap().clone()
        }

        /// How many deployment calls were made in all, which is what a
        /// pre-backend refusal has to leave at zero.
        fn total(&self) -> usize {
            self.installs.lock().unwrap().len()
                + self.updates.lock().unwrap().len()
                + self.removes.lock().unwrap().len()
        }

        /// The one install the stub was asked to make.
        fn only_install(&self) -> InstallCall {
            let installs = self.installs();
            assert_eq!(installs.len(), 1, "exactly one install is expected");
            installs.into_iter().next().expect("the length is one")
        }

        /// The one update the stub was asked to make.
        fn only_update(&self) -> UpdateCall {
            let updates = self.updates();
            assert_eq!(updates.len(), 1, "exactly one update is expected");
            assert_eq!(self.total(), 1, "no other deployment call is expected");
            updates.into_iter().next().expect("the length is one")
        }
    }

    /// Which `DeployError` variant the stub fails with.
    ///
    /// The error is built on demand because `DeployError` is not `Clone`.
    #[derive(Clone, Copy)]
    enum Failure {
        PortAllocationConflict,
        HostPortOccupied,
        HostOccupancyUnavailable,
        RequestKeyReused,
        MalformedRequestKey,
        RequestKeyRead,
        CleanupPending(Option<u32>),
        Other,
    }

    impl Failure {
        fn error(self) -> DeployError {
            match self {
                Self::PortAllocationConflict => DeployError::PortAllocationConflict {
                    host: "giganto-host-7".to_string(),
                    transport: ListenerTransport::Udp,
                    port: u16::MAX,
                    owner: PortOwner {
                        component: "giganto".to_string(),
                        // Above `i32::MAX`, so `Int` could not carry it.
                        instance: 3_000_000_000,
                        listener_key: "publish".to_string(),
                    },
                },
                Self::HostPortOccupied => DeployError::HostPortOccupied {
                    listener_key: "ingest".to_string(),
                    transport: ListenerTransport::Tcp,
                    port: 38_371,
                },
                Self::HostOccupancyUnavailable => DeployError::HostOccupancyUnavailable {
                    host: "giganto-host-7".to_string(),
                    reason: "the host did not answer".to_string(),
                },
                Self::RequestKeyReused => {
                    DeployError::RequestKey(RequestKeyError::RequestKeyReused {
                        request_key: REUSED_KEY.to_string(),
                    })
                }
                Self::MalformedRequestKey => {
                    DeployError::RequestKey(RequestKeyError::MalformedRequestKey {
                        request_key: REUSED_KEY.to_string(),
                    })
                }
                Self::RequestKeyRead => DeployError::RequestKey(RequestKeyError::Read(
                    anyhow::anyhow!("the ledger could not be read"),
                )),
                Self::CleanupPending(instance) => DeployError::CleanupPending {
                    host: "giganto-host-7".to_string(),
                    target: "giganto".to_string(),
                    instance,
                    operation_id: OperationId::new(OPERATION_ID.to_string()),
                },
                Self::Other => {
                    DeployError::Other(anyhow::anyhow!("review answered something unmodelled"))
                }
            }
        }
    }

    /// What the stub answers every deployment call with.
    enum Answer {
        /// Succeeds. An install answers with the submitted request key as its
        /// operation id, which is what review does for an install; an update
        /// or a removal answers with [`OPERATION_ID`].
        Succeed(DeployOutcome),
        /// Succeeds with a fixed operation id whatever the request key was,
        /// which is how review answers a repeat carrying the same request.
        SucceedWith(&'static str, DeployOutcome),
        /// Fails with the named variant.
        Fail(Failure),
    }

    /// Records every deployment call and answers from a fixed script.
    ///
    /// The read methods panic: a test that reaches one is testing something
    /// this module does not do.
    struct RecordingDeployer {
        calls: Arc<Calls>,
        answer: Answer,
    }

    impl RecordingDeployer {
        fn boxed(answer: Answer) -> (Box<dyn PackageDeployer>, Arc<Calls>) {
            let calls = Arc::<Calls>::default();
            let deployer = Self {
                calls: Arc::clone(&calls),
                answer,
            };
            (Box::new(deployer), calls)
        }

        /// A stub that succeeds with `Applied`, for every test whose
        /// assertion is about what reached the backend — the recorded call,
        /// or the absence of one.
        fn applying() -> (Box<dyn PackageDeployer>, Arc<Calls>) {
            Self::boxed(Answer::Succeed(DeployOutcome::Applied))
        }

        fn answer_with(
            &self,
            operation_id: &str,
        ) -> Result<(DeployOutcome, OperationId), DeployError> {
            match &self.answer {
                Answer::Succeed(outcome) => {
                    Ok((*outcome, OperationId::new(operation_id.to_string())))
                }
                Answer::SucceedWith(id, outcome) => {
                    Ok((*outcome, OperationId::new((*id).to_string())))
                }
                Answer::Fail(failure) => Err(failure.error()),
            }
        }
    }

    #[async_trait::async_trait]
    impl PackageDeployer for RecordingDeployer {
        async fn install(
            &self,
            host: &str,
            target: &str,
            selector: BuildSelector,
            on_failure: BackendFailurePolicy,
            bind_addrs: Option<Vec<BackendBindAddrInput>>,
            request_key: &str,
        ) -> Result<(DeployOutcome, OperationId), DeployError> {
            self.calls.installs.lock().unwrap().push(InstallCall {
                host: host.to_string(),
                target: target.to_string(),
                selector,
                on_failure,
                bind_addrs,
                request_key: request_key.to_string(),
            });
            self.answer_with(request_key)
        }

        async fn update(
            &self,
            host: &str,
            target: &str,
            instance: Option<u32>,
            selector: BuildSelector,
            on_failure: BackendFailurePolicy,
        ) -> Result<(DeployOutcome, OperationId), DeployError> {
            self.calls.updates.lock().unwrap().push(UpdateCall {
                host: host.to_string(),
                target: target.to_string(),
                instance,
                selector,
                on_failure,
            });
            self.answer_with(OPERATION_ID)
        }

        async fn remove(
            &self,
            host: &str,
            target: &str,
            instance: Option<u32>,
        ) -> Result<OperationId, DeployError> {
            self.calls.removes.lock().unwrap().push(RemoveCall {
                host: host.to_string(),
                target: target.to_string(),
                instance,
            });
            self.answer_with(OPERATION_ID)
                .map(|(_outcome, operation_id)| operation_id)
        }

        async fn recommend_bind_addrs(
            &self,
            _host: &str,
            _target: &str,
        ) -> Result<Vec<ListenerBinding>, DeployError> {
            unimplemented!("this stub answers the three deployment calls only")
        }

        async fn latest_build(&self, _target: &str) -> Result<Option<BuildId>, anyhow::Error> {
            unimplemented!("this stub answers the three deployment calls only")
        }

        async fn package_status(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> Result<PackageState, anyhow::Error> {
            unimplemented!("this stub answers the three deployment calls only")
        }

        async fn read_version(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> Result<Option<BuildId>, anyhow::Error> {
            unimplemented!("this stub answers the three deployment calls only")
        }

        async fn register(
            &self,
            _service_name: &str,
            _host: &str,
            _instance: Option<u32>,
            _mode: DeliveryMode,
        ) -> Result<BootstrapMaterial, anyhow::Error> {
            unimplemented!("this stub answers the three deployment calls only")
        }

        async fn deregister(
            &self,
            _service_name: &str,
            _host: &str,
            _instance: Option<u32>,
        ) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers the three deployment calls only")
        }
    }

    #[derive(Clone, Copy)]
    enum OnboardAnswer {
        Succeed,
        Fail,
    }

    #[derive(Default)]
    struct OnboardCalls {
        count: AtomicUsize,
        hosts: Mutex<Vec<String>>,
        ticket_debug: Mutex<Vec<String>>,
    }

    impl OnboardCalls {
        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }

        fn only_host(&self) -> String {
            let hosts = self.hosts.lock().unwrap();
            assert_eq!(hosts.len(), 1, "exactly one onboarding call is expected");
            hosts.first().expect("the length is one").clone()
        }

        fn only_ticket_debug(&self) -> String {
            let rendered = self.ticket_debug.lock().unwrap();
            assert_eq!(rendered.len(), 1, "exactly one ticket is expected");
            rendered.first().expect("the length is one").clone()
        }
    }

    struct RecordingOnboarder {
        calls: Arc<OnboardCalls>,
        answer: OnboardAnswer,
    }

    impl RecordingOnboarder {
        fn boxed(answer: OnboardAnswer) -> (BoxedHostOnboarder, Arc<OnboardCalls>) {
            let calls = Arc::<OnboardCalls>::default();
            (
                Box::new(Self {
                    calls: Arc::clone(&calls),
                    answer,
                }),
                calls,
            )
        }
    }

    #[async_trait::async_trait]
    impl HostOnboarder for RecordingOnboarder {
        async fn onboard_host(
            &self,
            host: &str,
        ) -> Result<(BackendHostOnboardingTicket, OperationId), anyhow::Error> {
            self.calls.count.fetch_add(1, Ordering::SeqCst);
            self.calls.hosts.lock().unwrap().push(host.to_string());
            match self.answer {
                OnboardAnswer::Succeed => {
                    let ticket = BackendHostOnboardingTicket::new(
                        JoinToken::new(JOIN_TOKEN.to_string()),
                        ONBOARD_COMMAND.to_string(),
                        jiff::Timestamp::from_second(EXPIRES_AT_SECOND)?,
                    );
                    self.calls
                        .ticket_debug
                        .lock()
                        .unwrap()
                        .push(format!("{ticket:?}"));
                    Ok((ticket, OperationId::new(ONBOARD_OPERATION_ID.to_string())))
                }
                OnboardAnswer::Fail => anyhow::bail!("review could not mint a host ticket"),
            }
        }
    }

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl LogCapture {
        fn contents(&self) -> String {
            let buffer = self.0.lock().unwrap();
            String::from_utf8_lossy(&buffer).into_owned()
        }
    }

    impl Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for LogCapture {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    const INSTALL_SELECTION: &str = "__typename
        ... on InstallServiceSuccess { operationId disposition }
        ... on PortAllocationConflict {
            listenerKey host transport port holder { component instance }
        }
        ... on HostPortOccupied { listenerKey transport port }
        ... on HostOccupancyUnavailable { host reason }
        ... on RequestKeyReused { requestKey }
        ... on CleanupPending { host target instance operationId }";

    const UPDATE_SELECTION: &str = "__typename
        ... on UpdateServiceSuccess { operationId disposition }
        ... on CleanupPending { host target instance operationId }";

    const REMOVE_SELECTION: &str = "__typename
        ... on RemoveServiceSuccess { operationId }
        ... on CleanupPending { host target instance operationId }";

    const CORE_UPDATE_SELECTION: &str = "__typename
        ... on UpdateCoreComponentSuccess { operationId disposition }
        ... on CleanupPending { host target instance operationId }";

    fn install_mutation(args: &str) -> String {
        format!("mutation {{ installService({args}) {{ {INSTALL_SELECTION} }} }}")
    }

    fn update_mutation(args: &str) -> String {
        format!("mutation {{ updateService({args}) {{ {UPDATE_SELECTION} }} }}")
    }

    fn remove_mutation(args: &str) -> String {
        format!("mutation {{ removeService({args}) {{ {REMOVE_SELECTION} }} }}")
    }

    fn core_update_mutation(args: &str) -> String {
        format!("mutation {{ updateCoreComponent({args}) {{ {CORE_UPDATE_SELECTION} }} }}")
    }

    fn core_update_args(component: &str, host: &str) -> String {
        format!(r#"component: "{component}", host: "{host}", buildSelector: {{version: "0.1.0"}}"#)
    }

    fn onboard_mutation(host: &str) -> String {
        format!(
            r#"mutation {{ onboardHost(host: "{host}") {{ operationId token command expiresAt }} }}"#
        )
    }

    fn schema_without_store(
        deployer: BoxedPackageDeployer,
        onboarder: BoxedHostOnboarder,
    ) -> Schema {
        Schema::build(
            Query::default(),
            Mutation::default(),
            Subscription::default(),
        )
        .data(deployer)
        .data(onboarder)
        .finish()
    }

    async fn execute_without_store(schema: &Schema, query: &str) -> async_graphql::Response {
        schema
            .execute(
                async_graphql::Request::new(query)
                    .data(RoleGuard::Role(Role::SystemAdministrator))
                    .data("testuser".to_string()),
            )
            .await
    }

    /// A well-formed `installService` submission against `target`.
    fn install_args(target: &str) -> String {
        format!(
            r#"host: "host1", target: "{target}", buildSelector: {{version: "0.1.0"}}, requestKey: "{REQUEST_KEY}""#
        )
    }

    fn update_args(target: &str) -> String {
        format!(
            r#"host: "host1", target: "{target}", instance: "3", buildSelector: {{version: "0.1.0"}}"#
        )
    }

    fn remove_args(target: &str) -> String {
        format!(r#"host: "host1", target: "{target}", instance: "3""#)
    }

    /// The three well-formed submissions, one per mutation.
    fn every_mutation(target: &str) -> [String; 3] {
        [
            install_mutation(&install_args(target)),
            update_mutation(&update_args(target)),
            remove_mutation(&remove_args(target)),
        ]
    }

    fn malformed_message(request_key: &str) -> String {
        RequestKeyError::MalformedRequestKey {
            request_key: request_key.to_string(),
        }
        .to_string()
    }

    fn rendered_sdl() -> String {
        crate::graphql::Schema::build(
            Query::default(),
            Mutation::default(),
            Subscription::default(),
        )
        .finish()
        .sdl()
    }

    /// Returns the one SDL line declaring `name`.
    fn sdl_line(sdl: &str, name: &str) -> String {
        sdl.lines()
            .find(|line| line.trim_start().starts_with(name))
            .unwrap_or_else(|| panic!("the schema declares no {name}"))
            .trim()
            .to_string()
    }

    #[tokio::test]
    async fn core_and_onboarding_mutations_require_a_system_administrator() {
        for role in [
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let (deployer, deploy_calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let query = core_update_mutation(&core_update_args("review", "control-host"));
            let response = schema
                .execute_with_guard_and_data(
                    &query,
                    RoleGuard::Role(role),
                    deployer as BoxedPackageDeployer,
                )
                .await;
            assert_eq!(response.errors.len(), 1, "{role:?}");
            assert_eq!(response.errors[0].message, "Forbidden", "{role:?}");
            assert_eq!(deploy_calls.total(), 0, "{role:?}");

            let (onboarder, onboard_calls) = RecordingOnboarder::boxed(OnboardAnswer::Succeed);
            let response = schema
                .execute_with_guard_and_data(
                    &onboard_mutation("new-host"),
                    RoleGuard::Role(role),
                    onboarder,
                )
                .await;
            assert_eq!(response.errors.len(), 1, "{role:?}");
            assert_eq!(response.errors[0].message, "Forbidden", "{role:?}");
            assert_eq!(onboard_calls.count(), 0, "{role:?}");
        }
    }

    #[tokio::test]
    async fn only_core_package_ids_reach_the_core_update_backend() {
        for component in CORE_PACKAGE_IDS {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let query = core_update_mutation(&core_update_args(component, "control-host"));
            let response = schema
                .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
                .await;

            assert!(
                response.errors.is_empty(),
                "{component}: {:?}",
                response.errors
            );
            let call = calls.only_update();
            assert_eq!(call.target, component);
            assert_eq!(call.instance, None);
        }

        for component in std::iter::once("bootroot").chain(MODULE_PACKAGE_IDS) {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let query = core_update_mutation(&core_update_args(component, "control-host"));
            let response = schema
                .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
                .await;

            assert_eq!(response.errors.len(), 1, "{component}");
            assert!(
                response.errors[0].message.contains(component),
                "{component}: {}",
                response.errors[0].message
            );
            assert_eq!(calls.total(), 0, "{component}");
        }
    }

    #[tokio::test]
    async fn core_update_forwards_selector_policy_host_and_no_instance() {
        let cases = [
            (
                r#"{version: "0.1.0"}"#,
                None,
                BuildSelector::Version("0.1.0".to_string()),
                BackendFailurePolicy::Rollback,
            ),
            (
                r#"{commit: "0123456789abcdef"}"#,
                Some("HOLD"),
                BuildSelector::Commit("0123456789abcdef".to_string()),
                BackendFailurePolicy::Hold,
            ),
        ];

        for (selector, policy, expected_selector, expected_policy) in cases {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let policy = policy.map_or_else(String::new, |value| format!(", onFailure: {value}"));
            let args = format!(
                r#"component: "roxyd", host: "host byte-for-byte", buildSelector: {selector}{policy}"#
            );
            let response = schema
                .execute_as_system_admin_with_data(
                    &core_update_mutation(&args),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert!(response.errors.is_empty(), "{:?}", response.errors);
            let call = calls.only_update();
            assert_eq!(call.host, "host byte-for-byte");
            assert_eq!(call.target, "roxyd");
            assert_eq!(call.instance, None);
            assert_eq!(call.selector, expected_selector);
            assert_eq!(call.on_failure, expected_policy);
        }
    }

    #[tokio::test]
    async fn hold_is_forwarded_for_each_self_affecting_component() {
        for component in ["review", "aice-web-next"] {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let args = format!(
                r"{}, onFailure: HOLD",
                core_update_args(component, "control-host")
            );
            let response = schema
                .execute_as_system_admin_with_data(
                    &core_update_mutation(&args),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert!(
                response.errors.is_empty(),
                "{component}: {:?}",
                response.errors
            );
            assert_eq!(calls.only_update().on_failure, BackendFailurePolicy::Hold);
        }
    }

    #[tokio::test]
    async fn malformed_core_selectors_are_refused_without_a_backend_call() {
        for selector in [r#"{version: "0.1.0", commit: "abcdef"}"#, "{}"] {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let args =
                format!(r#"component: "review", host: "control-host", buildSelector: {selector}"#);
            let response = schema
                .execute_as_system_admin_with_data(
                    &core_update_mutation(&args),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert_eq!(response.errors.len(), 1, "{selector}");
            assert!(response.errors[0].message.contains("buildSelector"));
            assert_eq!(calls.total(), 0, "{selector}");
        }
    }

    #[tokio::test]
    async fn core_update_has_no_instance_argument() {
        let (deployer, calls) = RecordingDeployer::applying();
        let schema = TestSchema::new().await;
        let args = format!(
            r#"{}, instance: "1""#,
            core_update_args("review", "control-host")
        );
        let response = schema
            .execute_as_system_admin_with_data(
                &core_update_mutation(&args),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert_eq!(response.errors.len(), 1);
        assert_eq!(calls.total(), 0);
    }

    #[tokio::test]
    async fn unknown_core_registry_keys_are_forwarded_without_a_store() {
        for (component, host) in [
            ("roxyd", "host-with-no-registry-entry"),
            ("review", "some-other-host"),
        ] {
            let (deployer, calls) = RecordingDeployer::boxed(Answer::Fail(Failure::Other));
            let (onboarder, _) = RecordingOnboarder::boxed(OnboardAnswer::Succeed);
            let schema = schema_without_store(deployer as BoxedPackageDeployer, onboarder);
            let query = core_update_mutation(&core_update_args(component, host));
            let response = execute_without_store(&schema, &query).await;

            assert_eq!(response.errors.len(), 1, "{component}@{host}");
            assert_eq!(
                response.errors[0].message,
                "review answered something unmodelled"
            );
            let call = calls.only_update();
            assert_eq!(call.host, host);
            assert_eq!(call.target, component);
            assert_eq!(call.instance, None);
        }
    }

    #[tokio::test]
    async fn core_update_renders_both_deploy_dispositions() {
        for (outcome, expected) in [
            (DeployOutcome::Applied, "APPLIED"),
            (DeployOutcome::Accepted, "ACCEPTED"),
        ] {
            let (deployer, _) = RecordingDeployer::boxed(Answer::Succeed(outcome));
            let schema = TestSchema::new().await;
            let response = schema
                .execute_as_system_admin_with_data(
                    &core_update_mutation(&core_update_args("review", "control-host")),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert!(response.errors.is_empty(), "{:?}", response.errors);
            assert_json_eq!(
                response.data.into_json().unwrap(),
                json!({
                    "updateCoreComponent": {
                        "__typename": "UpdateCoreComponentSuccess",
                        "operationId": OPERATION_ID,
                        "disposition": expected,
                    }
                })
            );
        }
    }

    #[tokio::test]
    async fn cleanup_pending_is_the_only_core_update_error_returned_as_a_member() {
        let (deployer, _) = RecordingDeployer::boxed(Answer::Fail(Failure::CleanupPending(None)));
        let schema = TestSchema::new().await;
        let response = schema
            .execute_as_system_admin_with_data(
                &core_update_mutation(&core_update_args("review", "control-host")),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_json_eq!(
            response.data.into_json().unwrap(),
            json!({
                "updateCoreComponent": {
                    "__typename": "CleanupPending",
                    "host": "giganto-host-7",
                    "target": "giganto",
                    "instance": null,
                    "operationId": OPERATION_ID,
                }
            })
        );

        for failure in [
            Failure::PortAllocationConflict,
            Failure::HostPortOccupied,
            Failure::HostOccupancyUnavailable,
            Failure::RequestKeyReused,
            Failure::Other,
        ] {
            let (deployer, _) = RecordingDeployer::boxed(Answer::Fail(failure));
            let schema = TestSchema::new().await;
            let response = schema
                .execute_as_system_admin_with_data(
                    &core_update_mutation(&core_update_args("review", "control-host")),
                    deployer as BoxedPackageDeployer,
                )
                .await;
            assert_eq!(response.errors.len(), 1);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn onboarding_renders_the_ticket_without_logging_or_debugging_the_token() {
        let (deployer, _) = RecordingDeployer::applying();
        let (onboarder, calls) = RecordingOnboarder::boxed(OnboardAnswer::Succeed);
        let schema = schema_without_store(deployer as BoxedPackageDeployer, onboarder);
        let logs = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .finish();

        let response = {
            let _guard = tracing::subscriber::set_default(subscriber);
            execute_without_store(&schema, &onboard_mutation("new-host")).await
        };

        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_json_eq!(
            response.data.into_json().unwrap(),
            json!({
                "onboardHost": {
                    "operationId": ONBOARD_OPERATION_ID,
                    "token": JOIN_TOKEN,
                    "command": ONBOARD_COMMAND,
                    "expiresAt": "2023-11-14T22:15:23Z",
                }
            })
        );
        assert_eq!(calls.count(), 1);
        assert_eq!(calls.only_host(), "new-host");
        let debug = calls.only_ticket_debug();
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains(JOIN_TOKEN), "{debug}");
        let logs = logs.contents();
        assert!(logs.contains("token issued for new-host"), "{logs}");
        assert!(!logs.contains(JOIN_TOKEN), "{logs}");
        assert!(!logs.contains("<redacted>"), "{logs}");
    }

    #[tokio::test]
    async fn onboarding_errors_are_ordinary_graphql_errors() {
        let (deployer, _) = RecordingDeployer::applying();
        let (onboarder, calls) = RecordingOnboarder::boxed(OnboardAnswer::Fail);
        let schema = schema_without_store(deployer as BoxedPackageDeployer, onboarder);
        let response = execute_without_store(&schema, &onboard_mutation("new-host")).await;

        assert_eq!(response.errors.len(), 1);
        assert_eq!(
            response.errors[0].message,
            "review could not mint a host ticket"
        );
        assert_eq!(calls.count(), 1);
        assert_eq!(calls.only_host(), "new-host");
    }

    #[tokio::test]
    async fn a_role_outside_the_guard_is_rejected_without_a_backend_call() {
        for query in every_mutation("giganto") {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;

            let res = schema
                .execute_with_guard_and_data(
                    &query,
                    RoleGuard::Role(Role::SecurityMonitor),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert_eq!(res.errors.len(), 1, "{query}");
            assert_eq!(calls.total(), 0, "{query}");
        }
    }

    #[tokio::test]
    async fn a_scoped_user_on_a_foreign_host_is_rejected_without_a_backend_call() {
        for query in every_mutation("giganto") {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            super::super::test_support::insert_active_node(
                &schema.store(),
                "giganto_host",
                2,
                "host1",
            );

            let res = schema
                .execute_as_scoped_user_with_data(
                    &query,
                    Role::SecurityAdministrator,
                    Some(vec![1]),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert_eq!(res.errors.len(), 1, "{query}");
            assert_eq!(res.errors[0].message, "Forbidden", "{query}");
            assert_eq!(calls.total(), 0, "{query}");
        }
    }

    /// The other side of the hostname check: without this, a
    /// `check_hostname_access` that refused everyone would still pass the test
    /// above, since the unscoped administrator the rest of them use bypasses
    /// the check.
    #[tokio::test]
    async fn a_scoped_user_whose_customer_owns_the_host_reaches_the_backend() {
        for query in every_mutation("giganto") {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            super::super::test_support::insert_active_node(
                &schema.store(),
                "giganto_host",
                1,
                "host1",
            );

            let res = schema
                .execute_as_scoped_user_with_data(
                    &query,
                    Role::SecurityAdministrator,
                    Some(vec![1]),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert!(res.errors.is_empty(), "{query}: {:?}", res.errors);
            assert_eq!(calls.total(), 1, "{query}");
        }
    }

    #[tokio::test]
    async fn a_target_outside_the_module_class_is_rejected_without_a_backend_call() {
        for target in FOREIGN_TARGETS {
            for query in every_mutation(target) {
                let (deployer, calls) = RecordingDeployer::applying();
                let schema = TestSchema::new().await;

                let res = schema
                    .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
                    .await;

                assert_eq!(res.errors.len(), 1, "{query}");
                assert!(
                    res.errors[0].message.contains(target),
                    "{query}: {}",
                    res.errors[0].message
                );
                assert_eq!(calls.total(), 0, "{query}");
            }
        }
    }

    /// The list reaches review in its submitted order and multiplicity, with a
    /// duplicate listener key intact and every address the value its spelling
    /// parses to.
    #[tokio::test]
    async fn the_bind_addresses_reach_the_backend_unchanged() {
        let (deployer, calls) = RecordingDeployer::applying();
        let schema = TestSchema::new().await;
        let args = format!(
            r#"{}, bindAddrs: [
                {{listenerKey: "publish", addr: "10.0.0.1:38372"}},
                {{listenerKey: "ingest", addr: "127.0.0.1:38370"}},
                {{listenerKey: "ingest", addr: "[0:0:0:0:0:0:0:1]:80"}}
            ]"#,
            install_args("giganto")
        );

        let res = schema
            .execute_as_system_admin_with_data(
                &install_mutation(&args),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let call = calls.only_install();
        assert_eq!(call.host, "host1");
        assert_eq!(call.target, "giganto");
        // The third entry is asserted as the `SocketAddr` the submitted
        // spelling parses to, never as the spelling: `[::1]:80` and
        // `[0:0:0:0:0:0:0:1]:80` are one address and only one can come back
        // out.
        assert_eq!(
            call.bind_addrs,
            Some(vec![
                BackendBindAddrInput {
                    listener_key: "publish".to_string(),
                    addr: "10.0.0.1:38372".parse::<SocketAddr>().unwrap(),
                },
                BackendBindAddrInput {
                    listener_key: "ingest".to_string(),
                    addr: "127.0.0.1:38370".parse::<SocketAddr>().unwrap(),
                },
                BackendBindAddrInput {
                    listener_key: "ingest".to_string(),
                    addr: "[::1]:80".parse::<SocketAddr>().unwrap(),
                },
            ])
        );
    }

    /// Absent means "no listening addresses to set", which is a different
    /// request from an empty list and must not be defaulted into one.
    #[tokio::test]
    async fn an_absent_bind_address_list_reaches_the_backend_as_none() {
        let (deployer, calls) = RecordingDeployer::applying();
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin_with_data(
                &install_mutation(&install_args("giganto")),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(calls.only_install().bind_addrs, None);
    }

    #[tokio::test]
    async fn an_empty_bind_address_list_reaches_the_backend_as_an_empty_list() {
        let (deployer, calls) = RecordingDeployer::applying();
        let schema = TestSchema::new().await;
        let args = format!("{}, bindAddrs: []", install_args("giganto"));

        let res = schema
            .execute_as_system_admin_with_data(
                &install_mutation(&args),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(calls.only_install().bind_addrs, Some(Vec::new()));
    }

    #[tokio::test]
    async fn an_unparseable_bind_address_is_refused_without_a_backend_call() {
        for addr in ["not-an-address", "127.0.0.1", "127.0.0.1:not-a-port"] {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let args = format!(
                r#"{}, bindAddrs: [{{listenerKey: "ingest", addr: "{addr}"}}]"#,
                install_args("giganto")
            );

            let res = schema
                .execute_as_system_admin_with_data(
                    &install_mutation(&args),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert_eq!(res.errors.len(), 1, "{addr}");
            assert_eq!(
                res.errors[0].message,
                format!("parsing the bind address {addr}"),
                "{addr}"
            );
            assert_eq!(calls.total(), 0, "{addr}");
        }
    }

    /// The key crosses byte for byte, and the operation id a first use comes
    /// back with is that same key.
    #[tokio::test]
    async fn the_request_key_is_passed_through_and_is_the_operation_id() {
        let (deployer, calls) = RecordingDeployer::boxed(Answer::Succeed(DeployOutcome::Applied));
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin_with_data(
                &install_mutation(&install_args("giganto")),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(calls.only_install().request_key, REQUEST_KEY);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "installService": {
                    "__typename": "InstallServiceSuccess",
                    "operationId": REQUEST_KEY,
                    "disposition": "APPLIED",
                }
            })
        );
    }

    /// A repeat carrying the same request is a success carrying the first
    /// call's id, not a refusal. This is the double-click case.
    #[tokio::test]
    async fn a_repeated_request_key_answering_with_the_first_id_is_a_success() {
        let (deployer, calls) =
            RecordingDeployer::boxed(Answer::SucceedWith(OPERATION_ID, DeployOutcome::Applied));
        let schema = TestSchema::new().await;
        let query = install_mutation(&install_args("giganto"));

        let first = schema
            .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
            .await;
        let (deployer, _second_calls) =
            RecordingDeployer::boxed(Answer::SucceedWith(OPERATION_ID, DeployOutcome::Applied));
        let second = schema
            .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
            .await;

        assert!(first.errors.is_empty(), "{:?}", first.errors);
        assert!(second.errors.is_empty(), "{:?}", second.errors);
        assert_eq!(calls.only_install().request_key, REQUEST_KEY);
        let expected = json!({
            "installService": {
                "__typename": "InstallServiceSuccess",
                "operationId": OPERATION_ID,
                "disposition": "APPLIED",
            }
        });
        assert_json_eq!(first.data.into_json().unwrap(), expected.clone());
        assert_json_eq!(second.data.into_json().unwrap(), expected);
    }

    /// A repeat carrying a *different* request is the union member, carrying
    /// the key the refusal names rather than the resolver's own argument.
    #[tokio::test]
    async fn a_reused_request_key_is_the_union_member() {
        let (deployer, calls) = RecordingDeployer::boxed(Answer::Fail(Failure::RequestKeyReused));
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin_with_data(
                &install_mutation(&install_args("giganto")),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(calls.total(), 1);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "installService": {
                    "__typename": "RequestKeyReused",
                    "requestKey": REUSED_KEY,
                }
            })
        );
    }

    /// The shape check restates `review-database`'s private `is_uuid_v4`, so
    /// this table walks its five rules.
    #[test]
    fn the_request_key_shape_check_matches_the_ledgers_rule() {
        let accepted = [
            "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e",
            // Each of the four permitted variant nibbles.
            "b0a6f6aa-7f7a-4b7c-8a3f-3f9b1a2c4d5e",
            "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e",
            "b0a6f6aa-7f7a-4b7c-aa3f-3f9b1a2c4d5e",
            "b0a6f6aa-7f7a-4b7c-ba3f-3f9b1a2c4d5e",
            "00000000-0000-4000-8000-000000000000",
            "ffffffff-ffff-4fff-bfff-ffffffffffff",
        ];
        let rejected = [
            // Uppercase hex, which is a second spelling of one UUID.
            "B0A6F6AA-7F7A-4B7C-9A3F-3F9B1A2C4D5E",
            "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5E",
            // The version nibble is not `4`.
            "b0a6f6aa-7f7a-3b7c-9a3f-3f9b1a2c4d5e",
            // The variant nibble is not one of `8`, `9`, `a`, `b`.
            "b0a6f6aa-7f7a-4b7c-ca3f-3f9b1a2c4d5e",
            "b0a6f6aa-7f7a-4b7c-7a3f-3f9b1a2c4d5e",
            // Thirty-five and thirty-seven bytes.
            "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5",
            "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5ee",
            // Thirty-six bytes with no hyphen at all.
            "b0a6f6aa7f7a4b7c9a3f3f9b1a2c4d5e1234",
            // Thirty-six bytes with the hyphens one position early.
            "b0a6f6a-a7f7a-4b7c-9a3f-3f9b1a2c4d5e",
            // A non-hex ASCII character.
            "b0a6f6ag-7f7a-4b7c-9a3f-3f9b1a2c4d5e",
            // A non-ASCII character, which the byte-length rule rejects rather
            // than letting it shift the positions the other rules index.
            "b0a6f6aé-7f7a-4b7c-9a3f-3f9b1a2c4d5e",
            "",
        ];

        for key in accepted {
            assert!(is_uuid_v4(key), "{key}");
        }
        for key in rejected {
            assert!(!is_uuid_v4(key), "{key}");
        }
    }

    /// A present-but-malformed key is refused before any backend call, in the
    /// ledger's own words.
    #[tokio::test]
    async fn a_malformed_request_key_is_refused_without_a_backend_call() {
        for key in [
            "B0A6F6AA-7F7A-4B7C-9A3F-3F9B1A2C4D5E",
            "b0a6f6aa-7f7a-3b7c-9a3f-3f9b1a2c4d5e",
            "b0a6f6aa-7f7a-4b7c-ca3f-3f9b1a2c4d5e",
            "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5",
            "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5ee",
            "b0a6f6aa7f7a4b7c9a3f3f9b1a2c4d5e1234",
            "b0a6f6a-a7f7a-4b7c-9a3f-3f9b1a2c4d5e",
            "b0a6f6ag-7f7a-4b7c-9a3f-3f9b1a2c4d5e",
            "b0a6f6aé-7f7a-4b7c-9a3f-3f9b1a2c4d5e",
            "",
        ] {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let args = format!(
                r#"host: "host1", target: "giganto", buildSelector: {{version: "0.1.0"}}, requestKey: "{key}""#
            );

            let res = schema
                .execute_as_system_admin_with_data(
                    &install_mutation(&args),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert_eq!(res.errors.len(), 1, "{key}");
            assert_eq!(res.errors[0].message, malformed_message(key), "{key}");
            assert_eq!(calls.total(), 0, "{key}");
        }
    }

    /// An omitted or explicitly null key is the schema's own refusal: the
    /// resolver body never runs, so no `RequestKeyError` is constructed.
    #[tokio::test]
    async fn an_omitted_or_null_request_key_is_refused_by_validation() {
        let omitted = r#"host: "host1", target: "giganto", buildSelector: {version: "0.1.0"}"#;
        let null = format!("{omitted}, requestKey: null");
        for args in [omitted.to_string(), null] {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;

            let res = schema
                .execute_as_system_admin_with_data(
                    &install_mutation(&args),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert_eq!(res.errors.len(), 1, "{args}");
            assert!(
                !res.errors[0].message.contains("UUIDv4"),
                "{args}: {}",
                res.errors[0].message
            );
            assert_eq!(calls.total(), 0, "{args}");
        }
    }

    #[tokio::test]
    async fn a_selector_reaches_the_trait_as_its_matching_variant() {
        let cases = [
            (
                r#"{version: "0.1.0"}"#,
                BuildSelector::Version("0.1.0".to_string()),
            ),
            (
                r#"{commit: "0123456789abcdef"}"#,
                BuildSelector::Commit("0123456789abcdef".to_string()),
            ),
        ];

        for (submitted, expected) in cases {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let args = format!(
                r#"host: "host1", target: "giganto", buildSelector: {submitted}, requestKey: "{REQUEST_KEY}""#
            );

            let res = schema
                .execute_as_system_admin_with_data(
                    &install_mutation(&args),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert!(res.errors.is_empty(), "{submitted}: {:?}", res.errors);
            assert_eq!(calls.only_install().selector, expected, "{submitted}");
        }
    }

    #[tokio::test]
    async fn a_selector_setting_both_or_neither_is_refused_without_a_backend_call() {
        for submitted in [r#"{version: "0.1.0", commit: "0123456789abcdef"}"#, "{}"] {
            let install = install_mutation(&format!(
                r#"host: "host1", target: "giganto", buildSelector: {submitted}, requestKey: "{REQUEST_KEY}""#
            ));
            let update = update_mutation(&format!(
                r#"host: "host1", target: "giganto", instance: "3", buildSelector: {submitted}"#
            ));

            for query in [install, update] {
                let (deployer, calls) = RecordingDeployer::applying();
                let schema = TestSchema::new().await;

                let res = schema
                    .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
                    .await;

                assert_eq!(res.errors.len(), 1, "{query}");
                assert!(
                    res.errors[0].message.contains("buildSelector"),
                    "{query}: {}",
                    res.errors[0].message
                );
                assert_eq!(calls.total(), 0, "{query}");
            }
        }
    }

    #[tokio::test]
    async fn an_omitted_on_failure_reaches_the_trait_as_rollback() {
        let (deployer, calls) = RecordingDeployer::applying();
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin_with_data(
                &install_mutation(&install_args("giganto")),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            calls.only_install().on_failure,
            BackendFailurePolicy::Rollback
        );
    }

    #[tokio::test]
    async fn each_failure_policy_reaches_the_trait_as_its_own_variant() {
        for (submitted, expected) in [
            ("ROLLBACK", BackendFailurePolicy::Rollback),
            ("HOLD", BackendFailurePolicy::Hold),
        ] {
            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let args = format!("{}, onFailure: {submitted}", install_args("giganto"));

            let res = schema
                .execute_as_system_admin_with_data(
                    &install_mutation(&args),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert!(res.errors.is_empty(), "{submitted}: {:?}", res.errors);
            assert_eq!(calls.only_install().on_failure, expected, "{submitted}");

            let (deployer, calls) = RecordingDeployer::applying();
            let schema = TestSchema::new().await;
            let args = format!("{}, onFailure: {submitted}", update_args("giganto"));

            let res = schema
                .execute_as_system_admin_with_data(
                    &update_mutation(&args),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert!(res.errors.is_empty(), "{submitted}: {:?}", res.errors);
            assert_eq!(calls.updates()[0].on_failure, expected, "{submitted}");
        }
    }

    /// An `ACCEPTED` disposition says the true outcome is reconciled later, so
    /// it must not be reported as done.
    #[tokio::test]
    async fn an_accepted_apply_renders_as_accepted() {
        for (query, field, success) in [
            (
                install_mutation(&install_args("giganto")),
                "installService",
                "InstallServiceSuccess",
            ),
            (
                update_mutation(&update_args("giganto")),
                "updateService",
                "UpdateServiceSuccess",
            ),
        ] {
            let (deployer, _calls) =
                RecordingDeployer::boxed(Answer::Succeed(DeployOutcome::Accepted));
            let schema = TestSchema::new().await;

            let res = schema
                .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
                .await;

            assert!(res.errors.is_empty(), "{query}: {:?}", res.errors);
            let data = res.data.into_json().unwrap();
            assert_eq!(data[field]["__typename"], success, "{query}");
            assert_eq!(data[field]["disposition"], "ACCEPTED", "{query}");
        }
    }

    #[tokio::test]
    async fn an_update_reaches_the_trait_with_its_instance_and_returns_the_id() {
        let (deployer, calls) = RecordingDeployer::applying();
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin_with_data(
                &update_mutation(&update_args("giganto")),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            calls.updates(),
            vec![UpdateCall {
                host: "host1".to_string(),
                target: "giganto".to_string(),
                instance: Some(3),
                selector: BuildSelector::Version("0.1.0".to_string()),
                on_failure: BackendFailurePolicy::Rollback,
            }]
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "updateService": {
                    "__typename": "UpdateServiceSuccess",
                    "operationId": OPERATION_ID,
                    "disposition": "APPLIED",
                }
            })
        );
    }

    #[tokio::test]
    async fn a_removal_reaches_the_trait_with_its_instance_and_returns_the_id() {
        let (deployer, calls) = RecordingDeployer::applying();
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin_with_data(
                &remove_mutation(&remove_args("giganto")),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            calls.removes(),
            vec![RemoveCall {
                host: "host1".to_string(),
                target: "giganto".to_string(),
                instance: Some(3),
            }]
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "removeService": {
                    "__typename": "RemoveServiceSuccess",
                    "operationId": OPERATION_ID,
                }
            })
        );
    }

    /// The whole point of the `StringNumber` scalar: what `Agent.instance`
    /// renders for a row is accepted verbatim as the argument, with no
    /// conversion in the client, including a value above `i32::MAX`.
    #[tokio::test]
    async fn an_instance_read_from_a_row_round_trips_into_the_mutation() {
        let schema = TestSchema::new().await;
        let node = Node {
            id: u32::MAX,
            name: "node1".to_string(),
            name_draft: Some("node1".to_string()),
            profile: Some(NodeProfile {
                customer_id: 1,
                description: String::new(),
                hostname: "host1".to_string(),
            }),
            profile_draft: None,
            agents: vec![Agent {
                node_id: u32::MAX,
                key: "001.hog".to_string(),
                kind: AgentKind::SemiSupervised,
                status: AgentStatus::Enabled,
                config: None,
                draft: None,
                installed_version: None,
                installed_commit: None,
                lifecycle: Lifecycle::Running,
                bound_addrs: Vec::new(),
                instance: Some(u32::MAX),
            }],
            external_services: Vec::new(),
            creation_time: Utc::now(),
        };
        let id = schema.store().node_map().put(&node).expect("insert node");

        let read = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{id}\") {{ agents {{ instance }} }} }}"
            ))
            .await;
        assert!(
            read.errors.is_empty(),
            "unexpected errors: {:?}",
            read.errors
        );
        let rendered = read.data.into_json().unwrap()["node"]["agents"][0]["instance"]
            .as_str()
            .expect("the instance renders as a string")
            .to_string();
        assert_eq!(rendered, "4294967295");

        let (deployer, calls) = RecordingDeployer::applying();
        let args = format!(
            r#"host: "host1", target: "hog", instance: "{rendered}", buildSelector: {{version: "0.1.0"}}"#
        );

        let res = schema
            .execute_as_system_admin_with_data(
                &update_mutation(&args),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(calls.updates()[0].instance, Some(u32::MAX));
    }

    /// Every field of the variant survives onto the member, and `host` is the
    /// variant's own rather than the resolver's argument.
    #[tokio::test]
    async fn each_install_failure_variant_is_its_like_named_member() {
        let cases = [
            (
                Failure::PortAllocationConflict,
                json!({
                    "__typename": "PortAllocationConflict",
                    "listenerKey": "publish",
                    "host": "giganto-host-7",
                    "transport": "UDP",
                    "port": 65535,
                    "holder": {"component": "giganto", "instance": "3000000000"},
                }),
            ),
            (
                Failure::HostPortOccupied,
                json!({
                    "__typename": "HostPortOccupied",
                    "listenerKey": "ingest",
                    "transport": "TCP",
                    "port": 38371,
                }),
            ),
            (
                Failure::HostOccupancyUnavailable,
                json!({
                    "__typename": "HostOccupancyUnavailable",
                    "host": "giganto-host-7",
                    "reason": "the host did not answer",
                }),
            ),
        ];

        for (failure, expected) in cases {
            let (deployer, calls) = RecordingDeployer::boxed(Answer::Fail(failure));
            let schema = TestSchema::new().await;

            let res = schema
                .execute_as_system_admin_with_data(
                    &install_mutation(&install_args("giganto")),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
            assert_eq!(calls.total(), 1);
            assert_json_eq!(
                res.data.into_json().unwrap()["installService"].clone(),
                expected
            );
        }
    }

    /// `CleanupPending` arrives as its member on all three mutations, fields
    /// unchanged, and its `instance` is null when the refused install never
    /// allocated one.
    #[tokio::test]
    async fn a_pending_cleanup_is_the_union_member_on_every_mutation() {
        for (instance, rendered) in [(Some(7), json!("7")), (None, json!(null))] {
            for (query, field) in [
                (install_mutation(&install_args("giganto")), "installService"),
                (update_mutation(&update_args("giganto")), "updateService"),
                (remove_mutation(&remove_args("giganto")), "removeService"),
            ] {
                let (deployer, calls) =
                    RecordingDeployer::boxed(Answer::Fail(Failure::CleanupPending(instance)));
                let schema = TestSchema::new().await;

                let res = schema
                    .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
                    .await;

                assert!(res.errors.is_empty(), "{query}: {:?}", res.errors);
                assert_eq!(calls.total(), 1, "{query}");
                assert_json_eq!(
                    res.data.into_json().unwrap()[field].clone(),
                    json!({
                        "__typename": "CleanupPending",
                        "host": "giganto-host-7",
                        "target": "giganto",
                        "instance": rendered,
                        "operationId": OPERATION_ID,
                    })
                );
            }
        }
    }

    /// Every variant outside the operation's union is an ordinary GraphQL
    /// error rather than a member.
    #[tokio::test]
    async fn a_variant_outside_the_union_is_an_ordinary_graphql_error() {
        let install_only = [
            Failure::Other,
            Failure::MalformedRequestKey,
            Failure::RequestKeyRead,
        ];
        for failure in install_only {
            let (deployer, calls) = RecordingDeployer::boxed(Answer::Fail(failure));
            let schema = TestSchema::new().await;

            let res = schema
                .execute_as_system_admin_with_data(
                    &install_mutation(&install_args("giganto")),
                    deployer as BoxedPackageDeployer,
                )
                .await;

            assert_eq!(res.errors.len(), 1);
            assert!(res.data.into_json().unwrap().is_null());
            assert_eq!(calls.total(), 1);
        }

        // An update and a removal allocate nothing, so every variant but
        // `CleanupPending` is outside their unions — the two bind-address
        // conflicts and the reuse refusal included.
        let outside = [
            Failure::Other,
            Failure::PortAllocationConflict,
            Failure::HostPortOccupied,
            Failure::HostOccupancyUnavailable,
            Failure::RequestKeyReused,
            Failure::MalformedRequestKey,
            Failure::RequestKeyRead,
        ];
        for failure in outside {
            for query in [
                update_mutation(&update_args("giganto")),
                remove_mutation(&remove_args("giganto")),
            ] {
                let (deployer, calls) = RecordingDeployer::boxed(Answer::Fail(failure));
                let schema = TestSchema::new().await;

                let res = schema
                    .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
                    .await;

                assert_eq!(res.errors.len(), 1, "{query}");
                assert!(res.data.into_json().unwrap().is_null(), "{query}");
                assert_eq!(calls.total(), 1, "{query}");
            }
        }
    }

    #[test]
    fn the_class_binding_answers_from_the_package_id_lists() {
        for target in MODULE_PACKAGE_IDS {
            assert!(
                bind_package_class(target, &MODULE_PACKAGE_IDS).is_ok(),
                "{target}"
            );
            assert!(
                bind_package_class(target, &CORE_PACKAGE_IDS).is_err(),
                "{target}"
            );
        }
        for target in CORE_PACKAGE_IDS {
            assert!(
                bind_package_class(target, &CORE_PACKAGE_IDS).is_ok(),
                "{target}"
            );
            assert!(
                bind_package_class(target, &MODULE_PACKAGE_IDS).is_err(),
                "{target}"
            );
        }
        // `bootroot` is in neither list, so it is refused by both tiers.
        assert!(bind_package_class("bootroot", &MODULE_PACKAGE_IDS).is_err());
        assert!(bind_package_class("bootroot", &CORE_PACKAGE_IDS).is_err());

        let refusal = bind_package_class("roxyd", &MODULE_PACKAGE_IDS)
            .expect_err("a core package-id is outside the module class");
        assert!(refusal.message.contains("roxyd"), "{}", refusal.message);
    }

    #[test]
    fn the_selector_conversion_refuses_both_and_neither() {
        assert_eq!(
            build_selector(BuildSelectorInput {
                version: Some("0.1.0".to_string()),
                commit: None,
            })
            .expect("a version alone is a selector"),
            BuildSelector::Version("0.1.0".to_string())
        );
        assert_eq!(
            build_selector(BuildSelectorInput {
                version: None,
                commit: Some("0123456789abcdef".to_string()),
            })
            .expect("a commit alone is a selector"),
            BuildSelector::Commit("0123456789abcdef".to_string())
        );
        assert!(
            build_selector(BuildSelectorInput {
                version: Some("0.1.0".to_string()),
                commit: Some("0123456789abcdef".to_string()),
            })
            .is_err()
        );
        assert!(
            build_selector(BuildSelectorInput {
                version: None,
                commit: None,
            })
            .is_err()
        );
    }

    /// The deployment and onboarding mutations carry exactly the arguments,
    /// nullability and types their contracts name.
    #[test]
    fn the_mutations_keep_their_signatures() {
        let sdl = rendered_sdl();

        let install = sdl_line(&sdl, "installService(");
        assert_eq!(
            install,
            "installService(host: String!, target: String!, buildSelector: BuildSelectorInput!, \
             onFailure: FailurePolicy! = ROLLBACK, bindAddrs: [BindAddrInput!], \
             requestKey: String!): InstallServiceResult!"
        );
        assert!(!install.contains("instance"), "{install}");

        assert_eq!(
            sdl_line(&sdl, "updateService("),
            "updateService(host: String!, target: String!, instance: StringNumber!, \
             buildSelector: BuildSelectorInput!, onFailure: FailurePolicy! = ROLLBACK): \
             UpdateServiceResult!"
        );
        assert_eq!(
            sdl_line(&sdl, "removeService("),
            "removeService(host: String!, target: String!, instance: StringNumber!): \
             RemoveServiceResult!"
        );
        let core_update = sdl_line(&sdl, "updateCoreComponent(");
        assert_eq!(
            core_update,
            "updateCoreComponent(component: String!, host: String!, buildSelector: \
             BuildSelectorInput!, onFailure: FailurePolicy! = ROLLBACK): \
             UpdateCoreComponentResult!"
        );
        assert!(!core_update.contains("instance"), "{core_update}");
        assert_eq!(
            sdl_line(&sdl, "onboardHost("),
            "onboardHost(host: String!): HostOnboardingTicket!"
        );
    }

    #[test]
    fn each_result_union_has_exactly_its_declared_members() {
        let sdl = rendered_sdl();

        assert_eq!(
            sdl_line(&sdl, "union InstallServiceResult"),
            "union InstallServiceResult = InstallServiceSuccess | PortAllocationConflict | \
             HostPortOccupied | HostOccupancyUnavailable | RequestKeyReused | CleanupPending"
        );
        assert_eq!(
            sdl_line(&sdl, "union UpdateServiceResult"),
            "union UpdateServiceResult = UpdateServiceSuccess | CleanupPending"
        );
        assert_eq!(
            sdl_line(&sdl, "union RemoveServiceResult"),
            "union RemoveServiceResult = RemoveServiceSuccess | CleanupPending"
        );
        assert_eq!(
            sdl_line(&sdl, "union UpdateCoreComponentResult"),
            "union UpdateCoreComponentResult = UpdateCoreComponentSuccess | CleanupPending"
        );
        assert!(!sdl.contains("union HostOnboardingTicket"));
    }

    #[test]
    fn the_host_onboarding_ticket_has_exactly_its_declared_fields() {
        let sdl = rendered_sdl();
        let body = sdl
            .split("type HostOnboardingTicket {")
            .nth(1)
            .expect("the schema declares the ticket")
            .split("\n}")
            .next()
            .expect("the ticket body ends");
        let fields: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|line| line.contains(':'))
            .collect();

        assert_eq!(
            fields,
            vec![
                "operationId: String!",
                "token: String!",
                "command: String!",
                "expiresAt: DateTime!",
            ]
        );
    }

    /// `BindAddrInput` enters the schema here, with the argument that first
    /// makes it reachable, and carries no `transport`.
    #[test]
    fn the_bind_address_input_has_exactly_two_fields() {
        let sdl = rendered_sdl();
        let body = sdl
            .split("input BindAddrInput {")
            .nth(1)
            .expect("the schema declares the input")
            .split("\n}")
            .next()
            .expect("the input body ends");

        // The body is cut at the closing brace, so the last field carries no
        // trailing newline of its own.
        assert!(body.contains("\n\tlistenerKey: String!\n"), "{body}");
        assert!(body.contains("\n\taddr: String!"), "{body}");
        assert!(!body.contains("transport"), "{body}");
    }

    /// The two enums this issue declares carry exactly their two variants.
    #[test]
    fn the_two_enums_carry_exactly_their_variants() {
        let sdl = rendered_sdl();
        for (header, variants) in [
            ("enum FailurePolicy {", ["ROLLBACK", "HOLD"]),
            ("enum DeployDisposition {", ["APPLIED", "ACCEPTED"]),
        ] {
            let body = sdl
                .split(header)
                .nth(1)
                .expect("the schema declares the enum")
                .split("\n}")
                .next()
                .expect("the enum body ends");
            let rendered: Vec<&str> = body
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('"') && !line.starts_with('`'))
                .filter(|line| line.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
                .collect();
            assert_eq!(rendered, variants.to_vec(), "{header}");
        }
    }

    /// The configuration draft-to-apply mutations are untouched: version and
    /// install never ride the draft.
    #[test]
    fn the_draft_mutations_are_unchanged() {
        let sdl = rendered_sdl();
        for declaration in [
            "applyNode(id: ID!, node: NodeInput!): ID!",
            "applyNodeDraft(id: ID!, node: NodeInput!): Node!",
            "updateNodeDraft(id: ID!, old: NodeInput!, new: NodeDraftInput!): ID!",
        ] {
            assert!(sdl.contains(declaration), "{declaration}");
        }
    }
}
