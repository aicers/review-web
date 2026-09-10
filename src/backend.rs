use std::{collections::HashMap, fmt, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use ipnet::IpNet;
// `review_database::Lifecycle` and `review_protocol::types::node::Lifecycle` are
// two distinct types with the same name, so nothing here glob-imports either
// module and neither `Lifecycle` is brought into scope.
use review_database::{BuildSelector, ListenerBinding, ListenerTransport, PortOwner};
use review_protocol::types::node::{BootstrapMaterial, DeliveryMode, FailurePolicy, PackageState};
pub use roxy::{Process, ResourceUsage};

use crate::graphql::customer::NetworksTargetAgentLookupKeysPair;
pub use crate::graphql::{ParsedCertificate, SamplingPolicy};

#[async_trait]
pub trait AgentManager: Send + Sync {
    async fn broadcast_trusted_domains(&self) -> Result<(), anyhow::Error> {
        Err(anyhow!("Not supported"))
    }

    async fn send_agent_specific_internal_networks(
        &self,
        networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error>;

    async fn send_agent_specific_allow_networks(
        &self,
        networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error>;

    async fn send_agent_specific_block_networks(
        &self,
        networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error>;

    async fn broadcast_trusted_user_agent_list(
        &self,
        _list: &[String],
    ) -> Result<(), anyhow::Error> {
        Err(anyhow!("Not supported"))
    }

    /// Returns a list of online applications grouped by host ID.
    ///
    /// The result is a `HashMap` where the key is the hostname and the value is a list of tuples.
    /// Each tuple contains the key of the agent and the name of the application.
    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error>; // (hostname, (agent_key, app_name))

    async fn broadcast_crusher_sampling_policy(
        &self,
        _sampling_policies: &[SamplingPolicy],
    ) -> Result<(), anyhow::Error>;

    /// Returns the list of processes running on the given host.
    async fn get_process_list(&self, _hostname: &str) -> Result<Vec<Process>, anyhow::Error>;

    /// Returns the resource usage of the given host.
    async fn get_resource_usage(&self, _hostname: &str) -> Result<ResourceUsage, anyhow::Error>;

    /// Halts the node with the given hostname.
    async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error>;

    /// Sends a ping message to the given host and waits for a response. Returns
    /// the round-trip time.
    async fn ping(&self, _hostname: &str) -> Result<Duration, anyhow::Error>;

    /// Reboots the node with the given hostname.
    async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error>;

    /// Notifies the agent identified by the runtime lookup key to update its configuration.
    async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error>;

    /// Updates the traffic filter rules for the given host.
    async fn update_traffic_filter_rules(
        &self,
        _host: &str,
        _rules: &[(IpNet, Option<Vec<u16>>, Option<Vec<u16>>)],
    ) -> Result<(), anyhow::Error> {
        Err(anyhow!("Not supported"))
    }
}

pub trait CertManager: Send + Sync {
    /// Returns the certificate path.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate path cannot be determined.
    fn cert_path(&self) -> Result<PathBuf, anyhow::Error>;

    /// Returns the key path.
    ///
    /// # Errors
    ///
    /// Returns an error if the key path cannot be determined.
    fn key_path(&self) -> Result<PathBuf, anyhow::Error>;

    /// Updates the certificate and key.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate and key cannot be updated.
    fn update_certificate(
        &self,
        cert: String,
        key: String,
    ) -> Result<Vec<ParsedCertificate>, anyhow::Error>;
}

/// The canonical package-ids of the module packages.
///
/// A module runs as one or more numbered instances of a host, so every
/// operation on one carries an instance number. The list is declared here and
/// nowhere else: five call sites classify a free-form `target` string by
/// package class, and a second copy of the list would be a second answer to
/// the same question.
///
/// The strings are the canonical package-id registry's literals, the same ones
/// [`review_database::AgentKind::package_id`] and
/// [`review_database::ExternalServiceKind::package_id`] return. This is not a
/// mapping from those enums and must never become one: a `target` here is a
/// free `String` off a GraphQL argument or a ledger row, with no variant set
/// to enumerate.
// The five call sites that classify a target by package class land in sibling
// issues; the list is declared here because it is what they all depend on, and
// the tests below assert its membership.
#[allow(dead_code)]
pub(crate) const MODULE_PACKAGE_IDS: [&str; 5] =
    ["piglet", "giganto", "hog", "reconverge", "crusher"];

/// The canonical package-ids of the core-component packages.
///
/// A core component is single-instance on a host, so an operation on one
/// carries no instance number.
///
/// `bootroot` is a core package and is deliberately absent: it is
/// installer-managed and no operation in this product targets it. Every
/// consumer of these lists treats an unrecognised target as the stricter case,
/// so leaving `bootroot` out gives it the right answer by the stricter route
/// rather than by a listing that invites someone to offer it an action.
// Declared here for the same reason as `MODULE_PACKAGE_IDS`.
#[allow(dead_code)]
pub(crate) const CORE_PACKAGE_IDS: [&str; 3] = ["review", "aice-web-next", "roxyd"];

// Upstream type-surface check for the six local types declared below.
//
// Each of `BuildId`, `OperationId`, `DeployOutcome`, `JoinToken`,
// `HostOnboardingTicket` and `DeployError` is declared here only because
// neither pinned upstream defines it. The surfaces checked, at the exact
// revisions this crate pins in `Cargo.toml`:
//
// - `review-database` at `698254e` — the `pub use` surface of its `lib.rs`,
//   its three public modules `types`, `event` and `backup`, which together
//   are every name this crate can import from it, and behind the re-exports
//   the private `tables::operation_attempt` and `tables::port_allocation`
//   modules that hold the deployment types.
// - `review-protocol` at `32ed9b0` — the `types::node` module, which carries
//   the package (`NodePackageRequest`/`NodePackageResponse`/
//   `NodePackageError`) and enrollment (`NodeEnrollRequest`/
//   `NodeEnrollResponse`/`NodeEnrollError`) surfaces, and the rest of its
//   public surface: the remainder of `types`, including its `capability`
//   submodule and its `structured::ColumnStatistics` re-export, the `lib.rs`
//   re-exports, and the `auth`, `client`, `frame`, `protocol_error`,
//   `request`, `server`, `service_id` and `test` modules, of which
//   `server::node` is the one that also carries node deployment types.
//   Several are feature-gated, so the check read the tree rather than a built
//   rustdoc, which would show only the features that happened to be on.
//
// None of the six names exists anywhere in either tree. What is there instead,
// and why it is not the same type:
//
// - `BuildId` — `review_database::BuildSelector` asks for a build by version
//   *or* commit, so it is a request and not an identity, and this crate
//   already imports it. `review_protocol::types::node::PackageIdentity` pairs
//   `version` and `commit` but adds `target`, making it a package identity
//   rather than a build identity, and it is a wire type. The persisted form
//   upstream keeps is `OperationAttempt::resolved_version` and
//   `resolved_commit`, two independent `String` fields with nothing tying
//   them together.
// - `OperationId` — upstream keys the ledger on
//   `OperationAttempt::idempotency_key`, a bare `String`. There is no newtype
//   over it; `review-database` exports `OperationAction`, `OperationAttempt`,
//   `OperationCleanupState`, `OperationOnFailure`, `OperationOutcome`,
//   `OperationPhase`, `OperationRetentionBound` and `OperationRetryPolicy`,
//   and no `OperationId`.
// - `DeployOutcome` — `review_database::OperationOutcome`, which is
//   `tables::operation_attempt::Outcome` under its re-export name, is the
//   *terminal* result of an apply as persisted (`Succeeded`, `Failed`,
//   `RolledBack`, `Cancelled`). This enum answers a different question —
//   whether the call returned a terminal outcome at all, or only an
//   acknowledgement that a self-disrupting apply owes a later reconciliation
//   — so it is not that type under another name.
// - `JoinToken` and `HostOnboardingTicket` — the nearest upstream surface is
//   `review_protocol::types::node::BootstrapMaterial`, which this crate
//   imports. `NodeEnrollRequest::Register` does cover new-host onboarding as
//   well as a per-service install, but what it returns is the wrapped
//   credential the *enrolling target* consumes to obtain its certificate —
//   `role_id`, `wrapped_secret_id`, `ca_anchor`, `expires_at` — travelling
//   agent-to-registrar. What these two types carry is the other half: the
//   one-time secret an *operator* is handed for a host that cannot yet speak
//   the protocol, and the command they paste on it. No type in either tree
//   models that, and none wraps a secret with the consuming-`expose`,
//   no-`Display`, no-`Clone` discipline `JoinToken` needs:
//   `BootstrapMaterial` derives `Clone` and exposes its secret as a
//   `pub String` field.
// - `DeployError` — upstream carries typed failures, but none of them is this
//   type. `review-database` raises `AddressAllocationError`,
//   `InstanceAllocationError`, `PortAllocationError` and `RequestKeyError`,
//   each scoped to one table's operation; `review-protocol` carries
//   `NodePackageError` and `NodeEnrollError`, which are wire *data* and
//   implement neither `std::error::Error` nor `Display` by design. This enum
//   is the union those leave open at this crate's trait boundary, and it
//   composes them rather than restating them — `RequestKey` is `#[from]`
//   `review_database::RequestKeyError`, and `PortAllocationConflict` carries
//   `review_database::PortOwner` whole.
//
// This is a different finding from the `BindAddrInput` note below, which
// records a type that upstream *does* define — `ListenerBinding` — and that
// this crate deliberately does not use for operator input. It is different
// again from `BuildSelector`, `ListenerBinding`, `ListenerTransport`,
// `PortOwner`, `FailurePolicy`, `DeliveryMode`, `PackageState` and
// `BootstrapMaterial`, which are imported from upstream at the top of this
// file and must stay imports rather than becoming local mirrors.
//
// Re-run this check whenever either pin moves: an upstream that grows one of
// these types makes the local declaration a duplicate rather than a gap.

/// A full build identity: the version and the commit that together name one
/// build.
///
/// Both parts are always present. An absent installed build is expressed by
/// `Option<BuildId>` at the call site, never by an empty or placeholder
/// `version` or `commit` — the rest of the system is required to refuse an
/// empty build identity, and a placeholder is that value arriving somewhere
/// nothing will refuse it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildId {
    /// The version the host reports, an opaque display label that is not
    /// required to be semver.
    pub version: String,
    /// The commit the build was made from.
    pub commit: String,
}

/// The identity of one operation in the attempt ledger.
///
/// It is the `operation_attempt.idempotency_key` the ledger keys on; for an
/// install it is the client's own `request_key`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationId(String);

impl OperationId {
    /// Wraps a ledger idempotency key.
    #[must_use]
    pub fn new(key: String) -> Self {
        Self(key)
    }

    /// Borrows the key for rendering.
    // The resolvers that render an operation id land in sibling issues; the
    // reader is declared here so review can build the type and this crate can
    // read it back, which the tests below exercise in both directions.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Yields the key without copying, for a resolver returning it as an owned
    /// `String!`.
    // Declared here for the same reason as `as_str`.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What became of a deployment operation by the time the call returned.
///
/// This is a disposition and carries no identity: every operation returns its
/// [`OperationId`] paired with whatever else it returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeployOutcome {
    /// The agent finished the apply and reported a terminal outcome.
    Applied,
    /// A self-disrupting apply answered before the swap tore the response
    /// channel down — roxyd's own binary, or `REview` itself — so the true
    /// outcome is reconciled later.
    ///
    /// A resolver must not report this as done.
    Accepted,
}

/// One bind address as it arrives from a GraphQL input list.
///
/// It carries two fields and never a transport, because transport is never
/// operator input: it comes from review's own catalog. That is why this is not
/// [`review_database::ListenerBinding`], which carries all three.
///
/// `listener_key` is not validated here. `addr` is a `SocketAddr`, so a
/// syntactically invalid address fails at parse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindAddrInput {
    /// The name the component knows the listener by.
    pub listener_key: String,
    /// The address the operator submitted for it.
    pub addr: SocketAddr,
}

/// A one-time host-onboarding token.
///
/// [`Debug`] is hand-written and prints `<redacted>`, so a derived `Debug` on
/// an enclosing struct cannot leak the token. There is deliberately no
/// `Display`, `as_str`, `Deref` or `AsRef<str>`: each would make interpolating
/// a live credential into a log line or an error message the path of least
/// resistance. The only reader is the crate-private consuming `expose`.
///
/// It derives neither `Clone` nor `PartialEq`. A derived `PartialEq` on a
/// secret-bearing type is a timing oracle — a token is compared, if at all, in
/// constant time by whoever holds the other copy — and a `Clone` would make
/// the consuming `expose` below a formality, since a call site could leave a
/// copy behind before disclosing.
pub struct JoinToken(String);

impl JoinToken {
    /// Wraps a one-time onboarding token.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self(token)
    }

    /// Consumes the wrapper and yields the secret, for the one GraphQL field
    /// that must carry it to the operator.
    ///
    /// It consumes rather than borrows so that a call site reads as a
    /// deliberate one-time disclosure and cannot leave a copy behind.
    // The one GraphQL field that discloses the token lands in a sibling issue;
    // the reader is declared here with the type, and the tests below exercise
    // it.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn expose(self) -> String {
        self.0
    }
}

impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JoinToken(<redacted>)")
    }
}

/// What an operator pastes on a host being onboarded.
///
/// It carries a [`JoinToken`], so it derives neither `Clone` nor `PartialEq`
/// either; `Debug` is derived and redacts the token through the token's own.
#[derive(Debug)]
pub struct HostOnboardingTicket {
    /// The one-time token, disclosed on its own.
    token: JoinToken,
    /// The command the operator runs on the host, which must not carry the
    /// token. The redaction above reaches the token's own field and nothing
    /// else, so a token interpolated into this string is printed in full by
    /// the derived `Debug`.
    command: String,
    /// The granted absolute deadline the ticket stops being usable at.
    expires_at: jiff::Timestamp,
}

impl HostOnboardingTicket {
    /// Creates a ticket from the token, the command that consumes it and the
    /// deadline it stops being usable at.
    #[must_use]
    pub fn new(token: JoinToken, command: String, expires_at: jiff::Timestamp) -> Self {
        Self {
            token,
            command,
            expires_at,
        }
    }

    /// Consumes the ticket and yields its three parts, so a resolver moves the
    /// token out rather than borrowing around it.
    // Declared here for the same reason as `JoinToken::expose`.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn into_parts(self) -> (JoinToken, String, jiff::Timestamp) {
        (self.token, self.command, self.expires_at)
    }
}

/// Why a deployment operation could not be carried out.
///
/// The five named variants are exactly the failures a resolver renders as a
/// state of the form the operator is looking at, so a resolver decides the
/// result-payload union member by matching on the kind rather than on a
/// message string — an upstream wording change would otherwise silently
/// reclassify a failure. Anything else review reports arrives as
/// [`Other`](DeployError::Other) and is rendered as an ordinary GraphQL error,
/// which is what keeps this enum from growing into a second copy of review's
/// internals.
///
/// Every field is `pub` because [`aicers/review`] constructs the named
/// variants from outside this crate; this crate only matches on them.
///
/// [`aicers/review`]: https://github.com/aicers/review
#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    /// Another instance already holds `(host, transport, port)` in the
    /// allocation table.
    ///
    /// It mirrors
    /// [`review_database::PortAllocationError::PortAllocationConflict`]
    /// field-for-field, and carries [`review_database::PortOwner`] whole
    /// rather than flattened, so the conflict this crate renders and the row
    /// upstream refused describe the same holder by construction.
    #[error("port {port} is allocated to another instance on {host}")]
    PortAllocationConflict {
        /// The host the contended address is bound on.
        host: String,
        /// The transport the contended address is bound on.
        transport: ListenerTransport,
        /// The contended port.
        port: u16,
        /// Who holds it.
        owner: PortOwner,
    },
    /// The port is in use on the host by something the allocation table does
    /// not know about.
    #[error("port {port} on the host is occupied by something unidentifiable")]
    HostPortOccupied {
        /// The listener the port was wanted for.
        listener_key: String,
        /// The transport the port was wanted on.
        transport: ListenerTransport,
        /// The occupied port.
        port: u16,
    },
    /// The host could not be asked what it already has bound.
    #[error("the host's occupancy could not be read")]
    HostOccupancyUnavailable {
        /// The host that could not be read.
        host: String,
        /// Why it could not be read.
        reason: String,
    },
    /// The submitted request key is malformed, or names an attempt that was
    /// submitted with a different request.
    #[error(transparent)]
    RequestKey(#[from] review_database::RequestKeyError),
    /// A teardown is still owed on this target, so a new operation on it
    /// cannot start.
    ///
    /// `instance` is `Option<u32>` because an install that never allocated one
    /// still has a teardown owed against the target.
    #[error("a teardown is still owed on this target")]
    CleanupPending {
        /// The host the teardown is owed on.
        host: String,
        /// The package-id the teardown is owed for.
        target: String,
        /// The instance the teardown is owed for, if one was allocated.
        instance: Option<u32>,
        /// The operation that owes it.
        operation_id: OperationId,
    },
    /// Any other failure, rendered as an ordinary GraphQL error.
    ///
    /// [`review_database::PortAllocationError::Database`] arrives here: it is
    /// not a bind-address conflict.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Installs, updates, removes and reads packages on a host through roxyd.
///
/// The surface is keyed on a **package-id**, not on an agent: it covers
/// agents, external services such as Giganto, and core components alike, all
/// driven through roxyd rather than through the installed thing dialling in to
/// `REview`. That is why it is its own trait rather than more methods on
/// [`AgentManager`].
///
/// No method resolves a [`BuildSelector`]. Only review owns the store index
/// that maps a version to its most-recently accepted commit and a commit to
/// its version.
#[async_trait]
pub trait PackageDeployer: Send + Sync {
    /// Installs `target` on `host` as a newly allocated instance, and returns
    /// how the apply ended paired with the operation's identity.
    ///
    /// `install` and [`update`](PackageDeployer::update) are separate methods
    /// because only this one allocates. It takes no `instance` — that is what
    /// it produces — and it is the only one carrying `bind_addrs` and
    /// `request_key`.
    ///
    /// It takes **no** `bootstrap_material` parameter: the implementation
    /// mints the identity itself, because the mint needs the instance number
    /// this call allocates and the owed teardown must be armed before the
    /// mint, so no caller can produce the material in advance.
    ///
    /// `bind_addrs` is a `Vec` and never a map all the way to this boundary:
    /// the implementation refuses a duplicate listener key at its own
    /// boundary and can only refuse what reaches it, so folding the list into
    /// a map here would turn a refusal into a silent last-wins merge.
    ///
    /// # Errors
    ///
    /// Returns [`DeployError::PortAllocationConflict`] or
    /// [`DeployError::HostPortOccupied`] if a submitted address is already
    /// taken, [`DeployError::HostOccupancyUnavailable`] if the host could not
    /// be asked, [`DeployError::RequestKey`] if `request_key` is malformed or
    /// was reused for a different request, [`DeployError::CleanupPending`] if
    /// a teardown is still owed on the target, and [`DeployError::Other`] for
    /// any other failure.
    async fn install(
        &self,
        host: &str,
        target: &str,
        selector: BuildSelector,
        on_failure: FailurePolicy,
        bind_addrs: Option<Vec<BindAddrInput>>,
        request_key: &str,
    ) -> Result<(DeployOutcome, OperationId), DeployError>;

    /// Updates the build of an existing placement, and returns how the apply
    /// ended paired with the operation's identity.
    ///
    /// `instance` names the placement — `None` for a single-instance core
    /// component, `Some(n)` for one of a module's instances — because a host
    /// may run two instances of one module at once and `(host, target)` alone
    /// is ambiguous.
    ///
    /// # Errors
    ///
    /// Returns [`DeployError::CleanupPending`] if a teardown is still owed on
    /// the target, and [`DeployError::Other`] for any other failure. It
    /// allocates nothing, so it produces no bind-address or request-key
    /// variant.
    async fn update(
        &self,
        host: &str,
        target: &str,
        instance: Option<u32>,
        selector: BuildSelector,
        on_failure: FailurePolicy,
    ) -> Result<(DeployOutcome, OperationId), DeployError>;

    /// Removes an existing placement and returns the operation's identity.
    ///
    /// It returns the id rather than `()` because it has no disposition to
    /// pair one with.
    ///
    /// # Errors
    ///
    /// Returns [`DeployError::CleanupPending`] if a teardown is already owed
    /// on the target, and [`DeployError::Other`] for any other failure.
    async fn remove(
        &self,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> Result<OperationId, DeployError>;

    /// Recommends an address for each listener `target` binds on `host`.
    ///
    /// It takes no `instance` — the instance being recommended for does not
    /// exist yet — and it holds nothing: a hold at read time would strand
    /// addresses behind abandoned screens.
    ///
    /// # Errors
    ///
    /// Returns [`DeployError::PortAllocationConflict`] or
    /// [`DeployError::HostPortOccupied`] if no free address could be offered
    /// for a listener, [`DeployError::HostOccupancyUnavailable`] if the host's
    /// occupancy could not be read, and [`DeployError::Other`] for any other
    /// failure.
    async fn recommend_bind_addrs(
        &self,
        host: &str,
        target: &str,
    ) -> Result<Vec<ListenerBinding>, DeployError>;

    /// Returns the most recent build of `target`, or `None` if the store holds
    /// no build for it.
    ///
    /// It is keyed on the package-id alone, because package identity is
    /// host-agnostic and the store index is per component; a caller asks once
    /// per package-id and reuses the answer across that package's rows.
    ///
    /// # Errors
    ///
    /// Returns an error if the build store could not be read.
    async fn latest_build(&self, target: &str) -> Result<Option<BuildId>, anyhow::Error>;

    /// Returns the install and lifecycle state the host reports for one
    /// placement.
    ///
    /// # Errors
    ///
    /// Returns an error if the host could not be reached or answered
    /// unintelligibly.
    async fn package_status(
        &self,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> Result<PackageState, anyhow::Error>;

    /// Returns the build installed for one placement, or `None` if the host
    /// reports none.
    ///
    /// The `Option` is the point. `None` is an ordinary answer, not a failure:
    /// the identity comes from [`PackageState`], whose `version` and `commit`
    /// are non-optional strings beside a lifecycle that includes
    /// `NotInstalled`, so the wire cannot express "nothing installed" in those
    /// two fields. A method returning a bare [`BuildId`] would leave an
    /// implementation two bad choices — invent an identity out of whatever the
    /// agent put in those strings, or fail a read that did not fail — so the
    /// mapping sits at the seam that owns it.
    ///
    /// A caller must never substitute `""` or `"unknown"` for the absent
    /// identity. An empty version or commit is a value the rest of the system
    /// is required to refuse, and a placeholder is that value arriving where
    /// nothing will refuse it.
    ///
    /// # Errors
    ///
    /// Returns an error if the host could not be reached or answered
    /// unintelligibly. A host that answers "nothing installed" is `Ok(None)`.
    async fn read_version(
        &self,
        host: &str,
        target: &str,
        instance: Option<u32>,
    ) -> Result<Option<BuildId>, anyhow::Error>;

    /// Enrolls a service identity with the registrar and returns the material
    /// a first install needs.
    ///
    /// `service_name` is the component's plain keyword, never a composed
    /// `<target>-<host>` string. There is neither a registration spec nor an
    /// idempotency key, because the caller holds neither the signed package
    /// nor the ledger.
    ///
    /// # Errors
    ///
    /// Returns an error if the registrar refused the enrollment or could not
    /// be reached.
    async fn register(
        &self,
        service_name: &str,
        host: &str,
        instance: Option<u32>,
        mode: DeliveryMode,
    ) -> Result<BootstrapMaterial, anyhow::Error>;

    /// Withdraws a service identity from the registrar.
    ///
    /// # Errors
    ///
    /// Returns an error if the registrar refused the withdrawal or could not
    /// be reached.
    async fn deregister(
        &self,
        service_name: &str,
        host: &str,
        instance: Option<u32>,
    ) -> Result<(), anyhow::Error>;
}

/// Brings a new host under management.
///
/// Onboarding installs nothing, so no [`PackageDeployer`] method represents
/// it. It is still a long-running host-scoped operation an operator starts and
/// then watches, so it yields an operation id like the rest.
#[async_trait]
pub trait HostOnboarder: Send + Sync {
    /// Starts onboarding `host` and returns the ticket an operator pastes on
    /// it, paired with the operation's identity.
    ///
    /// # Errors
    ///
    /// Returns an error if the ticket could not be minted or the operation
    /// could not be recorded.
    async fn onboard_host(
        &self,
        host: &str,
    ) -> Result<(HostOnboardingTicket, OperationId), anyhow::Error>;
}

#[cfg(test)]
mod tests {
    use review_database::{AgentKind, ExternalServiceKind};

    use super::{
        CORE_PACKAGE_IDS, HostOnboardingTicket, JoinToken, MODULE_PACKAGE_IDS, OperationId,
    };

    const TOKEN: &str = "s3cret-join-token";

    #[test]
    fn module_package_ids_are_the_five_modules() {
        assert_eq!(
            MODULE_PACKAGE_IDS,
            ["piglet", "giganto", "hog", "reconverge", "crusher"]
        );
    }

    #[test]
    fn core_package_ids_are_the_three_core_components() {
        assert_eq!(CORE_PACKAGE_IDS, ["review", "aice-web-next", "roxyd"]);
    }

    /// `bootroot` is installer-managed and no operation targets it, so it is in
    /// neither list and every consumer gives it the stricter answer.
    #[test]
    fn bootroot_is_in_neither_list() {
        assert!(!MODULE_PACKAGE_IDS.contains(&"bootroot"));
        assert!(!CORE_PACKAGE_IDS.contains(&"bootroot"));
    }

    #[test]
    fn the_two_lists_are_disjoint() {
        for module in MODULE_PACKAGE_IDS {
            assert!(!CORE_PACKAGE_IDS.contains(&module), "{module}");
        }
    }

    #[test]
    fn operation_id_reads_back_through_both_readers() {
        let key = "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e";
        let id = OperationId::new(key.to_string());
        assert_eq!(id.as_str(), key);
        assert_eq!(id.to_string(), key);
        assert_eq!(id.into_inner(), key);
    }

    #[test]
    fn join_token_reads_back_through_expose() {
        assert_eq!(JoinToken::new(TOKEN.to_string()).expose(), TOKEN);
    }

    #[test]
    fn host_onboarding_ticket_reads_back_through_into_parts() {
        let expires_at = jiff::Timestamp::from_second(1_700_000_000).unwrap();
        let ticket = HostOnboardingTicket::new(
            JoinToken::new(TOKEN.to_string()),
            "roxyd join --token <token>".to_string(),
            expires_at,
        );

        let (token, command, deadline) = ticket.into_parts();
        assert_eq!(token.expose(), TOKEN);
        assert_eq!(command, "roxyd join --token <token>");
        assert_eq!(deadline, expires_at);
    }

    /// A derived `Debug` on an enclosing struct must not be able to print the
    /// token, which is what `JoinToken`'s hand-written `Debug` is for.
    #[test]
    fn debug_of_an_enclosing_struct_redacts_the_token() {
        #[derive(Debug)]
        struct Enclosing {
            token: JoinToken,
            host: String,
        }

        let enclosing = Enclosing {
            token: JoinToken::new(TOKEN.to_string()),
            host: "host1".to_string(),
        };
        let rendered = format!("{enclosing:?}");

        assert!(!rendered.contains(TOKEN), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("host1"), "{rendered}");

        // The redaction is in the rendering only: the value itself is intact.
        let Enclosing { token, host } = enclosing;
        assert_eq!(token.expose(), TOKEN);
        assert_eq!(host, "host1");
    }

    /// Proves the pinned `review-database` revision carries the package-id
    /// accessor, and that this crate reaches it rather than mapping the kinds
    /// to package-ids itself.
    #[test]
    fn the_pinned_revision_carries_the_package_id_accessor() {
        assert_eq!(AgentKind::Sensor.package_id(), Some("piglet"));
        assert_eq!(AgentKind::SemiSupervised.package_id(), Some("hog"));
        assert_eq!(AgentKind::Unsupervised.package_id(), Some("reconverge"));
        assert_eq!(AgentKind::TimeSeriesGenerator.package_id(), Some("crusher"));
        assert_eq!(ExternalServiceKind::DataStore.package_id(), Some("giganto"));
        assert_eq!(ExternalServiceKind::TiContainer.package_id(), None);
    }

    /// Every package-id the accessor can return, other than the `None` the
    /// threat-intelligence container gives, is a module package-id here.
    #[test]
    fn every_kind_package_id_is_a_module_package_id() {
        let from_kinds = [
            AgentKind::Sensor.package_id(),
            AgentKind::SemiSupervised.package_id(),
            AgentKind::Unsupervised.package_id(),
            AgentKind::TimeSeriesGenerator.package_id(),
            ExternalServiceKind::DataStore.package_id(),
        ];
        for package_id in from_kinds.into_iter().flatten() {
            assert!(MODULE_PACKAGE_IDS.contains(&package_id), "{package_id}");
        }
    }
}
