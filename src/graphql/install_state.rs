//! The installed build state a host reports, as the read path renders it.
//!
//! The state itself is a projection of what `review-database` stores on an
//! agent, an external service or a core-component row. Two things are not.
//! Whether a newer build is available needs the store's newest accepted build
//! for the row's package, and that answer is memoized per request by
//! [`LatestBuildMemo`] so that a package installed on fifty hosts costs one
//! lookup rather than fifty. Whether the installed build has been withdrawn
//! needs the active trust generation's answer for that build, memoized per
//! request by [`WithdrawalMemo`] in the same way.

use std::{collections::HashMap, sync::Arc};

use async_graphql::{
    Context, Enum, Request, Result, ServerResult,
    extensions::{Extension, ExtensionContext, ExtensionFactory, NextPrepareRequest},
};
use review_database as database;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OnceCell};
use tracing::warn;

use super::BoxedPackageDeployer;
use crate::backend::BuildId;

/// The install and run state of a build on a host, as the host reports it.
///
/// It mirrors `review_database::Lifecycle` one-for-one, `UNKNOWN` included:
/// the database stores that variant for a state the build reading it does not
/// recognize, and a mirror that dropped it would leave a stored value with no
/// representation.
///
/// It is never intent. A component may be `RUNNING` while the last
/// configuration reload failed, which is what `AgentStatus` records.
#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, PartialEq, Serialize)]
#[graphql(remote = "database::Lifecycle")]
pub enum Lifecycle {
    NotInstalled,
    Installing,
    Running,
    Stopped,
    Failed,
    Removing,
    Unknown,
}

/// Whether a newer build is available for one row, and whether the check that
/// would have said so failed.
///
/// The two never disagree: `check_failed` is only ever `true` beside an
/// `available` of `false`, because a lookup that failed answered nothing to
/// compare against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct UpdateState {
    /// Whether the installed build differs from the store's newest accepted
    /// build for the row's package.
    pub(super) available: bool,
    /// Whether this response's lookup for the row's package failed.
    pub(super) check_failed: bool,
}

impl UpdateState {
    /// The answer for a row nothing was looked up for: a kind that maps to no
    /// package-id, an installer-managed core component, or a package whose
    /// store holds no accepted build.
    ///
    /// Nothing was asked, so nothing failed.
    pub(super) const NOT_CHECKED: Self = Self {
        available: false,
        check_failed: false,
    };
}

/// Whether the installed build of one row has been withdrawn, and whether the
/// check that would have said so failed.
///
/// The two never disagree: `check_failed` is only ever `true` beside a
/// `withdrawn` of `false`, because a check that failed answered nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WithdrawalState {
    /// Whether the trust generation active for this response withdraws the
    /// row's installed build.
    pub(super) withdrawn: bool,
    /// Whether this response's check of the row's installed build failed.
    pub(super) check_failed: bool,
}

impl WithdrawalState {
    /// The answer for a row nothing was checked for: a kind that maps to no
    /// package-id, an installer-managed core component, or a row with no
    /// installed build.
    ///
    /// Nothing was asked, so nothing failed.
    pub(super) const NOT_CHECKED: Self = Self {
        withdrawn: false,
        check_failed: false,
    };
}

/// The install state of one stored row as the wire renders it.
///
/// It is what [`projected_state`] returns, and the only shape the read path
/// builds an entry's install state from: the fields are normalized together
/// there rather than copied one by one, so no caller can forward a half
/// identity or an identity a package does not deploy.
pub(super) struct ProjectedState {
    /// The installed version, present only beside `commit`.
    pub(super) version: Option<String>,
    /// The installed commit, present only beside `version`.
    pub(super) commit: Option<String>,
    /// The stored lifecycle, or `None` for a row whose kind maps to no
    /// package-id.
    pub(super) lifecycle: Option<Lifecycle>,
}

/// Returns the install state to report for a row whose kind maps to
/// `package_id`.
///
/// Two normalizations happen here rather than in each caller's field list,
/// because each is an invariant of the wire contract that a per-field copy
/// would quietly break:
///
/// - A kind that maps to no package-id reports **nothing** installed and a
///   null lifecycle, whatever the record happens to carry. The row is not
///   package-managed, so a stale or malformed identity left on it names no
///   build anyone could act on, and `NOT_INSTALLED` would assert the stronger
///   claim that something *could* be installed here — which would have a
///   client offer an install action for something no package can install.
/// - The identity halves travel together or not at all. They are one build
///   identity and nothing in the store enforces that both are written, so a
///   row carrying one half names no build and reports neither half.
///
/// Neither half is ever defaulted. An empty version or commit is a value the
/// rest of the system is required to refuse, so a placeholder would be that
/// value arriving where nothing will refuse it.
pub(super) fn projected_state(
    package_id: Option<&str>,
    version: Option<&str>,
    commit: Option<&str>,
    lifecycle: database::Lifecycle,
) -> ProjectedState {
    if package_id.is_none() {
        return ProjectedState {
            version: None,
            commit: None,
            lifecycle: None,
        };
    }
    let (version, commit) = paired_identity(version, commit);
    ProjectedState {
        version,
        commit,
        lifecycle: Some(lifecycle.into()),
    }
}

/// Returns the identity halves if both are present, and two `None`s otherwise.
///
/// The core-component path needs this without the package-id question, since
/// its `component` is itself the package-id and its lifecycle is never null.
pub(super) fn paired_identity(
    version: Option<&str>,
    commit: Option<&str>,
) -> (Option<String>, Option<String>) {
    match version.zip(commit) {
        Some((version, commit)) => (Some(version.to_string()), Some(commit.to_string())),
        None => (None, None),
    }
}

/// Returns the installed build identity, or `None` if there is none to compare
/// against the store's newest build.
///
/// The identity is `(version, commit)` together or not at all: a half-identity
/// does not name a build, so a row carrying one half is read as carrying
/// nothing. A `lifecycle` of `NOT_INSTALLED` is the same answer by the other
/// route — the host says nothing is installed — and a `lifecycle` of `None`
/// belongs to a row whose kind maps to no package-id, which is never compared
/// at all.
///
/// Neither half is ever defaulted. An empty version or commit is a value the
/// rest of the system is required to refuse, so a placeholder would be that
/// value arriving where nothing will refuse it.
pub(super) fn installed_identity<'a>(
    version: Option<&'a str>,
    commit: Option<&'a str>,
    lifecycle: Option<Lifecycle>,
) -> Option<(&'a str, &'a str)> {
    if lifecycle == Some(Lifecycle::NotInstalled) {
        None
    } else {
        version.zip(commit)
    }
}

/// Returns whether a newer build is available for one row.
///
/// `package_id` is `None` for a row no package deploys and for a core
/// component excluded from update; both answer [`UpdateState::NOT_CHECKED`]
/// and consult no store. Everything else asks this request's
/// [`LatestBuildMemo`], which asks the deployer at most once per package-id.
///
/// Availability is inequality of identity, never an ordering comparison: an
/// installed version is an opaque display label, so a hotfix that keeps the
/// version and changes the commit is an available update.
///
/// # Errors
///
/// Returns an error if the deployer or the memo is missing from the GraphQL
/// context, which is a wiring fault rather than a failed lookup. A failed
/// lookup is reported in [`UpdateState::check_failed`] instead, so that one
/// unreachable build store cannot null an entry, its list and its node.
pub(super) async fn update_state(
    ctx: &Context<'_>,
    package_id: Option<&str>,
    installed: Option<(&str, &str)>,
) -> Result<UpdateState> {
    let Some(package_id) = package_id else {
        return Ok(UpdateState::NOT_CHECKED);
    };
    let deployer = ctx.data::<BoxedPackageDeployer>()?;
    let memo = ctx.data::<LatestBuildMemo>()?;

    Ok(
        match memo.latest_build(deployer.as_ref(), package_id).await {
            LatestBuild::Failed => UpdateState {
                available: false,
                check_failed: true,
            },
            LatestBuild::Missing => UpdateState::NOT_CHECKED,
            LatestBuild::Found(latest) => UpdateState {
                available: installed.is_some_and(|(version, commit)| {
                    version != latest.version || commit != latest.commit
                }),
                check_failed: false,
            },
        },
    )
}

/// Returns whether the installed build of one row has been withdrawn.
///
/// `package_id` is `None` for a row whose kind maps to no package-id, and
/// `installed` is `None` for a row with no installed build identity; each
/// answers [`WithdrawalState::NOT_CHECKED`] and asks nothing. Everything else
/// asks this request's [`WithdrawalMemo`], which asks the deployer at most once
/// per `(package-id, version, commit)`.
///
/// A core row never passes `None` for `package_id`:
/// `CoreComponent::withdrawal_state` answers
/// [`WithdrawalState::NOT_CHECKED`] for an installer-managed row itself,
/// without calling this helper, and calls it with `Some(&self.component)`
/// for every other core row.
///
/// The check is independent of [`update_state`]: it is made whatever
/// `latest_build` answered, and neither one's failure is reported as the
/// other's.
///
/// # Errors
///
/// Returns an error if the deployer or the memo is missing from the GraphQL
/// context, which is a wiring fault rather than a failed check. A failed check
/// is reported in [`WithdrawalState::check_failed`] instead, so that one
/// unreadable trust tree cannot null an entry, its list and its node.
pub(super) async fn withdrawal_state(
    ctx: &Context<'_>,
    package_id: Option<&str>,
    installed: Option<(&str, &str)>,
) -> Result<WithdrawalState> {
    let Some((package_id, (version, commit))) = package_id.zip(installed) else {
        return Ok(WithdrawalState::NOT_CHECKED);
    };
    let deployer = ctx.data::<BoxedPackageDeployer>()?;
    let memo = ctx.data::<WithdrawalMemo>()?;

    Ok(
        match memo
            .is_withdrawn(deployer.as_ref(), package_id, version, commit)
            .await
        {
            WithdrawalCheck::Answered(withdrawn) => WithdrawalState {
                withdrawn,
                check_failed: false,
            },
            WithdrawalCheck::Failed => WithdrawalState {
                withdrawn: false,
                check_failed: true,
            },
        },
    )
}

/// What this request's lookup for one package-id answered.
#[derive(Clone)]
enum LatestBuild {
    /// The store's newest accepted build for the package.
    Found(BuildId),
    /// The store holds no accepted build for the package.
    Missing,
    /// The lookup failed, so nothing is known about the package here.
    Failed,
}

/// The `latest_build` answers this request has already obtained.
///
/// The memo is request-scoped, installed by [`LatestBuildMemoExtension`]. A
/// cache outliving the request would report a stale newest build to every
/// later query, and what it would go stale against is an upload this same
/// server accepted.
///
/// The map holds one cell per package-id and the map lock is released before
/// the lookup runs. The cell is what makes two rows of one package share a
/// single call — the second waits on the first rather than repeating it —
/// while a package whose store is slow or unreachable delays only its own
/// rows. Holding the map lock across the lookup instead would serialize every
/// distinct package behind that one, which is the opposite of the promise
/// that a failing package leaves the rows that read fine alone.
#[derive(Default)]
pub(super) struct LatestBuildMemo {
    answers: Mutex<HashMap<String, Arc<OnceCell<LatestBuild>>>>,
}

impl LatestBuildMemo {
    /// Returns the newest accepted build of `package_id`, asking the deployer
    /// only if this request has not asked already.
    ///
    /// A failure is recorded like any other answer, so that a package whose
    /// store cannot be read is reported as unchecked on every one of its rows
    /// and is asked about once. It is logged once per package-id per request
    /// as an operator breadcrumb; the log is not the signal, the
    /// `updateCheckFailed` field is.
    async fn latest_build(
        &self,
        deployer: &dyn crate::backend::PackageDeployer,
        package_id: &str,
    ) -> LatestBuild {
        let answer = {
            let mut answers = self.answers.lock().await;
            Arc::clone(answers.entry(package_id.to_string()).or_default())
        };
        answer
            .get_or_init(|| async {
                match deployer.latest_build(package_id).await {
                    Ok(Some(build)) => LatestBuild::Found(build),
                    Ok(None) => LatestBuild::Missing,
                    Err(e) => {
                        warn!("cannot read the latest build of package {package_id}: {e:#}");
                        LatestBuild::Failed
                    }
                }
            })
            .await
            .clone()
    }
}

/// What this request's check of one build answered.
#[derive(Clone, Copy)]
enum WithdrawalCheck {
    /// Whether the active trust generation withdraws the build.
    Answered(bool),
    /// The check failed, so nothing is known about the build here.
    Failed,
}

/// The key a [`WithdrawalMemo`] answers under: package-id, version and commit.
type WithdrawalKey = (String, String, String);

/// The `is_build_withdrawn` answers this request has already obtained.
///
/// It is request-scoped for the same reason [`LatestBuildMemo`] is, and more
/// so: a withdrawal takes effect when a trust generation is activated, and a
/// cache outliving the request would keep reporting a build as not withdrawn
/// after one that withdraws it.
///
/// The map holds one cell per `(package-id, version, commit)` and its lock is
/// released before the check runs, so that rows of one build share a single
/// call while a build whose check is slow delays only its own rows.
#[derive(Default)]
pub(super) struct WithdrawalMemo {
    answers: Mutex<HashMap<WithdrawalKey, Arc<OnceCell<WithdrawalCheck>>>>,
}

impl WithdrawalMemo {
    /// Returns whether `version` and `commit` of `package_id` are withdrawn,
    /// asking the deployer only if this request has not asked already.
    ///
    /// A failure is recorded like any other answer and logged once per build
    /// per request as an operator breadcrumb; the log is not the signal, the
    /// `withdrawalCheckFailed` field is.
    async fn is_withdrawn(
        &self,
        deployer: &dyn crate::backend::PackageDeployer,
        package_id: &str,
        version: &str,
        commit: &str,
    ) -> WithdrawalCheck {
        let answer = {
            let mut answers = self.answers.lock().await;
            Arc::clone(
                answers
                    .entry((
                        package_id.to_string(),
                        version.to_string(),
                        commit.to_string(),
                    ))
                    .or_default(),
            )
        };
        *answer
            .get_or_init(|| async {
                let build = BuildId {
                    version: version.to_string(),
                    commit: commit.to_string(),
                };
                match deployer.is_build_withdrawn(package_id, &build).await {
                    Ok(withdrawn) => WithdrawalCheck::Answered(withdrawn),
                    Err(e) => {
                        warn!(
                            "cannot check whether build {version} ({commit}) of package \
                             {package_id} is withdrawn: {e:#}"
                        );
                        WithdrawalCheck::Failed
                    }
                }
            })
            .await
    }
}

/// Gives every request a [`LatestBuildMemo`] and a [`WithdrawalMemo`] of its
/// own.
///
/// The memos have to be per request and the schema is built once, so they are
/// put in the request's data as the request is prepared rather than in the
/// schema's. One extension installs both, so that the schema registers one.
pub(super) struct LatestBuildMemoExtension;

impl ExtensionFactory for LatestBuildMemoExtension {
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(LatestBuildMemoExtension)
    }
}

#[async_trait::async_trait]
impl Extension for LatestBuildMemoExtension {
    async fn prepare_request(
        &self,
        ctx: &ExtensionContext<'_>,
        request: Request,
        next: NextPrepareRequest<'_>,
    ) -> ServerResult<Request> {
        Ok(next
            .run(ctx, request)
            .await?
            .data(LatestBuildMemo::default())
            .data(WithdrawalMemo::default()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex, OnceLock, RwLock},
    };

    use assert_json_diff::assert_json_eq;
    use chrono::Utc;
    use review_database::{
        Agent, AgentKind, AgentStatus, CoreComponent, ExternalService, ExternalServiceKind,
        ExternalServiceStatus, Lifecycle, Node, NodeProfile, Role, Store,
    };
    use serde_json::json;
    use tokio::sync::Notify;

    use super::{
        LatestBuild, LatestBuildMemo, Lifecycle as GqlLifecycle, WithdrawalCheck, WithdrawalMemo,
        installed_identity, projected_state,
    };
    use crate::{
        backend::CertManager,
        graphql::{
            BoxedPackageDeployer, LatestBuildStub, MockAgentManager, MockHostOnboarder,
            MockPackageDeployer, ParsedCertificate, RoleGuard, TestSchema, WithdrawalStub,
        },
    };

    /// The withdrawal pair, selected on its own so the whole-entry assertions
    /// above it stay about the fields they were written for.
    const WITHDRAWAL_FIELDS: &str = "installedBuildWithdrawn withdrawalCheckFailed";

    /// The install-state fields of an agent entry.
    const AGENT_FIELDS: &str = "key instance installedVersion installedCommit lifecycle \
                                updateAvailable updateCheckFailed";

    /// The install-state fields of an external-service entry.
    const EXTERNAL_SERVICE_FIELDS: &str = "key instance installedVersion installedCommit lifecycle updateAvailable \
         updateCheckFailed boundAddrs { key addr }";

    /// The fields of a core-component row.
    const CORE_COMPONENT_FIELDS: &str = "component host installedVersion installedCommit \
                                         lifecycle updateAvailable updateCheckFailed \
                                         installerManaged";

    fn agent(
        key: &str,
        kind: AgentKind,
        instance: Option<u32>,
        installed: Option<(&str, &str)>,
        lifecycle: Lifecycle,
    ) -> Agent {
        Agent {
            node_id: u32::MAX,
            key: key.to_string(),
            kind,
            status: AgentStatus::Enabled,
            config: None,
            draft: None,
            installed_version: installed.map(|(version, _)| version.to_string()),
            installed_commit: installed.map(|(_, commit)| commit.to_string()),
            lifecycle,
            bound_addrs: Vec::new(),
            instance,
        }
    }

    fn external_service(
        key: &str,
        kind: ExternalServiceKind,
        instance: Option<u32>,
        installed: Option<(&str, &str)>,
        lifecycle: Lifecycle,
        bound_addrs: &[(&str, &str)],
    ) -> ExternalService {
        ExternalService {
            node_id: u32::MAX,
            key: key.to_string(),
            kind,
            status: ExternalServiceStatus::Enabled,
            draft: None,
            installed_version: installed.map(|(version, _)| version.to_string()),
            installed_commit: installed.map(|(_, commit)| commit.to_string()),
            lifecycle,
            bound_addrs: bound_addrs
                .iter()
                .map(|(key, addr)| ((*key).to_string(), (*addr).to_string()))
                .collect(),
            instance,
        }
    }

    fn insert_node(
        store: &Store,
        name: &str,
        agents: Vec<Agent>,
        external_services: Vec<ExternalService>,
    ) -> u32 {
        let node = Node {
            id: u32::MAX,
            name: name.to_string(),
            name_draft: Some(name.to_string()),
            profile: Some(NodeProfile {
                customer_id: 0,
                description: String::new(),
                hostname: format!("{name}.example.com"),
            }),
            profile_draft: None,
            agents,
            external_services,
            creation_time: Utc::now(),
        };
        store.node_map().put(&node).expect("insert node")
    }

    fn insert_core_component(
        store: &Store,
        component: &str,
        host: &str,
        installed: Option<(&str, &str)>,
        lifecycle: Lifecycle,
        installer_managed: bool,
    ) {
        let row = CoreComponent {
            component: component.to_string(),
            host: host.to_string(),
            installed_version: installed.map(|(version, _)| version.to_string()),
            installed_commit: installed.map(|(_, commit)| commit.to_string()),
            lifecycle,
            installer_managed,
        };
        store
            .core_component_map()
            .insert(&row)
            .expect("insert core component");
    }

    async fn schema_with(builds: &Arc<LatestBuildStub>) -> TestSchema {
        let deployer: BoxedPackageDeployer =
            Box::new(MockPackageDeployer::with_builds(builds.clone()));
        TestSchema::new_with_package_deployer(deployer).await
    }

    async fn schema_with_withdrawals(
        builds: &Arc<LatestBuildStub>,
        withdrawals: &Arc<WithdrawalStub>,
    ) -> TestSchema {
        let deployer: BoxedPackageDeployer = Box::new(
            MockPackageDeployer::with_builds(builds.clone()).with_withdrawals(withdrawals.clone()),
        );
        TestSchema::new_with_package_deployer(deployer).await
    }

    /// Reads the withdrawal pair of every row of all five types: the keyed
    /// node types through `node`, the snapshots through `nodeStatusList`, and
    /// the core components through `coreComponentList`.
    fn every_type_query(id: u32) -> String {
        format!(
            "{{ node(id: \"{id}\") {{ agents {{ {WITHDRAWAL_FIELDS} }} \
             externalServices {{ {WITHDRAWAL_FIELDS} }} }} \
             nodeStatusList(first: 10) {{ nodes {{ agents {{ {WITHDRAWAL_FIELDS} }} \
             externalServices {{ {WITHDRAWAL_FIELDS} }} }} }} \
             coreComponentList {{ {WITHDRAWAL_FIELDS} }} }}"
        )
    }

    /// Returns the rows of each of the five types in an [`every_type_query`]
    /// response, named after the type, for a store holding one node.
    fn rows_by_type(data: &serde_json::Value) -> Vec<(&'static str, Vec<serde_json::Value>)> {
        let rows = |value: &serde_json::Value| {
            value.as_array().expect("the rows render as a list").clone()
        };
        let snapshot = &data["nodeStatusList"]["nodes"][0];
        vec![
            ("Agent", rows(&data["node"]["agents"])),
            ("ExternalService", rows(&data["node"]["externalServices"])),
            ("AgentSnapshot", rows(&snapshot["agents"])),
            (
                "ExternalServiceSnapshot",
                rows(&snapshot["externalServices"]),
            ),
            ("CoreComponent", rows(&data["coreComponentList"])),
        ]
    }

    fn agents_query(id: u32) -> String {
        format!("{{ node(id: \"{id}\") {{ agents {{ {AGENT_FIELDS} }} }} }}")
    }

    fn external_services_query(id: u32) -> String {
        format!("{{ node(id: \"{id}\") {{ externalServices {{ {EXTERNAL_SERVICE_FIELDS} }} }} }}")
    }

    #[test]
    fn installed_identity_needs_both_halves() {
        assert_eq!(
            installed_identity(Some("1.0.0"), Some("abc"), Some(GqlLifecycle::Running)),
            Some(("1.0.0", "abc"))
        );
        assert_eq!(
            installed_identity(Some("1.0.0"), None, Some(GqlLifecycle::Running)),
            None
        );
        assert_eq!(
            installed_identity(None, Some("abc"), Some(GqlLifecycle::Running)),
            None
        );
        assert_eq!(
            installed_identity(Some("1.0.0"), Some("abc"), Some(GqlLifecycle::NotInstalled)),
            None
        );
    }

    #[test]
    fn the_projection_normalizes_both_absences() {
        let no_package = projected_state(None, Some("1.0.0"), Some("abc"), Lifecycle::Running);
        assert_eq!(no_package.version, None);
        assert_eq!(no_package.commit, None);
        assert_eq!(no_package.lifecycle, None);

        let half = projected_state(Some("hog"), Some("1.0.0"), None, Lifecycle::Running);
        assert_eq!(half.version, None);
        assert_eq!(half.commit, None);
        assert_eq!(half.lifecycle, Some(GqlLifecycle::Running));

        let other_half = projected_state(Some("hog"), None, Some("abc"), Lifecycle::Running);
        assert_eq!(other_half.version, None);
        assert_eq!(other_half.commit, None);

        let whole = projected_state(Some("hog"), Some("1.0.0"), Some("abc"), Lifecycle::Running);
        assert_eq!(whole.version.as_deref(), Some("1.0.0"));
        assert_eq!(whole.commit.as_deref(), Some("abc"));
        assert_eq!(whole.lifecycle, Some(GqlLifecycle::Running));
    }

    /// One package's lookup does not hold up another's.
    ///
    /// The memo makes rows of one package share a call, and the way it does
    /// that must not turn into a queue across packages: a store that is slow
    /// or unreachable for one package would then delay every other package in
    /// the same response, which is the opposite of the promise that a failing
    /// lookup leaves the rows that read fine alone. The gate holds `hog` open
    /// until `giganto` has answered, so a memo that serialized the two would
    /// never finish.
    #[tokio::test]
    async fn one_package_lookup_does_not_block_another() {
        let gate = Arc::new(Notify::new());
        let builds = Arc::new(
            LatestBuildStub::default()
                .with_answer("hog", "1.2.0", "abcabc")
                .with_answer("giganto", "2.0.0", "defdef")
                .with_gate("hog", gate.clone()),
        );
        let deployer = MockPackageDeployer::with_builds(builds.clone());
        let memo = LatestBuildMemo::default();

        let resolved = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(memo.latest_build(&deployer, "hog"), async {
                let answer = memo.latest_build(&deployer, "giganto").await;
                gate.notify_one();
                answer
            })
        })
        .await
        .expect("a lookup of one package does not wait on another");

        assert!(matches!(resolved.0, LatestBuild::Found(build) if build.version == "1.2.0"));
        assert!(matches!(resolved.1, LatestBuild::Found(build) if build.version == "2.0.0"));
    }

    /// Two rows of one package share a single lookup even when they resolve
    /// together, rather than both missing an answer that has not landed yet.
    #[tokio::test]
    async fn concurrent_rows_of_one_package_share_one_lookup() {
        let gate = Arc::new(Notify::new());
        let builds = Arc::new(
            LatestBuildStub::default()
                .with_answer("hog", "1.2.0", "abcabc")
                .with_gate("hog", gate.clone()),
        );
        let deployer = MockPackageDeployer::with_builds(builds.clone());
        let memo = LatestBuildMemo::default();

        let resolved = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(memo.latest_build(&deployer, "hog"), async {
                gate.notify_one();
                memo.latest_build(&deployer, "hog").await
            })
        })
        .await
        .expect("the second row waits on the first rather than deadlocking");

        assert!(matches!(resolved.0, LatestBuild::Found(_)));
        assert!(matches!(resolved.1, LatestBuild::Found(_)));
        assert_eq!(builds.calls("hog"), 1);
    }

    /// One build's check does not hold up another's, for the same reason one
    /// package's lookup does not: the gate holds the first build open until
    /// the second has answered, so a memo that serialized the two would never
    /// finish.
    #[tokio::test]
    async fn one_build_check_does_not_block_another() {
        let gate = Arc::new(Notify::new());
        let withdrawals = Arc::new(
            WithdrawalStub::default()
                .with_withdrawn("hog", "1.0.0", "aaaaaa")
                .with_gate("hog", "1.0.0", "aaaaaa", gate.clone()),
        );
        let deployer = MockPackageDeployer::default().with_withdrawals(withdrawals.clone());
        let memo = WithdrawalMemo::default();

        let resolved = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(
                memo.is_withdrawn(&deployer, "hog", "1.0.0", "aaaaaa"),
                async {
                    let answer = memo.is_withdrawn(&deployer, "hog", "1.1.0", "bbbbbb").await;
                    gate.notify_one();
                    answer
                }
            )
        })
        .await
        .expect("a check of one build does not wait on another");

        assert!(matches!(resolved.0, WithdrawalCheck::Answered(true)));
        assert!(matches!(resolved.1, WithdrawalCheck::Answered(false)));
    }

    /// Two rows of one build share a single check even when they resolve
    /// together, rather than both missing an answer that has not landed yet.
    #[tokio::test]
    async fn concurrent_rows_of_one_build_share_one_check() {
        let gate = Arc::new(Notify::new());
        let withdrawals = Arc::new(
            WithdrawalStub::default()
                .with_withdrawn("hog", "1.0.0", "aaaaaa")
                .with_gate("hog", "1.0.0", "aaaaaa", gate.clone()),
        );
        let deployer = MockPackageDeployer::default().with_withdrawals(withdrawals.clone());
        let memo = WithdrawalMemo::default();

        let resolved = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(
                memo.is_withdrawn(&deployer, "hog", "1.0.0", "aaaaaa"),
                async {
                    gate.notify_one();
                    memo.is_withdrawn(&deployer, "hog", "1.0.0", "aaaaaa").await
                }
            )
        })
        .await
        .expect("the second row waits on the first rather than deadlocking");

        assert!(matches!(resolved.0, WithdrawalCheck::Answered(true)));
        assert!(matches!(resolved.1, WithdrawalCheck::Answered(true)));
        assert_eq!(withdrawals.calls("hog", "1.0.0", "aaaaaa"), 1);
    }

    #[tokio::test]
    async fn install_state_comes_back_on_the_node_read_path() {
        let builds = Arc::new(
            LatestBuildStub::default()
                .with_answer("hog", "1.2.0", "abcabc")
                .with_answer("giganto", "2.0.0", "defdef"),
        );
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![agent(
                "001.hog",
                AgentKind::SemiSupervised,
                Some(1),
                Some(("1.2.0", "abcabc")),
                Lifecycle::Running,
            )],
            vec![external_service(
                "001.giganto",
                ExternalServiceKind::DataStore,
                Some(2),
                Some(("1.9.0", "cccccc")),
                Lifecycle::Running,
                &[("ingest", "10.0.0.1:38370"), ("publish", "10.0.0.1:38371")],
            )],
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{id}\") {{ agents {{ {AGENT_FIELDS} }} \
                 externalServices {{ {EXTERNAL_SERVICE_FIELDS} }} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "node": {
                    "agents": [{
                        "key": "001.hog",
                        "instance": "1",
                        "installedVersion": "1.2.0",
                        "installedCommit": "abcabc",
                        "lifecycle": "RUNNING",
                        "updateAvailable": false,
                        "updateCheckFailed": false,
                    }],
                    "externalServices": [{
                        "key": "001.giganto",
                        "instance": "2",
                        "installedVersion": "1.9.0",
                        "installedCommit": "cccccc",
                        "lifecycle": "RUNNING",
                        "updateAvailable": true,
                        "updateCheckFailed": false,
                        "boundAddrs": [
                            {"key": "ingest", "addr": "10.0.0.1:38370"},
                            {"key": "publish", "addr": "10.0.0.1:38371"},
                        ],
                    }],
                }
            })
        );
    }

    #[tokio::test]
    async fn the_node_list_carries_the_state_and_shares_one_lookup() {
        let builds = Arc::new(LatestBuildStub::default().with_answer("hog", "1.2.0", "abcabc"));
        let schema = schema_with(&builds).await;
        for name in ["node1", "node2"] {
            insert_node(
                &schema.store(),
                name,
                vec![agent(
                    "001.hog",
                    AgentKind::SemiSupervised,
                    Some(1),
                    Some(("1.1.0", "yyyyyy")),
                    Lifecycle::Running,
                )],
                vec![],
            );
        }

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ nodeList {{ edges {{ node {{ agents {{ {AGENT_FIELDS} }} }} }} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let edges = res.data.into_json().unwrap()["nodeList"]["edges"].clone();
        let edges = edges.as_array().expect("the nodes render as a list");
        assert_eq!(edges.len(), 2);
        for edge in edges {
            assert_json_eq!(
                edge["node"]["agents"][0].clone(),
                json!({
                    "key": "001.hog",
                    "instance": "1",
                    "installedVersion": "1.1.0",
                    "installedCommit": "yyyyyy",
                    "lifecycle": "RUNNING",
                    "updateAvailable": true,
                    "updateCheckFailed": false,
                })
            );
        }
        assert_eq!(
            builds.calls("hog"),
            1,
            "the memo spans the whole request, not one node's entries"
        );
    }

    #[tokio::test]
    async fn two_instances_of_one_module_keep_their_own_numbers() {
        let builds = Arc::new(LatestBuildStub::default());
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![
                agent(
                    "001.hog",
                    AgentKind::SemiSupervised,
                    Some(1),
                    Some(("1.0.0", "aaaaaa")),
                    Lifecycle::Running,
                ),
                agent(
                    "002.hog",
                    AgentKind::SemiSupervised,
                    Some(2),
                    Some(("1.0.0", "aaaaaa")),
                    Lifecycle::Running,
                ),
            ],
            vec![],
        );

        let res = schema.execute_as_system_admin(&agents_query(id)).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let agents = res.data.into_json().unwrap()["node"]["agents"].clone();
        assert_eq!(agents.as_array().map(Vec::len), Some(2));
        assert_eq!(agents[0]["key"], json!("001.hog"));
        assert_eq!(agents[0]["instance"], json!("1"));
        assert_eq!(agents[1]["key"], json!("002.hog"));
        assert_eq!(agents[1]["instance"], json!("2"));
    }

    #[tokio::test]
    async fn instance_carries_the_whole_u32_range() {
        let builds = Arc::new(LatestBuildStub::default());
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![
                agent(
                    "001.hog",
                    AgentKind::SemiSupervised,
                    Some(u32::MAX),
                    None,
                    Lifecycle::NotInstalled,
                ),
                agent(
                    "002.hog",
                    AgentKind::SemiSupervised,
                    None,
                    None,
                    Lifecycle::NotInstalled,
                ),
            ],
            vec![],
        );

        let res = schema.execute_as_system_admin(&agents_query(id)).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let agents = res.data.into_json().unwrap()["node"]["agents"].clone();
        assert_eq!(agents[0]["instance"], json!("4294967295"));
        assert_eq!(agents[1]["instance"], json!(null));
    }

    #[tokio::test]
    async fn update_available_compares_build_identity() {
        let builds = Arc::new(LatestBuildStub::default().with_answer("hog", "1.2.0", "abcabc"));
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![
                agent(
                    "001.hog",
                    AgentKind::SemiSupervised,
                    Some(1),
                    Some(("1.2.0", "abcabc")),
                    Lifecycle::Running,
                ),
                agent(
                    "002.hog",
                    AgentKind::SemiSupervised,
                    Some(2),
                    Some(("1.2.0", "zzzzzz")),
                    Lifecycle::Running,
                ),
                agent(
                    "003.hog",
                    AgentKind::SemiSupervised,
                    Some(3),
                    Some(("1.1.0", "yyyyyy")),
                    Lifecycle::Running,
                ),
                agent(
                    "004.hog",
                    AgentKind::SemiSupervised,
                    Some(4),
                    None,
                    Lifecycle::NotInstalled,
                ),
            ],
            vec![],
        );

        let res = schema.execute_as_system_admin(&agents_query(id)).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let agents = res.data.into_json().unwrap()["node"]["agents"].clone();
        // Identical identity.
        assert_eq!(agents[0]["updateAvailable"], json!(false));
        // A hotfix: the same version, a different commit.
        assert_eq!(agents[1]["updateAvailable"], json!(true));
        // A different version.
        assert_eq!(agents[2]["updateAvailable"], json!(true));
        // Nothing installed is not an available update.
        assert_eq!(agents[3]["updateAvailable"], json!(false));
        assert!(
            agents
                .as_array()
                .expect("the entries render as a list")
                .iter()
                .all(|entry| entry["updateCheckFailed"] == json!(false))
        );
        assert_eq!(
            builds.calls("hog"),
            1,
            "one package-id is looked up once however many rows carry it"
        );
    }

    #[tokio::test]
    async fn a_package_with_no_accepted_build_is_up_to_date() {
        let builds = Arc::new(LatestBuildStub::default());
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![agent(
                "001.hog",
                AgentKind::SemiSupervised,
                Some(1),
                Some(("1.0.0", "aaaaaa")),
                Lifecycle::Running,
            )],
            vec![],
        );

        let res = schema.execute_as_system_admin(&agents_query(id)).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let agents = res.data.into_json().unwrap()["node"]["agents"].clone();
        assert_eq!(agents[0]["updateAvailable"], json!(false));
        assert_eq!(agents[0]["updateCheckFailed"], json!(false));
        assert_eq!(builds.calls("hog"), 1);
    }

    #[tokio::test]
    async fn an_unknown_lifecycle_resolves_rather_than_erroring() {
        let builds = Arc::new(LatestBuildStub::default());
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![agent(
                "001.hog",
                AgentKind::SemiSupervised,
                Some(1),
                Some(("1.0.0", "aaaaaa")),
                Lifecycle::Unknown,
            )],
            vec![],
        );

        let res = schema.execute_as_system_admin(&agents_query(id)).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap()["node"]["agents"][0]["lifecycle"],
            json!("UNKNOWN")
        );
    }

    #[tokio::test]
    async fn a_kind_with_no_package_reports_a_null_lifecycle() {
        let builds = Arc::new(LatestBuildStub::default().with_answer("giganto", "2.0.0", "defdef"));
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![],
            vec![external_service(
                "001.ti-container",
                ExternalServiceKind::TiContainer,
                None,
                None,
                Lifecycle::NotInstalled,
                &[],
            )],
        );

        let res = schema
            .execute_as_system_admin(&external_services_query(id))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_json_eq!(
            res.data.into_json().unwrap()["node"]["externalServices"][0].clone(),
            json!({
                "key": "001.ti-container",
                "instance": null,
                "installedVersion": null,
                "installedCommit": null,
                "lifecycle": null,
                "updateAvailable": false,
                "updateCheckFailed": false,
                "boundAddrs": [],
            })
        );
        assert_eq!(
            builds.total_calls(),
            0,
            "a kind with no package-id consults no store"
        );
    }

    #[tokio::test]
    async fn a_null_lifecycle_marks_exactly_the_kinds_with_no_package() {
        let builds = Arc::new(LatestBuildStub::default());
        let schema = schema_with(&builds).await;
        let agent_kinds = [
            AgentKind::Unsupervised,
            AgentKind::Sensor,
            AgentKind::SemiSupervised,
            AgentKind::TimeSeriesGenerator,
        ];
        let service_kinds = [
            ExternalServiceKind::DataStore,
            ExternalServiceKind::TiContainer,
        ];
        let id = insert_node(
            &schema.store(),
            "node1",
            agent_kinds
                .iter()
                .enumerate()
                .map(|(i, &kind)| {
                    agent(
                        &format!("agent{i}"),
                        kind,
                        None,
                        None,
                        Lifecycle::NotInstalled,
                    )
                })
                .collect(),
            service_kinds
                .iter()
                .enumerate()
                .map(|(i, &kind)| {
                    external_service(
                        &format!("service{i}"),
                        kind,
                        None,
                        None,
                        Lifecycle::NotInstalled,
                        &[],
                    )
                })
                .collect(),
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{id}\") {{ agents {{ {AGENT_FIELDS} }} \
                 externalServices {{ {EXTERNAL_SERVICE_FIELDS} }} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let node = res.data.into_json().unwrap()["node"].clone();
        for (entry, kind) in node["agents"]
            .as_array()
            .expect("the entries render as a list")
            .iter()
            .zip(agent_kinds)
        {
            let expected = if kind.package_id().is_some() {
                json!("NOT_INSTALLED")
            } else {
                json!(null)
            };
            assert_eq!(entry["lifecycle"], expected, "for {kind:?}");
        }
        for (entry, kind) in node["externalServices"]
            .as_array()
            .expect("the entries render as a list")
            .iter()
            .zip(service_kinds)
        {
            let expected = if kind.package_id().is_some() {
                json!("NOT_INSTALLED")
            } else {
                json!(null)
            };
            assert_eq!(entry["lifecycle"], expected, "for {kind:?}");
        }
    }

    #[tokio::test]
    async fn a_running_row_with_no_recorded_identity_resolves_to_nulls() {
        let builds = Arc::new(LatestBuildStub::default().with_answer("hog", "1.2.0", "abcabc"));
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![agent(
                "001.hog",
                AgentKind::SemiSupervised,
                Some(1),
                None,
                Lifecycle::Running,
            )],
            vec![],
        );

        let res = schema.execute_as_system_admin(&agents_query(id)).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let entry = res.data.into_json().unwrap()["node"]["agents"][0].clone();
        assert_eq!(entry["installedVersion"], json!(null));
        assert_eq!(entry["installedCommit"], json!(null));
        assert_eq!(entry["lifecycle"], json!("RUNNING"));
        assert_eq!(entry["updateAvailable"], json!(false));
        assert_eq!(entry["updateCheckFailed"], json!(false));
    }

    /// A stored half-identity reads back as no identity at all.
    ///
    /// The two identity fields are one build identity and the record is
    /// supposed to carry them together, but nothing in the store enforces
    /// that. The wire contract does: the two are null together or not at all,
    /// so a row carrying one half reports neither and is compared against no
    /// build. Reporting the half that is there would put a version with no
    /// commit — a build nobody can name — in front of an operator, which is
    /// the same conflation the null-lifecycle discriminator exists to refuse.
    #[tokio::test]
    async fn a_half_identity_names_no_build_to_compare() {
        let builds = Arc::new(LatestBuildStub::default().with_answer("hog", "1.2.0", "abcabc"));
        let schema = schema_with(&builds).await;
        let mut half = agent(
            "001.hog",
            AgentKind::SemiSupervised,
            Some(1),
            Some(("1.0.0", "aaaaaa")),
            Lifecycle::Running,
        );
        half.installed_commit = None;
        let mut other_half = agent(
            "002.hog",
            AgentKind::SemiSupervised,
            Some(2),
            Some(("1.0.0", "aaaaaa")),
            Lifecycle::Running,
        );
        other_half.installed_version = None;
        let id = insert_node(&schema.store(), "node1", vec![half, other_half], vec![]);

        let res = schema.execute_as_system_admin(&agents_query(id)).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let agents = res.data.into_json().unwrap()["node"]["agents"].clone();
        assert_json_eq!(
            agents[0].clone(),
            json!({
                "key": "001.hog",
                "instance": "1",
                "installedVersion": null,
                "installedCommit": null,
                "lifecycle": "RUNNING",
                "updateAvailable": false,
                "updateCheckFailed": false,
            })
        );
        assert_json_eq!(
            agents[1].clone(),
            json!({
                "key": "002.hog",
                "instance": "2",
                "installedVersion": null,
                "installedCommit": null,
                "lifecycle": "RUNNING",
                "updateAvailable": false,
                "updateCheckFailed": false,
            })
        );
    }

    /// A row of a kind no package deploys reports nothing installed, whatever
    /// the record carries.
    ///
    /// The stored fields are `Option`s and nothing stops a row of such a kind
    /// from carrying a version and a commit — a kind that used to be
    /// package-managed, a host reporting a build it assembled itself. The
    /// projection is keyed on the package mapping rather than on the
    /// lifecycle, so the identity is dropped with the lifecycle rather than
    /// surviving beside a null one.
    #[tokio::test]
    async fn a_kind_with_no_package_reports_no_installed_identity() {
        let builds = Arc::new(LatestBuildStub::default());
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![],
            vec![external_service(
                "001.ti-container",
                ExternalServiceKind::TiContainer,
                Some(1),
                Some(("9.9.9", "zzzzzz")),
                Lifecycle::Running,
                &[],
            )],
        );

        let res = schema
            .execute_as_system_admin(&external_services_query(id))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_json_eq!(
            res.data.into_json().unwrap()["node"]["externalServices"][0].clone(),
            json!({
                "key": "001.ti-container",
                "instance": "1",
                "installedVersion": null,
                "installedCommit": null,
                "lifecycle": null,
                "updateAvailable": false,
                "updateCheckFailed": false,
                "boundAddrs": [],
            })
        );
        assert_eq!(
            builds.total_calls(),
            0,
            "a kind with no package-id consults no store"
        );
    }

    /// The status read path carries the same state the list path does.
    ///
    /// `nodeStatusList` is the other route this state has to be readable on,
    /// and it renders snapshots rather than the keyed types. The snapshots
    /// carry `instance`, which is what tells two rows of one kind on one host
    /// apart where there is no `key`.
    #[tokio::test]
    async fn the_status_path_carries_the_state() {
        let builds = Arc::new(
            LatestBuildStub::default()
                .with_answer("hog", "1.2.0", "abcabc")
                .with_answer("giganto", "2.0.0", "defdef"),
        );
        let schema = schema_with(&builds).await;
        insert_node(
            &schema.store(),
            "node1",
            vec![
                agent(
                    "001.hog",
                    AgentKind::SemiSupervised,
                    Some(1),
                    Some(("1.2.0", "abcabc")),
                    Lifecycle::Running,
                ),
                agent(
                    "002.hog",
                    AgentKind::SemiSupervised,
                    Some(2),
                    Some(("1.1.0", "yyyyyy")),
                    Lifecycle::Running,
                ),
            ],
            vec![external_service(
                "001.giganto",
                ExternalServiceKind::DataStore,
                Some(1),
                None,
                Lifecycle::NotInstalled,
                &[("ingest", "10.0.0.1:38370")],
            )],
        );

        let res = schema
            .execute_as_system_admin(
                "{ nodeStatusList(first: 10) { nodes { \
                 agents { kind instance installedVersion installedCommit lifecycle \
                 updateAvailable updateCheckFailed } \
                 externalServices { kind instance installedVersion installedCommit lifecycle \
                 updateAvailable updateCheckFailed boundAddrs { key addr } } } } }",
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let node = res.data.into_json().unwrap()["nodeStatusList"]["nodes"][0].clone();
        assert_json_eq!(
            node["agents"].clone(),
            json!([
                {
                    "kind": "SEMI_SUPERVISED",
                    "instance": "1",
                    "installedVersion": "1.2.0",
                    "installedCommit": "abcabc",
                    "lifecycle": "RUNNING",
                    "updateAvailable": false,
                    "updateCheckFailed": false,
                },
                {
                    "kind": "SEMI_SUPERVISED",
                    "instance": "2",
                    "installedVersion": "1.1.0",
                    "installedCommit": "yyyyyy",
                    "lifecycle": "RUNNING",
                    "updateAvailable": true,
                    "updateCheckFailed": false,
                },
            ])
        );
        assert_json_eq!(
            node["externalServices"].clone(),
            json!([{
                "kind": "DATA_STORE",
                "instance": "1",
                "installedVersion": null,
                "installedCommit": null,
                "lifecycle": "NOT_INSTALLED",
                "updateAvailable": false,
                "updateCheckFailed": false,
                "boundAddrs": [{"key": "ingest", "addr": "10.0.0.1:38370"}],
            }])
        );
        assert_eq!(
            builds.calls("hog"),
            1,
            "the status path shares the request's memo like the list path"
        );
    }

    #[tokio::test]
    async fn bound_addrs_are_a_list_in_the_stored_order() {
        let builds = Arc::new(LatestBuildStub::default());
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![],
            vec![
                external_service(
                    "001.giganto",
                    ExternalServiceKind::DataStore,
                    Some(1),
                    None,
                    Lifecycle::NotInstalled,
                    &[],
                ),
                external_service(
                    "002.giganto",
                    ExternalServiceKind::DataStore,
                    Some(2),
                    None,
                    Lifecycle::Running,
                    &[("ingest", "10.0.0.1:38370"), ("publish", "10.0.0.1:38371")],
                ),
            ],
        );

        let res = schema
            .execute_as_system_admin(&external_services_query(id))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let services = res.data.into_json().unwrap()["node"]["externalServices"].clone();
        assert_eq!(services[0]["boundAddrs"], json!([]));
        assert_eq!(
            services[1]["boundAddrs"],
            json!([
                {"key": "ingest", "addr": "10.0.0.1:38370"},
                {"key": "publish", "addr": "10.0.0.1:38371"},
            ])
        );
    }

    #[tokio::test]
    async fn a_failed_lookup_marks_only_its_own_package() {
        let builds = Arc::new(
            LatestBuildStub::default()
                .with_failure("hog")
                .with_answer("giganto", "2.0.0", "defdef"),
        );
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![
                agent(
                    "001.hog",
                    AgentKind::SemiSupervised,
                    Some(1),
                    Some(("1.0.0", "aaaaaa")),
                    Lifecycle::Running,
                ),
                agent(
                    "002.hog",
                    AgentKind::SemiSupervised,
                    Some(2),
                    Some(("1.0.0", "aaaaaa")),
                    Lifecycle::Running,
                ),
            ],
            vec![external_service(
                "001.giganto",
                ExternalServiceKind::DataStore,
                Some(1),
                Some(("2.0.0", "defdef")),
                Lifecycle::Running,
                &[],
            )],
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{id}\") {{ agents {{ {AGENT_FIELDS} }} \
                 externalServices {{ {EXTERNAL_SERVICE_FIELDS} }} }} }}"
            ))
            .await;

        assert!(
            res.errors.is_empty(),
            "a failed lookup is a field, not an error: {:?}",
            res.errors
        );
        let node = res.data.into_json().unwrap()["node"].clone();
        for entry in node["agents"]
            .as_array()
            .expect("the entries render as a list")
        {
            assert_eq!(entry["updateAvailable"], json!(false));
            assert_eq!(entry["updateCheckFailed"], json!(true));
            // The rest of the entry is unaffected by the failed lookup.
            assert_eq!(entry["installedVersion"], json!("1.0.0"));
            assert_eq!(entry["lifecycle"], json!("RUNNING"));
        }
        let service = node["externalServices"][0].clone();
        assert_eq!(service["updateAvailable"], json!(false));
        assert_eq!(
            service["updateCheckFailed"],
            json!(false),
            "a failure never spreads beyond its own package-id"
        );
        assert_eq!(
            builds.calls("hog"),
            1,
            "a failing package-id is asked about once too"
        );
    }

    #[tokio::test]
    async fn a_failed_lookup_is_logged_once_per_package() {
        // A package-id no other test in this binary drives, because the
        // captured lines are shared: the subscriber below is installed once
        // for the whole binary rather than per test.
        const COMPONENT: &str = "aice-web-next";

        let logs = captured_logs();
        let before = logs.lines_naming(COMPONENT).len();
        let builds = Arc::new(LatestBuildStub::default().with_failure(COMPONENT));
        let schema = schema_with(&builds).await;
        for host in ["host-a.example.com", "host-b.example.com"] {
            insert_core_component(
                &schema.store(),
                COMPONENT,
                host,
                Some(("1.0.0", "aaaaaa")),
                Lifecycle::Running,
                false,
            );
        }

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ coreComponentList {{ {CORE_COMPONENT_FIELDS} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let rows = res.data.into_json().unwrap()["coreComponentList"].clone();
        assert_eq!(rows.as_array().map(Vec::len), Some(2));
        for row in rows.as_array().expect("the rows render as a list") {
            assert_eq!(row["updateAvailable"], json!(false));
            assert_eq!(row["updateCheckFailed"], json!(true));
        }
        assert_eq!(
            builds.calls(COMPONENT),
            1,
            "a failing package-id is asked about once however many rows carry it"
        );
        let breadcrumbs = logs.lines_naming(COMPONENT);
        assert_eq!(
            breadcrumbs.len() - before,
            1,
            "one breadcrumb per package-id per request: {breadcrumbs:?}"
        );
    }

    #[tokio::test]
    async fn a_failed_check_never_reports_an_available_update() {
        let builds = Arc::new(
            LatestBuildStub::default()
                .with_failure("hog")
                .with_failure("roxyd")
                .with_answer("giganto", "2.0.0", "defdef"),
        );
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![agent(
                "001.hog",
                AgentKind::SemiSupervised,
                Some(1),
                Some(("1.0.0", "aaaaaa")),
                Lifecycle::Running,
            )],
            vec![
                external_service(
                    "001.giganto",
                    ExternalServiceKind::DataStore,
                    Some(1),
                    Some(("1.0.0", "aaaaaa")),
                    Lifecycle::Running,
                    &[],
                ),
                external_service(
                    "001.ti-container",
                    ExternalServiceKind::TiContainer,
                    None,
                    None,
                    Lifecycle::NotInstalled,
                    &[],
                ),
            ],
        );
        insert_core_component(
            &schema.store(),
            "roxyd",
            "node1.example.com",
            Some(("0.6.0", "aaaaaa")),
            Lifecycle::Running,
            false,
        );
        insert_core_component(
            &schema.store(),
            "bootroot",
            "node1.example.com",
            Some(("0.1.0", "bbbbbb")),
            Lifecycle::Running,
            true,
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{id}\") {{ agents {{ {AGENT_FIELDS} }} \
                 externalServices {{ {EXTERNAL_SERVICE_FIELDS} }} }} \
                 coreComponentList {{ {CORE_COMPONENT_FIELDS} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let entries: Vec<&serde_json::Value> = data["node"]["agents"]
            .as_array()
            .expect("the entries render as a list")
            .iter()
            .chain(
                data["node"]["externalServices"]
                    .as_array()
                    .expect("the entries render as a list"),
            )
            .chain(
                data["coreComponentList"]
                    .as_array()
                    .expect("the rows render as a list"),
            )
            .collect();
        assert_eq!(entries.len(), 5);
        for entry in entries {
            assert!(
                entry["updateCheckFailed"] != json!(true)
                    || entry["updateAvailable"] == json!(false),
                "a failed check reported an available update: {entry}"
            );
        }
    }

    #[tokio::test]
    async fn core_component_list_returns_the_registry_in_key_order() {
        let builds = Arc::new(LatestBuildStub::default());
        let schema = schema_with(&builds).await;
        insert_core_component(
            &schema.store(),
            "roxyd",
            "host-b.example.com",
            Some(("0.6.0", "bbbbbb")),
            Lifecycle::Running,
            false,
        );
        insert_core_component(
            &schema.store(),
            "roxyd",
            "host-a.example.com",
            Some(("0.6.0", "aaaaaa")),
            Lifecycle::Running,
            false,
        );
        insert_core_component(
            &schema.store(),
            "review",
            "host-a.example.com",
            None,
            Lifecycle::NotInstalled,
            false,
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ coreComponentList {{ {CORE_COMPONENT_FIELDS} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let rows = res.data.into_json().unwrap()["coreComponentList"].clone();
        let pairs: Vec<(String, String)> = rows
            .as_array()
            .expect("the rows render as a list")
            .iter()
            .map(|row| {
                (
                    row["component"].as_str().unwrap_or_default().to_string(),
                    row["host"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        // The registry is keyed on `(component, host)` and iterated in its own
        // key order, which groups a component's hosts together and orders them
        // among themselves; nothing here re-sorts it.
        //
        // That order is a deterministic function of the pair but is not
        // lexicographic: the key is a bincode tuple whose halves carry varint
        // length prefixes, so a shorter `component` sorts first and `roxyd`
        // precedes `review`. Re-sorting to read prettier is exactly what the
        // contract forbids, so the expectation below is the encoding's order.
        assert_eq!(
            pairs,
            vec![
                ("roxyd".to_string(), "host-a.example.com".to_string()),
                ("roxyd".to_string(), "host-b.example.com".to_string()),
                ("review".to_string(), "host-a.example.com".to_string()),
            ]
        );
        assert_json_eq!(
            rows[2].clone(),
            json!({
                "component": "review",
                "host": "host-a.example.com",
                "installedVersion": null,
                "installedCommit": null,
                "lifecycle": "NOT_INSTALLED",
                "updateAvailable": false,
                "updateCheckFailed": false,
                "installerManaged": false,
            })
        );
    }

    #[tokio::test]
    async fn core_component_list_is_denied_below_system_administrator() {
        let builds = Arc::new(LatestBuildStub::default());
        let schema = schema_with(&builds).await;
        insert_core_component(
            &schema.store(),
            "review",
            "host-a.example.com",
            None,
            Lifecycle::NotInstalled,
            false,
        );

        let res = schema
            .execute_with_guard(
                "{ coreComponentList { component } }",
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn a_core_component_is_checked_against_its_own_component_once() {
        let builds = Arc::new(LatestBuildStub::default().with_answer("roxyd", "0.7.0", "cccccc"));
        let schema = schema_with(&builds).await;
        for host in [
            "host-a.example.com",
            "host-b.example.com",
            "host-c.example.com",
        ] {
            insert_core_component(
                &schema.store(),
                "roxyd",
                host,
                Some(("0.6.0", "aaaaaa")),
                Lifecycle::Running,
                false,
            );
        }

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ coreComponentList {{ {CORE_COMPONENT_FIELDS} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let rows = res.data.into_json().unwrap()["coreComponentList"].clone();
        assert_eq!(rows.as_array().map(Vec::len), Some(3));
        for row in rows.as_array().expect("the rows render as a list") {
            assert_eq!(row["updateAvailable"], json!(true));
            assert_eq!(row["updateCheckFailed"], json!(false));
        }
        assert_eq!(
            builds.calls("roxyd"),
            1,
            "one lookup answers every host's row"
        );
    }

    #[tokio::test]
    async fn an_installer_managed_row_consults_no_store() {
        let builds =
            Arc::new(LatestBuildStub::default().with_answer("bootroot", "9.9.9", "zzzzzz"));
        let schema = schema_with(&builds).await;
        insert_core_component(
            &schema.store(),
            "bootroot",
            "host-a.example.com",
            Some(("0.1.0", "aaaaaa")),
            Lifecycle::Running,
            true,
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ coreComponentList {{ {CORE_COMPONENT_FIELDS} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let row = res.data.into_json().unwrap()["coreComponentList"][0].clone();
        assert_eq!(row["installerManaged"], json!(true));
        assert_eq!(row["updateAvailable"], json!(false));
        assert_eq!(row["updateCheckFailed"], json!(false));
        assert_eq!(
            builds.calls("bootroot"),
            0,
            "an excluded row is never looked up"
        );
    }

    // The mutation this drives names every field of the node it updates, and
    // the read back after it asserts the whole of both entries.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn a_node_update_leaves_the_observed_state_alone() {
        let builds = Arc::new(LatestBuildStub::default().with_answer("hog", "1.2.0", "abcabc"));
        let schema = schema_with(&builds).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![agent(
                "001.hog",
                AgentKind::SemiSupervised,
                Some(7),
                Some(("1.0.0", "aaaaaa")),
                Lifecycle::Running,
            )],
            vec![external_service(
                "001.giganto",
                ExternalServiceKind::DataStore,
                Some(8),
                Some(("2.0.0", "bbbbbb")),
                Lifecycle::Stopped,
                &[("ingest", "10.0.0.1:38370")],
            )],
        );

        let res = schema
            .execute_as_system_admin(&format!(
                r#"mutation {{
                    updateNodeDraft(
                        id: "{id}"
                        old: {{
                            name: "node1",
                            nameDraft: "node1",
                            profile: {{
                                customerId: 0,
                                description: "",
                                hostname: "node1.example.com",
                            }},
                            profileDraft: null,
                            agents: [
                                {{
                                    key: "001.hog",
                                    kind: "SEMI_SUPERVISED",
                                    status: "ENABLED",
                                    config: null,
                                    draft: null
                                }}
                            ],
                            externalServices: [
                                {{
                                    key: "001.giganto",
                                    kind: "DATA_STORE",
                                    status: "ENABLED",
                                    draft: null
                                }}
                            ]
                        }},
                        new: {{
                            nameDraft: "node1",
                            profileDraft: {{
                                customerId: 0,
                                description: "edited",
                                hostname: "node1.example.com",
                            }},
                            agents: [
                                {{
                                    key: "001.hog",
                                    kind: "SEMI_SUPERVISED",
                                    status: "ENABLED",
                                    draft: "test = 'toml'"
                                }}
                            ],
                            externalServices: [
                                {{
                                    key: "001.giganto",
                                    kind: "DATA_STORE",
                                    status: "ENABLED",
                                    draft: null
                                }}
                            ]
                        }}
                    )
                }}"#
            ))
            .await;
        assert!(res.errors.is_empty(), "update failed: {:?}", res.errors);

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{id}\") {{ agents {{ {AGENT_FIELDS} }} \
                 externalServices {{ {EXTERNAL_SERVICE_FIELDS} }} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let node = res.data.into_json().unwrap()["node"].clone();
        assert_json_eq!(
            node["agents"][0].clone(),
            json!({
                "key": "001.hog",
                "instance": "7",
                "installedVersion": "1.0.0",
                "installedCommit": "aaaaaa",
                "lifecycle": "RUNNING",
                "updateAvailable": true,
                "updateCheckFailed": false,
            })
        );
        assert_json_eq!(
            node["externalServices"][0].clone(),
            json!({
                "key": "001.giganto",
                "instance": "8",
                "installedVersion": "2.0.0",
                "installedCommit": "bbbbbb",
                "lifecycle": "STOPPED",
                "updateAvailable": false,
                "updateCheckFailed": false,
                "boundAddrs": [{"key": "ingest", "addr": "10.0.0.1:38370"}],
            })
        );
    }

    /// Inserts one node and three core components whose rows carry, on every
    /// one of the five types, a withdrawn build, a build that is not withdrawn
    /// and a build whose check fails, in that order.
    ///
    /// Each type uses its own package, so each type's rows ask about their own
    /// builds.
    fn insert_one_of_each_answer(store: &Store) -> u32 {
        let id = insert_node(
            store,
            "node1",
            [
                ("1.0.0", "wwwwww"),
                ("1.0.0", "nnnnnn"),
                ("1.0.0", "ffffff"),
            ]
            .iter()
            .enumerate()
            .map(|(i, &installed)| {
                agent(
                    &format!("00{i}.hog"),
                    AgentKind::SemiSupervised,
                    Some(u32::try_from(i).expect("a small index")),
                    Some(installed),
                    Lifecycle::Running,
                )
            })
            .collect(),
            [
                ("2.0.0", "wwwwww"),
                ("2.0.0", "nnnnnn"),
                ("2.0.0", "ffffff"),
            ]
            .iter()
            .enumerate()
            .map(|(i, &installed)| {
                external_service(
                    &format!("00{i}.giganto"),
                    ExternalServiceKind::DataStore,
                    Some(u32::try_from(i).expect("a small index")),
                    Some(installed),
                    Lifecycle::Running,
                    &[],
                )
            })
            .collect(),
        );
        for (host, commit) in [
            ("host-a.example.com", "wwwwww"),
            ("host-b.example.com", "nnnnnn"),
            ("host-c.example.com", "ffffff"),
        ] {
            insert_core_component(
                store,
                "roxyd",
                host,
                Some(("0.6.0", commit)),
                Lifecycle::Running,
                false,
            );
        }
        id
    }

    /// The withdrawal stub matching [`insert_one_of_each_answer`].
    fn one_of_each_answer() -> WithdrawalStub {
        WithdrawalStub::default()
            .with_withdrawn("hog", "1.0.0", "wwwwww")
            .with_failure("hog", "1.0.0", "ffffff")
            .with_withdrawn("giganto", "2.0.0", "wwwwww")
            .with_failure("giganto", "2.0.0", "ffffff")
            .with_withdrawn("roxyd", "0.6.0", "wwwwww")
            .with_failure("roxyd", "0.6.0", "ffffff")
    }

    /// Each of the three answers maps to its pair on all five types: withdrawn
    /// is `true`/`false`, not withdrawn is `false`/`false`, and a failed check
    /// is `false`/`true` — a field, never a GraphQL error.
    #[tokio::test]
    async fn the_withdrawal_pair_maps_every_answer_on_every_type() {
        let builds = Arc::new(LatestBuildStub::default());
        let withdrawals = Arc::new(one_of_each_answer());
        let schema = schema_with_withdrawals(&builds, &withdrawals).await;
        let id = insert_one_of_each_answer(&schema.store());

        let res = schema.execute_as_system_admin(&every_type_query(id)).await;

        assert!(
            res.errors.is_empty(),
            "a failed check is a field, not an error: {:?}",
            res.errors
        );
        let data = res.data.into_json().unwrap();
        for (type_name, rows) in rows_by_type(&data) {
            assert_eq!(
                rows,
                vec![
                    json!({"installedBuildWithdrawn": true, "withdrawalCheckFailed": false}),
                    json!({"installedBuildWithdrawn": false, "withdrawalCheckFailed": false}),
                    json!({"installedBuildWithdrawn": false, "withdrawalCheckFailed": true}),
                ],
                "on {type_name}"
            );
        }
        // The keyed types and the snapshots render the same rows, and share
        // one check per build.
        assert_eq!(withdrawals.calls("hog", "1.0.0", "wwwwww"), 1);
        assert_eq!(withdrawals.calls("hog", "1.0.0", "ffffff"), 1);
        assert_eq!(withdrawals.calls("giganto", "2.0.0", "nnnnnn"), 1);
        assert_eq!(withdrawals.total_calls(), 9);
    }

    /// A failed check never reports a withdrawn build, on any type.
    ///
    /// Every build here is both withdrawn and failing, so a mapping that let
    /// the stub's withdrawn set leak past a failure would render `true` beside
    /// the failure.
    #[tokio::test]
    async fn a_failed_withdrawal_check_never_reports_a_withdrawn_build() {
        let builds = Arc::new(LatestBuildStub::default());
        let mut stub = WithdrawalStub::default();
        for (package_id, version) in [("hog", "1.0.0"), ("giganto", "2.0.0"), ("roxyd", "0.6.0")] {
            for commit in ["wwwwww", "nnnnnn", "ffffff"] {
                stub = stub
                    .with_withdrawn(package_id, version, commit)
                    .with_failure(package_id, version, commit);
            }
        }
        let withdrawals = Arc::new(stub);
        let schema = schema_with_withdrawals(&builds, &withdrawals).await;
        let id = insert_one_of_each_answer(&schema.store());

        let res = schema.execute_as_system_admin(&every_type_query(id)).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        for (type_name, rows) in rows_by_type(&data) {
            assert_eq!(rows.len(), 3, "on {type_name}");
            for row in rows {
                assert_eq!(
                    row,
                    json!({"installedBuildWithdrawn": false, "withdrawalCheckFailed": true}),
                    "on {type_name}"
                );
            }
        }
    }

    /// A row with nothing to check reports both `false` and asks nothing: a
    /// kind no package deploys, an installer-managed core component, and a row
    /// with no installed identity — null, half, or whole under
    /// `NOT_INSTALLED`.
    ///
    /// Every build named here fails its check, so a row that asked anyway
    /// would also render `withdrawalCheckFailed: true`.
    #[tokio::test]
    async fn a_row_with_nothing_to_check_is_never_checked() {
        let builds = Arc::new(LatestBuildStub::default());
        let withdrawals = Arc::new(
            WithdrawalStub::default()
                .with_failure("hog", "1.0.0", "aaaaaa")
                .with_failure("giganto", "1.0.0", "aaaaaa")
                .with_failure("bootroot", "0.1.0", "bbbbbb")
                .with_failure("roxyd", "0.6.0", "cccccc"),
        );
        let schema = schema_with_withdrawals(&builds, &withdrawals).await;
        let null_identity = agent(
            "001.hog",
            AgentKind::SemiSupervised,
            Some(1),
            None,
            Lifecycle::Running,
        );
        let mut half = agent(
            "002.hog",
            AgentKind::SemiSupervised,
            Some(2),
            Some(("1.0.0", "aaaaaa")),
            Lifecycle::Running,
        );
        half.installed_commit = None;
        let mut other_half = agent(
            "003.hog",
            AgentKind::SemiSupervised,
            Some(3),
            Some(("1.0.0", "aaaaaa")),
            Lifecycle::Running,
        );
        other_half.installed_version = None;
        let not_installed = agent(
            "004.hog",
            AgentKind::SemiSupervised,
            Some(4),
            Some(("1.0.0", "aaaaaa")),
            Lifecycle::NotInstalled,
        );
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![null_identity, half, other_half, not_installed],
            vec![
                external_service(
                    "001.ti-container",
                    ExternalServiceKind::TiContainer,
                    Some(1),
                    Some(("1.0.0", "aaaaaa")),
                    Lifecycle::Running,
                    &[],
                ),
                external_service(
                    "001.giganto",
                    ExternalServiceKind::DataStore,
                    Some(1),
                    Some(("1.0.0", "aaaaaa")),
                    Lifecycle::NotInstalled,
                    &[],
                ),
            ],
        );
        insert_core_component(
            &schema.store(),
            "bootroot",
            "node1.example.com",
            Some(("0.1.0", "bbbbbb")),
            Lifecycle::Running,
            true,
        );
        insert_core_component(
            &schema.store(),
            "roxyd",
            "node1.example.com",
            Some(("0.6.0", "cccccc")),
            Lifecycle::NotInstalled,
            false,
        );

        let res = schema.execute_as_system_admin(&every_type_query(id)).await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let mut rows = 0;
        for (type_name, entries) in rows_by_type(&data) {
            assert!(!entries.is_empty(), "on {type_name}");
            for entry in entries {
                assert_eq!(
                    entry,
                    json!({"installedBuildWithdrawn": false, "withdrawalCheckFailed": false}),
                    "on {type_name}"
                );
                rows += 1;
            }
        }
        assert_eq!(rows, 14);
        assert_eq!(
            withdrawals.total_calls(),
            0,
            "a row with nothing to check asks nothing"
        );
    }

    /// One build on many hosts is one check, and two builds of one package are
    /// two, however many rows and types carry them.
    #[tokio::test]
    async fn the_withdrawal_check_is_asked_once_per_build() {
        let builds = Arc::new(LatestBuildStub::default());
        let withdrawals = Arc::new(WithdrawalStub::default());
        let schema = schema_with_withdrawals(&builds, &withdrawals).await;
        for (name, commit) in [
            ("node1", "aaaaaa"),
            ("node2", "aaaaaa"),
            ("node3", "bbbbbb"),
        ] {
            insert_node(
                &schema.store(),
                name,
                vec![agent(
                    "001.hog",
                    AgentKind::SemiSupervised,
                    Some(1),
                    Some(("1.0.0", commit)),
                    Lifecycle::Running,
                )],
                vec![],
            );
        }
        for host in ["host-a.example.com", "host-b.example.com"] {
            insert_core_component(
                &schema.store(),
                "roxyd",
                host,
                Some(("0.6.0", "cccccc")),
                Lifecycle::Running,
                false,
            );
        }

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ nodeList {{ edges {{ node {{ agents {{ {WITHDRAWAL_FIELDS} }} }} }} }} \
                 nodeStatusList(first: 10) {{ nodes {{ agents {{ {WITHDRAWAL_FIELDS} }} }} }} \
                 coreComponentList {{ {WITHDRAWAL_FIELDS} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            withdrawals.calls("hog", "1.0.0", "aaaaaa"),
            1,
            "one build is checked once across hosts and types"
        );
        assert_eq!(
            withdrawals.calls("hog", "1.0.0", "bbbbbb"),
            1,
            "another build of the same package is its own check"
        );
        assert_eq!(withdrawals.calls("roxyd", "0.6.0", "cccccc"), 1);
        assert_eq!(withdrawals.total_calls(), 3);
    }

    /// The withdrawal check is independent of the update check: it is made
    /// whatever `latest_build` answered, and neither one's failure is reported
    /// as the other's.
    #[tokio::test]
    async fn the_withdrawal_check_is_independent_of_the_update_check() {
        // `hog`'s newest build cannot be read and its installed build is
        // withdrawn; `giganto` has no accepted build and its check fails.
        let builds = Arc::new(LatestBuildStub::default().with_failure("hog"));
        let withdrawals = Arc::new(
            WithdrawalStub::default()
                .with_withdrawn("hog", "1.0.0", "aaaaaa")
                .with_failure("giganto", "2.0.0", "bbbbbb"),
        );
        let schema = schema_with_withdrawals(&builds, &withdrawals).await;
        let id = insert_node(
            &schema.store(),
            "node1",
            vec![agent(
                "001.hog",
                AgentKind::SemiSupervised,
                Some(1),
                Some(("1.0.0", "aaaaaa")),
                Lifecycle::Running,
            )],
            vec![external_service(
                "001.giganto",
                ExternalServiceKind::DataStore,
                Some(1),
                Some(("2.0.0", "bbbbbb")),
                Lifecycle::Running,
                &[],
            )],
        );

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ node(id: \"{id}\") {{ \
                 agents {{ updateAvailable updateCheckFailed {WITHDRAWAL_FIELDS} }} \
                 externalServices {{ updateAvailable updateCheckFailed {WITHDRAWAL_FIELDS} }} \
                 }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let node = res.data.into_json().unwrap()["node"].clone();
        assert_json_eq!(
            node["agents"][0].clone(),
            json!({
                "updateAvailable": false,
                "updateCheckFailed": true,
                "installedBuildWithdrawn": true,
                "withdrawalCheckFailed": false,
            })
        );
        assert_json_eq!(
            node["externalServices"][0].clone(),
            json!({
                "updateAvailable": false,
                "updateCheckFailed": false,
                "installedBuildWithdrawn": false,
                "withdrawalCheckFailed": true,
            })
        );
        assert_eq!(builds.calls("hog"), 1);
        assert_eq!(builds.calls("giganto"), 1);
        assert_eq!(withdrawals.calls("hog", "1.0.0", "aaaaaa"), 1);
        assert_eq!(withdrawals.calls("giganto", "2.0.0", "bbbbbb"), 1);
    }

    #[tokio::test]
    async fn a_failed_withdrawal_check_is_logged_once_per_build() {
        // A build no other test in this binary drives, because the captured
        // lines are shared across the binary.
        const VERSION: &str = "7.7.7-logged";

        let logs = captured_logs();
        let before = logs.withdrawal_lines_naming(VERSION).len();
        let builds = Arc::new(LatestBuildStub::default());
        let withdrawals =
            Arc::new(WithdrawalStub::default().with_failure("review", VERSION, "eeeeee"));
        let schema = schema_with_withdrawals(&builds, &withdrawals).await;
        for host in ["host-a.example.com", "host-b.example.com"] {
            insert_core_component(
                &schema.store(),
                "review",
                host,
                Some((VERSION, "eeeeee")),
                Lifecycle::Running,
                false,
            );
        }

        let res = schema
            .execute_as_system_admin(&format!(
                "{{ coreComponentList {{ {WITHDRAWAL_FIELDS} }} }}"
            ))
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let rows = res.data.into_json().unwrap()["coreComponentList"].clone();
        assert_eq!(rows.as_array().map(Vec::len), Some(2));
        for row in rows.as_array().expect("the rows render as a list") {
            assert_eq!(row["withdrawalCheckFailed"], json!(true));
        }
        assert_eq!(withdrawals.calls("review", VERSION, "eeeeee"), 1);
        let breadcrumbs = logs.withdrawal_lines_naming(VERSION);
        assert_eq!(
            breadcrumbs.len() - before,
            1,
            "one breadcrumb per build per request: {breadcrumbs:?}"
        );
    }

    /// The schema the server serves carries both request-scoped memos.
    ///
    /// Every assertion above runs against `TestSchema`, which installs the
    /// extension itself, so all of them would still pass if the production
    /// builder lost it. Losing it makes `updateAvailable` and
    /// `installedBuildWithdrawn` resolver errors on non-null fields, which
    /// null the entry, then its list, then its node.
    #[tokio::test]
    async fn the_served_schema_carries_the_memo() {
        struct StubCertManager;

        impl CertManager for StubCertManager {
            fn cert_path(&self) -> Result<PathBuf, anyhow::Error> {
                Ok(PathBuf::new())
            }

            fn key_path(&self) -> Result<PathBuf, anyhow::Error> {
                Ok(PathBuf::new())
            }

            fn update_certificate(
                &self,
                _cert: String,
                _key: String,
            ) -> Result<Vec<ParsedCertificate>, anyhow::Error> {
                Ok(Vec::new())
            }
        }

        let db_dir = tempfile::tempdir().expect("temporary directory");
        let backup_dir = tempfile::tempdir().expect("temporary directory");
        let store = Store::new(db_dir.path(), backup_dir.path(), None).expect("open the store");
        let id = insert_node(
            &store,
            "node1",
            vec![agent(
                "001.hog",
                AgentKind::SemiSupervised,
                Some(1),
                Some(("1.1.0", "yyyyyy")),
                Lifecycle::Running,
            )],
            vec![],
        );
        let builds = Arc::new(LatestBuildStub::default().with_answer("hog", "1.2.0", "abcabc"));
        let withdrawals =
            Arc::new(WithdrawalStub::default().with_withdrawn("hog", "1.1.0", "yyyyyy"));
        let schema = crate::graphql::schema(
            Arc::new(RwLock::new(store)),
            MockAgentManager {},
            MockPackageDeployer::with_builds(builds.clone()).with_withdrawals(withdrawals.clone()),
            MockHostOnboarder {},
            None,
            Arc::new(StubCertManager),
            Arc::new(Notify::new()),
            crate::maintenance::MaintenanceGate::new(),
            #[cfg(feature = "auth-mtls")]
            Arc::new(crate::customer_data_deletion::CustomerDataDeletionTaskManager::default()),
        );

        let res = schema
            .execute(
                async_graphql::Request::new(format!(
                    "{{ node(id: \"{id}\") {{ agents {{ {AGENT_FIELDS} {WITHDRAWAL_FIELDS} }} }} }}"
                ))
                .data(RoleGuard::Role(Role::SystemAdministrator)),
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let entry = res.data.into_json().unwrap()["node"]["agents"][0].clone();
        assert_eq!(entry["updateAvailable"], json!(true));
        assert_eq!(entry["updateCheckFailed"], json!(false));
        assert_eq!(entry["installedBuildWithdrawn"], json!(true));
        assert_eq!(entry["withdrawalCheckFailed"], json!(false));
        assert_eq!(builds.calls("hog"), 1);
        assert_eq!(withdrawals.calls("hog", "1.1.0", "yyyyyy"), 1);
    }

    /// Returns the log lines this test binary has emitted, installing the
    /// subscriber that captures them on the first call.
    ///
    /// The subscriber is global rather than per test on purpose. `tracing`
    /// decides a callsite's interest on whichever thread reaches it first and
    /// caches that answer for the whole process, so a scoped subscriber loses
    /// the race whenever another test drives the same `warn!` first — which
    /// two tests here do. One subscriber for every thread has no race to lose,
    /// at the cost of one shared buffer, which is why the assertions above
    /// filter by a package-id no other test drives.
    fn captured_logs() -> &'static CapturedLogs {
        static LOGS: OnceLock<CapturedLogs> = OnceLock::new();
        LOGS.get_or_init(|| {
            let logs = CapturedLogs::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(logs.clone())
                .with_max_level(tracing::Level::WARN)
                .with_ansi(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("nothing else in this binary installs a global subscriber");
            logs
        })
    }

    /// The log lines a test binary emitted, as bytes a `tracing` subscriber
    /// wrote.
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl CapturedLogs {
        /// Returns the failed-lookup breadcrumbs naming `package_id`.
        fn lines_naming(&self, package_id: &str) -> Vec<String> {
            self.lines_with("cannot read the latest build of package", package_id)
        }

        /// Returns the failed-withdrawal-check breadcrumbs naming `needle`.
        fn withdrawal_lines_naming(&self, needle: &str) -> Vec<String> {
            self.lines_with("cannot check whether build", needle)
        }

        fn lines_with(&self, breadcrumb: &str, needle: &str) -> Vec<String> {
            let captured = self
                .0
                .lock()
                .unwrap_or_else(|e| panic!("Mutex poisoned: {e}"));
            String::from_utf8_lossy(&captured)
                .lines()
                .filter(|line| line.contains(breadcrumb) && line.contains(needle))
                .map(ToString::to_string)
                .collect()
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|e| panic!("Mutex poisoned: {e}"))
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
}
