//! The bind-address recommendation query and the conflict objects a stale
//! recommendation produces.
//!
//! This crate selects nothing here. Every decision needing the listener
//! catalog, the host's occupancy or the allocation rows is review's, reached
//! through [`crate::backend::PackageDeployer`]; the resolver below is a pure
//! pass-through that maps one [`DeployError`](crate::backend::DeployError)
//! variant onto a union member and lets every other variant be an ordinary
//! GraphQL error.

use anyhow::Context as _;
use async_graphql::{
    Context, Enum, InputObject, Object, Result, SimpleObject, StringNumber, Union,
};
use review_database::{ListenerBinding, ListenerTransport, PortOwner};

use super::{
    super::{BoxedPackageDeployer, Role, RoleGuard, customer_access},
    BindAddrQuery,
};
use crate::backend::{DeployError, MODULE_PACKAGE_IDS};

/// The transport a listener binds on.
///
/// It is carried so a form can label a field without inferring it, and it is
/// never accepted back on a mutation: transport comes from review's own
/// catalog, not from the operator.
// It mirrors `review_database::ListenerTransport`, and the conversion is the
// one the `remote` attribute derives, so a variant added upstream stops this
// compiling.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "review_database::ListenerTransport")]
pub(crate) enum Transport {
    Tcp,
    Udp,
}

/// One address review proposes for one listener.
///
/// There is deliberately no `editable` flag: it could never be false, and the
/// fields an operator may not change are read from the allocation row rather
/// than from a proposal.
// It is the GraphQL rendering of `review_database::ListenerBinding`, whose
// `addr` is a `SocketAddr` and crosses here in its `Display` form.
#[derive(SimpleObject)]
pub(crate) struct BindAddrProposal {
    /// The name the component knows the listener by.
    listener_key: String,
    /// The transport the listener binds on.
    transport: Transport,
    /// The proposed address, as `<ip>:<port>`.
    addr: String,
}

impl From<ListenerBinding> for BindAddrProposal {
    fn from(binding: ListenerBinding) -> Self {
        Self {
            listener_key: binding.listener_key,
            transport: binding.transport.into(),
            addr: binding.addr.to_string(),
        }
    }
}

/// The addresses review would choose for the next instance of a component.
// The list is wrapped in an object because a GraphQL union has object members
// and never a list, and the query has to be able to answer with a failure
// object from the same position.
#[derive(SimpleObject)]
pub(crate) struct BindAddrProposals {
    /// One proposal per listener the component binds, in review's own order.
    /// It is empty for every component with no listeners of its own, which is
    /// an ordinary answer rather than a failure.
    proposals: Vec<BindAddrProposal>,
}

/// The host could not be asked what it already has bound.
///
/// It names the host so the UI can offer a retry rather than rendering an
/// empty install form.
#[derive(SimpleObject)]
pub(crate) struct HostOccupancyUnavailable {
    /// The host that could not be read.
    host: String,
    /// Why it could not be read.
    reason: String,
}

/// What a bind-address recommendation answers with: the proposals, or the
/// reason the host's occupancy could not be read.
// The members are exactly the two outcomes an install form can render. Every
// other `DeployError` variant, `Other` included, is an ordinary GraphQL
// error, and so are the guard, hostname-access and class-binding rejections,
// which are decided before any backend call.
#[derive(Union)]
pub(crate) enum RecommendBindAddrsResult {
    Proposals(BindAddrProposals),
    Unavailable(HostOccupancyUnavailable),
}

/// Who holds an allocated address.
///
/// It carries no listener key: the contended row's key is rendered by the
/// conflict itself.
#[derive(SimpleObject)]
pub(crate) struct BindAddrHolder {
    /// The canonical package-id of the component holding the address.
    component: String,
    /// The instance number holding it. It is a `u32` upstream, which `Int`
    /// cannot represent, so it crosses as the `StringNumber` scalar.
    instance: StringNumber<u32>,
}

/// Another instance already holds the address in the allocation table.
///
/// It carries every part of the refusal, so a screen can name the holder
/// rather than reporting a bare conflict.
#[derive(SimpleObject)]
pub(crate) struct PortAllocationConflict {
    /// The name the component knows the contended listener by, which is the
    /// holder's own listener key.
    listener_key: String,
    /// The host the contended address is bound on.
    host: String,
    /// The transport the contended address is bound on.
    transport: Transport,
    /// The contended port. A `u16` is exactly representable as `Int`.
    port: u16,
    /// Who holds it.
    holder: BindAddrHolder,
}

/// Something the allocation table does not know about holds the port on the
/// host.
///
/// It has no holder field at all, because there is none to name: host
/// occupancy is a live probe of the host rather than an allocation row, and
/// is identity-free by design.
#[derive(SimpleObject)]
pub(crate) struct HostPortOccupied {
    /// The listener the port was wanted for.
    listener_key: String,
    /// The transport the port was wanted on.
    transport: Transport,
    /// The occupied port.
    port: u16,
}

/// Builds the [`PortAllocationConflict`] object from the payload of
/// [`DeployError::PortAllocationConflict`](crate::backend::DeployError::PortAllocationConflict).
///
/// The parameter list is that variant's payload verbatim, so a caller
/// destructures the variant and passes the parts straight in, and a field
/// added to the variant stops the call site compiling rather than being
/// silently dropped. No `From<DeployError>` impl is written for it: such an
/// impl could not be total, since each object is reachable from exactly one of
/// the enum's six variants.
// The `installService` resolver is the caller, and lands in a sibling issue;
// the function is `pub(crate)` from the day it is written so that issue calls
// it rather than building a second construction site. The tests below exercise
// it in the meantime.
#[allow(dead_code)]
pub(crate) fn port_allocation_conflict(
    host: String,
    transport: ListenerTransport,
    port: u16,
    owner: PortOwner,
) -> PortAllocationConflict {
    PortAllocationConflict {
        listener_key: owner.listener_key,
        host,
        transport: transport.into(),
        port,
        holder: BindAddrHolder {
            component: owner.component,
            instance: StringNumber(owner.instance),
        },
    }
}

/// Builds the [`HostPortOccupied`] object from the payload of
/// [`DeployError::HostPortOccupied`](crate::backend::DeployError::HostPortOccupied).
///
/// The two field sets are identical, which is the whole rule: there is nothing
/// to look up, nothing to default and no holder to omit, because the variant
/// carries none.
// Declared `pub(crate)` for the same reason as [`port_allocation_conflict`].
#[allow(dead_code)]
pub(crate) fn host_port_occupied(
    listener_key: String,
    transport: ListenerTransport,
    port: u16,
) -> HostPortOccupied {
    HostPortOccupied {
        listener_key,
        transport: transport.into(),
        port,
    }
}

/// Builds the [`HostOccupancyUnavailable`] object from the payload of
/// [`DeployError::HostOccupancyUnavailable`](crate::backend::DeployError::HostOccupancyUnavailable).
///
/// The host is the variant's own, never the resolver's argument: the host the
/// backend names is the host it could not reach, so the conversion has no rule
/// that could quietly diverge from the variant.
pub(crate) fn host_occupancy_unavailable(host: String, reason: String) -> HostOccupancyUnavailable {
    HostOccupancyUnavailable { host, reason }
}

/// One address an operator submits with an install.
///
/// There is no `transport` field: transport is never operator input.
#[derive(InputObject)]
pub(crate) struct BindAddrInput {
    /// The name the component knows the listener by, passed through unchecked.
    listener_key: String,
    /// The address to bind, as `<ip>:<port>`.
    addr: String,
}

impl TryFrom<BindAddrInput> for crate::backend::BindAddrInput {
    type Error = anyhow::Error;

    /// Parses `addr` into a `SocketAddr`, so a syntactically invalid address
    /// fails here rather than reaching review as a string. Nothing else about
    /// the value is validated or normalised.
    fn try_from(input: BindAddrInput) -> Result<Self, Self::Error> {
        let addr = input
            .addr
            .parse()
            .with_context(|| format!("parsing the bind address {}", input.addr))?;
        Ok(Self {
            listener_key: input.listener_key,
            addr,
        })
    }
}

#[Object]
impl BindAddrQuery {
    /// Returns the addresses review would propose for the next instance of
    /// `target` on `host`.
    ///
    /// It takes no `instance`: the instance being recommended for is the one
    /// the following install will allocate. It reserves nothing, so a proposal
    /// goes stale only between this call and the install that carries it back,
    /// and that install is where the staleness is caught.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn recommend_bind_addrs(
        &self,
        ctx: &Context<'_>,
        host: String,
        target: String,
    ) -> Result<RecommendBindAddrsResult> {
        customer_access::check_hostname_access(ctx, &host)?;
        if !MODULE_PACKAGE_IDS.contains(&target.as_str()) {
            return Err(format!("{target} is not a module package").into());
        }

        let deployer = ctx.data::<BoxedPackageDeployer>()?;
        match deployer.recommend_bind_addrs(&host, &target).await {
            Ok(bindings) => Ok(RecommendBindAddrsResult::Proposals(BindAddrProposals {
                proposals: bindings.into_iter().map(Into::into).collect(),
            })),
            Err(DeployError::HostOccupancyUnavailable { host, reason }) => Ok(
                RecommendBindAddrsResult::Unavailable(host_occupancy_unavailable(host, reason)),
            ),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
    use review_database::{
        BuildSelector, ListenerBinding, ListenerTransport, PortOwner, RequestKeyError, Role,
    };
    use review_protocol::types::node::{
        BootstrapMaterial, DeliveryMode, FailurePolicy, PackageState,
    };

    use super::{
        BindAddrInput, HostPortOccupied, PortAllocationConflict, host_port_occupied,
        port_allocation_conflict,
    };
    use crate::{
        backend::{
            BindAddrInput as BackendBindAddrInput, BuildId, DeployError, DeployOutcome,
            OperationId, PackageDeployer,
        },
        graphql::{BoxedPackageDeployer, RoleGuard, TestSchema, node::test_support},
    };

    const QUERY: &str = r#"{
        recommendBindAddrs(host: "host1", target: "giganto") {
            __typename
            ... on BindAddrProposals {
                proposals { listenerKey transport addr }
            }
            ... on HostOccupancyUnavailable { host reason }
        }
    }"#;

    /// What a [`CountingDeployer`] answers `recommend_bind_addrs` with.
    enum StubAnswer {
        Bindings(Vec<ListenerBinding>),
        HostOccupancyUnavailable { host: String, reason: String },
        PortAllocationConflict,
        HostPortOccupied,
        Other,
    }

    /// Answers `recommend_bind_addrs` from a script and counts how often it was
    /// asked. Every other method panics: a test that reaches one is testing
    /// something this module does not do.
    struct CountingDeployer {
        calls: Arc<AtomicUsize>,
        answer: StubAnswer,
    }

    impl CountingDeployer {
        /// Boxes a stub answering with `answer`, paired with the counter it
        /// increments.
        fn boxed(answer: StubAnswer) -> (Box<dyn PackageDeployer>, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let deployer = Self {
                calls: Arc::clone(&calls),
                answer,
            };
            (Box::new(deployer), calls)
        }
    }

    #[async_trait::async_trait]
    impl PackageDeployer for CountingDeployer {
        async fn install(
            &self,
            _host: &str,
            _target: &str,
            _selector: BuildSelector,
            _on_failure: FailurePolicy,
            _bind_addrs: Option<Vec<BackendBindAddrInput>>,
            _request_key: &str,
        ) -> Result<(DeployOutcome, OperationId), DeployError> {
            unimplemented!("this stub answers recommend_bind_addrs only")
        }

        async fn update(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
            _selector: BuildSelector,
            _on_failure: FailurePolicy,
        ) -> Result<(DeployOutcome, OperationId), DeployError> {
            unimplemented!("this stub answers recommend_bind_addrs only")
        }

        async fn remove(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> Result<OperationId, DeployError> {
            unimplemented!("this stub answers recommend_bind_addrs only")
        }

        async fn recommend_bind_addrs(
            &self,
            _host: &str,
            _target: &str,
        ) -> Result<Vec<ListenerBinding>, DeployError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.answer {
                StubAnswer::Bindings(bindings) => Ok(bindings.clone()),
                StubAnswer::HostOccupancyUnavailable { host, reason } => {
                    Err(DeployError::HostOccupancyUnavailable {
                        host: host.clone(),
                        reason: reason.clone(),
                    })
                }
                StubAnswer::PortAllocationConflict => Err(DeployError::PortAllocationConflict {
                    host: "host1".to_string(),
                    transport: ListenerTransport::Tcp,
                    port: 38_370,
                    owner: PortOwner {
                        component: "giganto".to_string(),
                        instance: 1,
                        listener_key: "ingest".to_string(),
                    },
                }),
                StubAnswer::HostPortOccupied => Err(DeployError::HostPortOccupied {
                    listener_key: "ingest".to_string(),
                    transport: ListenerTransport::Udp,
                    port: 38_371,
                }),
                StubAnswer::Other => Err(DeployError::Other(anyhow::anyhow!(
                    "the host answered something this stub does not model"
                ))),
            }
        }

        async fn latest_build(&self, _target: &str) -> Result<Option<BuildId>, anyhow::Error> {
            unimplemented!("this stub answers recommend_bind_addrs only")
        }

        async fn package_status(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> Result<PackageState, anyhow::Error> {
            unimplemented!("this stub answers recommend_bind_addrs only")
        }

        async fn read_version(
            &self,
            _host: &str,
            _target: &str,
            _instance: Option<u32>,
        ) -> Result<Option<BuildId>, anyhow::Error> {
            unimplemented!("this stub answers recommend_bind_addrs only")
        }

        async fn register(
            &self,
            _service_name: &str,
            _host: &str,
            _instance: Option<u32>,
            _mode: DeliveryMode,
        ) -> Result<BootstrapMaterial, anyhow::Error> {
            unimplemented!("this stub answers recommend_bind_addrs only")
        }

        async fn deregister(
            &self,
            _service_name: &str,
            _host: &str,
            _instance: Option<u32>,
        ) -> Result<(), anyhow::Error> {
            unimplemented!("this stub answers recommend_bind_addrs only")
        }
    }

    fn binding(listener_key: &str, transport: ListenerTransport, port: u16) -> ListenerBinding {
        ListenerBinding {
            listener_key: listener_key.to_string(),
            transport,
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    /// The proposals come back in the stub's own order, which no sort would
    /// preserve.
    #[tokio::test]
    async fn the_resolver_passes_the_bindings_through_unchanged() {
        let bindings = vec![
            binding("publish", ListenerTransport::Udp, 38_372),
            binding("ingest", ListenerTransport::Tcp, 38_370),
            binding("graphql", ListenerTransport::Tcp, 8443),
            binding("ingest", ListenerTransport::Udp, 38_370),
        ];
        let (deployer, calls) = CountingDeployer::boxed(StubAnswer::Bindings(bindings));
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin_with_data(QUERY, deployer as BoxedPackageDeployer)
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            res.data.into_json().unwrap(),
            serde_json::json!({
                "recommendBindAddrs": {
                    "__typename": "BindAddrProposals",
                    "proposals": [
                        {"listenerKey": "publish", "transport": "UDP", "addr": "127.0.0.1:38372"},
                        {"listenerKey": "ingest", "transport": "TCP", "addr": "127.0.0.1:38370"},
                        {"listenerKey": "graphql", "transport": "TCP", "addr": "127.0.0.1:8443"},
                        {"listenerKey": "ingest", "transport": "UDP", "addr": "127.0.0.1:38370"}
                    ]
                }
            })
        );
    }

    /// Every component the catalog does not list has no listening addresses,
    /// and that is an ordinary answer rather than a failure member.
    #[tokio::test]
    async fn an_empty_list_is_an_empty_proposals_object() {
        let (deployer, calls) = CountingDeployer::boxed(StubAnswer::Bindings(Vec::new()));
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin_with_data(QUERY, deployer as BoxedPackageDeployer)
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            res.data.into_json().unwrap(),
            serde_json::json!({
                "recommendBindAddrs": {
                    "__typename": "BindAddrProposals",
                    "proposals": []
                }
            })
        );
    }

    #[tokio::test]
    async fn an_unreadable_host_is_the_failure_member() {
        let (deployer, calls) = CountingDeployer::boxed(StubAnswer::HostOccupancyUnavailable {
            host: "giganto-host-7".to_string(),
            reason: "the host did not answer".to_string(),
        });
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin_with_data(QUERY, deployer as BoxedPackageDeployer)
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The host is the variant's own, not the `host1` argument.
        assert_eq!(
            res.data.into_json().unwrap(),
            serde_json::json!({
                "recommendBindAddrs": {
                    "__typename": "HostOccupancyUnavailable",
                    "host": "giganto-host-7",
                    "reason": "the host did not answer"
                }
            })
        );
    }

    /// Neither port conflict is reachable from this query, so both are ordinary
    /// GraphQL errors here, as is every other variant.
    #[tokio::test]
    async fn every_other_variant_is_an_ordinary_graphql_error() {
        for answer in [
            StubAnswer::Other,
            StubAnswer::PortAllocationConflict,
            StubAnswer::HostPortOccupied,
        ] {
            let (deployer, calls) = CountingDeployer::boxed(answer);
            let schema = TestSchema::new().await;

            let res = schema
                .execute_as_system_admin_with_data(QUERY, deployer as BoxedPackageDeployer)
                .await;

            assert_eq!(res.errors.len(), 1);
            assert!(res.data.into_json().unwrap().is_null());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn a_target_outside_the_module_class_is_rejected_without_a_backend_call() {
        for target in ["roxyd", "review", "bootroot"] {
            let (deployer, calls) = CountingDeployer::boxed(StubAnswer::Bindings(Vec::new()));
            let schema = TestSchema::new().await;

            let query = format!(
                r#"{{ recommendBindAddrs(host: "host1", target: "{target}") {{ __typename }} }}"#
            );
            let res = schema
                .execute_as_system_admin_with_data(&query, deployer as BoxedPackageDeployer)
                .await;

            assert_eq!(res.errors.len(), 1, "{target}");
            assert_eq!(
                res.errors[0].message,
                format!("{target} is not a module package")
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0, "{target}");
        }
    }

    #[tokio::test]
    async fn a_host_outside_the_users_customers_is_rejected_without_a_backend_call() {
        let (deployer, calls) = CountingDeployer::boxed(StubAnswer::Bindings(Vec::new()));
        let schema = TestSchema::new().await;
        test_support::insert_active_node(&schema.store(), "giganto_host", 2, "host1");

        let res = schema
            .execute_as_scoped_user_with_data(
                QUERY,
                Role::SecurityAdministrator,
                Some(vec![1]),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// The other side of the hostname check: a scoped user whose customer owns
    /// the host reaches the backend. Without this, a `check_hostname_access`
    /// that refused everyone would still pass every test above, since the
    /// unscoped administrator the rest of them use bypasses the check.
    #[tokio::test]
    async fn a_scoped_user_whose_customer_owns_the_host_reaches_the_backend() {
        let bindings = vec![binding("ingest", ListenerTransport::Tcp, 38_370)];
        let (deployer, calls) = CountingDeployer::boxed(StubAnswer::Bindings(bindings));
        let schema = TestSchema::new().await;
        test_support::insert_active_node(&schema.store(), "giganto_host", 1, "host1");

        let res = schema
            .execute_as_scoped_user_with_data(
                QUERY,
                Role::SecurityAdministrator,
                Some(vec![1]),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            res.data.into_json().unwrap(),
            serde_json::json!({
                "recommendBindAddrs": {
                    "__typename": "BindAddrProposals",
                    "proposals": [
                        {"listenerKey": "ingest", "transport": "TCP", "addr": "127.0.0.1:38370"}
                    ]
                }
            })
        );
    }

    /// The role guard runs before anything else, so a role outside the two the
    /// query admits never reaches the stub.
    #[tokio::test]
    async fn a_role_outside_the_guard_is_rejected_without_a_backend_call() {
        let (deployer, calls) = CountingDeployer::boxed(StubAnswer::Bindings(Vec::new()));
        let schema = TestSchema::new().await;

        let res = schema
            .execute_with_guard_and_data(
                QUERY,
                RoleGuard::Role(Role::SecurityMonitor),
                deployer as BoxedPackageDeployer,
            )
            .await;

        assert_eq!(res.errors.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// Renders the two conflict objects, which no root of the crate's own
    /// schema reaches until the install mutation lands.
    #[derive(Default)]
    struct ConflictQuery;

    #[Object]
    impl ConflictQuery {
        /// Renders the conflict built from the payload of
        /// `DeployError::PortAllocationConflict`.
        ///
        /// The payload is destructured out of a real error value, so the
        /// conversion is exercised the way the install resolver will call it.
        async fn conflict(&self) -> PortAllocationConflict {
            let error = DeployError::PortAllocationConflict {
                host: "host1".to_string(),
                transport: ListenerTransport::Udp,
                port: u16::MAX,
                owner: PortOwner {
                    component: "giganto".to_string(),
                    // Above `i32::MAX`, so `Int` could not carry it.
                    instance: 3_000_000_000,
                    listener_key: "publish".to_string(),
                },
            };
            let DeployError::PortAllocationConflict {
                host,
                transport,
                port,
                owner,
            } = error
            else {
                unreachable!("the value above is that variant")
            };
            port_allocation_conflict(host, transport, port, owner)
        }

        /// Renders the object built from the payload of
        /// `DeployError::HostPortOccupied`.
        async fn occupied(&self) -> HostPortOccupied {
            let error = DeployError::HostPortOccupied {
                listener_key: "ingest".to_string(),
                transport: ListenerTransport::Tcp,
                port: 38_371,
            };
            let DeployError::HostPortOccupied {
                listener_key,
                transport,
                port,
            } = error
            else {
                unreachable!("the value above is that variant")
            };
            host_port_occupied(listener_key, transport, port)
        }

        /// Converts a submitted address, so the input object has a reachable
        /// parse to test.
        async fn parsed(&self, input: BindAddrInput) -> async_graphql::Result<String> {
            let converted: BackendBindAddrInput = input.try_into()?;
            Ok(format!("{} {}", converted.listener_key, converted.addr))
        }
    }

    fn conflict_schema() -> Schema<ConflictQuery, EmptyMutation, EmptySubscription> {
        Schema::build(ConflictQuery, EmptyMutation, EmptySubscription).finish()
    }

    /// Every part of the refusal survives, `owner`'s three included.
    #[tokio::test]
    async fn the_port_allocation_conflict_conversion_is_total() {
        let res = conflict_schema()
            .execute(
                "{ conflict { listenerKey host transport port holder { component instance } } }",
            )
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            serde_json::json!({
                "conflict": {
                    "listenerKey": "publish",
                    "host": "host1",
                    "transport": "UDP",
                    "port": 65535,
                    // A string, because `instance` crosses as `StringNumber`.
                    "holder": {"component": "giganto", "instance": "3000000000"}
                }
            })
        );
    }

    #[tokio::test]
    async fn the_host_port_occupied_conversion_is_total() {
        let res = conflict_schema()
            .execute("{ occupied { listenerKey transport port } }")
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            serde_json::json!({
                "occupied": {"listenerKey": "ingest", "transport": "TCP", "port": 38371}
            })
        );
    }

    /// `HostPortOccupied` has no holder to omit, and neither object carries an
    /// `editable` flag.
    #[test]
    fn the_two_conflict_objects_are_distinct() {
        let sdl = conflict_schema().sdl();
        let occupied = sdl
            .split("type HostPortOccupied {")
            .nth(1)
            .expect("the schema renders the type")
            .split('}')
            .next()
            .expect("the type body ends");

        assert!(!occupied.contains("holder"), "{occupied}");
        assert!(!occupied.contains("host"), "{occupied}");
        assert!(occupied.contains("listenerKey: String!"), "{occupied}");
        assert!(occupied.contains("transport: Transport!"), "{occupied}");
        assert!(occupied.contains("port: Int!"), "{occupied}");
        assert!(!sdl.contains("editable"), "{sdl}");
        assert!(sdl.contains("instance: StringNumber!"), "{sdl}");
    }

    #[tokio::test]
    async fn the_input_conversion_accepts_a_socket_address() {
        let res = conflict_schema()
            .execute(r#"{ parsed(input: {listenerKey: "ingest", addr: "127.0.0.1:38370"}) }"#)
            .await;

        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            serde_json::json!({"parsed": "ingest 127.0.0.1:38370"})
        );
    }

    #[tokio::test]
    async fn the_input_conversion_rejects_an_unparseable_address() {
        for addr in ["not-an-address", "127.0.0.1", "127.0.0.1:not-a-port"] {
            let res = conflict_schema()
                .execute(format!(
                    r#"{{ parsed(input: {{listenerKey: "ingest", addr: "{addr}"}}) }}"#
                ))
                .await;

            assert_eq!(res.errors.len(), 1, "{addr}");
            assert_eq!(
                res.errors[0].message,
                format!("parsing the bind address {addr}"),
                "{addr}"
            );
        }
    }

    /// A duplicate listener key reaches review: nothing here collapses a list
    /// into a map.
    #[test]
    fn the_input_conversion_keeps_a_duplicate_listener_key() {
        let submitted = [
            BindAddrInput {
                listener_key: "ingest".to_string(),
                addr: "127.0.0.1:38370".to_string(),
            },
            BindAddrInput {
                listener_key: "ingest".to_string(),
                addr: "127.0.0.1:38371".to_string(),
            },
        ];
        let converted = submitted
            .into_iter()
            .map(BackendBindAddrInput::try_from)
            .collect::<Result<Vec<_>, _>>()
            .expect("both addresses parse");

        assert_eq!(converted.len(), 2);
        assert_eq!(converted[0].listener_key, converted[1].listener_key);
        assert_ne!(converted[0].addr, converted[1].addr);
    }

    /// Names the conflict object a variant converts to, if any.
    ///
    /// The match is exhaustive on purpose: a variant added upstream stops this
    /// compiling rather than silently joining or leaving the conflict set.
    fn conflict_object(error: &DeployError) -> Option<&'static str> {
        match error {
            DeployError::PortAllocationConflict { .. } => Some("PortAllocationConflict"),
            DeployError::HostPortOccupied { .. } => Some("HostPortOccupied"),
            DeployError::HostOccupancyUnavailable { .. }
            | DeployError::RequestKey(_)
            | DeployError::CleanupPending { .. }
            | DeployError::Other(_) => None,
        }
    }

    /// Each conflict object is reachable from exactly one variant, which is why
    /// neither conversion is written as a `From<DeployError>` impl.
    #[test]
    fn no_other_variant_converts_to_either_conflict_object() {
        let every_variant = [
            (
                DeployError::PortAllocationConflict {
                    host: "host1".to_string(),
                    transport: ListenerTransport::Tcp,
                    port: 38_370,
                    owner: PortOwner {
                        component: "giganto".to_string(),
                        instance: 1,
                        listener_key: "ingest".to_string(),
                    },
                },
                Some("PortAllocationConflict"),
            ),
            (
                DeployError::HostPortOccupied {
                    listener_key: "ingest".to_string(),
                    transport: ListenerTransport::Udp,
                    port: 38_371,
                },
                Some("HostPortOccupied"),
            ),
            (
                DeployError::HostOccupancyUnavailable {
                    host: "host1".to_string(),
                    reason: "the host did not answer".to_string(),
                },
                None,
            ),
            (
                DeployError::RequestKey(RequestKeyError::MalformedRequestKey {
                    request_key: "not-a-uuid".to_string(),
                }),
                None,
            ),
            (
                DeployError::CleanupPending {
                    host: "host1".to_string(),
                    target: "giganto".to_string(),
                    instance: Some(1),
                    operation_id: OperationId::new("b0a6f6aa".to_string()),
                },
                None,
            ),
            // Where review's implementation lands an upstream database
            // failure: not a bind-address conflict.
            (
                DeployError::Other(anyhow::anyhow!("a database read failed")),
                None,
            ),
        ];

        for (error, expected) in &every_variant {
            assert_eq!(conflict_object(error), *expected, "{error}");
        }
    }
}
