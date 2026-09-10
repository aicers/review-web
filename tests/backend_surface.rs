//! Exercises the deploy surface from outside the crate.
//!
//! `aicers/review` is the real implementer, so the constructors and the field
//! visibility have to work from another crate. An integration test is compiled
//! as one, which a `#[cfg(test)]` module inside the crate is not: the readers
//! on `OperationId`, `JoinToken` and `HostOnboardingTicket` are `pub(crate)`
//! and are unreachable here on purpose, so the crate's own unit tests cover
//! that direction and this file covers the construction side.

use std::net::SocketAddr;

use async_trait::async_trait;
use review_database::{
    BuildSelector, ListenerBinding, ListenerTransport, PortOwner, RequestKeyError,
};
// `review_database::Lifecycle` and `review_protocol::types::node::Lifecycle`
// share a name, so nothing here glob-imports either module.
use review_protocol::types::node::{
    BootstrapMaterial, DeliveryMode, FailurePolicy, Lifecycle as ProtocolLifecycle, PackageState,
};
use review_web::backend::{
    BindAddrInput, BuildId, DeployError, DeployOutcome, HostOnboarder, HostOnboardingTicket,
    JoinToken, OperationId, PackageDeployer,
};

const TOKEN: &str = "s3cret-join-token";
const REQUEST_KEY: &str = "b0a6f6aa-7f7a-4b7c-9a3f-3f9b1a2c4d5e";

/// An implementer living outside the crate, exactly as `aicers/review` will.
struct OutsideDeployer {
    installed: Option<BuildId>,
}

#[async_trait]
impl PackageDeployer for OutsideDeployer {
    async fn install(
        &self,
        host: &str,
        target: &str,
        _selector: BuildSelector,
        _on_failure: FailurePolicy,
        bind_addrs: Option<Vec<BindAddrInput>>,
        request_key: &str,
    ) -> Result<(DeployOutcome, OperationId), DeployError> {
        // Reading `BindAddrInput`'s two public fields from another crate is the
        // point of the assertion, not the values themselves.
        if let Some(bind_addrs) = bind_addrs {
            for bind_addr in bind_addrs {
                if bind_addr.listener_key.is_empty() {
                    return Err(DeployError::HostPortOccupied {
                        listener_key: bind_addr.listener_key,
                        transport: ListenerTransport::Tcp,
                        port: bind_addr.addr.port(),
                    });
                }
            }
        }
        if request_key == "reused" {
            return Err(DeployError::RequestKey(RequestKeyError::RequestKeyReused {
                request_key: request_key.to_string(),
            }));
        }
        if target == "occupied" {
            return Err(DeployError::PortAllocationConflict {
                host: host.to_string(),
                transport: ListenerTransport::Udp,
                port: 38_371,
                owner: PortOwner {
                    component: "giganto".to_string(),
                    instance: 1,
                    listener_key: "ingest".to_string(),
                },
            });
        }
        Ok((
            DeployOutcome::Applied,
            OperationId::new(request_key.to_string()),
        ))
    }

    async fn update(
        &self,
        host: &str,
        target: &str,
        instance: Option<u32>,
        _selector: BuildSelector,
        _on_failure: FailurePolicy,
    ) -> Result<(DeployOutcome, OperationId), DeployError> {
        Err(DeployError::CleanupPending {
            host: host.to_string(),
            target: target.to_string(),
            instance,
            operation_id: OperationId::new(REQUEST_KEY.to_string()),
        })
    }

    async fn remove(
        &self,
        _host: &str,
        _target: &str,
        _instance: Option<u32>,
    ) -> Result<OperationId, DeployError> {
        // A bare `anyhow::Error` becomes `Other` through `?` rather than by
        // being named, which is the conversion review's implementation relies
        // on.
        Err(anyhow::anyhow!("roxyd did not answer"))?
    }

    async fn recommend_bind_addrs(
        &self,
        host: &str,
        _target: &str,
    ) -> Result<Vec<ListenerBinding>, DeployError> {
        Err(DeployError::HostOccupancyUnavailable {
            host: host.to_string(),
            reason: "roxyd did not answer".to_string(),
        })
    }

    async fn latest_build(&self, _target: &str) -> Result<Option<BuildId>, anyhow::Error> {
        Ok(self.installed.clone())
    }

    async fn package_status(
        &self,
        _host: &str,
        _target: &str,
        _instance: Option<u32>,
    ) -> Result<PackageState, anyhow::Error> {
        Ok(PackageState {
            version: "0.1.0".to_string(),
            commit: "0123456789abcdef".to_string(),
            lifecycle: ProtocolLifecycle::Running,
            bound_addrs: vec![],
        })
    }

    async fn read_version(
        &self,
        _host: &str,
        _target: &str,
        _instance: Option<u32>,
    ) -> Result<Option<BuildId>, anyhow::Error> {
        Ok(self.installed.clone())
    }

    async fn register(
        &self,
        service_name: &str,
        _host: &str,
        _instance: Option<u32>,
        mode: DeliveryMode,
    ) -> Result<BootstrapMaterial, anyhow::Error> {
        // The two modes are exhaustive: the arms below are the whole set, and a
        // third variant appearing upstream would fail to compile here.
        let role_id = match mode {
            DeliveryMode::LocalFile => format!("{service_name}-local"),
            DeliveryMode::RemoteBootstrap => format!("{service_name}-remote"),
        };
        Ok(BootstrapMaterial {
            role_id,
            wrapped_secret_id: "wrapped".to_string(),
            ca_anchor: vec![0x30, 0x82],
            expires_at: jiff::Timestamp::from_second(1_700_000_000)?,
        })
    }

    async fn deregister(
        &self,
        _service_name: &str,
        _host: &str,
        _instance: Option<u32>,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

struct OutsideOnboarder;

#[async_trait]
impl HostOnboarder for OutsideOnboarder {
    async fn onboard_host(
        &self,
        host: &str,
    ) -> Result<(HostOnboardingTicket, OperationId), anyhow::Error> {
        Ok((
            HostOnboardingTicket::new(
                JoinToken::new(TOKEN.to_string()),
                format!("roxyd join --host {host} --token <token>"),
                jiff::Timestamp::from_second(1_700_000_000)?,
            ),
            OperationId::new(REQUEST_KEY.to_string()),
        ))
    }
}

fn deployer(installed: Option<BuildId>) -> Box<dyn PackageDeployer> {
    Box::new(OutsideDeployer { installed })
}

/// `BuildId` and `BindAddrInput` are plain data carriers, so another crate
/// writes their fields directly.
#[test]
fn the_data_carriers_are_constructible_field_by_field() {
    let build = BuildId {
        package_id: "giganto".to_string(),
        version: "0.1.0".to_string(),
        commit: "0123456789abcdef".to_string(),
    };
    assert_eq!(build.package_id, "giganto");
    assert_eq!(build.version, "0.1.0");
    assert_eq!(build.commit, "0123456789abcdef");

    let addr: SocketAddr = "127.0.0.1:38370".parse().expect("a literal address");
    let bind_addr = BindAddrInput {
        listener_key: "ingest".to_string(),
        addr,
    };
    assert_eq!(bind_addr.listener_key, "ingest");
    assert_eq!(bind_addr.addr, addr);
}

/// Both traits are object-safe from outside the crate too.
#[test]
fn both_traits_are_boxable_from_another_crate() {
    let _deployer = deployer(None);
    let _onboarder: Box<dyn HostOnboarder> = Box::new(OutsideOnboarder);
}

#[tokio::test]
async fn an_outside_implementation_reports_an_installed_build() {
    let installed = BuildId {
        package_id: "giganto".to_string(),
        version: "0.1.0".to_string(),
        commit: "0123456789abcdef".to_string(),
    };
    let deployer = deployer(Some(installed.clone()));
    assert_eq!(
        deployer
            .read_version("host1", "giganto", Some(1))
            .await
            .expect("the stub answers"),
        Some(installed.clone())
    );
    assert_eq!(
        deployer
            .latest_build("giganto")
            .await
            .expect("the stub answers"),
        Some(installed)
    );
}

/// A host with nothing installed answers `None`, with no placeholder version or
/// commit anywhere on the path.
#[tokio::test]
async fn an_outside_implementation_reports_an_absent_build_as_none() {
    let deployer = deployer(None);
    assert_eq!(
        deployer
            .read_version("host1", "giganto", Some(1))
            .await
            .expect("the stub answers"),
        None
    );
}

#[tokio::test]
async fn every_named_variant_is_constructible_from_another_crate() {
    let deployer = deployer(None);

    let error = deployer
        .install(
            "host1",
            "occupied",
            BuildSelector::Version("0.1.0".to_string()),
            FailurePolicy::Rollback,
            None,
            REQUEST_KEY,
        )
        .await
        .map(|_| ())
        .expect_err("the target is occupied");
    assert!(matches!(
        error,
        DeployError::PortAllocationConflict { port: 38_371, .. }
    ));

    let error = deployer
        .install(
            "host1",
            "giganto",
            BuildSelector::Commit("0123456789abcdef".to_string()),
            FailurePolicy::Hold,
            Some(vec![BindAddrInput {
                listener_key: String::new(),
                addr: "127.0.0.1:38370".parse().expect("a literal address"),
            }]),
            REQUEST_KEY,
        )
        .await
        .map(|_| ())
        .expect_err("the listener key is empty");
    assert!(matches!(
        error,
        DeployError::HostPortOccupied { port: 38_370, .. }
    ));

    let error = deployer
        .install(
            "host1",
            "giganto",
            BuildSelector::Version("0.1.0".to_string()),
            FailurePolicy::Hold,
            None,
            "reused",
        )
        .await
        .map(|_| ())
        .expect_err("the request key was reused");
    assert!(matches!(error, DeployError::RequestKey(_)));

    let error = deployer
        .update(
            "host1",
            "giganto",
            Some(1),
            BuildSelector::Version("0.2.0".to_string()),
            FailurePolicy::Rollback,
        )
        .await
        .map(|_| ())
        .expect_err("a teardown is owed");
    assert!(matches!(
        error,
        DeployError::CleanupPending {
            instance: Some(1),
            ..
        }
    ));

    let error = deployer
        .recommend_bind_addrs("host1", "giganto")
        .await
        .map(|_| ())
        .expect_err("the host could not be read");
    assert!(matches!(
        error,
        DeployError::HostOccupancyUnavailable { .. }
    ));

    let error = deployer
        .remove("host1", "giganto", Some(1))
        .await
        .map(|_| ())
        .expect_err("roxyd did not answer");
    assert!(matches!(error, DeployError::Other(_)));
}

/// A successful install pairs the disposition with the operation's identity,
/// and `DeployOutcome` has exactly the two variants and carries no id.
#[tokio::test]
async fn an_operation_pairs_its_disposition_with_its_identity() {
    let (outcome, operation_id) = deployer(None)
        .install(
            "host1",
            "giganto",
            BuildSelector::Version("0.1.0".to_string()),
            FailurePolicy::Rollback,
            None,
            REQUEST_KEY,
        )
        .await
        .expect("the stub accepts the install");

    let named = match outcome {
        DeployOutcome::Applied => "applied",
        DeployOutcome::Accepted => "accepted",
    };
    assert_eq!(named, "applied");
    // The identity is the paired value, not something read off the outcome.
    assert_eq!(format!("{operation_id}"), REQUEST_KEY);
}

#[tokio::test]
async fn both_delivery_modes_are_namable_and_there_is_no_third() {
    let deployer = deployer(None);
    for (mode, expected) in [
        (DeliveryMode::LocalFile, "giganto-local"),
        (DeliveryMode::RemoteBootstrap, "giganto-remote"),
    ] {
        let material = deployer
            .register("giganto", "host1", Some(1), mode)
            .await
            .expect("the stub mints material");
        assert_eq!(material.role_id, expected);
    }
}

/// The ticket's token stays redacted in `Debug` when another crate renders it.
#[tokio::test]
async fn the_onboarding_ticket_redacts_its_token() {
    let (ticket, operation_id) = OutsideOnboarder
        .onboard_host("host1")
        .await
        .expect("the stub mints a ticket");

    let rendered = format!("{ticket:?}");
    assert!(!rendered.contains(TOKEN), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert_eq!(operation_id.to_string(), REQUEST_KEY);
}
