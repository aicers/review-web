//! Exercises the `EndpointManager` surface from outside the crate.
//!
//! `aicers/review` is the real implementer, so the trait, its argument types
//! and every case of its error have to be reachable and constructible from
//! another crate. An integration test is compiled as one; the mutations that
//! render the errors are covered by the crate's own unit tests.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use review_database::{SentaEndpointDeletionState, SentaEndpointError};
use review_web::backend::{
    ActiveListRefusalReason, EndpointDocumentOutcome, EndpointEnrollmentAttemptKey,
    EndpointEnrollmentResolution, EndpointManager, EndpointManagerError, EndpointRefusal,
    EndpointRefusalCode, InvalidEndpointRefusalCode, SharedEndpointManager,
};
use uuid::Uuid;

const CUSTOMER_ID: u32 = 7;
const COMMAND_ID: Uuid = Uuid::from_u128(0xa1b2_c3d4_e5f6_4a7b_8c9d_0e1f_2a3b_4c5d);
const APPLIED_VERSION: u64 = 12;

/// An implementer living outside the crate, as `aicers/review` will, that
/// refuses as review-database refuses and passes those refusals on with `?`.
#[derive(Default)]
struct OutsideEndpointManager {
    deleted_customers: Mutex<Vec<u32>>,
}

/// Stands in for a review-database write that refuses a customer with a data
/// deletion job.
fn write_for(customer_id: u32) -> Result<(), SentaEndpointError> {
    match customer_id {
        1 => Err(SentaEndpointError::CustomerDeletion {
            customer_id,
            state: SentaEndpointDeletionState::InProgress,
        }),
        2 => Err(SentaEndpointError::CustomerDeletion {
            customer_id,
            state: SentaEndpointDeletionState::AlreadyDeleted,
        }),
        3 => Err(SentaEndpointError::CustomerExists { customer_id }),
        _ => Ok(()),
    }
}

#[async_trait]
impl EndpointManager for OutsideEndpointManager {
    async fn register_customer(
        &self,
        customer_id: u32,
        _customer_endpoint_id: Uuid,
        _key_name: &str,
        _install_id: &str,
        _keyset: &str,
    ) -> Result<(), EndpointManagerError> {
        if customer_id == 4 {
            return Err(EndpointRefusal::TrustUnreadable { customer_id }.into());
        }
        write_for(customer_id)?;
        Ok(())
    }

    async fn register_install(
        &self,
        install_id: &str,
        _recovery_key: &str,
        version: u64,
    ) -> Result<(), EndpointManagerError> {
        if version == 0 {
            return Err(anyhow::anyhow!("install {install_id:?} has no key version 0").into());
        }
        Ok(())
    }

    async fn set_active_list(&self, update: Vec<u8>) -> Result<u64, EndpointManagerError> {
        match update.as_slice() {
            [] => Err(EndpointManagerError::ActiveListRefused {
                reason: ActiveListRefusalReason::Unknown,
                current_version: None,
            }),
            [0] => Err(EndpointManagerError::ActiveListRefused {
                reason: ActiveListRefusalReason::VersionMismatch,
                current_version: Some(APPLIED_VERSION),
            }),
            _ => Ok(APPLIED_VERSION),
        }
    }

    async fn put_documents(
        &self,
        documents: Vec<String>,
    ) -> Result<Vec<EndpointDocumentOutcome>, EndpointManagerError> {
        documents
            .iter()
            .map(|document| {
                Ok(match document.as_str() {
                    "ok" => EndpointDocumentOutcome::Accepted,
                    "unreadable" => {
                        EndpointDocumentOutcome::Refused(EndpointRefusal::TrustUnreadable {
                            customer_id: CUSTOMER_ID,
                        })
                    }
                    code => EndpointDocumentOutcome::Refused(EndpointRefusal::Code(
                        EndpointRefusalCode::new(code)
                            .map_err(|error| EndpointManagerError::Other(error.into()))?,
                    )),
                })
            })
            .collect()
    }

    async fn resolve_enrollment(
        &self,
        attempt: EndpointEnrollmentAttemptKey,
        resolution: EndpointEnrollmentResolution,
    ) -> Result<(), EndpointManagerError> {
        if attempt.spki_hash == [0; 32] {
            return Err(refused_with("UNKNOWN_ATTEMPT"));
        }
        match resolution {
            EndpointEnrollmentResolution::Approve(jws) if jws.is_empty() => {
                Err(refused_with("BAD_SIGNATURE"))
            }
            EndpointEnrollmentResolution::Approve(_)
            | EndpointEnrollmentResolution::Pending(_)
            | EndpointEnrollmentResolution::Reject(_) => Ok(()),
        }
    }

    async fn submit_command(&self, _command: &str) -> Result<Uuid, EndpointManagerError> {
        Ok(COMMAND_ID)
    }

    async fn customer_endpoint_data_deleted(
        &self,
        customer_id: u32,
    ) -> Result<(), EndpointManagerError> {
        self.deleted_customers
            .lock()
            .expect("the deleted customers mutex")
            .push(customer_id);
        Ok(())
    }
}

/// Builds a refusal with `REview`'s own code, failing internally if the code
/// is not upper snake case.
fn refused_with(code: &str) -> EndpointManagerError {
    match EndpointRefusalCode::new(code) {
        Ok(code) => EndpointRefusal::Code(code).into(),
        Err(error) => EndpointManagerError::Other(error.into()),
    }
}

fn shared() -> (Arc<OutsideEndpointManager>, SharedEndpointManager) {
    let manager = Arc::new(OutsideEndpointManager::default());
    let shared: SharedEndpointManager = manager.clone();
    (manager, shared)
}

#[tokio::test]
async fn review_database_deletion_refusals_pass_on_with_the_question_mark() {
    let (_, manager) = shared();
    let register = |customer_id| {
        let manager = Arc::clone(&manager);
        async move {
            manager
                .register_customer(customer_id, Uuid::nil(), "key", "install", "h.p.s")
                .await
        }
    };
    assert!(matches!(
        register(1).await,
        Err(EndpointManagerError::Refused(
            EndpointRefusal::CustomerDeletionInProgress { customer_id: 1 }
        ))
    ));
    assert!(matches!(
        register(2).await,
        Err(EndpointManagerError::Refused(
            EndpointRefusal::CustomerDataAlreadyDeleted { customer_id: 2 }
        ))
    ));
    let Err(EndpointManagerError::Other(error)) = register(3).await else {
        panic!("another review-database error is an internal failure");
    };
    assert_eq!(
        error.to_string(),
        "senta endpoint customer 3 already exists"
    );
    assert!(matches!(
        register(4).await,
        Err(EndpointManagerError::Refused(
            EndpointRefusal::TrustUnreadable { customer_id: 4 }
        ))
    ));
    assert!(register(CUSTOMER_ID).await.is_ok());
}

#[tokio::test]
async fn every_error_case_is_built_from_another_crate() {
    let (_, manager) = shared();
    let errors = [
        EndpointManagerError::ActiveListRefused {
            reason: ActiveListRefusalReason::VersionNotAdvanced,
            current_version: Some(3),
        },
        EndpointManagerError::ActiveListRefused {
            reason: ActiveListRefusalReason::Unknown,
            current_version: None,
        },
        EndpointRefusal::CustomerDeletionInProgress {
            customer_id: CUSTOMER_ID,
        }
        .into(),
        EndpointRefusal::CustomerDataAlreadyDeleted {
            customer_id: CUSTOMER_ID,
        }
        .into(),
        EndpointRefusal::TrustUnreadable {
            customer_id: CUSTOMER_ID,
        }
        .into(),
        EndpointRefusal::Code(
            EndpointRefusalCode::new("EPOCH_MISMATCH").expect("upper snake case"),
        )
        .into(),
        EndpointManagerError::NotSupported,
        anyhow::anyhow!("internal").into(),
    ];
    let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(
        messages,
        [
            "the active list update was refused: VERSION_NOT_ADVANCED",
            "the active list update was refused: UNKNOWN",
            "the data deletion of customer 7 is unfinished",
            "the data of customer 7 was already deleted",
            "the endpoint trust state of customer 7 cannot be read",
            "refused by REview: EPOCH_MISMATCH",
            "this REview does not support Clumit Endpoint",
            "internal",
        ]
    );
    for (reason, code) in [
        (ActiveListRefusalReason::VersionMismatch, "VERSION_MISMATCH"),
        (
            ActiveListRefusalReason::VersionNotAdvanced,
            "VERSION_NOT_ADVANCED",
        ),
        (ActiveListRefusalReason::UnknownReason, "UNKNOWN_REASON"),
        (
            ActiveListRefusalReason::RepeatedEndpoint,
            "REPEATED_ENDPOINT",
        ),
        (ActiveListRefusalReason::DuplicateSpki, "DUPLICATE_SPKI"),
        (ActiveListRefusalReason::Unknown, "UNKNOWN"),
    ] {
        assert_eq!(reason.code(), code);
    }
    assert_eq!(
        EndpointRefusalCode::new("epoch_mismatch"),
        Err(InvalidEndpointRefusalCode("epoch_mismatch".to_string()))
    );

    assert!(matches!(
        manager.register_install("install", "{}", 0).await,
        Err(EndpointManagerError::Other(_))
    ));
    assert!(manager.register_install("install", "{}", 1).await.is_ok());
}

#[tokio::test]
async fn every_method_is_called_through_the_shared_trait_object() {
    let (outside, manager) = shared();
    assert_eq!(
        manager.set_active_list(vec![1, 2]).await.ok(),
        Some(APPLIED_VERSION)
    );
    assert!(matches!(
        manager.set_active_list(vec![0]).await,
        Err(EndpointManagerError::ActiveListRefused {
            reason: ActiveListRefusalReason::VersionMismatch,
            current_version: Some(APPLIED_VERSION),
        })
    ));
    assert!(matches!(
        manager.set_active_list(Vec::new()).await,
        Err(EndpointManagerError::ActiveListRefused {
            reason: ActiveListRefusalReason::Unknown,
            current_version: None,
        })
    ));

    let outcomes = manager
        .put_documents(vec![
            "ok".to_string(),
            "unreadable".to_string(),
            "UNKNOWN_KID".to_string(),
        ])
        .await
        .expect("every document has an outcome");
    assert_eq!(
        outcomes,
        [
            EndpointDocumentOutcome::Accepted,
            EndpointDocumentOutcome::Refused(EndpointRefusal::TrustUnreadable {
                customer_id: CUSTOMER_ID
            }),
            EndpointDocumentOutcome::Refused(EndpointRefusal::Code(
                EndpointRefusalCode::new("UNKNOWN_KID").expect("upper snake case")
            )),
        ]
    );
    let Some(EndpointDocumentOutcome::Refused(EndpointRefusal::Code(code))) = outcomes.get(2)
    else {
        panic!("the third document is refused with a code");
    };
    assert_eq!(code.as_str(), "UNKNOWN_KID");
    assert_eq!(code.to_string(), "UNKNOWN_KID");

    let attempt = EndpointEnrollmentAttemptKey {
        spki_hash: [1; 32],
        attempt_id: Uuid::nil(),
    };
    for resolution in [
        EndpointEnrollmentResolution::Approve("r.e.s".to_string()),
        EndpointEnrollmentResolution::Pending("awaiting_approval".to_string()),
        EndpointEnrollmentResolution::Reject("denied".to_string()),
    ] {
        assert!(
            manager
                .resolve_enrollment(attempt, resolution)
                .await
                .is_ok()
        );
    }
    assert!(matches!(
        manager
            .resolve_enrollment(attempt, EndpointEnrollmentResolution::Approve(String::new()))
            .await,
        Err(EndpointManagerError::Refused(EndpointRefusal::Code(code))) if code.as_str() == "BAD_SIGNATURE"
    ));
    assert!(matches!(
        manager
            .resolve_enrollment(
                EndpointEnrollmentAttemptKey {
                    spki_hash: [0; 32],
                    attempt_id: attempt.attempt_id,
                },
                EndpointEnrollmentResolution::Reject("denied".to_string()),
            )
            .await,
        Err(EndpointManagerError::Refused(EndpointRefusal::Code(code))) if code.as_str() == "UNKNOWN_ATTEMPT"
    ));
    assert!(matches!(
        refused_with("not upper snake case"),
        EndpointManagerError::Other(_)
    ));

    assert_eq!(manager.submit_command("c.m.d").await.ok(), Some(COMMAND_ID));

    manager
        .customer_endpoint_data_deleted(CUSTOMER_ID)
        .await
        .expect("the in-memory state is dropped");
    assert_eq!(
        *outside
            .deleted_customers
            .lock()
            .expect("the deleted customers mutex"),
        [CUSTOMER_ID]
    );
}
