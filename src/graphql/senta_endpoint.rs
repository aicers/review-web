//! The Clumit Endpoint (`senta`) write mutations.
//!
//! Each mutation decodes its arguments, refusing malformed input before the
//! [`EndpointManager`](crate::backend::EndpointManager) is called, and passes
//! them to the manager, which verifies the documents, keys and list updates.
//! Every mutation is for a System Administrator only; a System Administrator
//! is unscoped, so no customer-scope check follows the role guard.
//!
//! An [`EndpointManagerError`] crosses GraphQL as an error whose
//! `extensions.code` names the refusal: the active list refusal's reason, with
//! `extensions.version` set to `REview`'s current version as a decimal string
//! or `null`; `CUSTOMER_DELETION_IN_PROGRESS` and
//! `CUSTOMER_DATA_ALREADY_DELETED` for a customer with a deletion job;
//! `ENDPOINT_TRUST_UNREADABLE`; `REview`'s own refusal code; and
//! `ENDPOINT_NOT_SUPPORTED`. Any other failure is an error with no code.

use async_graphql::{
    Context, ErrorExtensions, ID, Object, OneofObject, Result, SimpleObject, StringNumber, Value,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tracing::info;
use uuid::Uuid;

use super::customer_deletion_guard::CUSTOMER_DELETION_IN_PROGRESS;
use super::{Role, RoleGuard};
use crate::backend::{
    EndpointDocumentOutcome, EndpointEnrollmentAttemptKey, EndpointEnrollmentResolution,
    EndpointManagerError, EndpointRefusal, SharedEndpointManager,
};
use crate::customer_data_deletion::CUSTOMER_DATA_ALREADY_DELETED;
use crate::info_with_caller;

/// The `extensions.code` of a request refused because the customer's endpoint
/// trust state cannot be read.
const ENDPOINT_TRUST_UNREADABLE: &str = "ENDPOINT_TRUST_UNREADABLE";
/// The `extensions.code` of a request this `REview` does not support.
const ENDPOINT_NOT_SUPPORTED: &str = "ENDPOINT_NOT_SUPPORTED";
/// The length of an SPKI hash in hexadecimal characters.
const SPKI_HASH_HEX_LEN: usize = 64;

/// The outcome of one document of `putEndpointDocuments`.
#[derive(Debug, SimpleObject)]
struct SentaEndpointDocumentResult {
    /// The document's position in the input, from 0.
    index: i32,
    /// Whether the document was accepted.
    accepted: bool,
    /// The code of the refusal; `null` when the document was accepted.
    reason: Option<String>,
}

/// How an enrollment attempt is resolved: exactly one of `approve`, `pending`
/// and `reject`.
#[derive(Debug, OneofObject)]
enum SentaEndpointEnrollmentResolution {
    /// Approves the attempt with the enrollment-result JWS.
    Approve(String),
    /// Leaves the attempt pending, with a reason tag such as
    /// `awaiting_approval` or `license_pending`.
    Pending(String),
    /// Rejects the attempt, with a reason tag such as `denied` or
    /// `bad_token`.
    Reject(String),
}

impl From<SentaEndpointEnrollmentResolution> for EndpointEnrollmentResolution {
    fn from(resolution: SentaEndpointEnrollmentResolution) -> Self {
        match resolution {
            SentaEndpointEnrollmentResolution::Approve(jws) => Self::Approve(jws),
            SentaEndpointEnrollmentResolution::Pending(tag) => Self::Pending(tag),
            SentaEndpointEnrollmentResolution::Reject(tag) => Self::Reject(tag),
        }
    }
}

#[derive(Default)]
pub(super) struct SentaEndpointMutation;

#[Object]
impl SentaEndpointMutation {
    /// Registers a customer for Clumit Endpoint with its trust anchor: the
    /// customer endpoint id, the customer key name, the install the customer
    /// belongs to and the first keyset JWS.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn register_endpoint_customer(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        customer_endpoint_id: ID,
        key_name: String,
        install_id: String,
        keyset: String,
    ) -> Result<bool> {
        let customer_id = parse_customer_id(&customer_id)?;
        let customer_endpoint_id = parse_uuid("customerEndpointId", &customer_endpoint_id)?;
        info_with_caller!(
            ctx,
            "Received a request to register customer {customer_id} for Clumit Endpoint"
        );
        manager(ctx)?
            .register_customer(
                customer_id,
                customer_endpoint_id,
                &key_name,
                &install_id,
                &keyset,
            )
            .await
            .map_err(graphql_error)?;
        Ok(true)
    }

    /// Registers a Clumit Endpoint install with its first recovery public key,
    /// a JWK as JSON text, and that key's version.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn register_endpoint_install(
        &self,
        ctx: &Context<'_>,
        install_id: String,
        recovery_key: String,
        version: StringNumber<u64>,
    ) -> Result<bool> {
        info_with_caller!(
            ctx,
            "Received a request to register Clumit Endpoint install {install_id:?}"
        );
        manager(ctx)?
            .register_install(&install_id, &recovery_key, version.0)
            .await
            .map_err(graphql_error)?;
        Ok(true)
    }

    /// Applies an active list update and returns the version applied.
    ///
    /// `update` is the CBOR bytes of senta-protocol's `ListUpdate::encode` as
    /// standard padded base64; a full list and a diff are told apart inside
    /// it.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn set_endpoint_active_list(
        &self,
        ctx: &Context<'_>,
        update: String,
    ) -> Result<StringNumber<u64>> {
        let update = STANDARD
            .decode(&update)
            .map_err(|_| async_graphql::Error::new("update is not standard padded base64"))?;
        info_with_caller!(
            ctx,
            "Received a request to set the Clumit Endpoint active list"
        );
        let version = manager(ctx)?
            .set_active_list(update)
            .await
            .map_err(graphql_error)?;
        Ok(StringNumber(version))
    }

    /// Puts signed documents, and returns one result per document in input
    /// order.
    ///
    /// A refused document fails neither the call nor another document; its
    /// `reason` is the code of its refusal.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn put_endpoint_documents(
        &self,
        ctx: &Context<'_>,
        documents: Vec<String>,
    ) -> Result<Vec<SentaEndpointDocumentResult>> {
        info_with_caller!(
            ctx,
            "Received a request to put {} Clumit Endpoint documents",
            documents.len()
        );
        let count = documents.len();
        let outcomes = manager(ctx)?
            .put_documents(documents)
            .await
            .map_err(graphql_error)?;
        if outcomes.len() != count {
            return Err(async_graphql::Error::new(format!(
                "the endpoint manager returned {} outcomes for {count} documents",
                outcomes.len()
            )));
        }
        outcomes
            .into_iter()
            .enumerate()
            .map(|(index, outcome)| {
                let index = i32::try_from(index).map_err(|_| {
                    async_graphql::Error::new(format!("document index {index} is out of range"))
                })?;
                Ok(match outcome {
                    EndpointDocumentOutcome::Accepted => SentaEndpointDocumentResult {
                        index,
                        accepted: true,
                        reason: None,
                    },
                    EndpointDocumentOutcome::Refused(refusal) => SentaEndpointDocumentResult {
                        index,
                        accepted: false,
                        reason: Some(refusal_code(&refusal).to_string()),
                    },
                })
            })
            .collect()
    }

    /// Resolves an enrollment attempt, keyed by the SPKI hash of the
    /// enrolling endpoint (64 lowercase hexadecimal characters) and the
    /// attempt id.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn resolve_endpoint_enrollment(
        &self,
        ctx: &Context<'_>,
        spki_hash: String,
        attempt_id: ID,
        resolution: SentaEndpointEnrollmentResolution,
    ) -> Result<bool> {
        let attempt = EndpointEnrollmentAttemptKey {
            spki_hash: parse_spki_hash(&spki_hash)?,
            attempt_id: parse_uuid("attemptId", &attempt_id)?,
        };
        info_with_caller!(
            ctx,
            "Received a request to resolve Clumit Endpoint enrollment attempt {}",
            attempt.attempt_id
        );
        manager(ctx)?
            .resolve_enrollment(attempt, resolution.into())
            .await
            .map_err(graphql_error)?;
        Ok(true)
    }

    /// Submits a signed command and returns its command id.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn submit_endpoint_command(&self, ctx: &Context<'_>, command: String) -> Result<ID> {
        info_with_caller!(
            ctx,
            "Received a request to submit a Clumit Endpoint command"
        );
        let command_id = manager(ctx)?
            .submit_command(&command)
            .await
            .map_err(graphql_error)?;
        Ok(ID(command_id.hyphenated().to_string()))
    }
}

fn manager<'a>(ctx: &Context<'a>) -> Result<&'a SharedEndpointManager> {
    ctx.data::<SharedEndpointManager>()
}

fn parse_customer_id(id: &ID) -> Result<u32> {
    id.as_str()
        .parse::<u32>()
        .map_err(|_| async_graphql::Error::new(format!("invalid customer id: {:?}", id.as_str())))
}

fn parse_uuid(argument: &str, id: &ID) -> Result<Uuid> {
    Uuid::try_parse(id.as_str()).map_err(|_| {
        async_graphql::Error::new(format!("{argument} is not a UUID: {:?}", id.as_str()))
    })
}

/// Decodes an SPKI hash given as 64 lowercase hexadecimal characters.
fn parse_spki_hash(text: &str) -> Result<[u8; 32]> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }

    let invalid = || {
        async_graphql::Error::new(format!(
            "spkiHash is not {SPKI_HASH_HEX_LEN} lowercase hexadecimal characters"
        ))
    };
    if text.len() != SPKI_HASH_HEX_LEN {
        return Err(invalid());
    }
    let mut hash = [0_u8; 32];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (byte, &[high, low]) in hash.iter_mut().zip(pairs) {
        *byte = (nibble(high).ok_or_else(invalid)? << 4) | nibble(low).ok_or_else(invalid)?;
    }
    Ok(hash)
}

/// Returns the code a refusal crosses GraphQL with.
fn refusal_code(refusal: &EndpointRefusal) -> &str {
    match refusal {
        EndpointRefusal::CustomerDeletionInProgress { .. } => CUSTOMER_DELETION_IN_PROGRESS,
        EndpointRefusal::CustomerDataAlreadyDeleted { .. } => CUSTOMER_DATA_ALREADY_DELETED,
        EndpointRefusal::TrustUnreadable { .. } => ENDPOINT_TRUST_UNREADABLE,
        EndpointRefusal::Code(code) => code.as_str(),
    }
}

fn graphql_error(error: EndpointManagerError) -> async_graphql::Error {
    let with_code = |message: String, code: &str| {
        async_graphql::Error::new(message).extend_with(|_, extensions| {
            extensions.set("code", code);
        })
    };
    match error {
        EndpointManagerError::ActiveListRefused {
            reason,
            current_version,
        } => {
            let message = error.to_string();
            async_graphql::Error::new(message).extend_with(|_, extensions| {
                extensions.set("code", reason.code());
                extensions.set(
                    "version",
                    current_version.map_or(Value::Null, |version| Value::from(version.to_string())),
                );
            })
        }
        EndpointManagerError::Refused(ref refusal) => {
            with_code(error.to_string(), refusal_code(refusal))
        }
        EndpointManagerError::NotSupported => with_code(error.to_string(), ENDPOINT_NOT_SUPPORTED),
        EndpointManagerError::Other(error) => async_graphql::Error::new(format!("{error:#}")),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_graphql::Value;
    use async_trait::async_trait;
    use review_database::{Role, SentaEndpointDeletionState, SentaEndpointError};
    use uuid::Uuid;

    use super::{ENDPOINT_NOT_SUPPORTED, ENDPOINT_TRUST_UNREADABLE};
    use crate::backend::{
        ActiveListRefusalReason, EndpointDocumentOutcome, EndpointEnrollmentAttemptKey,
        EndpointEnrollmentResolution, EndpointManager, EndpointManagerError, EndpointRefusal,
        EndpointRefusalCode, SharedEndpointManager,
    };
    use crate::graphql::TestSchema;
    use crate::graphql::logging_test_support::CapturedEvents;

    const CUSTOMER_ENDPOINT_ID: &str = "0b5d3c1e-7a4f-4e8b-9c2d-1f3a5b7c9d0e";
    const ATTEMPT_ID: &str = "6f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0b";
    const COMMAND_ID: &str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    const SPKI_HASH: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const APPLIED_VERSION: u64 = 18_446_744_073_709_551_615;

    /// A mutation with arguments that decode, the field it answers in, and
    /// the call the manager receives for it.
    struct Case {
        query: &'static str,
        field: &'static str,
        call: Call,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        RegisterCustomer {
            customer_id: u32,
            customer_endpoint_id: Uuid,
            key_name: String,
            install_id: String,
            keyset: String,
        },
        RegisterInstall {
            install_id: String,
            recovery_key: String,
            version: u64,
        },
        SetActiveList(Vec<u8>),
        PutDocuments(Vec<String>),
        ResolveEnrollment(EndpointEnrollmentAttemptKey, EndpointEnrollmentResolution),
        SubmitCommand(String),
        CustomerEndpointDataDeleted(u32),
    }

    type ErrorFactory = Box<dyn Fn() -> EndpointManagerError + Send + Sync>;

    /// A manager that records every call and answers with `error`, or
    /// succeeds when there is none.
    #[derive(Default)]
    struct FakeEndpointManager {
        calls: Mutex<Vec<Call>>,
        error: Option<ErrorFactory>,
        outcomes: Vec<EndpointDocumentOutcome>,
    }

    impl FakeEndpointManager {
        fn failing(error: impl Fn() -> EndpointManagerError + Send + Sync + 'static) -> Self {
            Self {
                error: Some(Box::new(error)),
                ..Self::default()
            }
        }

        fn with_outcomes(outcomes: Vec<EndpointDocumentOutcome>) -> Self {
            Self {
                outcomes,
                ..Self::default()
            }
        }

        fn record(&self, call: Call) -> Result<(), EndpointManagerError> {
            self.calls.lock().unwrap().push(call);
            match &self.error {
                Some(error) => Err(error()),
                None => Ok(()),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl EndpointManager for FakeEndpointManager {
        async fn register_customer(
            &self,
            customer_id: u32,
            customer_endpoint_id: Uuid,
            key_name: &str,
            install_id: &str,
            keyset: &str,
        ) -> Result<(), EndpointManagerError> {
            self.record(Call::RegisterCustomer {
                customer_id,
                customer_endpoint_id,
                key_name: key_name.to_string(),
                install_id: install_id.to_string(),
                keyset: keyset.to_string(),
            })
        }

        async fn register_install(
            &self,
            install_id: &str,
            recovery_key: &str,
            version: u64,
        ) -> Result<(), EndpointManagerError> {
            self.record(Call::RegisterInstall {
                install_id: install_id.to_string(),
                recovery_key: recovery_key.to_string(),
                version,
            })
        }

        async fn set_active_list(&self, update: Vec<u8>) -> Result<u64, EndpointManagerError> {
            self.record(Call::SetActiveList(update))?;
            Ok(APPLIED_VERSION)
        }

        async fn put_documents(
            &self,
            documents: Vec<String>,
        ) -> Result<Vec<EndpointDocumentOutcome>, EndpointManagerError> {
            self.record(Call::PutDocuments(documents))?;
            Ok(self.outcomes.clone())
        }

        async fn resolve_enrollment(
            &self,
            attempt: EndpointEnrollmentAttemptKey,
            resolution: EndpointEnrollmentResolution,
        ) -> Result<(), EndpointManagerError> {
            self.record(Call::ResolveEnrollment(attempt, resolution))
        }

        async fn submit_command(&self, command: &str) -> Result<Uuid, EndpointManagerError> {
            self.record(Call::SubmitCommand(command.to_string()))?;
            Ok(Uuid::parse_str(COMMAND_ID).unwrap())
        }

        async fn customer_endpoint_data_deleted(
            &self,
            customer_id: u32,
        ) -> Result<(), EndpointManagerError> {
            self.record(Call::CustomerEndpointDataDeleted(customer_id))
        }
    }

    fn spki_hash() -> [u8; 32] {
        let mut hash = [0_u8; 32];
        for (byte, value) in hash.iter_mut().zip(0_u8..) {
            *byte = value;
        }
        hash
    }

    fn attempt() -> EndpointEnrollmentAttemptKey {
        EndpointEnrollmentAttemptKey {
            spki_hash: spki_hash(),
            attempt_id: Uuid::parse_str(ATTEMPT_ID).unwrap(),
        }
    }

    /// One call of each mutation, with arguments that decode.
    fn cases() -> Vec<Case> {
        vec![
            Case {
                query: r#"mutation { registerEndpointCustomer(customerId: "7", customerEndpointId: "0b5d3c1e-7a4f-4e8b-9c2d-1f3a5b7c9d0e", keyName: "customer-key-1", installId: "install-1", keyset: "h.p.s") }"#,
                field: "registerEndpointCustomer",
                call: Call::RegisterCustomer {
                    customer_id: 7,
                    customer_endpoint_id: Uuid::parse_str(CUSTOMER_ENDPOINT_ID).unwrap(),
                    key_name: "customer-key-1".to_string(),
                    install_id: "install-1".to_string(),
                    keyset: "h.p.s".to_string(),
                },
            },
            Case {
                query: r#"mutation { registerEndpointInstall(installId: "install-1", recoveryKey: "{\"kty\":\"OKP\"}", version: "18446744073709551615") }"#,
                field: "registerEndpointInstall",
                call: Call::RegisterInstall {
                    install_id: "install-1".to_string(),
                    recovery_key: r#"{"kty":"OKP"}"#.to_string(),
                    version: u64::MAX,
                },
            },
            Case {
                query: r#"mutation { setEndpointActiveList(update: "AAEC/w==") }"#,
                field: "setEndpointActiveList",
                call: Call::SetActiveList(vec![0, 1, 2, 255]),
            },
            Case {
                query: r#"mutation { putEndpointDocuments(documents: ["d.o.c"]) { index accepted reason } }"#,
                field: "putEndpointDocuments",
                call: Call::PutDocuments(vec!["d.o.c".to_string()]),
            },
            Case {
                query: r#"mutation { resolveEndpointEnrollment(spkiHash: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", attemptId: "6f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0b", resolution: { approve: "r.e.s" }) }"#,
                field: "resolveEndpointEnrollment",
                call: Call::ResolveEnrollment(
                    attempt(),
                    EndpointEnrollmentResolution::Approve("r.e.s".to_string()),
                ),
            },
            Case {
                query: r#"mutation { submitEndpointCommand(command: "c.m.d") }"#,
                field: "submitEndpointCommand",
                call: Call::SubmitCommand("c.m.d".to_string()),
            },
        ]
    }

    async fn execute_as_system_admin(
        schema: &TestSchema,
        query: &str,
        manager: &Arc<FakeEndpointManager>,
    ) -> async_graphql::Response {
        let shared: SharedEndpointManager = manager.clone();
        schema
            .execute_as_system_admin_with_data(query, shared)
            .await
    }

    fn codes(response: &async_graphql::Response) -> Vec<Option<Value>> {
        response
            .errors
            .iter()
            .map(|error| {
                error
                    .extensions
                    .as_ref()
                    .and_then(|extensions| extensions.get("code"))
                    .cloned()
            })
            .collect()
    }

    #[tokio::test]
    async fn system_administrator_reaches_the_manager_with_decoded_arguments() {
        let schema = TestSchema::new().await;
        for case in cases() {
            let manager = Arc::new(FakeEndpointManager::with_outcomes(vec![
                EndpointDocumentOutcome::Accepted,
            ]));
            let response = execute_as_system_admin(&schema, case.query, &manager).await;
            assert!(response.errors.is_empty(), "{}: {:?}", case.field, response);
            assert_eq!(manager.calls(), [case.call], "{}", case.field);
        }
    }

    #[tokio::test]
    async fn mutations_return_their_results() {
        let schema = TestSchema::new().await;
        let manager = Arc::new(FakeEndpointManager::default());
        let expected = [
            ("registerEndpointCustomer", "true".to_string()),
            ("registerEndpointInstall", "true".to_string()),
            ("setEndpointActiveList", format!("\"{APPLIED_VERSION}\"")),
            ("resolveEndpointEnrollment", "true".to_string()),
            ("submitEndpointCommand", format!("\"{COMMAND_ID}\"")),
        ];
        for case in cases() {
            let Some((_, value)) = expected.iter().find(|(field, _)| *field == case.field) else {
                continue;
            };
            let response = execute_as_system_admin(&schema, case.query, &manager).await;
            assert!(response.errors.is_empty(), "{}: {:?}", case.field, response);
            assert_eq!(
                response.data.to_string(),
                format!("{{{}: {value}}}", case.field)
            );
        }
    }

    #[tokio::test]
    async fn other_roles_are_refused_without_a_manager_call() {
        let schema = TestSchema::new().await;
        for case in cases() {
            for role in [
                Role::SecurityAdministrator,
                Role::SecurityManager,
                Role::SecurityMonitor,
            ] {
                for customer_ids in [None, Some(vec![7]), Some(vec![0, 7])] {
                    let manager = Arc::new(FakeEndpointManager::default());
                    let shared: SharedEndpointManager = manager.clone();
                    let response = schema
                        .execute_as_scoped_user_with_data(
                            case.query,
                            role,
                            customer_ids.clone(),
                            shared,
                        )
                        .await;
                    assert_eq!(
                        response
                            .errors
                            .iter()
                            .map(|error| error.message.as_str())
                            .collect::<Vec<_>>(),
                        ["Forbidden"],
                        "{} as {role:?} with {customer_ids:?}",
                        case.field
                    );
                    assert!(manager.calls().is_empty(), "{}", case.field);
                }
            }
        }
    }

    #[tokio::test]
    async fn a_caller_with_no_role_is_refused_without_a_manager_call() {
        let schema = TestSchema::new().await;
        for case in cases() {
            let manager = Arc::new(FakeEndpointManager::default());
            let shared: SharedEndpointManager = manager.clone();
            let request = async_graphql::Request::new(case.query).data(shared);
            let response = schema.schema.execute(request).await;
            assert!(!response.errors.is_empty(), "{}", case.field);
            assert!(manager.calls().is_empty(), "{}", case.field);
        }
    }

    #[tokio::test]
    async fn active_list_refusal_carries_its_reason_and_the_current_version() {
        let schema = TestSchema::new().await;
        let reasons = [
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
        ];
        for (reason, code) in reasons {
            for (current_version, expected_version) in [
                (
                    Some(APPLIED_VERSION),
                    Value::from(APPLIED_VERSION.to_string()),
                ),
                (Some(0), Value::from("0")),
                (None, Value::Null),
            ] {
                let manager = Arc::new(FakeEndpointManager::failing(move || {
                    EndpointManagerError::ActiveListRefused {
                        reason,
                        current_version,
                    }
                }));
                let response = execute_as_system_admin(
                    &schema,
                    r#"mutation { setEndpointActiveList(update: "AAEC/w==") }"#,
                    &manager,
                )
                .await;
                assert_eq!(response.data, Value::Null);
                let [error] = response.errors.as_slice() else {
                    panic!("one error expected: {:?}", response.errors);
                };
                let extensions = error.extensions.as_ref().unwrap();
                assert_eq!(extensions.get("code"), Some(&Value::from(code)));
                assert_eq!(extensions.get("version"), Some(&expected_version));
            }
        }
    }

    /// Every error case but the active list refusal, with the code it crosses
    /// GraphQL with.
    fn coded_errors() -> Vec<(ErrorFactory, Option<&'static str>)> {
        vec![
            (
                Box::new(|| {
                    SentaEndpointError::CustomerDeletion {
                        customer_id: 7,
                        state: SentaEndpointDeletionState::InProgress,
                    }
                    .into()
                }),
                Some("CUSTOMER_DELETION_IN_PROGRESS"),
            ),
            (
                Box::new(|| {
                    SentaEndpointError::CustomerDeletion {
                        customer_id: 7,
                        state: SentaEndpointDeletionState::AlreadyDeleted,
                    }
                    .into()
                }),
                Some("CUSTOMER_DATA_ALREADY_DELETED"),
            ),
            (
                Box::new(|| EndpointRefusal::CustomerDeletionInProgress { customer_id: 7 }.into()),
                Some("CUSTOMER_DELETION_IN_PROGRESS"),
            ),
            (
                Box::new(|| EndpointRefusal::CustomerDataAlreadyDeleted { customer_id: 7 }.into()),
                Some("CUSTOMER_DATA_ALREADY_DELETED"),
            ),
            (
                Box::new(|| EndpointRefusal::TrustUnreadable { customer_id: 7 }.into()),
                Some("ENDPOINT_TRUST_UNREADABLE"),
            ),
            (
                Box::new(|| {
                    EndpointRefusal::Code(EndpointRefusalCode::new("EPOCH_MISMATCH").unwrap())
                        .into()
                }),
                Some("EPOCH_MISMATCH"),
            ),
            (
                Box::new(|| EndpointManagerError::NotSupported),
                Some("ENDPOINT_NOT_SUPPORTED"),
            ),
            (
                Box::new(|| SentaEndpointError::CustomerExists { customer_id: 7 }.into()),
                None,
            ),
            (
                Box::new(|| anyhow::anyhow!("the trust store is locked").into()),
                None,
            ),
        ]
    }

    #[tokio::test]
    async fn every_mutation_renders_each_error_with_its_code() {
        let schema = TestSchema::new().await;
        for case in cases() {
            for (error, code) in coded_errors() {
                let message = error().to_string();
                let manager = Arc::new(FakeEndpointManager::failing(error));
                let response = execute_as_system_admin(&schema, case.query, &manager).await;
                assert_eq!(response.data, Value::Null, "{}: {response:?}", case.field);
                assert_eq!(
                    codes(&response),
                    [code.map(Value::from)],
                    "{}: {:?}",
                    case.field,
                    response.errors
                );
                assert_eq!(response.errors[0].message, message, "{}", case.field);
                assert_eq!(
                    manager.calls(),
                    std::slice::from_ref(&case.call),
                    "{}",
                    case.field
                );
            }
        }
    }

    #[tokio::test]
    async fn an_internal_failure_has_its_message_and_no_extensions() {
        let schema = TestSchema::new().await;
        let manager = Arc::new(FakeEndpointManager::failing(|| {
            SentaEndpointError::InstallNotFound {
                install_id: "install-1".to_string(),
            }
            .into()
        }));
        let response = execute_as_system_admin(
            &schema,
            r#"mutation { submitEndpointCommand(command: "c.m.d") }"#,
            &manager,
        )
        .await;
        assert_eq!(response.errors.len(), 1, "{:?}", response.errors);
        let error = &response.errors[0];
        assert_eq!(error.message, "no senta endpoint install \"install-1\"");
        assert!(error.extensions.is_none(), "{error:?}");
    }

    #[tokio::test]
    async fn documents_have_results_in_input_order() {
        let schema = TestSchema::new().await;
        let manager = Arc::new(FakeEndpointManager::with_outcomes(vec![
            EndpointDocumentOutcome::Accepted,
            EndpointDocumentOutcome::Refused(EndpointRefusal::CustomerDeletionInProgress {
                customer_id: 7,
            }),
            EndpointDocumentOutcome::Refused(EndpointRefusal::CustomerDataAlreadyDeleted {
                customer_id: 8,
            }),
            EndpointDocumentOutcome::Accepted,
            EndpointDocumentOutcome::Refused(EndpointRefusal::TrustUnreadable { customer_id: 9 }),
            EndpointDocumentOutcome::Refused(EndpointRefusal::Code(
                EndpointRefusalCode::new("BAD_SIGNATURE").unwrap(),
            )),
            EndpointDocumentOutcome::Refused(EndpointRefusal::Code(
                EndpointRefusalCode::new("UNKNOWN_KID").unwrap(),
            )),
        ]));
        let response = execute_as_system_admin(
            &schema,
            r#"mutation { putEndpointDocuments(documents: ["a", "b", "c", "d", "e", "f", "g"]) { index accepted reason } }"#,
            &manager,
        )
        .await;
        assert!(response.errors.is_empty(), "{response:?}");
        assert_eq!(
            manager.calls(),
            [Call::PutDocuments(
                ["a", "b", "c", "d", "e", "f", "g"]
                    .map(str::to_string)
                    .to_vec()
            )]
        );
        let results = response.data.into_json().unwrap();
        assert_eq!(
            results,
            serde_json::json!({ "putEndpointDocuments": [
                { "index": 0, "accepted": true, "reason": null },
                { "index": 1, "accepted": false, "reason": "CUSTOMER_DELETION_IN_PROGRESS" },
                { "index": 2, "accepted": false, "reason": "CUSTOMER_DATA_ALREADY_DELETED" },
                { "index": 3, "accepted": true, "reason": null },
                { "index": 4, "accepted": false, "reason": ENDPOINT_TRUST_UNREADABLE },
                { "index": 5, "accepted": false, "reason": "BAD_SIGNATURE" },
                { "index": 6, "accepted": false, "reason": "UNKNOWN_KID" },
            ]})
        );
    }

    #[tokio::test]
    async fn a_failure_of_the_whole_document_call_has_no_document_results() {
        let schema = TestSchema::new().await;
        let failures: [(ErrorFactory, Option<&str>); 2] = [
            (
                Box::new(|| EndpointManagerError::NotSupported),
                Some(ENDPOINT_NOT_SUPPORTED),
            ),
            (
                Box::new(|| anyhow::anyhow!("store unavailable").into()),
                None,
            ),
        ];
        for (error, code) in failures {
            let manager = Arc::new(FakeEndpointManager::failing(error));
            let response = execute_as_system_admin(
                &schema,
                r#"mutation { putEndpointDocuments(documents: ["a", "b"]) { index accepted reason } }"#,
                &manager,
            )
            .await;
            assert_eq!(response.data, Value::Null);
            assert_eq!(codes(&response), [code.map(Value::from)]);
        }
    }

    #[tokio::test]
    async fn a_wrong_number_of_document_outcomes_fails_the_call() {
        let schema = TestSchema::new().await;
        let manager = Arc::new(FakeEndpointManager::with_outcomes(vec![
            EndpointDocumentOutcome::Accepted,
        ]));
        let response = execute_as_system_admin(
            &schema,
            r#"mutation { putEndpointDocuments(documents: ["a", "b"]) { index accepted reason } }"#,
            &manager,
        )
        .await;
        assert_eq!(response.data, Value::Null);
        assert_eq!(codes(&response), [None]);
    }

    #[tokio::test]
    async fn every_resolution_reaches_the_manager() {
        let schema = TestSchema::new().await;
        for (input, resolution) in [
            (
                r#"{ approve: "r.e.s" }"#,
                EndpointEnrollmentResolution::Approve("r.e.s".to_string()),
            ),
            (
                r#"{ pending: "license_pending" }"#,
                EndpointEnrollmentResolution::Pending("license_pending".to_string()),
            ),
            (
                r#"{ reject: "denied" }"#,
                EndpointEnrollmentResolution::Reject("denied".to_string()),
            ),
        ] {
            let manager = Arc::new(FakeEndpointManager::default());
            let query = format!(
                r#"mutation {{ resolveEndpointEnrollment(spkiHash: "{SPKI_HASH}", attemptId: "{ATTEMPT_ID}", resolution: {input}) }}"#
            );
            let response = execute_as_system_admin(&schema, &query, &manager).await;
            assert!(response.errors.is_empty(), "{input}: {response:?}");
            assert_eq!(
                manager.calls(),
                [Call::ResolveEnrollment(attempt(), resolution)]
            );
        }
    }

    #[tokio::test]
    async fn an_empty_document_list_has_no_results() {
        let schema = TestSchema::new().await;
        let manager = Arc::new(FakeEndpointManager::default());
        let response = execute_as_system_admin(
            &schema,
            r"mutation { putEndpointDocuments(documents: []) { index accepted reason } }",
            &manager,
        )
        .await;
        assert!(response.errors.is_empty(), "{response:?}");
        assert_eq!(response.data.to_string(), "{putEndpointDocuments: []}");
        assert_eq!(manager.calls(), [Call::PutDocuments(Vec::new())]);
    }

    #[tokio::test]
    async fn malformed_input_is_refused_without_a_manager_call() {
        let schema = TestSchema::new().await;
        let customer = |customer_id: &str, customer_endpoint_id: &str| {
            format!(
                r#"mutation {{ registerEndpointCustomer(customerId: "{customer_id}", customerEndpointId: "{customer_endpoint_id}", keyName: "k", installId: "i", keyset: "h.p.s") }}"#
            )
        };
        let enrollment = |spki_hash: &str, attempt_id: &str, resolution: &str| {
            format!(
                r#"mutation {{ resolveEndpointEnrollment(spkiHash: "{spki_hash}", attemptId: "{attempt_id}", resolution: {resolution}) }}"#
            )
        };
        let approve = r#"{ approve: "r.e.s" }"#;
        let queries = [
            customer("x", CUSTOMER_ENDPOINT_ID),
            customer("-1", CUSTOMER_ENDPOINT_ID),
            customer("4294967296", CUSTOMER_ENDPOINT_ID),
            customer("", CUSTOMER_ENDPOINT_ID),
            customer("7", "not-a-uuid"),
            customer("7", "0b5d3c1e-7a4f-4e8b-9c2d-1f3a5b7c9d0"),
            r#"mutation { registerEndpointInstall(installId: "i", recoveryKey: "{}", version: "-1") }"#.to_string(),
            r#"mutation { registerEndpointInstall(installId: "i", recoveryKey: "{}", version: "18446744073709551616") }"#.to_string(),
            r#"mutation { registerEndpointInstall(installId: "i", recoveryKey: "{}", version: "one") }"#.to_string(),
            r#"mutation { setEndpointActiveList(update: "not base64!") }"#.to_string(),
            r#"mutation { setEndpointActiveList(update: "AAEC/w") }"#.to_string(),
            r#"mutation { setEndpointActiveList(update: "AAEC_w==") }"#.to_string(),
            enrollment(&SPKI_HASH[..62], ATTEMPT_ID, approve),
            enrollment(&format!("{SPKI_HASH}00"), ATTEMPT_ID, approve),
            enrollment(&SPKI_HASH.to_uppercase(), ATTEMPT_ID, approve),
            enrollment(&format!("{}zz", &SPKI_HASH[..62]), ATTEMPT_ID, approve),
            enrollment(SPKI_HASH, "not-a-uuid", approve),
            enrollment(SPKI_HASH, ATTEMPT_ID, "{}"),
            enrollment(
                SPKI_HASH,
                ATTEMPT_ID,
                r#"{ approve: "r.e.s", reject: "denied" }"#,
            ),
        ];
        for query in queries {
            let manager = Arc::new(FakeEndpointManager::default());
            let response = execute_as_system_admin(&schema, &query, &manager).await;
            assert!(!response.errors.is_empty(), "{query}");
            assert!(manager.calls().is_empty(), "{query}");
        }
    }

    #[test]
    fn spki_hash_decodes_lowercase_hex() {
        assert_eq!(super::parse_spki_hash(SPKI_HASH).unwrap(), spki_hash());
        assert_eq!(
            super::parse_spki_hash(&"f".repeat(64)).unwrap(),
            [0xff_u8; 32]
        );
        assert!(super::parse_spki_hash(&"é".repeat(32)).is_err());
    }

    #[test]
    fn refusal_codes_are_upper_snake_case() {
        for code in [
            "EPOCH_MISMATCH",
            "BAD_SIGNATURE",
            "UNKNOWN_KID",
            "A",
            "E2E_1",
        ] {
            assert_eq!(EndpointRefusalCode::new(code).unwrap().as_str(), code);
        }
        for code in [
            "",
            "epoch_mismatch",
            "EpochMismatch",
            "_EPOCH",
            "EPOCH_",
            "EPOCH__MISMATCH",
            "1EPOCH",
            "EPOCH-MISMATCH",
            "EPOCH MISMATCH",
        ] {
            assert!(EndpointRefusalCode::new(code).is_err(), "{code:?}");
        }
    }

    #[test]
    fn other_review_database_errors_are_internal_failures() {
        let error: EndpointManagerError = SentaEndpointError::DeletionJobExists {
            customer_id: 7,
            state: SentaEndpointDeletionState::InProgress,
        }
        .into();
        assert!(matches!(error, EndpointManagerError::Other(_)), "{error:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mutations_log_the_request_with_the_caller() {
        let schema = TestSchema::new().await;
        let messages = [
            (
                "registerEndpointCustomer",
                "Received a request to register customer 7 for Clumit Endpoint",
            ),
            (
                "registerEndpointInstall",
                "Received a request to register Clumit Endpoint install \"install-1\"",
            ),
            (
                "setEndpointActiveList",
                "Received a request to set the Clumit Endpoint active list",
            ),
            (
                "putEndpointDocuments",
                "Received a request to put 1 Clumit Endpoint documents",
            ),
            (
                "resolveEndpointEnrollment",
                "Received a request to resolve Clumit Endpoint enrollment attempt 6f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0b",
            ),
            (
                "submitEndpointCommand",
                "Received a request to submit a Clumit Endpoint command",
            ),
        ];
        for case in cases() {
            let (_, message) = messages
                .iter()
                .find(|(field, _)| *field == case.field)
                .unwrap();
            let manager = Arc::new(FakeEndpointManager::with_outcomes(vec![
                EndpointDocumentOutcome::Accepted,
            ]));
            let (events, _guard) = CapturedEvents::start();
            let response = execute_as_system_admin(&schema, case.query, &manager).await;
            assert!(response.errors.is_empty(), "{}: {:?}", case.field, response);
            assert_eq!(events.messages(), [*message], "{}", case.field);
            events.assert_fields(
                message,
                "an unauthenticated caller",
                Some("SystemAdministrator"),
            );
        }
    }

    #[tokio::test]
    async fn the_default_test_manager_is_not_supported() {
        let schema = TestSchema::new().await;
        for case in cases() {
            let response = schema.execute_as_system_admin(case.query).await;
            assert_eq!(
                codes(&response),
                [Some(Value::from(ENDPOINT_NOT_SUPPORTED))],
                "{}: {:?}",
                case.field,
                response.errors
            );
        }
        let error = crate::graphql::MockEndpointManager
            .customer_endpoint_data_deleted(7)
            .await
            .unwrap_err();
        assert!(
            matches!(error, EndpointManagerError::NotSupported),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn the_fake_manager_records_customer_endpoint_data_deleted() {
        let manager = FakeEndpointManager::default();
        manager.customer_endpoint_data_deleted(7).await.unwrap();
        assert_eq!(manager.calls(), [Call::CustomerEndpointDataDeleted(7)]);
    }
}
