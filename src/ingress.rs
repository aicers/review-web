//! HTTP ingress for content that cannot travel over GraphQL.
//!
//! Signed packages and trust-set generations reach `REView` as streamed
//! request bodies rather than as base64 in mutations. Everything here forwards
//! bytes as they arrive: nothing on these paths collects a body into a buffer,
//! and each byte cap is enforced chunk by chunk while the body is still being
//! read.
//!
//! The pieces every ingress route needs are module-level rather than folded
//! into a handler: the byte-counting adapter [`capped_stream`], and
//! [`authenticate`], which turns whichever credential the build's feature
//! configuration uses into an [`IngressActor`]. A route added here calls them
//! rather than carrying a second copy.
//!
//! What the tier check here guarantees is about this **route**, not about the
//! bytes on disk. The build store is writable by `REView`'s own service
//! account, so a component compromised on that host can edit `accepted/`
//! directly without traversing any route: the property held here is that the
//! upload path cannot be used to cross a tier, not that the store is protected
//! from a same-uid compromise.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::Extension,
    routing::post,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
    typed_header::TypedHeaderRejection,
};
use futures::{Stream, StreamExt};
#[cfg(feature = "auth-jwt")]
use review_database::Store;
use review_database::types::Role;
use serde::Serialize;
use tracing::{info, warn};

#[cfg(feature = "auth-mtls")]
use crate::TlsPeerInfo;
#[cfg(feature = "auth-jwt")]
use crate::auth::validate_token;
#[cfg(feature = "auth-mtls")]
use crate::auth::{MtlsAuthenticator, validate_context_jwt};
use crate::{
    Error,
    backend::{
        AcceptedPackage, CORE_PACKAGE_IDS, IngressStream, IngressStreamError, MODULE_PACKAGE_IDS,
        PackageIngestError, PackageStoreReceiver, TrustActivation, TrustIngestError, TrustManager,
    },
};

/// The one path a signed package is uploaded to.
///
/// It is written here and nowhere else. The name says `package` rather than
/// `module` because the route carries both tiers — a `SystemAdministrator`
/// uploads a core build through it — and a path that described less than the
/// route accepts would invite a second, core-only endpoint: a second way in to
/// secure, against the "only such ingress" property this route exists to hold.
///
/// It is a published contract, and public for that reason: the `aice-web-next`
/// BFF fronts it and calls it by name, so renaming it is a coordinated change
/// across two repositories, and a caller that names this constant is carried
/// through that change by the compiler rather than by a literal it repeated.
pub const PACKAGE_UPLOAD_PATH: &str = "/api/package/upload";

/// The one path a signed trust-set generation is submitted to.
///
/// A generation has no package tier or alternate payload shape, and it never
/// reaches the package store. Keeping the published path in one constant also
/// keeps tests and router wiring from creating an accidental second contract.
const TRUST_GENERATION_PATH: &str = "/api/trust/generation";

const ERR_ROLE_NOT_PERMITTED: &str = "uploading a signed package is not permitted for this role";
const ERR_SIGNATURE_INVALID: &str = "the package signature is invalid";
const ERR_MANIFEST_INCOMPLETE: &str =
    "the package manifest is incomplete or does not match the payload";
const ERR_PACKAGE_NOT_PERMITTED: &str = "uploading this package is not permitted for this role";
const ERR_TOO_LARGE: &str = "the upload exceeded the configured maximum size";
const ERR_TRANSPORT: &str = "reading the upload failed";
const ERR_UNAVAILABLE: &str = "the package store is unavailable";

const VARIANT_SIGNATURE_INVALID: &str = "SignatureInvalid";
const VARIANT_MANIFEST_INCOMPLETE: &str = "ManifestIncomplete";
const VARIANT_MALFORMED: &str = "Malformed";
const VARIANT_EPOCH_NOT_NEWER: &str = "EpochNotNewer";
const VARIANT_PACKAGE_NOT_PERMITTED: &str = "PackageNotPermitted";
const VARIANT_TOO_LARGE: &str = "TooLarge";
const VARIANT_TRANSPORT: &str = "Transport";
const VARIANT_UNAVAILABLE: &str = "Unavailable";

const ERR_TRUST_ROLE_NOT_PERMITTED: &str =
    "submitting a trust generation is not permitted for this role";
const ERR_TRUST_SIGNATURE_INVALID: &str = "trust generation signature is invalid";
const ERR_TRUST_MALFORMED: &str = "trust generation is malformed";
const ERR_TRUST_EPOCH_NOT_NEWER: &str = "trust generation epoch is not newer than the active epoch";
const ERR_TRUST_TOO_LARGE: &str = "the trust generation exceeded the configured maximum size";
const ERR_TRUST_TRANSPORT: &str = "reading the trust generation failed";
const ERR_TRUST_UNAVAILABLE: &str = "the trust manager is unavailable";

const TRUST_OUTCOME_ACTIVATED: &str = "Activated";
const TRUST_OUTCOME_FORBIDDEN: &str = "Forbidden";

/// The maximum request-body size, in bytes, the package-upload route accepts.
///
/// It reaches the handler as a newtype rather than as a bare `u64` extension,
/// which would collide at the type level with any other route's cap.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PackageUploadLimit(pub(crate) u64);

/// The maximum request-body size, in bytes, the trust-generation route
/// accepts.
///
/// Its distinct type prevents it from colliding with [`PackageUploadLimit`]
/// when both are installed as extensions on the same router.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TrustGenerationLimit(pub(crate) u64);

/// The build a successful upload was accepted as.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedBuild {
    package_id: String,
    version: String,
    commit: String,
}

/// The trust-set generation activated in response to a submission.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivatedTrustGeneration {
    epoch: u64,
}

impl From<TrustActivation> for ActivatedTrustGeneration {
    fn from(activation: TrustActivation) -> Self {
        Self {
            epoch: activation.epoch,
        }
    }
}

impl From<AcceptedPackage> for AcceptedBuild {
    fn from(accepted: AcceptedPackage) -> Self {
        Self {
            package_id: accepted.package_id,
            version: accepted.build.version,
            commit: accepted.build.commit,
        }
    }
}

/// Builds the router carrying the ingress routes.
pub(crate) fn router() -> Router {
    Router::new()
        .route(PACKAGE_UPLOAD_PATH, post(upload_package))
        .route(TRUST_GENERATION_PATH, post(submit_trust_generation))
}

/// Counts a body's bytes as they pass and cuts it off at `limit`.
///
/// The count is kept as the stream is consumed, never after: a cap checked
/// once the body has arrived is a cap already exceeded. The comparison is
/// inclusive, so a body of exactly `limit` bytes passes through intact and the
/// first byte past it does not.
///
/// The returned stream yields at most one [`Err`] item, forwards no chunk
/// after it and then ends. That single item is the whole cancellation
/// protocol: the receiver discards what it has written on seeing one, whether
/// the cap tripped or the client disappeared mid-upload. Nothing else is
/// added to this interface — no tripped flag, no shared counter handle — so
/// every route reading this adapter reads the same answer.
pub(crate) fn capped_stream<S, E>(body: S, limit: u64) -> IngressStream
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: std::fmt::Display,
{
    let state = Some((Box::pin(body), 0_u64));
    Box::pin(futures::stream::unfold(state, move |state| async move {
        let (mut body, total) = state?;
        match body.next().await {
            None => None,
            Some(Err(e)) => Some((Err(IngressStreamError::Transport(e.to_string())), None)),
            Some(Ok(chunk)) => {
                // A chunk length that does not fit in a `u64` cannot fit
                // under any cap either, so it takes the same branch as one
                // that overruns the cap.
                let Ok(len) = u64::try_from(chunk.len()) else {
                    return Some((Err(IngressStreamError::TooLarge { limit }), None));
                };
                match total.checked_add(len) {
                    Some(total) if total <= limit => Some((Ok(chunk), Some((body, total)))),
                    _ => Some((Err(IngressStreamError::TooLarge { limit }), None)),
                }
            }
        }
    }))
}

/// The authenticated caller of an ingress route.
///
/// Every route in this module needs the same two things out of a credential:
/// the role its tier check reads, and a name to record a rejection against.
/// Which credential carries them differs by feature, not by route, so the
/// extraction lives here rather than in a handler — a second ingress route
/// calls [`authenticate`] instead of repeating it.
pub(crate) struct IngressActor {
    /// The name a rejection is logged against — a username under `auth-jwt`,
    /// the peer's `instance.service.host` identity under `auth-mtls`.
    pub(crate) name: String,
    pub(crate) role: Role,
}

/// Authenticates a bearer-token caller and reads its role.
///
/// Role extraction happens inside the handler rather than in a `route_layer`
/// because the two feature configurations authenticate through different
/// paths; this is the `auth-jwt` one, validating the token exactly as the JWT
/// GraphQL handler does.
///
/// # Errors
///
/// Returns [`Error::Unauthorized`] if the request carries no bearer token or
/// if the token does not validate against the store.
///
/// # Panics
///
/// Panics if the store lock is poisoned, which means another thread panicked
/// while holding it and the store's contents can no longer be trusted.
#[cfg(feature = "auth-jwt")]
pub(crate) fn authenticate(
    store: &std::sync::RwLock<Store>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
) -> Result<IngressActor, Error> {
    let auth = auth?;
    let (name, role) = {
        let store = store
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        validate_token(&store, auth.token())?
    };
    Ok(IngressActor { name, role })
}

/// Authenticates an mTLS peer and reads its role.
///
/// The peer's leaf certificate authenticates the caller and the context JWT
/// bound to it carries the role, exactly as the mTLS GraphQL handler does.
/// This is the `auth-mtls` counterpart of the `auth-jwt` helper above, and
/// the reason role extraction is not a `route_layer`.
///
/// # Errors
///
/// Returns [`Error::Unauthorized`] if the connection carried no peer
/// certificate, if the leaf certificate does not authenticate, or if the
/// context JWT is absent or not bound to that certificate.
#[cfg(feature = "auth-mtls")]
pub(crate) fn authenticate(
    authenticator: &dyn MtlsAuthenticator,
    peer: Option<Extension<Arc<TlsPeerInfo>>>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
) -> Result<IngressActor, Error> {
    let peer = peer
        .map(|Extension(p)| p)
        .ok_or_else(|| Error::Unauthorized(crate::ERR_MTLS_REQUIRED.to_string()))?;
    let cert = peer
        .leaf_cert()
        .ok_or_else(|| Error::Unauthorized(crate::ERR_MTLS_MISSING_CERT.to_string()))?;
    let identity = authenticator.authenticate(cert)?;

    let auth = auth?;
    let (role, _customer_ids) = validate_context_jwt(auth.token(), cert)?;
    Ok(IngressActor {
        name: format!(
            "{}.{}.{}",
            identity.instance, identity.service, identity.host
        ),
        role,
    })
}

/// Expands a role into the package-ids it may write, or `None` if it may write
/// none.
///
/// Both lists are read from [`crate::backend`] rather than restated, so "core"
/// has one definition in one place. The match is exhaustive on purpose: a role
/// added upstream fails the build here rather than silently landing in a
/// permissive arm.
fn permitted_package_ids(role: Role) -> Option<Vec<&'static str>> {
    match role {
        Role::SystemAdministrator => Some(
            CORE_PACKAGE_IDS
                .iter()
                .chain(MODULE_PACKAGE_IDS.iter())
                .copied()
                .collect(),
        ),
        Role::SecurityAdministrator => Some(MODULE_PACKAGE_IDS.to_vec()),
        Role::SecurityManager | Role::SecurityMonitor => None,
    }
}

/// Matches a package-id this crate did not produce against the ones it knows,
/// yielding this crate's own `&'static str` on a hit.
fn known_package_id(package_id: &str) -> Option<&'static str> {
    CORE_PACKAGE_IDS
        .into_iter()
        .chain(MODULE_PACKAGE_IDS)
        .find(|known| *known == package_id)
}

fn log_rejection(actor: &str, variant: &'static str) {
    warn!(
        actor,
        route = PACKAGE_UPLOAD_PATH,
        variant,
        "a signed-package upload was rejected"
    );
}

/// Maps a receiver's failure to a response.
///
/// The match is exhaustive with no `_` arm, so a variant added later fails the
/// build rather than quietly inheriting another arm's text, and every arm
/// renders a message this crate owns. No string the receiver supplied reaches
/// the response body or a log line: the one arm that interpolates anything
/// interpolates the `&'static str` it found in this crate's own package-id
/// lists, and a value in neither list is dropped rather than echoed.
fn map_ingest_error(error: PackageIngestError, actor: &str) -> Error {
    match error {
        PackageIngestError::SignatureInvalid => {
            log_rejection(actor, VARIANT_SIGNATURE_INVALID);
            Error::BadRequest(ERR_SIGNATURE_INVALID.to_string())
        }
        PackageIngestError::ManifestIncomplete => {
            log_rejection(actor, VARIANT_MANIFEST_INCOMPLETE);
            Error::BadRequest(ERR_MANIFEST_INCOMPLETE.to_string())
        }
        PackageIngestError::PackageNotPermitted { package_id } => {
            log_rejection(actor, VARIANT_PACKAGE_NOT_PERMITTED);
            if let Some(known) = known_package_id(&package_id) {
                Error::Forbidden(format!("uploading {known} is not permitted for this role"))
            } else {
                // An id in neither list came from a manifest this product does
                // not know. Logging it would put the same untrusted bytes in a
                // file instead of in a response, so the value is dropped here.
                warn!(
                    route = PACKAGE_UPLOAD_PATH,
                    variant = VARIANT_PACKAGE_NOT_PERMITTED,
                    "the store receiver named a package-id in neither package-id list"
                );
                Error::Forbidden(ERR_PACKAGE_NOT_PERMITTED.to_string())
            }
        }
        PackageIngestError::TooLarge => {
            log_rejection(actor, VARIANT_TOO_LARGE);
            Error::PayloadTooLarge(ERR_TOO_LARGE.to_string())
        }
        PackageIngestError::Transport => {
            log_rejection(actor, VARIANT_TRANSPORT);
            Error::BadRequest(ERR_TRANSPORT.to_string())
        }
        PackageIngestError::Unavailable => {
            log_rejection(actor, VARIANT_UNAVAILABLE);
            Error::ServiceUnavailable(ERR_UNAVAILABLE.to_string())
        }
    }
}

fn log_trust_outcome(actor: &str, outcome: &'static str) {
    info!(
        actor,
        route = TRUST_GENERATION_PATH,
        outcome,
        "a trust generation submission completed"
    );
}

fn log_trust_refusal(actor: &str) {
    info!(
        actor,
        route = TRUST_GENERATION_PATH,
        outcome = TRUST_OUTCOME_FORBIDDEN,
        "a trust generation submission was rejected"
    );
}

/// Maps a trust manager's failure to a response and an audit outcome.
///
/// The exhaustive match deliberately has no catch-all arm. Every response
/// message is owned here, and the only submitted values that can reach one are
/// the two bounded epoch scalars.
fn map_trust_ingest_error(error: &TrustIngestError, actor: &str) -> Error {
    match error {
        TrustIngestError::SignatureInvalid => {
            log_trust_outcome(actor, VARIANT_SIGNATURE_INVALID);
            Error::BadRequest(ERR_TRUST_SIGNATURE_INVALID.to_string())
        }
        TrustIngestError::Malformed => {
            log_trust_outcome(actor, VARIANT_MALFORMED);
            Error::BadRequest(ERR_TRUST_MALFORMED.to_string())
        }
        TrustIngestError::EpochNotNewer { submitted, active } => {
            info!(
                actor,
                route = TRUST_GENERATION_PATH,
                outcome = VARIANT_EPOCH_NOT_NEWER,
                submitted,
                active,
                "a trust generation submission completed"
            );
            Error::Conflict(format!(
                "{ERR_TRUST_EPOCH_NOT_NEWER}: submitted {submitted}, active {active}"
            ))
        }
        TrustIngestError::TooLarge => {
            log_trust_outcome(actor, VARIANT_TOO_LARGE);
            Error::PayloadTooLarge(ERR_TRUST_TOO_LARGE.to_string())
        }
        TrustIngestError::Transport => {
            log_trust_outcome(actor, VARIANT_TRANSPORT);
            Error::BadRequest(ERR_TRUST_TRANSPORT.to_string())
        }
        TrustIngestError::Unavailable => {
            log_trust_outcome(actor, VARIANT_UNAVAILABLE);
            Error::ServiceUnavailable(ERR_TRUST_UNAVAILABLE.to_string())
        }
    }
}

/// Streams an authenticated caller's body into the store receiver.
///
/// The role is expanded into permitted package-ids before a single byte of the
/// body is read, and that set travels with the upload so the check gates the
/// receiver's commit. Nothing is checked once `accept_package` returns: by
/// then the store has been written or left alone, and a second check here
/// would be a decision arriving after the fact.
async fn accept(
    receiver: &Arc<dyn PackageStoreReceiver>,
    limit: u64,
    actor: &IngressActor,
    body: Body,
) -> Result<Json<AcceptedBuild>, Error> {
    let Some(permitted) = permitted_package_ids(actor.role) else {
        warn!(
            actor = actor.name,
            route = PACKAGE_UPLOAD_PATH,
            "a signed-package upload was refused: the role is neither administrator tier"
        );
        return Err(Error::Forbidden(ERR_ROLE_NOT_PERMITTED.to_string()));
    };

    let accepted = receiver
        .accept_package(&permitted, capped_stream(body.into_data_stream(), limit))
        .await
        .map_err(|e| map_ingest_error(e, &actor.name))?;
    Ok(Json(accepted.into()))
}

/// Streams a system administrator's body into the trust manager.
///
/// Authorization is complete before `body` is converted into a stream, so a
/// refused body is dropped unread and no byte reaches the shared counter.
async fn accept_trust_generation(
    manager: &Arc<dyn TrustManager>,
    limit: u64,
    actor: &IngressActor,
    body: Body,
) -> Result<Json<ActivatedTrustGeneration>, Error> {
    if actor.role != Role::SystemAdministrator {
        log_trust_refusal(&actor.name);
        return Err(Error::Forbidden(ERR_TRUST_ROLE_NOT_PERMITTED.to_string()));
    }

    let activation = manager
        .accept_generation(capped_stream(body.into_data_stream(), limit))
        .await
        .map_err(|error| map_trust_ingest_error(&error, &actor.name))?;
    info!(
        actor = actor.name,
        route = TRUST_GENERATION_PATH,
        outcome = TRUST_OUTCOME_ACTIVATED,
        epoch = activation.epoch,
        "a trust generation submission completed"
    );
    Ok(Json(activation.into()))
}

/// Accepts a signed package from a bearer-authenticated caller.
///
/// The role is extracted here rather than in a `route_layer` because the two
/// feature configurations authenticate through different paths, and the
/// `auth-jwt` archive middleware is scoped to a proxy's own role list.
#[cfg(feature = "auth-jwt")]
async fn upload_package(
    Extension(store): Extension<Arc<std::sync::RwLock<Store>>>,
    Extension(receiver): Extension<Arc<dyn PackageStoreReceiver>>,
    Extension(PackageUploadLimit(limit)): Extension<PackageUploadLimit>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    body: Body,
) -> Result<Json<AcceptedBuild>, Error> {
    let actor = authenticate(&store, auth)?;
    accept(&receiver, limit, &actor, body).await
}

/// Accepts a trust generation from a bearer-authenticated system
/// administrator.
#[cfg(feature = "auth-jwt")]
async fn submit_trust_generation(
    Extension(store): Extension<Arc<std::sync::RwLock<Store>>>,
    Extension(manager): Extension<Arc<dyn TrustManager>>,
    Extension(TrustGenerationLimit(limit)): Extension<TrustGenerationLimit>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    body: Body,
) -> Result<Json<ActivatedTrustGeneration>, Error> {
    let actor = authenticate(&store, auth)?;
    accept_trust_generation(&manager, limit, &actor, body).await
}

/// Accepts a signed package from an mTLS peer.
///
/// The peer's leaf certificate authenticates the caller and the context JWT
/// bound to it carries the role, exactly as the mTLS GraphQL handler does.
#[cfg(feature = "auth-mtls")]
async fn upload_package(
    Extension(authenticator): Extension<Arc<dyn MtlsAuthenticator>>,
    Extension(receiver): Extension<Arc<dyn PackageStoreReceiver>>,
    Extension(PackageUploadLimit(limit)): Extension<PackageUploadLimit>,
    peer: Option<Extension<Arc<TlsPeerInfo>>>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    body: Body,
) -> Result<Json<AcceptedBuild>, Error> {
    let actor = authenticate(authenticator.as_ref(), peer, auth)?;
    accept(&receiver, limit, &actor, body).await
}

/// Accepts a trust generation from an mTLS-authenticated system
/// administrator.
#[cfg(feature = "auth-mtls")]
async fn submit_trust_generation(
    Extension(authenticator): Extension<Arc<dyn MtlsAuthenticator>>,
    Extension(manager): Extension<Arc<dyn TrustManager>>,
    Extension(TrustGenerationLimit(limit)): Extension<TrustGenerationLimit>,
    peer: Option<Extension<Arc<TlsPeerInfo>>>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    body: Body,
) -> Result<Json<ActivatedTrustGeneration>, Error> {
    let actor = authenticate(authenticator.as_ref(), peer, auth)?;
    accept_trust_generation(&manager, limit, &actor, body).await
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Write},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_trait::async_trait;
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use tower::util::ServiceExt;
    use tracing_subscriber::fmt::MakeWriter;

    use super::{
        Body, Bytes, ERR_MANIFEST_INCOMPLETE, ERR_PACKAGE_NOT_PERMITTED, ERR_ROLE_NOT_PERMITTED,
        ERR_SIGNATURE_INVALID, ERR_TOO_LARGE, ERR_TRANSPORT, ERR_TRUST_EPOCH_NOT_NEWER,
        ERR_TRUST_MALFORMED, ERR_TRUST_ROLE_NOT_PERMITTED, ERR_TRUST_SIGNATURE_INVALID,
        ERR_TRUST_TOO_LARGE, ERR_TRUST_TRANSPORT, ERR_TRUST_UNAVAILABLE, ERR_UNAVAILABLE,
        Extension, PACKAGE_UPLOAD_PATH, PackageUploadLimit, Role, Router, StreamExt,
        TRUST_GENERATION_PATH, TRUST_OUTCOME_ACTIVATED, TRUST_OUTCOME_FORBIDDEN,
        TrustGenerationLimit, VARIANT_EPOCH_NOT_NEWER, VARIANT_MALFORMED,
        VARIANT_SIGNATURE_INVALID, VARIANT_TOO_LARGE, VARIANT_TRANSPORT, VARIANT_UNAVAILABLE,
        capped_stream, router,
    };
    use crate::backend::{
        AcceptedPackage, BuildId, CORE_PACKAGE_IDS, IngressStream, IngressStreamError,
        MODULE_PACKAGE_IDS, PackageIngestError, PackageStoreReceiver, TrustActivation,
        TrustIngestError, TrustManager,
    };
    use crate::{DEFAULT_PACKAGE_UPLOAD_MAX_BYTES, DEFAULT_TRUST_GENERATION_MAX_BYTES};

    #[cfg(feature = "auth-jwt")]
    const USERNAME: &str = "uploader";
    const ACCEPTED_PACKAGE_ID: &str = "piglet";
    const VERSION: &str = "0.21.0";
    const COMMIT: &str = "a1b2c3d";
    const CHUNK_LEN: usize = 16 * 1024;
    const CAP: u64 = 64 * 1024;
    /// A cap smaller than one chunk, so the first chunk alone overruns it.
    const TINY_CAP: u64 = 8;
    const GENEROUS_CAP: u64 = 1 << 40;
    /// A body far larger than any buffer a handler could sanely hold: 4096
    /// chunks of 64 KiB, or 256 MiB.
    const HUGE_CHUNK_LEN: usize = 64 * 1024;
    const HUGE_CHUNKS: usize = 4096;
    const MARKER: &str = "leak-marker-9f3a1c";
    #[cfg(feature = "auth-mtls")]
    const CLIENT_DNS: &str = "001.aice-web-next.node-01.example.com";
    #[cfg(feature = "auth-jwt")]
    const EXPECTED_TRUST_ACTOR: &str = USERNAME;
    #[cfg(feature = "auth-mtls")]
    const EXPECTED_TRUST_ACTOR: &str = "001.aice-web-next.node-01";

    /// The route answers at the published path and nowhere else. Every other
    /// test reaches the handler through [`PACKAGE_UPLOAD_PATH`], which holds
    /// one half of that; this one holds the other, that the router serves this
    /// path only for `POST` and serves nothing beneath it — a second way in
    /// would look exactly like a neighbouring path that also answered.
    #[tokio::test]
    async fn the_route_is_mounted_at_the_published_path() {
        let wrong_method = Request::builder()
            .method("GET")
            .uri(PACKAGE_UPLOAD_PATH)
            .body(Body::empty())
            .expect("a well-formed request");
        let sent = run(router(), wrong_method).await;
        assert_eq!(sent.status, StatusCode::METHOD_NOT_ALLOWED);

        let neighbour = Request::builder()
            .method("POST")
            .uri(format!("{PACKAGE_UPLOAD_PATH}/core"))
            .body(Body::empty())
            .expect("a well-formed request");
        let sent = run(router(), neighbour).await;
        assert_eq!(sent.status, StatusCode::NOT_FOUND);
    }

    /// The shipped default is provisional until a signing pipeline produces a
    /// real `.pkg`, so what a test can hold it to is that it behaves as
    /// a cap rather than as a sentinel: an ordinary body streams through it
    /// whole. That it is large enough not to refuse a real package is asserted
    /// where the constant is declared, against the reasoning it came from.
    #[tokio::test]
    async fn the_shipped_default_admits_an_ordinary_body() {
        let stub = stub(Outcome::Accept);
        let sent = send(
            &Caller::Role(Role::SystemAdministrator),
            DEFAULT_PACKAGE_UPLOAD_MAX_BYTES,
            &stub,
            small_body(),
        )
        .await;

        assert_eq!(sent.status, StatusCode::OK);
        assert_eq!(stub.observed().error_item, None);
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ErrorItem {
        TooLarge,
        Transport,
    }

    #[derive(Clone, Debug, Default)]
    struct Observed {
        calls: usize,
        permitted: Vec<String>,
        chunks: usize,
        peak_chunk_len: usize,
        total_len: u64,
        error_item: Option<ErrorItem>,
        items_after_error: usize,
        produced_when_first_chunk_seen: Option<usize>,
    }

    #[derive(Clone, Debug)]
    enum Outcome {
        Accept,
        SignatureInvalid,
        ManifestIncomplete,
        NotPermitted(&'static str),
        TooLarge,
        Transport,
        Unavailable,
    }

    impl Outcome {
        fn result(&self) -> Result<AcceptedPackage, PackageIngestError> {
            match self {
                Self::Accept => Ok(AcceptedPackage {
                    package_id: ACCEPTED_PACKAGE_ID.to_string(),
                    build: BuildId {
                        version: VERSION.to_string(),
                        commit: COMMIT.to_string(),
                    },
                }),
                Self::SignatureInvalid => Err(PackageIngestError::SignatureInvalid),
                Self::ManifestIncomplete => Err(PackageIngestError::ManifestIncomplete),
                Self::NotPermitted(package_id) => Err(PackageIngestError::PackageNotPermitted {
                    package_id: (*package_id).to_string(),
                }),
                Self::TooLarge => Err(PackageIngestError::TooLarge),
                Self::Transport => Err(PackageIngestError::Transport),
                Self::Unavailable => Err(PackageIngestError::Unavailable),
            }
        }
    }

    /// A receiver that records everything it was given and honours the trait's
    /// documented contract on a stream error.
    struct StubReceiver {
        observed: Arc<Mutex<Observed>>,
        outcome: Outcome,
        produced: Arc<AtomicUsize>,
    }

    struct Stub {
        receiver: Arc<StubReceiver>,
        observed: Arc<Mutex<Observed>>,
        produced: Arc<AtomicUsize>,
    }

    fn stub(outcome: Outcome) -> Stub {
        let observed = Arc::new(Mutex::new(Observed::default()));
        let produced = Arc::new(AtomicUsize::new(0));
        Stub {
            receiver: Arc::new(StubReceiver {
                observed: observed.clone(),
                outcome,
                produced: produced.clone(),
            }),
            observed,
            produced,
        }
    }

    impl Stub {
        fn observed(&self) -> Observed {
            self.observed.lock().expect("the observation mutex").clone()
        }
    }

    #[async_trait]
    impl PackageStoreReceiver for StubReceiver {
        async fn accept_package(
            &self,
            permitted_package_ids: &[&str],
            mut body: IngressStream,
        ) -> Result<AcceptedPackage, PackageIngestError> {
            {
                let mut observed = self.observed.lock().expect("the observation mutex");
                observed.calls += 1;
                observed.permitted = permitted_package_ids
                    .iter()
                    .map(|id| (*id).to_string())
                    .collect();
            }

            let mut stream_error = None;
            while let Some(item) = body.next().await {
                let mut observed = self.observed.lock().expect("the observation mutex");
                if observed.error_item.is_some() {
                    observed.items_after_error += 1;
                }
                match item {
                    Ok(chunk) => {
                        if observed.chunks == 0 {
                            observed.produced_when_first_chunk_seen =
                                Some(self.produced.load(Ordering::SeqCst));
                        }
                        observed.chunks += 1;
                        observed.peak_chunk_len = observed.peak_chunk_len.max(chunk.len());
                        observed.total_len +=
                            u64::try_from(chunk.len()).expect("a chunk length fits in a u64");
                    }
                    Err(e) => {
                        let kind = match e {
                            IngressStreamError::TooLarge { .. } => ErrorItem::TooLarge,
                            IngressStreamError::Transport(_) => ErrorItem::Transport,
                        };
                        observed.error_item = Some(kind);
                        stream_error = Some(kind);
                    }
                }
            }

            // The contract the trait's rustdoc states: an error item discards
            // everything written and maps to its own variant.
            if let Some(kind) = stream_error {
                return Err(match kind {
                    ErrorItem::TooLarge => PackageIngestError::TooLarge,
                    ErrorItem::Transport => PackageIngestError::Transport,
                });
            }
            self.outcome.result()
        }
    }

    #[derive(Clone, Debug)]
    enum TrustOutcome {
        Activate(u64),
        SignatureInvalid,
        Malformed,
        EpochNotNewer { submitted: u64, active: u64 },
        TooLarge,
        Transport,
        Unavailable,
    }

    impl TrustOutcome {
        fn result(&self) -> Result<TrustActivation, TrustIngestError> {
            match self {
                Self::Activate(epoch) => Ok(TrustActivation { epoch: *epoch }),
                Self::SignatureInvalid => Err(TrustIngestError::SignatureInvalid),
                Self::Malformed => Err(TrustIngestError::Malformed),
                Self::EpochNotNewer { submitted, active } => Err(TrustIngestError::EpochNotNewer {
                    submitted: *submitted,
                    active: *active,
                }),
                Self::TooLarge => Err(TrustIngestError::TooLarge),
                Self::Transport => Err(TrustIngestError::Transport),
                Self::Unavailable => Err(TrustIngestError::Unavailable),
            }
        }
    }

    #[derive(Clone, Debug, Default)]
    struct TrustObserved {
        calls: usize,
        chunks: usize,
        peak_chunk_len: usize,
        total_len: u64,
        bytes: Vec<u8>,
        error_item: Option<ErrorItem>,
        items_after_error: usize,
        produced_when_first_chunk_seen: Option<usize>,
    }

    struct StubTrustManager {
        observed: Arc<Mutex<TrustObserved>>,
        outcome: TrustOutcome,
        produced: Arc<AtomicUsize>,
        record_bytes: bool,
    }

    struct TrustStub {
        manager: Arc<StubTrustManager>,
        observed: Arc<Mutex<TrustObserved>>,
        produced: Arc<AtomicUsize>,
        package_calls: Arc<AtomicUsize>,
    }

    fn trust_stub(outcome: TrustOutcome) -> TrustStub {
        trust_stub_with_recording(outcome, true)
    }

    fn trust_stub_with_recording(outcome: TrustOutcome, record_bytes: bool) -> TrustStub {
        let observed = Arc::new(Mutex::new(TrustObserved::default()));
        let produced = Arc::new(AtomicUsize::new(0));
        TrustStub {
            manager: Arc::new(StubTrustManager {
                observed: observed.clone(),
                outcome,
                produced: produced.clone(),
                record_bytes,
            }),
            observed,
            produced,
            package_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    impl TrustStub {
        fn observed(&self) -> TrustObserved {
            self.observed.lock().expect("the observation mutex").clone()
        }
    }

    #[async_trait]
    impl TrustManager for StubTrustManager {
        async fn accept_generation(
            &self,
            mut body: IngressStream,
        ) -> Result<TrustActivation, TrustIngestError> {
            self.observed.lock().expect("the observation mutex").calls += 1;

            let mut stream_error = None;
            while let Some(item) = body.next().await {
                let mut observed = self.observed.lock().expect("the observation mutex");
                if observed.error_item.is_some() {
                    observed.items_after_error += 1;
                }
                match item {
                    Ok(chunk) => {
                        if observed.chunks == 0 {
                            observed.produced_when_first_chunk_seen =
                                Some(self.produced.load(Ordering::SeqCst));
                        }
                        observed.chunks += 1;
                        observed.peak_chunk_len = observed.peak_chunk_len.max(chunk.len());
                        observed.total_len +=
                            u64::try_from(chunk.len()).expect("a chunk length fits in a u64");
                        if self.record_bytes {
                            observed.bytes.extend_from_slice(&chunk);
                        }
                    }
                    Err(error) => {
                        let kind = match error {
                            IngressStreamError::TooLarge { .. } => ErrorItem::TooLarge,
                            IngressStreamError::Transport(_) => ErrorItem::Transport,
                        };
                        observed.error_item = Some(kind);
                        stream_error = Some(kind);
                    }
                }
            }

            if let Some(kind) = stream_error {
                return Err(match kind {
                    ErrorItem::TooLarge => TrustIngestError::TooLarge,
                    ErrorItem::Transport => TrustIngestError::Transport,
                });
            }
            self.outcome.result()
        }
    }

    struct CountingPackageStore(Arc<AtomicUsize>);

    #[async_trait]
    impl PackageStoreReceiver for CountingPackageStore {
        async fn accept_package(
            &self,
            _permitted_package_ids: &[&str],
            _body: IngressStream,
        ) -> Result<AcceptedPackage, PackageIngestError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(PackageIngestError::Unavailable)
        }
    }

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl LogCapture {
        fn contents(&self) -> String {
            let buffer = self.0.lock().expect("the log mutex");
            String::from_utf8_lossy(&buffer).into_owned()
        }
    }

    impl Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("the log mutex").extend_from_slice(buf);
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

    enum Caller {
        Anonymous,
        Invalid,
        Role(Role),
    }

    struct Sent {
        status: StatusCode,
        raw: String,
        logs: String,
    }

    impl Sent {
        fn error(&self) -> String {
            serde_json::from_str::<Value>(&self.raw)
                .ok()
                .and_then(|body| {
                    body.get("error")
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                })
                .unwrap_or_default()
        }

        fn field(&self, name: &str) -> String {
            serde_json::from_str::<Value>(&self.raw)
                .ok()
                .and_then(|body| {
                    body.get(name)
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                })
                .unwrap_or_default()
        }

        fn u64_field(&self, name: &str) -> Option<u64> {
            serde_json::from_str::<Value>(&self.raw)
                .ok()
                .and_then(|body| body.get(name).and_then(Value::as_u64))
        }
    }

    async fn run(router: Router, request: Request<Body>) -> Sent {
        let logs = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let response = {
            let _guard = tracing::subscriber::set_default(subscriber);
            router.oneshot(request).await.expect("the router answers")
        };
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body is complete");
        Sent {
            status,
            raw: String::from_utf8_lossy(&bytes).into_owned(),
            logs: logs.contents(),
        }
    }

    fn counted_body(chunks: usize, chunk_len: usize, produced: Arc<AtomicUsize>) -> Body {
        let chunk = Bytes::from(vec![b'p'; chunk_len]);
        Body::from_stream(futures::stream::unfold(0_usize, move |sent| {
            let chunk = chunk.clone();
            let produced = produced.clone();
            async move {
                if sent >= chunks {
                    return None;
                }
                produced.fetch_add(1, Ordering::SeqCst);
                Some((Ok::<Bytes, io::Error>(chunk), sent + 1))
            }
        }))
    }

    fn body_of(chunks: Vec<Bytes>) -> Body {
        Body::from_stream(futures::stream::iter(
            chunks.into_iter().map(Ok::<Bytes, io::Error>),
        ))
    }

    fn small_body() -> Body {
        body_of(vec![Bytes::from_static(b"a signed package")])
    }

    fn marker_body() -> Body {
        body_of(vec![Bytes::from(MARKER.repeat(8))])
    }

    /// A client that disappears mid-upload: one chunk, then a transport
    /// failure instead of the end of the body.
    fn dropping_body() -> Body {
        Body::from_stream(futures::stream::iter(vec![
            Ok::<Bytes, io::Error>(Bytes::from_static(b"the first half")),
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "the peer went away",
            )),
        ]))
    }

    #[cfg(feature = "auth-jwt")]
    async fn send_authenticated(
        caller: &Caller,
        path: &str,
        body: Body,
        configure: impl FnOnce(Router) -> Router,
    ) -> Sent {
        use std::sync::RwLock;

        use review_database::Store;

        let db_dir = tempfile::tempdir().expect("a temporary directory");
        let backup_dir = tempfile::tempdir().expect("a temporary directory");
        let store = Store::new(db_dir.path(), backup_dir.path(), None).expect("a store");
        crate::auth::update_jwt_secret(crate::graphql::test_jwt_secret_der().to_vec())
            .expect("the test secret is settable");

        let token = match caller {
            Caller::Anonymous => None,
            Caller::Invalid => Some("not.a.token".to_string()),
            Caller::Role(role) => {
                let (token, _) = crate::auth::create_token(USERNAME.to_string(), role.to_string())
                    .expect("a token for the role");
                crate::auth::insert_token(&store, &token, USERNAME).expect("the token is stored");
                Some(token)
            }
        };
        let store = Arc::new(RwLock::new(store));
        let router = configure(router().layer(Extension(store)));

        let mut builder = Request::builder().method("POST").uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = builder.body(body).expect("a well-formed request");
        run(router, request).await
    }

    #[cfg(feature = "auth-jwt")]
    async fn send(caller: &Caller, limit: u64, stub: &Stub, body: Body) -> Sent {
        let receiver: Arc<dyn PackageStoreReceiver> = stub.receiver.clone();
        send_authenticated(caller, PACKAGE_UPLOAD_PATH, body, |router| {
            router
                .layer(Extension(receiver))
                .layer(Extension(PackageUploadLimit(limit)))
        })
        .await
    }

    #[cfg(feature = "auth-jwt")]
    async fn send_trust(caller: &Caller, limit: u64, stub: &TrustStub, body: Body) -> Sent {
        let manager: Arc<dyn TrustManager> = stub.manager.clone();
        let package_store: Arc<dyn PackageStoreReceiver> =
            Arc::new(CountingPackageStore(stub.package_calls.clone()));
        send_authenticated(caller, TRUST_GENERATION_PATH, body, |router| {
            router
                .layer(Extension(manager))
                .layer(Extension(package_store))
                .layer(Extension(TrustGenerationLimit(limit)))
        })
        .await
    }

    #[cfg(feature = "auth-mtls")]
    struct StubAuthenticator;

    #[cfg(feature = "auth-mtls")]
    impl crate::auth::MtlsAuthenticator for StubAuthenticator {
        fn authenticate(
            &self,
            _cert: &rustls::pki_types::CertificateDer<'static>,
        ) -> Result<crate::auth::MtlsIdentity, crate::auth::MtlsAuthError> {
            Ok(crate::auth::MtlsIdentity {
                instance: "001".to_string(),
                service: "aice-web-next".to_string(),
                host: "node-01".to_string(),
                domain: "example.com".to_string(),
            })
        }
    }

    #[cfg(feature = "auth-mtls")]
    async fn send_authenticated(
        caller: &Caller,
        path: &str,
        body: Body,
        configure: impl FnOnce(Router) -> Router,
    ) -> Sent {
        use chrono::{Duration, Utc};
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        use rustls::pki_types::CertificateDer;

        use super::TlsPeerInfo;
        use crate::auth::MtlsAuthenticator;

        #[derive(serde::Serialize)]
        struct ContextClaims {
            role: String,
            customer_ids: Option<Vec<u32>>,
            exp: i64,
        }

        let key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("P-256 is supported in tests");
        let params = CertificateParams::new(vec![CLIENT_DNS.to_string()]).expect("a valid DNS SAN");
        let cert = params
            .self_signed(&key_pair)
            .expect("the generated key pair signs its own certificate");
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = key_pair.serialize_der();

        let token = match caller {
            Caller::Anonymous => None,
            Caller::Invalid => Some("not.a.token".to_string()),
            Caller::Role(role) => {
                let claims = ContextClaims {
                    role: role.to_string(),
                    customer_ids: Some(vec![1]),
                    exp: (Utc::now() + Duration::minutes(5)).timestamp(),
                };
                Some(
                    encode(
                        &Header::new(Algorithm::ES256),
                        &claims,
                        &EncodingKey::from_ec_der(&key_der),
                    )
                    .expect("the key was generated for ES256"),
                )
            }
        };

        let authenticator: Arc<dyn MtlsAuthenticator> = Arc::new(StubAuthenticator);
        let router = configure(router().layer(Extension(authenticator)));

        let mut builder = Request::builder().method("POST").uri(path);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let mut request = builder.body(body).expect("a well-formed request");
        request.extensions_mut().insert(Arc::new(TlsPeerInfo {
            certs: vec![cert_der],
        }));
        run(router, request).await
    }

    #[cfg(feature = "auth-mtls")]
    async fn send(caller: &Caller, limit: u64, stub: &Stub, body: Body) -> Sent {
        let receiver: Arc<dyn PackageStoreReceiver> = stub.receiver.clone();
        send_authenticated(caller, PACKAGE_UPLOAD_PATH, body, |router| {
            router
                .layer(Extension(receiver))
                .layer(Extension(PackageUploadLimit(limit)))
        })
        .await
    }

    #[cfg(feature = "auth-mtls")]
    async fn send_trust(caller: &Caller, limit: u64, stub: &TrustStub, body: Body) -> Sent {
        let manager: Arc<dyn TrustManager> = stub.manager.clone();
        let package_store: Arc<dyn PackageStoreReceiver> =
            Arc::new(CountingPackageStore(stub.package_calls.clone()));
        send_authenticated(caller, TRUST_GENERATION_PATH, body, |router| {
            router
                .layer(Extension(manager))
                .layer(Extension(package_store))
                .layer(Extension(TrustGenerationLimit(limit)))
        })
        .await
    }

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|id| (*id).to_string()).collect()
    }

    #[tokio::test]
    async fn a_successful_upload_returns_the_accepted_build() {
        let stub = stub(Outcome::Accept);
        let sent = send(
            &Caller::Role(Role::SystemAdministrator),
            CAP,
            &stub,
            small_body(),
        )
        .await;

        assert_eq!(sent.status, StatusCode::OK);
        assert_eq!(sent.field("packageId"), ACCEPTED_PACKAGE_ID);
        assert_eq!(sent.field("version"), VERSION);
        assert_eq!(sent.field("commit"), COMMIT);
    }

    /// The body is consumed as it arrives: the receiver sees its first chunk
    /// while the source has produced exactly one, no chunk it sees is bigger
    /// than the source's own, and 256 MiB pass through a handler that never
    /// holds more than one of them.
    #[tokio::test]
    async fn a_huge_body_is_streamed_rather_than_buffered() {
        let stub = stub(Outcome::Accept);
        let body = counted_body(HUGE_CHUNKS, HUGE_CHUNK_LEN, stub.produced.clone());
        let sent = send(
            &Caller::Role(Role::SystemAdministrator),
            GENEROUS_CAP,
            &stub,
            body,
        )
        .await;

        assert_eq!(sent.status, StatusCode::OK);
        let observed = stub.observed();
        assert_eq!(observed.chunks, HUGE_CHUNKS);
        assert_eq!(observed.peak_chunk_len, HUGE_CHUNK_LEN);
        assert_eq!(
            observed.total_len,
            u64::try_from(HUGE_CHUNKS * HUGE_CHUNK_LEN).expect("the total fits in a u64")
        );
        assert_eq!(observed.produced_when_first_chunk_seen, Some(1));
    }

    #[tokio::test]
    async fn a_system_administrator_may_write_core_and_module_packages() {
        let stub = stub(Outcome::Accept);
        let sent = send(
            &Caller::Role(Role::SystemAdministrator),
            CAP,
            &stub,
            small_body(),
        )
        .await;

        assert_eq!(sent.status, StatusCode::OK);
        let mut expected = ids(&CORE_PACKAGE_IDS);
        expected.extend(ids(&MODULE_PACKAGE_IDS));
        assert_eq!(stub.observed().permitted, expected);
    }

    #[tokio::test]
    async fn a_security_administrator_may_write_module_packages_only() {
        let stub = stub(Outcome::Accept);
        let sent = send(
            &Caller::Role(Role::SecurityAdministrator),
            CAP,
            &stub,
            small_body(),
        )
        .await;

        assert_eq!(sent.status, StatusCode::OK);
        let observed = stub.observed();
        assert_eq!(observed.permitted, ids(&MODULE_PACKAGE_IDS));
        for core in CORE_PACKAGE_IDS {
            assert!(!observed.permitted.iter().any(|id| id == core), "{core}");
        }
    }

    /// The store-side assertions — that `pending/`, `accepted/`, `index.json`
    /// and `latest_build` are untouched — cannot be made here, because this
    /// repository owns no store. What is asserted instead is the property that
    /// gates them: the core ids never reached the receiver, so the commit it
    /// would have made was refused before it happened.
    #[tokio::test]
    async fn a_security_administrator_uploading_a_core_build_is_forbidden() {
        let stub = stub(Outcome::NotPermitted("review"));
        let sent = send(
            &Caller::Role(Role::SecurityAdministrator),
            CAP,
            &stub,
            small_body(),
        )
        .await;

        assert_eq!(sent.status, StatusCode::FORBIDDEN);
        assert_eq!(
            sent.error(),
            "uploading review is not permitted for this role"
        );
        let observed = stub.observed();
        for core in CORE_PACKAGE_IDS {
            assert!(!observed.permitted.iter().any(|id| id == core), "{core}");
        }
    }

    #[tokio::test]
    async fn a_role_below_both_admin_tiers_is_forbidden_before_any_byte_is_read() {
        for role in [Role::SecurityManager, Role::SecurityMonitor] {
            let stub = stub(Outcome::Accept);
            let sent = send(&Caller::Role(role), CAP, &stub, small_body()).await;

            assert_eq!(sent.status, StatusCode::FORBIDDEN, "{role}");
            assert_eq!(sent.error(), ERR_ROLE_NOT_PERMITTED);
            let observed = stub.observed();
            assert_eq!(observed.calls, 0, "{role}");
            assert_eq!(observed.chunks, 0, "{role}");
        }
    }

    #[tokio::test]
    async fn a_caller_with_no_credential_is_unauthorized() {
        let stub = stub(Outcome::Accept);
        let sent = send(&Caller::Anonymous, CAP, &stub, small_body()).await;

        assert_eq!(sent.status, StatusCode::UNAUTHORIZED);
        assert_eq!(stub.observed().calls, 0);
    }

    #[tokio::test]
    async fn a_credential_that_fails_validation_is_unauthorized() {
        let stub = stub(Outcome::Accept);
        let sent = send(&Caller::Invalid, CAP, &stub, small_body()).await;

        assert_eq!(sent.status, StatusCode::UNAUTHORIZED);
        assert_eq!(stub.observed().calls, 0);
    }

    #[tokio::test]
    async fn a_body_of_exactly_the_cap_is_accepted() {
        let stub = stub(Outcome::Accept);
        let body = counted_body(4, CHUNK_LEN, stub.produced.clone());
        let sent = send(&Caller::Role(Role::SystemAdministrator), CAP, &stub, body).await;

        assert_eq!(sent.status, StatusCode::OK);
        let observed = stub.observed();
        assert_eq!(observed.total_len, CAP);
        assert!(observed.error_item.is_none());
    }

    /// One byte over the cap is cut off where it is crossed: the receiver sees
    /// the error item as the last thing on the stream, no chunk follows it, and
    /// the client gets a `413` with the ordinary `{"error": ...}` body rather
    /// than a reset connection it would retry.
    #[tokio::test]
    async fn a_body_one_byte_over_the_cap_is_refused_mid_stream() {
        let stub = stub(Outcome::Accept);
        let mut chunks = vec![Bytes::from(vec![b'p'; CHUNK_LEN]); 4];
        chunks.push(Bytes::from_static(b"!"));
        let sent = send(
            &Caller::Role(Role::SystemAdministrator),
            CAP,
            &stub,
            body_of(chunks),
        )
        .await;

        assert_eq!(sent.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(sent.error(), ERR_TOO_LARGE);
        let observed = stub.observed();
        assert_eq!(observed.error_item, Some(ErrorItem::TooLarge));
        assert_eq!(observed.items_after_error, 0);
        assert_eq!(observed.chunks, 4);
        assert_eq!(observed.total_len, CAP);
    }

    /// The cap is crossed by the chunk that opens the body, so the receiver is
    /// handed the error item and nothing else. The chunk that crosses is not
    /// forwarded in part or in whole, which is what keeps the inclusive
    /// comparison from admitting a body that only its first chunk overruns.
    #[tokio::test]
    async fn a_first_chunk_past_the_cap_hands_the_receiver_nothing_but_the_error() {
        let stub = stub(Outcome::Accept);
        let body = body_of(vec![Bytes::from(vec![b'p'; CHUNK_LEN])]);
        let sent = send(
            &Caller::Role(Role::SystemAdministrator),
            TINY_CAP,
            &stub,
            body,
        )
        .await;

        assert_eq!(sent.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(sent.error(), ERR_TOO_LARGE);
        let observed = stub.observed();
        assert_eq!(observed.chunks, 0);
        assert_eq!(observed.total_len, 0);
        assert_eq!(observed.error_item, Some(ErrorItem::TooLarge));
        assert_eq!(observed.items_after_error, 0);
    }

    #[tokio::test]
    async fn a_client_that_drops_mid_upload_ends_the_stream_with_a_transport_error() {
        let stub = stub(Outcome::Accept);
        let sent = send(
            &Caller::Role(Role::SystemAdministrator),
            CAP,
            &stub,
            dropping_body(),
        )
        .await;

        assert_eq!(sent.status, StatusCode::BAD_REQUEST);
        assert_eq!(sent.error(), ERR_TRANSPORT);
        let observed = stub.observed();
        assert_eq!(observed.error_item, Some(ErrorItem::Transport));
        assert_eq!(observed.items_after_error, 0);
        assert_eq!(observed.chunks, 1);
    }

    #[tokio::test]
    async fn every_receiver_failure_maps_to_its_status_and_message() {
        let table = [
            (
                Outcome::SignatureInvalid,
                StatusCode::BAD_REQUEST,
                ERR_SIGNATURE_INVALID,
            ),
            (
                Outcome::ManifestIncomplete,
                StatusCode::BAD_REQUEST,
                ERR_MANIFEST_INCOMPLETE,
            ),
            (
                Outcome::NotPermitted("nothing-known"),
                StatusCode::FORBIDDEN,
                ERR_PACKAGE_NOT_PERMITTED,
            ),
            (
                Outcome::TooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                ERR_TOO_LARGE,
            ),
            (Outcome::Transport, StatusCode::BAD_REQUEST, ERR_TRANSPORT),
            (
                Outcome::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                ERR_UNAVAILABLE,
            ),
        ];

        for (outcome, status, message) in table {
            let stub = stub(outcome.clone());
            let sent = send(
                &Caller::Role(Role::SystemAdministrator),
                CAP,
                &stub,
                small_body(),
            )
            .await;

            assert_eq!(sent.status, status, "{outcome:?}");
            assert_eq!(sent.error(), message, "{outcome:?}");
        }
    }

    /// A package-id in neither list is dropped rather than echoed, whatever it
    /// carries.
    #[tokio::test]
    async fn an_unknown_package_id_reaches_neither_the_response_nor_the_log() {
        for package_id in [
            "",
            "not-a-package",
            "<script>alert(1)</script>",
            "../../etc/passwd",
        ] {
            let stub = stub(Outcome::NotPermitted(package_id));
            let sent = send(
                &Caller::Role(Role::SystemAdministrator),
                CAP,
                &stub,
                small_body(),
            )
            .await;

            assert_eq!(sent.status, StatusCode::FORBIDDEN, "{package_id}");
            assert_eq!(sent.error(), ERR_PACKAGE_NOT_PERMITTED, "{package_id}");
            // The capture is live — the variant's own name is in it — so the
            // two assertions below are about what the log does not carry
            // rather than about an empty buffer.
            assert!(sent.logs.contains("PackageNotPermitted"), "{package_id}");
            assert!(sent.logs.contains(PACKAGE_UPLOAD_PATH), "{package_id}");
            if !package_id.is_empty() {
                assert!(!sent.raw.contains(package_id), "{package_id}");
                assert!(!sent.logs.contains(package_id), "{package_id}");
            }
        }
    }

    /// A package-id the receiver names that this crate does know is rendered
    /// from this crate's own constant, so the uploader learns which component
    /// the signed manifest actually declared.
    #[tokio::test]
    async fn a_known_package_id_is_named_from_this_crate_s_own_constant() {
        for package_id in CORE_PACKAGE_IDS.into_iter().chain(MODULE_PACKAGE_IDS) {
            let stub = stub(Outcome::NotPermitted(package_id));
            let sent = send(
                &Caller::Role(Role::SystemAdministrator),
                CAP,
                &stub,
                small_body(),
            )
            .await;

            assert_eq!(sent.status, StatusCode::FORBIDDEN, "{package_id}");
            assert_eq!(
                sent.error(),
                format!("uploading {package_id} is not permitted for this role"),
                "{package_id}"
            );
        }
    }

    /// Nothing read out of the submitted bytes reaches a response body or a
    /// log line, on any failure path.
    #[tokio::test]
    async fn no_byte_of_the_body_leaks_on_any_failure_path() {
        let table = [
            (Outcome::SignatureInvalid, ERR_SIGNATURE_INVALID),
            (Outcome::ManifestIncomplete, ERR_MANIFEST_INCOMPLETE),
            (
                Outcome::NotPermitted("not-a-package"),
                ERR_PACKAGE_NOT_PERMITTED,
            ),
            (Outcome::TooLarge, ERR_TOO_LARGE),
            (Outcome::Transport, ERR_TRANSPORT),
            (Outcome::Unavailable, ERR_UNAVAILABLE),
        ];

        for (outcome, message) in table {
            let stub = stub(outcome.clone());
            let sent = send(
                &Caller::Role(Role::SystemAdministrator),
                CAP,
                &stub,
                marker_body(),
            )
            .await;

            assert_eq!(sent.error(), message, "{outcome:?}");
            // As above: the log captured this request, and what it captured
            // names the variant and the route and nothing off the wire.
            assert!(sent.logs.contains(PACKAGE_UPLOAD_PATH), "{outcome:?}");
            assert!(!sent.raw.contains(MARKER), "{outcome:?}");
            assert!(!sent.logs.contains(MARKER), "{outcome:?}");
        }
    }

    #[tokio::test]
    async fn the_trust_route_is_mounted_at_its_published_path() {
        let wrong_method = Request::builder()
            .method("GET")
            .uri(TRUST_GENERATION_PATH)
            .body(Body::empty())
            .expect("a well-formed request");
        let sent = run(router(), wrong_method).await;
        assert_eq!(sent.status, StatusCode::METHOD_NOT_ALLOWED);

        let neighbour = Request::builder()
            .method("POST")
            .uri(format!("{TRUST_GENERATION_PATH}/current"))
            .body(Body::empty())
            .expect("a well-formed request");
        let sent = run(router(), neighbour).await;
        assert_eq!(sent.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_system_administrator_streams_a_generation_only_to_the_trust_manager() {
        let stub = trust_stub(TrustOutcome::Activate(u64::MAX));
        let submitted = Bytes::from_static(b"a signed trust generation");
        let sent = send_trust(
            &Caller::Role(Role::SystemAdministrator),
            CAP,
            &stub,
            body_of(vec![submitted.clone()]),
        )
        .await;

        assert_eq!(sent.status, StatusCode::OK);
        assert_eq!(sent.u64_field("epoch"), Some(u64::MAX));
        let observed = stub.observed();
        assert_eq!(observed.calls, 1);
        assert_eq!(observed.bytes, submitted);
        assert_eq!(stub.package_calls.load(Ordering::SeqCst), 0);
        assert!(sent.logs.contains(EXPECTED_TRUST_ACTOR));
        assert!(sent.logs.contains(TRUST_OUTCOME_ACTIVATED));
        assert!(sent.logs.contains(&u64::MAX.to_string()));
    }

    #[tokio::test]
    async fn every_other_role_is_forbidden_before_the_trust_body_is_read() {
        for role in [
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let stub = trust_stub(TrustOutcome::Activate(7));
            let body = counted_body(1, CHUNK_LEN, stub.produced.clone());
            let sent = send_trust(&Caller::Role(role), CAP, &stub, body).await;

            assert_eq!(sent.status, StatusCode::FORBIDDEN, "{role}");
            assert_eq!(sent.error(), ERR_TRUST_ROLE_NOT_PERMITTED, "{role}");
            let observed = stub.observed();
            assert_eq!(observed.calls, 0, "{role}");
            assert_eq!(observed.chunks, 0, "{role}");
            assert_eq!(stub.produced.load(Ordering::SeqCst), 0, "{role}");
            assert_eq!(stub.package_calls.load(Ordering::SeqCst), 0, "{role}");
            assert!(sent.logs.contains(EXPECTED_TRUST_ACTOR), "{role}");
            assert!(sent.logs.contains(TRUST_OUTCOME_FORBIDDEN), "{role}");
            assert!(sent.logs.contains("was rejected"), "{role}");
        }
    }

    #[tokio::test]
    async fn absent_or_invalid_credentials_do_not_reach_the_trust_manager() {
        for caller in [Caller::Anonymous, Caller::Invalid] {
            let stub = trust_stub(TrustOutcome::Activate(7));
            let body = counted_body(1, CHUNK_LEN, stub.produced.clone());
            let sent = send_trust(&caller, CAP, &stub, body).await;

            assert_eq!(sent.status, StatusCode::UNAUTHORIZED);
            assert_eq!(stub.observed().calls, 0);
            assert_eq!(stub.produced.load(Ordering::SeqCst), 0);
            assert_eq!(stub.package_calls.load(Ordering::SeqCst), 0);
        }
    }

    /// The manager observes each source chunk as it arrives and sees the first
    /// one before the source produces the second. Byte recording is disabled
    /// in this case so the test manager, like the route, retains no growing
    /// copy of the 64 MiB body.
    #[tokio::test]
    async fn a_large_trust_generation_is_streamed_without_whole_body_buffering() {
        const CHUNKS: usize = HUGE_CHUNKS / 4;

        let stub = trust_stub_with_recording(TrustOutcome::Activate(7), false);
        let body = counted_body(CHUNKS, HUGE_CHUNK_LEN, stub.produced.clone());
        let sent = send_trust(
            &Caller::Role(Role::SystemAdministrator),
            GENEROUS_CAP,
            &stub,
            body,
        )
        .await;

        assert_eq!(sent.status, StatusCode::OK);
        let observed = stub.observed();
        assert_eq!(observed.chunks, CHUNKS);
        assert_eq!(observed.peak_chunk_len, HUGE_CHUNK_LEN);
        assert_eq!(
            observed.total_len,
            u64::try_from(CHUNKS * HUGE_CHUNK_LEN).expect("the total fits in a u64")
        );
        assert_eq!(observed.produced_when_first_chunk_seen, Some(1));
        assert!(observed.bytes.is_empty());
    }

    #[tokio::test]
    async fn the_trust_cap_is_inclusive_and_cuts_off_the_first_excess_byte() {
        let exact = trust_stub(TrustOutcome::Activate(7));
        let exact_body = counted_body(4, CHUNK_LEN, exact.produced.clone());
        let sent = send_trust(
            &Caller::Role(Role::SystemAdministrator),
            CAP,
            &exact,
            exact_body,
        )
        .await;
        assert_eq!(sent.status, StatusCode::OK);
        assert_eq!(exact.observed().total_len, CAP);
        assert!(exact.observed().error_item.is_none());

        let excess = trust_stub(TrustOutcome::Activate(7));
        let mut chunks = vec![Bytes::from(vec![b't'; CHUNK_LEN]); 4];
        chunks.push(Bytes::from_static(b"!"));
        let sent = send_trust(
            &Caller::Role(Role::SystemAdministrator),
            CAP,
            &excess,
            body_of(chunks),
        )
        .await;

        assert_eq!(sent.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(sent.error(), ERR_TRUST_TOO_LARGE);
        let observed = excess.observed();
        assert_eq!(observed.total_len, CAP);
        assert_eq!(observed.chunks, 4);
        assert_eq!(observed.error_item, Some(ErrorItem::TooLarge));
        assert_eq!(observed.items_after_error, 0);
    }

    #[tokio::test]
    async fn a_dropped_trust_submission_maps_the_final_stream_error_to_bad_request() {
        let stub = trust_stub(TrustOutcome::Activate(7));
        let sent = send_trust(
            &Caller::Role(Role::SystemAdministrator),
            CAP,
            &stub,
            dropping_body(),
        )
        .await;

        assert_eq!(sent.status, StatusCode::BAD_REQUEST);
        assert_eq!(sent.error(), ERR_TRUST_TRANSPORT);
        let observed = stub.observed();
        assert_eq!(observed.chunks, 1);
        assert_eq!(observed.error_item, Some(ErrorItem::Transport));
        assert_eq!(observed.items_after_error, 0);
    }

    #[tokio::test]
    async fn every_trust_manager_failure_maps_to_its_status_and_owned_message() {
        let table = [
            (
                TrustOutcome::SignatureInvalid,
                StatusCode::BAD_REQUEST,
                ERR_TRUST_SIGNATURE_INVALID.to_string(),
                VARIANT_SIGNATURE_INVALID,
            ),
            (
                TrustOutcome::Malformed,
                StatusCode::BAD_REQUEST,
                ERR_TRUST_MALFORMED.to_string(),
                VARIANT_MALFORMED,
            ),
            (
                TrustOutcome::EpochNotNewer {
                    submitted: 7,
                    active: 9,
                },
                StatusCode::CONFLICT,
                format!("{ERR_TRUST_EPOCH_NOT_NEWER}: submitted 7, active 9"),
                VARIANT_EPOCH_NOT_NEWER,
            ),
            (
                TrustOutcome::TooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                ERR_TRUST_TOO_LARGE.to_string(),
                VARIANT_TOO_LARGE,
            ),
            (
                TrustOutcome::Transport,
                StatusCode::BAD_REQUEST,
                ERR_TRUST_TRANSPORT.to_string(),
                VARIANT_TRANSPORT,
            ),
            (
                TrustOutcome::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                ERR_TRUST_UNAVAILABLE.to_string(),
                VARIANT_UNAVAILABLE,
            ),
        ];

        for (outcome, status, message, variant) in table {
            let stub = trust_stub(outcome.clone());
            let sent = send_trust(
                &Caller::Role(Role::SystemAdministrator),
                CAP,
                &stub,
                marker_body(),
            )
            .await;

            assert_eq!(sent.status, status, "{outcome:?}");
            assert_eq!(sent.error(), message, "{outcome:?}");
            assert!(sent.logs.contains(EXPECTED_TRUST_ACTOR), "{outcome:?}");
            assert!(sent.logs.contains(variant), "{outcome:?}");
            assert!(!sent.raw.contains(MARKER), "{outcome:?}");
            assert!(!sent.logs.contains(MARKER), "{outcome:?}");
        }
    }

    #[tokio::test]
    async fn the_provisional_trust_default_admits_an_ordinary_generation() {
        let stub = trust_stub(TrustOutcome::Activate(7));
        let sent = send_trust(
            &Caller::Role(Role::SystemAdministrator),
            DEFAULT_TRUST_GENERATION_MAX_BYTES,
            &stub,
            marker_body(),
        )
        .await;

        assert_eq!(sent.status, StatusCode::OK);
        assert_eq!(stub.observed().error_item, None);
        assert!(!sent.logs.contains(MARKER));
    }

    #[tokio::test]
    async fn the_adapter_cuts_the_stream_off_where_the_cap_is_crossed() {
        let source = futures::stream::iter(vec![
            Ok::<Bytes, io::Error>(Bytes::from_static(b"aaaa")),
            Ok(Bytes::from_static(b"bbbb")),
            Ok(Bytes::from_static(b"cccc")),
        ]);
        let mut stream = capped_stream(source, 6);

        let first = stream
            .next()
            .await
            .expect("the first chunk is under the cap");
        assert_eq!(first.expect("an ordinary chunk").len(), 4);
        assert!(matches!(
            stream.next().await,
            Some(Err(IngressStreamError::TooLarge { limit: 6 }))
        ));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn the_adapter_admits_a_body_of_exactly_the_cap() {
        let source = futures::stream::iter(vec![
            Ok::<Bytes, io::Error>(Bytes::from_static(b"aaaa")),
            Ok(Bytes::from_static(b"bbbb")),
        ]);
        let mut stream = capped_stream(source, 8);

        assert_eq!(stream.next().await.expect("a chunk").expect("ok").len(), 4);
        assert_eq!(stream.next().await.expect("a chunk").expect("ok").len(), 4);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn the_adapter_maps_a_source_failure_to_a_transport_error() {
        let source = futures::stream::iter(vec![
            Ok::<Bytes, io::Error>(Bytes::from_static(b"aaaa")),
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "the peer went away",
            )),
            Ok(Bytes::from_static(b"never forwarded")),
        ]);
        let mut stream = capped_stream(source, u64::MAX);

        assert_eq!(stream.next().await.expect("a chunk").expect("ok").len(), 4);
        assert!(matches!(
            stream.next().await,
            Some(Err(IngressStreamError::Transport(_)))
        ));
        assert!(stream.next().await.is_none());
    }
}
