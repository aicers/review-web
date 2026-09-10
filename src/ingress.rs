//! HTTP ingress for content that cannot travel over GraphQL.
//!
//! A signed package may be a container image, so it reaches `REView` as a
//! streamed request body rather than as base64 in a mutation. Everything here
//! forwards bytes as they arrive: nothing on this path collects a body into a
//! buffer, and the byte cap is enforced chunk by chunk while the body is still
//! being read.
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
use tracing::warn;

#[cfg(feature = "auth-mtls")]
use crate::TlsPeerInfo;
#[cfg(feature = "auth-jwt")]
use crate::auth::validate_token;
#[cfg(feature = "auth-mtls")]
use crate::auth::{MtlsAuthenticator, validate_context_jwt};
use crate::{
    Error,
    backend::{
        BuildId, CORE_PACKAGE_IDS, IngressStream, IngressStreamError, MODULE_PACKAGE_IDS,
        PackageIngestError, PackageStoreReceiver,
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
/// It is a published contract. The `aice-web-next` BFF fronts it and calls it
/// by name, so renaming it is a coordinated change across two repositories.
const PACKAGE_UPLOAD_PATH: &str = "/api/package/upload";

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
const VARIANT_PACKAGE_NOT_PERMITTED: &str = "PackageNotPermitted";
const VARIANT_TOO_LARGE: &str = "TooLarge";
const VARIANT_TRANSPORT: &str = "Transport";
const VARIANT_UNAVAILABLE: &str = "Unavailable";

/// The maximum request-body size, in bytes, the package-upload route accepts.
///
/// It reaches the handler as a newtype rather than as a bare `u64` extension,
/// which would collide at the type level with any other route's cap.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PackageUploadLimit(pub(crate) u64);

/// The build a successful upload was accepted as.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedBuild {
    package_id: String,
    version: String,
    commit: String,
}

impl From<BuildId> for AcceptedBuild {
    fn from(build: BuildId) -> Self {
        Self {
            package_id: build.package_id,
            version: build.version,
            commit: build.commit,
        }
    }
}

/// Builds the router carrying the ingress routes.
pub(crate) fn router() -> Router {
    Router::new().route(PACKAGE_UPLOAD_PATH, post(upload_package))
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
    role: Role,
    actor: &str,
    body: Body,
) -> Result<Json<AcceptedBuild>, Error> {
    let Some(permitted) = permitted_package_ids(role) else {
        warn!(
            actor,
            route = PACKAGE_UPLOAD_PATH,
            "a signed-package upload was refused: the role is neither administrator tier"
        );
        return Err(Error::Forbidden(ERR_ROLE_NOT_PERMITTED.to_string()));
    };

    let build = receiver
        .accept_package(&permitted, capped_stream(body.into_data_stream(), limit))
        .await
        .map_err(|e| map_ingest_error(e, actor))?;
    Ok(Json(build.into()))
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
    let auth = auth?;
    let (username, role) = {
        let store = store
            .read()
            .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
        validate_token(&store, auth.token())?
    };
    accept(&receiver, limit, role, &username, body).await
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
    let peer = peer
        .map(|Extension(p)| p)
        .ok_or_else(|| Error::Unauthorized(crate::ERR_MTLS_REQUIRED.to_string()))?;
    let cert = peer
        .leaf_cert()
        .ok_or_else(|| Error::Unauthorized(crate::ERR_MTLS_MISSING_CERT.to_string()))?;
    let identity = authenticator.authenticate(cert)?;

    let auth = auth?;
    let (role, _customer_ids) = validate_context_jwt(auth.token(), cert)?;
    let actor = format!(
        "{}.{}.{}",
        identity.instance, identity.service, identity.host
    );
    accept(&receiver, limit, role, &actor, body).await
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
        ERR_SIGNATURE_INVALID, ERR_TOO_LARGE, ERR_TRANSPORT, ERR_UNAVAILABLE, Extension,
        PACKAGE_UPLOAD_PATH, PackageUploadLimit, Role, Router, StreamExt, capped_stream, router,
    };
    use crate::backend::{
        BuildId, CORE_PACKAGE_IDS, IngressStream, IngressStreamError, MODULE_PACKAGE_IDS,
        PackageIngestError, PackageStoreReceiver,
    };

    #[cfg(feature = "auth-jwt")]
    const USERNAME: &str = "uploader";
    const ACCEPTED_PACKAGE_ID: &str = "piglet";
    const VERSION: &str = "0.21.0";
    const COMMIT: &str = "a1b2c3d";
    const CHUNK_LEN: usize = 16 * 1024;
    const CAP: u64 = 64 * 1024;
    const GENEROUS_CAP: u64 = 1 << 40;
    /// A body far larger than any buffer a handler could sanely hold: 4096
    /// chunks of 64 KiB, or 256 MiB.
    const HUGE_CHUNK_LEN: usize = 64 * 1024;
    const HUGE_CHUNKS: usize = 4096;
    const MARKER: &str = "leak-marker-9f3a1c";
    #[cfg(feature = "auth-mtls")]
    const CLIENT_DNS: &str = "001.aice-web-next.node-01.example.com";

    /// The path is a published contract the `aice-web-next` BFF calls by name,
    /// so a rename has to be a deliberate, coordinated change rather than a
    /// tidy-up.
    #[test]
    fn the_route_is_mounted_at_the_published_path() {
        assert_eq!(PACKAGE_UPLOAD_PATH, "/api/package/upload");
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ErrorItem {
        TooLarge,
        Transport,
    }

    #[derive(Debug, Default)]
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
        fn result(&self) -> Result<BuildId, PackageIngestError> {
            match self {
                Self::Accept => Ok(BuildId {
                    package_id: ACCEPTED_PACKAGE_ID.to_string(),
                    version: VERSION.to_string(),
                    commit: COMMIT.to_string(),
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
            let observed = self.observed.lock().expect("the observation mutex");
            Observed {
                calls: observed.calls,
                permitted: observed.permitted.clone(),
                chunks: observed.chunks,
                peak_chunk_len: observed.peak_chunk_len,
                total_len: observed.total_len,
                error_item: observed.error_item,
                items_after_error: observed.items_after_error,
                produced_when_first_chunk_seen: observed.produced_when_first_chunk_seen,
            }
        }
    }

    #[async_trait]
    impl PackageStoreReceiver for StubReceiver {
        async fn accept_package(
            &self,
            permitted_package_ids: &[&str],
            mut body: IngressStream,
        ) -> Result<BuildId, PackageIngestError> {
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
    async fn send(caller: &Caller, limit: u64, stub: &Stub, body: Body) -> Sent {
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

        let receiver: Arc<dyn PackageStoreReceiver> = stub.receiver.clone();
        let router = router()
            .layer(Extension(store))
            .layer(Extension(receiver))
            .layer(Extension(PackageUploadLimit(limit)));

        let mut builder = Request::builder().method("POST").uri(PACKAGE_UPLOAD_PATH);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = builder.body(body).expect("a well-formed request");
        run(router, request).await
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
    async fn send(caller: &Caller, limit: u64, stub: &Stub, body: Body) -> Sent {
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

        let receiver: Arc<dyn PackageStoreReceiver> = stub.receiver.clone();
        let authenticator: Arc<dyn MtlsAuthenticator> = Arc::new(StubAuthenticator);
        let router = router()
            .layer(Extension(authenticator))
            .layer(Extension(receiver))
            .layer(Extension(PackageUploadLimit(limit)));

        let mut builder = Request::builder().method("POST").uri(PACKAGE_UPLOAD_PATH);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let mut request = builder.body(body).expect("a well-formed request");
        request.extensions_mut().insert(Arc::new(TlsPeerInfo {
            certs: vec![cert_der],
        }));
        run(router, request).await
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
