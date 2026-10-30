pub mod auth;
pub mod backend;
pub mod customer_data_deletion;
pub mod graphql;
pub mod ingress;
pub mod maintenance;

use std::sync::RwLock;
use std::{
    fs::read,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_graphql::Data;
use async_graphql_axum::{GraphQLProtocol, GraphQLRequest, GraphQLResponse, GraphQLWebSocket};
use axum::{
    Json, Router,
    extract::{Extension, WebSocketUpgrade},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
    typed_header::TypedHeaderRejection,
};
use futures::future::BoxFuture;
use graphql::CustomerIds;
use graphql::RoleGuard;
use review_database::Store;
use rustls::{
    RootCertStore,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use serde_json::json;
use tokio::{sync::Notify, task::JoinHandle};
use tower::Service;
use tracing::{error, warn};

use crate::auth::MtlsAuthError;
use crate::auth::MtlsAuthenticator;
use crate::auth::validate_context_jwt;
use crate::backend::{
    AgentManager, CertManager, HostOnboarder, PackageStoreReceiver, SharedPackageDeployer,
    TrustManager,
};
use crate::ingress::{PackageUploadLimit, TrustGenerationLimit};

const ERR_MTLS_REQUIRED: &str = "mTLS is required";
const ERR_MTLS_MISSING_CERT: &str = "mTLS client certificate is missing";
const ERR_MISSING_AUTHORIZATION: &str = "Missing Authorization";

/// The default maximum request-body size, in bytes, for the package-upload
/// route: 2 GiB.
///
/// **This value is provisional.** It was reasoned about rather than measured.
/// Re-derive it from a real signed `.pkg` — including a core component's
/// container image, the case a module-sized cap would wrongly reject — once a
/// signing pipeline produces one, and replace this paragraph with what was
/// measured and when.
///
/// What the cap is for is bounding what an authenticated uploader can write
/// into `pending/` on this host's data volume, and any finite value serves
/// that. A measurement matters only so the cap does not wrongly reject a
/// legitimate build — and as of 2026-09-11 no signed `.pkg` exists to reject:
/// `aicers/review` publishes releases with no assets and no signing pipeline
/// produces one yet. The nearest artifact anything in this product ships is a
/// bootler payload asset, a whole-product bundle rather than one package,
/// whose largest published form is roughly 980 MB; 2 GiB clears that
/// comfortably, so the first real signed package cannot plausibly be refused
/// by it. Measuring that bundle and calling the result a package size would
/// have laundered the same guess through a number that merely looks measured.
///
/// [`ServerConfig::package_upload_max_bytes`] carries the effective value.
/// This constant is the shipped default an embedding application falls back
/// to, and is exported because `ServerConfig` has no `Default` impl: a default
/// that exists only in prose is one the operator's configuration layer in
/// `aicers/review` cannot reach.
pub const DEFAULT_PACKAGE_UPLOAD_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The largest artifact anything in this product publishes as of 2026-09-11: a
/// bootler payload asset, which is a whole-product bundle rather than one
/// signed package, so no single package can plausibly exceed it.
const LARGEST_PUBLISHED_ARTIFACT_BYTES: u64 = 980 * 1000 * 1000;

// The whole basis of the provisional default is that it clears that artifact
// comfortably. Lowering it past that point would make it capable of refusing
// the first genuine signed package it ever saw, so the build fails rather than
// the route quietly starting to reject legitimate uploads.
const _: () = assert!(DEFAULT_PACKAGE_UPLOAD_MAX_BYTES > LARGEST_PUBLISHED_ARTIFACT_BYTES);

/// The default maximum request-body size, in bytes, for the trust-generation
/// route: 2 MiB.
///
/// **This value is provisional.** As of 2026-09-11 it is derived from the
/// serialized `aicers/deploy-core` `TrustSetDocument` shape, not measured from
/// a generated artifact. Compact JSON needs about 180 bytes for each anchor's
/// two 64-character lowercase-hex values and revocation flag, and about 120
/// bytes for each withdrawn package/version/40-character-commit triple. The
/// planning cardinalities are 100 anchors and 10,000 withdrawn builds:
/// `100 * 180 + 10,000 * 120 = 1,218,000` bytes. The 2 MiB default therefore
/// leaves 879,152 bytes of headroom for the top-level fields, longer safe
/// identifiers, whitespace and the signed container envelope.
///
/// Re-derive this value from a real generation once release-ops mints one,
/// replacing this arithmetic with the generation, cardinalities, measured
/// size and measurement date. This cap bounds per-request work and memory; the
/// trust route never reaches the package store's `pending/` directory.
///
/// [`ServerConfig::trust_generation_max_bytes`] carries the effective value.
/// This constant is exported because `ServerConfig` has no `Default` impl, so
/// an embedding application's operator configuration needs a shipped fallback.
pub const DEFAULT_TRUST_GENERATION_MAX_BYTES: u64 = 2 * 1024 * 1024;

const DERIVED_TRUST_GENERATION_BYTES: u64 = 100 * 180 + 10_000 * 120;

// Keep the provisional default tied to the documented format arithmetic and
// headroom. A changed value must update the derivation above rather than become
// an unexplained package-sized ceiling.
const _: () =
    assert!(DEFAULT_TRUST_GENERATION_MAX_BYTES - DERIVED_TRUST_GENERATION_BYTES == 879_152);

/// Parameters for a web server.
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub cert_manager: Arc<dyn CertManager>,
    pub tls_reload_handle: Arc<Notify>,
    pub ca_certs: Vec<PathBuf>,
    /// The rustls crypto provider every TLS configuration of the HTTPS server
    /// is built from: the first one and each one built after a certificate
    /// reload, client-certificate verifier included.
    ///
    /// The server sets no TLS policy of its own and does not read the
    /// process-default provider. Its key-exchange groups and cipher suites are
    /// this provider's, and so are its protocol versions: a provider holding
    /// only TLS 1.3 cipher suites makes the server TLS 1.3 only.
    pub crypto_provider: Arc<CryptoProvider>,
    pub authenticator: Arc<dyn MtlsAuthenticator>,
    /// Takes a signed package streamed to the package-upload route into the
    /// build store.
    pub package_store: Arc<dyn PackageStoreReceiver>,
    /// The maximum request-body size, in bytes, the package-upload route
    /// accepts.
    ///
    /// The field carries the effective value an operator configured; the
    /// shipped default is [`DEFAULT_PACKAGE_UPLOAD_MAX_BYTES`]. A body of
    /// exactly this many bytes is accepted and one byte more is refused
    /// mid-stream with `413`.
    pub package_upload_max_bytes: u64,
    /// Verifies and activates a trust generation streamed to the trust-plane
    /// ingress route.
    pub trust_manager: Arc<dyn TrustManager>,
    /// The maximum request-body size, in bytes, the trust-generation route
    /// accepts.
    ///
    /// The field carries the effective value an operator configured; the
    /// shipped default is [`DEFAULT_TRUST_GENERATION_MAX_BYTES`]. A body of
    /// exactly this many bytes is accepted and one byte more is refused
    /// mid-stream with `413`.
    pub trust_generation_max_bytes: u64,
    /// The gate the embedding application closes during a pending `Rollback`
    /// update.
    ///
    /// While it is closed, every GraphQL document containing a mutation is
    /// refused before it runs with the error code
    /// [`maintenance::MAINTENANCE_ERROR_CODE`], answered over HTTP with `503`;
    /// queries and subscriptions still run. The application keeps a clone of
    /// the gate to close and open it.
    pub maintenance_gate: maintenance::MaintenanceGate,
}

/// Runs a web server.
///
/// `ip_locator` is used only by the IP location queries (`ipLocation` and
/// `ipLocationList`). Country codes on events come from the locator passed to
/// `Store::new` when the store was created, so supplying one here while
/// opening the store without one does not resolve event country codes during
/// ingestion. Such events are stored with the `"XX"` placeholder and are
/// reachable through a `countries: ["XX"]` filter.
///
/// `agent_manager`, `package_deployer` and `host_onboarder` are placed on the
/// GraphQL schema, so a resolver reaches each of them through the request
/// context.
///
/// # Panics
///
/// Panics if binding to the address fails.
#[allow(clippy::too_many_lines)]
pub fn serve<A, O>(
    config: ServerConfig,
    store: Arc<RwLock<Store>>,
    ip_locator: Option<Arc<ip2location::DB>>,
    agent_manager: A,
    package_deployer: SharedPackageDeployer,
    host_onboarder: O,
    customer_data_deletion_manager: Arc<customer_data_deletion::CustomerDataDeletionTaskManager>,
) -> Arc<Notify>
where
    A: AgentManager + 'static,
    O: HostOnboarder + 'static,
{
    use axum_server::Handle;
    use tracing::info;

    let schema = graphql::schema(
        store.clone(),
        agent_manager,
        package_deployer,
        host_onboarder,
        ip_locator,
        config.cert_manager.clone(),
        config.tls_reload_handle.clone(),
        config.maintenance_gate.clone(),
        customer_data_deletion_manager,
    );
    let web_srv_shutdown_handle = Arc::new(Notify::new());
    let shutdown_handle = web_srv_shutdown_handle.clone();
    let server: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        loop {
            let router =
                Router::new().route("/graphql", get(graphql_ws_handler).post(graphql_handler));
            let router = router.merge(ingress::router());
            let router = router
                .layer(Extension(schema.clone()))
                .layer(Extension(store.clone()))
                .layer(Extension(config.package_store.clone()))
                .layer(Extension(PackageUploadLimit(
                    config.package_upload_max_bytes,
                )))
                .layer(Extension(config.trust_manager.clone()))
                .layer(Extension(TrustGenerationLimit(
                    config.trust_generation_max_bytes,
                )));
            let router = router.layer(Extension(config.authenticator.clone()));

            let handle = Handle::new();
            let notify_shutdown = Arc::new(Notify::new());
            let shutdown_completed = Arc::new(Notify::new());
            let tls_config = build_tls_config(
                config.cert_manager.as_ref(),
                &config.ca_certs,
                &config.crypto_provider,
            )?;

            let wait_shutdown = notify_shutdown.clone();
            let completed = shutdown_completed.clone();
            tokio::spawn(graceful_shutdown(handle.clone(), wait_shutdown));
            tokio::spawn(async move {
                let server = axum_server::Server::bind(config.addr)
                    .acceptor(TlsPeerAcceptor::new(tls_config));

                if let Err(e) = server
                    .handle(handle)
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                {
                    panic!("Web server encountered an error: {e:?}");
                }

                completed.notify_one();
            });

            let wait_shutdown = web_srv_shutdown_handle.notified();
            let tls_reload = config.tls_reload_handle.notified();

            tokio::select! {
                () = wait_shutdown => {
                    info!("Manager GraphQL web server is stopping");
                    notify_shutdown.notify_one();
                    shutdown_completed.notified().await;
                    web_srv_shutdown_handle.notify_one();
                    return Ok(());
                },
                () = tls_reload => {
                    info!("Restarting Web server to reload certificates");
                    notify_shutdown.notify_one();
                    shutdown_completed.notified().await;
                },
            }
        }
    });

    info!("Manager GraphQL web server is starting");
    tokio::spawn(async {
        match server.await {
            Ok(Err(e)) => error!("Web server died: {:?}", e),
            Err(e) => error!("Web server task failed to execute to completion: {:?}", e),
            _ => (),
        }
    });

    shutdown_handle
}

#[derive(Debug)]
struct TlsPeerInfo {
    certs: Vec<CertificateDer<'static>>,
}

impl TlsPeerInfo {
    fn leaf_cert(&self) -> Option<&CertificateDer<'static>> {
        self.certs.first()
    }
}

#[derive(Clone)]
struct InjectTlsPeer<S> {
    inner: S,
    peer: Option<Arc<TlsPeerInfo>>,
}

impl<S> InjectTlsPeer<S> {
    fn new(inner: S, peer: Option<Arc<TlsPeerInfo>>) -> Self {
        Self { inner, peer }
    }
}

impl<S, B> Service<http::Request<B>> for InjectTlsPeer<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        if let Some(peer) = &self.peer {
            req.extensions_mut().insert(peer.clone());
        }
        self.inner.call(req)
    }
}

#[derive(Clone)]
struct TlsPeerAcceptor {
    config: axum_server::tls_rustls::RustlsConfig,
    handshake_timeout: std::time::Duration,
}

impl TlsPeerAcceptor {
    fn new(config: axum_server::tls_rustls::RustlsConfig) -> Self {
        Self {
            config,
            handshake_timeout: std::time::Duration::from_secs(10),
        }
    }
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for TlsPeerAcceptor
where
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Service = InjectTlsPeer<S>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let config = self.config.clone();
        let timeout = self.handshake_timeout;
        Box::pin(async move {
            let peer_addr = stream.peer_addr();
            let server_config = config.get_inner();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let tls = match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => return Err(log_failed_handshake(peer_addr.ok(), e)),
                Err(e) => {
                    let e = io::Error::new(io::ErrorKind::TimedOut, e);
                    return Err(log_failed_handshake(peer_addr.ok(), e));
                }
            };

            let peer = tls.get_ref().1.peer_certificates().map(|certs| {
                let certs = certs
                    .iter()
                    .cloned()
                    .map(CertificateDer::into_owned)
                    .collect();
                Arc::new(TlsPeerInfo { certs })
            });
            let service = InjectTlsPeer::new(service, peer);

            Ok((tls, service))
        })
    }
}

/// Logs a TLS handshake that failed or timed out, and returns its error
/// unchanged.
fn log_failed_handshake(peer: Option<SocketAddr>, e: io::Error) -> io::Error {
    let peer = peer.map_or_else(|| "an unknown address".to_string(), |peer| peer.to_string());
    warn!("TLS handshake from {peer} failed: {e}");
    e
}

async fn graceful_shutdown(handle: axum_server::Handle<SocketAddr>, notify: Arc<Notify>) {
    use std::time::Duration;

    notify.notified().await;
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
}

async fn graphql_handler(
    Extension(schema): Extension<graphql::Schema>,
    Extension(_store): Extension<Arc<RwLock<Store>>>,
    Extension(authenticator): Extension<Arc<dyn MtlsAuthenticator>>,
    peer: Option<Extension<Arc<TlsPeerInfo>>>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    request: GraphQLRequest,
) -> Result<Response, Error> {
    let request = request.into_inner();
    let peer = peer
        .map(|Extension(p)| p)
        .ok_or_else(|| Error::Unauthorized(ERR_MTLS_REQUIRED.to_string()))?;
    let cert = peer
        .leaf_cert()
        .ok_or_else(|| Error::Unauthorized(ERR_MTLS_MISSING_CERT.to_string()))?;
    let identity = authenticator.authenticate(cert)?;

    let auth = auth?;
    let (role, customer_ids) = validate_context_jwt(auth.token(), cert)?;
    Ok(graphql_http_response(
        schema
            .execute(
                request
                    .data(RoleGuard::Role(role))
                    .data(CustomerIds(customer_ids))
                    .data(identity),
            )
            .await,
    ))
}

/// Converts a GraphQL response into an HTTP response.
///
/// A GraphQL error is otherwise answered with `200`, which some callers read
/// as success, so a mutation refused under a closed maintenance gate is
/// answered with `503` instead. The body is the GraphQL response either way,
/// so the caller also sees the error's code.
fn graphql_http_response(response: async_graphql::Response) -> Response {
    if response.errors.iter().any(maintenance::is_refusal) {
        (
            http::StatusCode::SERVICE_UNAVAILABLE,
            GraphQLResponse::from(response),
        )
            .into_response()
    } else {
        GraphQLResponse::from(response).into_response()
    }
}

#[allow(clippy::unused_async)]
async fn graphql_ws_handler(
    Extension(schema): Extension<graphql::Schema>,
    Extension(authenticator): Extension<Arc<dyn MtlsAuthenticator>>,
    protocol: GraphQLProtocol,
    websocket: WebSocketUpgrade,
    peer: Option<Extension<Arc<TlsPeerInfo>>>,
) -> Response {
    let peer = peer.map(|Extension(p)| p);
    websocket
        .protocols(["graphql-ws"])
        .on_upgrade(move |socket| {
            let peer = peer.clone();
            GraphQLWebSocket::new(socket, schema.clone(), protocol)
                .on_connection_init(move |value| {
                    let peer = peer.clone();
                    let authenticator = authenticator.clone();
                    async move {
                        #[derive(serde::Deserialize)]
                        struct AuthData {
                            #[serde(rename = "Authorization")]
                            auth: String,
                        }
                        let mut data = Data::default();

                        let peer =
                            peer.ok_or_else(|| async_graphql::Error::new(ERR_MTLS_REQUIRED))?;
                        let cert = peer
                            .leaf_cert()
                            .ok_or_else(|| async_graphql::Error::new(ERR_MTLS_MISSING_CERT))?;
                        let identity = authenticator
                            .authenticate(cert)
                            .map_err(|e| async_graphql::Error::new(e.to_string()))?;

                        let auth_data = serde_json::from_value::<AuthData>(value)?;
                        let token = auth_data
                            .auth
                            .split_ascii_whitespace()
                            .last()
                            .ok_or_else(|| async_graphql::Error::new(ERR_MISSING_AUTHORIZATION))?;
                        let (role, customer_ids) = validate_context_jwt(token, cert)
                            .map_err(|e| async_graphql::Error::new(e.to_string()))?;

                        data.insert(RoleGuard::Role(role));
                        data.insert(CustomerIds(customer_ids));
                        data.insert(identity);
                        Ok(data)
                    }
                })
                .serve()
        })
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Service Unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("Bad Request: {0}")]
    BadRequest(String),
    #[error("With status: {0}")]
    WithStatus(reqwest::StatusCode),
    #[error("Time out: {0}")]
    TimeOut(String),
    #[error("Authentication Error: {0}")]
    Unauthorized(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Payload Too Large: {0}")]
    PayloadTooLarge(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("InternalServerError: {0}")]
    InternalServerError(String),
    #[error("Other: {0}")]
    Other(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        use http::StatusCode;

        let (status, msg) = match self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            Self::WithStatus(s) => (s, format!("Oops, {s}")),
            Self::TimeOut(msg) => (StatusCode::REQUEST_TIMEOUT, msg),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            Self::PayloadTooLarge(msg) => (StatusCode::PAYLOAD_TOO_LARGE, msg),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg),
            Self::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Self::NotFound(msg) | Self::Other(msg) => (StatusCode::NOT_FOUND, msg),
        };
        let body = Json(json!({
            "error": msg,
        }));
        (status, body).into_response()
    }
}

impl From<MtlsAuthError> for Error {
    fn from(err: MtlsAuthError) -> Self {
        Self::Unauthorized(err.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Self::NotFound(err.to_string()),
            _ => Self::InternalServerError(err.to_string()),
        }
    }
}

impl From<TypedHeaderRejection> for Error {
    fn from(err: TypedHeaderRejection) -> Self {
        Self::Unauthorized(err.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        if err.is_status() {
            Self::WithStatus(err.status().unwrap_or_default())
        } else if err.is_connect() {
            Self::ServiceUnavailable(err.to_string())
        } else if err.is_timeout() {
            Self::TimeOut(err.to_string())
        } else if err.is_request() {
            Self::BadRequest(err.to_string())
        } else {
            Self::Other(err.to_string())
        }
    }
}

impl From<http::Error> for Error {
    fn from(err: http::Error) -> Self {
        Self::ServiceUnavailable(format!("Fail to route: {err}"))
    }
}

fn read_certificate_from_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<CertificateDer<'static>>, anyhow::Error> {
    let cert = read(&path)?;
    let certs = rustls_pemfile::certs(&mut &*cert).collect::<Result<_, _>>()?;
    Ok(certs)
}

fn read_private_key_from_path<P: AsRef<Path>>(
    path: P,
) -> Result<PrivateKeyDer<'static>, anyhow::Error> {
    let key = read(&path)?;
    let mut key_reader = &*key;

    // Try to read various private key formats
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut key_reader)
        .flatten()
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    key_reader = &*key;
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .flatten()
        .next()
    {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    key_reader = &*key;
    if let Some(key) = rustls_pemfile::ec_private_keys(&mut key_reader)
        .flatten()
        .next()
    {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    anyhow::bail!(
        "No supported private key found in {}",
        path.as_ref().display()
    )
}

/// Builds the TLS configuration of the HTTPS server from the certificate and
/// key `cert_manager` currently points at, with `provider` as its only source
/// of cryptography.
fn build_tls_config(
    cert_manager: &dyn CertManager,
    ca_certs: &[PathBuf],
    provider: &Arc<CryptoProvider>,
) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
    let (cert_path, key_path) = (cert_manager.cert_path()?, cert_manager.key_path()?);
    let server_config = build_mtls_server_config(
        cert_path.as_path(),
        key_path.as_path(),
        ca_certs,
        Arc::clone(provider),
    )?;
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    ))
}

fn build_mtls_server_config(
    cert_path: &Path,
    key_path: &Path,
    ca_certs: &[PathBuf],
    provider: Arc<CryptoProvider>,
) -> Result<rustls::ServerConfig, anyhow::Error> {
    let cert_chain = read_certificate_from_path(cert_path)?;
    let key = read_private_key_from_path(key_path)?;

    let mut root_store = RootCertStore::empty();
    for root in ca_certs {
        let certs = read_certificate_from_path(root)?;
        for cert in certs {
            root_store.add(cert)?;
        }
    }

    let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store),
        Arc::clone(&provider),
    )
    .build()
    .map_err(|e| anyhow::anyhow!("Invalid client auth config: {e:?}"))?;

    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(config)
}

#[macro_export]
macro_rules! error_with_username {
    ($ctx:expr, $($arg:tt)+) => {{
        let username = $ctx
            .data::<String>()
            .map(String::as_str)
            .unwrap_or("<unknown user>");

        error!("user={} {}", username, format!($($arg)+));
    }};
    (username: $username:expr, $($arg:tt)+) => {{
        error!("user={} {}", $username, format!($($arg)+));
    }};
}

#[macro_export]
macro_rules! info_with_username {
    ($ctx:expr, $($arg:tt)+) => {{
        let username = $ctx
            .data::<String>()
            .map(String::as_str)
            .unwrap_or("<unknown user>");

        info!("user={} {}", username, format!($($arg)+));
    }};
    (username: $username:expr, $($arg:tt)+) => {{
        info!("user={} {}", $username, format!($($arg)+));
    }};
}

#[macro_export]
macro_rules! warn_with_username {
    ($ctx:expr, $($arg:tt)+) => {{
        let username = $ctx
            .data::<String>()
            .map(String::as_str)
            .unwrap_or("<unknown user>");

        warn!("user={} {}", username, format!($($arg)+));
    }};
    (username: $username:expr, $($arg:tt)+) => {{
        warn!("user={} {}", $username, format!($($arg)+));
    }};
}

#[cfg(test)]
mod tests {
    use std::{io::Write, sync::Mutex, time::Duration};

    use async_graphql::{ErrorExtensionValues, ServerError};
    use axum_server::{accept::Accept, tls_rustls::RustlsConfig};
    use http::StatusCode;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
        SanType,
    };
    use rustls::{
        NamedGroup, PeerIncompatible, ProtocolVersion,
        client::WebPkiServerVerifier,
        crypto::aws_lc_rs,
        pki_types::{PrivatePkcs8KeyDer, ServerName},
    };
    use tempfile::TempDir;
    use tokio::net::{TcpListener, TcpStream};
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    const LOCALHOST: &str = "127.0.0.1";

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl LogCapture {
        /// Returns every captured WARN line.
        fn warnings(&self) -> Vec<String> {
            let buffer = self.0.lock().expect("the log mutex");
            String::from_utf8_lossy(&buffer)
                .lines()
                .filter(|line| line.trim_start().starts_with("WARN"))
                .map(ToString::to_string)
                .collect()
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

    /// Installs a subscriber capturing every event on the current thread for
    /// as long as the returned guard lives.
    fn capture_logs() -> (LogCapture, tracing::subscriber::DefaultGuard) {
        let logs = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .without_time()
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (logs, guard)
    }

    /// A provider whose only key-exchange group is X25519MLKEM768 and whose
    /// only cipher suites are TLS 1.3's.
    fn hybrid_only() -> Arc<CryptoProvider> {
        let base = aws_lc_rs::default_provider();
        Arc::new(CryptoProvider {
            cipher_suites: base
                .cipher_suites
                .iter()
                .copied()
                .filter(|suite| suite.tls13().is_some())
                .collect(),
            kx_groups: vec![aws_lc_rs::kx_group::X25519MLKEM768],
            ..base
        })
    }

    fn x25519_only() -> Arc<CryptoProvider> {
        Arc::new(CryptoProvider {
            kx_groups: vec![aws_lc_rs::kx_group::X25519],
            ..aws_lc_rs::default_provider()
        })
    }

    /// A CA, the certificate a client presents, and a directory holding the
    /// CA certificate and the server's certificate and key.
    struct Pki {
        issuer: Issuer<'static, KeyPair>,
        ca_der: CertificateDer<'static>,
        client_cert: CertificateDer<'static>,
        client_key: PrivateKeyDer<'static>,
        dir: TempDir,
    }

    impl Pki {
        fn new() -> Self {
            let mut params = CertificateParams::default();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params
                .distinguished_name
                .push(DnType::CommonName, "review-web-test-ca");
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let ca = params.self_signed(&key).unwrap();
            let issuer = Issuer::new(params, key);

            let client_params = CertificateParams::new(vec!["client.example.com".to_string()])
                .expect("the client name is a valid DNS name");
            let client_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("ca.pem"), ca.pem()).unwrap();
            let pki = Self {
                issuer,
                ca_der: ca.der().clone(),
                client_cert: client_cert.der().clone(),
                client_key: PrivatePkcs8KeyDer::from(client_key.serialize_der()).into(),
                dir,
            };
            pki.renew_server_cert();
            pki
        }

        /// Writes a new server certificate for `127.0.0.1` over the current
        /// one, and returns it.
        fn renew_server_cert(&self) -> CertificateDer<'static> {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params
                .subject_alt_names
                .push(SanType::IpAddress(LOCALHOST.parse().unwrap()));
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = params.signed_by(&key, &self.issuer).unwrap();
            std::fs::write(self.dir.path().join("server.pem"), cert.pem()).unwrap();
            std::fs::write(self.dir.path().join("server.key"), key.serialize_pem()).unwrap();
            cert.der().clone()
        }

        fn ca_certs(&self) -> Vec<PathBuf> {
            vec![self.dir.path().join("ca.pem")]
        }

        fn cert_manager(&self) -> StubCertManager {
            StubCertManager {
                cert_path: self.dir.path().join("server.pem"),
                key_path: self.dir.path().join("server.key"),
            }
        }

        fn client(&self, provider: Arc<CryptoProvider>) -> rustls::ClientConfig {
            self.client_with_versions(provider, rustls::DEFAULT_VERSIONS)
        }

        fn client_with_versions(
            &self,
            provider: Arc<CryptoProvider>,
            versions: &[&'static rustls::SupportedProtocolVersion],
        ) -> rustls::ClientConfig {
            let mut roots = RootCertStore::empty();
            roots.add(self.ca_der.clone()).unwrap();
            let verifier =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .unwrap();
            rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(versions)
                .unwrap()
                .with_webpki_verifier(verifier)
                .with_client_auth_cert(vec![self.client_cert.clone()], self.client_key.clone_key())
                .unwrap()
        }

        fn client_without_identity(&self, provider: Arc<CryptoProvider>) -> rustls::ClientConfig {
            let mut roots = RootCertStore::empty();
            roots.add(self.ca_der.clone()).unwrap();
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
    }

    struct StubCertManager {
        cert_path: PathBuf,
        key_path: PathBuf,
    }

    impl CertManager for StubCertManager {
        fn cert_path(&self) -> Result<PathBuf, anyhow::Error> {
            Ok(self.cert_path.clone())
        }

        fn key_path(&self) -> Result<PathBuf, anyhow::Error> {
            Ok(self.key_path.clone())
        }

        fn update_certificate(
            &self,
            _cert: String,
            _key: String,
        ) -> Result<Vec<crate::graphql::ParsedCertificate>, anyhow::Error> {
            Ok(Vec::new())
        }
    }

    struct Handshake {
        client: io::Result<tokio_rustls::client::TlsStream<TcpStream>>,
        server: io::Result<()>,
        client_port: u16,
    }

    /// Runs one handshake between `client` and `TlsPeerAcceptor` over
    /// `server`.
    async fn handshake(server: RustlsConfig, client: rustls::ClientConfig) -> Handshake {
        let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsPeerAcceptor::new(server);
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let client_port = tcp.local_addr().unwrap().port();
        let (accepted, _) = listener.accept().await.unwrap();
        let server_name = ServerName::try_from(LOCALHOST).unwrap();
        let (client, server) = tokio::join!(
            connector.connect(server_name, tcp),
            Accept::<TcpStream, ()>::accept(&acceptor, accepted, ()),
        );
        Handshake {
            client,
            server: server.map(|_| ()),
            client_port,
        }
    }

    fn rustls_error(e: &io::Error) -> &rustls::Error {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            .unwrap_or_else(|| panic!("not a rustls error: {e:?}"))
    }

    fn served_leaf(tls: &tokio_rustls::client::TlsStream<TcpStream>) -> CertificateDer<'static> {
        tls.get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .expect("the server presented a certificate")
            .clone()
            .into_owned()
    }

    fn hybrid_server(pki: &Pki) -> RustlsConfig {
        build_tls_config(&pki.cert_manager(), &pki.ca_certs(), &hybrid_only()).unwrap()
    }

    #[tokio::test]
    async fn an_x25519_only_client_is_refused_and_logged() {
        let pki = Pki::new();
        let (logs, _guard) = capture_logs();
        let outcome = handshake(hybrid_server(&pki), pki.client(x25519_only())).await;

        assert!(outcome.client.is_err());
        let e = outcome
            .server
            .expect_err("the server refuses the handshake");
        assert!(matches!(
            rustls_error(&e),
            rustls::Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon)
        ));
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let expected = format!(
            "TLS handshake from 127.0.0.1:{} failed: peer is incompatible: NoKxGroupsInCommon",
            outcome.client_port
        );
        assert!(warnings[0].ends_with(&expected), "{}", warnings[0]);
    }

    #[tokio::test]
    async fn a_tls12_only_client_is_refused() {
        let pki = Pki::new();
        let (logs, _guard) = capture_logs();
        let client = pki.client_with_versions(
            Arc::new(aws_lc_rs::default_provider()),
            &[&rustls::version::TLS12],
        );
        let outcome = handshake(hybrid_server(&pki), client).await;

        assert!(outcome.client.is_err());
        let e = outcome
            .server
            .expect_err("the server refuses the handshake");
        assert!(matches!(
            rustls_error(&e),
            rustls::Error::PeerIncompatible(PeerIncompatible::Tls12NotOfferedOrEnabled)
        ));
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let expected = format!(
            "TLS handshake from 127.0.0.1:{} failed: peer is incompatible: \
             Tls12NotOfferedOrEnabled",
            outcome.client_port
        );
        assert!(warnings[0].ends_with(&expected), "{}", warnings[0]);
    }

    #[tokio::test]
    async fn a_default_client_negotiates_x25519mlkem768() {
        let pki = Pki::new();
        let (logs, _guard) = capture_logs();
        let client = pki.client(Arc::new(aws_lc_rs::default_provider()));
        let outcome = handshake(hybrid_server(&pki), client).await;

        outcome.server.expect("the server completes the handshake");
        let tls = outcome.client.expect("the client completes the handshake");
        let connection = tls.get_ref().1;
        assert_eq!(
            connection
                .negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name),
            Some(NamedGroup::X25519MLKEM768)
        );
        assert_eq!(
            connection.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert!(logs.warnings().is_empty(), "{:?}", logs.warnings());
    }

    /// Asserts that `config` serves `expected`, refuses an X25519-only client
    /// and completes a handshake with a client on the default provider.
    async fn assert_serves(pki: &Pki, config: RustlsConfig, expected: &CertificateDer<'_>) {
        let refused = handshake(config.clone(), pki.client(x25519_only())).await;
        let e = refused
            .server
            .expect_err("the server refuses the handshake");
        assert!(matches!(
            rustls_error(&e),
            rustls::Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon)
        ));

        let client = pki.client(Arc::new(aws_lc_rs::default_provider()));
        let accepted = handshake(config, client).await;
        accepted.server.expect("the server completes the handshake");
        let tls = accepted.client.expect("the client completes the handshake");
        assert_eq!(&served_leaf(&tls), expected);
    }

    #[tokio::test]
    async fn a_rebuilt_configuration_keeps_the_provider() {
        let pki = Pki::new();
        let provider = hybrid_only();
        let cert_manager = pki.cert_manager();

        let first = pki.renew_server_cert();
        let config = build_tls_config(&cert_manager, &pki.ca_certs(), &provider).unwrap();
        assert_serves(&pki, config, &first).await;

        let second = pki.renew_server_cert();
        assert_ne!(first, second);
        let config = build_tls_config(&cert_manager, &pki.ca_certs(), &provider).unwrap();
        assert_serves(&pki, config, &second).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_timeout_is_logged() {
        let pki = Pki::new();
        let (logs, _guard) = capture_logs();
        let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let client_port = tcp.local_addr().unwrap().port();
        let (accepted, _) = listener.accept().await.unwrap();
        let acceptor = TlsPeerAcceptor::new(hybrid_server(&pki));

        let started = tokio::time::Instant::now();
        let e = Accept::<TcpStream, ()>::accept(&acceptor, accepted, ())
            .await
            .map(|_| ())
            .expect_err("a silent peer times out");
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_secs(10));
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let expected =
            format!("TLS handshake from 127.0.0.1:{client_port} failed: deadline has elapsed");
        assert!(warnings[0].ends_with(&expected), "{}", warnings[0]);
        drop(tcp);
    }

    #[tokio::test]
    async fn a_client_without_a_certificate_is_refused_and_logged() {
        let pki = Pki::new();
        let (logs, _guard) = capture_logs();
        let client = pki.client_without_identity(Arc::new(aws_lc_rs::default_provider()));
        let outcome = handshake(hybrid_server(&pki), client).await;

        let e = outcome
            .server
            .expect_err("the server refuses the handshake");
        assert!(matches!(
            rustls_error(&e),
            rustls::Error::NoCertificatesPresented
        ));
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let expected = format!(
            "TLS handshake from 127.0.0.1:{} failed: {e}",
            outcome.client_port
        );
        assert!(warnings[0].ends_with(&expected), "{}", warnings[0]);
    }

    #[test]
    fn an_unknown_peer_address_is_logged_as_such() {
        let (logs, _guard) = capture_logs();
        let e = log_failed_handshake(None, io::Error::other("tls handshake eof"));

        assert_eq!(e.kind(), io::ErrorKind::Other);
        assert_eq!(e.to_string(), "tls handshake eof");
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0]
                .ends_with("TLS handshake from an unknown address failed: tls handshake eof"),
            "{}",
            warnings[0]
        );
    }

    async fn status_and_body(response: async_graphql::Response) -> (StatusCode, serde_json::Value) {
        let response = graphql_http_response(response);
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn error_with_code(code: &str) -> ServerError {
        let mut extensions = ErrorExtensionValues::default();
        extensions.set("code", code);
        let mut error = ServerError::new("refused", None);
        error.extensions = Some(extensions);
        error
    }

    #[tokio::test]
    async fn maintenance_refusal_answers_503() {
        let refused = async_graphql::Response::from_errors(vec![error_with_code(
            maintenance::MAINTENANCE_ERROR_CODE,
        )]);
        let (status, body) = status_and_body(refused).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["data"], serde_json::Value::Null);
        assert_eq!(
            body["errors"][0]["extensions"]["code"],
            maintenance::MAINTENANCE_ERROR_CODE
        );

        let unrelated =
            async_graphql::Response::from_errors(vec![error_with_code("NOT_MAINTENANCE")]);
        let (status, _) = status_and_body(unrelated).await;
        assert_eq!(status, StatusCode::OK);

        let succeeded = async_graphql::Response::new(async_graphql::Value::Null);
        let (status, _) = status_and_body(succeeded).await;
        assert_eq!(status, StatusCode::OK);
    }
}
