pub mod archive;
pub mod auth;
pub mod backend;
pub mod graphql;

use std::{
    fs::read,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_graphql::{
    Data,
    http::{GraphQLPlaygroundConfig, playground_source},
};
use async_graphql_axum::{GraphQLProtocol, GraphQLRequest, GraphQLResponse, GraphQLWebSocket};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, WebSocketUpgrade},
    response::{Html, IntoResponse, Response},
    routing::{get, get_service},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
    typed_header::TypedHeaderRejection,
};
use graphql::RoleGuard;
use review_database::{Database, Store};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use serde_json::json;
use tokio::{
    sync::{Notify, RwLock},
    task::JoinHandle,
};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::{error, warn};

use crate::auth::{AuthError, validate_token};
use crate::backend::{AgentManager, CertManager};

/// Parameters for a web server.
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub document_root: PathBuf,
    pub cert_manager: Arc<dyn CertManager>,
    pub cert_reload_handle: Arc<Notify>,
    pub ca_certs: Vec<PathBuf>,
    pub reverse_proxies: Vec<archive::Config>,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
}

/// Runs a web server.
///
/// # Panics
///
/// Panics if binding to the address fails.
pub fn serve<A>(
    config: ServerConfig,
    db: Database,
    store: Arc<RwLock<Store>>,
    ip_locator: Option<ip2location::DB>,
    agent_manager: A,
) -> Arc<Notify>
where
    A: AgentManager + 'static,
{
    use axum_server::{Handle, tls_rustls::RustlsConfig};
    use tracing::info;

    let schema = graphql::schema(
        db,
        store.clone(),
        agent_manager,
        ip_locator,
        config.cert_manager.clone(),
        config.cert_reload_handle.clone(),
    );
    let web_srv_shutdown_handle = Arc::new(Notify::new());
    let shutdown_handle = web_srv_shutdown_handle.clone();
    let client = client(
        &config.ca_certs,
        config.client_cert_path.as_ref(),
        config.client_key_path.as_ref(),
    );
    let server: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        loop {
            let static_files = get_service(ServeDir::new(config.document_root.clone()));

            let proxies_config = crate::archive::Config::configure_reverse_proxies(
                &store,
                client.as_ref(),
                &config.reverse_proxies,
            );

            let mut router = Router::new()
                .route("/graphql", get(graphql_ws_handler).post(graphql_handler))
                .route(
                    "/graphql/playground",
                    get(graphql_playground).post(graphql_handler),
                )
                .fallback_service(static_files.layer(TraceLayer::new_for_http()))
                .layer(Extension(schema.clone()))
                .layer(Extension(store.clone()));
            for (s, p) in proxies_config {
                router = router.nest(&s.base(), p.with_state(s));
            }

            let handle = Handle::new();
            let notify_shutdown = Arc::new(Notify::new());
            let shutdown_completed = Arc::new(Notify::new());
            let (cert_path, key_path) = (
                config.cert_manager.cert_path()?,
                config.cert_manager.key_path()?,
            );
            let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;

            let wait_shutdown = notify_shutdown.clone();
            let completed = shutdown_completed.clone();
            tokio::spawn(graceful_shutdown(handle.clone(), wait_shutdown));
            tokio::spawn(async move {
                if let Err(e) = axum_server::bind_rustls(config.addr, tls_config)
                    .handle(handle)
                    .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                    .await
                {
                    panic!("Web server encountered an error: {e:?}");
                }

                completed.notify_one();
            });

            let wait_shutdown = web_srv_shutdown_handle.notified();
            let cert_reload = config.cert_reload_handle.notified();

            tokio::select! {
                () = wait_shutdown => {
                    info!("Shutting down Web server");
                    notify_shutdown.notify_one();
                    shutdown_completed.notified().await;
                    web_srv_shutdown_handle.notify_one();
                    return Ok(());
                },
                () = cert_reload => {
                    info!("Restarting Web server to reload certificates");
                    notify_shutdown.notify_one();
                    shutdown_completed.notified().await;
                },
            }
        }
    });

    info!("Starting Web Server");
    tokio::spawn(async {
        match server.await {
            Ok(Err(e)) => error!("Web server died: {:?}", e),
            Err(e) => error!("Web server task failed to execute to completion: {:?}", e),
            _ => (),
        }
    });

    shutdown_handle
}

pub(crate) fn client<P: AsRef<std::path::Path>>(
    ca_certs: &[P],
    client_cert_path: Option<&PathBuf>,
    client_key_path: Option<&PathBuf>,
) -> Option<reqwest::Client> {
    let with_platform_root = false;
    let tls_config = build_client_config(
        ca_certs,
        with_platform_root,
        client_cert_path,
        client_key_path,
    )
    .expect("failed to add cert to store");

    reqwest::ClientBuilder::new()
        .use_preconfigured_tls(tls_config)
        .build()
        .ok()
}

async fn graceful_shutdown(handle: axum_server::Handle, notify: Arc<Notify>) {
    use std::time::Duration;

    notify.notified().await;
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
}

#[allow(clippy::unused_async)]
async fn graphql_playground() -> Result<impl IntoResponse, Error> {
    Ok(Html(playground_source(
        GraphQLPlaygroundConfig::new("/graphql").subscription_endpoint("/graphql"),
    )))
}

fn is_local(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

async fn graphql_handler(
    Extension(schema): Extension<graphql::Schema>,
    Extension(store): Extension<Arc<RwLock<Store>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    request: GraphQLRequest,
) -> Result<GraphQLResponse, Error> {
    let request = request.into_inner();
    match auth {
        Ok(auth) => {
            let (username, role) = {
                let store = store.read().await;
                validate_token(&store, auth.token())?
            };
            Ok(schema
                .execute(request.data(username).data(RoleGuard::Role(role)))
                .await
                .into())
        }
        Err(_e) => {
            if is_local(addr) {
                Ok(schema
                    .execute(request.data(RoleGuard::Local).data(addr))
                    .await
                    .into())
            } else {
                Ok(schema.execute(request.data(addr)).await.into())
            }
        }
    }
}

#[allow(clippy::unused_async)]
async fn graphql_ws_handler(
    Extension(schema): Extension<graphql::Schema>,
    Extension(store): Extension<Arc<RwLock<Store>>>,
    protocol: GraphQLProtocol,
    websocket: WebSocketUpgrade,
) -> Response {
    websocket
        .protocols(["graphql-ws"])
        .on_upgrade(move |socket| {
            GraphQLWebSocket::new(socket, schema.clone(), protocol)
                .on_connection_init(|value| async move {
                    #[derive(serde::Deserialize)]
                    struct AuthData {
                        #[serde(rename = "Authorization")]
                        auth: String,
                    }
                    let auth_data = serde_json::from_value::<AuthData>(value)?;
                    let mut data = Data::default();
                    if let Some(token) = auth_data.auth.split_ascii_whitespace().last() {
                        let (username, role) = {
                            let store = store.read().await;
                            validate_token(&store, token)?
                        };

                        data.insert(RoleGuard::Role(role));
                        data.insert(username);
                    }
                    Ok(data)
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
            Self::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Self::NotFound(msg) | Self::Other(msg) => (StatusCode::NOT_FOUND, msg),
        };
        let body = Json(json!({
            "error": msg,
        }));
        (status, body).into_response()
    }
}

impl From<AuthError> for Error {
    fn from(err: AuthError) -> Self {
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

fn build_client_config<P: AsRef<Path>>(
    root_ca: &[P],
    with_platform_root: bool,
    client_cert_path: Option<&PathBuf>,
    client_key_path: Option<&PathBuf>,
) -> Result<ClientConfig, anyhow::Error> {
    let mut root_store = RootCertStore::empty();
    if with_platform_root {
        let certs = rustls_native_certs::load_native_certs();
        for c in certs.certs {
            root_store.add(c)?;
        }
        for e in certs.errors {
            warn!("Could not load platform certificate: {:#}", e);
        }
    }
    for root in root_ca {
        let certs = read_certificate_from_path(root)?;
        for cert in certs {
            root_store.add(cert)?;
        }
    }

    let mut builder = match (client_cert_path, client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let client_certs = read_certificate_from_path(cert_path)?;
            let client_key = read_private_key_from_path(key_path)?;

            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(client_certs, client_key)?
        }
        _ => rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    };

    builder.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(builder)
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
}
