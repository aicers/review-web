use std::sync::Arc;
use std::sync::RwLock;

use axum::{
    Router,
    body::Body,
    extract::{FromRef, FromRequestParts, Path, State},
    http::Request,
    middleware::{Next, from_fn_with_state},
    response::Response,
    routing::post,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
    typed_header::TypedHeaderRejection,
};
use http::{StatusCode, request::Parts};
use review_database::types::Role;
use serde::Deserialize;

use crate::{Error, Store, auth::validate_token};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    base: String,
    uri: String,
    roles: Option<Vec<Role>>,
}

impl Config {
    const ROLES: &'static [Role] = &[Role::SecurityAdministrator, Role::SystemAdministrator];

    fn base(&self) -> String {
        format!("/{}", self.base)
    }

    fn roles(&self) -> Vec<Role> {
        self.roles
            .as_ref()
            .map_or(Self::ROLES.to_owned(), Clone::clone)
    }

    fn uri(&self) -> &str {
        &self.uri
    }

    pub(crate) fn configure_reverse_proxies(
        store: &Arc<RwLock<Store>>,
        client: Option<&reqwest::Client>,
        reverse_proxies: &[Self],
    ) -> Vec<(ArchiveState, Router<ArchiveState>)> {
        reverse_proxies
            .iter()
            .map(|rp| {
                (
                    crate::archive::ArchiveState {
                        store: store.clone(),
                        client: client.cloned(),
                        config: rp.clone(),
                    },
                    crate::archive::reverse_proxy(store.clone(), client.cloned(), rp.clone()),
                )
            })
            .collect()
    }
}

#[derive(Clone, FromRef)]
pub(crate) struct ArchiveState {
    pub store: Arc<RwLock<Store>>,
    pub client: Option<reqwest::Client>,
    pub config: Config,
}

impl ArchiveState {
    pub(crate) fn base(&self) -> String {
        self.config.base()
    }
}

async fn auth(
    State(state): State<ArchiveState>,
    bearer: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Error> {
    let client = state.client;
    let config = state.config;
    match (client, config) {
        (Some(_client), config) => {
            let bearer = bearer?;
            let roles = config.roles();

            let role = {
                let store = state
                    .store
                    .read()
                    .unwrap_or_else(|e| panic!("RwLock poisoned: {e}"));
                let (_, role) = validate_token(&store, bearer.token())?;
                role
            };

            if roles.contains(&role) {
                Ok(next.run(req).await)
            } else {
                Err(Error::Unauthorized("Access denied".to_string()))
            }
        }
        _ => Err(Error::ServiceUnavailable(
            "proxy not configured".to_string(),
        )),
    }
}

async fn process_request(
    State(state): State<ArchiveState>,
    tail: Option<Path<String>>,
    req: Request<Body>,
) -> Result<Response, Error> {
    let client = state
        .client
        .ok_or_else(|| Error::ServiceUnavailable("Client was not initialized".to_string()))?;
    let config = state.config;

    let url = match tail {
        Some(Path(tail)) => format!("{}/{tail}", config.uri()),
        None => config.uri().into(),
    };

    let (parts, body) = req.into_parts();

    let method = parts.method;

    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| Error::BadRequest(e.to_string()))?;
    let req_body = reqwest::Body::from(body_bytes);
    let builder = client.request(method, url);
    let request = builder
        .headers(parts.headers)
        .version(parts.version)
        .body(req_body)
        .build()?;

    let response = client.execute(request).await?;

    let mut builder = http::response::Builder::new()
        .status(response.status())
        .version(response.version());
    if let Some(hdr) = builder.headers_mut() {
        *hdr = response.headers().clone();
    }
    let bytes = response.bytes().await?;

    let body = Body::from(bytes);

    Ok(builder.body(body)?)
}

fn reverse_proxy(
    store: Arc<RwLock<Store>>,
    client: Option<reqwest::Client>,
    config: Config,
) -> Router<ArchiveState> {
    let state = ArchiveState {
        store,
        client,
        config,
    };

    Router::new()
        .route("/", post(process_request))
        .route("/{*tail}", post(process_request))
        .route_layer(from_fn_with_state(state, auth))
}

impl<S> FromRequestParts<S> for ArchiveState
where
    S: Send + Sync,
    ArchiveState: FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);
    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(ArchiveState::from_ref(state))
    }
}
