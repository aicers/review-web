use std::sync::Arc;

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
use tokio::sync::RwLock;

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

            let store = state.store.read().await;
            let (_, role) = validate_token(&store, bearer.token())?;

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
        Some(Path(tail)) if !config.uri().ends_with("/graphql") => {
            format!("{}/{tail}", config.uri())
        }
        _ => config.uri().into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_construction_without_graphql_suffix() {
        let config = Config {
            base: "archive".to_string(),
            uri: "http://example.com".to_string(),
            roles: None,
        };

        // Test with tail
        let tail = Some("graphql");
        let url = match tail {
            Some(tail) if !config.uri().ends_with("/graphql") => {
                format!("{}/{tail}", config.uri())
            }
            _ => config.uri().into(),
        };
        assert_eq!(url, "http://example.com/graphql");

        // Test without tail
        let tail: Option<&str> = None;
        let url = match tail {
            Some(tail) if !config.uri().ends_with("/graphql") => {
                format!("{}/{tail}", config.uri())
            }
            _ => config.uri().into(),
        };
        assert_eq!(url, "http://example.com");
    }

    #[test]
    fn test_url_construction_with_graphql_suffix() {
        let config = Config {
            base: "archive".to_string(),
            uri: "http://example.com/graphql".to_string(),
            roles: None,
        };

        // Test with tail that would duplicate /graphql
        let tail = Some("graphql");
        let url = match tail {
            Some(tail) if !config.uri().ends_with("/graphql") => {
                format!("{}/{tail}", config.uri())
            }
            _ => config.uri().into(),
        };
        assert_eq!(url, "http://example.com/graphql");

        // Test without tail
        let tail: Option<&str> = None;
        let url = match tail {
            Some(tail) if !config.uri().ends_with("/graphql") => {
                format!("{}/{tail}", config.uri())
            }
            _ => config.uri().into(),
        };
        assert_eq!(url, "http://example.com/graphql");
    }

    #[test]
    fn test_url_construction_with_other_tail() {
        let config = Config {
            base: "archive".to_string(),
            uri: "http://example.com".to_string(),
            roles: None,
        };

        // Test with a different tail
        let tail = Some("api/v1");
        let url = match tail {
            Some(tail) if !config.uri().ends_with("/graphql") => {
                format!("{}/{tail}", config.uri())
            }
            _ => config.uri().into(),
        };
        assert_eq!(url, "http://example.com/api/v1");
    }

    #[test]
    fn test_config_base() {
        let config = Config {
            base: "archive".to_string(),
            uri: "http://example.com".to_string(),
            roles: None,
        };
        assert_eq!(config.base(), "/archive");
    }

    #[test]
    fn test_config_roles_default() {
        let config = Config {
            base: "archive".to_string(),
            uri: "http://example.com".to_string(),
            roles: None,
        };
        assert_eq!(
            config.roles(),
            vec![Role::SecurityAdministrator, Role::SystemAdministrator]
        );
    }

    #[test]
    fn test_config_roles_custom() {
        let config = Config {
            base: "archive".to_string(),
            uri: "http://example.com".to_string(),
            roles: Some(vec![Role::SecurityAdministrator]),
        };
        assert_eq!(config.roles(), vec![Role::SecurityAdministrator]);
    }
}
