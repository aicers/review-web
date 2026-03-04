#[cfg(feature = "auth-mtls")]
mod mtls_integration {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::{Arc, RwLock},
        time::Duration,
    };

    use anyhow::Context;
    use async_trait::async_trait;
    use chrono::{Duration as ChronoDuration, Utc};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair,
        PKCS_ECDSA_P256_SHA256, SanType,
    };
    use reqwest::Certificate as ReqwestCertificate;
    use review_database::Store;
    use review_web::{
        ServerConfig,
        auth::{MtlsAuthError, MtlsAuthenticator, MtlsIdentity},
        backend::{AgentManager, CertManager},
    };
    use serde::Serialize;
    use serde_json::json;
    use tokio::time::sleep;

    const SERVICE_DNS: &str = "edge.web-app.example.com";
    const ROLE: &str = "System Administrator";
    const CUSTOMER_ID: u32 = 1;
    const GRAPHQL_QUERY: &str = "{__typename}";
    const LOCALHOST_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const NON_ADMIN_ROLE: &str = "Security Administrator";
    const EXPECTED_SERVICE: &str = "web-app";
    const ERR_MISSING_SAN: &str = "Missing SAN";
    const ERR_NO_DNS_SAN: &str = "No DNS SAN";
    const ERR_MISSING_INSTANCE: &str = "Missing instance";
    const ERR_MISSING_SERVICE: &str = "Missing service";
    const ERR_MISSING_HOST: &str = "Missing host";
    const ERR_MISSING_DOMAIN: &str = "Missing domain";
    const ERR_SAN_SERVICE_MISMATCH: &str = "Client certificate SAN does not match service name";
    const ERR_JWT_ALG_EC_MISMATCH: &str = "JWT algorithm does not match EC key";
    const ERR_MISSING_CUSTOMER_IDS: &str = "Missing customer_ids claim for non-admin role";
    const WS_RECV_TIMEOUT: Duration = Duration::from_secs(5);
    // Fixed RSA private key used only to produce an RS256 JWT for alg-mismatch tests.
    const RSA_PRIVATE_KEY_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDL3Xrm3ySgvLcF
NcrMRfz9SN/DtjLfQzCU9kJWFXP42tcTrvFiOtZJoNzolSHLsc5QSXjlob5geTni
IO9Ter6tlNoaHxcFGlG8PCp2v8KRjHqUfctuW588tAKkPrO0pIkQpY119U/dSM/3
lNU7MNMjIgBKVqJX/kLMyqgFxbKNKZ+VFvbW5okDW3dth0QkGo2tyLQRmxv9lgHi
fE4/rmhR1ZrPlMhOj0fT/PZJGVdWl6+AxMmMulVby/EOWDupNGDhV3KnPlzesM0B
hFWeiRj4KpjJR2tk/YLIxhlxPBEf+7qSmIDc9oslpjmZ/GzPIjLdN62oskhw5874
0STjvcgZAgMBAAECggEAIecReQL7aaKwkhR9xwZNmgaMNdUfNStMkT05z2yOZoBo
O50AhfwwZjqy+hfQ8Lm/THFHgnKpQQxv8JfXDQww2ReTxLvOXXogxRvBWRGvRvq0
aOzZj577hoIOHWfTBVPGeob5lTgIQc3JzgvJgSgvuJw/LZ2mLll5nOqH0jvsI1bQ
VA54E71dV1kwe29MedHM76WRC0Y47OFuVHQfgPuiRl8ItpmuOkkvuN5UvOrcp09E
6xm8RGuG8UzfwxkppVxltjcSSue6jLFcCDMRmMtj4958YQa+fWWMHPEI5ow4lz5F
WZEWobWe7M2Ar1qXTRZIoCQmd6L7B7tAOggnWIUlLQKBgQDyy/czT+RzAqO7dQhK
Cxjr83uw/liYDpTV7P8z1gYwnsMPvaRQtqDVuXJ+yww4nE0KwRdXFimGeVjSI55B
llbYBjQ1GYEDICWUfMFl8V0+jGRdg5S9ph6xFtFSBCtlDEcExKdz6Nk8FE47EaHq
zTgd3G9cXHE9yVzuLA3NX5iTxQKBgQDW84nBI2qcG5ygSrxkDzF5AsshoFb/t8YT
Ebq3NGkLPZ7aNn8Yk17nmBIDVXLCxrgSuJqPKzlPKWP8jyIV91vbOqMSqdZ5GRcF
iNQchqHT8ZZ8BOsgyoOfhGVaef+xOk6tjUouOXos0RprFxDZScVaI3ydtl3VyyOl
LyY1q6FkRQKBgH7hJ+WgsnmHv5iOqC5JblSfgNwVjqanuA+zMgocpk9yJ+1p5Rxo
09PcfYDVCyXqSDh+f3v7EOg9MbVe96y+q9NoKpA1K74+ZmUabNahM2EkbK6RvID+
9rsEeY6qryK3L8XGHtvrqtpCoj8sD7lsVQ8FywwxItxvBilQzEWu10UhAoGBAIm+
ZN9Un8PL2fHKErGYHt7qEFvLERUrog2kRd+TAWGHql0xoP6RqbaFd72VK0Zv65Nr
ovft/fqhjoZQ/snOyplRGSEjnuHZVyxfw3VIPTnBTerJiBdqTzCQuhZhqZ3bvIFw
0kGO6aEAmopXrJ9hq8sYhInYTIdtdrkq3rRz+Kd1AoGAWYvxWQwFNoEjiL9LbMuS
PmV8OpeHDzsyUuOvrwtAP2OPJNWCoHEYP1pUx0QIrJ3tFYMjY1sFPszwiPpRWoVf
HjWmrn5yIWqDPDXNy8gnGe1eOPX1lUJZHgHPcuSuRZFocd6cK/OUVKyWAv4yFjJd
xvcNsYaYqk6sRk/INvcaN2E=
-----END PRIVATE KEY-----";

    struct StaticCertManager {
        cert_path: PathBuf,
        key_path: PathBuf,
    }

    impl CertManager for StaticCertManager {
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
        ) -> Result<Vec<review_web::graphql::ParsedCertificate>, anyhow::Error> {
            Ok(Vec::new())
        }
    }

    struct StubAgentManager;

    #[async_trait]
    impl AgentManager for StubAgentManager {
        async fn send_agent_specific_internal_networks(
            &self,
            _networks: &[review_web::graphql::customer::NetworksTargetAgentKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(Vec::new())
        }

        async fn send_agent_specific_allow_networks(
            &self,
            _networks: &[review_web::graphql::customer::NetworksTargetAgentKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(Vec::new())
        }

        async fn send_agent_specific_block_networks(
            &self,
            _networks: &[review_web::graphql::customer::NetworksTargetAgentKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(Vec::new())
        }

        async fn online_apps_by_host_id(
            &self,
        ) -> Result<std::collections::HashMap<String, Vec<(String, String)>>, anyhow::Error>
        {
            Ok(std::collections::HashMap::new())
        }

        async fn broadcast_crusher_sampling_policy(
            &self,
            _sampling_policies: &[review_web::graphql::SamplingPolicy],
        ) -> Result<(), anyhow::Error> {
            Ok(())
        }

        async fn get_process_list(
            &self,
            _hostname: &str,
        ) -> Result<Vec<review_web::backend::Process>, anyhow::Error> {
            Ok(Vec::new())
        }

        async fn get_resource_usage(
            &self,
            _hostname: &str,
        ) -> Result<review_web::backend::ResourceUsage, anyhow::Error> {
            Err(anyhow::anyhow!("Not supported in mTLS integration test"))
        }

        async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            Ok(())
        }

        async fn ping(&self, _hostname: &str) -> Result<Duration, anyhow::Error> {
            Ok(Duration::from_secs(0))
        }

        async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            Ok(())
        }

        async fn update_config(&self, _agent_key: &str) -> Result<(), anyhow::Error> {
            Ok(())
        }
    }

    struct StubAuthenticator;

    impl MtlsAuthenticator for StubAuthenticator {
        fn authenticate(
            &self,
            cert: &rustls::pki_types::CertificateDer<'static>,
        ) -> Result<MtlsIdentity, MtlsAuthError> {
            use x509_parser::extensions::GeneralName;
            use x509_parser::prelude::parse_x509_certificate;

            let (_, x509) = parse_x509_certificate(cert.as_ref())
                .map_err(|e| MtlsAuthError::InvalidToken(format!("Invalid certificate: {e:?}")))?;
            let san = x509
                .subject_alternative_name()
                .map_err(|e| MtlsAuthError::InvalidToken(format!("Invalid SAN: {e:?}")))?
                .ok_or_else(|| MtlsAuthError::InvalidToken(ERR_MISSING_SAN.to_string()))?;
            let dns_name = san
                .value
                .general_names
                .iter()
                .find_map(|name| {
                    if let GeneralName::DNSName(dns) = name {
                        Some(*dns)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| MtlsAuthError::InvalidToken(ERR_NO_DNS_SAN.to_string()))?;
            let mut parts = dns_name.splitn(4, '.');
            let instance = parts
                .next()
                .ok_or_else(|| MtlsAuthError::InvalidToken(ERR_MISSING_INSTANCE.to_string()))?;
            let service = parts
                .next()
                .ok_or_else(|| MtlsAuthError::InvalidToken(ERR_MISSING_SERVICE.to_string()))?;
            let host = parts
                .next()
                .ok_or_else(|| MtlsAuthError::InvalidToken(ERR_MISSING_HOST.to_string()))?;
            let domain = parts
                .next()
                .ok_or_else(|| MtlsAuthError::InvalidToken(ERR_MISSING_DOMAIN.to_string()))?;
            if service != EXPECTED_SERVICE {
                return Err(MtlsAuthError::InvalidToken(
                    ERR_SAN_SERVICE_MISMATCH.to_string(),
                ));
            }
            Ok(MtlsIdentity {
                instance: instance.to_string(),
                service: service.to_string(),
                host: host.to_string(),
                domain: domain.to_string(),
            })
        }
    }

    #[derive(Serialize)]
    struct ContextClaims<'a> {
        role: &'a str,
        customer_ids: Option<Vec<u32>>,
        exp: i64,
    }

    fn build_ca() -> anyhow::Result<(Certificate, Issuer<'static, KeyPair>)> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "review-web-test-ca");
        let key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate CA key pair")?;
        let cert = params
            .self_signed(&key_pair)
            .context("create CA certificate")?;
        let issuer = Issuer::new(params, key_pair);
        Ok((cert, issuer))
    }

    fn build_server_cert(
        issuer: &Issuer<'_, KeyPair>,
        ip: IpAddr,
    ) -> anyhow::Result<(Certificate, KeyPair)> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .context("create server certificate params")?;
        params
            .subject_alt_names
            .push(SanType::DnsName("localhost".try_into()?));
        params.subject_alt_names.push(SanType::IpAddress(ip));
        params
            .distinguished_name
            .push(DnType::CommonName, "review-web-test-server");
        let key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate server key pair")?;
        let cert = params
            .signed_by(&key_pair, issuer)
            .context("sign server certificate")?;
        Ok((cert, key_pair))
    }

    fn build_client_cert(
        issuer: &Issuer<'_, KeyPair>,
        dns_san: &str,
    ) -> anyhow::Result<(Certificate, KeyPair)> {
        let mut params = CertificateParams::new(vec![dns_san.to_string()])
            .context("create client certificate params")?;
        params
            .distinguished_name
            .push(DnType::CommonName, "review-web-test-client");
        let key_pair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate client key pair")?;
        let cert = params
            .signed_by(&key_pair, issuer)
            .context("sign client certificate")?;
        Ok((cert, key_pair))
    }

    fn sign_context_jwt_with_key(
        key: &EncodingKey,
        alg: Algorithm,
        customer_ids: Option<Vec<u32>>,
        role: &str,
    ) -> anyhow::Result<String> {
        let exp = (Utc::now() + ChronoDuration::minutes(5)).timestamp();
        let claims = ContextClaims {
            role,
            customer_ids,
            exp,
        };
        let header = Header::new(alg);
        Ok(encode(&header, &claims, key)?)
    }

    fn sign_context_jwt(key_der: &[u8]) -> anyhow::Result<String> {
        sign_context_jwt_with_key(
            &EncodingKey::from_ec_der(key_der),
            Algorithm::ES256,
            Some(vec![CUSTOMER_ID]),
            ROLE,
        )
    }

    struct TestServer {
        url: String,
        shutdown: Arc<tokio::sync::Notify>,
        ca_cert: Certificate,
        issuer: Issuer<'static, KeyPair>,
        _temp_root: tempfile::TempDir,
        _cert_dir: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
        _backup_dir: tempfile::TempDir,
    }

    fn start_test_server() -> anyhow::Result<TestServer> {
        // SAFETY: test-only environment override for auth bypass is scoped to this process.
        unsafe {
            std::env::set_var("REVIEW_WEB_DISABLE_LOCAL_AUTH_BYPASS", "1");
        }
        let addr_ip = LOCALHOST_IP;
        let port = {
            let listener =
                std::net::TcpListener::bind(SocketAddr::new(addr_ip, 0)).context("bind port")?;
            let port = listener.local_addr().context("read port")?.port();
            drop(listener);
            port
        };

        let temp_root = tempfile::tempdir().context("create temp dir")?;
        let cert_dir = tempfile::tempdir().context("create cert temp dir")?;

        let (ca_cert, issuer) = build_ca()?;
        let (server_cert, server_key) = build_server_cert(&issuer, addr_ip)?;

        let ca_path = cert_dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).context("write CA cert")?;

        let server_cert_path = cert_dir.path().join("server.pem");
        let server_key_path = cert_dir.path().join("server.key");
        std::fs::write(&server_cert_path, server_cert.pem()).context("write server cert")?;
        std::fs::write(&server_key_path, server_key.serialize_pem()).context("write server key")?;

        let store_dir = tempfile::tempdir().context("create store dir")?;
        let backup_dir = tempfile::tempdir().context("create backup dir")?;
        let store = Store::new(store_dir.path(), backup_dir.path()).context("create store")?;
        let store = Arc::new(RwLock::new(store));

        let config = ServerConfig {
            addr: SocketAddr::new(addr_ip, port),
            document_root: temp_root.path().to_path_buf(),
            cert_manager: Arc::new(StaticCertManager {
                cert_path: server_cert_path,
                key_path: server_key_path,
            }),
            tls_reload_handle: Arc::new(tokio::sync::Notify::new()),
            ca_certs: vec![ca_path],
            client_cert_path: None,
            client_key_path: None,
            authenticator: Arc::new(StubAuthenticator),
        };

        let shutdown = review_web::serve(config, store, None, StubAgentManager);

        Ok(TestServer {
            url: format!("https://{addr_ip}:{port}/graphql"),
            shutdown,
            ca_cert,
            issuer,
            _temp_root: temp_root,
            _cert_dir: cert_dir,
            _store_dir: store_dir,
            _backup_dir: backup_dir,
        })
    }

    fn build_client_with_identity(
        issuer: &Issuer<'_, KeyPair>,
        ca_cert: &Certificate,
        dns_san: &str,
    ) -> anyhow::Result<(reqwest::Client, KeyPair)> {
        let (client_cert, client_key) = build_client_cert(issuer, dns_san)?;
        let client_identity_pem = format!("{}\n{}", client_cert.pem(), client_key.serialize_pem());
        let identity = reqwest::Identity::from_pem(client_identity_pem.as_bytes())
            .context("build client identity")?;
        let ca_cert_reqwest = ReqwestCertificate::from_pem(ca_cert.pem().as_bytes())
            .context("build CA certificate")?;
        let client = reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(ca_cert_reqwest)
            .use_rustls_tls()
            .build()
            .context("build HTTP client")?;
        Ok((client, client_key))
    }

    fn build_client_without_identity(ca_cert: &Certificate) -> anyhow::Result<reqwest::Client> {
        let ca_cert_reqwest = ReqwestCertificate::from_pem(ca_cert.pem().as_bytes())
            .context("build CA certificate")?;
        let client = reqwest::Client::builder()
            .add_root_certificate(ca_cert_reqwest)
            .use_rustls_tls()
            .build()
            .context("build HTTP client")?;
        Ok(client)
    }

    async fn send_graphql_request(
        client: &reqwest::Client,
        url: &str,
        token: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        let request_body = serde_json::to_vec(&json!({ "query": GRAPHQL_QUERY }))
            .context("serialize GraphQL request")?;
        let mut last_err = None;
        for _ in 0..20 {
            let mut request = client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(request_body.clone());
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            let response = request.send().await;
            match response {
                Ok(res) => return Ok(res),
                Err(err) => {
                    last_err = Some(err);
                    sleep(Duration::from_millis(150)).await;
                }
            }
        }
        Err(anyhow::anyhow!("failed to reach mTLS server: {last_err:?}"))
    }

    #[tokio::test]
    async fn mtls_graphql_request_succeeds() -> anyhow::Result<()> {
        let server = start_test_server()?;
        let (client, client_key) =
            build_client_with_identity(&server.issuer, &server.ca_cert, SERVICE_DNS)?;
        let token = sign_context_jwt(client_key.serialize_der().as_slice())?;

        let response = send_graphql_request(&client, &server.url, Some(&token)).await?;
        let text = response.text().await.context("read response body")?;
        let body: serde_json::Value = serde_json::from_str(&text).context("parse response JSON")?;
        let typename = body
            .get("data")
            .and_then(|data| data.get("__typename"))
            .and_then(|value| value.as_str())
            .context("read __typename")?;
        assert_eq!(typename, "Query");
        server.shutdown.notify_one();
        server.shutdown.notified().await;
        Ok(())
    }

    #[tokio::test]
    async fn mtls_rejects_invalid_san() -> anyhow::Result<()> {
        let server = start_test_server()?;
        let (client, client_key) = build_client_with_identity(
            &server.issuer,
            &server.ca_cert,
            "edge.other-service.example.com",
        )?;
        let token = sign_context_jwt(client_key.serialize_der().as_slice())?;

        let response = send_graphql_request(&client, &server.url, Some(&token)).await?;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        let body: serde_json::Value =
            serde_json::from_str(&response.text().await.context("read response body")?)
                .context("parse response JSON")?;
        let error = body
            .get("error")
            .and_then(|value| value.as_str())
            .context("read error")?;
        assert!(error.contains(ERR_SAN_SERVICE_MISMATCH));
        server.shutdown.notify_one();
        server.shutdown.notified().await;
        Ok(())
    }

    #[tokio::test]
    async fn mtls_rejects_jwt_alg_mismatch() -> anyhow::Result<()> {
        let server = start_test_server()?;
        let (client, _client_key) =
            build_client_with_identity(&server.issuer, &server.ca_cert, SERVICE_DNS)?;
        let token = sign_context_jwt_with_key(
            &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_PEM.as_bytes())
                .context("parse RSA private key")?,
            Algorithm::RS256,
            Some(vec![CUSTOMER_ID]),
            ROLE,
        )?;

        let response = send_graphql_request(&client, &server.url, Some(&token)).await?;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        let body: serde_json::Value =
            serde_json::from_str(&response.text().await.context("read response body")?)
                .context("parse response JSON")?;
        let error = body
            .get("error")
            .and_then(|value| value.as_str())
            .context("read error")?;
        assert!(error.contains(ERR_JWT_ALG_EC_MISMATCH));
        server.shutdown.notify_one();
        server.shutdown.notified().await;
        Ok(())
    }

    #[tokio::test]
    async fn mtls_rejects_missing_customer_ids_for_non_admin() -> anyhow::Result<()> {
        let server = start_test_server()?;
        let (client, client_key) =
            build_client_with_identity(&server.issuer, &server.ca_cert, SERVICE_DNS)?;
        let token = sign_context_jwt_with_key(
            &EncodingKey::from_ec_der(client_key.serialize_der().as_slice()),
            Algorithm::ES256,
            None,
            NON_ADMIN_ROLE,
        )?;

        let response = send_graphql_request(&client, &server.url, Some(&token)).await?;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        let body: serde_json::Value =
            serde_json::from_str(&response.text().await.context("read response body")?)
                .context("parse response JSON")?;
        let error = body
            .get("error")
            .and_then(|value| value.as_str())
            .context("read error")?;
        assert!(error.contains(ERR_MISSING_CUSTOMER_IDS));
        server.shutdown.notify_one();
        server.shutdown.notified().await;
        Ok(())
    }

    #[tokio::test]
    async fn mtls_rejects_missing_client_cert() -> anyhow::Result<()> {
        let server = start_test_server()?;
        let client = build_client_without_identity(&server.ca_cert)?;
        let response = send_graphql_request(&client, &server.url, None).await?;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        server.shutdown.notify_one();
        server.shutdown.notified().await;
        Ok(())
    }

    #[tokio::test]
    async fn mtls_rejects_missing_authorization() -> anyhow::Result<()> {
        let server = start_test_server()?;
        let (client, _client_key) =
            build_client_with_identity(&server.issuer, &server.ca_cert, SERVICE_DNS)?;

        let response = send_graphql_request(&client, &server.url, None).await?;
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        server.shutdown.notify_one();
        server.shutdown.notified().await;
        Ok(())
    }

    #[tokio::test]
    async fn mtls_non_admin_with_customer_ids_succeeds() -> anyhow::Result<()> {
        let server = start_test_server()?;
        let (client, client_key) =
            build_client_with_identity(&server.issuer, &server.ca_cert, SERVICE_DNS)?;
        let token = sign_context_jwt_with_key(
            &EncodingKey::from_ec_der(client_key.serialize_der().as_slice()),
            Algorithm::ES256,
            Some(vec![CUSTOMER_ID]),
            NON_ADMIN_ROLE,
        )?;

        let response = send_graphql_request(&client, &server.url, Some(&token)).await?;
        let body: serde_json::Value =
            serde_json::from_str(&response.text().await.context("read response body")?)
                .context("parse response JSON")?;
        let typename = body
            .get("data")
            .and_then(|data| data.get("__typename"))
            .and_then(|value| value.as_str())
            .context("read __typename")?;
        assert_eq!(typename, "Query");
        server.shutdown.notify_one();
        server.shutdown.notified().await;
        Ok(())
    }

    #[test]
    fn stub_authenticator_parses_identity_fields() {
        let (cert, _key) = build_client_cert_self_signed(SERVICE_DNS);
        let identity = StubAuthenticator
            .authenticate(&cert)
            .expect("valid SAN should authenticate");
        assert_eq!(identity.instance, "edge");
        assert_eq!(identity.service, EXPECTED_SERVICE);
        assert_eq!(identity.host, "example");
        assert_eq!(identity.domain, "com");
    }

    #[test]
    fn stub_authenticator_rejects_wrong_service() {
        let (cert, _key) = build_client_cert_self_signed("edge.other-service.example.com");
        let err = StubAuthenticator
            .authenticate(&cert)
            .expect_err("wrong service should be rejected");
        match err {
            MtlsAuthError::InvalidToken(msg) => assert_eq!(msg, ERR_SAN_SERVICE_MISMATCH),
            MtlsAuthError::JsonWebToken(_) => {
                panic!("service mismatch should be InvalidToken, not JsonWebToken")
            }
        }
    }

    fn build_client_cert_self_signed(
        dns_san: &str,
    ) -> (rustls::pki_types::CertificateDer<'static>, KeyPair) {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .expect("PKCS_ECDSA_P256_SHA256 is supported");
        let params = CertificateParams::new(vec![dns_san.to_string()])
            .expect("test DNS SAN is a valid name");
        let cert = params
            .self_signed(&key_pair)
            .expect("key pair and params are valid for rcgen");
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        (cert_der, key_pair)
    }

    async fn connect_ws(
        server: &TestServer,
        client_dns: &str,
    ) -> anyhow::Result<(
        tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
        KeyPair,
    )> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
        use tokio_rustls::TlsConnector;

        let (client_cert, client_key) = build_client_cert(&server.issuer, client_dns)?;
        let client_cert_der = CertificateDer::from(client_cert.der().to_vec());
        let client_key_der =
            PrivateKeyDer::try_from(client_key.serialize_der()).map_err(|e| anyhow::anyhow!(e))?;

        let mut root_store = rustls::RootCertStore::empty();
        let ca_der = CertificateDer::from(server.ca_cert.der().to_vec());
        root_store.add(ca_der).context("add CA to root store")?;

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(vec![client_cert_der], client_key_der)
            .context("build client TLS config")?;
        let connector = TlsConnector::from(Arc::new(tls_config));

        let host_port = server
            .url
            .strip_prefix("https://")
            .and_then(|s| s.split('/').next())
            .context("extract host:port from URL")?;
        let addr: SocketAddr = host_port.parse().context("parse server addr")?;
        let mut tcp = None;
        for _ in 0..20 {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(_) => sleep(Duration::from_millis(150)).await,
            }
        }
        let tcp = tcp.context("TCP connect after retries")?;
        let domain = ServerName::IpAddress(LOCALHOST_IP.into());
        let tls_stream = connector
            .connect(domain, tcp)
            .await
            .context("TLS handshake")?;

        let ws_url = server.url.replace("https://", "wss://");
        let request = http::Request::builder()
            .uri(&ws_url)
            .header("Host", addr.to_string())
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Protocol", "graphql-ws")
            .body(())
            .context("build WS request")?;

        let (ws_stream, _response) = tokio_tungstenite::client_async(request, tls_stream)
            .await
            .context("WebSocket handshake")?;

        Ok((ws_stream, client_key))
    }

    async fn recv_ws_message(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        >,
    ) -> anyhow::Result<tokio_tungstenite::tungstenite::Message> {
        use futures::StreamExt;

        tokio::time::timeout(WS_RECV_TIMEOUT, ws.next())
            .await
            .context("WebSocket recv timed out")?
            .context("WebSocket stream ended")?
            .context("WebSocket recv error")
    }

    #[tokio::test]
    async fn mtls_ws_graphql_request_succeeds() -> anyhow::Result<()> {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let server = start_test_server()?;
        let (mut ws, client_key) = connect_ws(&server, SERVICE_DNS).await?;

        let token = sign_context_jwt(client_key.serialize_der().as_slice())?;
        let init = json!({
            "type": "connection_init",
            "payload": { "Authorization": format!("Bearer {token}") }
        });
        ws.send(Message::Text(init.to_string().into())).await?;

        let ack = recv_ws_message(&mut ws).await?;
        let ack: serde_json::Value = serde_json::from_str(ack.to_text()?)?;
        assert_eq!(ack["type"], "connection_ack");

        let start = json!({
            "type": "start",
            "id": "1",
            "payload": { "query": GRAPHQL_QUERY }
        });
        ws.send(Message::Text(start.to_string().into())).await?;

        let data_msg = recv_ws_message(&mut ws).await?;
        let data_msg: serde_json::Value = serde_json::from_str(data_msg.to_text()?)?;
        assert_eq!(data_msg["type"], "data");
        assert_eq!(data_msg["payload"]["data"]["__typename"], "Query");

        ws.close(None).await?;
        server.shutdown.notify_one();
        server.shutdown.notified().await;
        Ok(())
    }

    #[tokio::test]
    async fn mtls_ws_rejects_missing_authorization() -> anyhow::Result<()> {
        use futures::SinkExt;
        use tokio_tungstenite::tungstenite::Message;

        let server = start_test_server()?;
        let (mut ws, _client_key) = connect_ws(&server, SERVICE_DNS).await?;

        let init = json!({ "type": "connection_init", "payload": {} });
        ws.send(Message::Text(init.to_string().into())).await?;

        let msg = recv_ws_message(&mut ws).await?;
        let parsed: serde_json::Value = serde_json::from_str(msg.to_text()?)?;
        assert_eq!(parsed["type"], "connection_error");

        server.shutdown.notify_one();
        server.shutdown.notified().await;
        Ok(())
    }
}
