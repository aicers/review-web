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
        backend::{AgentManager, CertManager},
    };
    use serde::Serialize;
    use serde_json::json;
    use tokio::time::sleep;

    const SERVICE_DNS: &str = "edge.aice-web-next.example.com";
    const ROLE: &str = "System Administrator";
    const CUSTOMER_ID: u32 = 1;
    const GRAPHQL_QUERY: &str = "{__typename}";
    const LOCALHOST_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const NON_ADMIN_ROLE: &str = "Security Administrator";
    const ERR_SAN_SERVICE_MISMATCH: &str = "Client certificate SAN does not match service name";
    const ERR_JWT_ALG_EC_MISMATCH: &str = "JWT algorithm does not match EC key";
    const ERR_MISSING_CUSTOMER_IDS: &str = "Missing customer_ids claim for non-admin role";
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
}
