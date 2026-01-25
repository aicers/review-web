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
    use review_database::{HostNetworkGroup, Store};
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

        async fn broadcast_allow_networks(
            &self,
            _networks: &HostNetworkGroup,
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(Vec::new())
        }

        async fn broadcast_block_networks(
            &self,
            _networks: &HostNetworkGroup,
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

    fn build_client_cert(issuer: &Issuer<'_, KeyPair>) -> anyhow::Result<(Certificate, KeyPair)> {
        let mut params = CertificateParams::new(vec![SERVICE_DNS.to_string()])
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

    fn sign_context_jwt(key_der: &[u8]) -> anyhow::Result<String> {
        let exp = (Utc::now() + ChronoDuration::minutes(5)).timestamp();
        let claims = ContextClaims {
            role: ROLE,
            customer_ids: Some(vec![CUSTOMER_ID]),
            exp,
        };
        let header = Header::new(Algorithm::ES256);
        Ok(encode(
            &header,
            &claims,
            &EncodingKey::from_ec_der(key_der),
        )?)
    }

    #[tokio::test]
    async fn mtls_graphql_request_succeeds() -> anyhow::Result<()> {
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
        let (client_cert, client_key) = build_client_cert(&issuer)?;

        let ca_path = cert_dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).context("write CA cert")?;

        let server_cert_path = cert_dir.path().join("server.pem");
        let server_key_path = cert_dir.path().join("server.key");
        std::fs::write(&server_cert_path, server_cert.pem()).context("write server cert")?;
        std::fs::write(&server_key_path, server_key.serialize_pem()).context("write server key")?;

        let client_identity_pem = format!("{}\n{}", client_cert.pem(), client_key.serialize_pem());
        let identity = reqwest::Identity::from_pem(client_identity_pem.as_bytes())
            .context("build client identity")?;
        let ca_cert_reqwest = ReqwestCertificate::from_pem(ca_cert.pem().as_bytes())
            .context("build CA certificate")?;

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

        let client = reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(ca_cert_reqwest)
            .use_rustls_tls()
            .build()
            .context("build HTTP client")?;

        let token = sign_context_jwt(client_key.serialize_der().as_slice())?;
        let url = format!("https://{addr_ip}:{port}/graphql");

        let request_body = serde_json::to_vec(&json!({ "query": GRAPHQL_QUERY }))
            .context("serialize GraphQL request")?;
        let mut last_err = None;
        for _ in 0..20 {
            let response = client
                .post(&url)
                .bearer_auth(&token)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(request_body.clone())
                .send()
                .await;
            match response {
                Ok(res) => {
                    let text = res.text().await.context("read response body")?;
                    let body: serde_json::Value =
                        serde_json::from_str(&text).context("parse response JSON")?;
                    let typename = body
                        .get("data")
                        .and_then(|data| data.get("__typename"))
                        .and_then(|value| value.as_str())
                        .context("read __typename")?;
                    assert_eq!(typename, "Query");
                    shutdown.notify_one();
                    shutdown.notified().await;
                    return Ok(());
                }
                Err(err) => {
                    last_err = Some(err);
                    sleep(Duration::from_millis(150)).await;
                }
            }
        }

        shutdown.notify_one();
        shutdown.notified().await;
        Err(anyhow::anyhow!("failed to reach mTLS server: {last_err:?}"))
    }
}
