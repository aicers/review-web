use super::*;
use crate::backend::{SharedAgentManager, SignatureIngestError, SignatureSourceUpload};
use crate::ingress::{SIGNATURE_SOURCE_UPLOAD_PATH, SignatureRefusalCode, SignatureSourceLimit};
use crate::tests::signature_test_support::impl_signature_test_manager;

const VALID: &str = "source=et_open&origin=upload";
const VERSION_ID: u64 = (1 << 53) + 1;

#[derive(Default)]
struct SignatureObserved {
    uploads: Vec<SignatureSourceUpload>,
    bytes: Vec<u8>,
    chunks: usize,
    total: usize,
    first_produced: usize,
}

#[derive(Default)]
struct Manager {
    observed: Mutex<SignatureObserved>,
    error: Mutex<Option<SignatureIngestError>>,
    produced: Arc<AtomicUsize>,
    record_bytes: bool,
}

impl_signature_test_manager! { Manager {
    async fn ingest_signature_source(&self, upload: SignatureSourceUpload, mut body: IngressStream) -> Result<u64, SignatureIngestError> {
        self.observed.lock().unwrap().uploads.push(upload);
        while let Some(item) = body.next().await {
            let chunk = item.map_err(|error| match error {
                IngressStreamError::TooLarge { .. } => SignatureIngestError::TooLarge,
                IngressStreamError::Transport(_) => SignatureIngestError::Transport,
            })?;
            let mut seen = self.observed.lock().unwrap();
            if seen.chunks == 0 { seen.first_produced = self.produced.load(Ordering::SeqCst); }
            seen.chunks += 1;
            seen.total += chunk.len();
            if self.record_bytes { seen.bytes.extend_from_slice(&chunk); }
        }
        match self.error.lock().unwrap().take() {
            Some(error) => Err(error),
            None => Ok(VERSION_ID),
        }
    }
} }

struct DefaultManager;
impl_signature_test_manager! { DefaultManager {} }

async fn send_signature(
    caller: &Caller,
    query: &str,
    body: Body,
    manager: SharedAgentManager,
    cap: u64,
) -> Sent {
    send_authenticated(
        caller,
        &format!("{SIGNATURE_SOURCE_UPLOAD_PATH}?{query}"),
        body,
        |router| {
            router
                .layer(Extension(manager))
                .layer(Extension(SignatureSourceLimit(cap)))
        },
    )
    .await
}

#[tokio::test]
async fn published_path_success_and_decoded_provenance() {
    assert_eq!(SIGNATURE_SOURCE_UPLOAD_PATH, "/api/signature-source/upload");
    assert_eq!(crate::DEFAULT_SIGNATURE_SOURCE_MAX_BYTES, 64 * 1024 * 1024);
    let manager = Arc::new(Manager {
        record_bytes: true,
        ..Manager::default()
    });
    let sent = send_signature(&Caller::Role(Role::SystemAdministrator), "source=sigma_hq_emerging&origin=fetch&source_version=release%20one&fetched_url=https%3A%2F%2Fexample.com%2Farchive", body_of(vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")]), manager.clone(), CAP).await;
    assert_eq!(sent.status, StatusCode::ACCEPTED);
    assert_eq!(
        serde_json::from_str::<Value>(&sent.raw).unwrap(),
        serde_json::json!({"versionId": VERSION_ID.to_string()})
    );
    assert!(sent.logs.contains("accepted"));
    let seen = manager.observed.lock().unwrap();
    assert_eq!(seen.bytes, b"firstsecond");
    assert_eq!(
        seen.uploads,
        vec![SignatureSourceUpload {
            source: review_protocol::types::SignatureSource::SigmaHqEmerging,
            origin: review_database::SignatureOrigin::Fetch,
            fetch_label: Some("release one".into()),
            fetched_url: Some("https://example.com/archive".into())
        }]
    );
}

#[tokio::test]
async fn logging_filters_do_not_change_upload_responses() {
    use axum::middleware::{Next, from_fn};
    use tracing::instrument::WithSubscriber;

    for (error, status, expected) in [
        (
            None,
            StatusCode::ACCEPTED,
            serde_json::json!({"versionId": VERSION_ID.to_string()}),
        ),
        (
            Some(SignatureIngestError::Unreadable {
                reason: MARKER.to_owned(),
            }),
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "error": crate::ingress::ERR_SIGNATURE_UNREADABLE,
                "code": "UNREADABLE",
                "reason": MARKER,
            }),
        ),
    ] {
        let manager = Arc::new(Manager {
            error: Mutex::new(error),
            record_bytes: true,
            ..Manager::default()
        });
        let sent = send_authenticated(
            &Caller::Role(Role::SystemAdministrator),
            &format!("{SIGNATURE_SOURCE_UPLOAD_PATH}?{VALID}"),
            Body::from("archive"),
            |router| {
                let shared: SharedAgentManager = manager.clone();
                router
                    .layer(Extension(shared))
                    .layer(Extension(SignatureSourceLimit(CAP)))
                    .layer(from_fn(|request: Request<Body>, next: Next| async move {
                        next.run(request)
                            .with_subscriber(tracing::subscriber::NoSubscriber::default())
                            .await
                    }))
            },
        )
        .await;
        assert_eq!(sent.status, status);
        assert_eq!(serde_json::from_str::<Value>(&sent.raw).unwrap(), expected);
        assert!(sent.logs.is_empty(), "{}", sent.logs);
        let seen = manager.observed.lock().unwrap();
        assert_eq!(seen.uploads.len(), 1);
        assert_eq!(seen.bytes, b"archive");
    }
}

#[tokio::test]
async fn role_and_authentication_refusals_never_read_or_call() {
    for (caller, status, code) in [
        (Caller::Anonymous, StatusCode::UNAUTHORIZED, ""),
        (Caller::Invalid, StatusCode::UNAUTHORIZED, ""),
        (
            Caller::Role(Role::SecurityAdministrator),
            StatusCode::FORBIDDEN,
            "ROLE_NOT_PERMITTED",
        ),
        (
            Caller::Role(Role::SecurityManager),
            StatusCode::FORBIDDEN,
            "ROLE_NOT_PERMITTED",
        ),
        (
            Caller::Role(Role::SecurityMonitor),
            StatusCode::FORBIDDEN,
            "ROLE_NOT_PERMITTED",
        ),
    ] {
        for query in [
            VALID,
            "source=unknown&origin=unknown",
            "source=%FF&source=x",
        ] {
            let manager = Arc::new(Manager::default());
            let body = counted_body(3, CHUNK_LEN, manager.produced.clone());
            let sent = send_signature(&caller, query, body, manager.clone(), CAP).await;
            assert_eq!(sent.status, status, "{}", sent.raw);
            assert_eq!(sent.field("code"), code);
            assert_eq!(manager.produced.load(Ordering::SeqCst), 0);
            assert_eq!(manager.observed.lock().unwrap().uploads.len(), 0);
        }
    }
}

#[tokio::test]
async fn invalid_parameters_never_read_or_call() {
    let mut invalid: Vec<String> = [
        "",
        "source=et_open",
        "origin=upload",
        "source=unknown&origin=upload",
        "source=et_open&origin=unknown",
        "source=et_open&origin=fetch",
        "source=et_open&origin=upload&source_version=v",
        "source=et_open&origin=upload&fetched_url=url",
        "source=&origin=upload",
        "source=et_open&origin=",
        "source=et_open&origin=fetch&fetched_url=",
        "source=et_open&origin=fetch&fetched_url=url&source_version=",
        "source=et_open&origin=upload&extra=value",
        "source=et_open&source=et_open&origin=upload",
        "source=et_open&origin=upload&origin=upload",
        "source=et_open&origin=fetch&fetched_url=url&fetched_url=url",
        "source=et_open&origin=fetch&fetched_url=url&source_version=v&source_version=v",
        "source=et_open&origin=upload&%73ource=et_open",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    invalid.push(format!(
        "source=et_open&origin=fetch&fetched_url={}",
        "u".repeat(2049)
    ));
    invalid.push(format!(
        "source=et_open&origin=fetch&fetched_url=url&source_version={}",
        "v".repeat(257)
    ));
    // Limits are decoded UTF-8 byte lengths, not encoded lengths or characters.
    invalid.push(format!(
        "source=et_open&origin=fetch&fetched_url=url&source_version={}",
        "%C3%A9".repeat(129)
    ));
    for query in invalid {
        let manager = Arc::new(Manager::default());
        let sent = send_signature(
            &Caller::Role(Role::SystemAdministrator),
            &query,
            counted_body(3, CHUNK_LEN, manager.produced.clone()),
            manager.clone(),
            CAP,
        )
        .await;
        assert_eq!(
            sent.status,
            StatusCode::BAD_REQUEST,
            "{query}: {}",
            sent.raw
        );
        assert_eq!(sent.field("code"), "INVALID_PARAMETER");
        assert_ne!(sent.error(), "");
        assert_eq!(manager.produced.load(Ordering::SeqCst), 0);
        assert_eq!(manager.observed.lock().unwrap().uploads.len(), 0);
    }
}

#[tokio::test]
async fn parameter_bounds_and_all_sources_are_accepted() {
    for source in ["et_open", "sigma_hq", "sigma_hq_emerging"] {
        for (label, url) in [
            ("v".to_owned(), "u".to_owned()),
            ("%C3%A9".repeat(128), "u".repeat(2048)),
        ] {
            let sent = send_signature(
                &Caller::Role(Role::SystemAdministrator),
                &format!("source={source}&origin=fetch&source_version={label}&fetched_url={url}"),
                Body::empty(),
                Arc::new(Manager::default()),
                CAP,
            )
            .await;
            assert_eq!(sent.status, StatusCode::ACCEPTED, "{}", sent.raw);
        }
    }
    let sent = send_signature(
        &Caller::Role(Role::SystemAdministrator),
        "source=et_open&origin=fetch&fetched_url=u",
        Body::empty(),
        Arc::new(Manager::default()),
        CAP,
    )
    .await;
    assert_eq!(sent.status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn exact_cap_one_over_transport_and_large_stream() {
    for (bytes, expected, code) in [
        (8, StatusCode::ACCEPTED, ""),
        (9, StatusCode::PAYLOAD_TOO_LARGE, "TOO_LARGE"),
    ] {
        let manager = Arc::new(Manager {
            record_bytes: true,
            ..Manager::default()
        });
        let sent = send_signature(
            &Caller::Role(Role::SystemAdministrator),
            VALID,
            body_of(vec![Bytes::from(vec![7; bytes])]),
            manager.clone(),
            8,
        )
        .await;
        assert_eq!(sent.status, expected);
        assert_eq!(sent.field("code"), code);
        if bytes == 8 {
            assert_eq!(manager.observed.lock().unwrap().bytes, vec![7; 8]);
        }
    }
    let sent = send_signature(
        &Caller::Role(Role::SystemAdministrator),
        VALID,
        dropping_body(),
        Arc::new(Manager::default()),
        CAP,
    )
    .await;
    assert_eq!(sent.status, StatusCode::BAD_REQUEST);
    assert_eq!(sent.field("code"), "TRANSPORT");
    let manager = Arc::new(Manager::default());
    let sent = send_signature(
        &Caller::Role(Role::SystemAdministrator),
        VALID,
        counted_body(HUGE_CHUNKS, HUGE_CHUNK_LEN, manager.produced.clone()),
        manager.clone(),
        GENEROUS_CAP,
    )
    .await;
    assert_eq!(sent.status, StatusCode::ACCEPTED);
    let seen = manager.observed.lock().unwrap();
    assert_eq!(seen.first_produced, 1);
    assert_eq!(seen.chunks, HUGE_CHUNKS);
    assert_eq!(seen.total, HUGE_CHUNKS * HUGE_CHUNK_LEN);
}

#[tokio::test]
async fn receiver_errors_and_default_manager() {
    for (error, code, status, extra) in [
        (
            SignatureIngestError::Unreadable {
                reason: MARKER.to_owned(),
            },
            "UNREADABLE",
            StatusCode::BAD_REQUEST,
            Some(("reason", MARKER.to_owned())),
        ),
        (
            SignatureIngestError::AlreadyPresent {
                existing_version_id: VERSION_ID,
            },
            "ALREADY_PRESENT",
            StatusCode::CONFLICT,
            Some(("existingVersionId", VERSION_ID.to_string())),
        ),
        (
            SignatureIngestError::OlderThanApplied {
                applied_version_id: VERSION_ID,
            },
            "OLDER_THAN_APPLIED",
            StatusCode::CONFLICT,
            Some(("appliedVersionId", VERSION_ID.to_string())),
        ),
        (
            SignatureIngestError::TooLarge,
            "TOO_LARGE",
            StatusCode::PAYLOAD_TOO_LARGE,
            None,
        ),
        (
            SignatureIngestError::Transport,
            "TRANSPORT",
            StatusCode::BAD_REQUEST,
            None,
        ),
        (
            SignatureIngestError::Unavailable,
            "UNAVAILABLE",
            StatusCode::SERVICE_UNAVAILABLE,
            None,
        ),
    ] {
        let manager = Arc::new(Manager {
            error: Mutex::new(Some(error)),
            ..Manager::default()
        });
        let sent = send_signature(
            &Caller::Role(Role::SystemAdministrator),
            VALID,
            Body::empty(),
            manager,
            CAP,
        )
        .await;
        assert_eq!(sent.status, status);
        assert_eq!(sent.field("code"), code);
        assert!(!sent.logs.contains(MARKER));
        assert!(sent.logs.contains(code));
        assert!(sent.logs.contains(SIGNATURE_SOURCE_UPLOAD_PATH));
        assert!(sent.logs.contains(EXPECTED_TRUST_ACTOR));
        if let Some((field, value)) = extra {
            assert_eq!(sent.field(field), value);
        }
    }
    let sent = send_signature(
        &Caller::Role(Role::SystemAdministrator),
        VALID,
        Body::empty(),
        Arc::new(DefaultManager),
        CAP,
    )
    .await;
    assert_eq!(sent.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(sent.field("code"), "UNAVAILABLE");
}

#[test]
fn the_signature_route_answers_its_own_closed_code_set() {
    fn assert_code(code: &SignatureRefusalCode) {
        let expected = match code {
            SignatureRefusalCode::RoleNotPermitted => "ROLE_NOT_PERMITTED",
            SignatureRefusalCode::InvalidParameter => "INVALID_PARAMETER",
            SignatureRefusalCode::Unreadable { .. } => "UNREADABLE",
            SignatureRefusalCode::AlreadyPresent { .. } => "ALREADY_PRESENT",
            SignatureRefusalCode::OlderThanApplied { .. } => "OLDER_THAN_APPLIED",
            SignatureRefusalCode::TooLarge => "TOO_LARGE",
            SignatureRefusalCode::Transport => "TRANSPORT",
            SignatureRefusalCode::Unavailable => "UNAVAILABLE",
        };
        assert_eq!(serde_json::to_value(code).unwrap()["code"], expected);
    }
    for code in [
        SignatureRefusalCode::RoleNotPermitted,
        SignatureRefusalCode::InvalidParameter,
        SignatureRefusalCode::Unreadable {
            reason: "reason".into(),
        },
        SignatureRefusalCode::AlreadyPresent {
            existing_version_id: "1".into(),
        },
        SignatureRefusalCode::OlderThanApplied {
            applied_version_id: "1".into(),
        },
        SignatureRefusalCode::TooLarge,
        SignatureRefusalCode::Transport,
        SignatureRefusalCode::Unavailable,
    ] {
        assert_code(&code);
    }
}
