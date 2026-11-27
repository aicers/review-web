use std::sync::{Arc, Mutex};

use review_database::{
    NewSignatureVersion, SignatureOrderKey, SignatureOrigin, SignatureReconversionSuccess,
};
use review_protocol::types::{DetectionModel as Model, SignatureSource as Source};
use serde_json::{Value, json};

use super::*;
use crate::backend::{SignatureRule as BackendRule, SignatureRulePage};
use crate::graphql::TestSchema;
use crate::tests::signature_test_support::impl_signature_test_manager;

#[derive(Default)]
struct Manager {
    pushes: Mutex<Vec<Vec<String>>>,
    listings: Mutex<Vec<(SignatureRuleFilter, usize, usize)>>,
    fail: bool,
}

impl_signature_test_manager! { Manager {
    async fn send_signature_rules(&self, keys: &[String]) -> anyhow::Result<Vec<String>> {
        self.pushes.lock().unwrap().push(keys.to_vec());
        if self.fail {
            anyhow::bail!("push failed");
        }
        Ok(Vec::new())
    }
    async fn signature_rules(
        &self,
        filter: &SignatureRuleFilter,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<SignatureRulePage> {
        self.listings.lock().unwrap().push((filter.clone(), offset, limit));
        if self.fail {
            anyhow::bail!("listing failed");
        }
        Ok(SignatureRulePage {
            rules: vec![
                BackendRule {
                    source: Source::EtOpen,
                    detection_model: Model::EtSignature,
                    rule_id: "one".into(),
                    title: "Title".into(),
                    classification: Some("class".into()),
                    severity: "High".into(),
                },
                BackendRule {
                    source: Source::SigmaHq,
                    detection_model: Model::SigmaSignature,
                    rule_id: "one".into(),
                    title: "Other".into(),
                    classification: None,
                    severity: "medium".into(),
                },
            ],
            total_count: 1234,
        })
    }
} }

async fn fixture(fail: bool) -> (TestSchema, Arc<Manager>) {
    let manager = Arc::new(Manager {
        fail,
        ..Manager::default()
    });
    (
        TestSchema::new_with_params(manager.clone(), None).await,
        manager,
    )
}

async fn data(schema: &TestSchema, query: &str) -> Value {
    let response = schema.execute_as_system_admin(query).await;
    assert!(response.errors.is_empty(), "{query}: {:?}", response.errors);
    response.data.into_json().unwrap()
}

#[tokio::test]
async fn default_manager_refuses_listings_but_preserves_mutations() {
    let schema = TestSchema::new().await;
    let response = schema.execute_as_system_admin(RULES).await;
    assert_eq!(response.errors.len(), 1);
    assert_eq!(response.errors[0].message, "Not supported");

    assert_eq!(
        data(
            &schema,
            "mutation {setSignatureSourceEnabled(source:ET_OPEN,enabled:true)}"
        )
        .await,
        json!({"setSignatureSourceEnabled":true})
    );
    assert!(
        schema
            .store()
            .signature_source(Source::EtOpen)
            .unwrap()
            .enabled
    );
}

#[test]
fn unrelated_store_errors_keep_their_message_without_signature_codes() {
    let error = store_error(anyhow::anyhow!("disk full").context("writing signature versions"));
    assert_eq!(error.message, "writing signature versions");
    assert!(error.extensions.is_none());
}

fn ingest(store: &Store, number: u8) -> u64 {
    store
        .ingest_signature_version(&NewSignatureVersion {
            source: Source::EtOpen,
            source_version: &number.to_string(),
            order_key: SignatureOrderKey {
                date: "2026-01-01".parse().unwrap(),
                number: Some(u64::from(number)),
            },
            fetch_label: Some("fetch-label"),
            origin: SignatureOrigin::Fetch,
            fetched_url: Some("a URL"),
            archive_sha256: [number; 32],
            content_digest: &[number, 0xab],
            received_at: jiff::Timestamp::from_second(1_700_000_000).unwrap(),
            archive: b"archive",
        })
        .unwrap()
}

fn stage(store: &Store, number: u8) -> u64 {
    let id = ingest(store, number);
    store
        .complete_signature_conversion(id, "converter", b"opaque rule set", "stored summary")
        .unwrap();
    id
}

const SOURCES: &str = "{ signatureSources { source enabled applied { id } staged { id } kept { id } versions { id state } lastReconversion { versionId } } }";
const VERSION_FIELDS: &str = "id source sourceVersion fetchLabel converterVersion origin fetchedUrl archiveSha256 contentDigest receivedAt state failureReason summary";

#[tokio::test]
async fn empty_sources_and_all_role_guards() {
    let (schema, manager) = fixture(false).await;
    assert_eq!(
        data(&schema, SOURCES).await,
        json!({"signatureSources": (["ET_OPEN", "SIGMA_HQ", "SIGMA_HQ_EMERGING"].map(|source| json!({"source":source,"enabled":false,"applied":null,"staged":null,"kept":[],"versions":[],"lastReconversion":null})))})
    );
    for role in [
        Role::SystemAdministrator,
        Role::SecurityAdministrator,
        Role::SecurityManager,
        Role::SecurityMonitor,
    ] {
        for query in [
            SOURCES,
            "{signatureSourceVersion(id:\"999\"){id}}",
            "{signatureRules {totalCount}}",
            "{signatureStatus {reports {nodeId} truncationDailySums(date:\"2026-01-01\"){count}}}",
        ] {
            let response = schema.execute_as_scoped_user(query, role, None).await;
            assert_eq!(
                response.errors.is_empty(),
                matches!(
                    role,
                    Role::SystemAdministrator | Role::SecurityAdministrator
                ),
                "{role:?}: {query}: {:?}",
                response.errors
            );
        }
        for query in [
            "mutation {applySignatureSourceVersion(id:\"999\")}",
            "mutation {discardSignatureSourceVersion(id:\"999\")}",
            "mutation {setSignatureSourceEnabled(source:ET_OPEN,enabled:false)}",
            "mutation {setSignatureRuleEnabled(source:ET_OPEN,ruleId:\"one\",enabled:true,account:\"admin\")}",
        ] {
            let response = schema.execute_as_scoped_user(query, role, None).await;
            if role != Role::SystemAdministrator {
                assert_eq!(response.errors.len(), 1);
                assert_eq!(response.errors[0].message, "Forbidden");
            } else if query.contains("Version") {
                assert_eq!(
                    response.errors[0].extensions.as_ref().unwrap().get("code"),
                    Some(&async_graphql::Value::from("UNKNOWN_SIGNATURE_VERSION"))
                );
            } else {
                assert!(response.errors.is_empty(), "{:?}", response.errors);
            }
        }
    }
    assert_eq!(manager.pushes.lock().unwrap().len(), 0);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One lifecycle covers the related version states and push counts.
async fn versions_apply_rollback_discard_and_error_codes() {
    let (schema, manager) = fixture(false).await;
    let a = stage(&schema.store(), 1);
    let response = data(
        &schema,
        &format!("{{signatureSourceVersion(id:\"{a}\"){{{VERSION_FIELDS}}}}}"),
    )
    .await;
    assert_eq!(
        response["signatureSourceVersion"],
        json!({"id":a.to_string(),"source":"ET_OPEN","sourceVersion":"1","fetchLabel":"fetch-label","converterVersion":"converter","origin":"FETCH","fetchedUrl":"a URL","archiveSha256":"01".repeat(32),"contentDigest":"01ab","receivedAt":"2023-11-14T22:13:20Z","state":"STAGED","failureReason":null,"summary":"stored summary"})
    );
    data(
        &schema,
        &format!("mutation {{applySignatureSourceVersion(id:\"{a}\")}}"),
    )
    .await;
    let b = stage(&schema.store(), 2);
    data(
        &schema,
        &format!("mutation {{applySignatureSourceVersion(id:\"{b}\")}}"),
    )
    .await;
    let c = stage(&schema.store(), 3);
    let state = data(&schema, SOURCES).await;
    let row = &state["signatureSources"][0];
    assert_eq!(row["applied"]["id"], (a + 1).to_string());
    assert_eq!(row["kept"], json!([{"id":a.to_string()}]));
    assert_eq!(row["staged"]["id"], c.to_string());
    assert_eq!(
        row["versions"],
        json!([{"id":c.to_string(),"state":"STAGED"},{"id":(a+1).to_string(),"state":"APPLIED"},{"id":a.to_string(),"state":"KEPT"}])
    );
    for (verb, id, code, state) in [
        ("apply", 999, "UNKNOWN_SIGNATURE_VERSION", None),
        ("discard", 999, "UNKNOWN_SIGNATURE_VERSION", None),
        (
            "apply",
            a + 1,
            "INVALID_SIGNATURE_VERSION_STATE",
            Some("APPLIED"),
        ),
        (
            "discard",
            a,
            "INVALID_SIGNATURE_VERSION_STATE",
            Some("KEPT"),
        ),
    ] {
        let response = schema
            .execute_as_system_admin(&format!(
                "mutation {{{verb}SignatureSourceVersion(id:\"{id}\")}}"
            ))
            .await;
        assert_eq!(response.errors.len(), 1);
        let extensions = response.errors[0].extensions.as_ref().unwrap();
        assert_eq!(
            extensions.get("code"),
            Some(&async_graphql::Value::from(code))
        );
        assert_eq!(
            extensions.get("versionId"),
            Some(&async_graphql::Value::from(id.to_string()))
        );
        if let Some(state) = state {
            assert_eq!(
                extensions
                    .get("state")
                    .unwrap()
                    .clone()
                    .into_json()
                    .unwrap(),
                json!(state)
            );
        }
    }
    assert_eq!(manager.pushes.lock().unwrap().len(), 2);
    data(
        &schema,
        &format!("mutation {{applySignatureSourceVersion(id:\"{a}\")}}"),
    )
    .await;
    data(
        &schema,
        &format!("mutation {{discardSignatureSourceVersion(id:\"{c}\")}}"),
    )
    .await;
    assert_eq!(
        manager.pushes.lock().unwrap().as_slice(),
        &[Vec::<String>::new(), vec![], vec![]]
    );
    assert_eq!(
        schema.store().signature_version(c).unwrap().unwrap().state,
        database::SignatureVersionState::Discarded
    );
    assert_eq!(
        data(&schema, "{signatureSourceVersion(id:\"999\"){id}}").await,
        json!({"signatureSourceVersion":null})
    );
    for id in ["abc", "-1", "+1", "18446744073709551616"] {
        assert_eq!(
            schema
                .execute_as_system_admin(&format!("{{signatureSourceVersion(id:\"{id}\"){{id}}}}"))
                .await
                .errors
                .len(),
            1
        );
    }
    // Each remaining persisted state is returned without reinterpretation.
    let converting = ingest(&schema.store(), 4);
    assert_eq!(
        data(
            &schema,
            &format!("{{signatureSourceVersion(id:\"{converting}\"){{state}}}}")
        )
        .await["signatureSourceVersion"]["state"],
        "CONVERTING"
    );
    schema
        .store()
        .fail_signature_conversion(converting, "failed conversion")
        .unwrap();
    assert_eq!(
        data(
            &schema,
            &format!("{{signatureSourceVersion(id:\"{converting}\"){{state failureReason}}}}")
        )
        .await["signatureSourceVersion"],
        json!({"state":"FAILED","failureReason":"failed conversion"})
    );
}

#[tokio::test]
async fn source_history_keeps_newest_first_and_version_queries_preserve_states() {
    let (schema, manager) = fixture(false).await;
    let mut applied = Vec::new();
    for number in 1..=3 {
        let id = stage(&schema.store(), number);
        data(
            &schema,
            &format!("mutation {{applySignatureSourceVersion(id:\"{id}\")}}"),
        )
        .await;
        applied.push(id);
    }
    let staged = stage(&schema.store(), 4);
    let sources = data(&schema, SOURCES).await;
    let row = &sources["signatureSources"][0];
    assert_eq!(row["applied"]["id"], applied[2].to_string());
    assert_eq!(
        row["kept"],
        json!([{"id":applied[1].to_string()},{"id":applied[0].to_string()}])
    );
    assert_eq!(row["staged"]["id"], staged.to_string());
    assert_eq!(
        row["versions"],
        json!([
            {"id":staged.to_string(),"state":"STAGED"},
            {"id":applied[2].to_string(),"state":"APPLIED"},
            {"id":applied[1].to_string(),"state":"KEPT"},
            {"id":applied[0].to_string(),"state":"KEPT"}
        ])
    );
    data(
        &schema,
        &format!("mutation {{discardSignatureSourceVersion(id:\"{staged}\")}}"),
    )
    .await;
    for (id, state) in [
        (applied[0], "KEPT"),
        (applied[2], "APPLIED"),
        (staged, "DISCARDED"),
    ] {
        assert_eq!(
            data(
                &schema,
                &format!("{{signatureSourceVersion(id:\"{id}\"){{id state}}}}")
            )
            .await["signatureSourceVersion"],
            json!({"id":id.to_string(),"state":state})
        );
    }
    assert_eq!(manager.pushes.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn source_references_to_missing_versions_are_errors() {
    for missing in ["applied", "staged", "kept"] {
        let dir = tempfile::tempdir().unwrap();
        let backup = tempfile::tempdir().unwrap();
        let missing_id = {
            let store = Store::new(dir.path(), backup.path(), None).unwrap();
            let kept = stage(&store, 1);
            store.apply_signature_version(kept).unwrap();
            let applied = stage(&store, 2);
            store.apply_signature_version(applied).unwrap();
            let staged = stage(&store, 3);
            match missing {
                "applied" => applied,
                "staged" => staged,
                "kept" => kept,
                _ => unreachable!(),
            }
        };
        {
            // Simulate an inconsistent store without changing the source row.
            let path = dir.path().join("states.db");
            let options = rocksdb::Options::default();
            let families = rocksdb::DB::list_cf(&options, &path).unwrap();
            let db = rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open_cf(
                &options, &path, families,
            )
            .unwrap();
            let versions = db.cf_handle("signature source versions").unwrap();
            db.delete_cf(versions, missing_id.to_be_bytes()).unwrap();
        }
        let manager = Arc::new(Manager::default());
        let schema = TestSchema::new_in(manager.clone(), dir).await;
        let response = schema.execute_as_system_admin(SOURCES).await;
        assert_eq!(response.errors.len(), 1, "{missing}");
        assert_eq!(
            response.errors[0].message, "a signature source names a missing version",
            "{missing}"
        );
        assert_eq!(
            data(
                &schema,
                &format!("{{signatureSourceVersion(id:\"{missing_id}\"){{id}}}}")
            )
            .await,
            json!({"signatureSourceVersion":null})
        );
        assert!(manager.pushes.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn reconversion_success_and_failure() {
    let (schema, _) = fixture(false).await;
    let id = stage(&schema.store(), 1);
    let time = jiff::Timestamp::from_second(1_700_000_000).unwrap();
    schema
        .store()
        .complete_signature_reconversion(
            id,
            &SignatureReconversionSuccess {
                converter_version: "new converter",
                rule_set: b"new rules",
                summary: "new summary",
                previous_rule_count: Some(u64::MAX),
                rule_count: 42,
                time,
            },
        )
        .unwrap();
    let query = "{signatureSources {lastReconversion {time versionId previousConverterVersion attemptedConverterVersion succeeded previousRuleCount ruleCount failureReason}}}";
    assert_eq!(
        data(&schema, query).await["signatureSources"][0]["lastReconversion"],
        json!({"time":time.to_string(),"versionId":id.to_string(),"previousConverterVersion":"converter","attemptedConverterVersion":"new converter","succeeded":true,"previousRuleCount":u64::MAX.to_string(),"ruleCount":"42","failureReason":null})
    );
    schema
        .store()
        .complete_signature_reconversion(
            id,
            &SignatureReconversionSuccess {
                converter_version: "new converter",
                rule_set: b"new rules",
                summary: "new summary",
                previous_rule_count: None,
                rule_count: 42,
                time,
            },
        )
        .unwrap();
    let reconversion = data(&schema, query).await;
    let reconversion = &reconversion["signatureSources"][0]["lastReconversion"];
    assert_eq!(reconversion["succeeded"], true);
    assert_eq!(reconversion["previousRuleCount"], Value::Null);
    assert_eq!(reconversion["ruleCount"], "42");
    schema
        .store()
        .fail_signature_reconversion(id, "broken converter", "failure reason", time)
        .unwrap();
    assert_eq!(
        data(&schema, query).await["signatureSources"][0]["lastReconversion"],
        json!({"time":time.to_string(),"versionId":id.to_string(),"previousConverterVersion":"new converter","attemptedConverterVersion":"broken converter","succeeded":false,"previousRuleCount":null,"ruleCount":null,"failureReason":"failure reason"})
    );
}

const RULES: &str = "{signatureRules {rules {source detectionModel ruleId title classification severity disabled} totalCount}}";
const OFF: &str = "mutation {setSignatureRuleEnabled(source:ET_OPEN,ruleId:\"one\",enabled:false,account:\"  operator  \")}";
const ON: &str = "mutation {setSignatureRuleEnabled(source:ET_OPEN,ruleId:\"one\",enabled:true,account:\"operator\")}";

#[tokio::test]
async fn setters_push_on_changes_only_and_rule_overrides_are_reflected() {
    let (schema, manager) = fixture(false).await;
    for (enabled, changed) in [(true, true), (true, false), (false, true), (false, false)] {
        let result = data(
            &schema,
            &format!("mutation {{setSignatureSourceEnabled(source:ET_OPEN,enabled:{enabled})}}"),
        )
        .await;
        assert_eq!(result["setSignatureSourceEnabled"], changed);
    }
    assert_eq!(manager.pushes.lock().unwrap().len(), 2);
    for (query, changed) in [(OFF, true), (OFF, false), (ON, true), (ON, false)] {
        assert_eq!(
            data(&schema, query).await["setSignatureRuleEnabled"],
            changed
        );
        let disabled = query == OFF;
        let rules = data(&schema, RULES).await;
        assert_eq!(rules["signatureRules"]["totalCount"], "1234");
        assert_eq!(
            rules["signatureRules"]["rules"][0],
            json!({"source":"ET_OPEN","detectionModel":"ET_SIGNATURE","ruleId":"one","title":"Title","classification":"class","severity":"High","disabled":disabled})
        );
        assert_eq!(rules["signatureRules"]["rules"][1]["disabled"], false);
        if disabled {
            assert_eq!(
                schema.store().signature_rule_overrides().unwrap()[0].account,
                "operator"
            );
        }
    }
    assert_eq!(manager.pushes.lock().unwrap().len(), 4);
    for query in [
        OFF.replace("  operator  ", "  "),
        OFF.replace("ruleId:\"one\"", "ruleId:\"\""),
        ON.replace("operator", " "),
    ] {
        assert_eq!(schema.execute_as_system_admin(&query).await.errors.len(), 1);
    }
    assert_eq!(schema.store().signature_rule_overrides().unwrap().len(), 0);
    assert_eq!(manager.pushes.lock().unwrap().len(), 4);
    assert!(manager.pushes.lock().unwrap().iter().all(Vec::is_empty));
}

#[tokio::test]
async fn failed_push_still_succeeds_and_listing_errors_propagate() {
    let (schema, manager) = fixture(true).await;
    let id = stage(&schema.store(), 1);
    data(
        &schema,
        &format!("mutation {{applySignatureSourceVersion(id:\"{id}\")}}"),
    )
    .await;
    data(
        &schema,
        "mutation {setSignatureSourceEnabled(source:ET_OPEN,enabled:true)}",
    )
    .await;
    data(&schema, OFF).await;
    data(&schema, ON).await;
    assert_eq!(manager.pushes.lock().unwrap().len(), 4);
    let result = schema.execute_as_system_admin(RULES).await;
    assert_eq!(result.errors[0].message, "listing failed");
}

#[tokio::test]
async fn rule_filter_paging_and_boundaries() {
    let (schema, manager) = fixture(false).await;
    data(&schema, "{signatureRules(filter:{sources:[SIGMA_HQ],models:[ET_POLICY_SIGNATURE],ruleId:\"id\",text:\"Text\"},offset:5,limit:1000){totalCount}}").await;
    assert_eq!(
        manager.listings.lock().unwrap().as_slice(),
        &[(
            SignatureRuleFilter {
                sources: vec![Source::SigmaHq],
                models: vec![Model::EtPolicySignature],
                rule_id: Some("id".into()),
                text: Some("Text".into())
            },
            5,
            1000
        )]
    );
    data(&schema, RULES).await;
    data(
        &schema,
        "{signatureRules(filter:{},offset:2147483647,limit:1){totalCount}}",
    )
    .await;
    assert_eq!(
        manager.listings.lock().unwrap()[1],
        (SignatureRuleFilter::default(), 0, 100)
    );
    assert_eq!(
        manager.listings.lock().unwrap()[2],
        (SignatureRuleFilter::default(), 2_147_483_647, 1)
    );
    for args in ["offset:-1", "limit:0", "limit:-1", "limit:1001"] {
        assert_eq!(
            schema
                .execute_as_system_admin(&format!("{{signatureRules({args}){{totalCount}}}}"))
                .await
                .errors
                .len(),
            1
        );
    }
    assert_eq!(manager.listings.lock().unwrap().len(), 3);
    data(
        &schema,
        "{signatureRules(offset:null,limit:null){totalCount}}",
    )
    .await;
    assert_eq!(
        manager.listings.lock().unwrap()[3],
        (SignatureRuleFilter::default(), 0, 100)
    );
}

#[tokio::test]
async fn status_reports_respect_customer_scope_and_daily_sums_are_installation_wide() {
    use protocol::{LoadedSignatureSet as Loaded, SignatureStatusReport, TruncatedCount};

    use crate::graphql::time_series_generation_test_support::insert_generator_node;

    let (schema, _) = fixture(false).await;
    let time = jiff::Timestamp::from_second(1_700_000_000).unwrap();
    let mut instances = Vec::new();
    for (host, customer) in [("a.example.com", 1), ("b.example.com", 2)] {
        let store = schema.store();
        let instance = insert_generator_node(&store, host, customer);
        let mut map = store.node_map();
        let (mut node, _, _) = map.get_by_id(instance.node_id).unwrap().unwrap();
        let old = database::NodeUpdate::from(node.clone());
        for agent in &mut node.agents {
            if agent.key == instance.agent_key {
                agent.kind = database::AgentKind::SemiSupervised;
            }
        }
        map.update(instance.node_id, &old, &database::NodeUpdate::from(node))
            .unwrap();
        store
            .set_signature_status_report(
                &instance,
                &SignatureStatusReport {
                    loaded: vec![Loaded {
                        source: Source::EtOpen,
                        source_version: "release".into(),
                        converter_version: "converter".into(),
                        rules: u64::MAX,
                        failed_compile: 2,
                        load_error: Some("load error".into()),
                    }],
                    truncated: vec![TruncatedCount {
                        detection_model: Model::EtSignature,
                        source: Source::EtOpen,
                        rule_id: "one".into(),
                        orig_addr: "10.0.0.1".parse().unwrap(),
                        window_start: time.as_nanosecond().try_into().unwrap(),
                        count: 7,
                    }],
                    truncated_overflow: 42,
                    os_gated_skipped: vec![(protocol::RawEventKind::WindowsEventLog, 3)],
                    home_net_fallback: true,
                },
                time,
            )
            .unwrap();
        instances.push(instance);
    }
    let query = "{signatureStatus {reports {nodeId agentKey receivedAt loaded {source sourceVersion converterVersion rules failedCompile loadError} osGatedSkipped {rawEventKind count} homeNetFallback truncatedOverflow} truncationDailySums(date:\"2023-11-14\"){detectionModel source ruleId count}}}";
    for (role, customers, expected) in [
        (Role::SystemAdministrator, None, 2),
        (Role::SecurityAdministrator, None, 2),
        (Role::SecurityAdministrator, Some(vec![1]), 1),
        (Role::SecurityAdministrator, Some(vec![]), 0),
    ] {
        let response = schema.execute_as_scoped_user(query, role, customers).await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let result = response.data.into_json().unwrap();
        let reports = result["signatureStatus"]["reports"].as_array().unwrap();
        assert_eq!(reports.len(), expected);
        for (row, instance) in reports.iter().zip(&instances) {
            assert_eq!(
                *row,
                json!({"nodeId":instance.node_id.to_string(),"agentKey":instance.agent_key,"receivedAt":time.to_string(),"loaded":[{"source":"ET_OPEN","sourceVersion":"release","converterVersion":"converter","rules":u64::MAX.to_string(),"failedCompile":"2","loadError":"load error"}],"osGatedSkipped":[{"rawEventKind":"WINDOWS_EVENT_LOG","count":"3"}],"homeNetFallback":true,"truncatedOverflow":"42"})
            );
        }
        assert_eq!(
            result["signatureStatus"]["truncationDailySums"],
            json!([{"detectionModel":"ET_SIGNATURE","source":"ET_OPEN","ruleId":"one","count":"14"}])
        );
    }
    for date in [
        "20231114",
        "2023-2-14",
        "2023-02-29",
        "2023-11-14T00:00:00Z",
        "2023-11-14Z",
        " 2023-11-14",
    ] {
        assert!(
            !schema
                .execute_as_system_admin(&format!(
                    "{{signatureStatus{{truncationDailySums(date:\"{date}\"){{count}}}}}}"
                ))
                .await
                .errors
                .is_empty(),
            "{date}"
        );
    }
    assert_eq!(
        data(
            &schema,
            "{signatureStatus{truncationDailySums(date:\"2024-02-29\"){count}}}"
        )
        .await["signatureStatus"]["truncationDailySums"],
        json!([])
    );
}
