use review_database::{ClusteringModelTypeRef, SlotSize};
use serde_json::Value;

use super::*;
use crate::graphql::{
    model_test_support::{TestModel, http_url, insert_engine_node, insert_label_db},
    time_series_generation_test_support::{
        OWN_ADDRESS, POLICY_CUSTOMER, PolicyFixture, PolicyShape, generator_config,
        insert_generator_node_with, sensor_name,
    },
    training_test_support::HTTP_URL_CSV,
};

const VALID: &str = r#"
cpus = 4

[[detectors]]
id = 1
enabled = true
model = "web-http-node2"
sources = ["piglet.node2.example.com"]
period = "5m"
start = "2026-10-21T00:00:00Z"
batch_size = 500000
read_lag = "30s"
stats = false
timeseries = false

[detectors.data_store]
address = "10.0.0.5:38371"
server_name = "001.giganto.node1.example.com"
"#;

const FULL: &str = r#"
cpus = 64

[[detectors]]
id = 1
enabled = false
model = "web-http-node2"
sources = ["piglet.node2.example.com", "reproduce.node2.example.com"]
period = "5m"
start = "2026-10-21T00:00:00+09:00"
batch_size = 500000
read_lag = "30s"
suspicious_tokens = "indicator-name"
stats = false
timeseries = true

[detectors.data_store]
address = "[::1]:38371"
server_name = "001.giganto.node1.example.com"

[detectors.detection_models.label_db_match]
enabled = true
event_range = 30
min_events_ratio = 10
columns = [
  { column_ids = [15], db = "HttpUriThreat", min_score = 0.7 },
  { column_ids = [1, 2], db = "Other" },
]

[detectors.detection_models.far_outlier]
enabled = false

[[detectors]]
id = -2
enabled = true
model = "dns-node2"
sources = ["piglet.node2.example.com"]
period = "1h 30m"
start = "2026-10-21T00:00:00Z"
batch_size = 1
read_lag = "0s"
stats = true
timeseries = false

[detectors.data_store]
address = "10.0.0.5:38371"
server_name = "001.giganto.node1.example.com"
"#;

/// Returns `text` with the line starting with `key =` replaced by `line`, or
/// `line` inserted after `id = 1` when no such line exists.
fn with(text: &str, key: &str, line: &str) -> String {
    let prefix = format!("{key} =");
    if text.lines().any(|l| l.starts_with(&prefix)) {
        text.lines()
            .map(|l| if l.starts_with(&prefix) { line } else { l })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        text.replacen("id = 1\n", &format!("id = 1\n{line}\n"), 1)
    }
}

/// Returns `text` without the line starting with `key =`.
fn without(text: &str, key: &str) -> String {
    let prefix = format!("{key} =");
    text.lines()
        .filter(|l| !l.starts_with(&prefix))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns the code, `field`, `value` and `detectorId` of the refusal of
/// `text`.
fn refused(text: &str) -> (String, String, String, Value) {
    parts(&EngineDocument::parse_and_validate(text).expect_err(text))
}

/// Returns the code, `field`, `value` and `detectorId` of `error`, a
/// refusal.
fn parts(error: &async_graphql::Error) -> (String, String, String, Value) {
    let extensions =
        serde_json::to_value(error.extensions.as_ref().expect("a refusal has extensions")).unwrap();
    let get = |key: &str| match &extensions[key] {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    (
        get("code"),
        get("field"),
        get("value"),
        extensions["detectorId"].clone(),
    )
}

fn code_and_field(text: &str) -> (String, String) {
    let (code, field, _, _) = refused(text);
    (code, field)
}

#[test]
fn documents_without_detectors_parse() {
    for text in [
        "",
        "detectors = []",
        "cpus = 4",
        "cpus = 4\ndetectors = []\n",
    ] {
        let document = EngineDocument::parse_and_validate(text).expect(text);
        assert!(document.detectors.is_empty(), "{text}");
        assert_eq!(document.refs(), EngineDocumentRefs::default(), "{text}");
    }
}

#[test]
fn every_optional_key_may_be_absent() {
    let document = EngineDocument::parse_and_validate(VALID).unwrap();
    let detector = &document.detectors[0];
    assert_eq!(detector.id, 1);
    assert_eq!(detector.period.duration, Duration::from_mins(5));
    assert_eq!(detector.suspicious_tokens, None);
    assert_eq!(detector.detection_models, None);
    let without_cpus = without(VALID, "cpus");
    assert_eq!(
        EngineDocument::parse_and_validate(&without_cpus)
            .unwrap()
            .cpus,
        None
    );
}

#[test]
fn every_key_of_the_schema_parses() {
    let document = EngineDocument::parse_and_validate(FULL).unwrap();
    assert_eq!(document.cpus, Some(64));
    let [first, second] = &document.detectors[..] else {
        panic!("two detectors");
    };
    assert!(!first.enabled);
    assert_eq!(first.read_lag.duration, Duration::from_secs(30));
    assert!(!first.stats);
    assert!(first.timeseries);
    // The sections are kept as written, untyped.
    let sections = first.detection_models.as_ref().unwrap();
    assert_eq!(
        sections.keys().collect::<Vec<_>>(),
        ["far_outlier", "label_db_match"]
    );
    assert_eq!(
        sections["label_db_match"]["columns"][1]["db"].as_str(),
        Some("Other")
    );
    assert_eq!(second.read_lag.duration, Duration::ZERO);
    assert!(second.stats);
    assert!(!second.timeseries);
    assert_eq!(second.id, -2);
    assert_eq!(second.period.duration, Duration::from_mins(90));
    assert_eq!(
        document.refs(),
        EngineDocumentRefs {
            detectors: vec![
                EngineDetectorRef {
                    id: 1,
                    model: "web-http-node2".to_string(),
                    sources: vec![
                        "piglet.node2.example.com".to_string(),
                        "reproduce.node2.example.com".to_string()
                    ],
                    indicator: Some("indicator-name".to_string()),
                },
                EngineDetectorRef {
                    id: -2,
                    model: "dns-node2".to_string(),
                    sources: vec!["piglet.node2.example.com".to_string()],
                    indicator: None,
                },
            ],
        }
    );
    assert_eq!(
        document.server_names().into_iter().collect::<Vec<_>>(),
        ["001.giganto.node1.example.com"]
    );
}

#[test]
fn every_required_key_must_be_present() {
    for key in [
        "id",
        "enabled",
        "model",
        "sources",
        "period",
        "start",
        "batch_size",
        "read_lag",
        "stats",
        "timeseries",
    ] {
        let (code, field, _, detector_id) = refused(&without(VALID, key));
        assert_eq!(code, "INVALID_DOCUMENT", "{key}");
        assert_eq!(field, format!("detectors[0].{key}"), "{key}");
        if key != "id" {
            assert_eq!(detector_id, Value::from(1), "{key}");
        }
    }
    for (key, field) in [
        ("address", "detectors[0].data_store.address"),
        ("server_name", "detectors[0].data_store.server_name"),
    ] {
        assert_eq!(
            code_and_field(&without(VALID, key)),
            ("INVALID_DOCUMENT".to_string(), field.to_string())
        );
    }
    let no_data_store = VALID
        .replace("[detectors.data_store]\n", "")
        .replace("address = \"10.0.0.5:38371\"\n", "")
        .replace("server_name = \"001.giganto.node1.example.com\"\n", "");
    assert_eq!(
        code_and_field(&no_data_store),
        (
            "INVALID_DOCUMENT".to_string(),
            "detectors[0].data_store".to_string()
        )
    );
}

#[test]
fn unknown_keys_are_refused_at_every_level() {
    for (text, field, key) in [
        (
            format!("export_path = \"/tmp\"\n{VALID}"),
            "export_path",
            "export_path",
        ),
        (
            format!("log_path = \"/tmp\"\n{VALID}"),
            "log_path",
            "log_path",
        ),
        (
            with(VALID, "event_type", "event_type = \"http\""),
            "detectors[0].event_type",
            "event_type",
        ),
        (
            with(VALID, "export_path", "export_path = \"/x\""),
            "detectors[0].export_path",
            "export_path",
        ),
        (
            with(VALID, "kind", "kind = \"log\""),
            "detectors[0].kind",
            "kind",
        ),
        (
            format!("{VALID}\n[detectors.csv]\ntime_column = 0\n"),
            "detectors[0].csv",
            "csv",
        ),
        (
            VALID.replace("server_name =", "log_path = \"/x\"\nserver_name ="),
            "detectors[0].data_store.log_path",
            "log_path",
        ),
        (
            with(VALID, "max_event_id_num", "max_event_id_num = 25"),
            "detectors[0].max_event_id_num",
            "max_event_id_num",
        ),
        (
            format!("{VALID}\n[detectors.labeldb]\nevent_range = 30\ncolumns = []\n"),
            "detectors[0].labeldb",
            "labeldb",
        ),
        (
            with(VALID, "labeldb", "labeldb = { columns = [] }"),
            "detectors[0].labeldb",
            "labeldb",
        ),
        (format!("{VALID}\n[auth]\nkey = 1\n"), "auth", "auth"),
    ] {
        let (code, refused_field, value, _) = refused(&text);
        assert_eq!(code, "UNKNOWN_FIELD", "{text}");
        assert_eq!(refused_field, field, "{text}");
        assert_eq!(value, key, "{text}");
    }
    for (key, line) in [
        ("event_type", "event_type = \"http\""),
        ("max_event_id_num", "max_event_id_num = 25"),
        ("labeldb", "labeldb = { columns = [] }"),
    ] {
        let (_, _, _, detector_id) = refused(&with(VALID, key, line));
        assert_eq!(detector_id, Value::from(1), "{line}");
    }
}

/// Detector starts that are refused, some of which jiff alone would take, each
/// with whether the shape check (`false`) or the jiff parse (`true`) refuses
/// it.
const REFUSED_STARTS: [(&str, bool); 8] = [
    ("2026-03-15T15:00:04", false),
    ("2026-03-15T15:00:04+09", false),
    ("2026-03-15T15:00:04+0900", false),
    ("2026-03-15T15:00:04Z[Asia/Seoul]", false),
    ("2026-03-15T15:00:04,5Z", false),
    ("20260315T150004Z", false),
    ("2026-03-15T15:00:04.1234567890Z", true),
    ("9999-12-31T00:00:00Z", true),
];

#[test]
fn other_start_forms_are_refused() {
    for (start, parse_failure) in REFUSED_STARTS {
        let text = with(VALID, "start", &format!("start = \"{start}\""));
        let error = EngineDocument::parse_and_validate(&text).expect_err(start);
        let (code, field, _, detector_id) = parts(&error);
        assert_eq!(
            (code.as_str(), field.as_str()),
            ("INVALID_DOCUMENT", "detectors[0].start"),
            "{start}"
        );
        assert_eq!(detector_id, Value::from(1), "{start}");
        let prefix = format!("{start:?} is not RFC 3339 with an offset");
        assert!(
            error.message.contains(&prefix),
            "{start}: {}",
            error.message
        );
        assert_eq!(
            error.message.contains(&format!("{prefix}: ")),
            parse_failure,
            "{start}: {}",
            error.message
        );
    }
}

/// RFC 3339 detector starts with an offset that are accepted and passed on
/// to the engine exactly as written.
const ACCEPTED_STARTS: [&str; 3] = [
    "2026-03-15T15:00:04Z",
    "2026-03-15T15:00:04.123456789+09:00",
    "2026-03-15 15:00:04-05:30",
];

#[test]
fn rfc3339_starts_are_accepted_and_kept_as_written() {
    for start in ACCEPTED_STARTS {
        let text = with(VALID, "start", &format!("start = \"{start}\""));
        let document = EngineDocument::parse_and_validate(&text).expect(start);
        let detector = document.detectors.first().expect("one detector");
        assert_eq!(detector.start, start);
    }
}

#[test]
fn values_outside_their_type_are_invalid() {
    for (key, line, field) in [
        ("cpus", "cpus = -1", "cpus"),
        ("cpus", "cpus = 1.5", "cpus"),
        ("id", "id = 2147483648", "detectors[0].id"),
        ("id", "id = \"one\"", "detectors[0].id"),
        ("enabled", "enabled = 1", "detectors[0].enabled"),
        ("batch_size", "batch_size = -1", "detectors[0].batch_size"),
        ("batch_size", "batch_size = 1.5", "detectors[0].batch_size"),
        ("stats", "stats = \"no\"", "detectors[0].stats"),
        ("timeseries", "timeseries = 1", "detectors[0].timeseries"),
        ("read_lag", "read_lag = 30", "detectors[0].read_lag"),
        ("sources", "sources = \"piglet.a\"", "detectors[0].sources"),
        ("sources", "sources = [1]", "detectors[0].sources[0]"),
        ("period", "period = \"five minutes\"", "detectors[0].period"),
        ("period", "period = 300", "detectors[0].period"),
        ("read_lag", "read_lag = \"-1s\"", "detectors[0].read_lag"),
        (
            "start",
            "start = \"2026-10-21T00:00:00\"",
            "detectors[0].start",
        ),
        (
            "start",
            "start = 2026-10-21T00:00:00Z",
            "detectors[0].start",
        ),
        (
            "address",
            "address = \"10.0.0.5\"",
            "detectors[0].data_store.address",
        ),
    ] {
        let (code, refused_field, _, _) = refused(&with(VALID, key, line));
        assert_eq!(code, "INVALID_DOCUMENT", "{line}");
        assert_eq!(refused_field, field, "{line}");
    }
    // `detection_models` is a table; what it holds is the checker's.
    for (line, value) in [
        ("detection_models = 5", "5"),
        ("detection_models = \"far_outlier\"", "\"far_outlier\""),
        ("detection_models = [1]", "[1]"),
    ] {
        let (code, field, refused_value, detector_id) =
            refused(&with(VALID, "detection_models", line));
        assert_eq!(
            (code.as_str(), field.as_str(), refused_value.as_str()),
            ("INVALID_DOCUMENT", "detectors[0].detection_models", value),
            "{line}"
        );
        assert_eq!(detector_id, Value::from(1), "{line}");
    }
    for line in [
        "detection_models = { label_db_match = 5, foo = { bar = 1 } }",
        "detection_models = {}",
    ] {
        EngineDocument::parse_and_validate(&with(VALID, "detection_models", line)).expect(line);
    }
}

#[test]
fn a_syntax_error_names_no_field_and_carries_the_message() {
    for text in ["detectors = ", "[[detectors]\nid = 1", "not toml at all"] {
        let error = EngineDocument::parse_and_validate(text).expect_err(text);
        let (code, field, value, _) = refused(text);
        assert_eq!(code, "INVALID_DOCUMENT", "{text}");
        assert_eq!(field, "", "{text}");
        assert!(!value.is_empty(), "{text}");
        assert!(error.message.ends_with(&value), "{text}: {}", error.message);
    }
}

#[test]
fn bounds_are_accepted_at_their_limit_and_refused_past_it() {
    for (key, at, past, field) in [
        ("cpus", "cpus = 64", "cpus = 65", "cpus"),
        (
            "period",
            "period = \"1m\"",
            "period = \"59s\"",
            "detectors[0].period",
        ),
        (
            "read_lag",
            "read_lag = \"1h\"",
            "read_lag = \"3601s\"",
            "detectors[0].read_lag",
        ),
        (
            "batch_size",
            "batch_size = 5000000",
            "batch_size = 5000001",
            "detectors[0].batch_size",
        ),
    ] {
        EngineDocument::parse_and_validate(&with(VALID, key, at)).expect(at);
        let (code, refused_field, value, detector_id) = refused(&with(VALID, key, past));
        assert_eq!(code, "BOUND_VIOLATED", "{past}");
        assert_eq!(refused_field, field, "{past}");
        assert!(past.contains(&value), "{past}: {value}");
        if key != "cpus" {
            assert_eq!(detector_id, Value::from(1), "{past}");
        }
    }
    EngineDocument::parse_and_validate(&with(VALID, "read_lag", "read_lag = \"0s\""))
        .expect("a read lag of 0");
}

#[test]
fn ids_models_and_sources_are_listed_once_each() {
    let second = |id: i32, model: &str| {
        format!(
            "{VALID}\n[[detectors]]\nid = {id}\nenabled = true\nmodel = \"{model}\"\nsources = \
             [\"piglet.node2.example.com\"]\nperiod = \"5m\"\nstart = \
             \"2026-10-21T00:00:00Z\"\nbatch_size = 1\nread_lag = \"0s\"\nstats = \
             false\ntimeseries = false\n\n[detectors.data_store]\naddress = \
             \"10.0.0.5:38371\"\nserver_name = \"001.giganto.node1.example.com\"\n"
        )
    };
    EngineDocument::parse_and_validate(&second(2, "other")).unwrap();
    assert_eq!(
        refused(&second(1, "other")),
        (
            "DUPLICATE_ENTRY".to_string(),
            "detectors[1].id".to_string(),
            "1".to_string(),
            Value::from(1)
        )
    );
    assert_eq!(
        refused(&second(2, "web-http-node2")),
        (
            "DUPLICATE_ENTRY".to_string(),
            "detectors[1].model".to_string(),
            "web-http-node2".to_string(),
            Value::from(2)
        )
    );
    assert_eq!(
        refused(&with(VALID, "sources", "sources = []")),
        (
            "INVALID_DOCUMENT".to_string(),
            "detectors[0].sources".to_string(),
            String::new(),
            Value::from(1)
        )
    );
    assert_eq!(
        refused(&with(
            VALID,
            "sources",
            "sources = [\"piglet.a\", \"piglet.b\", \"piglet.a\"]"
        )),
        (
            "DUPLICATE_ENTRY".to_string(),
            "detectors[0].sources[2]".to_string(),
            "piglet.a".to_string(),
            Value::from(1)
        )
    );
}

#[test]
fn bounds_are_checked_before_repeats() {
    let text = with(
        &with(
            VALID,
            "sources",
            "sources = [\"piglet.node2.example.com\", \"piglet.node2.example.com\"]",
        ),
        "batch_size",
        "batch_size = 5000001",
    );
    assert_eq!(code_and_field(&text).0, "BOUND_VIOLATED");
}

#[test]
fn an_empty_source_list_is_refused_before_bounds() {
    let text = with(
        &with(VALID, "sources", "sources = []"),
        "batch_size",
        "batch_size = 5000001",
    );
    assert_eq!(
        code_and_field(&text),
        (
            "INVALID_DOCUMENT".to_string(),
            "detectors[0].sources".to_string()
        )
    );
}

#[test]
fn kept_pairs_come_from_documents_that_parse() {
    let pairs = kept_pairs([VALID, "test = 'toml'", "not toml", ""]);
    assert_eq!(
        pairs,
        HashSet::from([(
            "001.giganto.node1.example.com".to_string(),
            "10.0.0.5:38371".parse().unwrap()
        )])
    );
}

#[test]
fn kept_pairs_come_from_completed_documents_and_not_from_the_old_shape() {
    let on =
        |server_name: &str, text: &str| text.replace("001.giganto.node1.example.com", server_name);
    // The document the database write stores for an `http_url` model.
    let completed = complete_engine_document(
        AgentKind::Unsupervised,
        &on("completed.example.com", VALID),
        &|_| Some(http_url(1)),
        &|_| None,
        CompletionMode::Apply,
    )
    .unwrap();
    assert!(completed.contains("[detectors.detection_models.label_db_match]"));
    assert!(completed.contains("[detectors.detection_models.far_outlier]"));
    let old_shapes = [
        format!(
            "{}\n[detectors.labeldb]\ncolumns = []\n",
            on("old-label-table.example.com", VALID)
        ),
        with(
            &on("max-event-id-num.example.com", VALID),
            "max_event_id_num",
            "max_event_id_num = 25",
        ),
        without(&on("no-read-lag.example.com", VALID), "read_lag"),
        without(&on("no-stats.example.com", VALID), "stats"),
        without(&on("no-timeseries.example.com", VALID), "timeseries"),
    ];
    let pairs = kept_pairs(
        std::iter::once(completed.as_str()).chain(old_shapes.iter().map(String::as_str)),
    );
    assert_eq!(
        pairs,
        HashSet::from([(
            "completed.example.com".to_string(),
            "10.0.0.5:38371".parse().unwrap()
        )])
    );
}

// ---------------------------------------------------------------------------
// Detectors of a timeseries model

const TIMESERIES_MODEL: &str = "ts-model";
const MULTIDIMENSION_MODEL: &str = "md-model";

/// A [`PolicyFixture`] with an engine instance of its customer holding a
/// timeseries model trained on the fixture's assigned policies, and a
/// multidimension model.
struct Detectors {
    policies: PolicyFixture,
    instance: ModelInstance,
}

impl Detectors {
    fn new() -> Self {
        let policies = PolicyFixture::new();
        let instance = insert_engine_node(&policies.store, POLICY_CUSTOMER);
        TestModel {
            instance: instance.clone(),
            kind: TIMESERIES_KIND,
            trained_sources: policies.assigned.iter().map(ToString::to_string).collect(),
            ..TestModel::new(TIMESERIES_MODEL, POLICY_CUSTOMER)
        }
        .replace(&policies.store);
        TestModel {
            instance: instance.clone(),
            ..TestModel::new(MULTIDIMENSION_MODEL, POLICY_CUSTOMER)
        }
        .replace(&policies.store);
        Self { policies, instance }
    }

    /// Returns a document with one detector of `model` reading `sources`
    /// from the fixture's first Data Store, with `extra` lines.
    fn document(&self, model: &str, sources: &[String], extra: &str) -> String {
        format!(
            r#"
[[detectors]]
id = 7
enabled = true
model = "{model}"
sources = {sources}
period = "15m"
start = "2026-10-21T00:00:00Z"
batch_size = 1000
read_lag = "1m"
stats = false
timeseries = false
{extra}

[detectors.data_store]
address = "{OWN_ADDRESS}"
server_name = "{}"
"#,
            self.policies.server_name,
            sources = serde_json::to_string(sources).unwrap(),
        )
    }

    /// Checks `text` as a draft save on the instance by a Security
    /// Administrator does.
    fn check(&self, text: &str) -> Result<()> {
        let addrs = HashMap::from([(
            self.policies.server_name.clone(),
            vec!["10.0.0.5".parse().unwrap()],
        )]);
        EngineDocument::parse_and_validate(text)?.check_stored(
            text,
            &self.policies.store,
            &DocumentTarget {
                instance: &self.instance,
                customer_id: Some(POLICY_CUSTOMER),
                addrs: &addrs,
                kept: &HashSet::new(),
                system_admin: false,
            },
        )
    }

    /// Returns the code, `field`, `value` and `detectorId` of the refusal of
    /// `text`, and its message.
    fn refused(&self, text: &str) -> ((String, String, String, Value), String) {
        let error = self.check(text).expect_err(text);
        (parts(&error), error.message)
    }
}

#[test]
fn a_timeseries_detector_reads_policies_of_the_trained_shape() {
    let f = Detectors::new();
    let [p1, p2] = f.policies.assigned.map(|id| id.to_string());
    f.check(
        &f.document(TIMESERIES_MODEL, std::slice::from_ref(&p1), "")
            .replace("stats = false", "stats = true"),
    )
    .unwrap();
    f.check(
        &f.document(TIMESERIES_MODEL, &[p2, p1], "")
            .replace("timeseries = false", "timeseries = true"),
    )
    .unwrap();
    // A new policy of the same shape is accepted too.
    let p3 = f
        .policies
        .assigned_policy("p3", &f.policies.generator, PolicyShape::default())
        .to_string();
    f.check(&f.document(TIMESERIES_MODEL, &[p3], "")).unwrap();
}

#[test]
fn a_timeseries_detector_refuses_a_sensor() {
    let f = Detectors::new();
    let sensor = sensor_name("gen-a.example.com");
    let ((code, field, value, detector_id), message) =
        f.refused(&f.document(TIMESERIES_MODEL, std::slice::from_ref(&sensor), ""));
    assert_eq!(
        (code.as_str(), field.as_str(), value.as_str()),
        (
            "SOURCE_NOT_ALLOWED",
            "detectors[0].sources[0]",
            sensor.as_str()
        )
    );
    assert_eq!(detector_id, 7);
    assert_eq!(
        message,
        format!("{sensor:?} is not a time series generation policy of customer {POLICY_CUSTOMER}")
    );
}

#[test]
fn a_timeseries_detector_refuses_a_policy_of_another_shape() {
    let f = Detectors::new();
    let other = f.policies.assigned_policy(
        "other",
        &f.policies.generator,
        PolicyShape {
            slot_size: SlotSize::OneHour,
            ..PolicyShape::default()
        },
    );
    // Alone, the policy is of one shape with itself, but not the model's.
    let ((code, field, value, detector_id), message) =
        f.refused(&f.document(TIMESERIES_MODEL, &[other.to_string()], ""));
    assert_eq!(
        (code.as_str(), field.as_str(), value),
        (
            "SOURCES_INCOMPATIBLE",
            "detectors[0].sources[0]",
            other.to_string()
        )
    );
    assert_eq!(detector_id, 7);
    assert_eq!(
        message,
        format!(
            "time series generation policy {other} differs in slot_size from the time series \
             generation policies model {TIMESERIES_MODEL:?} was trained on"
        )
    );
}

#[test]
fn a_timeseries_detector_of_a_model_of_unknown_shape_is_refused() {
    let f = Detectors::new();
    let p1 = f.policies.assigned[0].to_string();
    let unknown =
        f.policies
            .assigned_policy("unknown", &f.policies.generator, PolicyShape::default());
    for (name, trained_sources) in [
        ("ts-empty", Vec::new()),
        (
            "ts-unresolved",
            vec![sensor_name("gen-a.example.com"), "9999".to_string()],
        ),
    ] {
        TestModel {
            instance: f.instance.clone(),
            kind: TIMESERIES_KIND,
            trained_sources,
            ..TestModel::new(name, POLICY_CUSTOMER)
        }
        .replace(&f.policies.store);
        // Even a policy of the shape every other source has is refused.
        let ((code, field, value, detector_id), message) =
            f.refused(&f.document(name, &[p1.clone(), unknown.to_string()], ""));
        assert_eq!(
            (code.as_str(), field.as_str(), value.as_str()),
            (
                "SOURCES_INCOMPATIBLE",
                "detectors[0].sources[0]",
                p1.as_str()
            ),
            "{name}"
        );
        assert_eq!(detector_id, 7);
        assert_eq!(
            message,
            format!(
                "none of the time series generation policies model {name:?} was trained on is \
                 stored, so the shape its sources must have is unknown"
            )
        );
    }
}

#[test]
fn a_timeseries_detector_whose_source_cannot_be_read_is_refused_with_the_error() {
    const NODES_TABLE: &str = "nodes";
    const BROKEN_HOST: &str = "gen-broken.example.com";

    let Detectors { policies, instance } = Detectors::new();
    let generator = insert_generator_node_with(
        &policies.store,
        BROKEN_HOST,
        POLICY_CUSTOMER,
        Some(generator_config(&policies.server_name)),
    );
    let source = policies.assigned_policy("broken", &generator, PolicyShape::default());
    // Every policy still reads, so the source is checked up to its
    // generator's applied Data Store, the record that does not read.
    let f = Detectors {
        policies: policies.with_undecodable_row(NODES_TABLE, BROKEN_HOST),
        instance,
    };
    let error = f
        .check(&f.document(TIMESERIES_MODEL, &[source.to_string()], ""))
        .expect_err("a source that cannot be read refuses the document");
    assert!(
        error
            .message
            .starts_with("cannot read time series generation policies: "),
        "{}",
        error.message
    );
}

#[test]
fn a_timeseries_detector_reads_one_data_store() {
    let f = Detectors::new();
    let elsewhere = f.policies.assigned_policy(
        "elsewhere",
        &f.policies.other_generator,
        PolicyShape::default(),
    );
    let sources = [f.policies.assigned[0].to_string(), elsewhere.to_string()];
    let ((code, field, _, detector_id), _) = f.refused(&f.document(TIMESERIES_MODEL, &sources, ""));
    assert_eq!(
        (code.as_str(), field.as_str()),
        (
            "SOURCES_INCOMPATIBLE",
            "detectors[0].data_store.server_name"
        )
    );
    assert_eq!(detector_id, 7);
}

#[test]
fn a_multidimension_detector_refuses_a_policy() {
    let f = Detectors::new();
    let p1 = f.policies.assigned[0].to_string();
    let ((code, field, value, _), _) =
        f.refused(&f.document(MULTIDIMENSION_MODEL, std::slice::from_ref(&p1), ""));
    assert_eq!(
        (code.as_str(), field.as_str(), value),
        ("SOURCE_NOT_ALLOWED", "detectors[0].sources[0]", p1)
    );
    f.check(&f.document(
        MULTIDIMENSION_MODEL,
        &[sensor_name("gen-a.example.com")],
        "",
    ))
    .unwrap();
}

// ---------------------------------------------------------------------------
// Detection model sections

/// A model of `http_url` version 1 trained with the `http_url` format.
const URL_MODEL: &str = "url-model";
/// A model stamped `http_url` version 0, an earlier version.
const URL_V0_MODEL: &str = "url-v0-model";
/// A custom model.
const CUSTOM_MODEL: &str = "custom-model";
/// A model of a catalog id with no current catalog entry.
const UNKNOWN_TYPE_MODEL: &str = "unknown-type-model";
/// A model of `http_url` whose trained definition has no `[csv]` format.
const NO_FORMAT_MODEL: &str = "no-format-model";
/// A model of `http_url` of another engine instance.
const ELSEWHERE_MODEL: &str = "elsewhere-model";
/// A stored label DB.
const LABEL_DB: &str = "HttpUriThreat";
/// The prefix of every path the sections of detector 0 are refused at.
const SECTIONS: &str = "detectors[0].detection_models";

/// A [`Detectors`] fixture whose instance also holds a model of each
/// clustering model type case, with a stored label DB [`LABEL_DB`].
fn sections_fixture() -> Detectors {
    let f = Detectors::new();
    let store = &f.policies.store;
    for (name, model_type, trained_definition) in [
        (URL_MODEL, http_url(1), HTTP_URL_CSV),
        (URL_V0_MODEL, http_url(0), HTTP_URL_CSV),
        (CUSTOM_MODEL, ClusteringModelTypeRef::Custom, HTTP_URL_CSV),
        (
            UNKNOWN_TYPE_MODEL,
            ClusteringModelTypeRef::Catalog {
                id: "no_such_type".to_string(),
                version: 1,
            },
            HTTP_URL_CSV,
        ),
        (NO_FORMAT_MODEL, http_url(1), "[model]\neps = 0.5\n"),
    ] {
        TestModel {
            instance: f.instance.clone(),
            clustering_model_type: model_type,
            trained_definition: trained_definition.to_string(),
            ..TestModel::new(name, POLICY_CUSTOMER)
        }
        .replace(store);
    }
    TestModel {
        clustering_model_type: http_url(1),
        trained_definition: HTTP_URL_CSV.to_string(),
        ..TestModel::new(ELSEWHERE_MODEL, POLICY_CUSTOMER)
    }
    .replace(store);
    insert_label_db(store, LABEL_DB);
    f
}

impl Detectors {
    /// Returns a document with one detector of `model` reading a sensor of
    /// the customer, followed by `sections`, header tables of its
    /// `detection_models`.
    fn with_sections(&self, model: &str, sections: &str) -> String {
        format!(
            "{}\n{sections}",
            self.document(model, &[sensor_name("gen-a.example.com")], "")
        )
    }
}

/// Returns a `label_db_match` section holding `columns`.
fn label_db_match(columns: &str) -> String {
    format!("[detectors.detection_models.label_db_match]\ncolumns = {columns}\n")
}

/// Returns a `label_db_match` section with the value `line`.
fn label_db_match_value(line: &str) -> String {
    format!("[detectors.detection_models.label_db_match]\n{line}\n")
}

/// Returns a `columns` list of one entry naming the stored label DB, with
/// `cells` after its `db`.
fn column(column_ids: &str, cells: &str) -> String {
    format!("[{{ column_ids = {column_ids}, db = \"{LABEL_DB}\"{cells} }}]")
}

#[test]
fn missing_sections_and_values_are_accepted() {
    let f = sections_fixture();
    for (model, sections) in [
        (URL_MODEL, String::new()),
        (URL_MODEL, "[detectors.detection_models]\n".to_string()),
        (CUSTOM_MODEL, "[detectors.detection_models]\n".to_string()),
        (CUSTOM_MODEL, String::new()),
        (
            URL_MODEL,
            label_db_match(&format!("[{{ column_ids = [15], db = \"{LABEL_DB}\" }}]")),
        ),
        (
            URL_MODEL,
            "[detectors.detection_models.far_outlier]\n".to_string(),
        ),
        (
            URL_MODEL,
            "[detectors.detection_models.label_db_match]\n\n\
             [detectors.detection_models.far_outlier]\nenabled = false\n"
                .to_string(),
        ),
        // An earlier version of the type allows what the current entry
        // allows.
        (
            URL_V0_MODEL,
            format!(
                "{}\n[detectors.detection_models.far_outlier]\n",
                label_db_match(&column("[0]", ""))
            ),
        ),
    ] {
        let text = f.with_sections(model, &sections);
        f.check(&text).expect(&text);
    }
    // An inline table is checked as a header table is.
    let inline = f.document(
        URL_MODEL,
        &[sensor_name("gen-a.example.com")],
        "detection_models = {}",
    );
    f.check(&inline).expect(&inline);
}

#[test]
fn values_at_their_bounds_are_accepted() {
    let f = sections_fixture();
    for line in [
        "event_range = 1",
        "event_range = 100",
        "min_events_ratio = 0",
        "min_events_ratio = 100",
        "enabled = false",
    ] {
        f.check(&f.with_sections(URL_MODEL, &label_db_match_value(line)))
            .expect(line);
    }
    for cells in [", min_score = 1.0", ", min_score = 0.001"] {
        f.check(&f.with_sections(URL_MODEL, &label_db_match(&column("[0, 15]", cells))))
            .expect(cells);
    }
}

/// Checks that `text` is refused with `code`, `field` and `value`, carrying
/// the detector id 7.
#[track_caller]
fn assert_refused(f: &Detectors, text: &str, code: &str, field: &str, value: &str) {
    let ((refused_code, refused_field, refused_value, detector_id), _) = f.refused(text);
    assert_eq!(
        (
            refused_code.as_str(),
            refused_field.as_str(),
            refused_value.as_str()
        ),
        (code, field, value),
        "{text}"
    );
    assert_eq!(detector_id, Value::from(7), "{text}");
}

#[test]
#[allow(clippy::too_many_lines)] // one case per refusal row
fn every_section_refusal_has_its_code_field_and_value() {
    let f = sections_fixture();
    let entry = |cell: &str| format!("{SECTIONS}.label_db_match.columns[0].{cell}");
    let value_path = |key: &str| format!("{SECTIONS}.label_db_match.{key}");
    let cases: Vec<(String, (&str, String, &str))> = vec![
        // INVALID_DOCUMENT, with the value
        (
            "[detectors.detection_models]\nlabel_db_match = 5\n".to_string(),
            (
                "INVALID_DOCUMENT",
                format!("{SECTIONS}.label_db_match"),
                "5",
            ),
        ),
        (
            label_db_match("[5]"),
            (
                "INVALID_DOCUMENT",
                format!("{SECTIONS}.label_db_match.columns[0]"),
                "5",
            ),
        ),
        (
            "[detectors.detection_models.far_outlier]\nenabled = 1\n".to_string(),
            (
                "INVALID_DOCUMENT",
                format!("{SECTIONS}.far_outlier.enabled"),
                "1",
            ),
        ),
        (
            label_db_match_value("enabled = 1"),
            ("INVALID_DOCUMENT", value_path("enabled"), "1"),
        ),
        (
            label_db_match_value("event_range = \"x\""),
            ("INVALID_DOCUMENT", value_path("event_range"), "\"x\""),
        ),
        (
            label_db_match("[{ column_ids = \"x\", db = \"d\" }]"),
            ("INVALID_DOCUMENT", entry("column_ids"), "\"x\""),
        ),
        (
            label_db_match("[{ column_ids = [1], db = 1 }]"),
            ("INVALID_DOCUMENT", entry("db"), "1"),
        ),
        (
            label_db_match(&column("[1]", ", min_score = \"high\"")),
            ("INVALID_DOCUMENT", entry("min_score"), "\"high\""),
        ),
        // UNKNOWN_FIELD, with no value
        (
            "[detectors.detection_models.foo]\n".to_string(),
            ("UNKNOWN_FIELD", format!("{SECTIONS}.foo"), ""),
        ),
        (
            "[detectors.detection_models.port_scan]\nenabled = true\n".to_string(),
            ("UNKNOWN_FIELD", format!("{SECTIONS}.port_scan"), ""),
        ),
        (
            label_db_match_value("protocol = \"http\""),
            ("UNKNOWN_FIELD", value_path("protocol"), ""),
        ),
        (
            label_db_match(&column("[1]", ", path = \"/x\"")),
            ("UNKNOWN_FIELD", entry("path"), ""),
        ),
        // FIELD_NOT_ALLOWED, with no value
        (
            label_db_match(&format!("[{{ db = \"{LABEL_DB}\" }}]")),
            ("FIELD_NOT_ALLOWED", entry("column_ids"), ""),
        ),
        (
            label_db_match("[{ column_ids = [1] }]"),
            ("FIELD_NOT_ALLOWED", entry("db"), ""),
        ),
        // BOUND_VIOLATED, with the value
        (
            label_db_match_value("event_range = 0"),
            ("BOUND_VIOLATED", value_path("event_range"), "0"),
        ),
        (
            label_db_match_value("event_range = 101"),
            ("BOUND_VIOLATED", value_path("event_range"), "101"),
        ),
        (
            label_db_match_value("min_events_ratio = -1"),
            ("BOUND_VIOLATED", value_path("min_events_ratio"), "-1"),
        ),
        (
            label_db_match_value("min_events_ratio = 101"),
            ("BOUND_VIOLATED", value_path("min_events_ratio"), "101"),
        ),
        (
            label_db_match(&column("[1]", ", min_score = 0.0")),
            ("BOUND_VIOLATED", entry("min_score"), "0.0"),
        ),
        (
            label_db_match(&column("[1]", ", min_score = 1.5")),
            ("BOUND_VIOLATED", entry("min_score"), "1.5"),
        ),
        (
            label_db_match(&column("[]", "")),
            ("BOUND_VIOLATED", entry("column_ids"), "[]"),
        ),
        (
            label_db_match("[{ column_ids = [1], db = \"\" }]"),
            ("BOUND_VIOLATED", entry("db"), "\"\""),
        ),
        (
            label_db_match(&column("[1, -1]", "")),
            ("BOUND_VIOLATED", entry("column_ids"), "-1"),
        ),
        // The column ids against the model's format, and the label DB.
        (
            label_db_match(&column("[1, 33]", "")),
            ("BOUND_VIOLATED", entry("column_ids"), "33"),
        ),
        (
            label_db_match("[{ column_ids = [1], db = \"Missing\" }]"),
            ("NOT_FOUND", entry("db"), "Missing"),
        ),
    ];
    for (sections, (code, field, value)) in cases {
        assert_refused(
            &f,
            &f.with_sections(URL_MODEL, &sections),
            code,
            &field,
            value,
        );
    }
    // The last index of the format is accepted.
    assert_eq!(format_len(HTTP_URL_CSV), 33);
    f.check(&f.with_sections(URL_MODEL, &label_db_match(&column("[32]", ""))))
        .unwrap();
}

#[test]
fn a_section_the_model_type_does_not_allow_is_refused() {
    let f = sections_fixture();
    for (model, section) in [
        (CUSTOM_MODEL, "far_outlier"),
        (CUSTOM_MODEL, "label_db_match"),
        (UNKNOWN_TYPE_MODEL, "far_outlier"),
        (UNKNOWN_TYPE_MODEL, "label_db_match"),
    ] {
        let text = f.with_sections(
            model,
            &format!("[detectors.detection_models.{section}]\nenabled = true\n"),
        );
        assert_refused(
            &f,
            &text,
            "FIELD_NOT_ALLOWED",
            &format!("{SECTIONS}.{section}"),
            "",
        );
    }
}

#[test]
fn a_model_without_a_format_accepts_no_column_id() {
    let f = sections_fixture();
    assert_refused(
        &f,
        &f.with_sections(NO_FORMAT_MODEL, &label_db_match(&column("[0]", ""))),
        "BOUND_VIOLATED",
        &format!("{SECTIONS}.label_db_match.columns[0].column_ids"),
        "0",
    );
    f.check(&f.with_sections(NO_FORMAT_MODEL, &label_db_match("[]")))
        .unwrap();
}

#[test]
fn column_ids_come_before_the_label_db_and_entries_in_order() {
    let f = sections_fixture();
    let ((code, field, _, _), _) = f.refused(&f.with_sections(
        URL_MODEL,
        &label_db_match("[{ column_ids = [40], db = \"Missing\" }]"),
    ));
    assert_eq!(
        (code.as_str(), field.as_str()),
        (
            "BOUND_VIOLATED",
            "detectors[0].detection_models.label_db_match.columns[0].column_ids"
        )
    );
    let ((code, field, _, _), _) = f.refused(&f.with_sections(
        URL_MODEL,
        &label_db_match(&format!(
            "[{{ column_ids = [1], db = \"Missing\" }}, {{ column_ids = [40], db = \"{LABEL_DB}\" }}]"
        )),
    ));
    assert_eq!(
        (code.as_str(), field.as_str()),
        (
            "NOT_FOUND",
            "detectors[0].detection_models.label_db_match.columns[0].db"
        )
    );
}

#[test]
fn sections_are_checked_after_the_model_and_before_the_sources() {
    let f = sections_fixture();
    // A model of another instance is refused as such, whatever its sections.
    let ((code, field, _, _), _) = f.refused(&f.with_sections(
        ELSEWHERE_MODEL,
        "[detectors.detection_models.far_outlier]\n",
    ));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("MODEL_NOT_OF_INSTANCE", "detectors[0].model")
    );
    // A section is refused before a source of another customer.
    let text = format!(
        "{}\n[detectors.detection_models.foo]\n",
        f.document(URL_MODEL, &["piglet.nobody.example.com".to_string()], "")
    );
    let ((code, field, _, _), _) = f.refused(&text);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("UNKNOWN_FIELD", "detectors[0].detection_models.foo")
    );
}

#[test]
fn a_later_detector_section_waits_for_the_checks_to_reach_it() {
    let f = sections_fixture();
    let first = f.with_sections(URL_MODEL, "");
    let second = |model: &str, sections: &str| {
        f.with_sections(model, sections)
            .replace("id = 7", "id = 8")
            .replace("period = \"15m\"", "period = \"30m\"")
    };
    // The first detector's own refusal comes before the second's section.
    let unknown_indicator = first.replace(
        "timeseries = false\n",
        "timeseries = false\nsuspicious_tokens = \"nope\"\n",
    );
    let text = format!(
        "{unknown_indicator}{}",
        second(CUSTOM_MODEL, "[detectors.detection_models.far_outlier]\n")
    );
    let ((code, field, _, detector_id), _) = f.refused(&text);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("INDICATOR_NOT_ALLOWED", "detectors[0].suspicious_tokens")
    );
    assert_eq!(detector_id, Value::from(7));
    // The second detector's model of another instance is refused as such,
    // not by the section the completion refused for want of its type.
    let text = format!(
        "{first}{}",
        second(
            ELSEWHERE_MODEL,
            "[detectors.detection_models.far_outlier]\n"
        )
    );
    let ((code, field, _, detector_id), _) = f.refused(&text);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("MODEL_NOT_OF_INSTANCE", "detectors[1].model")
    );
    assert_eq!(detector_id, Value::from(8));
    // Once reached, the second detector's section is refused there.
    let text = format!(
        "{first}{}",
        second(CUSTOM_MODEL, "[detectors.detection_models.far_outlier]\n")
    );
    let ((code, field, value, detector_id), _) = f.refused(&text);
    assert_eq!(
        (code.as_str(), field.as_str(), value.as_str()),
        (
            "FIELD_NOT_ALLOWED",
            "detectors[1].detection_models.far_outlier",
            ""
        )
    );
    assert_eq!(detector_id, Value::from(8));
}

#[test]
fn detectors_not_written_as_an_array_of_tables_are_refused() {
    let f = sections_fixture();
    // The database write's completion refuses such a document as a whole and
    // checks none of its sections, so the checker refuses it before any
    // section could slip past a draft save, as the completion refusal mapper
    // refuses it on Apply.
    let text = |model: &str, sections: &str| {
        format!(
            "detectors = [{{ id = 7, enabled = true, model = \"{model}\", sources = \
             [{source:?}], period = \"15m\", start = \"2026-10-21T00:00:00Z\", batch_size = \
             1000, read_lag = \"1m\", stats = false, timeseries = false, data_store = {{ \
             address = \"{OWN_ADDRESS}\", server_name = \"{}\" }}{sections} }}]\n",
            f.policies.server_name,
            source = sensor_name("gen-a.example.com"),
        )
    };
    for document in [
        text(URL_MODEL, ""),
        text(
            URL_MODEL,
            ", detection_models = { label_db_match = { columns = [] } }",
        ),
        text(CUSTOM_MODEL, ", detection_models = { far_outlier = {} }"),
        text(URL_MODEL, ", detection_models = { foo = {} }"),
        text(
            URL_MODEL,
            ", detection_models = { far_outlier = { enabled = 1 } }",
        ),
    ] {
        for (code, field, value, detector_id) in [
            refused(&document),
            parts(&f.check(&document).expect_err(&document)),
        ] {
            assert_eq!(
                (code.as_str(), field.as_str(), value.as_str()),
                ("INVALID_DOCUMENT", "", ""),
                "{document}"
            );
            assert_eq!(detector_id, Value::Null, "{document}");
        }
    }
    // An empty inline array holds no detector, which the completion takes.
    f.check("detectors = []\n").unwrap();
}
