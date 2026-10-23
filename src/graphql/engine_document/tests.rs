use serde_json::Value;

use super::*;

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
max_event_id_num = 25
suspicious_tokens = "indicator-name"
stats = false
timeseries = true

[detectors.data_store]
address = "[::1]:38371"
server_name = "001.giganto.node1.example.com"

[detectors.labeldb]
event_range = 30
min_events_ratio = 10
generate_unlabeled_from_outliers = true
limit_unlabeled_from_outliers = 5
columns = [
  { column_ids = [15], db = "HttpUriThreat", min_score = 0.7 },
  { column_ids = [1, 2], db = "Other" },
]

[[detectors]]
id = -2
enabled = true
model = "dns-node2"
sources = ["piglet.node2.example.com"]
period = "1h 30m"
start = "2026-10-21T00:00:00Z"
batch_size = 1

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
    let error = EngineDocument::parse_and_validate(text).expect_err(text);
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
    assert_eq!(detector.read_lag, None);
    assert_eq!(detector.max_event_id_num, None);
    assert_eq!(detector.suspicious_tokens, None);
    assert_eq!(detector.stats, None);
    assert_eq!(detector.timeseries, None);
    assert_eq!(detector.labeldb, None);
    let without_cpus = without(VALID, "cpus");
    assert_eq!(
        EngineDocument::parse_and_validate(&without_cpus)
            .unwrap()
            .cpus,
        None
    );

    // Each optional setting of a present label database, with its columns.
    let full = EngineDocument::parse_and_validate(FULL).unwrap().detectors[0]
        .labeldb
        .clone()
        .unwrap();
    for (key, expected) in [
        (
            "event_range",
            LabelDb {
                event_range: None,
                ..full.clone()
            },
        ),
        (
            "min_events_ratio",
            LabelDb {
                min_events_ratio: None,
                ..full.clone()
            },
        ),
        (
            "generate_unlabeled_from_outliers",
            LabelDb {
                generate_unlabeled_from_outliers: None,
                ..full.clone()
            },
        ),
        (
            "limit_unlabeled_from_outliers",
            LabelDb {
                limit_unlabeled_from_outliers: None,
                ..full.clone()
            },
        ),
    ] {
        let document = EngineDocument::parse_and_validate(&without(FULL, key)).expect(key);
        assert_eq!(document.detectors[0].labeldb, Some(expected), "{key}");
    }
}

#[test]
fn every_key_of_the_schema_parses() {
    let document = EngineDocument::parse_and_validate(FULL).unwrap();
    assert_eq!(document.cpus, Some(64));
    let [first, second] = &document.detectors[..] else {
        panic!("two detectors");
    };
    assert!(!first.enabled);
    assert_eq!(
        first.read_lag.as_ref().map(|lag| lag.duration),
        Some(Duration::from_secs(30))
    );
    let labeldb = first.labeldb.as_ref().unwrap();
    assert_eq!(labeldb.columns[0].min_score, Some(0.7));
    assert_eq!(labeldb.columns[1].min_score, None);
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
    let no_columns = FULL.replace(
        "columns = [\n  { column_ids = [15], db = \"HttpUriThreat\", min_score = 0.7 },\n  { \
         column_ids = [1, 2], db = \"Other\" },\n]\n",
        "",
    );
    assert_eq!(
        code_and_field(&no_columns),
        (
            "INVALID_DOCUMENT".to_string(),
            "detectors[0].labeldb.columns".to_string()
        )
    );
    let no_column_ids = FULL.replace("{ column_ids = [1, 2], db", "{ db");
    assert_eq!(
        code_and_field(&no_column_ids),
        (
            "INVALID_DOCUMENT".to_string(),
            "detectors[0].labeldb.columns[1].column_ids".to_string()
        )
    );
    let no_db = FULL.replace(", db = \"Other\"", "");
    assert_eq!(
        code_and_field(&no_db),
        (
            "INVALID_DOCUMENT".to_string(),
            "detectors[0].labeldb.columns[1].db".to_string()
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
            FULL.replace("event_range = 30", "event_range = 30\nprotocol = \"http\""),
            "detectors[0].labeldb.protocol",
            "protocol",
        ),
        (
            FULL.replace("db = \"Other\" }", "db = \"Other\", path = \"/x\" }"),
            "detectors[0].labeldb.columns[1].path",
            "path",
        ),
        (format!("{VALID}\n[auth]\nkey = 1\n"), "auth", "auth"),
    ] {
        let (code, refused_field, value, _) = refused(&text);
        assert_eq!(code, "UNKNOWN_FIELD", "{text}");
        assert_eq!(refused_field, field, "{text}");
        assert_eq!(value, key, "{text}");
    }
    let (_, _, _, detector_id) = refused(&with(VALID, "event_type", "event_type = \"http\""));
    assert_eq!(detector_id, Value::from(1));
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
        (
            "max_event_id_num",
            "max_event_id_num = 4294967296",
            "detectors[0].max_event_id_num",
        ),
        ("stats", "stats = \"no\"", "detectors[0].stats"),
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
    for (replaced, by, field) in [
        (
            "event_range = 30",
            "event_range = -30",
            "detectors[0].labeldb.event_range",
        ),
        (
            "min_events_ratio = 10",
            "min_events_ratio = 1.5",
            "detectors[0].labeldb.min_events_ratio",
        ),
        (
            "limit_unlabeled_from_outliers = 5",
            "limit_unlabeled_from_outliers = -5",
            "detectors[0].labeldb.limit_unlabeled_from_outliers",
        ),
        (
            "generate_unlabeled_from_outliers = true",
            "generate_unlabeled_from_outliers = 1",
            "detectors[0].labeldb.generate_unlabeled_from_outliers",
        ),
        (
            "column_ids = [15]",
            "column_ids = [-15]",
            "detectors[0].labeldb.columns[0].column_ids[0]",
        ),
        (
            "min_score = 0.7",
            "min_score = \"high\"",
            "detectors[0].labeldb.columns[0].min_score",
        ),
        (
            "min_score = 0.7",
            "min_score = 1e100",
            "detectors[0].labeldb.columns[0].min_score",
        ),
        (
            "min_score = 0.7",
            "min_score = -1e39",
            "detectors[0].labeldb.columns[0].min_score",
        ),
    ] {
        let (code, refused_field, _, _) = refused(&FULL.replace(replaced, by));
        assert_eq!(code, "INVALID_DOCUMENT", "{by}");
        assert_eq!(refused_field, field, "{by}");
    }
}

#[test]
fn a_min_score_up_to_the_largest_f32_is_accepted() {
    for (by, expected) in [
        ("min_score = 3.4028235e38", f32::MAX),
        ("min_score = -3.4028235e38", f32::MIN),
        ("min_score = 1", 1.0),
    ] {
        let document =
            EngineDocument::parse_and_validate(&FULL.replace("min_score = 0.7", by)).expect(by);
        let labeldb = document.detectors[0].labeldb.as_ref().unwrap();
        assert_eq!(labeldb.columns[0].min_score, Some(expected), "{by}");
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
        (
            "max_event_id_num",
            "max_event_id_num = 100",
            "max_event_id_num = 101",
            "detectors[0].max_event_id_num",
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
             \"2026-10-21T00:00:00Z\"\nbatch_size = 1\n\n[detectors.data_store]\naddress = \
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
