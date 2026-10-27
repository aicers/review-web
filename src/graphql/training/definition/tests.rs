use std::net::IpAddr;

use review_database::{SamplingInterval, SamplingKind, SamplingPeriod};
use serde_json::Value;

use super::*;
use crate::graphql::sampling_test_support::{
    OTHER_POLICY_CUSTOMER, OWN_ADDRESS, POLICY_CUSTOMER, PolicyFixture, PolicyShape,
    generator_config, insert_assigned_policy, insert_policy, sensor_name, set_generator_config,
    timeseries_definition,
};

const VALID: &str = r#"
event_kind = "http"
method = "multidimension"
sources = ["piglet.a.example.com"]
window_start = "2026-10-14T00:00:00Z"
window_end = "2026-10-21T00:00:00Z"

[data_store]
address = "10.0.0.5:38371"
server_name = "001.giganto.store.example.com"

[csv]
format = [{ data_type = "utf8", weight = 1.0, name = "host" }]
"#;

const PREFIX: &str = r#"
event_kind = "log"
method = "prefix"
sources = ["reproduce.a.example.com"]
window_start = "2026-10-14T00:00:00+09:00"
window_end = "2026-10-21T00:00:00+09:00"

[data_store]
address = "10.0.0.5:38371"
server_name = "001.giganto.store.example.com"
"#;

const TIMESERIES: &str = r#"
event_kind = "timeseries"
method = "timeseries"
sources = ["3", "5"]
window_start = "2026-10-14T00:00:00Z"
window_end = "2026-10-21T00:00:00Z"

[data_store]
address = "10.0.0.5:38371"
server_name = "001.giganto.store.example.com"
"#;

/// Returns `text` with the line starting with `key =` replaced by `line`, or
/// `line` inserted before the first table when no such line exists.
fn with(text: &str, key: &str, line: &str) -> String {
    let prefix = format!("{key} =");
    if text.lines().any(|l| l.starts_with(&prefix)) {
        text.lines()
            .map(|l| if l.starts_with(&prefix) { line } else { l })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        text.replacen("\n[data_store]", &format!("{line}\n\n[data_store]"), 1)
    }
}

/// Returns the code, `field` and `value` of the refusal of `text`.
fn refused(text: &str) -> (String, String, String) {
    parts(&TrainingDocument::parse_and_validate(text).expect_err(text))
}

/// Returns the code, `field` and `value` of `error`, a refusal.
fn parts(error: &async_graphql::Error) -> (String, String, String) {
    let extensions =
        serde_json::to_value(error.extensions.as_ref().expect("a refusal has extensions")).unwrap();
    let get = |key: &str| match &extensions[key] {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    (get("code"), get("field"), get("value"))
}

fn code(text: &str) -> String {
    refused(text).0
}

#[test]
fn valid_definitions_parse() {
    let document = TrainingDocument::parse_and_validate(VALID).unwrap();
    assert_eq!(document.method, Method::Multidimension);
    assert_eq!(document.sources, ["piglet.a.example.com"]);
    let document = TrainingDocument::parse_and_validate(PREFIX).unwrap();
    assert_eq!(document.method, Method::Prefix);
}

#[test]
fn every_optional_key_of_the_schema_parses() {
    let text = r#"
event_kind = "conn"
method = "multidimension"
sources = ["piglet.a.example.com", "piglet.b.example.com"]
window_start = "2026-10-14T00:00:00Z"
window_end = "2026-10-21T00:00:00Z"
batch_size = 1000000
algorithm = "hdbscan"
eps = 2
min_token_length = 3
max_token_length = 10
max_data_len = 30
long_pattern_len = 16000
precision = -2
numbers_of_top_n = [30, 30]
max_event_id_num = 25
suspicious_tokens = "indicator"

[data_store]
address = "[::1]:38371"
server_name = "001.giganto.store.example.com"

[csv]
reader = { delimiter = 9, quote = 0 }
format = [
  { data_type = "datetime", weight = 0.0, name = "time", format = "%s" },
  { data_type = "ipaddr", weight = 1.5 },
]
time_intervals = [60]
time_column = 0
count_columns = [0]
prefix_columns = [14, 15]
"#;
    let document = TrainingDocument::parse_and_validate(text).unwrap();
    assert_eq!(document.eps, Some(2.0));
    assert_eq!(document.algorithm, Some(Algorithm::Hdbscan));
    let reparsed = TrainingDocument::parse_and_validate(&document.to_text().unwrap()).unwrap();
    assert_eq!(reparsed, document);
}

#[test]
fn a_serialization_keeps_the_window_text_and_drops_comments() {
    let text = format!("# trained for piglet.secret.example.com\n{PREFIX}");
    let document = TrainingDocument::parse_and_validate(&text).unwrap();
    let serialized = document.to_text().unwrap();
    assert!(!serialized.contains('#'), "{serialized}");
    assert!(!serialized.contains("secret"), "{serialized}");
    assert!(
        serialized.contains("2026-10-14T00:00:00+09:00"),
        "{serialized}"
    );
}

#[test]
fn syntax_errors_and_missing_keys_are_invalid() {
    assert_eq!(code("event_kind = "), "INVALID_DOCUMENT");
    let (code, field, _) = refused(&VALID.replace("window_end = \"2026-10-21T00:00:00Z\"\n", ""));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("INVALID_DOCUMENT", "window_end")
    );
    let (code, field, _) =
        refused(&VALID.replace("server_name = \"001.giganto.store.example.com\"\n", ""));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("INVALID_DOCUMENT", "data_store.server_name")
    );
}

#[test]
fn unknown_keys_are_refused_at_every_level() {
    for (text, field) in [
        (with(VALID, "name", "name = \"model\""), "name"),
        (
            with(VALID, "export_path", "export_path = \"/tmp\""),
            "export_path",
        ),
        (
            VALID.replace("server_name =", "log_path = \"/x\"\nserver_name ="),
            "data_store.log_path",
        ),
        (
            VALID.replace("[csv]\n", "[csv]\nlocal = \"/x\"\n"),
            "csv.local",
        ),
        (
            VALID.replace("name = \"host\" }", "name = \"host\", path = \"/x\" }"),
            "csv.format[0].path",
        ),
        (format!("{VALID}\n[auth]\nkey = 1\n"), "auth"),
    ] {
        let (code, refused_field, _) = refused(&text);
        assert_eq!(code, "UNKNOWN_FIELD", "{text}");
        assert_eq!(refused_field, field, "{text}");
    }
}

#[test]
fn values_outside_their_type_are_invalid() {
    for (key, line, field) in [
        ("batch_size", "batch_size = -1", "batch_size"),
        ("batch_size", "batch_size = 1.5", "batch_size"),
        ("eps", "eps = \"two\"", "eps"),
        ("precision", "precision = 2147483648", "precision"),
        (
            "max_event_id_num",
            "max_event_id_num = -3",
            "max_event_id_num",
        ),
        (
            "numbers_of_top_n",
            "numbers_of_top_n = [1, -1]",
            "numbers_of_top_n[1]",
        ),
        ("algorithm", "algorithm = \"kmeans\"", "algorithm"),
        ("method", "method = \"other\"", "method"),
        ("sources", "sources = \"piglet.a.example.com\"", "sources"),
        (
            "window_start",
            "window_start = 2026-10-14T00:00:00Z",
            "window_start",
        ),
    ] {
        let (code, refused_field, _) = refused(&with(VALID, key, line));
        assert_eq!(code, "INVALID_DOCUMENT", "{line}");
        assert_eq!(refused_field, field, "{line}");
    }
    for (replaced, by, field) in [
        ("10.0.0.5:38371", "10.0.0.5", "data_store.address"),
        (
            "format = [",
            "time_intervals = [60, -1]\nformat = [",
            "csv.time_intervals[1]",
        ),
        (
            "format = [",
            "reader = { delimiter = 300, quote = 0 }\nformat = [",
            "csv.reader.delimiter",
        ),
        (
            "format = [",
            "reader = { delimiter = 9 }\nformat = [",
            "csv.reader.quote",
        ),
        (
            "data_type = \"utf8\"",
            "data_type = \"text\"",
            "csv.format[0].data_type",
        ),
        (
            "format = [",
            "time_column = -1\nformat = [",
            "csv.time_column",
        ),
        (
            "format = [",
            "count_columns = [1.5]\nformat = [",
            "csv.count_columns[0]",
        ),
    ] {
        let (code, refused_field, _) = refused(&VALID.replace(replaced, by));
        assert_eq!(code, "INVALID_DOCUMENT", "{by}");
        assert_eq!(refused_field, field, "{by}");
    }
}

#[test]
fn a_format_entry_needs_a_weight() {
    let (code, field, _) = refused(&VALID.replace(", weight = 1.0", ""));
    assert_eq!(code, "INVALID_DOCUMENT");
    assert_eq!(field, "csv.format[0].weight");
}

#[test]
fn timeseries_takes_its_event_kind_and_no_csv() {
    let document = TrainingDocument::parse_and_validate(TIMESERIES).unwrap();
    assert_eq!(document.method, Method::Timeseries);
    assert_eq!(document.sources, ["3", "5"]);
    let reparsed = TrainingDocument::parse_and_validate(&document.to_text().unwrap()).unwrap();
    assert_eq!(reparsed, document);

    for kind in ["conn", "log", "periodic_time_series", ""] {
        let text = with(
            TIMESERIES,
            "event_kind",
            &format!("event_kind = \"{kind}\""),
        );
        let (code, field, value) = refused(&text);
        assert_eq!(code, "EVENT_KIND_NOT_ALLOWED", "{kind}");
        assert_eq!((field.as_str(), value.as_str()), ("event_kind", kind));
    }

    let extra = format!("{TIMESERIES}\n[csv]\ntime_column = 0\n");
    let (code, field, _) = refused(&extra);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("FIELD_NOT_ALLOWED", "csv")
    );
}

#[test]
fn timeseries_refuses_each_prefix_only_field() {
    for (field, line) in [
        ("min_token_length", "min_token_length = 3"),
        ("max_token_length", "max_token_length = 10"),
        ("max_data_len", "max_data_len = 30"),
        ("long_pattern_len", "long_pattern_len = 16000"),
        ("suspicious_tokens", "suspicious_tokens = \"indicator\""),
    ] {
        let (code, refused_field, _) = refused(&with(TIMESERIES, field, line));
        assert_eq!(
            (code.as_str(), refused_field.as_str()),
            ("FIELD_NOT_ALLOWED", field)
        );
    }
    // The fields every method reads are taken.
    for line in [
        "batch_size = 1000",
        "algorithm = \"dbscan\"",
        "eps = 0.5",
        "precision = 2",
        "numbers_of_top_n = [3]",
        "max_event_id_num = 10",
    ] {
        let key = line.split(" =").next().unwrap();
        TrainingDocument::parse_and_validate(&with(TIMESERIES, key, line)).expect(line);
    }
}

#[test]
fn multidimension_takes_only_column_structured_kinds() {
    for kind in MULTIDIMENSION_EVENT_KINDS {
        let text = with(VALID, "event_kind", &format!("event_kind = \"{kind}\""));
        TrainingDocument::parse_and_validate(&text).expect(kind);
    }
    for kind in [
        "log",
        "statistics",
        "op_log",
        "periodic_time_series",
        "dns_event",
        "",
    ] {
        let text = with(VALID, "event_kind", &format!("event_kind = \"{kind}\""));
        let (code, field, value) = refused(&text);
        assert_eq!(code, "EVENT_KIND_NOT_ALLOWED", "{kind}");
        assert_eq!((field.as_str(), value.as_str()), ("event_kind", kind));
    }
}

#[test]
fn prefix_takes_only_log_kinds() {
    for kind in ["log", "syslog", "apache-access"] {
        let text = with(PREFIX, "event_kind", &format!("event_kind = \"{kind}\""));
        TrainingDocument::parse_and_validate(&text).expect(kind);
    }
    for kind in NAMED_EVENT_KINDS.iter().copied().chain([""]) {
        let text = with(PREFIX, "event_kind", &format!("event_kind = \"{kind}\""));
        assert_eq!(code(&text), "EVENT_KIND_NOT_ALLOWED", "{kind}");
    }
    for kind in ["dce rpc", "dns_event", "timeseries"] {
        assert!(NAMED_EVENT_KINDS.contains(&kind));
    }
}

#[test]
fn csv_is_required_for_multidimension_and_refused_for_prefix() {
    let missing = VALID
        .split("\n[csv]")
        .next()
        .expect("the text has a [csv] table")
        .to_string();
    let (code, field, _) = refused(&missing);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("FIELD_NOT_ALLOWED", "csv")
    );
    let extra = format!("{PREFIX}\n[csv]\ntime_column = 0\n");
    let (code, field, _) = refused(&extra);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("FIELD_NOT_ALLOWED", "csv")
    );
}

#[test]
fn sources_must_be_listed_once_each() {
    let (code, field, _) = refused(&with(VALID, "sources", "sources = []"));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("INVALID_DOCUMENT", "sources")
    );
    let (code, field, value) = refused(&with(
        VALID,
        "sources",
        "sources = [\"piglet.a.example.com\", \"piglet.b.example.com\", \"piglet.a.example.com\"]",
    ));
    assert_eq!(code, "DUPLICATE_ENTRY");
    assert_eq!(field, "sources[2]");
    assert_eq!(value, "piglet.a.example.com");
}

#[test]
fn windows_must_be_rfc3339_with_an_offset() {
    for line in [
        "window_start = \"2026-10-14T00:00:00\"",
        "window_start = \"2026-10-14\"",
        "window_start = \"yesterday\"",
    ] {
        let (code, field, _) = refused(&with(VALID, "window_start", line));
        assert_eq!(
            (code.as_str(), field.as_str()),
            ("INVALID_DOCUMENT", "window_start")
        );
    }
}

#[test]
fn bounds_are_accepted_at_their_limit_and_refused_past_it() {
    let at_limit = [
        ("batch_size", "batch_size = 5000000"),
        ("max_event_id_num", "max_event_id_num = 100"),
        ("max_token_length", "max_token_length = 6"),
        ("window_end", "window_end = \"2027-01-12T00:00:00Z\""),
    ];
    for (key, line) in at_limit {
        TrainingDocument::parse_and_validate(&with(VALID, key, line)).expect(line);
    }
    let with_min = with(VALID, "min_token_length", "min_token_length = 5");
    TrainingDocument::parse_and_validate(&with(
        &with_min,
        "max_token_length",
        "max_token_length = 10",
    ))
    .unwrap();

    let past_limit = [
        ("batch_size", "batch_size = 5000001", "batch_size"),
        (
            "max_event_id_num",
            "max_event_id_num = 101",
            "max_event_id_num",
        ),
        (
            "max_token_length",
            "max_token_length = 5",
            "max_token_length",
        ),
        (
            "window_end",
            "window_end = \"2027-01-12T00:00:01Z\"",
            "window_end",
        ),
        (
            "window_end",
            "window_end = \"2026-10-14T00:00:00Z\"",
            "window_end",
        ),
        (
            "window_end",
            "window_end = \"2026-10-13T00:00:00Z\"",
            "window_end",
        ),
    ];
    for (key, line, field) in past_limit {
        let (code, refused_field, _) = refused(&with(VALID, key, line));
        assert_eq!(code, "BOUND_VIOLATED", "{line}");
        assert_eq!(refused_field, field, "{line}");
    }
    let (code, field, _) = refused(&with(&with_min, "max_token_length", "max_token_length = 9"));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("BOUND_VIOLATED", "max_token_length")
    );
    let huge = with(
        VALID,
        "min_token_length",
        &format!("min_token_length = {}", i64::MAX),
    );
    assert_eq!(
        refused(&with(&huge, "max_token_length", "max_token_length = 1")).0,
        "BOUND_VIOLATED"
    );
}

#[test]
fn sources_of_reads_a_definition_text() {
    assert_eq!(sources_of(VALID), ["piglet.a.example.com"]);
    assert_eq!(sources_of(""), Vec::<String>::new());
    assert_eq!(sources_of("not toml ="), Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// The timeseries source rule

const A: u32 = POLICY_CUSTOMER;
const B: u32 = OTHER_POLICY_CUSTOMER;

impl PolicyFixture {
    /// Checks `text` as an insert of customer A by a Security Administrator
    /// does.
    fn check(&self, text: &str) -> Result<()> {
        let addrs = ["10.0.0.5".parse::<IpAddr>().unwrap()];
        TrainingDocument::parse_and_validate(text)?.check_stored(
            &self.store,
            A,
            &addrs,
            &HashSet::new(),
            ShapeReference::FirstSource,
            false,
        )
    }

    /// Returns the code, `field` and `value` of the refusal of `text`, and
    /// its message.
    fn refused(&self, text: &str) -> ((String, String, String), String) {
        let error = self.check(text).expect_err(text);
        (parts(&error), error.message)
    }
}

#[test]
fn assigned_policies_of_one_shape_and_data_store_are_accepted() {
    let f = PolicyFixture::new();
    f.check(&f.definition(&f.assigned)).unwrap();
}

#[test]
fn a_source_must_be_an_assigned_policy_of_the_customer() {
    let f = PolicyFixture::new();
    let [p1, _] = f.assigned;
    let policy_b =
        insert_assigned_policy(&f.store, "of-b", B, &f.generator_b, PolicyShape::default());
    let unassigned = insert_policy(&f.store, "unassigned", A, &sensor_name("gen-a.example.com"));
    for (source, message) in [
        (
            policy_b.to_string(),
            format!("\"{policy_b}\" is not a sampling policy of customer {A}"),
        ),
        (
            "999".to_string(),
            format!("\"999\" is not a sampling policy of customer {A}"),
        ),
        (
            unassigned.to_string(),
            format!("sampling policy {unassigned} has no assignee"),
        ),
        (
            sensor_name("gen-a.example.com"),
            format!(
                "\"{}\" is not a sampling policy of customer {A}",
                sensor_name("gen-a.example.com")
            ),
        ),
        (
            format!("0{p1}"),
            format!("\"0{p1}\" is not a sampling policy of customer {A}"),
        ),
    ] {
        let text = f
            .definition(&[p1])
            .replace(&format!("[\"{p1}\"]"), &format!("[\"{p1}\", {source:?}]"));
        let ((code, field, value), refused_message) = f.refused(&text);
        assert_eq!(
            (code.as_str(), field.as_str(), value.as_str()),
            ("SOURCE_NOT_ALLOWED", "sources[1]", source.as_str())
        );
        assert_eq!(refused_message, message);
    }
}

#[test]
fn sources_must_have_one_shape() {
    let f = PolicyFixture::new();
    let [p1, _] = f.assigned;
    let shapes = [
        (
            "kind",
            PolicyShape {
                kind: SamplingKind::Dns,
                ..PolicyShape::default()
            },
        ),
        (
            "column",
            PolicyShape {
                column: Some(2),
                ..PolicyShape::default()
            },
        ),
        (
            "interval",
            PolicyShape {
                interval: SamplingInterval::FiveMinutes,
                ..PolicyShape::default()
            },
        ),
        (
            "period",
            PolicyShape {
                period: SamplingPeriod::SixHours,
                ..PolicyShape::default()
            },
        ),
        (
            "offset",
            PolicyShape {
                offset: 9,
                ..PolicyShape::default()
            },
        ),
    ];
    for (attribute, shape) in shapes {
        let other = f.assigned_policy(attribute, &f.generator, shape);
        let ((code, field, value), message) = f.refused(&f.definition(&[p1, other]));
        assert_eq!(
            (code.as_str(), field.as_str(), value),
            ("SOURCES_INCOMPATIBLE", "sources[1]", other.to_string())
        );
        assert_eq!(
            message,
            format!("sampling policy {other} differs in {attribute} from sampling policy {p1}")
        );
    }
}

#[test]
fn sources_must_be_kept_in_the_data_store_read() {
    let f = PolicyFixture::new();
    let [p1, _] = f.assigned;
    let elsewhere = f.assigned_policy("elsewhere", &f.other_generator, PolicyShape::default());
    let ((code, field, value), message) = f.refused(&f.definition(&[p1, elsewhere]));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("SOURCES_INCOMPATIBLE", "data_store.server_name")
    );
    assert_eq!(value, f.server_name);
    assert_eq!(
        message,
        format!(
            "sampling policy {elsewhere} keeps its series in Data Store {:?}, not {:?}",
            f.other_server_name, f.server_name
        )
    );

    // Read from the other Data Store, the first policy is the one refused.
    let text = timeseries_definition(&[p1, elsewhere], &f.other_server_name, OWN_ADDRESS, "");
    let ((code, field, _), message) = f.refused(&text);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("SOURCES_INCOMPATIBLE", "data_store.server_name")
    );
    assert!(
        message.starts_with(&format!("sampling policy {p1} keeps")),
        "{message}"
    );
}

#[test]
fn an_assignee_writing_to_another_data_store_is_refused() {
    let f = PolicyFixture::new();
    // `assign` and `applyNode` keep the stored `data_store` equal to the
    // applied `giganto_name`, so the store is written directly.
    set_generator_config(
        &f.store,
        &f.generator,
        Some(generator_config(&f.other_server_name)),
    );
    let ((code, field, value), message) = f.refused(&f.definition(&f.assigned));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("SOURCES_INCOMPATIBLE", "data_store.server_name")
    );
    assert_eq!(value, f.server_name);
    assert_eq!(
        message,
        format!(
            "the Time Series Generator of sampling policy {} writes to Data Store {:?}, not {:?}",
            f.assigned[0], f.other_server_name, f.server_name
        )
    );
}

#[test]
fn an_assignee_with_no_applied_data_store_is_refused_first() {
    for config in [Some(generator_config("")), Some(String::new()), None] {
        let f = PolicyFixture::new();
        // The empty name also leaves the stored `data_store` unequal to the
        // one read, which is not what is refused.
        set_generator_config(&f.store, &f.generator, config.clone());
        let ((code, field, value), message) = f.refused(&f.definition(&f.assigned));
        assert_eq!(
            (code.as_str(), field.as_str()),
            ("DATA_STORE_NOT_INSTALLED", "data_store.server_name"),
            "{config:?}"
        );
        assert_eq!(value, f.server_name);
        assert_eq!(
            message,
            format!(
                "the Time Series Generator of sampling policy {} has no applied Data Store",
                f.assigned[0]
            )
        );
    }
}

#[test]
fn the_data_store_rule_still_applies_to_the_address() {
    let f = PolicyFixture::new();
    let text = timeseries_definition(&f.assigned, &f.server_name, "192.0.2.1:9999", "");
    let ((code, field, _), _) = f.refused(&text);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("ADDRESS_OVERRIDE_FORBIDDEN", "data_store.address")
    );
}

#[test]
fn other_methods_still_take_only_source_names() {
    let f = PolicyFixture::new();
    let [p1, _] = f.assigned;
    let text = PREFIX.replace("reproduce.a.example.com", &p1.to_string());
    let document = TrainingDocument::parse_and_validate(&text).unwrap();
    let (code, field, _) = parts(
        &document
            .check_sources(&f.store, A, ShapeReference::FirstSource)
            .unwrap_err(),
    );
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("SOURCE_NOT_ALLOWED", "sources[0]")
    );
    let text = PREFIX.replace("reproduce.a.example.com", &sensor_name("gen-a.example.com"));
    TrainingDocument::parse_and_validate(&text)
        .unwrap()
        .check_sources(&f.store, A, ShapeReference::FirstSource)
        .unwrap();
}
