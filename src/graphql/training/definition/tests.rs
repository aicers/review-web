use serde_json::Value;

use super::*;

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
    let error = TrainingDocument::parse_and_validate(text).expect_err(text);
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
fn timeseries_is_not_supported() {
    let (code, field, _) = refused(&with(VALID, "method", "method = \"timeseries\""));
    assert_eq!(code, "TIMESERIES_UNSUPPORTED");
    assert_eq!(field, "method");
    let error =
        TrainingDocument::parse_and_validate(&with(VALID, "method", "method = \"timeseries\""))
            .unwrap_err();
    assert_eq!(error.message, "the timeseries method is not supported yet");
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
