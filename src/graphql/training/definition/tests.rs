use std::{net::IpAddr, sync::LazyLock};

use review_database::{SamplingInterval, SamplingKind, SamplingPeriod};
use serde_json::Value;

use super::*;
use crate::graphql::{
    sampling_test_support::{
        OTHER_POLICY_CUSTOMER, OWN_ADDRESS, POLICY_CUSTOMER, PolicyFixture, PolicyShape,
        generator_config, insert_assigned_policy, insert_policy, sensor_name, set_generator_config,
        timeseries_definition,
    },
    training_test_support::{
        custom_timeseries_definition, http_url_definition, prefix_definition, window_end,
        window_start,
    },
};

const SERVER_NAME: &str = "001.giganto.store.example.com";

/// A complete `http_url` version 1 definition.
static VALID: LazyLock<String> =
    LazyLock::new(|| http_url_definition(&["piglet.a.example.com"], SERVER_NAME, OWN_ADDRESS, ""));

/// A complete custom `multidimension` definition.
static CUSTOM: LazyLock<String> = LazyLock::new(|| {
    VALID.replace(
        "type = \"http_url\"\ntype_version = 1\n",
        "type = \"custom\"\n",
    )
});

/// A complete custom `prefix` definition reading the log `syslog`.
static PREFIX: LazyLock<String> = LazyLock::new(|| {
    prefix_definition(
        &["reproduce.a.example.com"],
        "syslog",
        SERVER_NAME,
        OWN_ADDRESS,
        "",
    )
});

/// A complete custom `timeseries` definition.
static TIMESERIES: LazyLock<String> =
    LazyLock::new(|| custom_timeseries_definition(&["3", "5"], SERVER_NAME, OWN_ADDRESS, ""));

/// Returns `text` with the line starting with `key =` replaced by `line`, or
/// `line` inserted before the first table when no such line exists.
fn with(text: &str, key: &str, line: &str) -> String {
    let prefix = format!("{key} =");
    if text.lines().any(|l| l.starts_with(&prefix)) {
        let mut replaced = text
            .lines()
            .map(|l| if l.starts_with(&prefix) { line } else { l })
            .collect::<Vec<_>>()
            .join("\n");
        replaced.push('\n');
        replaced
    } else {
        text.replacen("\n[data_store]", &format!("{line}\n\n[data_store]"), 1)
    }
}

/// Returns `text` without the line starting with `key =`.
fn without(text: &str, key: &str) -> String {
    let prefix = format!("{key} =");
    let mut kept = text
        .lines()
        .filter(|l| !l.starts_with(&prefix))
        .collect::<Vec<_>>()
        .join("\n");
    kept.push('\n');
    kept
}

/// Returns the code, `field` and `value` of the refusal of `text` by the
/// rules of this module alone.
fn refused(text: &str) -> (String, String, String) {
    parts(&TrainingDocument::parse_and_validate(text).expect_err(text))
}

/// Returns the code, `field` and `value` of the refusal of `text` by the
/// clustering model type check followed by the rules of this module.
fn checked(text: &str) -> (String, String, String) {
    parts(&TrainingDocument::check(text).expect_err(text))
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

fn triple(code: &str, field: &str, value: &str) -> (String, String, String) {
    (code.to_string(), field.to_string(), value.to_string())
}

fn http_url(version: u32) -> ClusteringModelTypeRef {
    ClusteringModelTypeRef::Catalog {
        id: "http_url".to_string(),
        version,
    }
}

#[test]
fn complete_definitions_are_checked_and_name_their_type() {
    let (document, model_type) = TrainingDocument::check(&VALID).unwrap();
    assert_eq!(document.method, Method::Multidimension);
    assert_eq!(document.sources, ["piglet.a.example.com"]);
    assert_eq!(document.model_type.as_deref(), Some("http_url"));
    assert_eq!(document.type_version, Some(1));
    assert_eq!(model_type, http_url(1));
    for text in [&*CUSTOM, &*PREFIX, &*TIMESERIES] {
        let (_, model_type) = TrainingDocument::check(text).expect(text);
        assert_eq!(model_type, ClusteringModelTypeRef::Custom, "{text}");
    }
    let (document, _) = TrainingDocument::check(&PREFIX).unwrap();
    assert_eq!(document.method, Method::Prefix);
    assert_eq!(document.log_kind.as_deref(), Some("syslog"));
}

#[test]
fn every_optional_key_of_the_schema_parses() {
    let text = r#"
type = "custom"
type_version = 7
raw_event_kind = "conn"
log_kind = "syslog"
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
    assert_eq!(document.model_type.as_deref(), Some("custom"));
    assert_eq!(document.type_version, Some(7));
    assert_eq!(document.log_kind.as_deref(), Some("syslog"));
    let reparsed = TrainingDocument::parse_and_validate(&document.to_text().unwrap()).unwrap();
    assert_eq!(reparsed, document);
}

#[test]
fn a_serialization_keeps_the_type_and_the_window_text_and_drops_comments() {
    let text = format!(
        "# trained for piglet.secret.example.com\n{}",
        with(
            &PREFIX,
            "window_start",
            "window_start = \"2026-10-14T00:00:00+09:00\""
        )
    );
    let document = TrainingDocument::parse_and_validate(&text).unwrap();
    let serialized = document.to_text().unwrap();
    assert!(!serialized.contains('#'), "{serialized}");
    assert!(!serialized.contains("secret"), "{serialized}");
    assert!(
        serialized.contains("2026-10-14T00:00:00+09:00"),
        "{serialized}"
    );
    assert!(
        serialized.starts_with("type = \"custom\"\n"),
        "{serialized}"
    );
    assert!(serialized.contains("log_kind = \"syslog\""), "{serialized}");

    // A catalog definition's serialization still checks as its type.
    let (document, _) = TrainingDocument::check(&VALID).unwrap();
    let serialized = document.to_text().unwrap();
    assert!(
        serialized.starts_with("type = \"http_url\"\ntype_version = 1\n"),
        "{serialized}"
    );
    assert_eq!(check_type(&serialized).unwrap(), http_url(1));
}

#[test]
fn syntax_errors_and_missing_keys_are_invalid() {
    assert_eq!(code("raw_event_kind = "), "INVALID_DOCUMENT");
    assert_eq!(checked("raw_event_kind = ").0, "INVALID_DOCUMENT");
    assert_eq!(checked("raw_event_kind = ").1, "");
    let (code, field, _) = refused(&without(&VALID, "window_end"));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("INVALID_DOCUMENT", "window_end")
    );
    let (code, field, _) = refused(&without(&VALID, "server_name"));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("INVALID_DOCUMENT", "data_store.server_name")
    );
    assert_eq!(
        checked(&without(&VALID, "type")),
        triple("INVALID_DOCUMENT", "type", "")
    );
}

#[test]
fn unknown_keys_are_refused_at_every_level() {
    for (text, field) in [
        (with(&VALID, "name", "name = \"model\""), "name"),
        (
            with(&VALID, "export_path", "export_path = \"/tmp\""),
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
            VALID.replacen("weight = 0.0 }", "weight = 0.0, path = \"/x\" }", 1),
            "csv.format[0].path",
        ),
        (format!("{}\n[auth]\nkey = 1\n", *VALID), "auth"),
    ] {
        let (code, refused_field, _) = refused(&text);
        assert_eq!(code, "UNKNOWN_FIELD", "{text}");
        assert_eq!(refused_field, field, "{text}");
    }
}

#[test]
fn the_former_raw_event_kind_key_is_an_unknown_key() {
    let former = "event_kind";
    let line = format!("{former} = \"http\"");
    for text in [
        with(&VALID, "raw_event_kind", &line),
        VALID.replacen("raw_event_kind =", &format!("{line}\nraw_event_kind ="), 1),
    ] {
        let (code, field, _) = refused(&text);
        assert_eq!(
            (code.as_str(), field.as_str()),
            ("UNKNOWN_FIELD", former),
            "{text}"
        );
        assert_eq!(checked(&text), triple("UNKNOWN_FIELD", former, "http"));
    }
    let document = TrainingDocument::parse_and_validate(&VALID).unwrap();
    assert_eq!(document.raw_event_kind, "http");
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
        let (code, refused_field, _) = refused(&with(&VALID, key, line));
        assert_eq!(code, "INVALID_DOCUMENT", "{line}");
        assert_eq!(refused_field, field, "{line}");
    }
    for (replaced, by, field) in [
        ("10.0.0.5:38371", "10.0.0.5", "data_store.address"),
        (
            "time_intervals = [60]",
            "time_intervals = [60, -1]",
            "csv.time_intervals[1]",
        ),
        (
            "reader = { delimiter = 9, quote = 0 }",
            "reader = { delimiter = 300, quote = 0 }",
            "csv.reader.delimiter",
        ),
        (
            "reader = { delimiter = 9, quote = 0 }",
            "reader = { delimiter = 9 }",
            "csv.reader.quote",
        ),
        (
            "data_type = \"utf8\"",
            "data_type = \"text\"",
            "csv.format[0].data_type",
        ),
        ("time_column = 0", "time_column = -1", "csv.time_column"),
        (
            "count_columns = [0]",
            "count_columns = [1.5]",
            "csv.count_columns[0]",
        ),
    ] {
        let (code, refused_field, _) = refused(&VALID.replacen(replaced, by, 1));
        assert_eq!(code, "INVALID_DOCUMENT", "{by}");
        assert_eq!(refused_field, field, "{by}");
    }
}

#[test]
fn a_format_entry_needs_a_weight() {
    let (code, field, _) = refused(&VALID.replacen(", weight = 0.0", "", 1));
    assert_eq!(code, "INVALID_DOCUMENT");
    assert_eq!(field, "csv.format[0].weight");
}

#[test]
fn timeseries_takes_its_event_kind_and_no_csv() {
    let document = TrainingDocument::parse_and_validate(&TIMESERIES).unwrap();
    assert_eq!(document.method, Method::Timeseries);
    assert_eq!(document.sources, ["3", "5"]);
    let reparsed = TrainingDocument::parse_and_validate(&document.to_text().unwrap()).unwrap();
    assert_eq!(reparsed, document);

    for kind in ["conn", "log", "periodic_time_series", ""] {
        let text = with(
            &TIMESERIES,
            "raw_event_kind",
            &format!("raw_event_kind = \"{kind}\""),
        );
        assert_eq!(
            checked(&text),
            triple("EVENT_KIND_NOT_ALLOWED", "raw_event_kind", kind),
            "{kind}"
        );
    }

    let extra = format!("{}\n[csv]\ntime_column = 0\n", *TIMESERIES);
    let (code, field, _) = checked(&extra);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("FIELD_NOT_ALLOWED", "csv")
    );
}

#[test]
fn timeseries_refuses_each_field_its_method_rejects() {
    for (field, line) in [
        ("min_token_length", "min_token_length = 3"),
        ("max_token_length", "max_token_length = 10"),
        ("max_data_len", "max_data_len = 30"),
        ("long_pattern_len", "long_pattern_len = 16000"),
    ] {
        let (code, refused_field, _) = checked(&with(&TIMESERIES, field, line));
        assert_eq!(
            (code.as_str(), refused_field.as_str()),
            ("FIELD_NOT_ALLOWED", field)
        );
    }
    // The fields its key table takes are taken.
    for line in [
        "batch_size = 1000",
        "algorithm = \"hdbscan\"",
        "eps = 0.5",
        "precision = 3",
        "numbers_of_top_n = [3]",
        "max_event_id_num = 10",
        "suspicious_tokens = \"indicator\"",
    ] {
        let key = line.split(" =").next().unwrap();
        TrainingDocument::check(&with(&TIMESERIES, key, line)).expect(line);
    }
}

#[test]
fn multidimension_takes_the_raw_event_kinds_of_the_catalog() {
    for text in [&*VALID, &*CUSTOM] {
        TrainingDocument::check(text).expect("http is the kind of http_url");
        for kind in ["conn", "log", "periodic_time_series", "dns_event", ""] {
            let text = with(
                text,
                "raw_event_kind",
                &format!("raw_event_kind = \"{kind}\""),
            );
            assert_eq!(
                checked(&text),
                triple("EVENT_KIND_NOT_ALLOWED", "raw_event_kind", kind),
                "{kind}"
            );
        }
    }
}

#[test]
fn prefix_reads_a_log_named_by_its_log_kind() {
    for kind in ["log", "syslog", "apache-access"] {
        let text = with(&PREFIX, "log_kind", &format!("log_kind = \"{kind}\""));
        let (document, _) = TrainingDocument::check(&text).expect(kind);
        assert_eq!(
            document.record_kinds(),
            ("log".to_string(), Some(kind.to_string()))
        );
    }
    for kind in NAMED_EVENT_KINDS.iter().copied().chain([""]) {
        let text = with(&PREFIX, "log_kind", &format!("log_kind = \"{kind}\""));
        assert_eq!(
            checked(&text),
            triple("EVENT_KIND_NOT_ALLOWED", "log_kind", kind),
            "{kind}"
        );
    }
    for kind in ["dce rpc", "dns_event", "timeseries", "http"] {
        assert!(NAMED_EVENT_KINDS.contains(&kind));
    }

    // The raw event kind of a prefix definition is always `log`.
    for kind in ["http", "syslog"] {
        let text = with(
            &PREFIX,
            "raw_event_kind",
            &format!("raw_event_kind = \"{kind}\""),
        );
        assert_eq!(
            checked(&text),
            triple("EVENT_KIND_NOT_ALLOWED", "raw_event_kind", kind)
        );
    }
    assert_eq!(
        checked(&without(&PREFIX, "log_kind")),
        triple("FIELD_NOT_ALLOWED", "log_kind", "")
    );
    // Only a prefix definition names a log kind.
    for text in [&*VALID, &*CUSTOM, &*TIMESERIES] {
        let text = with(text, "log_kind", "log_kind = \"syslog\"");
        assert_eq!(
            checked(&text),
            triple("FIELD_NOT_ALLOWED", "log_kind", "syslog")
        );
    }
}

#[test]
fn the_record_kinds_follow_the_method() {
    let kinds = |text: &str| TrainingDocument::check(text).unwrap().0.record_kinds();
    assert_eq!(kinds(&VALID), ("http".to_string(), None));
    assert_eq!(kinds(&CUSTOM), ("http".to_string(), None));
    assert_eq!(
        kinds(&PREFIX),
        ("log".to_string(), Some("syslog".to_string()))
    );
    // The engine records a time-series model's kind under its Giganto name,
    // while the text keeps `timeseries`.
    assert_eq!(
        kinds(&TIMESERIES),
        ("periodic_time_series".to_string(), None)
    );
    let (document, _) = TrainingDocument::check(&TIMESERIES).unwrap();
    assert_eq!(document.raw_event_kind, "timeseries");
}

#[test]
fn csv_is_required_for_multidimension_and_refused_for_prefix() {
    let missing = CUSTOM
        .split("\n[csv]")
        .next()
        .expect("the text has a [csv] table")
        .to_string();
    let (code, field, _) = checked(&missing);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("FIELD_NOT_ALLOWED", "csv")
    );
    let extra = format!("{}\n[csv]\ntime_column = 0\n", *PREFIX);
    let (code, field, _) = checked(&extra);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("FIELD_NOT_ALLOWED", "csv")
    );
}

#[test]
fn every_refusal_code_of_the_type_check_maps_to_its_own_code() {
    use TrainingDefinitionRefusalCode as Code;

    let cases = [
        (Code::InvalidDocument, RefusalCode::InvalidDocument),
        (Code::UnknownField, RefusalCode::UnknownField),
        (Code::UnknownModelType, RefusalCode::UnknownModelType),
        (
            Code::ModelTypeVersionMismatch,
            RefusalCode::ModelTypeVersionMismatch,
        ),
        (Code::EventKindNotAllowed, RefusalCode::EventKindNotAllowed),
        (Code::FieldFixed, RefusalCode::FieldFixed),
        (Code::FieldNotAllowed, RefusalCode::FieldNotAllowed),
        (Code::BoundViolated, RefusalCode::BoundViolated),
    ];
    for (code, expected) in cases {
        let refused = TrainingDefinitionRefusal {
            code,
            key: "csv.format[3]".to_string(),
            value: "v".to_string(),
            message: "why".to_string(),
        };
        let error = definition_refusal(&refused);
        assert_eq!(error.message, "why");
        assert_eq!(
            parts(&error),
            triple(expected.as_str(), "csv.format[3]", "v"),
            "{code:?}"
        );
    }
    assert_eq!(RefusalCode::UnknownModelType.as_str(), "UNKNOWN_MODEL_TYPE");
    assert_eq!(
        RefusalCode::ModelTypeVersionMismatch.as_str(),
        "MODEL_TYPE_VERSION_MISMATCH"
    );
}

#[test]
fn a_catalog_definition_is_refused_with_the_type_check_refusal() {
    let six_days = {
        let end = rfc3339::parse(window_end()).unwrap();
        let start = end
            .checked_sub(jiff::SignedDuration::from_secs(7 * 24 * 60 * 60 - 1))
            .unwrap();
        with(
            &VALID,
            "window_start",
            &format!("window_start = \"{start}\""),
        )
    };
    for (text, expected) in [
        (
            with(&VALID, "type", "type = \"no_such_type\""),
            triple("UNKNOWN_MODEL_TYPE", "type", "no_such_type"),
        ),
        (
            with(&VALID, "type_version", "type_version = 0"),
            triple("MODEL_TYPE_VERSION_MISMATCH", "type_version", "0"),
        ),
        (
            with(&VALID, "eps", "eps = 4.0"),
            triple("FIELD_FIXED", "eps", "4.0"),
        ),
        (
            without(&VALID, "max_event_id_num"),
            triple("FIELD_NOT_ALLOWED", "max_event_id_num", ""),
        ),
        (
            with(&VALID, "batch_size", "batch_size = 9999"),
            triple("BOUND_VIOLATED", "batch_size", "9999"),
        ),
        (
            six_days,
            triple("BOUND_VIOLATED", "window_end", window_end()),
        ),
        (
            with(&VALID, "event_kind", "event_kind = \"http\""),
            triple("UNKNOWN_FIELD", "event_kind", "http"),
        ),
    ] {
        assert_eq!(checked(&text), expected, "{text}");
    }
    // The type check runs first: a definition at an earlier version is
    // refused for its version whatever else it holds.
    let stale = with(
        &with(&VALID, "type_version", "type_version = 0"),
        "eps",
        "eps = 4.0",
    );
    assert_eq!(
        checked(&stale),
        triple("MODEL_TYPE_VERSION_MISMATCH", "type_version", "0")
    );
}

#[test]
fn sources_must_be_listed_once_each() {
    let (code, field, _) = refused(&with(&VALID, "sources", "sources = []"));
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("INVALID_DOCUMENT", "sources")
    );
    let (code, field, value) = refused(&with(
        &VALID,
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
        let (code, field, _) = refused(&with(&VALID, "window_start", line));
        assert_eq!(
            (code.as_str(), field.as_str()),
            ("INVALID_DOCUMENT", "window_start")
        );
    }
}

/// Window bounds that are refused, some of which jiff alone would take, each
/// with whether the shape check (`false`) or the jiff parse (`true`) refuses
/// it.
const REFUSED_WINDOW_STARTS: [(&str, bool); 8] = [
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
fn other_window_forms_are_refused() {
    for (start, parse_failure) in REFUSED_WINDOW_STARTS {
        let text = with(
            &VALID,
            "window_start",
            &format!("window_start = \"{start}\""),
        );
        let error = TrainingDocument::parse_and_validate(&text).expect_err(start);
        assert_eq!(
            parts(&error),
            (
                "INVALID_DOCUMENT".to_string(),
                "window_start".to_string(),
                start.to_string()
            )
        );
        let prefix = "window_start is not RFC 3339 with an offset";
        if parse_failure {
            assert!(
                error.message.starts_with(&format!("{prefix}: ")),
                "{start}: {}",
                error.message
            );
        } else {
            assert_eq!(error.message, prefix, "{start}");
        }
    }
}

/// RFC 3339 window bounds with an offset that are accepted and passed on
/// to the engine exactly as written.
const ACCEPTED_WINDOW_STARTS: [&str; 3] = [
    "2026-03-15T15:00:04Z",
    "2026-03-15T15:00:04.123456789+09:00",
    "2026-03-15 15:00:04-05:30",
];

#[test]
fn rfc3339_windows_are_accepted_and_kept_as_written() {
    for start in ACCEPTED_WINDOW_STARTS {
        let text = with(
            &with(
                &VALID,
                "window_start",
                &format!("window_start = \"{start}\""),
            ),
            "window_end",
            "window_end = \"2026-03-25T00:00:00Z\"",
        );
        let document = TrainingDocument::parse_and_validate(&text).expect(start);
        assert_eq!(document.window_start, start);
        let reparsed = TrainingDocument::parse(&document.to_text().unwrap()).unwrap();
        assert_eq!(reparsed.window_start, start);
    }
}

/// A leap second (`:60`) orders and measures a window as the engine reads
/// it, not as the `:59` jiff reads it as.
#[test]
fn a_window_through_a_leap_second_is_ordered_as_the_engine_reads_it() {
    let window = |start: &str, end: &str| {
        with(
            &with(
                &CUSTOM,
                "window_start",
                &format!("window_start = \"{start}\""),
            ),
            "window_end",
            &format!("window_end = \"{end}\""),
        )
    };
    for (start, end) in [
        ("2016-12-31T23:59:59Z", "2016-12-31T23:59:60Z"),
        ("2016-12-31T23:59:59.5Z", "2016-12-31T23:59:60Z"),
        ("2016-12-31T23:59:60Z", "2016-12-31T23:59:60.5Z"),
        ("2016-12-31T23:59:60Z", "2017-03-31T23:59:60Z"),
        ("2016-12-31T23:59:60Z", "2017-04-01T00:00:00Z"),
    ] {
        let document = TrainingDocument::parse_and_validate(&window(start, end))
            .unwrap_or_else(|e| panic!("{start} to {end}: {}", e.message));
        assert_eq!(document.window_start, start);
        assert_eq!(document.window_end, end);
    }
    for (start, end) in [
        ("2016-12-31T23:59:60Z", "2016-12-31T23:59:59.5Z"),
        ("2016-12-31T23:59:60Z", "2016-12-31T23:59:59Z"),
        ("2017-01-01T08:59:60+09:00", "2016-12-31T23:59:60Z"),
    ] {
        let (code, field, value) = refused(&window(start, end));
        assert_eq!(
            (code.as_str(), field.as_str(), value.as_str()),
            ("BOUND_VIOLATED", "window_end", end),
            "{start} to {end}"
        );
    }
}

#[test]
fn bounds_are_accepted_at_their_limit_and_refused_past_it() {
    TrainingDocument::check(&with(&CUSTOM, "max_event_id_num", "max_event_id_num = 100")).unwrap();
    assert_eq!(
        checked(&with(&CUSTOM, "max_event_id_num", "max_event_id_num = 101")),
        triple("BOUND_VIOLATED", "max_event_id_num", "101")
    );
    for (key, line, field) in [
        ("window_end", window_start(), "window_end"),
        ("window_end", "2026-10-13T00:00:00Z", "window_end"),
    ] {
        let text = with(&CUSTOM, key, &format!("{key} = \"{line}\""));
        let (code, refused_field, _) = refused(&text);
        assert_eq!(code, "BOUND_VIOLATED", "{line}");
        assert_eq!(refused_field, field, "{line}");
    }
}

#[test]
fn max_token_length_is_at_least_twice_the_definitions_min_token_length() {
    // PREFIX sets min_token_length = 2.
    TrainingDocument::check(&with(&PREFIX, "max_token_length", "max_token_length = 4")).unwrap();
    assert_eq!(
        checked(&with(&PREFIX, "max_token_length", "max_token_length = 3")),
        triple("BOUND_VIOLATED", "max_token_length", "3")
    );
    let with_min = with(&PREFIX, "min_token_length", "min_token_length = 5");
    TrainingDocument::check(&with(
        &with_min,
        "max_token_length",
        "max_token_length = 10",
    ))
    .unwrap();
    assert_eq!(
        checked(&with(&with_min, "max_token_length", "max_token_length = 9")),
        triple("BOUND_VIOLATED", "max_token_length", "9")
    );
    let huge = with(
        &PREFIX,
        "min_token_length",
        &format!("min_token_length = {}", i64::MAX),
    );
    assert_eq!(
        checked(&with(&huge, "max_token_length", "max_token_length = 1")).0,
        "BOUND_VIOLATED"
    );
    // No default stands in for an absent min_token_length: the definition is
    // refused for lacking it.
    let no_min = without(
        &with(&PREFIX, "max_token_length", "max_token_length = 4"),
        "min_token_length",
    );
    assert_eq!(
        checked(&no_min),
        triple("FIELD_NOT_ALLOWED", "min_token_length", "")
    );
}

#[test]
fn sources_of_reads_a_definition_text() {
    assert_eq!(sources_of(&VALID), ["piglet.a.example.com"]);
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
