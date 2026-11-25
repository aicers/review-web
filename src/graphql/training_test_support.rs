//! Test helpers that write complete training definitions: one of the
//! `http_url` clustering model type and custom ones of each method, every
//! value set, with a window the default Data Store retention keeps.

use std::sync::LazyLock;

use jiff::Timestamp;

/// The `[csv]` table `http_url` version 1 fixes, as a definition writes it.
pub(crate) const HTTP_URL_CSV: &str = r#"[csv]
reader = { delimiter = 9, quote = 0 }
prefix_columns = [14, 15]
time_intervals = [60]
time_column = 0
count_columns = [0]
format = [
  { name = "time", data_type = "utf8", weight = 0.0 },
  { name = "source", data_type = "utf8", weight = 0.0 },
  { name = "orig_addr", data_type = "utf8", weight = 0.0 },
  { name = "orig_port", data_type = "enum", weight = 0.0 },
  { name = "resp_addr", data_type = "utf8", weight = 0.0 },
  { name = "resp_port", data_type = "enum", weight = 0.0 },
  { name = "proto", data_type = "enum", weight = 0.0 },
  { name = "start_time", data_type = "utf8", weight = 0.0 },
  { name = "duration", data_type = "int64", weight = 0.0 },
  { name = "orig_pkts", data_type = "int64", weight = 0.0 },
  { name = "resp_pkts", data_type = "int64", weight = 0.0 },
  { name = "orig_l2_bytes", data_type = "int64", weight = 0.0 },
  { name = "resp_l2_bytes", data_type = "int64", weight = 0.0 },
  { name = "method", data_type = "enum", weight = 0.0 },
  { name = "host", data_type = "utf8", weight = 1.0 },
  { name = "uri", data_type = "utf8", weight = 2147483647.0 },
  { name = "referer", data_type = "utf8", weight = 0.0 },
  { name = "version", data_type = "utf8", weight = 0.0 },
  { name = "user_agent", data_type = "utf8", weight = 0.0 },
  { name = "request_len", data_type = "int64", weight = 0.0 },
  { name = "response_len", data_type = "int64", weight = 0.0 },
  { name = "status_code", data_type = "int64", weight = 0.0 },
  { name = "status_msg", data_type = "utf8", weight = 0.0 },
  { name = "username", data_type = "utf8", weight = 0.0 },
  { name = "password", data_type = "utf8", weight = 0.0 },
  { name = "cookie", data_type = "utf8", weight = 0.0 },
  { name = "content_encoding", data_type = "utf8", weight = 0.0 },
  { name = "content_type", data_type = "utf8", weight = 0.0 },
  { name = "cache_control", data_type = "utf8", weight = 0.0 },
  { name = "filenames", data_type = "utf8", weight = 0.0 },
  { name = "mime_types", data_type = "utf8", weight = 0.0 },
  { name = "body", data_type = "utf8", weight = 0.0 },
  { name = "state", data_type = "utf8", weight = 0.0 },
]
"#;

/// The `numbers_of_top_n` `http_url` version 1 fixes.
const HTTP_URL_TOP_N: &str = "[30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]";

/// The window every test definition reads: the seven days from midnight UTC
/// two weeks ago, fixed for the test binary so that texts built at different
/// times compare equal.
pub(crate) static WINDOW: LazyLock<(String, String)> = LazyLock::new(|| {
    const DAY: i64 = 24 * 60 * 60;
    let midnight = Timestamp::now().as_second().div_euclid(DAY) * DAY;
    let day = |days_ago: i64| {
        Timestamp::from_second(midnight - days_ago * DAY)
            .expect("a recent day is a time")
            .to_string()
    };
    (day(14), day(7))
});

/// Returns the `window_start` of [`WINDOW`].
pub(crate) fn window_start() -> &'static str {
    &WINDOW.0
}

/// Returns the `window_end` of [`WINDOW`].
pub(crate) fn window_end() -> &'static str {
    &WINDOW.1
}

/// Returns the `[data_store]` table reading `server_name` at `address`.
fn data_store(server_name: &str, address: &str) -> String {
    format!("[data_store]\naddress = \"{address}\"\nserver_name = \"{server_name}\"\n")
}

/// Returns `template` with each top-level line of `extra` in place of the
/// line of its key, or after the window when the template has no such line.
fn with_extra(template: &str, extra: &str) -> String {
    let mut text = template.to_string();
    for line in extra.lines().filter(|line| !line.trim().is_empty()) {
        let key = line.split('=').next().unwrap_or_default().trim();
        let prefix = format!("{key} =");
        if let Some(old) = text.lines().find(|l| l.starts_with(&prefix)) {
            let old = old.to_string();
            text = text.replacen(&old, line, 1);
        } else {
            let anchor = format!("window_end = \"{}\"\n", window_end());
            text = text.replacen(&anchor, &format!("{anchor}{line}\n"), 1);
        }
    }
    text
}

/// Returns the sources `sources` as a TOML list.
fn source_list(sources: &[&str]) -> String {
    serde_json::to_string(sources).expect("a list of strings serializes")
}

/// Returns a complete `http_url` version 1 definition reading `sources` from
/// the Data Store `server_name` at `address`, with the top-level lines of
/// `extra` in place of those of their keys, or after the window.
pub(crate) fn http_url_definition(
    sources: &[&str],
    server_name: &str,
    address: &str,
    extra: &str,
) -> String {
    let template = format!(
        r#"type = "http_url"
type_version = 1
raw_event_kind = "http"
method = "multidimension"
sources = {sources}
window_start = "{start}"
window_end = "{end}"
batch_size = 1000000
max_event_id_num = 50
numbers_of_top_n = {HTTP_URL_TOP_N}
precision = 2
min_token_length = 2
max_data_len = 30
long_pattern_len = 16000
algorithm = "dbscan"
eps = 5.0

{data_store}
{HTTP_URL_CSV}"#,
        sources = source_list(sources),
        start = window_start(),
        end = window_end(),
        data_store = data_store(server_name, address),
    );
    with_extra(&template, extra)
}

/// Returns a complete custom `prefix` definition reading the log `log_kind`
/// of `sources` from the Data Store `server_name` at `address`, with `extra`
/// top-level lines in place of those of their keys, or after the window.
pub(crate) fn prefix_definition(
    sources: &[&str],
    log_kind: &str,
    server_name: &str,
    address: &str,
    extra: &str,
) -> String {
    let template = format!(
        r#"type = "custom"
raw_event_kind = "log"
log_kind = "{log_kind}"
method = "prefix"
sources = {sources}
window_start = "{start}"
window_end = "{end}"
batch_size = 1000000
max_event_id_num = 25
min_token_length = 2
long_pattern_len = 16000

{data_store}"#,
        sources = source_list(sources),
        start = window_start(),
        end = window_end(),
        data_store = data_store(server_name, address),
    );
    with_extra(&template, extra)
}

/// Returns a complete custom `timeseries` definition reading the time series
/// generation policies `sources` from the Data Store `server_name` at
/// `address`, with `extra` top-level lines in place of those of their keys,
/// or after the window.
pub(crate) fn custom_timeseries_definition(
    sources: &[&str],
    server_name: &str,
    address: &str,
    extra: &str,
) -> String {
    let template = format!(
        r#"type = "custom"
raw_event_kind = "conn"
method = "timeseries"
sources = {sources}
window_start = "{start}"
window_end = "{end}"
batch_size = 1000000
max_event_id_num = 25
algorithm = "dbscan"
eps = 2.0
precision = 2
numbers_of_top_n = []
slot_size = 900
min_cluster_size = 3
transform = "none"

{data_store}"#,
        sources = source_list(sources),
        start = window_start(),
        end = window_end(),
        data_store = data_store(server_name, address),
    );
    with_extra(&template, extra)
}
