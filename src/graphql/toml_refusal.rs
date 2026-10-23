//! The refusal of a TOML document that does not parse into its schema types,
//! shared by the training definitions and the engine documents.
//!
//! The refusal names the offending key as a dotted path, found by walking the
//! document's spans to the deepest key or value that covers the parser's
//! error.

use std::ops::Range;

use toml::de::{DeTable, DeValue};

use super::refusal::{RefusalCode, refusal};

/// Returns the refusal of `text`, a `what` (such as "training definition"),
/// that does not parse into its schema types.
///
/// A key outside the schema is `UNKNOWN_FIELD`, anything else
/// `INVALID_DOCUMENT`. `field` is the dotted path of the offending key, found
/// from the error's position. A TOML syntax error has an empty `field` and the
/// parser's message in `value`; elsewhere `value` is the offending text.
pub(crate) fn parse_refusal(
    text: &str,
    error: &toml::de::Error,
    what: &str,
) -> async_graphql::Error {
    let message = error.message();
    if DeTable::parse(text).is_err() {
        return refusal(
            RefusalCode::InvalidDocument,
            format!("invalid {what}: {message}"),
            "",
            message,
        );
    }
    let mut field = error
        .span()
        .and_then(|span| path_at(text, &span))
        .unwrap_or_default();
    let value = error
        .span()
        .and_then(|span| text.get(span))
        .unwrap_or_default();
    if let Some(key) = quoted(message, "unknown field `") {
        let field = if field.is_empty() {
            key.to_string()
        } else {
            field
        };
        return refusal(
            RefusalCode::UnknownField,
            format!("unknown key {field}"),
            &field,
            key,
        );
    }
    if let Some(key) = quoted(message, "missing field `") {
        field = if field.is_empty() {
            key.to_string()
        } else {
            format!("{field}.{key}")
        };
        return refusal(
            RefusalCode::InvalidDocument,
            format!("required key {field} is missing"),
            &field,
            "",
        );
    }
    refusal(
        RefusalCode::InvalidDocument,
        format!("invalid {what}: {message}"),
        &field,
        value,
    )
}

/// Returns the text between `prefix` and the next backtick of `message`, if
/// `message` starts with `prefix`.
fn quoted<'a>(message: &'a str, prefix: &str) -> Option<&'a str> {
    message.strip_prefix(prefix)?.split('`').next()
}

/// Returns the dotted path of the deepest key or value of `text` whose span
/// covers `span`, or `None` for an empty span or a document that does not
/// parse.
fn path_at(text: &str, span: &Range<usize>) -> Option<String> {
    if span.is_empty() {
        return None;
    }
    let table = DeTable::parse(text).ok()?;
    let mut found = None;
    walk_table(table.get_ref(), span, "", 0, &mut found);
    found.map(|(path, _)| path)
}

/// Records in `found` the deepest path under `table` whose key or value
/// covers `span`, with its depth.
fn walk_table(
    table: &DeTable<'_>,
    span: &Range<usize>,
    prefix: &str,
    depth: usize,
    found: &mut Option<(String, usize)>,
) {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.get_ref().to_string()
        } else {
            format!("{prefix}.{}", key.get_ref())
        };
        if covers(&key.span(), span) || covers(&value.span(), span) {
            record(found, &path, depth + 1);
        }
        walk_value(value.get_ref(), span, &path, depth + 1, found);
    }
}

fn walk_value(
    value: &DeValue<'_>,
    span: &Range<usize>,
    path: &str,
    depth: usize,
    found: &mut Option<(String, usize)>,
) {
    match value {
        DeValue::Table(table) => walk_table(table, span, path, depth, found),
        DeValue::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let path = format!("{path}[{i}]");
                if covers(&item.span(), span) {
                    record(found, &path, depth + 1);
                }
                walk_value(item.get_ref(), span, &path, depth + 1, found);
            }
        }
        _ => {}
    }
}

fn covers(outer: &Range<usize>, inner: &Range<usize>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn record(found: &mut Option<(String, usize)>, path: &str, depth: usize) {
    if found.as_ref().is_none_or(|(_, deepest)| *deepest < depth) {
        *found = Some((path.to_string(), depth));
    }
}
