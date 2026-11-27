//! Signature source metadata, rule overrides and engine status reports.

use std::collections::HashSet;

use async_graphql::{
    Context, Enum, ErrorExtensions, ID, InputObject, Object, Result, SimpleObject, StringNumber,
};
use review_database::{self as database, Store};
use review_protocol::types as protocol;
use tracing::warn;

use super::{
    Role, RoleGuard, SharedAgentManager, customer_access,
    filter::{DetectionModel, RawEventKind},
    get_store, hex,
    timestamp::Timestamp,
};
use crate::backend::SignatureRuleFilter;

const DEFAULT_RULE_PAGE_SIZE: i32 = 100;
const MAX_RULE_PAGE_SIZE: i32 = 1_000;

#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "protocol::SignatureSource")]
pub(super) enum SignatureSource {
    EtOpen,
    SigmaHq,
    SigmaHqEmerging,
}

#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::SignatureVersionState")]
enum SignatureSourceVersionState {
    Converting,
    Staged,
    Applied,
    Kept,
    Failed,
    Discarded,
}

#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::SignatureOrigin")]
enum SignatureSourceOrigin {
    Fetch,
    Upload,
}

#[derive(SimpleObject)]
struct SignatureSourceVersion {
    id: ID,
    source: SignatureSource,
    source_version: String,
    fetch_label: Option<String>,
    converter_version: Option<String>,
    origin: SignatureSourceOrigin,
    fetched_url: Option<String>,
    archive_sha256: String,
    content_digest: String,
    received_at: Timestamp,
    state: SignatureSourceVersionState,
    failure_reason: Option<String>,
    summary: Option<String>,
}

impl From<database::SignatureVersion> for SignatureSourceVersion {
    fn from(value: database::SignatureVersion) -> Self {
        Self {
            id: ID(value.id.to_string()),
            source: value.source.into(),
            source_version: value.source_version,
            fetch_label: value.fetch_label,
            converter_version: value.converter_version,
            origin: value.origin.into(),
            fetched_url: value.fetched_url,
            archive_sha256: hex(&value.archive_sha256),
            content_digest: hex(&value.content_digest),
            received_at: value.received_at.into(),
            state: value.state.into(),
            failure_reason: value.failure_reason,
            summary: value.summary,
        }
    }
}

#[derive(SimpleObject)]
struct SignatureReconversion {
    time: Timestamp,
    version_id: ID,
    previous_converter_version: Option<String>,
    attempted_converter_version: String,
    succeeded: bool,
    previous_rule_count: Option<StringNumber<u64>>,
    rule_count: Option<StringNumber<u64>>,
    failure_reason: Option<String>,
}

impl From<database::SignatureReconversion> for SignatureReconversion {
    fn from(value: database::SignatureReconversion) -> Self {
        let (succeeded, previous_rule_count, rule_count, failure_reason) = match value.outcome {
            database::SignatureReconversionOutcome::Succeeded {
                previous_rule_count,
                rule_count,
            } => (
                true,
                previous_rule_count.map(StringNumber),
                Some(StringNumber(rule_count)),
                None,
            ),
            database::SignatureReconversionOutcome::Failed { reason } => {
                (false, None, None, Some(reason))
            }
        };
        Self {
            time: value.time.into(),
            version_id: ID(value.version_id.to_string()),
            previous_converter_version: value.previous_converter_version,
            attempted_converter_version: value.attempted_converter_version,
            succeeded,
            previous_rule_count,
            rule_count,
            failure_reason,
        }
    }
}

#[derive(SimpleObject)]
struct SignatureSourceState {
    source: SignatureSource,
    enabled: bool,
    applied: Option<SignatureSourceVersion>,
    staged: Option<SignatureSourceVersion>,
    kept: Vec<SignatureSourceVersion>,
    versions: Vec<SignatureSourceVersion>,
    last_reconversion: Option<SignatureReconversion>,
}

fn named_version(store: &Store, id: u64) -> Result<SignatureSourceVersion> {
    Ok(store
        .signature_version(id)?
        .ok_or("a signature source names a missing version")?
        .into())
}

#[derive(InputObject)]
struct SignatureRuleFilterInput {
    sources: Option<Vec<SignatureSource>>,
    models: Option<Vec<DetectionModel>>,
    rule_id: Option<String>,
    text: Option<String>,
}

impl From<SignatureRuleFilterInput> for SignatureRuleFilter {
    fn from(value: SignatureRuleFilterInput) -> Self {
        Self {
            sources: value
                .sources
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect(),
            models: value
                .models
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect(),
            rule_id: value.rule_id,
            text: value.text,
        }
    }
}

#[derive(SimpleObject)]
struct SignatureRule {
    source: SignatureSource,
    detection_model: DetectionModel,
    rule_id: String,
    title: String,
    classification: Option<String>,
    severity: String,
    disabled: bool,
}

#[derive(SimpleObject)]
struct SignatureRuleList {
    rules: Vec<SignatureRule>,
    total_count: StringNumber<usize>,
}

#[derive(SimpleObject)]
struct LoadedSignatureSet {
    source: SignatureSource,
    source_version: String,
    converter_version: String,
    rules: StringNumber<u64>,
    failed_compile: StringNumber<u64>,
    load_error: Option<String>,
}

impl From<protocol::LoadedSignatureSet> for LoadedSignatureSet {
    fn from(value: protocol::LoadedSignatureSet) -> Self {
        Self {
            source: value.source.into(),
            source_version: value.source_version,
            converter_version: value.converter_version,
            rules: StringNumber(value.rules),
            failed_compile: StringNumber(value.failed_compile),
            load_error: value.load_error,
        }
    }
}

#[derive(SimpleObject)]
struct OsGatedSkipCount {
    raw_event_kind: RawEventKind,
    count: StringNumber<u64>,
}

#[derive(SimpleObject)]
struct SignatureEngineStatus {
    node_id: ID,
    agent_key: String,
    received_at: Timestamp,
    loaded: Vec<LoadedSignatureSet>,
    os_gated_skipped: Vec<OsGatedSkipCount>,
    home_net_fallback: bool,
    truncated_overflow: StringNumber<u64>,
}

#[derive(SimpleObject)]
struct SignatureTruncationDailySum {
    detection_model: DetectionModel,
    source: SignatureSource,
    rule_id: String,
    count: StringNumber<u64>,
}

struct SignatureStatusOverview {
    reports: Vec<SignatureEngineStatus>,
}

#[Object]
impl SignatureStatusOverview {
    async fn reports(&self) -> &[SignatureEngineStatus] {
        &self.reports
    }

    async fn truncation_daily_sums(
        &self,
        ctx: &Context<'_>,
        date: String,
    ) -> Result<Vec<SignatureTruncationDailySum>> {
        // Jiff also accepts compact dates; the API accepts only YYYY-MM-DD.
        if date.len() != 10
            || !date.bytes().enumerate().all(|(i, b)| {
                if i == 4 || i == 7 {
                    b == b'-'
                } else {
                    b.is_ascii_digit()
                }
            })
        {
            return Err("invalid date; expected YYYY-MM-DD".into());
        }
        let date: jiff::civil::Date = date.parse()?;
        Ok(get_store(ctx)?
            .signature_truncation_daily(date)?
            .into_iter()
            .map(|row| SignatureTruncationDailySum {
                detection_model: row.detection_model.into(),
                source: row.source.into(),
                rule_id: row.rule_id,
                count: StringNumber(row.count),
            })
            .collect())
    }
}

#[derive(Default)]
pub(super) struct SignatureQuery;

#[Object]
impl SignatureQuery {
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn signature_sources(&self, ctx: &Context<'_>) -> Result<Vec<SignatureSourceState>> {
        let store = get_store(ctx)?;
        [
            protocol::SignatureSource::EtOpen,
            protocol::SignatureSource::SigmaHq,
            protocol::SignatureSource::SigmaHqEmerging,
        ]
        .into_iter()
        .map(|source| {
            let row = store.signature_source(source)?;
            Ok(SignatureSourceState {
                source: source.into(),
                enabled: row.enabled,
                applied: row
                    .applied
                    .map(|id| named_version(&store, id))
                    .transpose()?,
                staged: row.staged.map(|id| named_version(&store, id)).transpose()?,
                kept: row
                    .kept
                    .into_iter()
                    .map(|id| named_version(&store, id))
                    .collect::<Result<_>>()?,
                versions: store
                    .signature_versions_of_source(source)?
                    .into_iter()
                    .rev()
                    .map(Into::into)
                    .collect(),
                last_reconversion: row.last_reconversion.map(Into::into),
            })
        })
        .collect()
    }

    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn signature_source_version(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<SignatureSourceVersion>> {
        Ok(get_store(ctx)?
            .signature_version(version_id(&id)?)?
            .map(Into::into))
    }

    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn signature_rules(
        &self,
        ctx: &Context<'_>,
        filter: Option<SignatureRuleFilterInput>,
        #[graphql(default_with = "Some(0)")] offset: Option<i32>,
        #[graphql(default_with = "Some(DEFAULT_RULE_PAGE_SIZE)")] limit: Option<i32>,
    ) -> Result<SignatureRuleList> {
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(DEFAULT_RULE_PAGE_SIZE);
        if offset < 0 || !(1..=MAX_RULE_PAGE_SIZE).contains(&limit) {
            return Err("invalid signature rule pagination".into());
        }
        let filter = filter.map_or_else(SignatureRuleFilter::default, Into::into);
        let page = ctx
            .data::<SharedAgentManager>()?
            .signature_rules(&filter, usize::try_from(offset)?, usize::try_from(limit)?)
            .await?;
        let overrides = get_store(ctx)?.signature_disabled_rules()?;
        let disabled: HashSet<_> = overrides
            .iter()
            .map(|(source, id)| (*source, id.as_str()))
            .collect();
        let rules = page
            .rules
            .into_iter()
            .map(|rule| {
                let disabled = disabled.contains(&(rule.source, rule.rule_id.as_str()));
                SignatureRule {
                    source: rule.source.into(),
                    detection_model: rule.detection_model.into(),
                    rule_id: rule.rule_id,
                    title: rule.title,
                    classification: rule.classification,
                    severity: rule.severity,
                    disabled,
                }
            })
            .collect();
        Ok(SignatureRuleList {
            rules,
            total_count: StringNumber(page.total_count),
        })
    }

    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn signature_status(&self, ctx: &Context<'_>) -> Result<SignatureStatusOverview> {
        let customers = customer_access::users_customers(ctx)?;
        let store = get_store(ctx)?;
        let mut reports = Vec::new();
        for (instance, status) in store.signature_statuses()? {
            if customers.is_some() {
                let node = store.node_map().get_by_id(instance.node_id)?;
                if !node.is_some_and(|(node, _, _)| {
                    customer_access::can_access_node(customers.as_deref(), &node)
                }) {
                    continue;
                }
            }
            reports.push(SignatureEngineStatus {
                node_id: ID(instance.node_id.to_string()),
                agent_key: instance.agent_key,
                received_at: status.received_at.into(),
                loaded: status.report.loaded.into_iter().map(Into::into).collect(),
                os_gated_skipped: status
                    .report
                    .os_gated_skipped
                    .into_iter()
                    .map(|(kind, count)| OsGatedSkipCount {
                        raw_event_kind: kind.into(),
                        count: StringNumber(count),
                    })
                    .collect(),
                home_net_fallback: status.report.home_net_fallback,
                truncated_overflow: StringNumber(status.report.truncated_overflow),
            });
        }
        Ok(SignatureStatusOverview { reports })
    }
}

fn version_id(id: &ID) -> Result<u64> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid signature version ID".into());
    }
    Ok(id.parse()?)
}

fn store_error(error: anyhow::Error) -> async_graphql::Error {
    match error.downcast_ref::<database::SignatureError>() {
        Some(database::SignatureError::UnknownVersion { version_id }) => {
            async_graphql::Error::new(error.to_string()).extend_with(|_, extensions| {
                extensions.set("code", "UNKNOWN_SIGNATURE_VERSION");
                extensions.set("versionId", version_id.to_string());
            })
        }
        Some(database::SignatureError::InvalidState { version_id, state }) => {
            async_graphql::Error::new(error.to_string()).extend_with(|_, extensions| {
                extensions.set("code", "INVALID_SIGNATURE_VERSION_STATE");
                extensions.set("versionId", version_id.to_string());
                extensions.set(
                    "state",
                    async_graphql::Value::from(SignatureSourceVersionState::from(*state)),
                );
            })
        }
        _ => error.into(),
    }
}

async fn push(ctx: &Context<'_>) -> Result<()> {
    if let Err(error) = ctx
        .data::<SharedAgentManager>()?
        .send_signature_rules(&[])
        .await
    {
        warn!("cannot send signature rule sets: {error:#}");
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct SignatureMutation;

#[Object]
impl SignatureMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn apply_signature_source_version(&self, ctx: &Context<'_>, id: ID) -> Result<ID> {
        let version_id = version_id(&id)?;
        get_store(ctx)?
            .apply_signature_version(version_id)
            .map_err(store_error)?;
        push(ctx).await?;
        Ok(ID(version_id.to_string()))
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn discard_signature_source_version(&self, ctx: &Context<'_>, id: ID) -> Result<ID> {
        let version_id = version_id(&id)?;
        get_store(ctx)?
            .discard_signature_version(version_id)
            .map_err(store_error)?;
        Ok(ID(version_id.to_string()))
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn set_signature_source_enabled(
        &self,
        ctx: &Context<'_>,
        source: SignatureSource,
        enabled: bool,
    ) -> Result<bool> {
        let changed = get_store(ctx)?
            .set_signature_source_enabled(source.into(), enabled)?
            .is_some();
        if changed {
            push(ctx).await?;
        }
        Ok(changed)
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn set_signature_rule_enabled(
        &self,
        ctx: &Context<'_>,
        source: SignatureSource,
        rule_id: String,
        enabled: bool,
        account: String,
    ) -> Result<bool> {
        let account = account.trim();
        if account.is_empty() || rule_id.is_empty() {
            return Err("account and ruleId must not be empty".into());
        }
        let changed = {
            let store = get_store(ctx)?;
            if enabled {
                store.enable_signature_rule(source.into(), &rule_id)?
            } else {
                store.disable_signature_rule(
                    source.into(),
                    &rule_id,
                    account,
                    jiff::Timestamp::now(),
                )?
            }
            .is_some()
        };
        if changed {
            push(ctx).await?;
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests;
