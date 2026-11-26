//! Holds the committed schema artifact honest.
//!
//! `schema.graphql` is the output of `examples/schema_sdl.rs`, and this test
//! renders the same schema and compares it against the committed file.

use async_graphql::SDLExportOptions;
use review_web::graphql::{Mutation, Query, Schema, Subscription};

/// The committed artifact, read at compile time so a missing file is a build
/// failure rather than a test that silently passes.
const COMMITTED_SDL: &str = include_str!("../schema.graphql");

const REGENERATE: &str = "the GraphQL schema changed. If the change is deliberate, regenerate the \
                          committed artifact with:\n\n    cargo run --example schema_sdl > \
                          schema.graphql\n";

/// Renders the schema with the same export options as `examples/schema_sdl.rs`.
fn rendered_sdl() -> String {
    Schema::build(
        Query::default(),
        Mutation::default(),
        Subscription::default(),
    )
    .finish()
    .sdl_with_options(SDLExportOptions::new().include_specified_by())
}

#[test]
fn committed_sdl_matches_rendered_schema() {
    // Compared with `assert!` rather than `assert_eq!`: the schema is well over
    // a hundred kilobytes, and printing both copies buries the one line that
    // says what to do about it.
    assert!(rendered_sdl() == COMMITTED_SDL, "{REGENERATE}");
}

/// The retired process list has no query or object left in the schema.
#[test]
fn schema_has_no_process_list() {
    let sdl = rendered_sdl();
    assert!(!sdl.contains("processList"), "{REGENERATE}");
    assert!(!sdl.contains("type Process {"), "{REGENERATE}");
}

/// The customer, allow/block network and network tag APIs have no operation,
/// type, event field, filter field or network field left in the schema.
#[test]
fn schema_has_no_customer_allow_block_or_network_tag_api() {
    let sdl = rendered_sdl();
    for removed in [
        "type Customer {",
        "customerList",
        "insertCustomer",
        "updateCustomer",
        "removeCustomers",
        "origCustomer",
        "respCustomer",
        "AllowNetwork",
        "BlockNetwork",
        "allowNetworkList",
        "blockNetworkList",
        "networkTagList",
        "insertNetworkTag",
        "removeNetworkTag",
        "updateNetworkTag",
    ] {
        assert!(!sdl.contains(removed), "{removed}: {REGENERATE}");
    }

    for header in [
        "input EventListFilterInput {",
        "input EventStandardFilterInput {",
    ] {
        let filter = definition(&sdl, header);
        assert!(!filter.contains("customers"), "{header}: {REGENERATE}");
        assert!(!filter.contains("networkTags"), "{header}: {REGENERATE}");
    }

    for header in ["type Network {", "input NetworkUpdateInput {"] {
        assert!(
            !definition(&sdl, header).contains("tagIds"),
            "{header}: {REGENERATE}"
        );
    }
    let insert_network = sdl
        .lines()
        .find(|line| line.contains("insertNetwork("))
        .expect("the schema defines insertNetwork");
    assert!(!insert_network.contains("tagIds"), "{REGENERATE}");
}

/// The data-source API has no operation, type or model field left in the
/// schema.
#[test]
fn schema_has_no_data_source_api() {
    let sdl = rendered_sdl();
    for removed in [
        "dataSourceList",
        "insertDataSource",
        "updateDataSource",
        "removeDataSource",
        "type DataSource {",
        "DataSourceConnection",
        "DataSourceEdge",
        "DataSourceInsertInput",
        "DataSourceUpdateInput",
        "DataSourceTotalCount",
        "enum DataType {",
    ] {
        assert!(!sdl.contains(removed), "{removed}: {REGENERATE}");
    }
    assert!(
        !definition(&sdl, "type ModelDigest {").contains("dataSource"),
        "{REGENERATE}"
    );
}

/// A time series generation policy has a state instead of `immutable`, and
/// no input takes `immutable`.
#[test]
fn time_series_generation_policies_have_no_immutable_api() {
    let sdl = rendered_sdl();
    for header in [
        "type TimeSeriesGenerationPolicy {",
        "input TimeSeriesGenerationPolicyInput {",
    ] {
        assert!(
            !definition(&sdl, header).contains("immutable"),
            "{header}: {REGENERATE}"
        );
    }
    let insert = sdl
        .lines()
        .find(|line| {
            line.trim_start()
                .starts_with("insertTimeSeriesGenerationPolicy(")
        })
        .expect("the schema defines insertTimeSeriesGenerationPolicy");
    assert!(!insert.contains("immutable"), "{REGENERATE}");
    assert!(insert.contains("customerId: ID!"), "{REGENERATE}");
    assert!(
        definition(&sdl, "type TimeSeriesGenerationPolicy {")
            .contains("state: TimeSeriesGenerationPolicyState!"),
        "{REGENERATE}"
    );
}

/// The time series generation policy API has its new names and fields, and a
/// policy made from a type is inserted by its own mutation.
#[test]
fn time_series_generation_policies_have_the_spec_fields() {
    let sdl = rendered_sdl();
    let policy = definition(&sdl, "type TimeSeriesGenerationPolicy {");
    for field in [
        "rawEventKind: RawEventKind!",
        "measure: Measure!",
        "groupBy: EndpointRole\n",
        "groupByUnit: GroupByUnit!",
        "counterpartScope: CounterpartScope!",
        "slotSize: SlotSize!",
        "windowSize: WindowSize!",
        "utcOffset: Int!",
        "srcIp: String",
        "dstIp: String",
        "sensors: [String!]!",
        "timeSeriesType: TimeSeriesTypeRef\n",
        "customerId: ID!",
    ] {
        assert!(policy.contains(field), "{field}: {REGENERATE}");
    }
    let input = definition(&sdl, "input TimeSeriesGenerationPolicyInput {");
    assert!(input.contains("sensors: [String!]!"), "{REGENERATE}");
    let insert = sdl
        .lines()
        .find(|line| {
            line.trim_start()
                .starts_with("insertTimeSeriesGenerationPolicy(")
        })
        .expect("the schema defines insertTimeSeriesGenerationPolicy");
    for text in [input, insert] {
        assert!(!text.contains("timeSeriesType"), "{REGENERATE}");
    }
    for removed in ["kind", "interval", "period", "offset", "node", "column"] {
        for text in [policy, input] {
            assert!(
                !text.contains(&format!("\n\t{removed}:")),
                "{removed}: {REGENERATE}"
            );
        }
    }
    let from_type = sdl
        .lines()
        .find(|line| {
            line.trim_start()
                .starts_with("insertTimeSeriesGenerationPolicyFromType(")
        })
        .expect("the schema defines insertTimeSeriesGenerationPolicyFromType");
    assert!(
        from_type.contains(
            "(customerId: ID!, name: String!, timeSeriesType: TimeSeriesTypeRefInput!, \
             sensors: [String!]!, utcOffset: Int!): ID!"
        ),
        "{from_type}: {REGENERATE}"
    );
}

/// The enums of a time series generation policy have their values, and the
/// enums they replaced are gone.
#[test]
fn time_series_generation_policy_enums_have_their_values() {
    let sdl = rendered_sdl();
    for removed in ["enum Kind {", "enum Interval {", "enum Period {"] {
        assert!(!sdl.contains(removed), "{removed}: {REGENERATE}");
    }
    for (header, values) in [
        (
            "enum SlotSize {",
            &[
                "FIVE_MINUTES",
                "TEN_MINUTES",
                "FIFTEEN_MINUTES",
                "THIRTY_MINUTES",
                "ONE_HOUR",
            ][..],
        ),
        (
            "enum WindowSize {",
            &["SIX_HOURS", "TWELVE_HOURS", "ONE_DAY"][..],
        ),
        ("enum GroupByUnit {", &["IP", "OWNED_NETWORK"][..]),
        (
            "enum CounterpartScope {",
            &["ANY", "INTERNAL", "EXTERNAL"][..],
        ),
        (
            "enum Measure {",
            &[
                "COUNT",
                "SUM_DURATION",
                "SUM_ORIG_BYTES",
                "SUM_RESP_BYTES",
                "SUM_ORIG_PKTS",
                "SUM_RESP_PKTS",
            ][..],
        ),
    ] {
        let found: Vec<_> = definition(&sdl, header)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('"'))
            .map(ToString::to_string)
            .collect();
        let found: Vec<&str> = found
            .iter()
            .map(String::as_str)
            .filter(|line| values.contains(line))
            .collect();
        assert_eq!(found, values, "{header}: {REGENERATE}");
    }
}

/// Category counts preserve the nullable uncategorized bucket without making
/// the count at the corresponding index nullable.
#[test]
fn category_counter_keeps_nullable_values_and_non_null_counts() {
    let sdl = rendered_sdl();
    let counter = definition(&sdl, "type U8EventCounter {");

    assert!(counter.contains("\n\tvalues: [Int]!\n"), "{REGENERATE}");
    assert!(counter.contains("\n\tcounts: [Int!]!\n"), "{REGENERATE}");
}

/// Neither `DeliveryMode` nor `BootstrapMaterial` may reach GraphQL.
///
/// `BootstrapMaterial` carries `wrapped_secret_id`, a live single-use
/// credential, and no resolver in this repository calls `register`, so neither
/// type has a caller on this side of the API. Putting either in the schema
/// would put the credential in browser memory for nobody.
#[test]
fn schema_names_no_enrollment_type() {
    let sdl = rendered_sdl();
    assert!(!sdl.contains("DeliveryMode"), "{REGENERATE}");
    assert!(!sdl.contains("BootstrapMaterial"), "{REGENERATE}");
}

/// Every time in the schema is the one `DateTime` scalar, which has no
/// description and names RFC 3339 as its specification; no offset-free time
/// scalar is left.
#[tokio::test]
async fn every_time_is_the_rfc3339_datetime_scalar() {
    let sdl = rendered_sdl();
    assert!(!sdl.contains("NaiveDateTime"), "{REGENERATE}");
    assert!(
        sdl.contains(
            "\nscalar DateTime @specifiedBy(url: \"https://datatracker.ietf.org/doc/html/rfc3339\")\n"
        ),
        "{REGENERATE}"
    );

    let response = Schema::build(
        Query::default(),
        Mutation::default(),
        Subscription::default(),
    )
    .finish()
    .execute(r#"{ __type(name: "DateTime") { kind description specifiedByURL } }"#)
    .await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response
            .data
            .into_json()
            .expect("introspection data is JSON"),
        serde_json::json!({
            "__type": {
                "kind": "SCALAR",
                "description": null,
                "specifiedByURL": "https://datatracker.ietf.org/doc/html/rfc3339",
            }
        })
    );
}

/// Returns the body of the named type or enum in `sdl`.
///
/// # Panics
///
/// Panics if the schema holds no such definition, which is itself the failure
/// the assertions below are looking for.
fn definition<'a>(sdl: &'a str, header: &str) -> &'a str {
    let start = sdl
        .find(header)
        .unwrap_or_else(|| panic!("the schema defines no {header}"));
    let body = &sdl[start + header.len()..];
    let end = body
        .find("\n}")
        .unwrap_or_else(|| panic!("the {header} definition is unterminated"));
    // Inclusive of the newline that closes the last field, so that a field
    // written last is matched the same way as one written above it.
    &body[..=end]
}

/// The install-state fields carry the nullability the read contract promises,
/// and `instance` crosses as a `StringNumber`.
///
/// The committed artifact above already pins the whole schema, but it pins it
/// as one opaque blob: a regeneration accepts whatever the code renders. These
/// name the signatures that are the contract, so a change to one fails as
/// itself rather than as a diff someone has to read.
#[test]
fn the_install_state_fields_keep_their_signatures() {
    let sdl = rendered_sdl();

    // The two snapshot types are here beside the keyed ones because
    // `nodeStatusList` renders those instead, and the install state has to be
    // readable on the status path as well as on the list path.
    for header in [
        "type Agent {",
        "type ExternalService {",
        "type AgentSnapshot {",
        "type ExternalServiceSnapshot {",
    ] {
        let definition = definition(&sdl, header);
        assert!(
            definition.contains("\n\tinstance: StringNumber\n"),
            "{header}"
        );
        assert!(!definition.contains("instance: Int"), "{header}");
        assert!(
            definition.contains("\n\tinstalledVersion: String\n"),
            "{header}"
        );
        assert!(
            definition.contains("\n\tinstalledCommit: String\n"),
            "{header}"
        );
        assert!(
            definition.contains("\n\tlifecycle: Lifecycle\n"),
            "{header}"
        );
        assert!(
            definition.contains("\n\tupdateAvailable: Boolean!\n"),
            "{header}"
        );
        assert!(
            definition.contains("\n\tupdateCheckFailed: Boolean!\n"),
            "{header}"
        );
        assert!(
            definition.contains("\n\tinstalledBuildWithdrawn: Boolean!\n"),
            "{header}"
        );
        assert!(
            definition.contains("\n\twithdrawalCheckFailed: Boolean!\n"),
            "{header}"
        );
    }

    // `boundAddrs` is on the external service alone: the agent modules bind
    // nothing, and a field that is always empty is one a client has to be told
    // to ignore.
    assert!(definition(&sdl, "type ExternalService {").contains("\n\tboundAddrs: [BoundAddr!]!\n"));
    assert!(
        definition(&sdl, "type ExternalServiceSnapshot {")
            .contains("\n\tboundAddrs: [BoundAddr!]!\n")
    );
    assert!(!definition(&sdl, "type Agent {").contains("boundAddrs"));
    assert!(!definition(&sdl, "type AgentSnapshot {").contains("boundAddrs"));

    let bound_addr = definition(&sdl, "type BoundAddr {");
    assert!(bound_addr.contains("\n\tkey: String!\n"));
    assert!(bound_addr.contains("\n\taddr: String!\n"));

    let core_component = definition(&sdl, "type CoreComponent {");
    assert!(core_component.contains("\n\tcomponent: String!\n"));
    assert!(core_component.contains("\n\thost: String!\n"));
    assert!(core_component.contains("\n\tinstalledVersion: String\n"));
    assert!(core_component.contains("\n\tinstalledCommit: String\n"));
    // Non-null here, and nullable on the two types above: a core component is
    // package-managed by construction.
    assert!(core_component.contains("\n\tlifecycle: Lifecycle!\n"));
    assert!(core_component.contains("\n\tupdateAvailable: Boolean!\n"));
    assert!(core_component.contains("\n\tupdateCheckFailed: Boolean!\n"));
    assert!(core_component.contains("\n\tinstalledBuildWithdrawn: Boolean!\n"));
    assert!(core_component.contains("\n\twithdrawalCheckFailed: Boolean!\n"));
    assert!(core_component.contains("\n\tinstallerManaged: Boolean!\n"));

    assert!(sdl.contains("\n\tcoreComponentList: [CoreComponent!]!\n"));
}

/// The `Lifecycle` enum mirrors the stored one, `UNKNOWN` included and with no
/// eighth variant for the entry that has no package.
#[test]
fn the_lifecycle_enum_mirrors_the_stored_one() {
    let sdl = rendered_sdl();
    let variants: Vec<&str> = definition(&sdl, "enum Lifecycle {")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    assert_eq!(
        variants,
        vec![
            "NOT_INSTALLED",
            "INSTALLING",
            "RUNNING",
            "STOPPED",
            "FAILED",
            "REMOVING",
            "UNKNOWN",
        ]
    );
}

/// The update check has two fields and no third state.
///
/// An enum of `UP_TO_DATE | UPDATE_AVAILABLE | UNKNOWN` beside
/// `updateAvailable` would give one question two answers on the same type and
/// let clients branch on either.
///
/// The schema's unrelated `updateStatus` mutation, which edits a node's status
/// description, is why this looks at the types carrying the field rather than
/// at the whole document.
#[test]
fn the_schema_names_no_update_status_enum() {
    let sdl = rendered_sdl();
    assert!(!sdl.contains("enum UpdateStatus"), "{REGENERATE}");
    for header in [
        "type Agent {",
        "type ExternalService {",
        "type AgentSnapshot {",
        "type ExternalServiceSnapshot {",
        "type CoreComponent {",
    ] {
        assert!(
            !definition(&sdl, header).contains("updateStatus"),
            "{header}: {REGENERATE}"
        );
    }
}

/// The observed-state fields are read-only: no input type accepts one.
///
/// They are what a host reports, so a client that could submit one could
/// contradict the host. The check reads field lines rather than the whole
/// block, because an input's description may legitimately mention one of the
/// names in prose.
#[test]
fn no_input_type_accepts_an_observed_state_field() {
    const OBSERVED: [&str; 7] = [
        "instance",
        "installedVersion",
        "installedCommit",
        "lifecycle",
        "updateAvailable",
        "updateCheckFailed",
        "boundAddrs",
    ];

    let sdl = rendered_sdl();
    for block in sdl.split("\ninput ").skip(1) {
        let (name, body) = block
            .split_once(" {\n")
            .expect("an input definition opens with its name");
        let body = body.split_once("\n}").map_or(body, |(fields, _)| fields);
        for line in body.lines().map(str::trim) {
            let Some((field, _)) = line.split_once(':') else {
                continue;
            };
            assert!(
                !OBSERVED.contains(&field),
                "input {name} accepts the observed-state field {field}"
            );
        }
    }
}

/// The core-component registry is a top-level query and not a field of a node.
///
/// A core component is host-fixed infrastructure rather than a child of a node
/// record, and hanging it there would inherit the customer scoping a node read
/// carries.
#[test]
fn the_core_component_registry_is_not_reachable_through_a_node() {
    let sdl = rendered_sdl();
    let node = definition(&sdl, "type Node {");
    assert!(!node.contains("CoreComponent"), "{REGENERATE}");
    assert!(!node.contains("coreComponent"), "{REGENERATE}");
    let node_status = definition(&sdl, "type NodeStatus {");
    assert!(!node_status.contains("CoreComponent"), "{REGENERATE}");
}

/// The operation-attempt surface carries the names, nullability and scalars
/// its contract names.
///
/// The id is a `String!` and not an `ID!`, because the value is client-minted
/// and `ID` coerces an input integer to a string; `instance` is the
/// `StringNumber` this schema already uses for a `u32`; and the two timestamps
/// are the `DateTime` scalar the node read path already renders.
#[test]
fn the_operation_attempt_type_keeps_its_signature() {
    let sdl = rendered_sdl();

    let attempt = definition(&sdl, "type OperationAttempt {");
    for field in [
        "\n\tid: String!\n",
        "\n\taction: OperationAction!\n",
        "\n\tphase: OperationPhase!\n",
        "\n\toutcome: OperationOutcome\n",
        "\n\tfailureKind: OperationFailureKind\n",
        "\n\thost: String!\n",
        "\n\ttarget: String\n",
        "\n\tinstance: StringNumber\n",
        "\n\tresolvedVersion: String\n",
        "\n\tresolvedCommit: String\n",
        "\n\tcleanupOwed: OperationCleanupState\n",
        "\n\tstartedAt: DateTime!\n",
        "\n\texpiresAt: DateTime!\n",
    ] {
        assert!(attempt.contains(field), "{field}: {REGENERATE}");
    }
    assert!(!attempt.contains("id: ID!"), "{REGENERATE}");
    assert!(!attempt.contains("instance: Int"), "{REGENERATE}");
    // The record's internal bookkeeping stays off the wire.
    for field in [
        "installIntent",
        "packageDigest",
        "retryPolicy",
        "finalizedAt",
        "backupId",
        "preUpdateVersion",
    ] {
        assert!(!attempt.contains(field), "{field}: {REGENERATE}");
    }

    assert!(
        sdl.contains("\n\toperationAttempt(id: String!): OperationAttempt\n"),
        "{REGENERATE}"
    );
    assert!(
        sdl.contains(
            "\n\tinFlightInstalls(host: String!, target: String!): [OperationAttempt!]!\n"
        ),
        "{REGENERATE}"
    );
}

/// The five operation enums mirror the stored ones, one variant for one
/// variant, and none of them carries a fallback.
#[test]
fn the_operation_enums_mirror_the_stored_ones() {
    let sdl = rendered_sdl();

    for (header, expected) in [
        (
            "enum OperationAction {",
            vec!["INSTALL", "UPDATE", "REMOVE", "ONBOARD"],
        ),
        (
            "enum OperationPhase {",
            vec!["PENDING", "DISPATCHED", "AWAITING_REPORT", "COMPLETED"],
        ),
        (
            "enum OperationOutcome {",
            vec!["SUCCEEDED", "FAILED", "ROLLED_BACK", "CANCELLED"],
        ),
        (
            "enum OperationCleanupState {",
            vec!["PENDING_DEREGISTER", "PENDING_IDENTITY_TEARDOWN"],
        ),
        (
            "enum OperationFailureKind {",
            vec![
                "HOST_DISK_SPACE",
                "HOST_AGENT_UNSUPPORTED",
                "HOST_NOT_PREPARED",
                "UNMANAGED_INSTANCE",
                "SERVICE_FAILED",
                "NOT_APPLIED",
                "TRUST_ANCHOR_REFUSED",
                "BUILD_NOT_SERVABLE",
                "NO_CONFIRMATION",
                "OTHER",
            ],
        ),
    ] {
        let variants: Vec<&str> = definition(&sdl, header)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(variants, expected, "{header}");
    }
}

/// The inline latest attempt is on the three entry types and the system log
/// collector, and on no other.
///
/// It is reachable only through read paths already guarded
/// `SystemAdministrator` or `SecurityAdministrator` — the system log
/// collector through `systemLogCollectorList`, for a System Administrator
/// alone — and hanging it on another type would be the way that stops being
/// true.
#[test]
fn the_inline_latest_attempt_is_on_the_entry_types_and_the_system_log_collector() {
    let sdl = rendered_sdl();

    for header in [
        "type Agent {",
        "type ExternalService {",
        "type CoreComponent {",
        "type SystemLogCollector {",
    ] {
        assert!(
            definition(&sdl, header).contains("\n\tlatestOperationAttempt: OperationAttempt\n"),
            "{header}: {REGENERATE}"
        );
    }
    assert_eq!(
        sdl.matches("\tlatestOperationAttempt: OperationAttempt\n")
            .count(),
        4,
        "{REGENERATE}"
    );
    // One word for one concept: no type spells it shorter.
    assert!(!sdl.contains("latestOperation:"), "{REGENERATE}");
    // No history query and no desired version comes with it.
    assert!(!sdl.contains("desiredVersion"), "{REGENERATE}");
    assert!(!sdl.contains("operationAttemptList"), "{REGENERATE}");
    assert!(!sdl.contains("operationAttemptHistory"), "{REGENERATE}");
}

/// Both time-series queries document the inclusive trend order range.
#[test]
fn trend_order_descriptions_include_zero() {
    let sdl = rendered_sdl();
    let query = definition(&sdl, "type Query {");
    for field in ["topTimeSeries(", "topTimeSeriesOfCluster("] {
        let arguments = query.split_once(field).unwrap().1;
        let order_description = arguments.split_once("trendiOrder:").unwrap().0;
        assert!(
            order_description.contains("from 0 to 20 inclusive"),
            "{field}: {REGENERATE}"
        );
    }
}

/// The deletion result query and types match the GraphQL API contract.
#[test]
fn customer_data_deletion_result_contract() {
    let sdl = rendered_sdl();
    assert!(
        definition(&sdl, "type Query {").contains(
            "\n\tcustomerDataDeletionResult(customerId: ID!): CustomerDataDeletionResult\n"
        )
    );
    for (header, fields) in [
        (
            "type CustomerDataDeletionResult {",
            vec![
                "customerId: ID!",
                "serviceResults: [CustomerDataDeletionServiceResult!]!",
            ],
        ),
        (
            "type CustomerDataDeletionServiceResult {",
            vec![
                "service: CustomerDataDeletionService!",
                "hostFqdns: [String!]!",
                "status: CustomerDataDeletionStatus!",
                "requestedAt: DateTime!",
                "completedAt: DateTime",
                "error: String",
            ],
        ),
        (
            "enum CustomerDataDeletionService {",
            vec![
                "REVIEW",
                "SENSOR",
                "SEMI_SUPERVISED",
                "DATA_STORE",
                "MODULE_REMOVAL",
            ],
        ),
        (
            "enum CustomerDataDeletionStatus {",
            vec!["IN_PROGRESS", "SUCCEEDED", "FAILED"],
        ),
    ] {
        let actual: Vec<_> = definition(&sdl, header)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(actual, fields, "{header}");
    }
}

/// Event filters take `detectionModels` as the `DetectionModel` enum, which
/// mirrors review-protocol's detection models, and
/// `eventCountsByDetectionModel` counts into the same enum, so a counted value
/// can be passed back as a filter.
#[test]
fn detection_models_cross_as_the_detection_model_enum() {
    let sdl = rendered_sdl();

    for header in [
        "input EventListFilterInput {",
        "input EventStandardFilterInput {",
    ] {
        let input = definition(&sdl, header);
        for field in [
            "\n\tdetectionModels: [DetectionModel!]\n",
            "\n\trawEventKinds: [RawEventKind!]\n",
            "\n\tscoreMin: Float\n",
            "\n\tscoreMax: Float\n",
        ] {
            assert!(input.contains(field), "{header} {field}: {REGENERATE}");
        }
        for removed in ["\n\tkinds:", "\n\tlevels:"] {
            assert!(!input.contains(removed), "{header} {removed}: {REGENERATE}");
        }
    }

    let values: Vec<_> = definition(&sdl, "enum DetectionModel {")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(
        values,
        [
            "WATCHLIST_MATCH",
            "CRYPTOCURRENCY_MINING_POOL",
            "LOCKY_RANSOMWARE",
            "SUSPICIOUS_TLS_TRAFFIC",
            "PORT_SCAN",
            "MULTI_HOST_PORT_SCAN",
            "EXTERNAL_DDOS",
            "RDP_BRUTE_FORCE",
            "FTP_BRUTE_FORCE",
            "LDAP_BRUTE_FORCE",
            "REPEATED_HTTP_SESSIONS",
            "FTP_PLAIN_TEXT",
            "LDAP_PLAIN_TEXT",
            "NON_BROWSER",
            "TOR_EXIT_NODE",
            "DOMAIN_GENERATION_ALGORITHM",
            "DNS_COVERT_CHANNEL",
            "UNUSUAL_DESTINATION_PATTERN",
            "LABEL_DB_MATCH",
            "FAR_OUTLIER",
            "WINDOW_OUTLIER",
        ],
        "{REGENERATE}"
    );

    let counter = definition(&sdl, "type DetectionModelEventCounter {");
    assert!(
        counter.contains("\n\tvalues: [DetectionModel!]!\n"),
        "{REGENERATE}"
    );
    assert!(counter.contains("\n\tcounts: [Int!]!\n"), "{REGENERATE}");
    let query = definition(&sdl, "type Query {");
    assert!(
        query.contains(
            "\n\teventCountsByDetectionModel(filter: EventListFilterInput!, first: Int!): \
             DetectionModelEventCounter!\n"
        ),
        "{REGENERATE}"
    );
    assert!(
        query.contains(
            "\n\teventCountsByIpAddressPairAndDetectionModel(filter: EventListFilterInput!, \
             first: Int!): StringEventCounter!\n"
        ),
        "{REGENERATE}"
    );
    assert!(
        query.contains(
            "\n\tdetectionEventsByRawEventKeys(keys: [RawEventKeyInput!]!): \
             [[DetectionEvent!]!]!\n"
        ),
        "{REGENERATE}"
    );
}

/// The detection event API has one object type, and the shapes it replaced
/// are gone without a compatibility layer.
#[test]
fn schema_has_one_detection_event_type_and_no_replaced_shapes() {
    let sdl = rendered_sdl();
    for removed in [
        "interface Event ",
        "enum EventKind ",
        "enum ThreatLevel ",
        "type EventKindEventCounter ",
        "type ThreatLevelEventCounter ",
        "type DnsCovertChannel ",
        "type BlocklistConn ",
        "type HttpThreat ",
        "type WindowsThreat ",
        "type NetworkThreat ",
        "type ExtraThreat ",
        "type TorConnection ",
        "input ConfidenceInput ",
        "eventCountsByLevel",
        "eventCountsByKind",
        "confidenceMin",
        "confidenceMax",
    ] {
        assert!(!sdl.contains(removed), "{removed:?}: {REGENERATE}");
    }
    // The threat level is gone; the only field of that name is the level of
    // a Windows event log record.
    assert!(
        !definition(&sdl, "type DetectionEvent {").contains("\tlevel:"),
        "{REGENERATE}"
    );
    assert_eq!(sdl.matches("\tlevel:").count(), 1, "{REGENERATE}");
    assert!(
        definition(&sdl, "type WindowsEventLogBody {").contains("\n\tlevel: Int\n"),
        "{REGENERATE}"
    );
    // A detection event no longer carries a learning method; the only field of
    // that name is the static property of a detection model.
    assert!(
        !definition(&sdl, "type DetectionEvent {").contains("learningMethod"),
        "{REGENERATE}"
    );
    assert_eq!(sdl.matches("\tlearningMethod:").count(), 1, "{REGENERATE}");
    assert!(
        definition(&sdl, "type DetectionModelProperties {")
            .contains("\n\tlearningMethod: LearningMethod!\n"),
        "{REGENERATE}"
    );
    for header in ["enum ThreatRole {", "enum EndpointRole {"] {
        assert!(sdl.contains(header), "{header}: {REGENERATE}");
    }
    assert_eq!(
        definition(&sdl, "enum ThreatRole {")
            .split_whitespace()
            .collect::<Vec<_>>(),
        ["ACTOR", "TARGET"]
    );
    assert_eq!(
        definition(&sdl, "enum EndpointRole {")
            .split_whitespace()
            .collect::<Vec<_>>(),
        ["SOURCE", "DESTINATION"]
    );
}

/// Returns the members of `union name` in schema order.
fn union_members(sdl: &str, name: &str) -> Vec<String> {
    let prefix = format!("union {name} = ");
    let line = sdl
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no union {name}"));
    line[prefix.len()..]
        .split(" | ")
        .map(ToString::to_string)
        .collect()
}

/// Returns the values of `enum name` in schema order, leaving out their
/// descriptions.
fn enum_values(sdl: &str, name: &str) -> Vec<String> {
    let header = format!("enum {name} {{");
    let mut lines = sdl
        .lines()
        .skip_while(|line| *line != header)
        .skip(1)
        .take_while(|line| *line != "}");
    let mut values = Vec::new();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line == "\"\"\"" {
            for line in lines.by_ref() {
                if line.trim() == "\"\"\"" {
                    break;
                }
            }
        } else if !line.starts_with('"') {
            values.push(line.to_string());
        }
    }
    assert!(!values.is_empty(), "no enum {name}");
    values
}

/// The members and values added for Clumit Endpoint come after every
/// existing one.
#[test]
fn endpoint_members_and_values_come_last() {
    let sdl = rendered_sdl();

    let members = union_members(&sdl, "PrimarySubject");
    assert_eq!(
        members,
        [
            "HostSubject",
            "ClusterSubject",
            "SensorSubject",
            "NetworkSubject",
            "SentaEndpointSubject",
        ]
    );

    let members = union_members(&sdl, "RawEventBody");
    assert_eq!(members.len(), 44);
    assert_eq!(members[..2], ["ConnBody", "DnsBody"]);
    assert_eq!(
        members[34..],
        [
            "Netflow5Body",
            "Netflow9Body",
            "DriverLoadBody",
            "CreateRemoteThreadBody",
            "RawAccessReadBody",
            "ProcessAccessBody",
            "RegistryObjectAddDelBody",
            "WindowsEventLogBody",
            "JournaldBody",
            "AuditdBody",
        ]
    );

    let values = enum_values(&sdl, "RawEventKind");
    assert_eq!(
        values[values.len() - 8..],
        [
            "DRIVER_LOAD",
            "CREATE_REMOTE_THREAD",
            "RAW_ACCESS_READ",
            "PROCESS_ACCESS",
            "REGISTRY_OBJECT_ADD_DEL",
            "WINDOWS_EVENT_LOG",
            "JOURNALD",
            "AUDITD",
        ]
    );

    let values = enum_values(&sdl, "DetectionModelSubjectKind");
    assert_eq!(values.last().map(String::as_str), Some("ENDPOINT"));
}
