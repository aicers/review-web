//! Holds the committed schema artifact honest.
//!
//! `examples/schema_sdl.rs` is `required-features = ["auth-mtls"]` and
//! `#![cfg(feature = "auth-mtls")]`, so `schema.graphql` is the mTLS schema and
//! this test is gated the same way. Under `auth-jwt` the rendered schema is a
//! different one, and comparing it against the committed file would fail for a
//! reason that is not a schema change.
#![cfg(feature = "auth-mtls")]

use review_web::graphql::{Mutation, Query, Schema, Subscription};

/// The committed artifact, read at compile time so a missing file is a build
/// failure rather than a test that silently passes.
const COMMITTED_SDL: &str = include_str!("../schema.graphql");

const REGENERATE: &str = "the GraphQL schema changed. If the change is deliberate, regenerate the \
                          committed artifact with:\n\n    cargo run --no-default-features \
                          --features auth-mtls --example schema_sdl > schema.graphql\n";

fn rendered_sdl() -> String {
    Schema::build(
        Query::default(),
        Mutation::default(),
        Subscription::default(),
    )
    .finish()
    .sdl()
}

#[test]
fn committed_sdl_matches_rendered_schema() {
    // Compared with `assert!` rather than `assert_eq!`: the schema is well over
    // a hundred kilobytes, and printing both copies buries the one line that
    // says what to do about it.
    assert!(rendered_sdl() == COMMITTED_SDL, "{REGENERATE}");
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
