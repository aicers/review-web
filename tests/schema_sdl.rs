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
