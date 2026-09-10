#![cfg(feature = "auth-mtls")]

use review_web::graphql::{Mutation, Query, Schema, Subscription};

fn main() {
    let schema = Schema::build(
        Query::default(),
        Mutation::default(),
        Subscription::default(),
    )
    .finish();

    // `sdl()` already ends in a newline, so this prints the artifact byte for
    // byte: `tests/schema_sdl.rs` compares the committed file against the same
    // string, and a trailing newline added here would make that comparison fail.
    print!("{}", schema.sdl());
}
