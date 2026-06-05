#![cfg(feature = "auth-mtls")]

use review_web::graphql::{Mutation, Query, Schema, Subscription};

fn main() {
    let schema = Schema::build(
        Query::default(),
        Mutation::default(),
        Subscription::default(),
    )
    .finish();

    println!("{}", schema.sdl());
}
