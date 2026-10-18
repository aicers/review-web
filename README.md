# review-web

This project aims to provide an easy-to-use interface for the REview system,
allowing users to manage and analyze events from various sensors. The web
interface is built using modern web technologies, and it exposes a GraphQL API
for flexible data querying and manipulation.

[![Coverage Status](https://codecov.io/gh/aicers/review-web/branch/main/graphs/badge.svg)](https://codecov.io/gh/aicers/review-web)

## Generate schema.graphql

Generate the GraphQL SDL as follows:

```sh
cargo run --example schema_sdl > schema.graphql
```

The example writes the schema to stdout, so redirect it to the desired output
file.

`schema.graphql` at the repository root is tracked, and `tests/schema_sdl.rs`
compares the rendered schema against it, so a change to the GraphQL surface
fails the test until the artifact is regenerated with the command above and the
regenerated file is committed alongside the change. That is what turns a schema
change into a reviewable diff.

## License

Copyright 2018-2023 Petabi, Inc.  
Copyright 2023-2026 ClumL Inc.

Licensed under [Apache License, Version 2.0][apache-license] (the "License");
you may not use this crate except in compliance with the License.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See [LICENSE](LICENSE) for
the specific language governing permissions and limitations under the License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0
license][apache-license], shall be licensed as above, without any additional
terms or conditions.

[apache-license]: https://www.apache.org/licenses/LICENSE-2.0
