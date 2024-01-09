# review-web

This project aims to provide an easy-to-use interface for the REview system,
allowing users to manage and analyze events from various sources. The web
interface is built using modern web technologies, and it exposes a GraphQL API
for flexible data querying and manipulation.

[![Coverage Status](https://codecov.io/gh/aicers/review-web/branch/main/graphs/badge.svg)](https://codecov.io/gh/aicers/review-web)

## Minireview

### Build

Build as follows:

```sh
cargo build --example minireview
```

### Test

Test as follows:

```sh
target/debug/examples/minireview <path to a config file>
```

The config file has the following options:

```toml
backup_dir = "/path/to/backup"              # path to a backup directory
ca_certs = ["/path/to/cert.pem"]            # paths to CA certificate files
cert = "/path/to/cert.pem"                  # path to a certificate file
data_dir = "/path/to/data"                  # path to a RocksDB data directory
database_url = "postgres://id:pw@host/db"   # PostgreSQL URL
graphql_srv_addr = "127.0.0.1:8442"         # GraphQL address
htdocs_dir = "/path/to/htdocs"              # path to a directory for web files
ip2location = "/path/to/IP2LOCATON"         # path to a IP2LOCATION file
key = "/path/to/key.pem"                    # path to a key file
log_dir = "/path/to/log"                    # path to a log directory
redis_log_addr = "127.0.0.1:6379"           # address to redis server
redis_log_agent_id = "review@localhost"     # agent id to send log to redis server

[[reverse_proxies]]
base = "archive"                            # proxy name for Giganto
uri = "https://localhost:8443/graphql"      # Giganto's GraphQL address

[[reverse_proxies]]
base = "tivan"                              # proxy name for Tivan
uri = "https://localhost:8444/graphql"      # Tivan's GraphQL address
```

## License

Copyright 2018-2023 Petabi, Inc.

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

[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
