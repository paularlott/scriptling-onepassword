# scriptling-onepassword

1Password [service account](https://developer.1password.com/docs/service-accounts/) support for [Scriptling](https://github.com/paularlott/scriptling)'s `onepassword` secret provider.

Scriptling's `onepassword` provider talks to 1Password Connect out of the box. This extension adds service accounts, so a provider can read secrets with a single `ops_...` token and no Connect server:

```toml
[[secrets.provider]]
provider = "onepassword"
alias = "op"
service_account_token = "ops_..."
```

It uses the official [1Password Go SDK](https://github.com/1password/onepassword-sdk-go), which adds about 14 MB to a binary, so it's a separate module: only programs that import it link it. Without it, a `service_account_token` config fails with an error naming this extension.

Paths and fields work the same as with Connect: `vault/item` by name or ID, the field defaulting to `password` and falling back to `credential` and the item's notes. A read is normally one request to 1Password.

## Embedding Scriptling

Import the package for its side effect:

```go
import _ "github.com/paularlott/scriptling-onepassword"
```

Every `secretprovider.Config` with `ServiceAccountToken` set then builds a service account provider. Set `onepassword.IntegrationName` and `IntegrationVersion` before first use to identify your application to 1Password.

## A Scriptling CLI with service accounts

Scriptling releases include two CLI builds with this extension compiled in:

```sh
brew install paularlott/tap/scriptling-onepassword        # with the database plugins
brew install paularlott/tap/scriptling-slim-onepassword   # without them
```

The zips (`scriptling-onepassword-<os>-<arch>.zip`, `scriptling-slim-onepassword-<os>-<arch>.zip`) are on the [Scriptling releases page](https://github.com/paularlott/scriptling/releases). The standard `scriptling` and `scriptling-slim` builds support 1Password Connect only.

To build your own instead, make a module with this `main.go`:

```go
package main

import (
	"github.com/paularlott/scriptling/scriptling-cli/scriptlingcmd"
	_ "github.com/paularlott/scriptling-onepassword"
)

func main() { scriptlingcmd.Main() }
```

then:

```sh
go mod init example.com/scriptling
go mod tidy
go build -o scriptling .
```

Add the database drivers by building with the same tags as the released CLI, for example `-tags plugin_sqlite,plugin_sql,plugin_valkey,plugin_badgerdb`.

## Service account or Connect?

A service account needs only its token. Each new process starts cold, though: its first secret read loads 1Password's engine and signs in (about a second), and each secret is fetched from 1Password once per process, counting against the service account's rate limits. That suits long-running programs, interactive use and occasional scripts. For something that starts many times a minute, 1Password Connect, which keeps a synced copy of your vaults on your own server, is the better fit.

A service account can only read the vaults it was given when it was created, and can't be given your built-in Personal, Private or Employee vault, or the default Shared vault.

## License

MIT — see [LICENSE.txt](LICENSE.txt). Contributions are covered by the [Scriptling CLA](CONTRIBUTOR_LICENSE_AGREEMENT.md); see [CONTRIBUTING.md](CONTRIBUTING.md).
