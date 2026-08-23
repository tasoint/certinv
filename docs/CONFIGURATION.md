# Configuration

`config.yaml` is YAML. Copy `config.example.yaml` and change the apexes to
domains you own and administer.

## `apexes`

The eTLD+1 domains that define the scope of discovery and `check`. Hosts outside
these apexes are rejected.

## `manual_hosts`

Hosts that should be checked even when they do not appear in Certificate
Transparency. Each entry has a hostname, port, and apex.

## `discovery`

Select discovery sources with `sources`.

- `crtname` uses the configured `endpoint` to find CT-log hostnames. Its UI
  settings are stored separately in the database.
- `manual` uses `manual_hosts`.
- `zone` reads the configured `files`; `allowed_dir` limits files selectable
  through the UI.

## `probe`

Controls probe concurrency and connection / TLS handshake timeouts.
`http_check: true` additionally performs one HTTPS GET after the TLS probe and
records its status code. It is disabled by default.

## `thresholds`

Defines the remaining-lifetime ratio and minimum-day thresholds for `warn` and
`alert`. Certificate states are evaluated against the certificate's lifetime.

## `storage`

`dsn` is the SQLite database path. The database stores inventory, certificate
metadata, events, and UI-managed discovery settings.

## `schedule`

`interval` controls how often `serve` runs a scheduled scan.

## `notifiers`

Configure notification destinations such as Slack or webhooks. Notifications
are sent on relevant state transitions.

## `exporter`

`listen` sets the HTTP address for the web UI and Prometheus `/metrics`.
Set both `basic_auth.username` and `basic_auth.password` to protect these
endpoints with Basic Authentication. Leaving both empty disables authentication.
