# certinv

日本語版はこちら: [README.md](README.md)

**TLS certificate inventory for domains you own**

certinv narrows down reachable hosts from subdomains found through Certificate
Transparency, collects their certificates, tracks expiration, and sends alerts
before they expire.

> **Under development.** The `scan`, `serve`, and `check` commands are currently
> implemented. `serve` provides a Prometheus exporter and a web UI for reviewing
> the inventory and performing limited operational actions.
> See [docs/status.md](docs/status.md) and [docs/design.md](docs/design.md) for details.
> Developer verification steps are in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Background

The CA/Browser Forum Ballot SC-081v3 progressively reduces the maximum lifetime
of public TLS certificates to 200 days in March 2026, 100 days in March 2027,
and 47 days in March 2029.

As renewal cycles move from once a year to eight times a year, the first problem
is not renewal itself but **not knowing how many certificates your organization
has**. certinv automates that inventory.

## Scope

certinv is intended for inventorying **domains you own and administer**.

- Only apex domains explicitly registered in the configuration file are processed.
- An arbitrary domain cannot be supplied using only a command-line argument.
- Probe concurrency and rate limits use conservative defaults.

Investigating third-party domains is outside the intended use of this tool.

## Main features

- Process only configured apex domains
- Discovery sources:
  - `crtname`: fetch candidate hostnames from the crt.name API
  - `manual`: read manually registered hosts from the configuration
  - `zone`: read hosts from DNS zone files
- Liveness checks through DNS resolution
- TLS probing and certificate metadata collection
- Optionally make an HTTPS GET and record the host's HTTP status
- Store hosts, certificates, and events in SQLite
- Warn / alert / expired / misconfigured decisions based on remaining lifetime ratio
- Slack / webhook notifications on state transitions
- `serve` mode, Prometheus `/metrics`, and a web UI for inventory review and limited operations

## Usage

Go 1.25 or later is required.

### Quick start

For a first run, follow these steps from configuration through continuous operation.

1. Copy the example configuration:

   ```sh
   cp config.example.yaml config.yaml
   ```

2. Replace `apexes` in `config.yaml` with domains you own and administer.
   Only registered apexes are processed. `example.com` is heavily used for
   test and placeholder certificates worldwide in Certificate Transparency logs.
   Leaving it unchanged while enabling crt.name discovery can discover thousands
   of unrelated hosts. Always replace it with a real domain you own before scanning.

3. Run a one-off scan:

   ```sh
   go run ./cmd/certinv scan --config config.yaml
   ```

4. Start the resident service, including scheduled scans, the web UI, and metrics:

   ```sh
   go run ./cmd/certinv serve --config config.yaml
   ```

5. Open http://localhost:9101/ui in a browser.

### Installing the command

```sh
go install ./cmd/certinv
```

If `GOBIN` is unset, the binary is normally built in `GOPATH/bin` (typically
`~/go/bin`). Add that directory to `PATH`, or create a symlink in a directory
already on `PATH` such as `~/.local/bin`, to run `certinv scan`, `certinv serve`,
and `certinv check` directly.

### Command usage

One-off `scan`:

```sh
go run ./cmd/certinv scan --config config.yaml
```

Resident `serve`:

```sh
go run ./cmd/certinv serve --config config.yaml
```

### Inventory tab

- Run a manual scan and acknowledge events / alerts. Manual and scheduled scans use saved discovery settings and do not apply per-run overrides.
- `Run scan now` scans configured apexes immediately. Concurrent runs are rejected; while polling, the UI shows Scanning and disables the button. After 60 seconds it asks you to reload manually.
- Shows the apexes currently enabled for crt.name discovery.
- `Suppress` removes a host from the list and future discovery / scans; `Unsuppress` restores it.
- `All clear` suppresses all currently displayed hosts.
- `Purge` / `Purge all` permanently remove suppressed host records and certificate links, but do not remove certificate metadata itself.
- `/ui/export.csv` downloads certificate metadata equivalent to the inventory. The Inventory table can be filtered by hostname and certificate state.
- Certificate issuance, renewal, and private-key operations are not performed.

### Sources & Targets tab

- Add and remove apexes / manual hosts as DB-managed overlays. A DB-managed manual host's port can be edited without changing its hostname.
- `apexes` / `manual_hosts` from `config.yaml` remain the authoritative base and cannot be changed or removed from the UI.
- An apex scopes automatic CT-log subdomain discovery when crt.name is enabled; a manual host adds a host not found in CT logs and is not an apex-discovery filter.
- Save crt.name enablement, its endpoint, per-apex crt.name enablement, and added zone files as DB-managed overlays. The global crt.name switch takes precedence: when OFF, all crt.name discovery is disabled regardless of per-apex settings. Per-apex settings default to ON.
- Run a lookup against the configured crt.name endpoint for one selected apex from the current apex list (config plus DB-managed apexes), then add selected candidates as managed manual hosts on port 443.
- Lookup only fetches candidates; it does not perform DNS resolution or TLS probing. Lookup now uses the form's enabled / endpoint values without saving them. Save crt.name settings are used by future scheduled scans and Run scan now and are shown in the UI.
- Already registered manual hostnames are excluded from candidates; the candidate list supports hostname filtering, select-all, and clear-all.
- For zone-file additions, only existing files below `discovery.zone.allowed_dir` can be selected.

### Authentication

When both `exporter.basic_auth.username` and `exporter.basic_auth.password` are
set, `/metrics` and `/ui` are protected with Basic Authentication. With both
empty, authentication is disabled for backward compatibility.

```yaml
exporter:
  listen: :9101
  basic_auth:
    username: operator
    password: change-me
```

When exposing the `serve` HTTP server externally, place it behind a reverse
proxy that provides TLS termination and access control.

### Grafana dashboard

An importable sample for Prometheus data from `/metrics` is provided at
[dashboards/certinv.json](dashboards/certinv.json). certinv does not run or
manage Grafana; this JSON is only an import template.

One-off FQDN check:

```sh
go run ./cmd/certinv check --config config.example.yaml www.example.com
go run ./cmd/certinv check --config config.example.yaml --port 8443 app.example.com
```

The FQDN supplied to `check` must be under an apex in the configuration file;
arbitrary domains outside the apex are rejected. `check` is read-only, prints
certificate metadata to standard output, and does not persist to the database or
change configuration.

## What certinv does not do

- Issue or renew certificates (use certbot / lego / cert-manager)
- Handle private keys. Even with UI operations, private keys are never read, generated, or stored.

## License

MIT License ([LICENSE](LICENSE))
