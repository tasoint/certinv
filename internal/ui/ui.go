package ui

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/store"
)

type Handler struct {
	store    store.Store
	template *template.Template
	now      func() time.Time
	scanner  ScanTrigger
	config   ConfigTargets
}

type ScanTrigger interface {
	TriggerScan() bool
}

type Option func(*Handler)

type ConfigTargets struct {
	Apexes      []string
	ManualHosts []config.ManualHost
}

func WithScanTrigger(scanner ScanTrigger) Option {
	return func(h *Handler) {
		h.scanner = scanner
	}
}

func WithConfigTargets(apexes []string, manualHosts []config.ManualHost) Option {
	return func(h *Handler) {
		h.config = ConfigTargets{
			Apexes:      append([]string{}, apexes...),
			ManualHosts: append([]config.ManualHost{}, manualHosts...),
		}
	}
}

func New(st store.Store, opts ...Option) (*Handler, error) {
	tmpl, err := template.New("inventory").Funcs(template.FuncMap{
		"shortFingerprint": shortFingerprint,
		"splitSAN":         splitSAN,
		"fallback":         fallback,
	}).Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		store:    st,
		template: tmpl,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(handler)
	}
	return handler, nil
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/", h.redirectRoot)
	mux.HandleFunc("/ui", h.serveInventory)
	mux.HandleFunc("/ui/export.csv", h.serveExportCSV)
	mux.HandleFunc("/ui/scan", h.serveScan)
	mux.HandleFunc("/ui/apexes", h.serveAddApex)
	mux.HandleFunc("/ui/apexes/delete", h.serveDeleteApex)
	mux.HandleFunc("/ui/manual-hosts", h.serveAddManualHost)
	mux.HandleFunc("/ui/manual-hosts/delete", h.serveDeleteManualHost)
}

func (h *Handler) redirectRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/ui", http.StatusFound)
}

func (h *Handler) serveInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := h.store.InventorySnapshot(r.Context())
	if err != nil {
		http.Error(w, "failed to load inventory", http.StatusInternalServerError)
		return
	}
	data := pageData{
		GeneratedAt: h.now().UTC().Format(time.RFC3339),
		Rows:        snapshot.Rows,
	}
	if targets, err := h.targetRows(r.Context()); err == nil {
		data.Targets = targets
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.template.Execute(w, data); err != nil {
		http.Error(w, "failed to render inventory", http.StatusInternalServerError)
	}
}

func (h *Handler) serveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.scanner == nil {
		http.Error(w, "scan trigger is not configured", http.StatusServiceUnavailable)
		return
	}
	if !h.scanner.TriggerScan() {
		http.Error(w, "scan is already running", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("scan accepted\n"))
}

func (h *Handler) serveAddApex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	apex, err := validateApex(r.FormValue("apex"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.store.AddManagedApex(r.Context(), apex, h.now()); err != nil {
		http.Error(w, "failed to add apex", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui", http.StatusSeeOther)
}

func (h *Handler) serveDeleteApex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	apex, err := validateApex(r.FormValue("apex"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.store.DeleteManagedApex(r.Context(), apex); err != nil {
		http.Error(w, "failed to delete apex", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui", http.StatusSeeOther)
}

func (h *Handler) serveAddManualHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	host, err := h.validateManualHost(r.Context(), r.FormValue("hostname"), r.FormValue("port"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.store.AddManagedManualHost(r.Context(), host, h.now()); err != nil {
		http.Error(w, "failed to add manual host", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui", http.StatusSeeOther)
}

func (h *Handler) serveDeleteManualHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	hostname := discover.NormalizeHostname(r.FormValue("hostname"))
	port, err := parsePort(r.FormValue("port"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.store.DeleteManagedManualHost(r.Context(), hostname, port); err != nil {
		http.Error(w, "failed to delete manual host", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui", http.StatusSeeOther)
}

func (h *Handler) serveExportCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := h.store.InventorySnapshot(r.Context())
	if err != nil {
		http.Error(w, "failed to load inventory", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="certinv-inventory.csv"`)
	writer := csv.NewWriter(w)
	if err := writer.Write(csvHeader); err != nil {
		http.Error(w, "failed to write inventory csv", http.StatusInternalServerError)
		return
	}
	for _, row := range snapshot.Rows {
		if err := writer.Write(csvRow(row)); err != nil {
			http.Error(w, "failed to write inventory csv", http.StatusInternalServerError)
			return
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		http.Error(w, "failed to write inventory csv", http.StatusInternalServerError)
	}
}

type pageData struct {
	GeneratedAt string
	Rows        []store.InventoryRow
	Targets     targetRows
}

type targetRows struct {
	Apexes      []targetApex
	ManualHosts []targetManualHost
}

type targetApex struct {
	Apex      string
	Origin    string
	CanDelete bool
}

type targetManualHost struct {
	Hostname  string
	Port      int
	Apex      string
	Origin    string
	CanDelete bool
}

func shortFingerprint(fingerprint string) string {
	if len(fingerprint) <= 12 {
		return fingerprint
	}
	return fingerprint[:12]
}

func splitSAN(sanJSON string) []string {
	sanJSON = strings.TrimSpace(sanJSON)
	if sanJSON == "" || sanJSON == "[]" {
		return nil
	}
	var names []string
	if err := json.Unmarshal([]byte(sanJSON), &names); err != nil {
		return nil
	}
	return names
}

func fallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (h *Handler) targetRows(ctx context.Context) (targetRows, error) {
	rows := targetRows{}
	for _, apex := range h.config.Apexes {
		rows.Apexes = append(rows.Apexes, targetApex{Apex: discover.NormalizeHostname(apex), Origin: "config"})
	}
	for _, host := range h.config.ManualHosts {
		hostname := discover.NormalizeHostname(host.Hostname)
		apex, _ := discover.ApexFor(hostname, h.config.Apexes)
		rows.ManualHosts = append(rows.ManualHosts, targetManualHost{
			Hostname: hostname,
			Port:     normalizedPort(host.Port),
			Apex:     apex,
			Origin:   "config",
		})
	}
	managed, err := h.store.ManagedTargets(ctx)
	if err != nil {
		return targetRows{}, err
	}
	for _, apex := range managed.Apexes {
		rows.Apexes = append(rows.Apexes, targetApex{Apex: apex.Apex, Origin: apex.Source, CanDelete: true})
	}
	for _, host := range managed.ManualHosts {
		rows.ManualHosts = append(rows.ManualHosts, targetManualHost{
			Hostname:  host.Hostname,
			Port:      host.Port,
			Apex:      host.Apex,
			Origin:    host.Source,
			CanDelete: true,
		})
	}
	return rows, nil
}

func validateApex(value string) (string, error) {
	apex := discover.NormalizeHostname(value)
	if apex == "" {
		return "", fmt.Errorf("apex is required")
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(apex)
	if err != nil || etld1 != apex {
		return "", fmt.Errorf("apex must be a registrable eTLD+1 domain")
	}
	return apex, nil
}

func (h *Handler) validateManualHost(ctx context.Context, hostnameValue, portValue string) (discover.Host, error) {
	hostname := discover.NormalizeHostname(hostnameValue)
	if hostname == "" {
		return discover.Host{}, fmt.Errorf("hostname is required")
	}
	port, err := parsePort(portValue)
	if err != nil {
		return discover.Host{}, err
	}
	apexes := append([]string{}, h.config.Apexes...)
	managed, err := h.store.ManagedTargets(ctx)
	if err != nil {
		return discover.Host{}, err
	}
	for _, apex := range managed.Apexes {
		apexes = append(apexes, apex.Apex)
	}
	apex, ok := discover.ApexFor(hostname, apexes)
	if !ok {
		return discover.Host{}, fmt.Errorf("hostname is outside configured or managed apexes")
	}
	return discover.Host{Hostname: hostname, Port: port, Apex: apex, Source: "managed"}, nil
}

func parsePort(value string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return discover.DefaultPort, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return port, nil
}

func normalizedPort(port int) int {
	if port == 0 {
		return discover.DefaultPort
	}
	return port
}

var csvHeader = []string{
	"host",
	"port",
	"apex",
	"source",
	"host_status",
	"cert_state",
	"not_before",
	"not_after",
	"issuer_cn",
	"issuer_org",
	"subject_cn",
	"fingerprint",
	"san",
	"chain_complete",
	"hostname_match",
	"first_seen_at",
	"last_resolved_at",
	"last_probed_at",
	"last_seen_at",
	"observed_at",
}

func csvRow(row store.InventoryRow) []string {
	return []string{
		row.Hostname,
		strconv.Itoa(row.Port),
		row.Apex,
		row.Source,
		row.HostStatus,
		row.CertState,
		row.NotBefore,
		row.NotAfter,
		row.IssuerCN,
		row.IssuerOrg,
		row.SubjectCN,
		row.Fingerprint,
		strings.Join(splitSAN(row.SANNames), ";"),
		strconv.FormatBool(row.ChainComplete),
		strconv.FormatBool(row.HostnameMatch),
		row.FirstSeenAt,
		row.LastResolvedAt,
		row.LastProbedAt,
		row.LastSeenAt,
		row.ObservedAt,
	}
}

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>certinv inventory</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #182026;
      --muted: #65717d;
      --line: #d8dee4;
      --warn: #9a6700;
      --alert: #cf222e;
      --ok: #1a7f37;
      --misconfigured: #8250df;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      padding: 20px 24px 12px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    h1 {
      margin: 0;
      font-size: 22px;
      font-weight: 650;
    }
    .meta {
      margin-top: 4px;
      color: var(--muted);
      font-size: 13px;
    }
    .actions {
      margin-top: 10px;
    }
    .button {
      display: inline-block;
      padding: 6px 10px;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: #eef2f6;
      color: var(--text);
      text-decoration: none;
      font-size: 13px;
      font-weight: 650;
    }
    button.button { cursor: pointer; }
    main {
      padding: 20px 24px 28px;
    }
    section {
      margin-bottom: 20px;
    }
    h2 {
      margin: 0 0 10px;
      font-size: 16px;
    }
    .forms {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 10px;
    }
    input {
      padding: 6px 8px;
      border: 1px solid var(--line);
      border-radius: 4px;
      background: var(--panel);
      color: var(--text);
      font: inherit;
    }
    .table-wrap {
      overflow: auto;
      border: 1px solid var(--line);
      background: var(--panel);
    }
    table {
      width: 100%;
      min-width: 1120px;
      border-collapse: collapse;
    }
    th, td {
      padding: 9px 10px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      white-space: nowrap;
    }
    th {
      position: sticky;
      top: 0;
      background: #eef2f6;
      color: #38424d;
      font-size: 12px;
      font-weight: 650;
      text-transform: uppercase;
    }
    tr:last-child td { border-bottom: 0; }
    .muted { color: var(--muted); }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
    }
    .state {
      display: inline-block;
      min-width: 78px;
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid var(--line);
      text-align: center;
      font-size: 12px;
      font-weight: 650;
    }
    .state-healthy { color: var(--ok); border-color: #8fd19e; background: #dafbe1; }
    .state-warn { color: var(--warn); border-color: #d4a72c; background: #fff8c5; }
    .state-alert, .state-expired { color: var(--alert); border-color: #ff8182; background: #ffebe9; }
    .state-misconfigured { color: var(--misconfigured); border-color: #d8b9ff; background: #fbefff; }
    .san {
      max-width: 260px;
      white-space: normal;
      color: var(--muted);
    }
    .empty {
      padding: 30px;
      color: var(--muted);
      background: var(--panel);
      border: 1px solid var(--line);
    }
  </style>
</head>
<body>
  <header>
    <h1>certinv inventory</h1>
    <div class="meta">Generated at {{.GeneratedAt}}. Certificates and keys are not modified from this UI.</div>
    <div class="actions">
      <form method="post" action="/ui/scan" style="display:inline"><button class="button" type="submit">Run scan now</button></form>
      <a class="button" href="/ui/export.csv">Download CSV</a>
    </div>
  </header>
  <main>
    <section>
      <h2>Targets</h2>
      <div class="forms">
        <form method="post" action="/ui/apexes">
          <input name="apex" placeholder="example.com" required>
          <button class="button" type="submit">Add apex</button>
        </form>
        <form method="post" action="/ui/manual-hosts">
          <input name="hostname" placeholder="host.example.com" required>
          <input name="port" placeholder="443">
          <button class="button" type="submit">Add manual host</button>
        </form>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Type</th><th>Target</th><th>Apex</th><th>Origin</th><th>Action</th></tr></thead>
          <tbody>
            {{range .Targets.Apexes}}
            <tr>
              <td>apex</td><td>{{.Apex}}</td><td>{{.Apex}}</td><td>{{.Origin}}</td>
              <td>{{if .CanDelete}}<form method="post" action="/ui/apexes/delete"><input type="hidden" name="apex" value="{{.Apex}}"><button class="button" type="submit">Delete</button></form>{{else}}<span class="muted">config</span>{{end}}</td>
            </tr>
            {{end}}
            {{range .Targets.ManualHosts}}
            <tr>
              <td>manual</td><td>{{.Hostname}}:{{.Port}}</td><td>{{.Apex}}</td><td>{{.Origin}}</td>
              <td>{{if .CanDelete}}<form method="post" action="/ui/manual-hosts/delete"><input type="hidden" name="hostname" value="{{.Hostname}}"><input type="hidden" name="port" value="{{.Port}}"><button class="button" type="submit">Delete</button></form>{{else}}<span class="muted">config</span>{{end}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>
    {{if .Rows}}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Host status</th>
            <th>Cert state</th>
            <th>Not after</th>
            <th>Issuer</th>
            <th>Subject CN</th>
            <th>Fingerprint</th>
            <th>SAN</th>
            <th>Last probed</th>
            <th>Observed</th>
            <th>Checks</th>
          </tr>
        </thead>
        <tbody>
          {{range .Rows}}
          <tr>
            <td><strong>{{.Hostname}}</strong>:{{.Port}}<div class="muted">{{.Apex}} / {{.Source}}</div></td>
            <td>{{.HostStatus}}</td>
            <td><span class="state state-{{fallback .CertState "unknown"}}">{{fallback .CertState "unknown"}}</span></td>
            <td>{{fallback .NotAfter "-"}}</td>
            <td>{{fallback .IssuerCN "-"}}<div class="muted">{{.IssuerOrg}}</div></td>
            <td>{{fallback .SubjectCN "-"}}</td>
            <td class="mono" title="{{.Fingerprint}}">{{shortFingerprint .Fingerprint}}</td>
            <td class="san">{{range splitSAN .SANNames}}<div>{{.}}</div>{{else}}<span class="muted">-</span>{{end}}</td>
            <td>{{fallback .LastProbedAt "-"}}</td>
            <td>{{fallback .ObservedAt "-"}}</td>
            <td>chain={{.ChainComplete}}<br>host={{.HostnameMatch}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{else}}
    <div class="empty">No inventory rows yet.</div>
    {{end}}
  </main>
</body>
</html>`
