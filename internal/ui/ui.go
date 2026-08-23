package ui

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/discover/crtname"
	"github.com/tasoint/certinv/internal/store"
)

type Handler struct {
	store    store.Store
	template *template.Template
	now      func() time.Time
	scanner  ScanTrigger
	config   ConfigTargets
	sources  SourceConfig
}

type ScanTrigger interface {
	TriggerScan() bool
	Running() bool
}

type Option func(*Handler)

type ConfigTargets struct {
	Apexes      []string
	ManualHosts []config.ManualHost
}

type SourceConfig struct {
	CrtNameEnabled  bool
	CrtNameEndpoint string
	ZoneAllowedDir  string
	ZoneFiles       []string
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

func WithSourceConfig(discovery config.Discovery) Option {
	return func(h *Handler) {
		h.sources = SourceConfig{
			CrtNameEnabled:  contains(discovery.Sources, discover.SourceCrtName),
			CrtNameEndpoint: discovery.CrtName.Endpoint,
			ZoneAllowedDir:  discovery.Zone.AllowedDir,
			ZoneFiles:       append([]string{}, discovery.Zone.Files...),
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
	mux.HandleFunc("/ui/events/", h.acknowledgeEvent)
	mux.HandleFunc("/ui/scan", h.serveScan)
	mux.HandleFunc("/ui/scan/status", h.serveScanStatus)
	mux.HandleFunc("/ui/apexes", h.serveAddApex)
	mux.HandleFunc("/ui/apexes/delete", h.serveDeleteApex)
	mux.HandleFunc("/ui/manual-hosts", h.serveAddManualHost)
	mux.HandleFunc("/ui/manual-hosts/edit", h.serveEditManualHost)
	mux.HandleFunc("/ui/manual-hosts/delete", h.serveDeleteManualHost)
	mux.HandleFunc("/ui/hosts/suppress", h.serveSuppressHost)
	mux.HandleFunc("/ui/hosts/unsuppress", h.serveUnsuppressHost)
	mux.HandleFunc("/ui/hosts/purge", h.servePurgeHost)
	mux.HandleFunc("/ui/crtname", h.serveSaveCrtName)
	mux.HandleFunc("/ui/crtname/lookup", h.serveCrtNameLookup)
	mux.HandleFunc("/ui/crtname/add-selected", h.serveAddCrtNameSelected)
	mux.HandleFunc("/ui/zone-files", h.serveAddZoneFile)
	mux.HandleFunc("/ui/zone-files/delete", h.serveDeleteZoneFile)
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
	data, err := h.pageData(r.Context(), activeTab(r), r.URL.Query().Get("notice"), r.URL.Query().Get("error"))
	if err != nil {
		http.Error(w, "failed to load inventory", http.StatusInternalServerError)
		return
	}
	h.renderPage(w, data)
}

func (h *Handler) serveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.scanner == nil {
		redirectUIError(w, r, "scan trigger is not configured")
		return
	}
	if !h.scanner.TriggerScan() {
		redirectUIError(w, r, "scan is already running")
		return
	}
	redirectUINotice(w, r, "scan accepted")
}

func (h *Handler) serveScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	running := false
	if h.scanner != nil {
		running = h.scanner.Running()
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(struct {
		Running bool `json:"running"`
	}{Running: running}); err != nil {
		http.Error(w, "failed to render scan status", http.StatusInternalServerError)
	}
}

func (h *Handler) serveAddApex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUIError(w, r, "invalid form")
		return
	}
	apex, err := validateApex(r.FormValue("apex"))
	if err != nil {
		redirectUIError(w, r, err.Error())
		return
	}
	if err := h.store.AddManagedApex(r.Context(), apex, h.now()); err != nil {
		redirectUIError(w, r, "failed to add apex")
		return
	}
	redirectUINotice(w, r, "apex added")
}

func (h *Handler) serveDeleteApex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUIError(w, r, "invalid form")
		return
	}
	apex, err := validateApex(r.FormValue("apex"))
	if err != nil {
		redirectUIError(w, r, err.Error())
		return
	}
	if err := h.store.DeleteManagedApex(r.Context(), apex); err != nil {
		redirectUIError(w, r, "failed to delete apex")
		return
	}
	redirectUINotice(w, r, "apex deleted")
}

func (h *Handler) serveAddManualHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUIError(w, r, "invalid form")
		return
	}
	host, err := h.validateManualHost(r.Context(), r.FormValue("hostname"), r.FormValue("port"))
	if err != nil {
		redirectUIError(w, r, err.Error())
		return
	}
	if err := h.store.AddManagedManualHost(r.Context(), host, h.now()); err != nil {
		redirectUIError(w, r, "failed to add manual host")
		return
	}
	redirectUINotice(w, r, "manual host added")
}

func (h *Handler) serveDeleteManualHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		redirectUIError(w, r, "invalid form")
		return
	}
	hostname := discover.NormalizeHostname(r.FormValue("hostname"))
	port, err := parsePort(r.FormValue("port"))
	if err != nil {
		redirectUIError(w, r, err.Error())
		return
	}
	if err := h.store.DeleteManagedManualHost(r.Context(), hostname, port); err != nil {
		redirectUIError(w, r, "failed to delete manual host")
		return
	}
	redirectUINotice(w, r, "manual host deleted")
}

func (h *Handler) serveEditManualHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUITabError(w, r, "sources", "invalid form")
		return
	}
	hostname := discover.NormalizeHostname(r.FormValue("hostname"))
	oldPort, err := parsePort(r.FormValue("old_port"))
	if hostname == "" || err != nil {
		redirectUITabError(w, r, "sources", "invalid host")
		return
	}
	if !h.hasManagedManualHost(r.Context(), hostname, oldPort) {
		redirectUITabError(w, r, "sources", "manual host is not editable")
		return
	}
	host, err := h.validateManualHost(r.Context(), hostname, r.FormValue("port"))
	if err != nil {
		redirectUITabError(w, r, "sources", err.Error())
		return
	}
	if err := h.store.DeleteManagedManualHost(r.Context(), hostname, oldPort); err != nil {
		redirectUITabError(w, r, "sources", "failed to update manual host")
		return
	}
	if err := h.store.AddManagedManualHost(r.Context(), host, h.now()); err != nil {
		redirectUITabError(w, r, "sources", "failed to update manual host")
		return
	}
	redirectUITabNotice(w, r, "sources", "manual host updated")
}

func (h *Handler) serveSaveCrtName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUITabError(w, r, "sources", "invalid form")
		return
	}
	enabled := r.FormValue("enabled") == "on"
	endpoint := strings.TrimSpace(r.FormValue("endpoint"))
	if enabled && endpoint == "" {
		redirectUITabError(w, r, "sources", "crtname endpoint is required")
		return
	}
	if err := h.store.SaveManagedCrtName(r.Context(), enabled, endpoint, h.now()); err != nil {
		redirectUITabError(w, r, "sources", "failed to save crtname settings")
		return
	}
	redirectUITabNotice(w, r, "sources", "crtname settings saved")
}

func (h *Handler) serveCrtNameLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	apexes, err := h.effectiveApexes(r.Context())
	if err != nil {
		h.renderSourcesError(w, r, "failed to load apexes")
		return
	}
	if len(apexes) == 0 {
		h.renderSourcesError(w, r, "no apexes configured")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderSourcesError(w, r, "invalid form")
		return
	}
	selectedApex, ok := selectedLookupApex(r.FormValue("apex"), apexes)
	if !ok {
		h.renderSourcesError(w, r, "lookup apex must be configured or managed")
		return
	}
	enabled := r.FormValue("enabled") == "on"
	if !enabled {
		h.renderSourcesError(w, r, "crtname discovery is disabled")
		return
	}
	endpoint := strings.TrimSpace(r.FormValue("endpoint"))
	if strings.TrimSpace(endpoint) == "" {
		h.renderSourcesError(w, r, "crtname endpoint is not configured")
		return
	}
	hosts, err := crtname.New(endpoint).Discover(r.Context(), []string{selectedApex})
	if err != nil {
		h.renderSourcesError(w, r, "crtname lookup failed")
		return
	}
	registered, err := h.registeredManualHostnames(r.Context())
	if err != nil {
		h.renderSourcesError(w, r, "failed to load existing targets")
		return
	}
	candidates := make([]crtNameCandidate, 0, len(hosts))
	for _, host := range hosts {
		if _, ok := registered[host.Hostname]; ok {
			continue
		}
		candidates = append(candidates, crtNameCandidate{
			Hostname: host.Hostname,
			Apex:     host.Apex,
		})
	}
	data, err := h.pageData(r.Context(), "sources", "crtname lookup completed", "")
	if err != nil {
		http.Error(w, "failed to load inventory", http.StatusInternalServerError)
		return
	}
	data.Sources.CrtName = crtNameRow{Enabled: enabled, Endpoint: endpoint, Origin: "form"}
	data.Lookup.SelectedApex = selectedApex
	data.Lookup.Candidates = candidates
	h.renderPage(w, data)
}

func (h *Handler) serveAddCrtNameSelected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUITabError(w, r, "sources", "invalid form")
		return
	}
	hostnames := r.Form["hostname"]
	if len(hostnames) == 0 {
		redirectUITabError(w, r, "sources", "no crtname hosts selected")
		return
	}
	added := 0
	for _, hostname := range hostnames {
		host, err := h.validateManualHost(r.Context(), hostname, strconv.Itoa(discover.DefaultPort))
		if err != nil {
			redirectUITabError(w, r, "sources", "selected host is outside configured or managed apexes")
			return
		}
		if err := h.store.AddManagedManualHost(r.Context(), host, h.now()); err != nil {
			redirectUITabError(w, r, "sources", "failed to add selected hosts")
			return
		}
		added++
	}
	redirectUITabNotice(w, r, "sources", fmt.Sprintf("added %d crtname hosts", added))
}

func (h *Handler) serveAddZoneFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUITabError(w, r, "sources", "invalid form")
		return
	}
	path, err := h.resolveAllowedZoneFile(r.FormValue("file"))
	if err != nil {
		redirectUITabError(w, r, "sources", err.Error())
		return
	}
	if err := h.store.AddManagedZoneFile(r.Context(), path, h.now()); err != nil {
		redirectUITabError(w, r, "sources", "failed to add zone file")
		return
	}
	redirectUITabNotice(w, r, "sources", "zone file added")
}

func (h *Handler) serveDeleteZoneFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUITabError(w, r, "sources", "invalid form")
		return
	}
	path := strings.TrimSpace(r.FormValue("path"))
	if path == "" {
		redirectUITabError(w, r, "sources", "zone file path is required")
		return
	}
	if err := h.store.DeleteManagedZoneFile(r.Context(), path); err != nil {
		redirectUITabError(w, r, "sources", "failed to delete zone file")
		return
	}
	redirectUITabNotice(w, r, "sources", "zone file deleted")
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

func (h *Handler) serveSuppressHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUIError(w, r, "invalid form")
		return
	}
	hostname := discover.NormalizeHostname(r.FormValue("hostname"))
	port, err := parsePort(r.FormValue("port"))
	if hostname == "" || err != nil {
		redirectUIError(w, r, "invalid host")
		return
	}
	if err := h.store.SuppressHost(r.Context(), hostname, port, h.now()); err != nil {
		redirectUIError(w, r, "failed to suppress host")
		return
	}
	redirectUINotice(w, r, "host suppressed")
}

func (h *Handler) serveUnsuppressHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUIError(w, r, "invalid form")
		return
	}
	hostname := discover.NormalizeHostname(r.FormValue("hostname"))
	port, err := parsePort(r.FormValue("port"))
	if hostname == "" || err != nil {
		redirectUIError(w, r, "invalid host")
		return
	}
	if err := h.store.UnsuppressHost(r.Context(), hostname, port); err != nil {
		redirectUIError(w, r, "failed to unsuppress host")
		return
	}
	redirectUINotice(w, r, "host unsuppressed")
}

func (h *Handler) servePurgeHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectUIError(w, r, "invalid form")
		return
	}
	hostname := discover.NormalizeHostname(r.FormValue("hostname"))
	port, err := parsePort(r.FormValue("port"))
	if hostname == "" || err != nil {
		redirectUIError(w, r, "invalid host")
		return
	}
	if err := h.store.PurgeHost(r.Context(), hostname, port); err != nil {
		redirectUIError(w, r, "failed to purge host")
		return
	}
	redirectUINotice(w, r, "host purged")
}

func (h *Handler) acknowledgeEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	const prefix = "/ui/events/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if !strings.HasSuffix(path, "/ack") {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(strings.TrimSuffix(path, "/ack"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	by, _, ok := r.BasicAuth()
	if !ok || strings.TrimSpace(by) == "" {
		by = "ui"
	}
	if err := h.store.AcknowledgeEvent(r.Context(), id, by, h.now()); err != nil {
		if errors.Is(err, store.ErrEventNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to acknowledge event", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui", http.StatusSeeOther)
}

type pageData struct {
	GeneratedAt  string
	Tab          string
	InventoryTab bool
	SourcesTab   bool
	Rows         []store.InventoryRow
	Targets      targetRows
	Events       []store.StoredEvent
	Suppressed   []store.SuppressedHost
	Sources      sourceRows
	Lookup       crtNameLookup
	Notice       string
	Error        string
	PollScan     bool
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

type sourceRows struct {
	CrtName      crtNameRow
	SavedCrtName crtNameRow
	Zone         zoneRows
}

type crtNameRow struct {
	Enabled  bool
	Endpoint string
	Origin   string
}

type crtNameLookup struct {
	Apexes       []string
	SelectedApex string
	Candidates   []crtNameCandidate
}

type crtNameCandidate struct {
	Hostname string
	Apex     string
}

type zoneRows struct {
	AllowedDir     string
	Enabled        bool
	ConfigFiles    []string
	ManagedFiles   []store.ManagedZoneFile
	AvailableFiles []string
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

func (h *Handler) pageData(ctx context.Context, tab, notice, messageError string) (pageData, error) {
	snapshot, err := h.store.InventorySnapshot(ctx)
	if err != nil {
		return pageData{}, err
	}
	events, err := h.store.UnacknowledgedEvents(ctx)
	if err != nil {
		return pageData{}, err
	}
	suppressed, err := h.store.SuppressedHosts(ctx)
	if err != nil {
		return pageData{}, err
	}
	data := pageData{
		GeneratedAt: h.now().UTC().Format(time.RFC3339),
		Tab:         tab,
		Rows:        snapshot.Rows,
		Events:      events,
		Suppressed:  suppressed,
		Notice:      notice,
		Error:       messageError,
	}
	data.PollScan = data.Notice == "scan accepted"
	data.InventoryTab = data.Tab == "inventory"
	data.SourcesTab = data.Tab == "sources"
	targets, err := h.targetRows(ctx)
	if err != nil {
		return pageData{}, err
	}
	data.Targets = targets
	for _, apex := range targets.Apexes {
		data.Lookup.Apexes = append(data.Lookup.Apexes, apex.Apex)
	}
	if len(data.Lookup.Apexes) > 0 {
		data.Lookup.SelectedApex = data.Lookup.Apexes[0]
	}
	sources, err := h.sourceRows(ctx)
	if err != nil {
		return pageData{}, err
	}
	data.Sources = sources
	return data, nil
}

func (h *Handler) renderPage(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.template.Execute(w, data); err != nil {
		http.Error(w, "failed to render inventory", http.StatusInternalServerError)
	}
}

func (h *Handler) renderSourcesError(w http.ResponseWriter, r *http.Request, message string) {
	data, err := h.pageData(r.Context(), "sources", "", message)
	if err != nil {
		http.Error(w, "failed to load inventory", http.StatusInternalServerError)
		return
	}
	h.renderPage(w, data)
}

func redirectUINotice(w http.ResponseWriter, r *http.Request, message string) {
	redirectUITabNotice(w, r, activeTab(r), message)
}

func redirectUIError(w http.ResponseWriter, r *http.Request, message string) {
	redirectUITabError(w, r, activeTab(r), message)
}

func redirectUITabNotice(w http.ResponseWriter, r *http.Request, tab, message string) {
	redirectUIMessage(w, r, tab, "notice", message)
}

func redirectUITabError(w http.ResponseWriter, r *http.Request, tab, message string) {
	redirectUIMessage(w, r, tab, "error", message)
}

func redirectUIMessage(w http.ResponseWriter, r *http.Request, tab, key, message string) {
	values := url.Values{}
	if tab != "" && tab != "inventory" {
		values.Set("tab", tab)
	}
	values.Set(key, message)
	http.Redirect(w, r, "/ui?"+values.Encode(), http.StatusSeeOther)
}

func activeTab(r *http.Request) string {
	switch r.URL.Query().Get("tab") {
	case "sources":
		return "sources"
	default:
		return "inventory"
	}
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

func (h *Handler) hasManagedManualHost(ctx context.Context, hostname string, port int) bool {
	managed, err := h.store.ManagedTargets(ctx)
	if err != nil {
		return false
	}
	for _, host := range managed.ManualHosts {
		if discover.NormalizeHostname(host.Hostname) == hostname && host.Port == port {
			return true
		}
	}
	return false
}

func (h *Handler) registeredManualHostnames(ctx context.Context) (map[string]struct{}, error) {
	registered := make(map[string]struct{})
	for _, host := range h.config.ManualHosts {
		hostname := discover.NormalizeHostname(host.Hostname)
		if hostname != "" {
			registered[hostname] = struct{}{}
		}
	}
	managed, err := h.store.ManagedTargets(ctx)
	if err != nil {
		return nil, err
	}
	for _, host := range managed.ManualHosts {
		hostname := discover.NormalizeHostname(host.Hostname)
		if hostname != "" {
			registered[hostname] = struct{}{}
		}
	}
	return registered, nil
}

func (h *Handler) effectiveApexes(ctx context.Context) ([]string, error) {
	apexes := append([]string{}, h.config.Apexes...)
	managed, err := h.store.ManagedTargets(ctx)
	if err != nil {
		return nil, err
	}
	for _, apex := range managed.Apexes {
		apexes = append(apexes, apex.Apex)
	}
	return uniqueStrings(apexes), nil
}

func (h *Handler) sourceRows(ctx context.Context) (sourceRows, error) {
	managed, err := h.store.ManagedDiscovery(ctx)
	if err != nil {
		return sourceRows{}, err
	}
	crt := crtNameRow{
		Enabled:  h.sources.CrtNameEnabled,
		Endpoint: h.sources.CrtNameEndpoint,
		Origin:   "config",
	}
	if managed.CrtNameSet {
		crt.Enabled = managed.CrtNameEnabled
		crt.Endpoint = managed.CrtNameEndpoint
		crt.Origin = "db"
	}
	available, _ := h.availableZoneFiles()
	return sourceRows{
		CrtName:      crt,
		SavedCrtName: crt,
		Zone: zoneRows{
			AllowedDir:     h.sources.ZoneAllowedDir,
			Enabled:        strings.TrimSpace(h.sources.ZoneAllowedDir) != "",
			ConfigFiles:    append([]string{}, h.sources.ZoneFiles...),
			ManagedFiles:   managed.ZoneFiles,
			AvailableFiles: available,
		},
	}, nil
}

func selectedLookupApex(value string, apexes []string) (string, bool) {
	apex := discover.NormalizeHostname(value)
	if apex == "" && len(apexes) == 1 {
		apex = discover.NormalizeHostname(apexes[0])
	}
	for _, candidate := range apexes {
		candidate = discover.NormalizeHostname(candidate)
		if apex == candidate {
			return candidate, true
		}
	}
	return "", false
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

func (h *Handler) availableZoneFiles() ([]string, error) {
	dir := strings.TrimSpace(h.sources.ZoneAllowedDir)
	if dir == "" {
		return nil, nil
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	return files, err
}

func (h *Handler) resolveAllowedZoneFile(name string) (string, error) {
	dir := strings.TrimSpace(h.sources.ZoneAllowedDir)
	if dir == "" {
		return "", fmt.Errorf("zone allowed_dir is not configured")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("zone file is required")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("zone file must be under allowed_dir")
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("invalid zone allowed_dir")
	}
	path, err := filepath.Abs(filepath.Join(root, filepath.Clean(name)))
	if err != nil {
		return "", fmt.Errorf("invalid zone file")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return "", fmt.Errorf("zone file must be under allowed_dir")
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return "", fmt.Errorf("zone file must exist under allowed_dir")
	}
	return path, nil
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

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var result []string
	for _, value := range values {
		value = discover.NormalizeHostname(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
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
	"http_status",
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
		strconv.Itoa(row.HTTPStatus),
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
    .tabs {
      display: flex;
      gap: 8px;
      margin-top: 12px;
    }
    .tab {
      padding: 7px 10px;
      border: 1px solid var(--line);
      border-radius: 4px;
      color: var(--text);
      text-decoration: none;
      background: #eef2f6;
      font-weight: 650;
    }
    .tab-active {
      background: var(--panel);
      border-bottom-color: var(--panel);
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
    select {
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
    .flash {
      margin-bottom: 16px;
      padding: 9px 10px;
      border: 1px solid var(--line);
      background: var(--panel);
    }
    .flash-notice { border-color: #8fd19e; color: var(--ok); }
    .flash-error { border-color: #ff8182; color: var(--alert); }
  </style>
</head>
<body>
  <header>
    <h1>certinv inventory</h1>
    <div class="meta">Generated at {{.GeneratedAt}}. Certificates and keys are not modified from this UI.</div>
    <nav class="tabs">
      <a class="tab {{if .InventoryTab}}tab-active{{end}}" href="/ui?tab=inventory">Inventory</a>
      <a class="tab {{if .SourcesTab}}tab-active{{end}}" href="/ui?tab=sources">Sources &amp; Targets</a>
    </nav>
  </header>
  <main>
    {{if .Notice}}<div class="flash flash-notice">{{.Notice}}</div>{{end}}
    {{if .Error}}<div class="flash flash-error">{{.Error}}</div>{{end}}
    {{if .SourcesTab}}
    <section>
      <h2>Targets</h2>
      <div class="forms">
        <form method="post" action="/ui/apexes?tab=sources">
          <input name="apex" placeholder="example.com" required>
          <button class="button" type="submit">Add apex</button>
        </form>
        <form method="post" action="/ui/manual-hosts?tab=sources">
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
              <td>{{if .CanDelete}}<form method="post" action="/ui/apexes/delete?tab=sources"><input type="hidden" name="apex" value="{{.Apex}}"><button class="button" type="submit">Delete</button></form>{{else}}<span class="muted">config</span>{{end}}</td>
            </tr>
            {{end}}
            {{range .Targets.ManualHosts}}
            <tr>
              <td>manual</td><td>{{.Hostname}}:{{.Port}}</td><td>{{.Apex}}</td><td>{{.Origin}}</td>
              <td>{{if .CanDelete}}<form method="post" action="/ui/manual-hosts/edit?tab=sources" style="display:inline"><input type="hidden" name="hostname" value="{{.Hostname}}"><input type="hidden" name="old_port" value="{{.Port}}"><input name="port" value="{{.Port}}" size="5"><button class="button" type="submit">Update port</button></form> <form method="post" action="/ui/manual-hosts/delete?tab=sources" style="display:inline"><input type="hidden" name="hostname" value="{{.Hostname}}"><input type="hidden" name="port" value="{{.Port}}"><button class="button" type="submit">Delete</button></form>{{else}}<span class="muted">config</span>{{end}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>
    <section>
      <h2>crt.name discovery</h2>
      <form method="post" action="/ui/crtname?tab=sources" class="forms">
        <label><input type="checkbox" name="enabled" {{if .Sources.CrtName.Enabled}}checked{{end}}> Enabled</label>
        <input name="endpoint" value="{{.Sources.CrtName.Endpoint}}" placeholder="https://crt.name/v1/search">
        <select name="apex">
          {{range .Lookup.Apexes}}<option value="{{.}}" {{if eq . $.Lookup.SelectedApex}}selected{{end}}>{{.}}</option>{{end}}
        </select>
        <button class="button" type="submit">Save crt.name</button>
        <button class="button" type="submit" formaction="/ui/crtname/lookup?tab=sources">Lookup now</button>
        <span class="muted">origin={{.Sources.CrtName.Origin}}</span>
      </form>
      <div class="meta">Saving applies this setting to future scheduled scans and Run scan now.</div>
      <div class="meta">Saved setting: enabled={{.Sources.SavedCrtName.Enabled}} endpoint={{.Sources.SavedCrtName.Endpoint}}</div>
      {{if .Lookup.Candidates}}
      <form method="post" action="/ui/crtname/add-selected?tab=sources">
        <div class="forms">
          <input id="crtname-filter" placeholder="Filter hostnames">
          <button class="button" type="button" id="crtname-select-all">Select all</button>
          <button class="button" type="button" id="crtname-clear-all">Clear all</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Select</th><th>Hostname</th><th>Apex</th><th>Port</th></tr></thead>
            <tbody>
              {{range .Lookup.Candidates}}
              <tr data-crtname-host="{{.Hostname}}">
                <td><input type="checkbox" name="hostname" value="{{.Hostname}}"></td>
                <td>{{.Hostname}}</td>
                <td>{{.Apex}}</td>
                <td>443</td>
              </tr>
              {{end}}
            </tbody>
          </table>
        </div>
        <div class="actions"><button class="button" type="submit">Add selected to Targets</button></div>
      </form>
      {{end}}
    </section>
    <section>
      <h2>Zone files</h2>
      {{if .Sources.Zone.Enabled}}
      <div class="forms">
        <form method="post" action="/ui/zone-files?tab=sources">
          <select name="file">
            {{range .Sources.Zone.AvailableFiles}}<option value="{{.}}">{{.}}</option>{{end}}
          </select>
          <button class="button" type="submit">Add zone file</button>
        </form>
      </div>
      {{else}}
      <div class="empty">discovery.zone.allowed_dir is not configured.</div>
      {{end}}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Origin</th><th>Path</th><th>Action</th></tr></thead>
          <tbody>
            {{range .Sources.Zone.ConfigFiles}}<tr><td>config</td><td>{{.}}</td><td><span class="muted">config</span></td></tr>{{end}}
            {{range .Sources.Zone.ManagedFiles}}
            <tr><td>db</td><td>{{.Path}}</td><td><form method="post" action="/ui/zone-files/delete?tab=sources"><input type="hidden" name="path" value="{{.Path}}"><button class="button" type="submit">Delete</button></form></td></tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>
    {{else}}
    <section>
    <div class="actions">
      <form method="post" action="/ui/scan" style="display:inline"><button class="button" type="submit">Run scan now</button></form>
      <a class="button" href="/ui/export.csv">Download CSV</a>
    </div>
    </section>
    <section>
    <h2>Unacknowledged alerts</h2>
    {{if .Events}}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Event</th><th>Fingerprint</th><th>Detail</th><th>Action</th></tr></thead>
        <tbody>
          {{range .Events}}
          <tr>
            <td><span class="state state-{{.Kind}}">{{.Kind}}</span></td>
            <td class="mono">{{shortFingerprint .Fingerprint}}</td>
            <td>{{.Detail}}</td>
            <td><form method="post" action="/ui/events/{{.ID}}/ack"><button type="submit">Acknowledge</button></form></td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{else}}
    <div class="empty">No unacknowledged warn or alert events.</div>
    {{end}}
    </section>
    <section>
    <h2>Inventory</h2>
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
            <th>HTTP status</th>
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
            <td>{{if .HTTPStatus}}{{.HTTPStatus}}{{else}}-{{end}}</td>
            <td>chain={{.ChainComplete}}<br>host={{.HostnameMatch}}<br><form method="post" action="/ui/hosts/suppress" onsubmit="return confirm('このホストをインベントリから削除しますか？次回scanでも対象外になります')"><input type="hidden" name="hostname" value="{{.Hostname}}"><input type="hidden" name="port" value="{{.Port}}"><button class="button" type="submit">Suppress</button></form></td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{else}}
    <div class="empty">No inventory rows yet.</div>
    {{end}}
      <section>
        <h2>Suppressed hosts</h2>
        {{if .Suppressed}}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Host</th><th>Action</th></tr></thead>
            <tbody>
              {{range .Suppressed}}
              <tr><td>{{.Hostname}}:{{.Port}}</td><td><form method="post" action="/ui/hosts/unsuppress" style="display:inline"><input type="hidden" name="hostname" value="{{.Hostname}}"><input type="hidden" name="port" value="{{.Port}}"><button class="button" type="submit">Unsuppress</button></form> <form method="post" action="/ui/hosts/purge" style="display:inline" onsubmit="return confirm('このホストの記録を完全に削除します。元に戻せません。よろしいですか？')"><input type="hidden" name="hostname" value="{{.Hostname}}"><input type="hidden" name="port" value="{{.Port}}"><button class="button" type="submit">Purge</button></form></td></tr>
              {{end}}
            </tbody>
          </table>
        </div>
        {{else}}
        <div class="empty">No suppressed hosts.</div>
        {{end}}
      </section>
    </section>
    {{end}}
  </main>
  {{if .PollScan}}
  <script>
    (function () {
      var started = Date.now();
      function poll() {
        if (Date.now() - started > 60000) return;
        fetch('/ui/scan/status', {credentials: 'same-origin'})
          .then(function (response) { return response.ok ? response.json() : {running: true}; })
          .then(function (status) {
            if (!status.running) {
              window.location = '/ui';
              return;
            }
            setTimeout(poll, 1500);
          })
          .catch(function () { setTimeout(poll, 1500); });
      }
      setTimeout(poll, 1500);
    }());
  </script>
  {{end}}
  {{if .Lookup.Candidates}}
  <script>
    (function () {
      var filter = document.getElementById('crtname-filter');
      var selectAll = document.getElementById('crtname-select-all');
      var clearAll = document.getElementById('crtname-clear-all');
      var rows = Array.prototype.slice.call(document.querySelectorAll('tr[data-crtname-host]'));
      function visibleRows() {
        return rows.filter(function (row) { return row.style.display !== 'none'; });
      }
      filter.addEventListener('input', function () {
        var query = filter.value.toLowerCase();
        rows.forEach(function (row) {
          var host = row.getAttribute('data-crtname-host').toLowerCase();
          row.style.display = host.indexOf(query) === -1 ? 'none' : '';
        });
      });
      selectAll.addEventListener('click', function () {
        visibleRows().forEach(function (row) {
          row.querySelector('input[type="checkbox"]').checked = true;
        });
      });
      clearAll.addEventListener('click', function () {
        rows.forEach(function (row) {
          row.querySelector('input[type="checkbox"]').checked = false;
        });
      });
    }());
  </script>
  {{end}}
</body>
</html>`
