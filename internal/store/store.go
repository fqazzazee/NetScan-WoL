// Package store persists hub state.
//
// The whole dataset is a few hundred kilobytes at most — dozens of agents,
// hundreds of hosts — so it lives in memory and is flushed to a JSON file on
// change. That avoids a database dependency entirely, which matters for a tool
// meant to be dropped into an LXC container or a distroless image. Writes go
// through a temp file and rename, so an interrupted flush can never leave a
// half-written state file behind.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/netutil"
)

// state is the on-disk document.
type state struct {
	Version   int                     `json:"version"`
	Settings  Settings                `json:"settings"`
	Operators map[string]*Operator    `json:"operators"`
	Agents    map[string]*Agent       `json:"agents"`
	Tokens    map[string]*EnrollToken `json:"tokens"`
	Hosts     map[string]*SavedHost   `json:"hosts"`
	Scans     []*ScanRecord           `json:"scans"`
}

// Store is the concurrency-safe handle to hub state.
type Store struct {
	dir   string
	path  string
	mu    sync.RWMutex
	st    *state
	audit *auditLog
}

// stateVersion lets a future release migrate an old file instead of guessing.
const stateVersion = 2

// Open loads state from dir, creating an empty dataset on first run.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	s := &Store{
		dir:  dir,
		path: filepath.Join(dir, "hub-state.json"),
	}
	audit, err := openAuditLog(filepath.Join(dir, "audit.log"))
	if err != nil {
		return nil, err
	}
	s.audit = audit

	data, err := os.ReadFile(s.path)
	switch {
	case os.IsNotExist(err):
		s.st = &state{
			Version:   stateVersion,
			Settings:  DefaultSettings(),
			Operators: map[string]*Operator{},
			Agents:    map[string]*Agent{},
			Tokens:    map[string]*EnrollToken{},
			Hosts:     map[string]*SavedHost{},
		}
		return s, s.flush()
	case err != nil:
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	if st.Operators == nil {
		st.Operators = map[string]*Operator{}
	}
	if st.Agents == nil {
		st.Agents = map[string]*Agent{}
	}
	if st.Tokens == nil {
		st.Tokens = map[string]*EnrollToken{}
	}
	if st.Hosts == nil {
		st.Hosts = map[string]*SavedHost{}
	}
	if st.Settings.HubName == "" {
		st.Settings = DefaultSettings()
	}
	st.Version = stateVersion
	s.st = &st
	return s, nil
}

// Close flushes and releases the audit log.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.flushLocked(); err != nil {
		return err
	}
	return s.audit.Close()
}

// Dir returns the data directory, used to place the CA alongside state.
func (s *Store) Dir() string { return s.dir }

func (s *Store) flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

// flushLocked serialises state to disk. The caller must hold the write lock.
func (s *Store) flushLocked() error {
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	tmp := s.path + ".tmp"
	// 0600: the state file holds password hashes and token hashes.
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install state file: %w", err)
	}
	return nil
}

// --- settings ---

func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.Settings
}

func (s *Store) SaveSettings(set Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if set.HubName == "" {
		set.HubName = "NetScan-WoL"
	}
	switch set.DefaultTheme {
	case "light", "dark", "system":
	default:
		set.DefaultTheme = "system"
	}
	if set.ScanTimeoutSeconds <= 0 || set.ScanTimeoutSeconds > 900 {
		set.ScanTimeoutSeconds = 60
	}
	if set.HistoryLimit <= 0 || set.HistoryLimit > 1000 {
		set.HistoryLimit = 50
	}
	if set.AgentOnlineWindowSeconds < 15 {
		set.AgentOnlineWindowSeconds = 90
	}
	s.st.Settings = set
	return s.flushLocked()
}

// --- agents ---

func (s *Store) PutAgent(a *Agent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Agents[a.ID] = a
	return s.flushLocked()
}

func (s *Store) Agent(id string) (*Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.st.Agents[id]
	if !ok {
		return nil, false
	}
	clone := *a
	return &clone, true
}

func (s *Store) Agents() []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Agent, 0, len(s.st.Agents))
	for _, a := range s.st.Agents {
		clone := *a
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// TouchAgent records a successful authenticated contact. It is called on every
// poll, so it updates in place and only flushes periodically — writing the
// whole state file on each heartbeat would be pointless disk churn.
func (s *Store) TouchAgent(id, remoteAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.st.Agents[id]
	if !ok {
		return
	}
	now := time.Now()
	// Persist at most once a minute; LastSeen is reconstructed from the poll
	// stream anyway and losing a few seconds of it across a restart is fine.
	shouldFlush := now.Sub(a.LastSeen) > time.Minute || a.RemoteAddr != remoteAddr
	a.LastSeen = now
	a.RemoteAddr = remoteAddr
	if shouldFlush {
		_ = s.flushLocked()
	}
}

func (s *Store) DeleteAgent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.st.Agents, id)
	return s.flushLocked()
}

func (s *Store) SetAgentDisabled(id string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.st.Agents[id]
	if !ok {
		return fmt.Errorf("agent %s not found", id)
	}
	a.Disabled = disabled
	return s.flushLocked()
}

// RenameAgent updates the display name only; the certificate identity is
// unchanged, which is the point of keeping the two separate.
func (s *Store) RenameAgent(id, name, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.st.Agents[id]
	if !ok {
		return fmt.Errorf("agent %s not found", id)
	}
	if name != "" {
		a.Name = name
	}
	a.Note = note
	return s.flushLocked()
}

// --- enrollment tokens ---

func (s *Store) PutToken(t *EnrollToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Tokens[t.ID] = t
	return s.flushLocked()
}

func (s *Store) Tokens() []*EnrollToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*EnrollToken, 0, len(s.st.Tokens))
	for _, t := range s.st.Tokens {
		clone := *t
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *Store) RevokeToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.st.Tokens[id]
	if !ok {
		return fmt.Errorf("token %s not found", id)
	}
	t.Revoked = true
	return s.flushLocked()
}

func (s *Store) DeleteToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.st.Tokens, id)
	return s.flushLocked()
}

// ClaimToken finds a usable token matching the presented secret and consumes
// one use of it, all under a single lock.
//
// Doing the match and the increment atomically is what stops two agents
// enrolling simultaneously with the same single-use token — a race that would
// otherwise be trivially winnable by an attacker who obtained a copy.
func (s *Store) ClaimToken(match func(hash string) bool, agentID string) (*EnrollToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()

	var found *EnrollToken
	for _, t := range s.st.Tokens {
		if match(t.Hash) {
			found = t
			break
		}
	}
	if found == nil {
		return nil, ErrTokenUnknown
	}
	if ok, why := found.Usable(now); !ok {
		return nil, fmt.Errorf("%w: %s", ErrTokenUnusable, why)
	}
	found.Uses++
	found.LastUsedAt = now
	found.AgentIDs = append(found.AgentIDs, agentID)
	if err := s.flushLocked(); err != nil {
		return nil, err
	}
	clone := *found
	return &clone, nil
}

// Sentinel errors so the API layer can answer with the right status code
// without string matching.
var (
	ErrTokenUnknown  = fmt.Errorf("enrollment token not recognised")
	ErrTokenUnusable = fmt.Errorf("enrollment token cannot be used")
)

// --- saved hosts ---

// SaveHost inserts or updates a host, keyed by normalized MAC.
func (s *Store) SaveHost(h *SavedHost) (*SavedHost, error) {
	mac, err := netutil.NormalizeMAC(h.MAC)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	h.MAC = mac
	if existing, ok := s.st.Hosts[mac]; ok {
		h.CreatedAt = existing.CreatedAt
		if h.LastWake.IsZero() {
			h.LastWake = existing.LastWake
		}
		if h.LastSeen.IsZero() {
			h.LastSeen = existing.LastSeen
		}
	} else {
		h.CreatedAt = now
	}
	h.UpdatedAt = now
	if h.Label == "" {
		h.Label = mac
	}
	s.st.Hosts[mac] = h
	if err := s.flushLocked(); err != nil {
		return nil, err
	}
	clone := *h
	return &clone, nil
}

func (s *Store) Host(mac string) (*SavedHost, bool) {
	norm, err := netutil.NormalizeMAC(mac)
	if err != nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.st.Hosts[norm]
	if !ok {
		return nil, false
	}
	clone := *h
	return &clone, true
}

func (s *Store) Hosts() []*SavedHost {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*SavedHost, 0, len(s.st.Hosts))
	for _, h := range s.st.Hosts {
		clone := *h
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Label) < strings.ToLower(out[j].Label) })
	return out
}

func (s *Store) DeleteHost(mac string) error {
	norm, err := netutil.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.st.Hosts, norm)
	return s.flushLocked()
}

// MarkWoken stamps the last-wake time so the UI can show that a magic packet
// went out even before the host finishes booting.
func (s *Store) MarkWoken(mac string) {
	norm, err := netutil.NormalizeMAC(mac)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.st.Hosts[norm]; ok {
		h.LastWake = time.Now()
		_ = s.flushLocked()
	}
}

// ObserveHosts folds a scan's results into the saved-host records, refreshing
// the last-known IP so a wake still works after a DHCP change.
func (s *Store) ObserveHosts(agentID string, hosts []ObservedHost) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	changed := false
	for _, o := range hosts {
		norm, err := netutil.NormalizeMAC(o.MAC)
		if err != nil {
			continue
		}
		h, ok := s.st.Hosts[norm]
		if !ok {
			continue
		}
		h.LastSeen = now
		if o.IP != "" && o.IP != h.LastIP {
			h.LastIP = o.IP
			changed = true
		}
		if o.Hostname != "" && o.Hostname != h.Hostname {
			h.Hostname = o.Hostname
			changed = true
		}
		if o.Vendor != "" && h.Vendor == "" {
			h.Vendor = o.Vendor
			changed = true
		}
		if h.AgentID == "" {
			h.AgentID = agentID
			changed = true
		}
	}
	if changed {
		_ = s.flushLocked()
	}
}

// ObservedHost is the subset of a scan result that updates a saved host.
type ObservedHost struct {
	MAC      string
	IP       string
	Hostname string
	Vendor   string
}

// ObservedFrom builds an ObservedHost, keeping the protocol package out of the
// store's dependency graph.
func ObservedFrom(mac, ip, hostname, vendor string) ObservedHost {
	return ObservedHost{MAC: mac, IP: ip, Hostname: hostname, Vendor: vendor}
}

// --- scan history ---

func (s *Store) AddScan(rec *ScanRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Scans = append([]*ScanRecord{rec}, s.st.Scans...)
	limit := s.st.Settings.HistoryLimit
	if limit <= 0 {
		limit = 50
	}
	if len(s.st.Scans) > limit {
		s.st.Scans = s.st.Scans[:limit]
	}
	return s.flushLocked()
}

func (s *Store) Scans() []*ScanRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ScanRecord, len(s.st.Scans))
	copy(out, s.st.Scans)
	return out
}

func (s *Store) Scan(id string) (*ScanRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.st.Scans {
		if r.ID == id {
			return r, true
		}
	}
	return nil, false
}

// --- operators ---

func (s *Store) Operator(username string) (*Operator, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	op, ok := s.st.Operators[strings.ToLower(username)]
	if !ok {
		return nil, false
	}
	clone := *op
	return &clone, true
}

func (s *Store) PutOperator(op *Operator) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Operators[strings.ToLower(op.Username)] = op
	return s.flushLocked()
}

func (s *Store) OperatorCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.st.Operators)
}

func (s *Store) MarkLogin(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if op, ok := s.st.Operators[strings.ToLower(username)]; ok {
		op.LastLogin = time.Now()
		_ = s.flushLocked()
	}
}

// --- audit ---

// Audit appends a security-relevant event. Failures to write are ignored on
// purpose: losing an audit line must not take the hub down, and the error is
// already surfaced when the log is opened.
func (s *Store) Audit(e AuditEntry) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	s.audit.Append(e)
}

// AuditTail returns the most recent audit entries for the UI.
func (s *Store) AuditTail(n int) []AuditEntry {
	return s.audit.Tail(n)
}
