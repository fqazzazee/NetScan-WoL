package hub

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/netutil"
	"github.com/fqazzazee/netscan-wol/internal/protocol"
	"github.com/fqazzazee/netscan-wol/internal/store"
	"github.com/fqazzazee/netscan-wol/internal/token"
)

// commandTimeout bounds how long the UI waits for an agent to answer. A scan
// of a /24 finishes in about a second; a /22 with name resolution can take
// most of a minute, so the ceiling is generous.
const commandTimeout = 120 * time.Second

func (s *Server) routeOperator(mux *http.ServeMux) {
	// Authentication.
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.requireOperator(s.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/me", s.requireOperator(s.handleMe))
	mux.HandleFunc("POST /api/v1/auth/password", s.requireOperator(s.handleChangePassword))

	// Agents.
	mux.HandleFunc("GET /api/v1/agents", s.requireOperator(s.handleListAgents))
	mux.HandleFunc("PATCH /api/v1/agents/{id}", s.requireOperator(s.handleUpdateAgent))
	mux.HandleFunc("DELETE /api/v1/agents/{id}", s.requireOperator(s.handleDeleteAgent))
	mux.HandleFunc("POST /api/v1/agents/{id}/scan", s.requireOperator(s.handleScan))
	mux.HandleFunc("POST /api/v1/agents/{id}/discover", s.requireOperator(s.handleDiscover))
	mux.HandleFunc("POST /api/v1/agents/{id}/wake", s.requireOperator(s.handleWakeViaAgent))
	mux.HandleFunc("POST /api/v1/agents/{id}/status", s.requireOperator(s.handleStatus))

	// Enrollment tokens.
	mux.HandleFunc("GET /api/v1/tokens", s.requireOperator(s.handleListTokens))
	mux.HandleFunc("POST /api/v1/tokens", s.requireOperator(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.requireOperator(s.handleDeleteToken))

	// Saved hosts.
	mux.HandleFunc("GET /api/v1/hosts", s.requireOperator(s.handleListHosts))
	mux.HandleFunc("POST /api/v1/hosts", s.requireOperator(s.handleSaveHost))
	mux.HandleFunc("DELETE /api/v1/hosts/{mac}", s.requireOperator(s.handleDeleteHost))
	mux.HandleFunc("POST /api/v1/hosts/{mac}/wake", s.requireOperator(s.handleWakeSavedHost))

	// History, settings, audit.
	mux.HandleFunc("GET /api/v1/scans", s.requireOperator(s.handleListScans))
	mux.HandleFunc("GET /api/v1/scans/{id}", s.requireOperator(s.handleGetScan))
	mux.HandleFunc("GET /api/v1/settings", s.requireOperator(s.handleGetSettings))
	mux.HandleFunc("PUT /api/v1/settings", s.requireOperator(s.handlePutSettings))
	mux.HandleFunc("GET /api/v1/audit", s.requireOperator(s.handleAudit))
	mux.HandleFunc("GET /api/v1/join-info", s.requireOperator(s.handleJoinInfo))
}

// operatorHandler is a handler with an authenticated session attached.
type operatorHandler func(w http.ResponseWriter, r *http.Request, sess *Session)

// requireOperator enforces session authentication and, for anything that
// changes state, a matching CSRF token.
//
// The session cookie is SameSite=Strict, which already blocks cross-site form
// posts in current browsers. The header check is the belt to that suspenders:
// it also covers the case of a subdomain or a proxy that muddies site origin.
func (s *Server) requireOperator(next operatorHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "not signed in")
			return
		}
		sess, ok := s.sessions.Lookup(cookie.Value)
		if !ok {
			ClearCookie(w, !s.cfg.Insecure)
			writeError(w, http.StatusUnauthorized, "session expired; sign in again")
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			presented := r.Header.Get(CSRFHeader)
			if subtle.ConstantTimeCompare([]byte(presented), []byte(sess.CSRF)) != 1 {
				writeError(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
		}
		next(w, r, sess)
	}
}

// --- authentication ---

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	remote := s.remoteAddr(r)
	if ok, wait := s.throttle.Allowed(remote); !ok {
		writeError(w, http.StatusTooManyRequests, "too many failed sign-ins; try again in %s", wait.Round(time.Second))
		return
	}

	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	op, found := s.store.Operator(req.Username)
	// The password is verified even when the user does not exist, against a
	// dummy record, so a missing username and a wrong password take the same
	// time. Otherwise the response latency enumerates valid usernames.
	valid := false
	if found {
		valid = store.CheckPassword(op, req.Password)
	} else {
		store.CheckPassword(dummyOperator(), req.Password)
	}

	if !valid {
		s.throttle.Fail(remote)
		s.store.Audit(store.AuditEntry{
			Actor: req.Username, Action: "auth.login", Remote: remote, OK: false,
			Detail: "invalid credentials",
		})
		writeError(w, http.StatusUnauthorized, "incorrect username or password")
		return
	}

	s.throttle.Succeed(remote)
	sess, err := s.sessions.Create(op.Username, remote)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}
	s.store.MarkLogin(op.Username)
	s.store.Audit(store.AuditEntry{Actor: op.Username, Action: "auth.login", Remote: remote, OK: true})
	SetCookie(w, sess, !s.cfg.Insecure)

	writeJSON(w, http.StatusOK, map[string]any{
		"username":             op.Username,
		"csrf":                 sess.CSRF,
		"must_change_password": op.MustChangePassword,
	})
}

// dummyOperator is a fixed record used to burn the same PBKDF2 time on a
// failed username lookup as on a real one.
func dummyOperator() *store.Operator {
	return &store.Operator{
		Username: "-",
		// A hash of a value nobody will ever present. Only the cost matters.
		PassHash: strings.Repeat("00", 32),
		Salt:     strings.Repeat("00", 16),
		Iter:     0,
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.sessions.Destroy(sess.ID)
	ClearCookie(w, !s.cfg.Insecure)
	s.store.Audit(store.AuditEntry{Actor: sess.Username, Action: "auth.logout", Remote: s.remoteAddr(r), OK: true})
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, sess *Session) {
	op, _ := s.store.Operator(sess.Username)
	set := s.store.Settings()
	resp := map[string]any{
		"username":      sess.Username,
		"csrf":          sess.CSRF,
		"hub_name":      set.HubName,
		"default_theme": set.DefaultTheme,
	}
	if op != nil {
		resp["must_change_password"] = op.MustChangePassword
	}
	writeJSON(w, http.StatusOK, resp)
}

type passwordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, sess *Session) {
	var req passwordRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	op, ok := s.store.Operator(sess.Username)
	if !ok {
		writeError(w, http.StatusUnauthorized, "account no longer exists")
		return
	}
	if !store.CheckPassword(op, req.Current) {
		s.store.Audit(store.AuditEntry{Actor: sess.Username, Action: "auth.password", Remote: s.remoteAddr(r), OK: false})
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	if err := store.SetPassword(op, req.New); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	if err := s.store.PutOperator(op); err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}
	// Every other session for this user dies with the old password. If the
	// change was prompted by a suspected compromise, leaving the attacker's
	// session alive would defeat the point.
	s.sessions.DestroyUser(sess.Username)
	ClearCookie(w, !s.cfg.Insecure)
	s.store.Audit(store.AuditEntry{Actor: sess.Username, Action: "auth.password", Remote: s.remoteAddr(r), OK: true})
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed; sign in again"})
}

// --- agents ---

// agentView is the API shape of an agent, with liveness folded in.
type agentView struct {
	*store.Agent
	Online    bool `json:"online"`
	Connected bool `json:"connected"`
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request, _ *Session) {
	set := s.store.Settings()
	window := time.Duration(set.AgentOnlineWindowSeconds) * time.Second
	now := time.Now()

	agents := s.store.Agents()
	out := make([]agentView, 0, len(agents))
	for _, a := range agents {
		out = append(out, agentView{
			Agent:     a,
			Online:    a.Online(now, window),
			Connected: s.registry.Connected(a.ID),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": out})
}

type updateAgentRequest struct {
	Name     string `json:"name,omitempty"`
	Note     string `json:"note,omitempty"`
	Disabled *bool  `json:"disabled,omitempty"`
}

func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	var req updateAgentRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	if _, ok := s.store.Agent(id); !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if req.Name != "" || req.Note != "" {
		if err := s.store.RenameAgent(id, req.Name, req.Note); err != nil {
			writeError(w, http.StatusInternalServerError, "%s", err)
			return
		}
	}
	if req.Disabled != nil {
		if err := s.store.SetAgentDisabled(id, *req.Disabled); err != nil {
			writeError(w, http.StatusInternalServerError, "%s", err)
			return
		}
		if *req.Disabled {
			// Drop the inbox so nothing queued reaches an agent the operator
			// has just switched off.
			s.registry.Disconnect(id)
		}
		s.store.Audit(store.AuditEntry{
			Actor: sess.Username, Action: "agent.disabled", Target: id,
			Detail: fmt.Sprintf("disabled=%t", *req.Disabled), Remote: s.remoteAddr(r), OK: true,
		})
	}
	agent, _ := s.store.Agent(id)
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	agent, ok := s.store.Agent(id)
	if !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := s.store.DeleteAgent(id); err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}
	s.registry.Disconnect(id)
	// Deleting the record is the revocation: the agent's certificate stays
	// cryptographically valid but no longer maps to anything, so every request
	// it makes is refused.
	s.store.Audit(store.AuditEntry{
		Actor: sess.Username, Action: "agent.removed", Target: agent.Name,
		Detail: "agent id " + id, Remote: s.remoteAddr(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "agent removed"})
}

// --- commands ---

type scanRequest struct {
	Interface    string `json:"interface,omitempty"`
	Subnet       string `json:"subnet,omitempty"`
	ResolveNames *bool  `json:"resolve_names,omitempty"`
	Retries      int    `json:"retries,omitempty"`
	Timeout      int    `json:"timeout_seconds,omitempty"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request, sess *Session) {
	agent, ok := s.store.Agent(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	var req scanRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	set := s.store.Settings()

	scanReq := protocol.ScanRequest{
		Interface:      strings.TrimSpace(req.Interface),
		Subnet:         strings.TrimSpace(req.Subnet),
		Retries:        req.Retries,
		TimeoutSeconds: set.ScanTimeoutSeconds,
		ResolveNames:   set.ResolveNames,
	}
	if req.Timeout > 0 {
		scanReq.TimeoutSeconds = req.Timeout
	}
	if req.ResolveNames != nil {
		scanReq.ResolveNames = *req.ResolveNames
	}
	if scanReq.Subnet != "" {
		if err := validateSubnet(scanReq.Subnet); err != nil {
			writeError(w, http.StatusBadRequest, "%s", err)
			return
		}
	}

	started := time.Now()
	res, err := s.dispatch(r.Context(), agent.ID, &protocol.Command{
		Type: protocol.CmdScan,
		Scan: &scanReq,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "%s", err)
		return
	}
	if !res.OK {
		writeError(w, http.StatusBadGateway, "%s", res.Error)
		return
	}

	recID, _ := NewID()
	rec := &store.ScanRecord{
		ID:          recID,
		AgentID:     agent.ID,
		AgentName:   agent.Name,
		StartedAt:   started,
		FinishedAt:  time.Now(),
		TriggeredBy: sess.Username,
	}
	if res.Scan != nil {
		rec.Segments = res.Scan.Segments
		rec.Hosts = res.Scan.Hosts

		observed := make([]store.ObservedHost, 0, len(res.Scan.Hosts))
		for _, h := range res.Scan.Hosts {
			observed = append(observed, store.ObservedFrom(h.MAC, h.IP, h.Hostname, h.Vendor))
		}
		s.store.ObserveHosts(agent.ID, observed)
	}
	if err := s.store.AddScan(rec); err != nil {
		s.log.Warn("could not record scan history", "error", err)
	}

	s.store.Audit(store.AuditEntry{
		Actor: sess.Username, Action: "scan", Target: agent.Name,
		Detail: fmt.Sprintf("%d hosts", len(rec.Hosts)), Remote: s.remoteAddr(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]any{"scan": rec})
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request, _ *Session) {
	agent, ok := s.store.Agent(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	res, err := s.dispatch(r.Context(), agent.ID, &protocol.Command{
		Type:     protocol.CmdDiscover,
		Discover: &protocol.DiscoverRequest{},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "%s", err)
		return
	}
	if !res.OK {
		writeError(w, http.StatusBadGateway, "%s", res.Error)
		return
	}
	// Refresh the stored topology so the agent list stays accurate without
	// waiting for the agent to restart.
	if res.Discover != nil {
		agent.Interfaces = res.Discover.Interfaces
		if err := s.store.PutAgent(agent); err != nil {
			s.log.Warn("could not persist rediscovered interfaces", "error", err)
		}
	}
	writeJSON(w, http.StatusOK, res.Discover)
}

type wakeRequest struct {
	MAC       string `json:"mac"`
	Broadcast string `json:"broadcast,omitempty"`
	Port      int    `json:"port,omitempty"`
	Count     int    `json:"count,omitempty"`
	SecureOn  string `json:"secure_on,omitempty"`
	Interface string `json:"interface,omitempty"`
}

func (s *Server) handleWakeViaAgent(w http.ResponseWriter, r *http.Request, sess *Session) {
	agent, ok := s.store.Agent(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	var req wakeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	res, err := s.wake(r.Context(), agent, protocol.WoLRequest{
		MAC:       req.MAC,
		Broadcast: req.Broadcast,
		Port:      req.Port,
		Count:     req.Count,
		SecureOn:  req.SecureOn,
		Interface: req.Interface,
	}, sess, r)
	if err != nil {
		writeError(w, http.StatusBadGateway, "%s", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// wake validates and dispatches a Wake-on-LAN request, auditing the result.
// Every wake is audited: a magic packet is a physical-world side effect, and
// "who turned that machine on at 3am" is a question worth being able to answer.
func (s *Server) wake(ctx context.Context, agent *store.Agent, req protocol.WoLRequest, sess *Session, r *http.Request) (*protocol.WoLResult, error) {
	mac, err := netutil.NormalizeMAC(req.MAC)
	if err != nil {
		return nil, err
	}
	req.MAC = mac

	res, err := s.dispatch(ctx, agent.ID, &protocol.Command{Type: protocol.CmdWoL, WoL: &req})
	if err != nil {
		s.store.Audit(store.AuditEntry{
			Actor: sess.Username, Action: "wake", Target: mac,
			Detail: "via " + agent.Name + ": " + err.Error(), Remote: s.remoteAddr(r), OK: false,
		})
		return nil, err
	}
	if !res.OK {
		s.store.Audit(store.AuditEntry{
			Actor: sess.Username, Action: "wake", Target: mac,
			Detail: "via " + agent.Name + ": " + res.Error, Remote: s.remoteAddr(r), OK: false,
		})
		return nil, fmt.Errorf("%s", res.Error)
	}
	s.store.MarkWoken(mac)
	s.store.Audit(store.AuditEntry{
		Actor: sess.Username, Action: "wake", Target: mac,
		Detail: fmt.Sprintf("via %s, %d packets", agent.Name, res.WoL.Sent),
		Remote: s.remoteAddr(r), OK: true,
	})
	return res.WoL, nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ *Session) {
	agent, ok := s.store.Agent(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	var req protocol.StatusRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	if len(req.Targets) == 0 {
		writeJSON(w, http.StatusOK, &protocol.StatusResult{})
		return
	}
	if len(req.Targets) > 512 {
		writeError(w, http.StatusBadRequest, "at most 512 targets per status check")
		return
	}
	res, err := s.dispatch(r.Context(), agent.ID, &protocol.Command{Type: protocol.CmdStatus, Status: &req})
	if err != nil {
		writeError(w, http.StatusBadGateway, "%s", err)
		return
	}
	if !res.OK {
		writeError(w, http.StatusBadGateway, "%s", res.Error)
		return
	}
	writeJSON(w, http.StatusOK, res.Status)
}

// dispatch sends a command with the standard timeout and a clear error when
// the agent is not there.
func (s *Server) dispatch(ctx context.Context, agentID string, cmd *protocol.Command) (*protocol.CommandResult, error) {
	if !s.registry.Connected(agentID) {
		return nil, errAgentOffline
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	return s.registry.Dispatch(ctx, agentID, cmd)
}

// --- enrollment tokens ---

type createTokenRequest struct {
	Label      string `json:"label,omitempty"`
	MaxUses    int    `json:"max_uses,omitempty"`
	TTLMinutes int    `json:"ttl_minutes,omitempty"`
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, sess *Session) {
	var req createTokenRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	secret, err := token.New()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}
	id, err := NewID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}

	t := &store.EnrollToken{
		ID:        id,
		Label:     strings.TrimSpace(req.Label),
		Hash:      token.Hash(secret),
		CreatedAt: time.Now(),
		CreatedBy: sess.Username,
		MaxUses:   req.MaxUses,
	}
	// Single-use by default. A token that can admit any number of agents
	// forever is the thing most likely to end up pasted into a wiki and
	// forgotten.
	if t.MaxUses == 0 {
		t.MaxUses = 1
	}
	if t.MaxUses < 0 {
		t.MaxUses = 0 // explicit unlimited
	}
	ttl := req.TTLMinutes
	if ttl == 0 {
		ttl = 60
	}
	if ttl > 0 {
		t.ExpiresAt = t.CreatedAt.Add(time.Duration(ttl) * time.Minute)
	}
	if err := s.store.PutToken(t); err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}
	s.store.Audit(store.AuditEntry{
		Actor: sess.Username, Action: "token.created", Target: t.ID,
		Detail: fmt.Sprintf("max_uses=%d ttl=%dm", t.MaxUses, ttl), Remote: s.remoteAddr(r), OK: true,
	})

	// The secret is returned exactly once, here. The hub keeps only its hash,
	// so a lost token cannot be recovered — only replaced.
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":        t,
		"secret":       secret,
		"join_command": s.joinCommand(s.publicURL(r), secret),
		"ca_pin":       s.ca.Fingerprint(),
	})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, _ *Session) {
	writeJSON(w, http.StatusOK, map[string]any{"tokens": s.store.Tokens()})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request, sess *Session) {
	id := r.PathValue("id")
	if err := s.store.DeleteToken(id); err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}
	s.store.Audit(store.AuditEntry{
		Actor: sess.Username, Action: "token.revoked", Target: id,
		Remote: s.remoteAddr(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "token revoked"})
}

// handleJoinInfo gives the UI what it needs to render a copy-pasteable enroll
// command, including the CA pin that closes the trust-on-first-use gap.
func (s *Server) handleJoinInfo(w http.ResponseWriter, r *http.Request, _ *Session) {
	writeJSON(w, http.StatusOK, map[string]any{
		"hub_url": s.publicURL(r),
		"ca_pin":  s.ca.Fingerprint(),
		"ca_pem":  string(s.ca.CAPEM()),
	})
}

// --- saved hosts ---

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request, _ *Session) {
	writeJSON(w, http.StatusOK, map[string]any{"hosts": s.store.Hosts()})
}

type saveHostRequest struct {
	MAC           string   `json:"mac"`
	Label         string   `json:"label"`
	LastIP        string   `json:"last_ip,omitempty"`
	Hostname      string   `json:"hostname,omitempty"`
	Vendor        string   `json:"vendor,omitempty"`
	AgentID       string   `json:"agent_id,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	WakePort      int      `json:"wake_port,omitempty"`
	WakeBroadcast string   `json:"wake_broadcast,omitempty"`
	SecureOn      string   `json:"secure_on,omitempty"`
	Note          string   `json:"note,omitempty"`
}

func (s *Server) handleSaveHost(w http.ResponseWriter, r *http.Request, sess *Session) {
	var req saveHostRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	if req.SecureOn != "" {
		if _, err := netutil.NormalizeMAC(req.SecureOn); err != nil {
			writeError(w, http.StatusBadRequest, "SecureOn password must be six hex bytes: %s", err)
			return
		}
	}
	host := &store.SavedHost{
		MAC:           req.MAC,
		Label:         strings.TrimSpace(req.Label),
		LastIP:        req.LastIP,
		Hostname:      req.Hostname,
		Vendor:        req.Vendor,
		AgentID:       req.AgentID,
		Tags:          req.Tags,
		WakePort:      req.WakePort,
		WakeBroadcast: req.WakeBroadcast,
		SecureOn:      req.SecureOn,
		Note:          req.Note,
	}
	saved, err := s.store.SaveHost(host)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	s.store.Audit(store.AuditEntry{
		Actor: sess.Username, Action: "host.saved", Target: saved.MAC,
		Detail: saved.Label, Remote: s.remoteAddr(r), OK: true,
	})
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request, sess *Session) {
	mac := r.PathValue("mac")
	if err := s.store.DeleteHost(mac); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	s.store.Audit(store.AuditEntry{
		Actor: sess.Username, Action: "host.deleted", Target: mac,
		Remote: s.remoteAddr(r), OK: true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "host deleted"})
}

// handleWakeSavedHost wakes a stored host, choosing the agent automatically
// when the host has no pinned one.
func (s *Server) handleWakeSavedHost(w http.ResponseWriter, r *http.Request, sess *Session) {
	host, ok := s.store.Host(r.PathValue("mac"))
	if !ok {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	agent, err := s.agentForHost(host)
	if err != nil {
		writeError(w, http.StatusConflict, "%s", err)
		return
	}
	res, err := s.wake(r.Context(), agent, protocol.WoLRequest{
		MAC:       host.MAC,
		Broadcast: host.WakeBroadcast,
		Port:      host.WakePort,
		SecureOn:  host.SecureOn,
	}, sess, r)
	if err != nil {
		writeError(w, http.StatusBadGateway, "%s", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"wol": res, "agent": agent.Name})
}

// agentForHost resolves which agent should carry a wake.
//
// A magic packet only works on the host's own broadcast domain, so the choice
// matters: sending from the wrong site simply does nothing, silently.
func (s *Server) agentForHost(host *store.SavedHost) (*store.Agent, error) {
	if host.AgentID != "" {
		agent, ok := s.store.Agent(host.AgentID)
		if !ok {
			return nil, fmt.Errorf("the agent pinned to this host no longer exists; pick another")
		}
		if !s.registry.Connected(agent.ID) {
			return nil, fmt.Errorf("agent %s is offline", agent.Name)
		}
		return agent, nil
	}

	// No pinned agent: prefer one whose subnets contain the host's last known
	// IP, since that agent is provably on the right segment.
	var fallback *store.Agent
	for _, agent := range s.store.Agents() {
		if agent.Disabled || !s.registry.Connected(agent.ID) {
			continue
		}
		if fallback == nil {
			fallback = agent
		}
		if host.LastIP == "" {
			continue
		}
		if agentCoversIP(agent, host.LastIP) {
			return agent, nil
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("no agent is connected")
}

// agentCoversIP reports whether any of an agent's subnets contains an address.
func agentCoversIP(agent *store.Agent, ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, ifi := range agent.Interfaces {
		for _, cidr := range ifi.Subnets {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil && network.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// --- history, settings, audit ---

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request, _ *Session) {
	// The list view only needs summaries; sending every host of every scan
	// would be megabytes for no benefit.
	scans := s.store.Scans()
	type summary struct {
		ID          string    `json:"id"`
		AgentID     string    `json:"agent_id"`
		AgentName   string    `json:"agent_name"`
		StartedAt   time.Time `json:"started_at"`
		FinishedAt  time.Time `json:"finished_at"`
		HostCount   int       `json:"host_count"`
		TriggeredBy string    `json:"triggered_by,omitempty"`
	}
	out := make([]summary, 0, len(scans))
	for _, rec := range scans {
		out = append(out, summary{
			ID: rec.ID, AgentID: rec.AgentID, AgentName: rec.AgentName,
			StartedAt: rec.StartedAt, FinishedAt: rec.FinishedAt,
			HostCount: len(rec.Hosts), TriggeredBy: rec.TriggeredBy,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": out})
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request, _ *Session) {
	rec, ok := s.store.Scan(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request, _ *Session) {
	writeJSON(w, http.StatusOK, s.store.Settings())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request, sess *Session) {
	var set store.Settings
	if err := readJSON(r, &set); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	if err := s.store.SaveSettings(set); err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}
	s.store.Audit(store.AuditEntry{
		Actor: sess.Username, Action: "settings.updated", Remote: s.remoteAddr(r), OK: true,
	})
	writeJSON(w, http.StatusOK, s.store.Settings())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ *Session) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.store.AuditTail(limit)})
}

// --- helpers ---

// validateSubnet rejects malformed CIDRs and anything large enough to turn a
// scan into a flood.
func validateSubnet(cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid subnet %q: %w", cidr, err)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("only IPv4 subnets can be ARP-scanned")
	}
	if ones < 18 {
		return fmt.Errorf("subnet %s is too large to ARP-scan; use /18 or smaller", cidr)
	}
	return nil
}

// publicURL reconstructs the address an agent should be pointed at, for the
// join command shown in the UI.
func (s *Server) publicURL(r *http.Request) string {
	scheme := "https"
	if s.cfg.Insecure {
		scheme = "http"
	}
	host := r.Host
	if s.cfg.AgentListen != "" {
		// The agent plane is on its own port; rewrite the host to match so the
		// printed command points somewhere that will actually answer.
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if _, port, err := net.SplitHostPort(s.cfg.AgentListen); err == nil && port != "" {
			host = net.JoinHostPort(host, port)
		}
	}
	return scheme + "://" + host
}

// joinCommand renders the exact command an operator runs on a new agent host.
// The CA pin is included so the agent can verify the hub on first contact
// rather than trusting whatever certificate it is offered.
func (s *Server) joinCommand(hubURL, secret string) string {
	return fmt.Sprintf("nswagent enroll --hub %s --token %s --ca-pin %s",
		hubURL, secret, s.ca.Fingerprint())
}
