package hub

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/ca"
	"github.com/fqazzazee/netscan-wol/internal/protocol"
	"github.com/fqazzazee/netscan-wol/internal/store"
	"github.com/fqazzazee/netscan-wol/internal/token"
)

// pollHold is how long a poll request waits for work before returning empty.
// Shorter than any sensible proxy or load-balancer idle timeout, so the
// connection is refreshed before something in the middle decides to drop it.
const pollHold = 25 * time.Second

func (s *Server) routeAgent(mux *http.ServeMux) {
	mux.HandleFunc("POST "+protocol.PathEnroll, s.handleEnroll)
	mux.HandleFunc("POST "+protocol.PathAgentHello, s.requireAgent(s.handleAgentHello))
	mux.HandleFunc("GET "+protocol.PathAgentPoll, s.requireAgent(s.handleAgentPoll))
	mux.HandleFunc("POST "+protocol.PathAgentResult, s.requireAgent(s.handleAgentResult))
}

// agentHandler is a handler that has already been given an authenticated agent.
type agentHandler func(w http.ResponseWriter, r *http.Request, agent *store.Agent)

// requireAgent authenticates by client certificate.
//
// Three things must hold: TLS verified a chain to the hub CA, the certificate's
// subject names an agent the hub still knows about, and that agent has not been
// disabled. The last check is the revocation mechanism — no CRL to distribute,
// just a flag consulted on every single request.
func (s *Server) requireAgent(next agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cert := clientCert(r)
		if cert == nil {
			writeError(w, http.StatusUnauthorized, "a client certificate issued by this hub is required")
			return
		}
		agentID := ca.AgentIDFromCert(cert)
		agent, ok := s.store.Agent(agentID)
		if !ok {
			// The certificate is cryptographically valid but the agent record
			// is gone: this is what a removed agent looks like.
			s.store.Audit(store.AuditEntry{
				Actor: "agent:" + agentID, Action: "agent.rejected",
				Detail: "certificate is valid but the agent is no longer registered",
				Remote: s.remoteAddr(r),
			})
			writeError(w, http.StatusForbidden, "this agent has been removed from the hub; enroll again")
			return
		}
		if agent.Disabled {
			writeError(w, http.StatusForbidden, "this agent is disabled")
			return
		}
		s.store.TouchAgent(agent.ID, s.remoteAddr(r))
		next(w, r, agent)
	}
}

// handleEnroll admits a new agent in exchange for a valid enrollment token.
//
// This is the only agent route reachable without a certificate, so it is the
// one an attacker would attack. The defences are: a 256-bit secret compared
// against a stored hash in constant time, an atomic claim that consumes a
// single-use token before the certificate is issued, a per-source rate limit,
// and an audit entry for every attempt whether it succeeds or not.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	remote := s.remoteAddr(r)
	if !s.enrollLimiter.allow(hostOnly(remote)) {
		writeError(w, http.StatusTooManyRequests, "too many enrollment attempts; wait a minute and retry")
		return
	}

	var req protocol.EnrollRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	if !token.Valid(req.Token) {
		s.auditEnroll(remote, "", false, "malformed token")
		writeError(w, http.StatusUnauthorized, "enrollment token is not a %d-character hex string", token.Chars)
		return
	}
	if req.CSRPEM == "" {
		writeError(w, http.StatusBadRequest, "a certificate signing request is required")
		return
	}
	name := strings.TrimSpace(req.Hello.Name)
	if name == "" {
		name = req.Hello.Hostname
	}
	if name == "" {
		name = "agent"
	}
	if len(name) > 100 {
		name = name[:100]
	}

	agentID, err := NewID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}

	// Claim before signing. If the token turns out to be single-use and
	// already spent, no certificate is ever minted.
	claimed, err := s.store.ClaimToken(func(hash string) bool {
		return token.Equal(req.Token, hash)
	}, agentID)
	if err != nil {
		s.auditEnroll(remote, name, false, err.Error())
		switch {
		case errors.Is(err, store.ErrTokenUnknown):
			writeError(w, http.StatusUnauthorized, "enrollment token is not recognised")
		case errors.Is(err, store.ErrTokenUnusable):
			writeError(w, http.StatusForbidden, "%s", err)
		default:
			writeError(w, http.StatusInternalServerError, "%s", err)
		}
		return
	}

	certPEM, err := s.ca.SignAgent([]byte(req.CSRPEM), agentID, name)
	if err != nil {
		s.auditEnroll(remote, name, false, "CSR rejected: "+err.Error())
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}

	agent := &store.Agent{
		ID:           agentID,
		Name:         name,
		Hostname:     req.Hello.Hostname,
		Platform:     normalizePlatform(req.Hello.Platform),
		Version:      req.Hello.Version,
		OS:           req.Hello.OS,
		Arch:         req.Hello.Arch,
		Capabilities: req.Hello.Capabilities,
		Interfaces:   req.Hello.Interfaces,
		Labels:       req.Hello.Labels,
		EnrolledAt:   time.Now(),
		LastSeen:     time.Now(),
		RemoteAddr:   remote,
		EnrolledVia:  claimed.ID,
	}
	if err := s.store.PutAgent(agent); err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}

	s.auditEnroll(remote, name, true, "token "+claimed.ID)
	s.log.Info("agent enrolled", "agent", name, "id", agentID, "remote", remote, "platform", agent.Platform)

	writeJSON(w, http.StatusOK, protocol.EnrollResponse{
		AgentID:  agentID,
		CertPEM:  string(certPEM),
		CAPEM:    string(s.ca.CAPEM()),
		HubName:  s.store.Settings().HubName,
		Protocol: protocol.Version,
	})
}

func (s *Server) auditEnroll(remote, name string, ok bool, detail string) {
	s.store.Audit(store.AuditEntry{
		Actor:  "enroll",
		Action: "agent.enroll",
		Target: name,
		Detail: detail,
		Remote: remote,
		OK:     ok,
	})
}

// handleAgentHello refreshes an agent's self-description after a restart.
func (s *Server) handleAgentHello(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var hello protocol.AgentHello
	if err := readJSON(r, &hello); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	if hello.Protocol != "" && hello.Protocol != protocol.Version {
		writeError(w, http.StatusConflict,
			"agent speaks protocol %s but this hub speaks %s; upgrade the agent", hello.Protocol, protocol.Version)
		return
	}

	// An agent may refresh its own description but never its identity: the ID
	// and display name stay under hub control, so a compromised agent cannot
	// rename itself into something an operator would trust more.
	agent.Hostname = hello.Hostname
	agent.Platform = normalizePlatform(hello.Platform)
	agent.Version = hello.Version
	agent.OS = hello.OS
	agent.Arch = hello.Arch
	agent.Capabilities = hello.Capabilities
	agent.Interfaces = hello.Interfaces
	agent.Labels = hello.Labels
	agent.LastSeen = time.Now()
	agent.RemoteAddr = s.remoteAddr(r)
	if err := s.store.PutAgent(agent); err != nil {
		writeError(w, http.StatusInternalServerError, "%s", err)
		return
	}

	writeJSON(w, http.StatusOK, protocol.HelloResponse{
		AgentID:             agent.ID,
		HubName:             s.store.Settings().HubName,
		PollIntervalSeconds: int(pollHold / time.Second),
	})
}

// handleAgentPoll holds a request open until a command is ready.
//
// Returning 204 on timeout rather than an error keeps the agent loop simple:
// any non-2xx means something is wrong and is worth backing off over, while an
// empty 204 just means "nothing to do, ask again".
func (s *Server) handleAgentPoll(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	inbox, disconnect := s.registry.Connect(agent.ID)
	defer disconnect()

	ctx := r.Context()
	timer := time.NewTimer(pollHold)
	defer timer.Stop()

	select {
	case cmd := <-inbox:
		if cmd == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, cmd)
	case <-timer.C:
		w.WriteHeader(http.StatusNoContent)
	case <-ctx.Done():
		// Client hung up; nothing to write.
	}
}

// handleAgentResult accepts a command result and routes it to the waiting
// dispatcher.
func (s *Server) handleAgentResult(w http.ResponseWriter, r *http.Request, agent *store.Agent) {
	var res protocol.CommandResult
	if err := readJSON(r, &res); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)
		return
	}
	// The agent ID is taken from the certificate, never from the body. A
	// result claiming to be from another agent is rejected by the registry.
	res.AgentID = agent.ID

	if err := s.registry.Deliver(&res); err != nil {
		// Not an error worth failing the agent over: the waiter may simply
		// have timed out. Acknowledge and move on.
		s.log.Debug("orphan command result", "agent", agent.Name, "command", res.CommandID, "reason", err)
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "no waiter"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "delivered"})
}

// normalizePlatform keeps unexpected values out of the UI's grouping logic.
func normalizePlatform(p protocol.Platform) protocol.Platform {
	switch p {
	case protocol.PlatformHost, protocol.PlatformDocker, protocol.PlatformPodman,
		protocol.PlatformKubernetes, protocol.PlatformLXC:
		return p
	default:
		return protocol.PlatformUnknown
	}
}

// rateLimiter is a fixed-window counter keyed by source address. Fixed windows
// allow a small burst at a boundary, which is fine here: the goal is to stop
// sustained token guessing, not to police exact request spacing.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*windowCount
}

type windowCount struct {
	count int
	start time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: make(map[string]*windowCount)}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	rec, ok := l.hits[key]
	if !ok || now.Sub(rec.start) > l.window {
		l.hits[key] = &windowCount{count: 1, start: now}
		// Opportunistic cleanup so an attacker cycling source addresses cannot
		// grow the map without bound.
		if len(l.hits) > 4096 {
			for k, v := range l.hits {
				if now.Sub(v.start) > l.window {
					delete(l.hits, k)
				}
			}
		}
		return true
	}
	if rec.count >= l.limit {
		return false
	}
	rec.count++
	return true
}
