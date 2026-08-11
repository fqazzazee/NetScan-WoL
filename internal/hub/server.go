// Package hub implements the NetScan-WoL command hub: the operator web UI, the
// agent-facing API, and the dispatcher that connects the two.
package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/ca"
	"github.com/fqazzazee/netscan-wol/internal/store"
	"github.com/fqazzazee/netscan-wol/internal/web"
)

// Config describes how the hub should run.
type Config struct {
	// Listen is the operator UI address, e.g. ":8443".
	Listen string
	// AgentListen optionally puts the agent API on its own listener. Leaving it
	// empty serves both planes on Listen, which is simpler to expose through a
	// single Kubernetes ingress. Setting it lets you firewall the agent plane
	// separately from the browser plane.
	AgentListen string
	// Names are the DNS names and IPs the hub's TLS certificate should cover.
	Names []string
	// DataDir holds state, the CA, and the audit log.
	DataDir string
	// Insecure serves plain HTTP. Only for putting the hub behind a TLS-
	// terminating proxy you control; agents still require the mTLS listener.
	Insecure bool
	// TrustProxyHeaders makes the hub believe X-Forwarded-For. Off by default
	// because a spoofable client address would defeat login throttling.
	TrustProxyHeaders bool
	Logger            *slog.Logger
}

// Server is a running hub.
type Server struct {
	cfg           Config
	log           *slog.Logger
	store         *store.Store
	ca            *ca.Authority
	registry      *Registry
	sessions      *Sessions
	throttle      *LoginThrottle
	enrollLimiter *rateLimiter

	uiSrv    *http.Server
	agentSrv *http.Server
}

// New builds a hub from its configuration, creating the CA, the data
// directory and the bootstrap operator on first run.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("a data directory is required")
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	authority, err := ca.Open(cfg.DataDir+"/pki", cfg.Names)
	if err != nil {
		return nil, err
	}

	// A CA created by an early v2 build used Ed25519, which no browser can
	// verify. Agents are unaffected, but the web interface becomes unreachable,
	// so say so plainly rather than leaving the operator to debug an opaque TLS
	// error.
	if !authority.BrowserCompatible() {
		cfg.Logger.Warn("this hub's certificate authority uses Ed25519, which no browser can verify",
			"effect", "Firefox, Chrome and Brave refuse to connect with SSL_ERROR_NO_CYPHER_OVERLAP; agents still work",
			"fix", "stop the hub, delete "+cfg.DataDir+"/pki, restart to generate an ECDSA authority, then re-enroll every agent")
	}

	s := &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		store:    st,
		ca:       authority,
		registry: NewRegistry(),
		sessions: NewSessions(),
		throttle: NewLoginThrottle(),
		// Enrollment is the one route reachable with only a shared secret, so
		// it gets its own limiter independent of the login throttle.
		enrollLimiter: newRateLimiter(10, time.Minute),
	}
	return s, nil
}

// Store exposes the state store, used by the bootstrap command.
func (s *Server) Store() *store.Store { return s.store }

// CA exposes the authority so the CLI can print the pin.
func (s *Server) CA() *ca.Authority { return s.ca }

// Start begins serving. It returns once the listeners are up; use Wait or the
// returned error channel to observe failures.
func (s *Server) Start() (<-chan error, error) {
	errs := make(chan error, 2)

	uiMux := http.NewServeMux()
	s.routeOperator(uiMux)
	s.routeUI(uiMux)

	agentMux := uiMux
	if s.cfg.AgentListen != "" {
		agentMux = http.NewServeMux()
	}
	s.routeAgent(agentMux)

	uiHandler := s.withCommonMiddleware(uiMux)

	if s.cfg.Insecure {
		s.uiSrv = &http.Server{
			Addr:              s.cfg.Listen,
			Handler:           uiHandler,
			ReadHeaderTimeout: 10 * time.Second,
			// No write timeout: the agent long-poll deliberately holds a
			// response open, and a global write deadline would cut it.
			IdleTimeout: 120 * time.Second,
		}
		go func() { errs <- s.uiSrv.ListenAndServe() }()
		s.log.Warn("serving without TLS; agent traffic and operator credentials are not protected in transit",
			"listen", s.cfg.Listen)
		return errs, nil
	}

	tlsCfg, err := s.tlsConfig(s.cfg.AgentListen == "")
	if err != nil {
		return nil, err
	}
	s.uiSrv = &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           uiHandler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() { errs <- s.uiSrv.ListenAndServeTLS("", "") }()

	if s.cfg.AgentListen != "" {
		agentTLS, err := s.tlsConfig(true)
		if err != nil {
			return nil, err
		}
		s.agentSrv = &http.Server{
			Addr:              s.cfg.AgentListen,
			Handler:           s.withCommonMiddleware(agentMux),
			TLSConfig:         agentTLS,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() { errs <- s.agentSrv.ListenAndServeTLS("", "") }()
	}

	return errs, nil
}

// Shutdown stops the listeners and flushes state.
func (s *Server) Shutdown(ctx context.Context) error {
	var firstErr error
	for _, srv := range []*http.Server{s.uiSrv, s.agentSrv} {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := s.store.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// tlsConfig builds the server TLS settings.
//
// TLS 1.2 is the floor rather than 1.3 only because some minimal container
// bases still ship older clients; every cipher offered below is an AEAD with
// forward secrecy, so a 1.2 handshake here is not a meaningful downgrade.
func (s *Server) tlsConfig(acceptClientCerts bool) (*tls.Config, error) {
	certPath, keyPath := s.ca.ServerCertPaths()
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load hub TLS certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
	if acceptClientCerts {
		// VerifyClientCertIfGiven rather than RequireAndVerify: the enrollment
		// endpoint is by definition reached without a certificate, and when
		// both planes share a listener, browsers arrive without one too. Every
		// agent route re-checks for a verified chain before doing anything.
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		cfg.ClientCAs = s.ca.ClientCAPool()
	}
	return cfg, nil
}

// withCommonMiddleware applies security headers and a body size limit to every
// request.
func (s *Server) withCommonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// The UI ships no third-party code and makes no external requests, so
		// the policy can be as tight as it gets: same-origin everything, no
		// framing, no plugins, no form posts off-site.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "+
				"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "+
				"form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		if !s.cfg.Insecure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}

		// 4 MiB is far more than any legitimate request; a scan result from a
		// /18 is well under it, and the cap stops an unbounded body from
		// exhausting memory.
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		next.ServeHTTP(w, r)
	})
}

// routeUI serves the embedded single-page interface.
func (s *Server) routeUI(mux *http.ServeMux) {
	mux.Handle("GET /", web.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

// --- request helpers ---

// remoteAddr returns the client address, honouring proxy headers only when the
// operator explicitly opted in. Trusting X-Forwarded-For by default would let
// anyone reset their own login throttle by inventing a header.
func (s *Server) remoteAddr(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if first, _, ok := strings.Cut(fwd, ","); ok {
				return strings.TrimSpace(first)
			}
			return strings.TrimSpace(fwd)
		}
	}
	return r.RemoteAddr
}

// clientCert returns the verified agent certificate on a request, if any.
func clientCert(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already out; nothing useful is left to do but note
		// it for the operator.
		slog.Debug("write response body", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, args...)})
}

// readJSON decodes a request body, rejecting unknown fields so a typo in an
// API call fails loudly instead of being silently ignored.
func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

// errAgentOffline is returned when a command is issued to an agent that is not
// holding a poll open.
var errAgentOffline = errors.New("agent is not connected")

// hostPortNames expands a listen address into the names the certificate should
// carry, so a hub reachable at both its IP and hostname works either way.
func hostPortNames(listen string, extra []string) []string {
	names := append([]string{}, extra...)
	host, _, err := net.SplitHostPort(listen)
	if err == nil && host != "" && host != "0.0.0.0" && host != "::" {
		names = append(names, host)
	}
	return names
}
