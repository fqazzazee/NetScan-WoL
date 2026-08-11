package hub

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// SessionCookie is the name of the operator session cookie.
const SessionCookie = "nsw_session"

// CSRFHeader carries the anti-forgery token on state-changing requests.
const CSRFHeader = "X-NSW-CSRF"

// Session lifetimes. Short enough that a forgotten browser tab on a shared
// machine stops being useful the same day; long enough not to be a nuisance.
const (
	sessionTTL  = 12 * time.Hour
	sessionIdle = 2 * time.Hour
)

// Session is one logged-in operator.
type Session struct {
	ID       string
	Username string
	CSRF     string
	Created  time.Time
	LastSeen time.Time
	Remote   string
}

// Sessions is an in-memory session table. Sessions deliberately do not survive
// a hub restart: the state file already holds password and token hashes, and
// persisting live session tokens next to them would widen what a stolen backup
// is worth.
type Sessions struct {
	mu   sync.Mutex
	byID map[string]*Session
}

// NewSessions builds an empty session table and starts its reaper.
func NewSessions() *Sessions {
	s := &Sessions{byID: make(map[string]*Session)}
	go s.reap()
	return s
}

// Create issues a session for a username.
func (s *Sessions) Create(username, remote string) (*Session, error) {
	id, err := randomToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sess := &Session{
		ID:       id,
		Username: username,
		CSRF:     csrf,
		Created:  now,
		LastSeen: now,
		Remote:   remote,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[id] = sess
	return sess, nil
}

// Lookup validates a session ID and refreshes its idle timer.
func (s *Sessions) Lookup(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	now := time.Now()
	if now.Sub(sess.Created) > sessionTTL || now.Sub(sess.LastSeen) > sessionIdle {
		delete(s.byID, id)
		return nil, false
	}
	sess.LastSeen = now
	clone := *sess
	return &clone, true
}

// Destroy invalidates one session.
func (s *Sessions) Destroy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

// DestroyUser invalidates every session belonging to a user, which is what a
// password change must do.
func (s *Sessions) DestroyUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.byID {
		if sess.Username == username {
			delete(s.byID, id)
		}
	}
}

// reap clears expired sessions so an abandoned hub does not accumulate them.
func (s *Sessions) reap() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, sess := range s.byID {
			if now.Sub(sess.Created) > sessionTTL || now.Sub(sess.LastSeen) > sessionIdle {
				delete(s.byID, id)
			}
		}
		s.mu.Unlock()
	}
}

// SetCookie writes the session cookie.
//
// HttpOnly keeps the value away from any script on the page, SameSite=Strict
// means a hostile site cannot cause the browser to attach it to a cross-site
// request, and Secure is set whenever the hub is serving TLS — which, being the
// default, is almost always.
func SetCookie(w http.ResponseWriter, sess *Session, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  sess.Created.Add(sessionTTL),
	})
}

// ClearCookie expires the session cookie on logout.
func ClearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// randomToken returns 256 bits of randomness in URL-safe base64.
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// LoginThrottle rate-limits failed logins per source address.
//
// The operator login is the one endpoint an attacker can guess at, and PBKDF2
// makes each attempt expensive for the *server* too. Throttling protects both
// the account and the hub's CPU.
type LoginThrottle struct {
	mu       sync.Mutex
	attempts map[string]*attemptRecord
}

type attemptRecord struct {
	count int
	first time.Time
	until time.Time
}

const (
	maxFailedLogins = 8
	throttleWindow  = 10 * time.Minute
	lockoutPeriod   = 15 * time.Minute
)

// NewLoginThrottle builds an empty throttle.
func NewLoginThrottle() *LoginThrottle {
	return &LoginThrottle{attempts: make(map[string]*attemptRecord)}
}

// Allowed reports whether an address may attempt a login, and how long it must
// wait if not.
func (t *LoginThrottle) Allowed(remote string) (bool, time.Duration) {
	key := hostOnly(remote)
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.attempts[key]
	if !ok {
		return true, 0
	}
	now := time.Now()
	if now.Before(rec.until) {
		return false, time.Until(rec.until)
	}
	if now.Sub(rec.first) > throttleWindow {
		delete(t.attempts, key)
	}
	return true, 0
}

// Fail records a failed attempt and locks the address out once the limit is hit.
func (t *LoginThrottle) Fail(remote string) {
	key := hostOnly(remote)
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	rec, ok := t.attempts[key]
	if !ok || now.Sub(rec.first) > throttleWindow {
		t.attempts[key] = &attemptRecord{count: 1, first: now}
		return
	}
	rec.count++
	if rec.count >= maxFailedLogins {
		rec.until = now.Add(lockoutPeriod)
	}
}

// Succeed clears the record for an address after a successful login.
func (t *LoginThrottle) Succeed(remote string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.attempts, hostOnly(remote))
}

// hostOnly strips the port so attempts from one machine share a bucket.
func hostOnly(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}
