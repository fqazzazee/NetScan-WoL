package store

import (
	"time"

	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

// Agent is a registered remote agent as the hub knows it.
type Agent struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Hostname string            `json:"hostname,omitempty"`
	Platform protocol.Platform `json:"platform"`
	Version  string            `json:"version,omitempty"`
	OS       string            `json:"os,omitempty"`
	Arch     string            `json:"arch,omitempty"`

	Capabilities []string                `json:"capabilities,omitempty"`
	Interfaces   []protocol.NetInterface `json:"interfaces,omitempty"`
	Labels       map[string]string       `json:"labels,omitempty"`

	EnrolledAt time.Time `json:"enrolled_at"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	// RemoteAddr is the address the agent last connected from. Shown in the UI
	// because an agent that suddenly appears from a new network is worth
	// noticing.
	RemoteAddr string `json:"remote_addr,omitempty"`
	// EnrolledVia records which token admitted this agent, so revoking a leaked
	// token also tells you exactly what it let in.
	EnrolledVia string `json:"enrolled_via,omitempty"`
	// Disabled agents keep their certificate but are refused at the API. This
	// is the revocation mechanism: no CRL to distribute, just a flag the hub
	// checks on every request.
	Disabled bool   `json:"disabled,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Online reports whether the agent has polled recently enough to be considered
// connected. The window is deliberately generous: an agent mid-scan can go
// quiet for the length of the scan.
func (a Agent) Online(now time.Time, window time.Duration) bool {
	return !a.LastSeen.IsZero() && now.Sub(a.LastSeen) < window
}

// EnrollToken is a shared secret that admits agents. Only the hash is stored.
type EnrollToken struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	// Hash is the SHA-256 of the token; the token itself is shown exactly once,
	// at creation, and never persisted.
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// MaxUses of 0 means unlimited. One is the default and the safe choice: a
	// token that can only ever admit one agent cannot be quietly reused by
	// someone who read it over your shoulder.
	MaxUses int  `json:"max_uses"`
	Uses    int  `json:"uses"`
	Revoked bool `json:"revoked,omitempty"`
	// LastUsedAt and AgentIDs make a leaked token's blast radius visible.
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	AgentIDs   []string  `json:"agent_ids,omitempty"`
}

// Usable reports whether the token may still admit an agent, and why not if it
// cannot.
func (t EnrollToken) Usable(now time.Time) (bool, string) {
	switch {
	case t.Revoked:
		return false, "token has been revoked"
	case !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt):
		return false, "token has expired"
	case t.MaxUses > 0 && t.Uses >= t.MaxUses:
		return false, "token has already been used"
	}
	return true, ""
}

// SavedHost is a machine an operator cares about, keyed by MAC because that is
// the only identifier that survives a DHCP lease change.
type SavedHost struct {
	MAC      string `json:"mac"`
	Label    string `json:"label"`
	LastIP   string `json:"last_ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	// AgentID is the agent that can reach this host. Empty means "whichever
	// agent last saw it", which the hub resolves at wake time.
	AgentID   string    `json:"agent_id,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	LastWake  time.Time `json:"last_wake,omitempty"`
	// WoL overrides for hosts that need them.
	WakePort      int    `json:"wake_port,omitempty"`
	WakeBroadcast string `json:"wake_broadcast,omitempty"`
	SecureOn      string `json:"secure_on,omitempty"`
	Note          string `json:"note,omitempty"`
}

// ScanRecord is one completed scan, kept for history.
type ScanRecord struct {
	ID          string                 `json:"id"`
	AgentID     string                 `json:"agent_id"`
	AgentName   string                 `json:"agent_name,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	FinishedAt  time.Time              `json:"finished_at"`
	Segments    []protocol.ScanSegment `json:"segments,omitempty"`
	Hosts       []protocol.Host        `json:"hosts,omitempty"`
	Error       string                 `json:"error,omitempty"`
	TriggeredBy string                 `json:"triggered_by,omitempty"`
}

// Operator is a web UI login.
type Operator struct {
	Username  string    `json:"username"`
	PassHash  string    `json:"pass_hash"`
	Salt      string    `json:"salt"`
	Iter      int       `json:"iter"`
	CreatedAt time.Time `json:"created_at"`
	// MustChangePassword is set when the hub generated the initial password, so
	// the UI can insist on a real one before anything else happens.
	MustChangePassword bool      `json:"must_change_password,omitempty"`
	LastLogin          time.Time `json:"last_login,omitempty"`
}

// Settings holds hub-wide preferences.
type Settings struct {
	HubName string `json:"hub_name"`
	// DefaultTheme is the theme served to a browser with no stored preference:
	// "system", "light" or "dark".
	DefaultTheme string `json:"default_theme"`
	// ScanTimeoutSeconds and ResolveNames are the defaults applied to scans
	// launched from the UI.
	ScanTimeoutSeconds int  `json:"scan_timeout_seconds"`
	ResolveNames       bool `json:"resolve_names"`
	// HistoryLimit caps how many scan records are retained per agent.
	HistoryLimit int `json:"history_limit"`
	// AgentOnlineWindowSeconds is how long after its last poll an agent is
	// still shown as online.
	AgentOnlineWindowSeconds int `json:"agent_online_window_seconds"`
}

// DefaultSettings returns the settings a fresh hub starts with.
func DefaultSettings() Settings {
	return Settings{
		HubName:                  "NetScan-WoL",
		DefaultTheme:             "system",
		ScanTimeoutSeconds:       60,
		ResolveNames:             true,
		HistoryLimit:             50,
		AgentOnlineWindowSeconds: 90,
	}
}

// AuditEntry is one line of the append-only security log.
type AuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Remote string    `json:"remote,omitempty"`
	OK     bool      `json:"ok"`
}
