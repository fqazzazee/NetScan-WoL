// Package protocol defines the wire types shared between the NetScan-WoL
// command hub and its agents. Everything here is JSON over mTLS; keeping the
// definitions in one package means the hub and the agent can never disagree
// about a field name.
package protocol

import "time"

// Version is the protocol revision. The hub refuses agents that speak a
// different major revision.
const Version = "2"

// APIPath prefixes. Agent endpoints require a client certificate issued by the
// hub CA; the enroll endpoint is the sole exception and is guarded by a
// one-time enrollment token instead.
const (
	PathEnroll      = "/api/v1/agent/enroll"
	PathAgentHello  = "/api/v1/agent/hello"
	PathAgentPoll   = "/api/v1/agent/poll"
	PathAgentResult = "/api/v1/agent/result"
)

// CommandType enumerates the work a hub can ask an agent to perform.
type CommandType string

const (
	CmdScan     CommandType = "scan"
	CmdWoL      CommandType = "wol"
	CmdStatus   CommandType = "status"
	CmdDiscover CommandType = "discover"
	CmdPing     CommandType = "ping"
)

// Command travels hub -> agent. Exactly one of the request pointers is set,
// matching Type.
type Command struct {
	ID       string      `json:"id"`
	Type     CommandType `json:"type"`
	IssuedAt time.Time   `json:"issued_at"`

	Scan     *ScanRequest     `json:"scan,omitempty"`
	WoL      *WoLRequest      `json:"wol,omitempty"`
	Status   *StatusRequest   `json:"status,omitempty"`
	Discover *DiscoverRequest `json:"discover,omitempty"`
}

// CommandResult travels agent -> hub in reply to a Command.
type CommandResult struct {
	CommandID  string      `json:"command_id"`
	AgentID    string      `json:"agent_id"`
	Type       CommandType `json:"type"`
	OK         bool        `json:"ok"`
	Error      string      `json:"error,omitempty"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`

	Scan     *ScanResult     `json:"scan,omitempty"`
	WoL      *WoLResult      `json:"wol,omitempty"`
	Status   *StatusResult   `json:"status,omitempty"`
	Discover *DiscoverResult `json:"discover,omitempty"`
}

// ScanRequest asks an agent to sweep a broadcast domain with ARP.
type ScanRequest struct {
	// Interface to scan from. Empty means "every eligible interface the agent
	// can see", which is the auto-discovery path.
	Interface string `json:"interface,omitempty"`
	// Subnet in CIDR form. Empty means the interface's own subnet.
	Subnet string `json:"subnet,omitempty"`
	// TimeoutSeconds bounds the whole scan. Zero uses the agent default.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// ResolveNames enables reverse DNS and mDNS lookups for discovered hosts.
	ResolveNames bool `json:"resolve_names"`
	// Retries is how many ARP requests to send per address.
	Retries int `json:"retries,omitempty"`
}

// Host is one discovered machine on a broadcast domain.
type Host struct {
	IP       string  `json:"ip"`
	MAC      string  `json:"mac"`
	Vendor   string  `json:"vendor,omitempty"`
	Hostname string  `json:"hostname,omitempty"`
	RTTMs    float64 `json:"rtt_ms,omitempty"`
	// Source records how the host was found: "arp", "neigh" or "arp-scan".
	Source string `json:"source,omitempty"`
}

// ScanResult is the outcome of one ScanRequest, possibly spanning several
// interfaces when the request asked for auto-discovery.
type ScanResult struct {
	Segments []ScanSegment `json:"segments"`
	Hosts    []Host        `json:"hosts"`
}

// ScanSegment records which interface/subnet pair produced results.
type ScanSegment struct {
	Interface string `json:"interface"`
	Subnet    string `json:"subnet"`
	HostCount int    `json:"host_count"`
	Method    string `json:"method"`
	Error     string `json:"error,omitempty"`
}

// WoLRequest asks an agent to emit magic packets.
type WoLRequest struct {
	MAC string `json:"mac"`
	// Broadcast is the destination address. Empty means the directed broadcast
	// of the agent's interface, falling back to 255.255.255.255.
	Broadcast string `json:"broadcast,omitempty"`
	Port      int    `json:"port,omitempty"`
	// Count is how many identical packets to send; repeats improve delivery on
	// lossy links. Zero uses the agent default.
	Count int `json:"count,omitempty"`
	// SecureOn is an optional 6-byte password in MAC notation, appended to the
	// magic packet for adapters configured with SecureOn.
	SecureOn string `json:"secure_on,omitempty"`
	// Interface pins the outgoing interface. Empty lets the agent choose.
	Interface string `json:"interface,omitempty"`
}

// WoLResult reports what was actually sent.
type WoLResult struct {
	MAC          string   `json:"mac"`
	Sent         int      `json:"sent"`
	Destinations []string `json:"destinations"`
}

// StatusRequest asks the agent to liveness-check a set of hosts.
type StatusRequest struct {
	Targets        []StatusTarget `json:"targets"`
	TimeoutSeconds int            `json:"timeout_seconds,omitempty"`
}

// StatusTarget identifies one host to probe. IP is required; MAC is used to
// confirm the responder is the host we meant rather than a DHCP reassignment.
type StatusTarget struct {
	IP  string `json:"ip"`
	MAC string `json:"mac,omitempty"`
}

// HostStatus is one liveness verdict.
type HostStatus struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac,omitempty"`
	Online bool   `json:"online"`
	// Method is "arp" or "icmp" depending on which probe answered.
	Method string  `json:"method,omitempty"`
	RTTMs  float64 `json:"rtt_ms,omitempty"`
	// MACMatch is false when the host answered but from a different MAC than
	// expected, which usually means the IP was reassigned.
	MACMatch bool `json:"mac_match"`
}

// StatusResult carries the verdicts back.
type StatusResult struct {
	Targets []HostStatus `json:"targets"`
}

// DiscoverRequest asks the agent to re-enumerate its own network topology.
type DiscoverRequest struct{}

// DiscoverResult lists what the agent can reach.
type DiscoverResult struct {
	Interfaces []NetInterface `json:"interfaces"`
}

// NetInterface describes one usable network interface on an agent.
type NetInterface struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac,omitempty"`
	MTU   int      `json:"mtu,omitempty"`
	Up    bool     `json:"up"`
	Addrs []string `json:"addrs,omitempty"`
	// Subnets are the IPv4 CIDRs reachable directly on this link.
	Subnets []string `json:"subnets,omitempty"`
	// Broadcast is the directed broadcast address for the primary subnet.
	Broadcast string `json:"broadcast,omitempty"`
	// Eligible is false for loopback, down, and point-to-point links that
	// cannot carry ARP scans.
	Eligible bool   `json:"eligible"`
	Skip     string `json:"skip_reason,omitempty"`
}

// Platform describes where an agent is running. Used by the UI for grouping
// and by the hub to explain capability differences.
type Platform string

const (
	PlatformHost       Platform = "host"
	PlatformDocker     Platform = "docker"
	PlatformPodman     Platform = "podman"
	PlatformKubernetes Platform = "kubernetes"
	PlatformLXC        Platform = "lxc"
	PlatformUnknown    Platform = "unknown"
)

// Capability strings an agent may advertise.
const (
	CapARPRaw  = "arp-raw"  // native AF_PACKET ARP scanning
	CapARPScan = "arp-scan" // external arp-scan binary present
	CapNeigh   = "neigh"    // can read the kernel neighbour table
	CapMDNS    = "mdns"     // multicast DNS resolution
	CapICMP    = "icmp"     // can send ICMP echo
	CapWoL     = "wol"      // can emit UDP broadcast
)

// AgentHello is the self-description an agent sends at enrollment and on every
// reconnect.
type AgentHello struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Protocol     string            `json:"protocol"`
	OS           string            `json:"os"`
	Arch         string            `json:"arch"`
	Hostname     string            `json:"hostname"`
	Platform     Platform          `json:"platform"`
	Capabilities []string          `json:"capabilities"`
	Interfaces   []NetInterface    `json:"interfaces"`
	Labels       map[string]string `json:"labels,omitempty"`
}

// EnrollRequest is the one unauthenticated-by-certificate call in the API. The
// token proves the operator authorised this agent; the CSR carries the public
// key the hub will bind to the issued identity.
type EnrollRequest struct {
	Token  string     `json:"token"`
	CSRPEM string     `json:"csr_pem"`
	Hello  AgentHello `json:"hello"`
}

// EnrollResponse hands back the signed identity plus the CA needed to verify
// the hub on subsequent connections.
type EnrollResponse struct {
	AgentID  string `json:"agent_id"`
	CertPEM  string `json:"cert_pem"`
	CAPEM    string `json:"ca_pem"`
	HubName  string `json:"hub_name"`
	Protocol string `json:"protocol"`
}

// HelloResponse is returned from the hello endpoint after a reconnect.
type HelloResponse struct {
	AgentID string `json:"agent_id"`
	HubName string `json:"hub_name"`
	// PollIntervalSeconds is how long the agent should let a poll hang before
	// retrying.
	PollIntervalSeconds int `json:"poll_interval_seconds"`
}

// Error is the uniform error body for every API failure.
type Error struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}
