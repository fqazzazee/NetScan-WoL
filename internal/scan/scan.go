// Package scan discovers hosts on a broadcast domain.
//
// ARP is used rather than ICMP for the reason the tool exists: every host that
// participates in an Ethernet segment must answer ARP, while a firewalled
// workstation can silently drop pings. Three methods are tried in order of
// fidelity — native raw-socket ARP, the external arp-scan binary, and finally
// the kernel neighbour table — so the agent still returns useful results in a
// container that was not granted CAP_NET_RAW.
package scan

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/netutil"
	"github.com/fqazzazee/netscan-wol/internal/oui"
	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

// Method names reported back to the hub so an operator can tell a
// full-fidelity sweep from a degraded one.
const (
	MethodRawARP = "arp-raw"
	MethodARPBin = "arp-scan"
	MethodNeigh  = "neigh"
)

// Defaults chosen to finish a /24 in roughly a second on a healthy segment
// while staying gentle enough not to trip switch storm control.
const (
	defaultRetries = 2
	defaultPacing  = 800 * time.Microsecond
	defaultSettle  = 700 * time.Millisecond
	defaultTimeout = 60 * time.Second
)

// Scanner runs scans on behalf of an agent. It is safe for concurrent use, but
// deliberately serialises the actual sweeps: two raw ARP sweeps on the same
// segment interleave badly and produce noisier results than one at a time.
type Scanner struct {
	mu       sync.Mutex
	resolver *Resolver
	vendors  *oui.DB
}

// NewScanner builds a scanner with hostname resolution and vendor lookup wired
// in.
func NewScanner() *Scanner {
	return &Scanner{
		resolver: NewResolver(),
		vendors:  oui.Default(),
	}
}

// Capabilities reports what this host can actually do, so the hub UI can
// explain a degraded agent rather than just showing worse results.
func Capabilities() []string {
	caps := []string{protocol.CapNeigh, protocol.CapWoL}
	if rawARPAvailable() {
		caps = append(caps, protocol.CapARPRaw, protocol.CapICMP)
	}
	if _, err := exec.LookPath("arp-scan"); err == nil {
		caps = append(caps, protocol.CapARPScan)
	}
	caps = append(caps, protocol.CapMDNS)
	sort.Strings(caps)
	return caps
}

// Scan executes a scan request across one or all eligible interfaces.
func (s *Scanner) Scan(ctx context.Context, req protocol.ScanRequest) (*protocol.ScanResult, error) {
	timeout := defaultTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	segments, err := s.plan(req)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	result := &protocol.ScanResult{}
	// byMAC dedupes across segments: a host reachable on two interfaces should
	// appear once, not twice.
	byMAC := make(map[string]protocol.Host)

	for _, seg := range segments {
		if ctx.Err() != nil {
			break
		}
		hosts, method, err := s.scanSegment(ctx, seg, req)
		reported := protocol.ScanSegment{
			Interface: seg.iface.Name,
			Subnet:    seg.network.String(),
			Method:    method,
			HostCount: len(hosts),
		}
		if err != nil {
			reported.Error = err.Error()
		}
		result.Segments = append(result.Segments, reported)
		for _, h := range hosts {
			existing, ok := byMAC[h.MAC]
			if !ok || (existing.Hostname == "" && h.Hostname != "") {
				byMAC[h.MAC] = h
			}
		}
	}

	for _, h := range byMAC {
		result.Hosts = append(result.Hosts, h)
	}
	sortHosts(result.Hosts)

	if req.ResolveNames {
		s.resolver.Enrich(ctx, result.Hosts)
	}
	for i := range result.Hosts {
		result.Hosts[i].Vendor = s.vendors.Lookup(result.Hosts[i].MAC)
	}

	if len(result.Segments) == 0 {
		return nil, fmt.Errorf("no scannable interface found")
	}
	return result, nil
}

// segment is one interface/network pair to sweep.
type segment struct {
	iface   *net.Interface
	srcIP   net.IP
	network *net.IPNet
}

// plan turns a request into the concrete list of segments to sweep. An empty
// Interface means auto-discovery: every eligible interface on the agent.
func (s *Scanner) plan(req protocol.ScanRequest) ([]segment, error) {
	var candidates []protocol.NetInterface
	if req.Interface != "" {
		ni, err := netutil.InterfaceByName(req.Interface)
		if err != nil {
			return nil, err
		}
		if !ni.Eligible {
			return nil, fmt.Errorf("interface %s cannot be scanned: %s", ni.Name, ni.Skip)
		}
		candidates = []protocol.NetInterface{ni}
	} else {
		var err error
		candidates, err = netutil.EligibleInterfaces()
		if err != nil {
			return nil, err
		}
		if len(candidates) == 0 {
			return nil, fmt.Errorf("no eligible interface: every link is down, loopback, or has no IPv4 address")
		}
	}

	var out []segment
	for _, ni := range candidates {
		ifi, err := net.InterfaceByName(ni.Name)
		if err != nil {
			continue
		}
		srcIP, ownNet, err := netutil.PrimarySourceIP(ifi)
		if err != nil {
			continue
		}
		target := ownNet
		if req.Subnet != "" {
			_, parsed, err := net.ParseCIDR(req.Subnet)
			if err != nil {
				return nil, fmt.Errorf("invalid subnet %q: %w", req.Subnet, err)
			}
			// An explicit subnet only makes sense on the interface that can
			// reach it; when auto-discovering, skip interfaces on other links.
			if req.Interface == "" && !ownNet.Contains(parsed.IP) {
				continue
			}
			target = parsed
		}
		out = append(out, segment{iface: ifi, srcIP: srcIP, network: target})
	}
	if len(out) == 0 {
		if req.Subnet != "" {
			return nil, fmt.Errorf("no interface is attached to %s", req.Subnet)
		}
		return nil, fmt.Errorf("no interface could be prepared for scanning")
	}
	return out, nil
}

// scanSegment sweeps one segment, walking down the method chain until one
// works.
func (s *Scanner) scanSegment(ctx context.Context, seg segment, req protocol.ScanRequest) ([]protocol.Host, string, error) {
	targets, err := netutil.HostsIn(seg.network, netutil.MaxScanHosts)
	if err != nil {
		return nil, "", err
	}

	retries := req.Retries
	if retries <= 0 {
		retries = defaultRetries
	}
	opt := sweepOptions{retries: retries, pacing: defaultPacing, settle: defaultSettle}

	if rawARPAvailable() {
		replies, err := arpSweep(ctx, seg.iface, seg.srcIP, targets, opt)
		if err == nil {
			return repliesToHosts(replies, MethodRawARP), MethodRawARP, nil
		}
		// Fall through to the external tool rather than failing outright: a
		// permission or driver problem on one interface should not abort the
		// whole scan.
		if hosts, err2 := s.arpScanBinary(ctx, seg); err2 == nil {
			return hosts, MethodARPBin, nil
		}
		return s.neighTable(seg), MethodNeigh, fmt.Errorf("raw ARP failed, fell back to the neighbour table: %w", err)
	}

	if hosts, err := s.arpScanBinary(ctx, seg); err == nil {
		return hosts, MethodARPBin, nil
	}
	hosts := s.neighTable(seg)
	return hosts, MethodNeigh, nil
}

// repliesToHosts converts raw sweep replies into wire hosts.
func repliesToHosts(replies []arpReply, source string) []protocol.Host {
	out := make([]protocol.Host, 0, len(replies))
	for _, r := range replies {
		out = append(out, protocol.Host{
			IP:     r.IP.String(),
			MAC:    r.MAC.String(),
			RTTMs:  float64(r.RTT.Microseconds()) / 1000,
			Source: source,
		})
	}
	return out
}

// arpScanBinary shells out to arp-scan when it is installed. Used only as a
// fallback; the native path is preferred because it needs no external package
// and cannot be affected by a hijacked PATH entry.
func (s *Scanner) arpScanBinary(ctx context.Context, seg segment) ([]protocol.Host, error) {
	bin, err := exec.LookPath("arp-scan")
	if err != nil {
		return nil, fmt.Errorf("arp-scan is not installed")
	}
	// Arguments are built from validated interface names and parsed CIDRs, not
	// from operator free text, so there is nothing here a caller can inject.
	cmd := exec.CommandContext(ctx, bin,
		"--interface="+seg.iface.Name,
		"--retry=2",
		"--quiet",
		seg.network.String(),
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run arp-scan: %w", err)
	}
	return parseARPScanOutput(string(out), seg.network), nil
}

// parseARPScanOutput reads arp-scan's tab-separated "IP<TAB>MAC<TAB>vendor"
// lines, ignoring its banner and footer.
func parseARPScanOutput(out string, network *net.IPNet) []protocol.Host {
	var hosts []protocol.Host
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(fields[0]))
		if ip == nil || ip.To4() == nil {
			continue
		}
		mac, err := netutil.NormalizeMAC(fields[1])
		if err != nil {
			continue
		}
		if network != nil && !network.Contains(ip) {
			continue
		}
		hosts = append(hosts, protocol.Host{IP: ip.String(), MAC: mac, Source: MethodARPBin})
	}
	return hosts
}

// neighTable reads whatever the kernel already knows. This is the last-resort
// method: it finds only hosts this machine has recently talked to, so it will
// under-report, but it needs no privileges at all and works in a locked-down
// container.
func (s *Scanner) neighTable(seg segment) []protocol.Host {
	entries, err := readNeighbours()
	if err != nil {
		return nil
	}
	var hosts []protocol.Host
	for _, e := range entries {
		if seg.network != nil && !seg.network.Contains(e.IP) {
			continue
		}
		if e.Iface != "" && e.Iface != seg.iface.Name {
			continue
		}
		hosts = append(hosts, protocol.Host{
			IP:     e.IP.String(),
			MAC:    e.MAC.String(),
			Source: MethodNeigh,
		})
	}
	return hosts
}

// sortHosts orders results by IP so the UI is stable between scans.
func sortHosts(hosts []protocol.Host) {
	sort.Slice(hosts, func(i, j int) bool {
		a, b := net.ParseIP(hosts[i].IP).To4(), net.ParseIP(hosts[j].IP).To4()
		if a == nil || b == nil {
			return hosts[i].IP < hosts[j].IP
		}
		for k := 0; k < 4; k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
}
