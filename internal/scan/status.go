package scan

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/netutil"
	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

// Status probes a set of hosts for liveness.
//
// The probe order mirrors the reason this tool prefers ARP: a Layer 2 probe
// cannot be firewalled off without breaking the host's networking, so a
// Windows box with ICMP blocked still shows up correctly as online.
func (s *Scanner) Status(ctx context.Context, req protocol.StatusRequest) (*protocol.StatusResult, error) {
	timeout := 5 * time.Second
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := &protocol.StatusResult{Targets: make([]protocol.HostStatus, len(req.Targets))}

	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, target := range req.Targets {
		wg.Add(1)
		go func(idx int, t protocol.StatusTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				result.Targets[idx] = protocol.HostStatus{IP: t.IP, MAC: t.MAC}
				return
			}
			result.Targets[idx] = s.probe(ctx, t)
		}(i, target)
	}
	wg.Wait()
	return result, nil
}

// probe checks one host, trying ARP then ICMP then a TCP handshake probe.
func (s *Scanner) probe(ctx context.Context, t protocol.StatusTarget) protocol.HostStatus {
	out := protocol.HostStatus{IP: t.IP, MAC: t.MAC}
	ip := net.ParseIP(t.IP)
	if ip == nil || ip.To4() == nil {
		return out
	}

	if mac, rtt, ok := s.arpProbe(ctx, ip); ok {
		out.Online = true
		out.Method = "arp"
		out.RTTMs = float64(rtt.Microseconds()) / 1000
		// A reply from a different MAC than expected almost always means DHCP
		// handed the address to another machine. Reporting the host as "online"
		// without saying so would make an operator wake the wrong box.
		out.MACMatch = t.MAC == "" || equalMAC(t.MAC, mac.String())
		if !out.MACMatch {
			out.MAC = mac.String()
		}
		return out
	}

	if rtt, ok := icmpProbe(ctx, ip); ok {
		out.Online = true
		out.Method = "icmp"
		out.RTTMs = float64(rtt.Microseconds()) / 1000
		out.MACMatch = t.MAC == "" || s.confirmMACFromCache(ip, t.MAC)
		return out
	}

	if rtt, ok := tcpProbe(ctx, ip); ok {
		out.Online = true
		out.Method = "tcp"
		out.RTTMs = float64(rtt.Microseconds()) / 1000
		out.MACMatch = t.MAC == "" || s.confirmMACFromCache(ip, t.MAC)
	}
	return out
}

// arpProbe sends a single ARP request for one address on whichever interface
// owns its subnet.
func (s *Scanner) arpProbe(ctx context.Context, ip net.IP) (net.HardwareAddr, time.Duration, bool) {
	if !rawARPAvailable() {
		return nil, 0, false
	}
	ifaces, err := netutil.EligibleInterfaces()
	if err != nil {
		return nil, 0, false
	}
	for _, ni := range ifaces {
		ifi, err := net.InterfaceByName(ni.Name)
		if err != nil {
			continue
		}
		srcIP, ownNet, err := netutil.PrimarySourceIP(ifi)
		if err != nil || !ownNet.Contains(ip) {
			continue
		}
		s.mu.Lock()
		replies, err := arpSweep(ctx, ifi, srcIP, []net.IP{ip}, sweepOptions{
			retries: 2,
			pacing:  0,
			settle:  400 * time.Millisecond,
		})
		s.mu.Unlock()
		if err == nil && len(replies) > 0 {
			return replies[0].MAC, replies[0].RTT, true
		}
	}
	return nil, 0, false
}

// confirmMACFromCache checks the kernel neighbour table after a successful
// non-ARP probe, so an ICMP or TCP answer can still be tied back to a MAC.
func (s *Scanner) confirmMACFromCache(ip net.IP, want string) bool {
	mac, ok := lookupNeighbour(ip)
	if !ok {
		// Nothing cached: report a match rather than a false alarm, since we
		// have no evidence either way.
		return true
	}
	return equalMAC(want, mac.String())
}

// isConnRefused reports whether a dial failed because the host actively
// rejected the connection. A refusal still proves the machine is powered on and
// its IP stack is answering, which is exactly what a status check asks. Host-
// unreachable and timeouts prove nothing and are deliberately excluded.
func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

func equalMAC(a, b string) bool {
	na, err1 := netutil.NormalizeMAC(a)
	nb, err2 := netutil.NormalizeMAC(b)
	return err1 == nil && err2 == nil && na == nb
}

// tcpProbe is the universally-available fallback. A refused connection proves
// the host is up just as well as an accepted one — only silence means down.
func tcpProbe(ctx context.Context, ip net.IP) (time.Duration, bool) {
	ports := []string{"445", "22", "80", "443", "3389"}
	deadline := 900 * time.Millisecond
	for _, port := range ports {
		start := time.Now()
		d := net.Dialer{Timeout: deadline}
		conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
		elapsed := time.Since(start)
		if err == nil {
			conn.Close()
			return elapsed, true
		}
		if isConnRefused(err) {
			return elapsed, true
		}
		if ctx.Err() != nil {
			return 0, false
		}
	}
	return 0, false
}
