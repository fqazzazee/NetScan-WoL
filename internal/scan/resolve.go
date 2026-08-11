package scan

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

// Resolver turns IP addresses into names. It tries unicast reverse DNS first
// because it is cheap and usually authoritative on a managed network, then
// falls back to multicast DNS, which is how most consumer devices, printers
// and Apple hardware announce themselves.
type Resolver struct {
	// concurrency bounds simultaneous lookups. Reverse DNS on a subnet with no
	// PTR records means one timeout per host; without a cap, a /24 would open
	// 254 sockets at once.
	concurrency int
	timeout     time.Duration
}

// NewResolver returns a resolver with defaults suited to a LAN sweep.
func NewResolver() *Resolver {
	return &Resolver{concurrency: 32, timeout: 1500 * time.Millisecond}
}

// Enrich fills in the Hostname field of every host that does not already have
// one. Failures are silent by design: a missing name is normal and should not
// turn a good scan into an error.
func (r *Resolver) Enrich(ctx context.Context, hosts []protocol.Host) {
	sem := make(chan struct{}, r.concurrency)
	var wg sync.WaitGroup
	for i := range hosts {
		if hosts[i].Hostname != "" {
			continue
		}
		wg.Add(1)
		go func(h *protocol.Host) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			h.Hostname = r.lookup(ctx, h.IP)
		}(&hosts[i])
	}
	wg.Wait()
}

// lookup resolves a single address, trying unicast then multicast DNS.
func (r *Resolver) lookup(ctx context.Context, ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	lookupCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	if names, err := net.DefaultResolver.LookupAddr(lookupCtx, ipStr); err == nil && len(names) > 0 {
		return cleanName(names[0])
	}
	if name, err := mdnsReverse(lookupCtx, ip); err == nil && name != "" {
		return cleanName(name)
	}
	return ""
}

// cleanName strips the trailing dot of a fully-qualified name and the .local
// suffix that mDNS always carries, which is noise in a host list.
func cleanName(n string) string {
	n = strings.TrimSuffix(n, ".")
	n = strings.TrimSuffix(n, ".local")
	return n
}
