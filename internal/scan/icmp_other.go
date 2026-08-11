//go:build !linux

package scan

import (
	"context"
	"net"
	"time"
)

// icmpProbe is unimplemented off Linux; the caller falls back to the TCP probe,
// which needs no privileges anywhere.
func icmpProbe(context.Context, net.IP) (time.Duration, bool) { return 0, false }
