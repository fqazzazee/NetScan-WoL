//go:build !linux

package scan

import (
	"context"
	"errors"
	"net"
	"time"
)

// errNoRawARP is returned on platforms without the AF_PACKET implementation.
// The scanner falls back to the external arp-scan binary and the kernel
// neighbour table, both of which work anywhere those tools exist.
var errNoRawARP = errors.New("native ARP scanning is only implemented on Linux")

func rawARPAvailable() bool { return false }

func arpSweep(context.Context, *net.Interface, net.IP, []net.IP, sweepOptions) ([]arpReply, error) {
	return nil, errNoRawARP
}

type arpReply struct {
	IP  net.IP
	MAC net.HardwareAddr
	RTT time.Duration
}

type sweepOptions struct {
	retries int
	pacing  time.Duration
	settle  time.Duration
}
