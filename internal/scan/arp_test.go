//go:build linux

package scan

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestARPRequestRoundTrip builds a request frame and parses it back as if it
// were a reply, which exercises every offset in the packet layout. An error
// here means probes go out malformed and no host ever answers.
func TestARPRequestRoundTrip(t *testing.T) {
	srcMAC := net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcIP := net.IPv4(192, 168, 1, 10)
	dstIP := net.IPv4(192, 168, 1, 20)

	frame := make([]byte, frameLen)
	buildARPRequest(frame, srcMAC, srcIP, dstIP)

	if got := net.HardwareAddr(frame[0:6]).String(); got != broadcastMAC.String() {
		t.Errorf("Ethernet destination = %s, want the broadcast address", got)
	}
	if got := net.HardwareAddr(frame[6:12]).String(); got != srcMAC.String() {
		t.Errorf("Ethernet source = %s, want %s", got, srcMAC)
	}
	if frame[12] != 0x08 || frame[13] != 0x06 {
		t.Errorf("EtherType = %#x%02x, want 0806", frame[12], frame[13])
	}

	p := frame[ethHeaderLen:]
	if p[6] != 0 || p[7] != arpOpRequest {
		t.Errorf("opcode = %d, want %d (request)", int(p[6])<<8|int(p[7]), arpOpRequest)
	}
	if p[4] != 6 || p[5] != 4 {
		t.Errorf("address lengths = %d/%d, want 6/4", p[4], p[5])
	}
	if got := net.IP(p[14:18]).String(); got != srcIP.String() {
		t.Errorf("sender protocol address = %s, want %s", got, srcIP)
	}
	if got := net.IP(p[24:28]).String(); got != dstIP.String() {
		t.Errorf("target protocol address = %s, want %s", got, dstIP)
	}
	// The target hardware address is what we are asking for, so it must go out
	// zeroed. A stale value here is a classic copy-paste bug that makes some
	// stacks ignore the request entirely.
	for i, b := range p[18:24] {
		if b != 0 {
			t.Errorf("target hardware address byte %d = %#x, want 0", i, b)
		}
	}
}

// TestParseARPReply checks that the parser accepts a well-formed reply and
// rejects everything it should. The input here is attacker-influenced in
// production, so the negative cases matter more than the positive one.
func TestParseARPReply(t *testing.T) {
	good := func() []byte {
		f := make([]byte, frameLen)
		// Ethernet header.
		copy(f[0:6], net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
		copy(f[6:12], net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
		f[12], f[13] = 0x08, 0x06 // ARP
		p := f[ethHeaderLen:]
		p[0], p[1] = 0, 1       // Ethernet hardware type
		p[2], p[3] = 0x08, 0x00 // IPv4
		p[4], p[5] = 6, 4
		p[6], p[7] = 0, 2 // reply
		copy(p[8:14], net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
		copy(p[14:18], net.IPv4(10, 0, 0, 5).To4())
		return f
	}

	t.Run("valid reply", func(t *testing.T) {
		reply, ok := parseARPReply(good())
		if !ok {
			t.Fatal("a well-formed reply was rejected")
		}
		if reply.IP.String() != "10.0.0.5" {
			t.Errorf("sender IP = %s, want 10.0.0.5", reply.IP)
		}
		if reply.MAC.String() != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("sender MAC = %s, want aa:bb:cc:dd:ee:ff", reply.MAC)
		}
	})

	cases := map[string]func([]byte) []byte{
		"truncated frame":        func(f []byte) []byte { return f[:frameLen-1] },
		"not ARP":                func(f []byte) []byte { f[12] = 0x08; f[13] = 0x00; return f },
		"a request, not a reply": func(f []byte) []byte { f[ethHeaderLen+7] = 1; return f },
		"wrong hardware type":    func(f []byte) []byte { f[ethHeaderLen+1] = 6; return f },
		"wrong protocol type":    func(f []byte) []byte { f[ethHeaderLen+2] = 0x86; return f },
		"bad address lengths":    func(f []byte) []byte { f[ethHeaderLen+4] = 8; return f },
		"zero sender MAC": func(f []byte) []byte {
			copy(f[ethHeaderLen+8:ethHeaderLen+14], make([]byte, 6))
			return f
		},
		"broadcast sender MAC": func(f []byte) []byte {
			copy(f[ethHeaderLen+8:ethHeaderLen+14], broadcastMAC)
			return f
		},
		"unspecified sender IP": func(f []byte) []byte {
			copy(f[ethHeaderLen+14:ethHeaderLen+18], make([]byte, 4))
			return f
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := parseARPReply(mutate(good())); ok {
				t.Errorf("parser accepted a frame it should have rejected: %s", name)
			}
		})
	}
}

// TestRawSweepAgainstEmptySegment exercises the whole socket path — open,
// bind, send, receive, timeout — on a link with nothing on it. It needs
// CAP_NET_RAW, so it skips when run unprivileged; run it inside
// `unshare -Urn` with a dummy interface to see it actually execute.
func TestRawSweepAgainstEmptySegment(t *testing.T) {
	if !rawARPAvailable() {
		t.Skip("no CAP_NET_RAW; run under `unshare -Urn` to exercise the raw socket path")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("enumerate interfaces: %v", err)
	}
	var target *net.Interface
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 || len(ifi.HardwareAddr) != 6 {
			continue
		}
		if _, _, err := primaryIPv4(&ifi); err == nil {
			target = &ifi
			break
		}
	}
	if target == nil {
		t.Skip("no Ethernet interface with an IPv4 address to sweep")
	}

	src, _, err := primaryIPv4(target)
	if err != nil {
		t.Fatalf("source address: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Two addresses is enough to prove the send and receive loops run and the
	// settle timeout fires. Whether anything answers is not the point.
	targets := []net.IP{net.IPv4(10, 255, 255, 253), net.IPv4(10, 255, 255, 254)}
	start := time.Now()
	if _, err := arpSweep(ctx, target, src, targets, sweepOptions{
		retries: 1, pacing: 0, settle: 300 * time.Millisecond,
	}); err != nil {
		t.Fatalf("sweep on %s failed: %v", target.Name, err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("sweep took %s; the settle timeout does not appear to be honoured", elapsed)
	}
}

// primaryIPv4 is a local copy of the netutil helper, kept here so the test does
// not depend on that package's behaviour while testing this one.
func primaryIPv4(ifi *net.Interface) (net.IP, *net.IPNet, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil {
				return ip4, ipn, nil
			}
		}
	}
	return nil, nil, net.InvalidAddrError("no IPv4 address")
}
