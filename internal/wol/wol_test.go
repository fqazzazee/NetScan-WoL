package wol

import (
	"bytes"
	"net"
	"testing"

	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

func TestBuildPacket(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	pkt, err := BuildPacket(mac, nil)
	if err != nil {
		t.Fatalf("BuildPacket: %v", err)
	}
	if len(pkt) != magicPacketLen {
		t.Fatalf("packet is %d bytes, want %d", len(pkt), magicPacketLen)
	}
	// Six 0xFF sync bytes.
	if !bytes.Equal(pkt[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("sync header = %x, want six 0xff bytes", pkt[:6])
	}
	// Then the MAC exactly sixteen times. A NIC matches on this pattern, so a
	// miscount means the target simply never wakes.
	for i := 0; i < 16; i++ {
		start := 6 + i*6
		if !bytes.Equal(pkt[start:start+6], mac) {
			t.Fatalf("repetition %d = %x, want %x", i, pkt[start:start+6], mac)
		}
	}
}

func TestBuildPacketWithSecureOn(t *testing.T) {
	mac := net.HardwareAddr{1, 2, 3, 4, 5, 6}
	password := net.HardwareAddr{9, 9, 9, 9, 9, 9}
	pkt, err := BuildPacket(mac, password)
	if err != nil {
		t.Fatalf("BuildPacket: %v", err)
	}
	if len(pkt) != magicPacketLen+6 {
		t.Fatalf("packet is %d bytes, want %d", len(pkt), magicPacketLen+6)
	}
	if !bytes.Equal(pkt[magicPacketLen:], password) {
		t.Errorf("SecureOn suffix = %x, want %x", pkt[magicPacketLen:], password)
	}
}

// TestBuildPacketRefusesNonHosts covers the addresses that are never a real
// wake target. Sending sixteen repetitions of the broadcast address would put
// a packet on the wire that every NIC on the segment might match.
func TestBuildPacketRefusesNonHosts(t *testing.T) {
	cases := map[string]net.HardwareAddr{
		"broadcast":      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"all zeroes":     make(net.HardwareAddr, 6),
		"too short":      {1, 2, 3},
		"64-bit address": {1, 2, 3, 4, 5, 6, 7, 8},
	}
	for name, mac := range cases {
		if _, err := BuildPacket(mac, nil); err == nil {
			t.Errorf("BuildPacket accepted %s", name)
		}
	}
	if _, err := BuildPacket(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.HardwareAddr{1, 2, 3}); err == nil {
		t.Error("BuildPacket accepted a SecureOn password that was not six bytes")
	}
}

func TestSendValidatesInput(t *testing.T) {
	cases := map[string]protocol.WoLRequest{
		"malformed MAC":      {MAC: "nonsense"},
		"broadcast MAC":      {MAC: "ff:ff:ff:ff:ff:ff"},
		"port out of range":  {MAC: "aa:bb:cc:dd:ee:ff", Port: 70000},
		"bad SecureOn":       {MAC: "aa:bb:cc:dd:ee:ff", SecureOn: "xyz"},
		"bad broadcast addr": {MAC: "aa:bb:cc:dd:ee:ff", Broadcast: "999.1.1.1"},
	}
	for name, req := range cases {
		if _, err := Send(req); err == nil {
			t.Errorf("Send accepted %s", name)
		}
	}
}

// TestSendClampsCount keeps the endpoint from being usable as a broadcast
// flooder: an operator asking for a thousand packets gets the ceiling instead.
func TestSendClampsCount(t *testing.T) {
	res, err := Send(protocol.WoLRequest{
		MAC:       "aa:bb:cc:dd:ee:ff",
		Broadcast: "127.0.0.1", // stays on loopback, disturbs nothing
		Port:      9,
		Count:     10_000,
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Sent > 16 {
		t.Errorf("sent %d packets, want the ceiling of 16", res.Sent)
	}
}
