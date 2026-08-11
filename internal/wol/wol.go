// Package wol builds and sends Wake-on-LAN magic packets.
//
// A magic packet is six 0xFF bytes followed by the target MAC repeated sixteen
// times. A sleeping network adapter matches that pattern anywhere in any
// Ethernet frame, which is why it is normally carried in a UDP datagram to a
// broadcast address — the payload is what matters, not the port.
package wol

import (
	"fmt"
	"net"

	"github.com/fqazzazee/netscan-wol/internal/netutil"
	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

// DefaultPort is the conventional WoL port. 7 and 0 are also common; nothing
// listens on any of them, so the choice only matters to intermediate firewalls.
const DefaultPort = 9

// DefaultCount is how many identical packets to emit. Repeats cost nothing and
// materially improve success on wireless bridges and busy segments.
const DefaultCount = 3

// magicPacketLen is 6 sync bytes plus 16 MAC repetitions.
const magicPacketLen = 6 + 16*6

// BuildPacket assembles the magic packet for mac, optionally appending a
// SecureOn password. Adapters configured with SecureOn ignore packets that lack
// the matching six-byte suffix.
func BuildPacket(mac net.HardwareAddr, secureOn net.HardwareAddr) ([]byte, error) {
	if len(mac) != 6 {
		return nil, fmt.Errorf("magic packets require a 48-bit MAC, got %d bytes", len(mac))
	}
	if netutil.IsBroadcastMAC(mac) || netutil.IsZeroMAC(mac) {
		return nil, fmt.Errorf("refusing to build a magic packet for %s: broadcast and zero addresses are not real hosts", mac)
	}
	pkt := make([]byte, 0, magicPacketLen+len(secureOn))
	for i := 0; i < 6; i++ {
		pkt = append(pkt, 0xff)
	}
	for i := 0; i < 16; i++ {
		pkt = append(pkt, mac...)
	}
	if len(secureOn) > 0 {
		if len(secureOn) != 6 {
			return nil, fmt.Errorf("a SecureOn password must be exactly 6 bytes, got %d", len(secureOn))
		}
		pkt = append(pkt, secureOn...)
	}
	return pkt, nil
}

// Send emits magic packets according to req and reports what was sent.
//
// When no broadcast address is given, the packet goes to the directed
// broadcast of every eligible interface as well as the limited broadcast
// 255.255.255.255. Directed broadcast is what reaches a host on a different
// VLAN when the router is configured to forward it; the limited broadcast
// covers the common single-segment case.
func Send(req protocol.WoLRequest) (*protocol.WoLResult, error) {
	mac, err := netutil.ParseMAC(req.MAC)
	if err != nil {
		return nil, err
	}
	var secure net.HardwareAddr
	if req.SecureOn != "" {
		secure, err = netutil.ParseMAC(req.SecureOn)
		if err != nil {
			return nil, fmt.Errorf("SecureOn password: %w", err)
		}
	}
	packet, err := BuildPacket(mac, secure)
	if err != nil {
		return nil, err
	}

	port := req.Port
	if port == 0 {
		port = DefaultPort
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %d is out of range", port)
	}
	count := req.Count
	if count <= 0 {
		count = DefaultCount
	}
	if count > 16 {
		// Beyond a handful the extra packets are pure noise, and an unbounded
		// count turns this endpoint into a broadcast flooder.
		count = 16
	}

	destinations, err := resolveDestinations(req)
	if err != nil {
		return nil, err
	}

	result := &protocol.WoLResult{MAC: mac.String()}
	var lastErr error
	for _, dst := range destinations {
		addr := &net.UDPAddr{IP: dst, Port: port}
		sent, err := sendTo(addr, packet, count, req.Interface)
		if err != nil {
			lastErr = err
			continue
		}
		result.Sent += sent
		result.Destinations = append(result.Destinations, addr.String())
	}
	if result.Sent == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("no magic packet could be sent: %w", lastErr)
		}
		return nil, fmt.Errorf("no usable broadcast destination was found")
	}
	return result, nil
}

// resolveDestinations decides where the packets go.
func resolveDestinations(req protocol.WoLRequest) ([]net.IP, error) {
	if req.Broadcast != "" {
		ip := net.ParseIP(req.Broadcast)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid broadcast address %q", req.Broadcast)
		}
		return []net.IP{ip.To4()}, nil
	}

	ifaces, err := netutil.EligibleInterfaces()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []net.IP
	for _, ni := range ifaces {
		if req.Interface != "" && ni.Name != req.Interface {
			continue
		}
		if ni.Broadcast == "" || seen[ni.Broadcast] {
			continue
		}
		if ip := net.ParseIP(ni.Broadcast); ip != nil {
			seen[ni.Broadcast] = true
			out = append(out, ip.To4())
		}
	}
	// The limited broadcast is never routed but always reaches the local
	// segment, so it is a useful backstop when interface enumeration is
	// unhelpful — as it is inside a container with a single veth.
	limited := net.IPv4bcast
	if !seen[limited.String()] {
		out = append(out, limited)
	}
	return out, nil
}

// sendTo writes count copies of the packet to one destination.
func sendTo(addr *net.UDPAddr, packet []byte, count int, iface string) (int, error) {
	local, err := sourceAddrFor(iface)
	if err != nil {
		return 0, err
	}
	conn, err := net.DialUDP("udp4", local, addr)
	if err != nil {
		return 0, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	sent := 0
	for i := 0; i < count; i++ {
		if _, err := conn.Write(packet); err != nil {
			if sent == 0 {
				return 0, fmt.Errorf("send to %s: %w", addr, err)
			}
			break
		}
		sent++
	}
	return sent, nil
}

// sourceAddrFor pins the outgoing socket to a named interface's address. On a
// multi-homed agent this is the difference between the packet leaving on the
// management NIC and leaving on the segment the sleeping host is actually on.
func sourceAddrFor(iface string) (*net.UDPAddr, error) {
	if iface == "" {
		return nil, nil
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}
	ip, _, err := netutil.PrimarySourceIP(ifi)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip}, nil
}
