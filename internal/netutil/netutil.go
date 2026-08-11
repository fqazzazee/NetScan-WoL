// Package netutil holds the addressing helpers shared by the scanner, the WoL
// sender and the auto-discovery code.
package netutil

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

// ErrBadMAC is returned by ParseMAC for input that is not a 6-byte address.
var ErrBadMAC = errors.New("not a valid 48-bit MAC address")

// ParseMAC accepts the notations people actually type: colon-separated,
// dash-separated, dot-separated Cisco style, and bare hex. It only accepts
// 48-bit addresses, because that is all Wake-on-LAN and ARP deal with.
func ParseMAC(s string) (net.HardwareAddr, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			return r
		default:
			return -1
		}
	}, s)
	if len(cleaned) != 12 {
		return nil, fmt.Errorf("%w: %q", ErrBadMAC, s)
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrBadMAC, s)
	}
	return net.HardwareAddr(b), nil
}

// NormalizeMAC renders a MAC in the canonical lower-case colon form used
// everywhere in storage and on the wire. Comparing normalized strings is how
// the hub decides two sightings are the same host.
func NormalizeMAC(s string) (string, error) {
	hw, err := ParseMAC(s)
	if err != nil {
		return "", err
	}
	return hw.String(), nil
}

// IsBroadcastMAC reports whether the address is the all-ones broadcast, which
// must never be used as a WoL target or stored as a host identity.
func IsBroadcastMAC(hw net.HardwareAddr) bool {
	if len(hw) != 6 {
		return false
	}
	for _, b := range hw {
		if b != 0xff {
			return false
		}
	}
	return true
}

// IsZeroMAC reports whether the address is all zeroes.
func IsZeroMAC(hw net.HardwareAddr) bool {
	if len(hw) != 6 {
		return false
	}
	for _, b := range hw {
		if b != 0 {
			return false
		}
	}
	return true
}

// BroadcastAddr computes the directed broadcast address of an IPv4 network.
// Sending a magic packet to the directed broadcast is what lets a sleeping
// host on a remote subnet receive it, assuming the router forwards it.
func BroadcastAddr(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	mask := net.IP(n.Mask).To4()
	if ip == nil || mask == nil {
		return nil
	}
	out := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

// HostsIn enumerates the usable host addresses of an IPv4 network, excluding
// the network and broadcast addresses. It refuses networks larger than
// maxHosts so a mistyped /8 cannot turn into a 16-million-probe scan.
func HostsIn(n *net.IPNet, maxHosts int) ([]net.IP, error) {
	ip := n.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("%s is not an IPv4 network", n)
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("%s is not an IPv4 network", n)
	}
	if ones >= 31 {
		// /31 and /32 have no broadcast address; treat every address as usable.
		var out []net.IP
		for u := ipToU32(ip.Mask(n.Mask)); ; u++ {
			out = append(out, u32ToIP(u))
			if ones == 32 || len(out) == 2 {
				break
			}
		}
		return out, nil
	}
	count := 1<<uint(32-ones) - 2
	if count > maxHosts {
		return nil, fmt.Errorf("network %s holds %d hosts, above the %d limit; scan a smaller prefix", n, count, maxHosts)
	}
	base := ipToU32(ip.Mask(n.Mask))
	out := make([]net.IP, 0, count)
	for i := 1; i <= count; i++ {
		out = append(out, u32ToIP(base+uint32(i)))
	}
	return out, nil
}

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func u32ToIP(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

// maxScanHosts caps a single scan at a /18. Anything larger is almost always a
// typo, and ARP scanning across it would take minutes and flood the segment.
const MaxScanHosts = 16382

// Interfaces enumerates the machine's network interfaces and marks which ones
// can carry an ARP scan. Nothing here requires privileges, so the hub UI can
// show the topology of an agent before any scan is run.
func Interfaces() ([]protocol.NetInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	out := make([]protocol.NetInterface, 0, len(ifaces))
	for _, ifi := range ifaces {
		ni := protocol.NetInterface{
			Name: ifi.Name,
			MTU:  ifi.MTU,
			Up:   ifi.Flags&net.FlagUp != 0,
		}
		if len(ifi.HardwareAddr) == 6 {
			ni.MAC = ifi.HardwareAddr.String()
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			ni.Skip = "cannot read addresses: " + err.Error()
			out = append(out, ni)
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ni.Addrs = append(ni.Addrs, ipn.String())
			if ipn.IP.To4() == nil {
				continue
			}
			netw := &net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask}
			ni.Subnets = append(ni.Subnets, netw.String())
			if ni.Broadcast == "" {
				if b := BroadcastAddr(netw); b != nil {
					ni.Broadcast = b.String()
				}
			}
		}
		ni.Eligible, ni.Skip = eligible(ifi, ni)
		out = append(out, ni)
	}
	return out, nil
}

// eligible decides whether an interface can host an ARP scan and explains the
// verdict, so the UI can tell an operator *why* an interface is greyed out
// rather than silently hiding it.
func eligible(ifi net.Interface, ni protocol.NetInterface) (bool, string) {
	switch {
	case ifi.Flags&net.FlagLoopback != 0:
		return false, "loopback"
	case ifi.Flags&net.FlagUp == 0:
		return false, "link is down"
	case ifi.Flags&net.FlagPointToPoint != 0:
		return false, "point-to-point link has no ARP broadcast domain"
	case len(ifi.HardwareAddr) != 6:
		return false, "no Ethernet hardware address"
	case len(ni.Subnets) == 0:
		return false, "no IPv4 address assigned"
	}
	return true, ""
}

// EligibleInterfaces returns only the interfaces that can carry a scan.
func EligibleInterfaces() ([]protocol.NetInterface, error) {
	all, err := Interfaces()
	if err != nil {
		return nil, err
	}
	var out []protocol.NetInterface
	for _, ni := range all {
		if ni.Eligible {
			out = append(out, ni)
		}
	}
	return out, nil
}

// InterfaceByName looks up a single interface by name and reports whether it
// can be scanned.
func InterfaceByName(name string) (protocol.NetInterface, error) {
	all, err := Interfaces()
	if err != nil {
		return protocol.NetInterface{}, err
	}
	for _, ni := range all {
		if ni.Name == name {
			return ni, nil
		}
	}
	return protocol.NetInterface{}, fmt.Errorf("interface %q not found", name)
}

// PrimarySourceIP picks the IPv4 address the given interface should use as the
// source of ARP probes.
func PrimarySourceIP(ifi *net.Interface) (net.IP, *net.IPNet, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("addresses of %s: %w", ifi.Name, err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipn.IP.To4(); ip4 != nil {
			return ip4, &net.IPNet{IP: ip4.Mask(ipn.Mask), Mask: ipn.Mask}, nil
		}
	}
	return nil, nil, fmt.Errorf("interface %s has no IPv4 address", ifi.Name)
}

// IsPrivate reports whether an address is in RFC1918 or link-local space. The
// hub uses this to warn when an operator points a scan at public address space,
// which is rarely intended and can look like hostile reconnaissance.
func IsPrivate(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
