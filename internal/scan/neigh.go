package scan

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/fqazzazee/netscan-wol/internal/netutil"
)

// neighbour is one entry from the kernel's ARP cache.
type neighbour struct {
	IP    net.IP
	MAC   net.HardwareAddr
	Iface string
	// Stale entries are kept: a host that answered five minutes ago is still
	// worth showing, flagged, rather than dropped.
	Stale bool
}

// readNeighbours parses /proc/net/arp. The format has been stable for decades:
//
//	IP address  HW type  Flags  HW address  Mask  Device
//
// Flags 0x2 means the entry is complete; 0x0 means an incomplete probe that
// never resolved, which is not a discovered host.
func readNeighbours() ([]neighbour, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []neighbour
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() == nil {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if err != nil || flags == 0 {
			continue
		}
		mac, err := netutil.ParseMAC(fields[3])
		if err != nil || netutil.IsZeroMAC(mac) || netutil.IsBroadcastMAC(mac) {
			continue
		}
		out = append(out, neighbour{
			IP:    ip,
			MAC:   mac,
			Iface: fields[5],
			Stale: flags&0x2 == 0,
		})
	}
	return out, sc.Err()
}

// lookupNeighbour finds the cached MAC for one address, used to confirm that a
// host answering a status probe is the machine we expected.
func lookupNeighbour(ip net.IP) (net.HardwareAddr, bool) {
	entries, err := readNeighbours()
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		if e.IP.Equal(ip) {
			return e.MAC, true
		}
	}
	return nil, false
}
