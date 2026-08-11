package netutil

import (
	"net"
	"testing"
)

func TestParseMAC(t *testing.T) {
	// Every notation a person might paste in should resolve to the same
	// address; MAC equality is how the hub decides two sightings are one host.
	equivalent := []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff",
		"aabb.ccdd.eeff",
		"aabbccddeeff",
		"  aa:bb:cc:dd:ee:ff  ",
	}
	for _, in := range equivalent {
		got, err := NormalizeMAC(in)
		if err != nil {
			t.Errorf("NormalizeMAC(%q) failed: %v", in, err)
			continue
		}
		if got != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("NormalizeMAC(%q) = %q, want aa:bb:cc:dd:ee:ff", in, got)
		}
	}
}

func TestParseMACRejects(t *testing.T) {
	// 64-bit EUI addresses are rejected on purpose: neither ARP nor
	// Wake-on-LAN can use them, so accepting one would fail later and less
	// clearly.
	bad := []string{"", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00:11", "not a mac", "zz:bb:cc:dd:ee:ff"}
	for _, in := range bad {
		if _, err := ParseMAC(in); err == nil {
			t.Errorf("ParseMAC(%q) succeeded, want an error", in)
		}
	}
}

func TestBroadcastAddr(t *testing.T) {
	cases := map[string]string{
		"10.0.0.0/24":     "10.0.0.255",
		"192.168.1.64/26": "192.168.1.127",
		"172.16.0.0/12":   "172.31.255.255",
		"10.1.2.3/32":     "10.1.2.3",
	}
	for cidr, want := range cases {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if got := BroadcastAddr(network); got.String() != want {
			t.Errorf("BroadcastAddr(%s) = %s, want %s", cidr, got, want)
		}
	}
}

func TestHostsIn(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/29")
	hosts, err := HostsIn(network, MaxScanHosts)
	if err != nil {
		t.Fatalf("HostsIn: %v", err)
	}
	// A /29 has 8 addresses: 6 usable, excluding network and broadcast.
	if len(hosts) != 6 {
		t.Fatalf("got %d hosts, want 6", len(hosts))
	}
	if hosts[0].String() != "192.168.1.1" {
		t.Errorf("first host = %s, want 192.168.1.1", hosts[0])
	}
	if hosts[5].String() != "192.168.1.6" {
		t.Errorf("last host = %s, want 192.168.1.6", hosts[5])
	}
}

// TestHostsInRefusesHugeNetworks guards the sanity limit. Without it, a
// mistyped /8 would queue sixteen million ARP probes at the segment.
func TestHostsInRefusesHugeNetworks(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	if _, err := HostsIn(network, MaxScanHosts); err == nil {
		t.Fatal("a /8 was accepted for scanning")
	}
}

func TestIsBroadcastAndZeroMAC(t *testing.T) {
	if !IsBroadcastMAC(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Error("the all-ones address was not recognised as broadcast")
	}
	if IsBroadcastMAC(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}) {
		t.Error("a near-broadcast address was misidentified as broadcast")
	}
	if !IsZeroMAC(make(net.HardwareAddr, 6)) {
		t.Error("the all-zeroes address was not recognised")
	}
	// A short address is neither; length checks must not panic.
	if IsBroadcastMAC(net.HardwareAddr{0xff}) || IsZeroMAC(net.HardwareAddr{0x00}) {
		t.Error("a truncated address was accepted")
	}
}

// TestInterfaces exercises the real enumeration. It cannot assert much about a
// machine it has never seen, but it can insist the verdicts are self-consistent
// — an eligible interface must have everything eligibility requires.
func TestInterfaces(t *testing.T) {
	interfaces, err := Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	for _, ifi := range interfaces {
		if ifi.Eligible {
			if ifi.Skip != "" {
				t.Errorf("%s is eligible but carries the skip reason %q", ifi.Name, ifi.Skip)
			}
			if !ifi.Up {
				t.Errorf("%s is eligible but the link is down", ifi.Name)
			}
			if len(ifi.Subnets) == 0 {
				t.Errorf("%s is eligible but has no IPv4 subnet", ifi.Name)
			}
			if ifi.MAC == "" {
				t.Errorf("%s is eligible but has no hardware address", ifi.Name)
			}
		} else if ifi.Skip == "" {
			t.Errorf("%s is not eligible but no reason was recorded", ifi.Name)
		}
	}
}
