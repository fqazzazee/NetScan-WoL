package scan

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// TestDecodeDNSNameCompressionLoop is the one that matters for safety. A
// device on the segment can send any bytes it likes, including a compression
// pointer that points at itself. Without the depth cap this parser would spin
// forever inside a network-facing code path.
func TestDecodeDNSNameCompressionLoop(t *testing.T) {
	msg := make([]byte, dnsHeaderLen+4)
	// A pointer at offset 12 that targets offset 12 — itself.
	binary.BigEndian.PutUint16(msg[dnsHeaderLen:], 0xc000|uint16(dnsHeaderLen))

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, ok := decodeDNSName(msg, dnsHeaderLen, 0); ok {
			t.Error("a self-referential compression pointer was accepted")
		}
	}()
	<-done
}

func TestDecodeDNSName(t *testing.T) {
	// "printer.local" encoded as length-prefixed labels.
	msg := append([]byte{}, byte(7))
	msg = append(msg, "printer"...)
	msg = append(msg, byte(5))
	msg = append(msg, "local"...)
	msg = append(msg, 0)

	name, next, ok := decodeDNSName(msg, 0, 0)
	if !ok {
		t.Fatal("failed to decode a well-formed name")
	}
	if name != "printer.local" {
		t.Errorf("name = %q, want %q", name, "printer.local")
	}
	if next != len(msg) {
		t.Errorf("next offset = %d, want %d", next, len(msg))
	}
}

func TestDecodeDNSNameRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"length runs past the buffer": {5, 'a', 'b'},
		"label longer than 63 bytes":  {64, 'a'},
		"pointer past the buffer":     {0xc0, 0xff},
		"truncated pointer":           {0xc0},
		"empty buffer":                {},
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := decodeDNSName(msg, 0, 0); ok {
				t.Errorf("parser accepted malformed input: %s", name)
			}
		})
	}
}

func TestBuildDNSQuery(t *testing.T) {
	q, err := buildDNSQuery("5.0.0.10.in-addr.arpa.", dnsTypePTR)
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	if len(q) < dnsHeaderLen+4 {
		t.Fatalf("query is only %d bytes; too short to be valid", len(q))
	}
	if got := binary.BigEndian.Uint16(q[4:6]); got != 1 {
		t.Errorf("question count = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(q[len(q)-4 : len(q)-2]); got != dnsTypePTR {
		t.Errorf("query type = %d, want %d (PTR)", got, dnsTypePTR)
	}
	if got := binary.BigEndian.Uint16(q[len(q)-2:]); got != dnsClassIN {
		t.Errorf("query class = %d, want %d (IN)", got, dnsClassIN)
	}
}

func TestBuildDNSQueryRejectsBadLabels(t *testing.T) {
	if _, err := buildDNSQuery(strings.Repeat("a", 64)+".local", dnsTypePTR); err == nil {
		t.Error("a label longer than 63 bytes was accepted")
	}
	if _, err := buildDNSQuery("a..b", dnsTypePTR); err == nil {
		t.Error("an empty label was accepted")
	}
}

// TestParsePTRAnswer walks a realistic response, including the compression
// pointer that real responders use for the answer's owner name.
func TestParsePTRAnswer(t *testing.T) {
	question := "5.0.0.10.in-addr.arpa."

	msg := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(msg[4:6], 1)      // one question
	binary.BigEndian.PutUint16(msg[6:8], 1)      // one answer

	qname, err := encodeDNSName(question)
	if err != nil {
		t.Fatalf("encode question: %v", err)
	}
	questionOffset := len(msg)
	msg = append(msg, qname...)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypePTR)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)

	// Answer: owner name as a pointer back to the question, then the PTR data.
	msg = binary.BigEndian.AppendUint16(msg, 0xc000|uint16(questionOffset))
	msg = binary.BigEndian.AppendUint16(msg, dnsTypePTR)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	msg = binary.BigEndian.AppendUint32(msg, 120) // TTL

	target, err := encodeDNSName("officeprinter.local.")
	if err != nil {
		t.Fatalf("encode target: %v", err)
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(target)))
	msg = append(msg, target...)

	name, ok := parsePTRAnswer(msg, question)
	if !ok {
		t.Fatal("a well-formed PTR answer was not recognised")
	}
	if name != "officeprinter.local" {
		t.Errorf("name = %q, want %q", name, "officeprinter.local")
	}
}

func TestParsePTRAnswerIgnoresOtherNames(t *testing.T) {
	// An answer for a different address must not be attributed to ours; on a
	// shared multicast bus, replies for other hosts arrive constantly.
	msg := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400)
	binary.BigEndian.PutUint16(msg[6:8], 1)

	owner, _ := encodeDNSName("99.0.0.10.in-addr.arpa.")
	msg = append(msg, owner...)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypePTR)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	msg = binary.BigEndian.AppendUint32(msg, 120)
	target, _ := encodeDNSName("other.local.")
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(target)))
	msg = append(msg, target...)

	if name, ok := parsePTRAnswer(msg, "5.0.0.10.in-addr.arpa."); ok {
		t.Errorf("answer for another address was accepted as %q", name)
	}
}

func TestParseARPScanOutput(t *testing.T) {
	out := "Interface: eth0, type: EN10MB\n" +
		"Starting arp-scan 1.9.7\n" +
		"10.0.0.1\t00:11:22:33:44:55\tSome Vendor, Inc.\n" +
		"10.0.0.9\taa-bb-cc-dd-ee-ff\tAnother Vendor\n" +
		"garbage line without tabs\n" +
		"192.168.99.1\t00:00:00:00:00:01\tOut of range\n" +
		"\n4 packets received by filter\n"

	_, network, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	hosts := parseARPScanOutput(out, network)
	if len(hosts) != 2 {
		t.Fatalf("parsed %d hosts, want 2: %+v", len(hosts), hosts)
	}
	if hosts[0].IP != "10.0.0.1" || hosts[0].MAC != "00:11:22:33:44:55" {
		t.Errorf("first host = %+v", hosts[0])
	}
	// Dash-separated input must be normalised to the canonical colon form.
	if hosts[1].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("second host MAC = %s, want aa:bb:cc:dd:ee:ff", hosts[1].MAC)
	}
}
