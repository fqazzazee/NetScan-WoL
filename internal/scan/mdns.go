package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Multicast DNS lives at 224.0.0.251:5353 with a TTL of 1, so queries never
// leave the local segment. Implemented here rather than pulled in as a
// dependency: a reverse PTR query is about a hundred lines of DNS wire format
// and this keeps the agent free of third-party code.
var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// errNoAnswer means the query went out but nothing on the segment claimed the
// address, which is the normal case for most hosts.
var errNoAnswer = errors.New("no mDNS answer")

// mdnsReverse asks the local segment "who owns this address?" and returns the
// first PTR name that answers.
func mdnsReverse(ctx context.Context, ip net.IP) (string, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("mDNS reverse lookup needs an IPv4 address")
	}
	qname := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip4[3], ip4[2], ip4[1], ip4[0])

	query, err := buildDNSQuery(qname, dnsTypePTR)
	if err != nil {
		return "", err
	}

	// Binding to :0 rather than :5353 means we do not fight the system's
	// Avahi/mDNSResponder for the well-known port. Responders reply to the
	// source port, so one-shot queries work fine from an ephemeral port.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return "", fmt.Errorf("open mDNS socket: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(600 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}
	if _, err := conn.WriteToUDP(query, mdnsGroup); err != nil {
		return "", fmt.Errorf("send mDNS query: %w", err)
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return "", errNoAnswer
		}
		name, ok := parsePTRAnswer(buf[:n], qname)
		if ok {
			return name, nil
		}
		// Not our answer — mDNS is a shared bus and other traffic arrives
		// constantly. Keep reading until the deadline.
	}
}

const (
	dnsTypePTR   = 12
	dnsClassIN   = 1
	dnsHeaderLen = 12
)

// buildDNSQuery encodes a standard query with a single question.
func buildDNSQuery(name string, qtype uint16) ([]byte, error) {
	encoded, err := encodeDNSName(name)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, dnsHeaderLen+len(encoded)+4)
	header := make([]byte, dnsHeaderLen)
	// ID 0 is conventional for one-shot mDNS; the query is matched by name.
	binary.BigEndian.PutUint16(header[4:6], 1) // one question
	msg = append(msg, header...)
	msg = append(msg, encoded...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	return msg, nil
}

// encodeDNSName writes a name in length-prefixed label form.
func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label %q", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// parsePTRAnswer walks a response and returns the target of the first PTR
// record whose owner name matches the question we asked.
//
// This parses unauthenticated multicast traffic from any device on the
// segment, so every offset is bounds-checked and pointer following is depth-
// limited against compression loops.
func parsePTRAnswer(msg []byte, want string) (string, bool) {
	if len(msg) < dnsHeaderLen {
		return "", false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 { // not a response
		return "", false
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	if anCount == 0 {
		return "", false
	}

	off := dnsHeaderLen
	for i := 0; i < qdCount; i++ {
		_, next, ok := decodeDNSName(msg, off, 0)
		if !ok || next+4 > len(msg) {
			return "", false
		}
		off = next + 4
	}

	want = strings.ToLower(strings.TrimSuffix(want, "."))
	for i := 0; i < anCount; i++ {
		owner, next, ok := decodeDNSName(msg, off, 0)
		if !ok || next+10 > len(msg) {
			return "", false
		}
		rtype := binary.BigEndian.Uint16(msg[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdStart := next + 10
		if rdStart+rdLen > len(msg) {
			return "", false
		}
		if rtype == dnsTypePTR && strings.EqualFold(strings.TrimSuffix(owner, "."), want) {
			target, _, ok := decodeDNSName(msg, rdStart, 0)
			if ok && target != "" {
				return target, true
			}
		}
		off = rdStart + rdLen
	}
	return "", false
}

// maxPointerDepth caps compression-pointer following. A malicious or broken
// responder can craft a name that points at itself; without this cap that is
// an infinite loop in a network-facing parser.
const maxPointerDepth = 16

// decodeDNSName reads a possibly-compressed name at off. It returns the name,
// the offset just past the name in the *original* stream, and whether parsing
// succeeded.
func decodeDNSName(msg []byte, off, depth int) (string, int, bool) {
	if depth > maxPointerDepth {
		return "", 0, false
	}
	var labels []string
	cursor := off
	afterPointer := -1
	for {
		if cursor >= len(msg) {
			return "", 0, false
		}
		length := int(msg[cursor])
		switch {
		case length == 0:
			cursor++
			if afterPointer >= 0 {
				cursor = afterPointer
			}
			return strings.Join(labels, "."), cursor, true

		case length&0xc0 == 0xc0: // compression pointer
			if cursor+1 >= len(msg) {
				return "", 0, false
			}
			target := int(binary.BigEndian.Uint16(msg[cursor:cursor+2]) & 0x3fff)
			if target >= len(msg) {
				return "", 0, false
			}
			if afterPointer < 0 {
				afterPointer = cursor + 2
			}
			suffix, _, ok := decodeDNSName(msg, target, depth+1)
			if !ok {
				return "", 0, false
			}
			if suffix != "" {
				labels = append(labels, suffix)
			}
			return strings.Join(labels, "."), afterPointer, true

		case length > 63:
			return "", 0, false

		default:
			start := cursor + 1
			end := start + length
			if end > len(msg) {
				return "", 0, false
			}
			labels = append(labels, string(msg[start:end]))
			cursor = end
		}
	}
}
