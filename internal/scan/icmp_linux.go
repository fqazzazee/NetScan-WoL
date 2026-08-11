//go:build linux

package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"
)

// icmpProbe sends one ICMP echo request using an unprivileged datagram ICMP
// socket. Linux allows these without CAP_NET_RAW when the process GID falls in
// net.ipv4.ping_group_range, which is how a rootless container can still ping.
// If the socket cannot be opened the caller falls back to a TCP probe.
func icmpProbe(ctx context.Context, ip net.IP) (time.Duration, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		// Fall back to a raw socket, which works when we do hold CAP_NET_RAW.
		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
		if err != nil {
			return 0, false
		}
	}
	defer syscall.Close(fd)

	timeout := 1 * time.Second
	if d, ok := ctx.Deadline(); ok {
		if remaining := time.Until(d); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		return 0, false
	}
	tv := syscall.NsecToTimeval(int64(timeout))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return 0, false
	}

	// On a datagram ICMP socket the kernel rewrites the identifier field, so
	// replies are matched on the payload token instead.
	token := uint32(rand.Int31())
	seq := uint16(1)
	packet := buildEchoRequest(uint16(os.Getpid()&0xffff), seq, token)

	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], ip4)

	start := time.Now()
	if err := syscall.Sendto(fd, packet, 0, &addr); err != nil {
		return 0, false
	}

	buf := make([]byte, 1500)
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return 0, false
		}
		src, ok := from.(*syscall.SockaddrInet4)
		if !ok || !net.IP(src.Addr[:]).Equal(ip4) {
			continue
		}
		if matchEchoReply(buf[:n], token) {
			return time.Since(start), true
		}
		if time.Since(start) > timeout {
			return 0, false
		}
	}
}

const (
	icmpTypeEchoRequest = 8
	icmpTypeEchoReply   = 0
	icmpEchoHeaderLen   = 8
)

// buildEchoRequest assembles an ICMP echo with a 4-byte token in the payload.
func buildEchoRequest(id, seq uint16, token uint32) []byte {
	pkt := make([]byte, icmpEchoHeaderLen+4)
	pkt[0] = icmpTypeEchoRequest
	pkt[1] = 0 // code
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	binary.BigEndian.PutUint32(pkt[8:12], token)
	binary.BigEndian.PutUint16(pkt[2:4], checksum(pkt))
	return pkt
}

// matchEchoReply verifies a reply carries our token. A raw socket hands back
// the IPv4 header too, so both layouts are accepted.
func matchEchoReply(buf []byte, token uint32) bool {
	if len(buf) >= 20 && buf[0]>>4 == 4 {
		ihl := int(buf[0]&0x0f) * 4
		if ihl >= 20 && len(buf) > ihl {
			buf = buf[ihl:]
		}
	}
	if len(buf) < icmpEchoHeaderLen+4 {
		return false
	}
	if buf[0] != icmpTypeEchoReply {
		return false
	}
	return binary.BigEndian.Uint32(buf[8:12]) == token
}

// checksum is the standard one's-complement sum used by ICMP.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
