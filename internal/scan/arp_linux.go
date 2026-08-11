//go:build linux

package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/netutil"
)

// Ethernet and ARP wire constants. Spelled out rather than pulled from a
// dependency so the whole packet path is auditable in one place.
const (
	ethHeaderLen = 14
	arpPacketLen = 28
	frameLen     = ethHeaderLen + arpPacketLen

	ethTypeARP = 0x0806
	ethTypeIP4 = 0x0800

	arpHWEthernet = 1
	arpOpRequest  = 1
	arpOpReply    = 2
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// rawARPAvailable reports whether this process may open AF_PACKET sockets,
// which requires CAP_NET_RAW. Checked once at startup so the agent can
// advertise its real capabilities instead of failing at scan time.
func rawARPAvailable() bool {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethTypeARP)))
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// htons converts a 16-bit value to network byte order. AF_PACKET wants the
// protocol number in network order, which is a classic source of silent
// "socket receives nothing" bugs.
func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

// arpSweep sends an ARP request to every address in targets over ifi and
// collects the replies. It returns as soon as the context is done, the reply
// deadline passes, or every target has answered.
//
// The send and receive halves run concurrently: replies from fast hosts start
// arriving while later requests are still going out, which is what keeps a /24
// sweep close to the pacing delay rather than the full round-trip budget.
func arpSweep(ctx context.Context, ifi *net.Interface, srcIP net.IP, targets []net.IP, opt sweepOptions) ([]arpReply, error) {
	if len(ifi.HardwareAddr) != 6 {
		return nil, fmt.Errorf("interface %s has no Ethernet address", ifi.Name)
	}
	src4 := srcIP.To4()
	if src4 == nil {
		return nil, fmt.Errorf("source address %s is not IPv4", srcIP)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethTypeARP)))
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) {
			return nil, fmt.Errorf("opening a raw ARP socket needs CAP_NET_RAW: %w", err)
		}
		return nil, fmt.Errorf("open AF_PACKET socket: %w", err)
	}
	defer syscall.Close(fd)

	// Bind to the one interface so we do not receive ARP traffic from every
	// other link on the machine.
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: htons(ethTypeARP),
		Ifindex:  ifi.Index,
	}); err != nil {
		return nil, fmt.Errorf("bind raw socket to %s: %w", ifi.Name, err)
	}

	// A receive timeout is what lets the reader goroutine notice cancellation;
	// without it a blocking Recvfrom would outlive the scan.
	tv := syscall.NsecToTimeval(int64(200 * time.Millisecond))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("set receive timeout: %w", err)
	}

	wanted := make(map[string]bool, len(targets))
	for _, ip := range targets {
		if ip4 := ip.To4(); ip4 != nil {
			wanted[ip4.String()] = true
		}
	}

	var (
		mu   sync.Mutex
		seen = make(map[string]arpReply, len(targets))
		// sentAt records when each address was last probed so the reply can be
		// turned into a real per-host round-trip time.
		sentAt  = make(map[string]time.Time, len(targets))
		sendErr error
	)

	readCtx, stopReading := context.WithCancel(ctx)
	defer stopReading()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1514)
		for {
			select {
			case <-readCtx.Done():
				return
			default:
			}
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
					continue
				}
				return
			}
			reply, ok := parseARPReply(buf[:n])
			if !ok {
				continue
			}
			// Ignore answers for addresses we did not ask about; other hosts'
			// ARP chatter is constantly on the wire.
			if !wanted[reply.IP.String()] {
				continue
			}
			key := reply.IP.String()
			mu.Lock()
			if _, dup := seen[key]; !dup {
				if t, ok := sentAt[key]; ok {
					reply.RTT = time.Since(t)
				}
				seen[key] = reply
			}
			done := len(seen) == len(wanted)
			mu.Unlock()
			if done {
				stopReading()
				return
			}
		}
	}()

	// Send phase. Each retry pass re-probes only addresses still unanswered,
	// so a second pass over a mostly-populated /24 is cheap.
	frame := make([]byte, frameLen)
	dst := syscall.SockaddrLinklayer{
		Protocol: htons(ethTypeARP),
		Ifindex:  ifi.Index,
		Halen:    6,
	}
	copy(dst.Addr[:], broadcastMAC)

	// send emits one probe, retrying once past a full transmit queue. ENOBUFS
	// means we are outrunning the NIC rather than failing, so backing off and
	// re-sending the same address is better than dropping it from the sweep.
	send := func(ip4 net.IP) error {
		buildARPRequest(frame, ifi.HardwareAddr, src4, ip4)
		mu.Lock()
		sentAt[ip4.String()] = time.Now()
		mu.Unlock()
		err := syscall.Sendto(fd, frame, 0, &dst)
		if errors.Is(err, syscall.ENOBUFS) {
			time.Sleep(5 * time.Millisecond)
			err = syscall.Sendto(fd, frame, 0, &dst)
		}
		if err != nil {
			return fmt.Errorf("send ARP request to %s: %w", ip4, err)
		}
		return nil
	}

	retries := opt.retries
	if retries < 1 {
		retries = 1
	}
sendLoop:
	for pass := 0; pass < retries; pass++ {
		for _, ip := range targets {
			select {
			case <-ctx.Done():
				break sendLoop
			default:
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if pass > 0 {
				mu.Lock()
				_, answered := seen[ip4.String()]
				mu.Unlock()
				if answered {
					continue
				}
			}
			if err := send(ip4); err != nil {
				sendErr = err
				break sendLoop
			}
			if opt.pacing > 0 {
				time.Sleep(opt.pacing)
			}
		}
	}

	// Give in-flight replies time to land after the last request went out.
	select {
	case <-ctx.Done():
	case <-readCtx.Done():
	case <-time.After(opt.settle):
	}
	stopReading()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	out := make([]arpReply, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	if len(out) == 0 && sendErr != nil {
		return nil, sendErr
	}
	return out, nil
}

// buildARPRequest writes an Ethernet-framed ARP request into buf, which must be
// frameLen bytes. Reusing one buffer across the sweep avoids allocating a frame
// per probe.
func buildARPRequest(buf []byte, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) {
	copy(buf[0:6], broadcastMAC)
	copy(buf[6:12], srcMAC)
	binary.BigEndian.PutUint16(buf[12:14], ethTypeARP)

	p := buf[ethHeaderLen:]
	binary.BigEndian.PutUint16(p[0:2], arpHWEthernet)
	binary.BigEndian.PutUint16(p[2:4], ethTypeIP4)
	p[4] = 6 // hardware address length
	p[5] = 4 // protocol address length
	binary.BigEndian.PutUint16(p[6:8], arpOpRequest)
	copy(p[8:14], srcMAC)
	copy(p[14:18], srcIP.To4())
	copy(p[18:24], make([]byte, 6)) // target hardware address is unknown
	copy(p[24:28], dstIP.To4())
}

// arpReply is one host that answered a probe.
type arpReply struct {
	IP  net.IP
	MAC net.HardwareAddr
	RTT time.Duration
}

// parseARPReply validates a received frame and extracts the sender's addresses.
// Every length and field check here is deliberate: this parses attacker-
// influenced bytes straight off the wire.
func parseARPReply(frame []byte) (arpReply, bool) {
	if len(frame) < frameLen {
		return arpReply{}, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeARP {
		return arpReply{}, false
	}
	p := frame[ethHeaderLen:]
	if binary.BigEndian.Uint16(p[0:2]) != arpHWEthernet {
		return arpReply{}, false
	}
	if binary.BigEndian.Uint16(p[2:4]) != ethTypeIP4 {
		return arpReply{}, false
	}
	if p[4] != 6 || p[5] != 4 {
		return arpReply{}, false
	}
	if binary.BigEndian.Uint16(p[6:8]) != arpOpReply {
		return arpReply{}, false
	}
	mac := make(net.HardwareAddr, 6)
	copy(mac, p[8:14])
	if netutil.IsZeroMAC(mac) || netutil.IsBroadcastMAC(mac) {
		return arpReply{}, false
	}
	ip := make(net.IP, 4)
	copy(ip, p[14:18])
	if ip.IsUnspecified() {
		return arpReply{}, false
	}
	return arpReply{IP: ip, MAC: mac}, true
}

// sweepOptions tunes one ARP sweep.
type sweepOptions struct {
	retries int
	// pacing is the delay between probes. It keeps a large sweep from
	// saturating the segment or tripping switch storm control.
	pacing time.Duration
	// settle is how long to keep listening after the final request.
	settle time.Duration
}
