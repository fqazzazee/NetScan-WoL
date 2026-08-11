// Package oui maps MAC address prefixes to hardware vendors.
//
// The IEEE registry holds tens of thousands of assignments and changes weekly,
// so shipping a full copy inside the binary would be both large and
// perpetually stale. Instead a small high-confidence table is embedded — the
// hypervisors, single-board computers and NIC vendors that dominate a homelab
// or office segment — and the complete registry can be loaded from disk when an
// operator wants exhaustive coverage.
package oui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/fqazzazee/netscan-wol/internal/netutil"
)

// DB resolves vendors. The zero value is not usable; call Default or Load.
type DB struct {
	mu      sync.RWMutex
	entries map[string]string
}

var (
	defaultOnce sync.Once
	defaultDB   *DB
)

// Default returns the process-wide database seeded with the embedded table.
func Default() *DB {
	defaultOnce.Do(func() {
		defaultDB = &DB{entries: make(map[string]string, len(embedded))}
		for prefix, vendor := range embedded {
			defaultDB.entries[normalizePrefix(prefix)] = vendor
		}
	})
	return defaultDB
}

// Lookup returns the vendor for a MAC address, or a descriptive placeholder
// when the address is not from a registered assignment.
func (d *DB) Lookup(mac string) string {
	hw, err := netutil.ParseMAC(mac)
	if err != nil {
		return ""
	}

	// The second-least-significant bit of the first octet marks a locally
	// administered address. Hypervisors, container runtimes and randomised
	// client MACs all live here, and none of them appear in the IEEE registry,
	// so saying so is more useful than an empty cell.
	locallyAdministered := hw[0]&0x02 != 0

	key := fmt.Sprintf("%02x%02x%02x", hw[0], hw[1], hw[2])
	d.mu.RLock()
	vendor, ok := d.entries[key]
	d.mu.RUnlock()
	if ok {
		return vendor
	}
	if locallyAdministered {
		return "locally administered"
	}
	return ""
}

// LoadFile merges an IEEE-format OUI file into the database. Both the classic
// oui.txt layout and the CSV export are accepted, since the IEEE publishes
// both and people download whichever they find first.
func (d *DB) LoadFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open OUI file: %w", err)
	}
	defer f.Close()

	added := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	d.mu.Lock()
	defer d.mu.Unlock()
	for sc.Scan() {
		prefix, vendor, ok := parseOUILine(sc.Text())
		if !ok {
			continue
		}
		d.entries[prefix] = vendor
		added++
	}
	if err := sc.Err(); err != nil {
		return added, fmt.Errorf("read OUI file: %w", err)
	}
	return added, nil
}

// parseOUILine handles the two published formats:
//
//	oui.txt: "00-50-56   (hex)		VMware, Inc."
//	oui.csv: "MA-L,005056,VMware, Inc.,3401 Hillview..."
func parseOUILine(line string) (prefix, vendor string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}

	if i := strings.Index(line, "(hex)"); i > 0 {
		prefix = normalizePrefix(line[:i])
		vendor = strings.TrimSpace(line[i+len("(hex)"):])
		return prefix, vendor, len(prefix) == 6 && vendor != ""
	}

	fields := strings.Split(line, ",")
	if len(fields) >= 3 && (fields[0] == "MA-L" || fields[0] == "MA-M" || fields[0] == "MA-S") {
		prefix = normalizePrefix(fields[1])
		vendor = strings.Trim(strings.TrimSpace(fields[2]), `"`)
		return prefix, vendor, len(prefix) == 6 && vendor != ""
	}
	return "", "", false
}

// normalizePrefix reduces any of 00-50-56 / 00:50:56 / 005056 to "005056".
func normalizePrefix(s string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			return r
		default:
			return -1
		}
	}, s))
}

// Size reports how many prefixes are loaded, for the UI's diagnostics panel.
func (d *DB) Size() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.entries)
}
