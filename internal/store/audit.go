package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// auditLog is an append-only JSON-lines file of security-relevant events:
// logins, enrollments, token issuance and revocation, agent removal, and every
// wake command. Append-only and line-oriented so it can be tailed, shipped to
// a log collector, or read with grep when the hub itself is unavailable.
type auditLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	w    *bufio.Writer
	// recent keeps the last entries in memory so the UI can show them without
	// re-reading the file on every request.
	recent []AuditEntry
}

// recentCap bounds the in-memory tail.
const recentCap = 500

func openAuditLog(path string) (*auditLog, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	l := &auditLog{path: path, f: f, w: bufio.NewWriter(f)}
	l.recent = l.loadTail()
	return l, nil
}

// Append writes one entry and flushes immediately. Buffering audit records
// across a crash would lose exactly the events most worth having.
func (l *auditLog) Append(e AuditEntry) {
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w.Write(data)
	l.w.WriteByte('\n')
	l.w.Flush()

	l.recent = append(l.recent, e)
	if len(l.recent) > recentCap {
		l.recent = l.recent[len(l.recent)-recentCap:]
	}
}

// Tail returns up to n recent entries, newest first.
func (l *auditLog) Tail(n int) []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.recent) {
		n = len(l.recent)
	}
	out := make([]AuditEntry, 0, n)
	for i := len(l.recent) - 1; i >= len(l.recent)-n; i-- {
		out = append(out, l.recent[i])
	}
	return out
}

func (l *auditLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w.Flush()
	return l.f.Close()
}

// loadTail reads the existing log so a restart does not blank the UI's recent
// activity panel.
func (l *auditLog) loadTail() []AuditEntry {
	f, err := os.Open(l.path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		out = append(out, e)
		if len(out) > recentCap {
			out = out[1:]
		}
	}
	return out
}
