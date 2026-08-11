// Package token generates and verifies the shared secrets used for agent
// enrollment and operator sessions.
//
// Enrollment tokens are 256 bits of cryptographic randomness rendered as 64
// hex characters. The hub stores only a SHA-256 hash, so a leaked database
// backup does not hand an attacker a working join credential, and comparison
// is constant-time so response latency cannot be used to guess a token a
// character at a time.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// Bytes is the token length in bytes. 32 bytes is 256 bits: far beyond any
// feasible online or offline guessing attack, while still being a single
// copy-pasteable string.
const Bytes = 32

// Chars is the rendered length, used for input validation in the UI and API.
const Chars = Bytes * 2

// New returns a fresh token as lower-case hex.
func New() (string, error) {
	buf := make([]byte, Bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes for token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Hash returns the storable digest of a token. Enrollment tokens are
// high-entropy random values rather than user-chosen passwords, so a plain
// SHA-256 is appropriate: there is no dictionary to attack and no benefit to
// the deliberate slowness of a password hash.
func Hash(tok string) string {
	sum := sha256.Sum256([]byte(Normalize(tok)))
	return hex.EncodeToString(sum[:])
}

// Equal compares a presented token against a stored hash in constant time.
func Equal(presented, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(Hash(presented)), []byte(storedHash)) == 1
}

// Normalize trims whitespace and lower-cases a token so a value pasted with a
// trailing newline or in upper case still works.
func Normalize(tok string) string {
	return strings.ToLower(strings.TrimSpace(tok))
}

// Valid reports whether a string is well-formed. Rejecting malformed input
// before any lookup keeps obviously-bogus requests out of the audit log's
// failed-authentication counters.
func Valid(tok string) bool {
	tok = Normalize(tok)
	if len(tok) != Chars {
		return false
	}
	_, err := hex.DecodeString(tok)
	return err == nil
}

// Format inserts dashes every 8 characters for display. Only ever used for
// showing a token to a human; the wire format is always the plain hex.
func Format(tok string) string {
	tok = Normalize(tok)
	var b strings.Builder
	for i, r := range tok {
		if i > 0 && i%8 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}
