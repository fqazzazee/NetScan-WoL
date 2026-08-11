package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// PBKDF2 parameters. Operator passwords are human-chosen and therefore
// low-entropy, so unlike enrollment tokens they need a deliberately slow hash.
// 600,000 SHA-256 iterations is the current OWASP guidance and costs roughly a
// quarter-second per login on modest hardware — unnoticeable to a person,
// expensive for an offline cracker.
const (
	pbkdf2Iterations = 600_000
	pbkdf2KeyLen     = 32
	saltLen          = 16
)

// MinPasswordLength is enforced on every password change. Length is the only
// composition rule applied: character-class requirements push people toward
// predictable substitutions without adding real entropy.
const MinPasswordLength = 12

// NewOperator builds an operator record with a hashed password.
func NewOperator(username, password string) (*Operator, error) {
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive password hash: %w", err)
	}
	return &Operator{
		Username:  strings.ToLower(strings.TrimSpace(username)),
		PassHash:  hex.EncodeToString(key),
		Salt:      hex.EncodeToString(salt),
		Iter:      pbkdf2Iterations,
		CreatedAt: time.Now(),
	}, nil
}

// CheckPassword verifies a password against an operator record in constant
// time.
func CheckPassword(op *Operator, password string) bool {
	salt, err := hex.DecodeString(op.Salt)
	if err != nil {
		return false
	}
	iter := op.Iter
	if iter <= 0 {
		iter = pbkdf2Iterations
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, pbkdf2KeyLen)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(op.PassHash)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(key, want) == 1
}

// SetPassword replaces an operator's password in place.
func SetPassword(op *Operator, password string) error {
	fresh, err := NewOperator(op.Username, password)
	if err != nil {
		return err
	}
	op.PassHash = fresh.PassHash
	op.Salt = fresh.Salt
	op.Iter = fresh.Iter
	op.MustChangePassword = false
	return nil
}

// ValidatePassword enforces the minimum length and rejects the handful of
// values people reach for when a field simply demands twelve characters.
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(pw) > 256 {
		// Bounded so a huge input cannot turn 600k PBKDF2 rounds into a
		// denial-of-service lever.
		return fmt.Errorf("password must be at most 256 characters")
	}
	switch strings.ToLower(pw) {
	case "password1234", "changeme1234", "netscanwol1", "administrator":
		return fmt.Errorf("that password is too predictable")
	}
	return nil
}

// ValidateUsername keeps usernames to a printable, log-safe character set.
func ValidateUsername(u string) error {
	u = strings.TrimSpace(u)
	if len(u) < 2 || len(u) > 64 {
		return fmt.Errorf("username must be between 2 and 64 characters")
	}
	for _, r := range u {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-' && r != '_' {
			return fmt.Errorf("username may contain only letters, digits, dot, dash and underscore")
		}
	}
	return nil
}

// GeneratePassword returns a random initial password for the bootstrap
// operator. Ambiguous characters are excluded so it can be read off a console
// and typed without a "was that a one or an ell" detour.
func GeneratePassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const length = 20

	out := make([]byte, 0, length)
	buf := make([]byte, 1)
	// Rejection sampling rather than a modulo fold: 256 is not a multiple of
	// the alphabet size, so plain modulo would make early letters marginally
	// more likely than late ones.
	limit := byte(256 - (256 % len(alphabet)))
	for len(out) < length {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		if buf[0] >= limit {
			continue
		}
		out = append(out, alphabet[int(buf[0])%len(alphabet)])
	}
	return string(out), nil
}
