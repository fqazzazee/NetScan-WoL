package store

import (
	"sync"
	"testing"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/token"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestClaimTokenIsSingleUse is the security-critical one. A single-use
// enrollment token must admit exactly one agent, and the check-and-consume has
// to be atomic — otherwise anyone holding a copy of the token can race a
// legitimate agent and get an identity of their own.
func TestClaimTokenIsSingleUse(t *testing.T) {
	st := newTestStore(t)
	secret, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutToken(&EnrollToken{
		ID: "t1", Hash: token.Hash(secret), CreatedAt: time.Now(), MaxUses: 1,
	}); err != nil {
		t.Fatal(err)
	}

	match := func(hash string) bool { return token.Equal(secret, hash) }

	const racers = 32
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if _, err := st.ClaimToken(match, "agent"); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent claims succeeded on a single-use token; want exactly 1", succeeded, racers)
	}
}

func TestClaimTokenRejects(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()

	secrets := map[string]*EnrollToken{
		"expired": {ID: "expired", CreatedAt: now, MaxUses: 1, ExpiresAt: now.Add(-time.Minute)},
		"revoked": {ID: "revoked", CreatedAt: now, MaxUses: 1, Revoked: true},
		"spent":   {ID: "spent", CreatedAt: now, MaxUses: 2, Uses: 2},
	}
	plain := map[string]string{}
	for name, tok := range secrets {
		secret, err := token.New()
		if err != nil {
			t.Fatal(err)
		}
		plain[name] = secret
		tok.Hash = token.Hash(secret)
		if err := st.PutToken(tok); err != nil {
			t.Fatal(err)
		}
	}

	for name, secret := range plain {
		s := secret
		if _, err := st.ClaimToken(func(h string) bool { return token.Equal(s, h) }, "agent"); err == nil {
			t.Errorf("a %s token was accepted", name)
		}
	}

	// An unknown secret must be distinguishable from an unusable one so the
	// API can answer 401 rather than 403.
	unknown, _ := token.New()
	if _, err := st.ClaimToken(func(h string) bool { return token.Equal(unknown, h) }, "agent"); err != ErrTokenUnknown {
		t.Errorf("unknown token gave %v, want ErrTokenUnknown", err)
	}
}

// TestStatePersistsAcrossReopen proves the JSON file is a real store and not
// just an in-memory map that happens to be written out.
func TestStatePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveHost(&SavedHost{MAC: "AA-BB-CC-DD-EE-FF", Label: "nas"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAgent(&Agent{ID: "a1", Name: "agent one", EnrolledAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	host, ok := reopened.Host("aa:bb:cc:dd:ee:ff")
	if !ok {
		t.Fatal("saved host did not survive a reopen")
	}
	if host.Label != "nas" {
		t.Errorf("label = %q, want nas", host.Label)
	}
	if _, ok := reopened.Agent("a1"); !ok {
		t.Error("agent did not survive a reopen")
	}
}

// TestSaveHostNormalizesMAC matters because the MAC is the primary key: if
// "AA-BB" and "aa:bb" were different keys, the same machine could be saved
// twice and a wake would update the wrong record.
func TestSaveHostNormalizesMAC(t *testing.T) {
	st := newTestStore(t)
	for _, form := range []string{"AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"} {
		if _, err := st.SaveHost(&SavedHost{MAC: form, Label: "same machine"}); err != nil {
			t.Fatalf("SaveHost(%q): %v", form, err)
		}
	}
	if got := len(st.Hosts()); got != 1 {
		t.Errorf("stored %d hosts, want 1 — MAC normalisation is not collapsing notations", got)
	}
}

func TestSaveHostRejectsBadMAC(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.SaveHost(&SavedHost{MAC: "not-a-mac"}); err == nil {
		t.Error("SaveHost accepted a malformed MAC")
	}
}

func TestPasswordHashing(t *testing.T) {
	op, err := NewOperator("admin", "correct horse battery")
	if err != nil {
		t.Fatalf("NewOperator: %v", err)
	}
	if op.PassHash == "" || op.Salt == "" {
		t.Fatal("operator was created without a hash or salt")
	}
	// The plaintext must not be recoverable from the record.
	if op.PassHash == "correct horse battery" {
		t.Fatal("the password was stored in plaintext")
	}
	if !CheckPassword(op, "correct horse battery") {
		t.Error("the correct password was rejected")
	}
	if CheckPassword(op, "Correct horse battery") {
		t.Error("a wrong password was accepted")
	}

	// Two operators with the same password must not share a hash, or one
	// cracked password would reveal every reuse of it.
	other, err := NewOperator("admin2", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if other.PassHash == op.PassHash {
		t.Error("identical passwords produced identical hashes; the salt is not being applied")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("short"); err == nil {
		t.Error("a password below the minimum length was accepted")
	}
	if err := ValidatePassword(string(make([]byte, 300))); err == nil {
		t.Error("an over-long password was accepted; PBKDF2 cost is unbounded")
	}
	if err := ValidatePassword("a-perfectly-fine-password"); err != nil {
		t.Errorf("a reasonable password was rejected: %v", err)
	}
}

func TestGeneratePasswordIsRandom(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		pw, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 20 {
			t.Fatalf("generated password is %d characters, want 20", len(pw))
		}
		if seen[pw] {
			t.Fatal("GeneratePassword returned a duplicate")
		}
		seen[pw] = true
	}
}
