package token

import (
	"strings"
	"testing"
)

func TestNewProducesDistinct256BitTokens(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if len(tok) != Chars {
			t.Fatalf("token is %d characters, want %d (256 bits of hex)", len(tok), Chars)
		}
		if seen[tok] {
			t.Fatal("New returned a duplicate token")
		}
		seen[tok] = true
	}
}

func TestValid(t *testing.T) {
	good, _ := New()
	cases := map[string]bool{
		good:                         true,
		strings.ToUpper(good):        true,
		"  " + good + "\n":           true,
		strings.Repeat("a", Chars):   true,
		strings.Repeat("a", Chars-1): false,
		strings.Repeat("a", Chars+1): false,
		strings.Repeat("z", Chars):   false, // not hex
		"":                           false,
	}
	for in, want := range cases {
		if got := Valid(in); got != want {
			t.Errorf("Valid(%.12s…) = %t, want %t", in, got, want)
		}
	}
}

// TestEqualUsesHash confirms the stored form is a digest, not the secret. A
// leaked state file must not hand over working enrollment credentials.
func TestEqualUsesHash(t *testing.T) {
	tok, _ := New()
	stored := Hash(tok)

	if stored == tok {
		t.Fatal("Hash returned the token itself")
	}
	if !Equal(tok, stored) {
		t.Error("a correct token did not match its own hash")
	}
	if Equal(tok, Hash("something else")) {
		t.Error("a wrong token matched")
	}
	// Case and surrounding whitespace must not change the verdict; people
	// paste tokens with both.
	if !Equal(strings.ToUpper(tok)+"\n", stored) {
		t.Error("a correct token was rejected because of case or whitespace")
	}
}

func TestFormat(t *testing.T) {
	got := Format(strings.Repeat("ab", 32))
	if strings.Count(got, "-") != 7 {
		t.Errorf("Format produced %d separators, want 7: %s", strings.Count(got, "-"), got)
	}
	if strings.ReplaceAll(got, "-", "") != strings.Repeat("ab", 32) {
		t.Error("Format changed the token's characters")
	}
}
