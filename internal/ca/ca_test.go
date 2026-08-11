package ca

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenCreatesAndReloads(t *testing.T) {
	dir := t.TempDir()

	first, err := Open(dir, []string{"hub.example.com", "10.0.0.5"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pin := first.Fingerprint()
	if pin == "" {
		t.Fatal("no CA fingerprint was produced")
	}

	// Reopening must reuse the same CA. Regenerating it would silently
	// invalidate every enrolled agent.
	second, err := Open(dir, []string{"hub.example.com", "10.0.0.5"})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if second.Fingerprint() != pin {
		t.Fatal("reopening the CA directory produced a different CA")
	}
}

// TestCAKeyPermissions checks the file mode directly. Anyone who can read
// ca.key can mint an agent identity, so 0600 is part of the security boundary.
func TestCAKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.key", "hub.key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s has mode %04o, want 0600", name, mode)
		}
	}
}

// TestServerCertIncludesChain guards the bug that breaks CA pinning: if the
// hub sends only its leaf, an agent has nothing in the handshake to match its
// pin against and enrollment fails.
func TestServerCertIncludesChain(t *testing.T) {
	dir := t.TempDir()
	authority, err := Open(dir, []string{"hub.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	certPath, _ := authority.ServerCertPaths()
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}

	var count int
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			count++
		}
	}
	if count < 2 {
		t.Fatalf("the server certificate file holds %d certificates; it must include the CA so agents can verify their pin", count)
	}
}

func TestSignAgent(t *testing.T) {
	dir := t.TempDir()
	authority, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, csrPEM, err := NewAgentKeyAndCSR("branch-office")
	if err != nil {
		t.Fatalf("NewAgentKeyAndCSR: %v", err)
	}

	certPEM, err := authority.SignAgent(csrPEM, "agent-id-123", "branch-office")
	if err != nil {
		t.Fatalf("SignAgent: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}

	// The identity must come from the hub, not the CSR: an agent that could
	// choose its own common name could impersonate another agent.
	if cert.Subject.CommonName != "agent-id-123" {
		t.Errorf("common name = %q, want the hub-assigned agent id", cert.Subject.CommonName)
	}
	if AgentIDFromCert(cert) != "agent-id-123" {
		t.Error("AgentIDFromCert did not return the hub-assigned id")
	}

	// Client auth only. A leaf that also carried server auth could be used to
	// stand up an impostor hub for other agents.
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("extended key usage = %v, want client auth only", cert.ExtKeyUsage)
	}
	if cert.IsCA {
		t.Error("the issued agent certificate is marked as a CA")
	}

	// It must actually chain to the hub CA.
	pool := authority.ClientCAPool()
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("issued certificate does not verify against the hub CA: %v", err)
	}
}

func TestSignAgentRejectsBadCSR(t *testing.T) {
	dir := t.TempDir()
	authority, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"not PEM":        []byte("hello"),
		"wrong PEM type": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
		"corrupt DER":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1, 2, 3}}),
	}
	for name, csr := range cases {
		if _, err := authority.SignAgent(csr, "id", "name"); err == nil {
			t.Errorf("SignAgent accepted %s", name)
		}
	}
}

func TestHalfInitialisedDirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, nil); err != nil {
		t.Fatal(err)
	}
	// Removing the key but leaving the certificate is what a partial restore
	// looks like. Silently regenerating would invalidate every agent; the code
	// should say so instead.
	if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, nil); err == nil {
		t.Fatal("a half-initialised CA directory was accepted")
	}
}
