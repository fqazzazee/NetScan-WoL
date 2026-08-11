package ca

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// The hub's certificate chain must use algorithms browsers implement.
//
// This is a regression guard for a real failure: an early build used Ed25519
// throughout, and every browser refused to connect with
// SSL_ERROR_NO_CYPHER_OVERLAP. Neither NSS (Firefox) nor BoringSSL (Chrome,
// Brave, Edge) can verify an Ed25519 X.509 certificate.
//
// The check is on the algorithms rather than on a simulated handshake. Go's
// crypto/tls offers no client-side control of the signature_algorithms
// extension, so a Go client cannot reproduce a browser's constraints — it
// completes an Ed25519 handshake quite happily, which is exactly why the
// original bug survived testing with Go and curl. Asserting the algorithm
// directly is the only check here that actually fails when the bug returns.
func TestChainUsesBrowserVerifiableAlgorithms(t *testing.T) {
	dir := t.TempDir()
	authority, err := Open(dir, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !authority.BrowserCompatible() {
		t.Error("a freshly created authority reports itself as browser-incompatible")
	}

	// A browser verifies the whole chain, so the CA matters as much as the
	// leaf: an ECDSA leaf signed by an Ed25519 CA still fails.
	for name, cert := range map[string]*x509.Certificate{
		"CA":   authority.caCert,
		"leaf": authority.srvCert,
	} {
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Errorf("%s public key is %T, want *ecdsa.PublicKey — browsers cannot verify anything else here",
				name, cert.PublicKey)
			continue
		}
		if got := pub.Curve.Params().Name; got != "P-256" {
			t.Errorf("%s uses curve %s, want P-256", name, got)
		}
		switch cert.SignatureAlgorithm {
		case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		default:
			t.Errorf("%s is signed with %v, which browsers do not accept here", name, cert.SignatureAlgorithm)
		}
	}
}

// TestHubCertificateChainVerifies confirms the served certificate actually
// chains to the CA and covers the names it was asked to cover. This is the
// ordinary correctness check; the algorithm test above is what guards browser
// compatibility.
func TestHubCertificateChainVerifies(t *testing.T) {
	dir := t.TempDir()
	authority, err := Open(dir, []string{"localhost", "127.0.0.1", "hub.example.com"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	certPath, keyPath := authority.ServerCertPaths()
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("the hub certificate and key do not load as a pair: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CAPEM()) {
		t.Fatal("CA PEM did not parse")
	}

	for _, name := range []string{"localhost", "hub.example.com", "127.0.0.1"} {
		if _, err := authority.srvCert.Verify(x509.VerifyOptions{
			Roots:     roots,
			DNSName:   name,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Errorf("certificate does not verify for %q: %v", name, err)
		}
	}
}

// TestAgentKeysAreAccepted confirms enrollment still works with the key type
// agents generate. Agent certificates never reach a browser, but they must
// chain to the same CA.
func TestAgentKeysAreAccepted(t *testing.T) {
	dir := t.TempDir()
	authority, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	_, csrPEM, err := NewAgentKeyAndCSR("test-agent")
	if err != nil {
		t.Fatalf("NewAgentKeyAndCSR: %v", err)
	}
	if _, err := authority.SignAgent(csrPEM, "agent-1", "test-agent"); err != nil {
		t.Fatalf("SignAgent: %v", err)
	}
}
