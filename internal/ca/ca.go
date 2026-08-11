// Package ca implements the hub's private certificate authority.
//
// Every agent gets its own client certificate signed by this CA, and the hub
// presents a server certificate from the same CA. That gives mutual TLS with
// per-agent identity: the hub knows exactly which agent is calling, an agent
// can be revoked individually by deleting its record, and a stolen enrollment
// token cannot be replayed once it has been consumed.
//
// Keys are Ed25519. They are small, fast, have no parameter choices to get
// wrong, and are supported by every TLS 1.3 stack — including Go's, which is
// the only one involved here.
package ca

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Lifetimes. The CA outlives any realistic deployment; leaf certificates are
// deliberately shorter so a compromised agent key stops working on its own if
// the agent is decommissioned without a formal revocation.
const (
	caValidity     = 10 * year
	serverValidity = 2 * year
	agentValidity  = 2 * year
	year           = 365 * 24 * time.Hour
	// backdate absorbs clock skew between hub and agent, which is common on
	// LXC containers and appliances that boot without NTP.
	backdate = 10 * time.Minute
)

// File names inside the CA directory.
const (
	caCertFile     = "ca.crt"
	caKeyFile      = "ca.key"
	serverCertFile = "hub.crt"
	serverKeyFile  = "hub.key"
)

// Authority owns the CA key material and issues certificates.
type Authority struct {
	dir string

	mu        sync.RWMutex
	caCert    *x509.Certificate
	caKey     ed25519.PrivateKey
	caPEM     []byte
	fprint    string
	srvCert   *x509.Certificate
	srvPEM    []byte
	srvKey    ed25519.PrivateKey
	srvKeyPEM []byte
}

// Open loads the CA from dir, creating it on first run. The directory and the
// private keys are created 0700/0600: anyone who can read ca.key can mint an
// agent identity and issue commands, so the file permissions are part of the
// security boundary, not housekeeping.
func Open(dir string, hubNames []string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create CA directory: %w", err)
	}
	a := &Authority{dir: dir}

	if err := a.loadOrCreateRoot(); err != nil {
		return nil, err
	}
	if err := a.loadOrCreateServer(hubNames); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Authority) loadOrCreateRoot() error {
	certPath := filepath.Join(a.dir, caCertFile)
	keyPath := filepath.Join(a.dir, caKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		cert, key, err := parseCertKey(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("load CA: %w", err)
		}
		a.caCert, a.caKey, a.caPEM = cert, key, certPEM
		a.fprint = Fingerprint(cert)
		return nil
	}
	if certErr == nil || keyErr == nil {
		return fmt.Errorf("CA directory %s is half-initialised: one of ca.crt/ca.key exists without the other; remove both to regenerate", a.dir)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "NetScan-WoL Hub CA",
			Organization: []string{"NetScan-WoL"},
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// The CA signs leaves directly; no intermediates are ever issued.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return fmt.Errorf("self-sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse freshly created CA certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := writeSecret(keyPath, keyPEM); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}

	a.caCert, a.caKey, a.caPEM = cert, priv, certPEM
	a.fprint = Fingerprint(cert)
	return nil
}

// loadOrCreateServer issues the hub's own TLS certificate. It is reissued
// whenever the requested name set changes, so adding a DNS name or an extra
// listen address does not require wiping the CA.
func (a *Authority) loadOrCreateServer(names []string) error {
	certPath := filepath.Join(a.dir, serverCertFile)
	keyPath := filepath.Join(a.dir, serverKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		cert, key, err := parseCertKey(certPEM, keyPEM)
		// Regenerate if the stored file predates chain-sending and holds only
		// the leaf; agents pin the CA and need to see it in the handshake.
		if err == nil && bytes.Contains(certPEM, a.caPEM) &&
			coversNames(cert, names) && time.Now().Before(cert.NotAfter.Add(-30*24*time.Hour)) {
			a.srvCert, a.srvKey, a.srvPEM, a.srvKeyPEM = cert, key, certPEM, keyPEM
			return nil
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate hub server key: %w", err)
	}
	dnsNames, ips := splitNames(names)
	serial, err := newSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "NetScan-WoL Hub", Organization: []string{"NetScan-WoL"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(serverValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, pub, a.caKey)
	if err != nil {
		return fmt.Errorf("sign hub server certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse hub server certificate: %w", err)
	}
	// The file holds the leaf followed by the CA, so the TLS handshake presents
	// the whole chain. Agents pin the CA's fingerprint, and a server that sent
	// only its leaf would give them nothing to match against.
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPEM = append(leafPEM, a.caPEM...)

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal hub server key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := writeSecret(keyPath, keyPEM); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write hub server certificate: %w", err)
	}
	a.srvCert, a.srvKey, a.srvPEM, a.srvKeyPEM = cert, priv, certPEM, keyPEM
	return nil
}

// SignAgent issues a client certificate for an agent from its CSR.
//
// Only the public key is taken from the CSR. The subject, validity, and key
// usage are all set by the hub, so an agent cannot talk its way into a
// different identity by crafting a creative CSR — a classic mistake in
// home-grown PKI.
func (a *Authority) SignAgent(csrPEM []byte, agentID, agentName string) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature does not verify: %w", err)
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("agent keys must be Ed25519")
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			// The agent ID is the authenticated identity the hub authorises
			// against. The friendly name is decoration only.
			CommonName:         agentID,
			Organization:       []string{"NetScan-WoL Agents"},
			OrganizationalUnit: []string{agentName},
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(agentValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.caCert, csr.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign agent certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// CAPEM returns the PEM-encoded CA certificate, which agents pin and use to
// verify the hub.
func (a *Authority) CAPEM() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.caPEM
}

// Fingerprint returns the hub CA's SHA-256 fingerprint in the "sha256:hex"
// form printed in join commands. An operator who carries this value to the
// agent closes the one trust gap in enrollment: without it the agent has to
// trust the certificate offered on first contact.
func (a *Authority) Fingerprint() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.fprint
}

// ServerCertPaths returns the on-disk paths of the hub's TLS material.
func (a *Authority) ServerCertPaths() (certPath, keyPath string) {
	return filepath.Join(a.dir, serverCertFile), filepath.Join(a.dir, serverKeyFile)
}

// ClientCAPool is the pool the hub uses to verify agent certificates.
func (a *Authority) ClientCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	a.mu.RLock()
	defer a.mu.RUnlock()
	pool.AddCert(a.caCert)
	return pool
}

// Fingerprint computes the "sha256:<hex>" fingerprint of a certificate's DER
// encoding. Used for CA pinning on both ends.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FingerprintPEM parses a PEM certificate and fingerprints it.
func FingerprintPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("expected a PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	return Fingerprint(cert), nil
}

// NewAgentKeyAndCSR generates an agent's key pair and a CSR for it. The private
// key never leaves the agent host.
func NewAgentKeyAndCSR(commonName string) (keyPEM, csrPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate agent key: %w", err)
	}
	_ = pub
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal agent key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return keyPEM, csrPEM, nil
}

// AgentIDFromCert extracts the authenticated agent identity from a verified
// client certificate.
func AgentIDFromCert(cert *x509.Certificate) string {
	return cert.Subject.CommonName
}

// --- helpers ---

// newSerial draws a 128-bit random serial. Sequential serials leak how many
// agents exist and how fast they are enrolled.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}

func parseCertKey(certPEM, keyPEM []byte) (*x509.Certificate, ed25519.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("certificate file is not valid PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("key file is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("expected an Ed25519 private key, got %T", parsed)
	}
	if !cert.PublicKey.(crypto.PublicKey).(ed25519.PublicKey).Equal(key.Public()) {
		return nil, nil, fmt.Errorf("certificate and private key do not match")
	}
	return cert, key, nil
}

// writeSecret writes private key material with owner-only permissions, using a
// temp file and rename so a crash mid-write cannot leave a truncated key.
func writeSecret(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// splitNames sorts a name list into DNS names and IP SANs.
func splitNames(names []string) ([]string, []net.IP) {
	var dns []string
	var ips []net.IP
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	if len(dns) == 0 && len(ips) == 0 {
		dns = append(dns, "localhost")
		ips = append(ips, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
	}
	return dns, ips
}

// coversNames reports whether an existing certificate already covers every
// requested name, so the hub only reissues when something actually changed.
func coversNames(cert *x509.Certificate, names []string) bool {
	want, wantIPs := splitNames(names)
	for _, n := range want {
		found := false
		for _, have := range cert.DNSNames {
			if strings.EqualFold(have, n) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, ip := range wantIPs {
		found := false
		for _, have := range cert.IPAddresses {
			if have.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
