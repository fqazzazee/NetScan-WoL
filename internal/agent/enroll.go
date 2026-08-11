package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/ca"
	"github.com/fqazzazee/netscan-wol/internal/netutil"
	"github.com/fqazzazee/netscan-wol/internal/protocol"
	"github.com/fqazzazee/netscan-wol/internal/scan"
	"github.com/fqazzazee/netscan-wol/internal/token"
)

// Version is stamped at build time via -ldflags; the default marks a
// development build.
var Version = "2.0.0-dev"

// EnrollOptions describes a join request.
type EnrollOptions struct {
	HubURL   string
	Token    string
	Name     string
	CAPin    string
	StateDir string
	// Force re-enrolls over an existing identity.
	Force bool
	// Labels are arbitrary key=value tags shown in the hub UI.
	Labels map[string]string
}

// Enroll exchanges a shared secret for a client certificate.
//
// The trust problem this has to solve: the agent has never spoken to the hub,
// so it has no CA to verify the hub's certificate against. With --ca-pin the
// operator carries the hub's CA fingerprint over from the hub UI and the
// certificate is checked against it before the token is ever transmitted.
// Without a pin the agent falls back to trust-on-first-use and says so loudly,
// because in that window an attacker positioned in the path could impersonate
// the hub and capture the enrollment token.
func Enroll(ctx context.Context, opt EnrollOptions) (*Identity, error) {
	if !token.Valid(opt.Token) {
		return nil, fmt.Errorf("the enrollment token must be %d hex characters", token.Chars)
	}
	hubURL := strings.TrimRight(strings.TrimSpace(opt.HubURL), "/")
	if hubURL == "" {
		return nil, fmt.Errorf("a hub URL is required")
	}
	if !strings.HasPrefix(hubURL, "https://") && !strings.HasPrefix(hubURL, "http://") {
		hubURL = "https://" + hubURL
	}

	stateDir := opt.StateDir
	if stateDir == "" {
		stateDir = DefaultStateDir()
	}
	if !opt.Force {
		if _, err := os.Stat(PathsIn(stateDir).Identity); err == nil {
			return nil, fmt.Errorf("this agent is already enrolled (%s); pass --force to replace that identity", stateDir)
		}
	}

	name := strings.TrimSpace(opt.Name)
	if name == "" {
		name, _ = os.Hostname()
	}
	if name == "" {
		name = "agent"
	}

	keyPEM, csrPEM, err := ca.NewAgentKeyAndCSR(name)
	if err != nil {
		return nil, err
	}

	hello := BuildHello(name, opt.Labels)
	body, err := json.Marshal(protocol.EnrollRequest{
		Token:  token.Normalize(opt.Token),
		CSRPEM: string(csrPEM),
		Hello:  hello,
	})
	if err != nil {
		return nil, fmt.Errorf("encode enrollment request: %w", err)
	}

	client := enrollClient(opt.CAPin)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hubURL+protocol.PathEnroll, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contact hub at %s: %w", hubURL, err)
	}
	defer res.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read hub response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		var apiErr protocol.Error
		if json.Unmarshal(payload, &apiErr) == nil && apiErr.Error != "" {
			return nil, fmt.Errorf("hub refused enrollment: %s", apiErr.Error)
		}
		return nil, fmt.Errorf("hub refused enrollment with status %d", res.StatusCode)
	}

	var enrolled protocol.EnrollResponse
	if err := json.Unmarshal(payload, &enrolled); err != nil {
		return nil, fmt.Errorf("parse hub response: %w", err)
	}
	if enrolled.Protocol != "" && enrolled.Protocol != protocol.Version {
		return nil, fmt.Errorf("hub speaks protocol %s but this agent speaks %s", enrolled.Protocol, protocol.Version)
	}
	if enrolled.CertPEM == "" || enrolled.CAPEM == "" {
		return nil, fmt.Errorf("hub returned an incomplete enrollment response")
	}

	// The CA the hub just handed us must be the one we verified the connection
	// against. Without this check a hub that passed the pin could still hand
	// back a different CA for future connections.
	gotPin, err := ca.FingerprintPEM([]byte(enrolled.CAPEM))
	if err != nil {
		return nil, fmt.Errorf("hub returned an unreadable CA certificate: %w", err)
	}
	if opt.CAPin != "" && !pinsEqual(opt.CAPin, gotPin) {
		return nil, fmt.Errorf("hub returned CA %s but the pin required %s; refusing to enroll", gotPin, opt.CAPin)
	}

	id := &Identity{
		HubURL:     hubURL,
		AgentID:    enrolled.AgentID,
		Name:       name,
		CAPin:      gotPin,
		HubName:    enrolled.HubName,
		EnrolledAt: time.Now(),
	}
	if err := SaveIdentity(stateDir, id, keyPEM, []byte(enrolled.CertPEM), []byte(enrolled.CAPEM)); err != nil {
		return nil, err
	}
	return id, nil
}

// enrollClient builds the one-shot HTTP client used for enrollment.
//
// It deliberately does not use the system trust store: the hub's certificate
// is issued by its own private CA, so the only meaningful check is against the
// pin the operator supplied.
func enrollClient(pin string) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is done by hand in VerifyPeerCertificate below, so the
		// default chain-building against the system roots is switched off. It
		// would always fail for a private CA.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("hub presented no certificate")
			}
			// The pin covers the CA, which is the last certificate in the
			// chain the hub sends, or the leaf itself if it sent only one.
			if pin == "" {
				return nil // trust-on-first-use; the caller warns about it
			}
			for _, raw := range rawCerts {
				sum := sha256.Sum256(raw)
				if pinsEqual(pin, "sha256:"+hex.EncodeToString(sum[:])) {
					return nil
				}
			}
			return fmt.Errorf("no certificate in the hub's chain matches the pin %s", pin)
		},
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// pinsEqual compares fingerprints tolerantly: with or without the "sha256:"
// prefix, and in either case.
func pinsEqual(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "sha256:")
		return strings.ReplaceAll(s, ":", "")
	}
	return norm(a) != "" && norm(a) == norm(b)
}

// BuildHello assembles the agent's self-description.
func BuildHello(name string, labels map[string]string) protocol.AgentHello {
	hostname, _ := os.Hostname()
	interfaces, err := netutil.Interfaces()
	if err != nil {
		interfaces = nil
	}
	return protocol.AgentHello{
		Name:         name,
		Version:      Version,
		Protocol:     protocol.Version,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Hostname:     hostname,
		Platform:     DetectPlatform(),
		Capabilities: scan.Capabilities(),
		Interfaces:   interfaces,
		Labels:       labels,
	}
}
