// Package agent implements the NetScan-WoL remote agent: the process that
// enrolls with a hub, holds a connection open, and executes scan and wake
// commands on its own broadcast domain.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Identity is what an enrolled agent keeps on disk.
type Identity struct {
	HubURL     string    `json:"hub_url"`
	AgentID    string    `json:"agent_id"`
	Name       string    `json:"name"`
	CAPin      string    `json:"ca_pin"`
	HubName    string    `json:"hub_name,omitempty"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// File names inside the agent's state directory.
const (
	identityFile = "agent.json"
	keyFile      = "agent.key"
	certFile     = "agent.crt"
	caFile       = "ca.crt"
)

// Paths bundles the on-disk locations of an agent's material.
type Paths struct {
	Dir      string
	Identity string
	Key      string
	Cert     string
	CA       string
}

// PathsIn resolves the file layout under a state directory.
func PathsIn(dir string) Paths {
	return Paths{
		Dir:      dir,
		Identity: filepath.Join(dir, identityFile),
		Key:      filepath.Join(dir, keyFile),
		Cert:     filepath.Join(dir, certFile),
		CA:       filepath.Join(dir, caFile),
	}
}

// LoadIdentity reads an enrolled agent's configuration.
func LoadIdentity(dir string) (*Identity, error) {
	p := PathsIn(dir)
	data, err := os.ReadFile(p.Identity)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("this agent is not enrolled: %s does not exist. Run `nswagent enroll` first", p.Identity)
		}
		return nil, fmt.Errorf("read agent identity: %w", err)
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p.Identity, err)
	}
	for _, required := range []string{p.Key, p.Cert, p.CA} {
		if _, err := os.Stat(required); err != nil {
			return nil, fmt.Errorf("agent state is incomplete: %s is missing; enroll again", required)
		}
	}
	return &id, nil
}

// SaveIdentity writes the agent's configuration and key material.
//
// The private key is written 0600 and the directory 0700: anything that can
// read agent.key can impersonate this agent to the hub, which means it can
// receive scan commands for the segment and send magic packets on it.
func SaveIdentity(dir string, id *Identity, keyPEM, certPEM, caPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create agent state directory: %w", err)
	}
	p := PathsIn(dir)

	if err := writeFileAtomic(p.Key, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(p.Cert, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(p.CA, caPEM, 0o644); err != nil {
		return err
	}

	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent identity: %w", err)
	}
	return writeFileAtomic(p.Identity, data, 0o600)
}

// writeFileAtomic writes through a temporary file and a rename, so an
// interrupted write cannot leave a half-written key behind.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// DefaultStateDir picks a sensible state directory: the system location when
// running as root, and a per-user directory otherwise, so the agent works
// unprivileged for testing without needing to be told where to put things.
func DefaultStateDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/netscan-wol/agent"
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".netscan-wol", "agent")
	}
	return "./nswagent-state"
}
