// Command nswagent is the NetScan-WoL remote agent. It enrolls with a command
// hub, holds a connection open, and carries out ARP scans and Wake-on-LAN
// requests on the broadcast domain it is attached to.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fqazzazee/netscan-wol/internal/agent"
	"github.com/fqazzazee/netscan-wol/internal/netutil"
	"github.com/fqazzazee/netscan-wol/internal/scan"
)

var Version = "2.0.0-dev"

func main() {
	agent.Version = Version
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "nswagent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return fmt.Errorf("a subcommand is required")
	}

	switch os.Args[1] {
	case "enroll":
		return cmdEnroll(os.Args[2:])
	case "run":
		return cmdRun(os.Args[2:])
	case "status":
		return cmdStatus(os.Args[2:])
	case "interfaces":
		return cmdInterfaces(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("nswagent %s\n", Version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
}

// cmdEnroll exchanges an enrollment token for a client certificate.
func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	hubURL := fs.String("hub", "", "hub URL, e.g. https://hub.example.com:8443")
	tok := fs.String("token", "", "64-character enrollment token from the hub UI")
	tokenFile := fs.String("token-file", "", "read the token from a file instead of the command line")
	name := fs.String("name", "", "display name for this agent (defaults to the hostname)")
	pin := fs.String("ca-pin", "", "expected hub CA fingerprint, sha256:...")
	stateDir := fs.String("state", agent.DefaultStateDir(), "directory for this agent's key and certificate")
	force := fs.Bool("force", false, "replace an existing enrollment")
	labels := fs.String("labels", "", "comma-separated key=value tags, e.g. site=hq,rack=3")
	if err := fs.Parse(args); err != nil {
		return err
	}

	secret := strings.TrimSpace(*tok)
	if *tokenFile != "" {
		// Reading from a file keeps the token out of the process list and the
		// shell history, which matters on a shared box.
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		secret = strings.TrimSpace(string(data))
	}
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("NSWAGENT_TOKEN"))
	}
	if *hubURL == "" || secret == "" {
		return fmt.Errorf("both --hub and a token are required (use --token, --token-file, or NSWAGENT_TOKEN)")
	}

	if *pin == "" {
		fmt.Fprintln(os.Stderr,
			"warning: no --ca-pin given. The hub's certificate will be accepted on first contact\n"+
				"         without verification. Anyone able to intercept this connection could\n"+
				"         impersonate the hub and capture the enrollment token. The hub UI shows\n"+
				"         the pin next to every token it issues.")
	}

	id, err := agent.Enroll(context.Background(), agent.EnrollOptions{
		HubURL:   *hubURL,
		Token:    secret,
		Name:     *name,
		CAPin:    *pin,
		StateDir: *stateDir,
		Force:    *force,
		Labels:   parseLabels(*labels),
	})
	if err != nil {
		return err
	}

	fmt.Printf("Enrolled with %s\n", id.HubName)
	fmt.Printf("  agent id:  %s\n", id.AgentID)
	fmt.Printf("  name:      %s\n", id.Name)
	fmt.Printf("  hub:       %s\n", id.HubURL)
	fmt.Printf("  CA pin:    %s\n", id.CAPin)
	fmt.Printf("  state:     %s\n", *stateDir)
	fmt.Println("\nStart the agent with:  nswagent run")
	return nil
}

// cmdRun starts the agent loop.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state", agent.DefaultStateDir(), "directory holding this agent's key and certificate")
	logLevel := fs.String("log-level", "info", "debug, info, warn or error")
	labels := fs.String("labels", "", "comma-separated key=value tags")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := newLogger(*logLevel)
	slog.SetDefault(logger)

	a, err := agent.New(*stateDir, parseLabels(*labels), logger)
	if err != nil {
		return err
	}

	warnAboutCapabilities(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return a.Run(ctx)
}

// cmdStatus prints what this agent knows about itself without contacting the
// hub, which is the first thing to check when an agent will not connect.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	stateDir := fs.String("state", agent.DefaultStateDir(), "agent state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	id, err := agent.LoadIdentity(*stateDir)
	if err != nil {
		return err
	}
	fmt.Printf("name:       %s\n", id.Name)
	fmt.Printf("agent id:   %s\n", id.AgentID)
	fmt.Printf("hub:        %s (%s)\n", id.HubURL, id.HubName)
	fmt.Printf("CA pin:     %s\n", id.CAPin)
	fmt.Printf("enrolled:   %s\n", id.EnrolledAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("platform:   %s\n", agent.DetectPlatform())
	fmt.Printf("caps:       %s\n", strings.Join(scan.Capabilities(), ", "))
	return nil
}

// cmdInterfaces shows what the agent can scan, and explains every interface it
// has ruled out.
func cmdInterfaces(args []string) error {
	fs := flag.NewFlagSet("interfaces", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	interfaces, err := netutil.Interfaces()
	if err != nil {
		return err
	}
	for _, ifi := range interfaces {
		mark := "  "
		note := ifi.Skip
		if ifi.Eligible {
			mark = "✓ "
			note = strings.Join(ifi.Subnets, ", ")
		}
		fmt.Printf("%s%-14s %-18s %s\n", mark, ifi.Name, ifi.MAC, note)
	}
	fmt.Println("\n✓ marks interfaces that can carry an ARP scan.")
	return nil
}

// warnAboutCapabilities explains a degraded setup at startup rather than
// letting the operator discover it as mysteriously empty scan results.
func warnAboutCapabilities(logger *slog.Logger) {
	caps := scan.Capabilities()
	hasRaw := false
	for _, c := range caps {
		if c == "arp-raw" {
			hasRaw = true
		}
	}
	if !hasRaw {
		logger.Warn("no raw socket access, so ARP scanning is unavailable",
			"effect", "scans fall back to arp-scan if installed, otherwise to the kernel neighbour table, which only reports hosts this machine has recently talked to",
			"fix", "grant CAP_NET_RAW: setcap cap_net_raw+ep /usr/local/bin/nswagent, or run the container with --cap-add=NET_RAW")
	}

	eligible, err := netutil.EligibleInterfaces()
	if err == nil && len(eligible) == 0 {
		logger.Warn("no interface can be scanned",
			"effect", "every link is loopback, down, or has no IPv4 address",
			"fix", "in a container, use host networking or a macvlan so the agent sees the real segment")
	}
}

// parseLabels turns "site=hq,rack=3" into a map, ignoring malformed entries.
func parseLabels(s string) map[string]string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(pair, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if ok && k != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func usage() {
	fmt.Fprintf(os.Stderr, `nswagent %s — NetScan-WoL remote agent

Usage:
  nswagent <command> [options]

Commands:
  enroll        Join a hub using an enrollment token
  run           Connect to the hub and serve commands
  status        Show this agent's identity and capabilities
  interfaces    List interfaces and which ones can be scanned
  version       Print the version

The agent dials out to the hub, so no inbound firewall rule is needed on the
network it lives on. It needs CAP_NET_RAW for ARP scanning; without it, scans
degrade to the kernel neighbour table.

Examples:
  nswagent enroll --hub https://hub.example.com:8443 \
    --token 8f3c... --ca-pin sha256:1a2b...
  nswagent run
  nswagent interfaces

Run "nswagent <command> --help" for the options of a single command.
`, Version)
}
