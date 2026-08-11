// Command nswhub runs the NetScan-WoL Command Hub: the web interface,
// the agent API, and the certificate authority that ties them together.
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
	"time"

	"github.com/fqazzazee/netscan-wol/internal/hub"
	"github.com/fqazzazee/netscan-wol/internal/store"
)

// Version is stamped at build time with -ldflags.
var Version = "2.0.0-dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "nswhub: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen      = flag.String("listen", ":8443", "address for the operator web interface")
		agentListen = flag.String("agent-listen", "", "optional separate address for the agent API; empty serves both on -listen")
		dataDir     = flag.String("data", defaultDataDir(), "directory for state, the CA and the audit log")
		names       = flag.String("names", "", "comma-separated DNS names and IPs for the hub's TLS certificate")
		insecure    = flag.Bool("insecure", false, "serve plain HTTP (only behind a TLS-terminating proxy you control)")
		trustProxy  = flag.Bool("trust-proxy-headers", false, "trust X-Forwarded-For for client addresses")
		logLevel    = flag.String("log-level", "info", "debug, info, warn or error")
		showVersion = flag.Bool("version", false, "print the version and exit")
		printPin    = flag.Bool("print-pin", false, "print the CA fingerprint agents should pin, then exit")
		resetPass   = flag.String("reset-password", "", "reset the named operator's password and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("nswhub %s\n", Version)
		return nil
	}

	logger := newLogger(*logLevel)
	slog.SetDefault(logger)

	cfg := hub.Config{
		Listen:            *listen,
		AgentListen:       *agentListen,
		DataDir:           *dataDir,
		Names:             certNames(*names, *listen),
		Insecure:          *insecure,
		TrustProxyHeaders: *trustProxy,
		Logger:            logger,
	}

	server, err := hub.New(cfg)
	if err != nil {
		return err
	}

	if *printPin {
		fmt.Println(server.CA().Fingerprint())
		return nil
	}
	if *resetPass != "" {
		return resetPassword(server, *resetPass)
	}

	if err := bootstrapOperator(server); err != nil {
		return err
	}

	errs, err := server.Start()
	if err != nil {
		return err
	}

	scheme := "https"
	if *insecure {
		scheme = "http"
	}
	logger.Info("command hub ready",
		"version", Version,
		"url", fmt.Sprintf("%s://%s", scheme, displayAddr(*listen)),
		"data", *dataDir)
	if *agentListen != "" {
		logger.Info("agent API on its own listener", "address", *agentListen)
	}
	logger.Info("agents should pin this CA fingerprint", "pin", server.CA().Fingerprint())

	// Wait for a shutdown signal or a listener failure, whichever comes first.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stop:
		logger.Info("shutting down", "signal", sig.String())
	case err := <-errs:
		if err != nil {
			return fmt.Errorf("listener stopped: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}

// bootstrapOperator creates the first login on a fresh hub and prints the
// generated password once. It is marked must-change so the UI insists on a real
// password before anything else can be done.
func bootstrapOperator(server *hub.Server) error {
	st := server.Store()
	if st.OperatorCount() > 0 {
		return nil
	}

	password, err := store.GeneratePassword()
	if err != nil {
		return err
	}
	op, err := store.NewOperator("admin", password)
	if err != nil {
		return err
	}
	op.MustChangePassword = true
	if err := st.PutOperator(op); err != nil {
		return err
	}

	// Printed to stderr, not the log, so it is not swept into a log
	// aggregator along with everything else.
	fmt.Fprintf(os.Stderr, `
╭──────────────────────────────────────────────────────────────╮
│  NetScan-WoL Command Hub — first start                       │
│                                                              │
│  Username:  admin                                            │
│  Password:  %-48s │
│                                                              │
│  This password is shown once and must be changed at first    │
│  sign-in. It is stored only as a PBKDF2 hash.                │
╰──────────────────────────────────────────────────────────────╯

`, password)
	return nil
}

// resetPassword sets a fresh generated password for an existing operator, for
// when someone is locked out.
func resetPassword(server *hub.Server, username string) error {
	st := server.Store()
	op, ok := st.Operator(username)
	if !ok {
		return fmt.Errorf("no operator named %q", username)
	}
	password, err := store.GeneratePassword()
	if err != nil {
		return err
	}
	if err := store.SetPassword(op, password); err != nil {
		return err
	}
	op.MustChangePassword = true
	if err := st.PutOperator(op); err != nil {
		return err
	}
	fmt.Printf("New password for %s: %s\n", username, password)
	fmt.Println("It must be changed at the next sign-in.")
	return nil
}

// certNames assembles the SAN list for the hub certificate: whatever the
// operator supplied, plus the listen host and the loopback names that make a
// local browser work without a warning.
func certNames(names, listen string) []string {
	var out []string
	for _, n := range strings.Split(names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	if host, _, ok := strings.Cut(strings.TrimPrefix(listen, "["), "]:"); ok && host != "" {
		out = append(out, host)
	} else if h, _, ok := strings.Cut(listen, ":"); ok && h != "" && h != "0.0.0.0" {
		out = append(out, h)
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		out = append(out, hostname)
	}
	return append(out, "localhost", "127.0.0.1", "::1")
}

// displayAddr turns a wildcard listen address into something clickable.
func displayAddr(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "localhost" + listen
	}
	return listen
}

func defaultDataDir() string {
	if dir := os.Getenv("NSWHUB_DATA"); dir != "" {
		return dir
	}
	if os.Geteuid() == 0 {
		return "/var/lib/netscan-wol/hub"
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home + "/.netscan-wol/hub"
	}
	return "./nswhub-data"
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
	fmt.Fprintf(os.Stderr, `nswhub %s — NetScan-WoL Command Hub

Usage:
  nswhub [options]

The hub serves the operator web interface and the agent API, and runs the
certificate authority that issues each agent its identity. On first start it
creates the CA, generates an admin password, and prints both.

Options:
`, Version)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
Examples:
  # First run, reachable at https://hub.example.com:8443
  nswhub --names hub.example.com

  # Split the agent plane onto its own port so it can be firewalled separately
  nswhub --names hub.example.com --agent-listen :8444

  # Behind an ingress or reverse proxy that terminates TLS
  nswhub --insecure --listen 127.0.0.1:8080 --trust-proxy-headers

  # Recover a locked-out account
  nswhub --reset-password admin
`)
}
