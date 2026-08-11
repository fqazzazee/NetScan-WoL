package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/netutil"
	"github.com/fqazzazee/netscan-wol/internal/protocol"
	"github.com/fqazzazee/netscan-wol/internal/scan"
	"github.com/fqazzazee/netscan-wol/internal/wol"
)

// Agent is a running remote agent.
type Agent struct {
	id       *Identity
	client   *http.Client
	scanner  *scan.Scanner
	log      *slog.Logger
	labels   map[string]string
	stateDir string
}

// Reconnect backoff. The floor is short so a hub restart is barely noticed;
// the ceiling keeps a long outage from turning a fleet of agents into a
// thundering herd against the hub as it comes back.
const (
	minBackoff = 2 * time.Second
	maxBackoff = 60 * time.Second
	// pollTimeout must exceed the hub's poll hold, or every long poll would be
	// cancelled client-side just before the hub gives up on it.
	pollTimeout = 60 * time.Second
	// commandBudget bounds a single command's execution regardless of what the
	// hub asked for.
	commandBudget = 10 * time.Minute
)

// New builds an agent from an enrolled state directory.
func New(stateDir string, labels map[string]string, log *slog.Logger) (*Agent, error) {
	if log == nil {
		log = slog.Default()
	}
	id, err := LoadIdentity(stateDir)
	if err != nil {
		return nil, err
	}
	client, err := mutualTLSClient(stateDir)
	if err != nil {
		return nil, err
	}
	return &Agent{
		id:       id,
		client:   client,
		scanner:  scan.NewScanner(),
		log:      log,
		labels:   labels,
		stateDir: stateDir,
	}, nil
}

// Identity exposes the loaded identity for status output.
func (a *Agent) Identity() *Identity { return a.id }

// mutualTLSClient builds the HTTP client used for every call after
// enrollment: the hub is verified against the CA received at enrollment, and
// the agent proves itself with the certificate the hub issued.
func mutualTLSClient(stateDir string) (*http.Client, error) {
	p := PathsIn(stateDir)

	cert, err := tls.LoadX509KeyPair(p.Cert, p.Key)
	if err != nil {
		return nil, fmt.Errorf("load agent certificate: %w", err)
	}
	caPEM, err := os.ReadFile(p.CA)
	if err != nil {
		return nil, fmt.Errorf("read hub CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s contains no usable certificate", p.CA)
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS12,
			},
			// One connection is reused for the long poll; keeping it alive
			// avoids a TLS handshake every 25 seconds per agent.
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     90 * time.Second,
		},
	}, nil
}

// Run connects to the hub and serves commands until the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("agent starting",
		"name", a.id.Name, "hub", a.id.HubURL, "id", a.id.AgentID,
		"platform", DetectPlatform(), "version", Version)

	backoff := minBackoff
	greeted := false

	for {
		if ctx.Err() != nil {
			return nil
		}

		if !greeted {
			if err := a.hello(ctx); err != nil {
				a.log.Warn("cannot reach hub", "error", err, "retry_in", backoff)
				if !sleepCtx(ctx, backoff) {
					return nil
				}
				backoff = nextBackoff(backoff)
				continue
			}
			greeted = true
			backoff = minBackoff
			a.log.Info("connected to hub", "hub_name", a.id.HubName)
		}

		cmd, err := a.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			a.log.Warn("poll failed", "error", err, "retry_in", backoff)
			// A failed poll may mean the hub restarted, so re-greet on the next
			// pass to refresh the topology it holds for us.
			greeted = false
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = minBackoff
		if cmd == nil {
			continue // nothing queued; poll again
		}

		// Commands run on their own goroutine so a slow scan does not stall
		// the poll loop and make the agent look disconnected.
		go a.execute(ctx, cmd)
	}
}

// hello announces the agent and refreshes what the hub knows about it.
func (a *Agent) hello(ctx context.Context) error {
	body, err := json.Marshal(BuildHello(a.id.Name, a.labels))
	if err != nil {
		return fmt.Errorf("encode hello: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	res, err := a.do(ctx, http.MethodPost, protocol.PathAgentHello, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return a.responseError(res)
	}
	var hr protocol.HelloResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&hr); err != nil {
		return fmt.Errorf("parse hello response: %w", err)
	}
	if hr.HubName != "" {
		a.id.HubName = hr.HubName
	}
	return nil
}

// poll waits for a command. A nil command with a nil error means the hold
// expired with nothing queued, which is the normal idle case.
func (a *Agent) poll(ctx context.Context) (*protocol.Command, error) {
	ctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()

	res, err := a.do(ctx, http.MethodGet, protocol.PathAgentPoll, nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var cmd protocol.Command
		if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&cmd); err != nil {
			return nil, fmt.Errorf("parse command: %w", err)
		}
		return &cmd, nil
	default:
		return nil, a.responseError(res)
	}
}

// execute runs one command and posts the result back.
func (a *Agent) execute(ctx context.Context, cmd *protocol.Command) {
	ctx, cancel := context.WithTimeout(ctx, commandBudget)
	defer cancel()

	started := time.Now()
	result := &protocol.CommandResult{
		CommandID: cmd.ID,
		AgentID:   a.id.AgentID,
		Type:      cmd.Type,
		StartedAt: started,
	}

	err := a.run(ctx, cmd, result)
	result.FinishedAt = time.Now()
	if err != nil {
		result.OK = false
		result.Error = err.Error()
		a.log.Warn("command failed", "type", cmd.Type, "error", err)
	} else {
		result.OK = true
		a.log.Info("command done", "type", cmd.Type, "took", result.FinishedAt.Sub(started).Round(time.Millisecond))
	}

	if err := a.postResult(ctx, result); err != nil {
		a.log.Warn("could not return result to hub", "command", cmd.ID, "error", err)
	}
}

// run dispatches on command type.
func (a *Agent) run(ctx context.Context, cmd *protocol.Command, result *protocol.CommandResult) error {
	switch cmd.Type {
	case protocol.CmdScan:
		if cmd.Scan == nil {
			return fmt.Errorf("scan command carried no request")
		}
		res, err := a.scanner.Scan(ctx, *cmd.Scan)
		if err != nil {
			return err
		}
		result.Scan = res
		return nil

	case protocol.CmdWoL:
		if cmd.WoL == nil {
			return fmt.Errorf("wake command carried no request")
		}
		res, err := wol.Send(*cmd.WoL)
		if err != nil {
			return err
		}
		result.WoL = res
		return nil

	case protocol.CmdStatus:
		if cmd.Status == nil {
			return fmt.Errorf("status command carried no request")
		}
		res, err := a.scanner.Status(ctx, *cmd.Status)
		if err != nil {
			return err
		}
		result.Status = res
		return nil

	case protocol.CmdDiscover:
		interfaces, err := netutil.Interfaces()
		if err != nil {
			return err
		}
		result.Discover = &protocol.DiscoverResult{Interfaces: interfaces}
		return nil

	case protocol.CmdPing:
		return nil

	default:
		return fmt.Errorf("unknown command type %q; the hub may be newer than this agent", cmd.Type)
	}
}

func (a *Agent) postResult(ctx context.Context, result *protocol.CommandResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res, err := a.do(ctx, http.MethodPost, protocol.PathAgentResult, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	if res.StatusCode >= 300 {
		return fmt.Errorf("hub returned status %d", res.StatusCode)
	}
	return nil
}

// do issues one request to the hub.
func (a *Agent) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.id.HubURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "nswagent/"+Version)

	res, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	return res, nil
}

// responseError turns a non-2xx response into a useful message, preferring the
// hub's own explanation over a bare status code.
func (a *Agent) responseError(res *http.Response) error {
	payload, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	var apiErr protocol.Error
	if json.Unmarshal(payload, &apiErr) == nil && apiErr.Error != "" {
		return fmt.Errorf("hub returned %d: %s", res.StatusCode, apiErr.Error)
	}
	return fmt.Errorf("hub returned status %d", res.StatusCode)
}

// nextBackoff doubles the delay up to the ceiling.
func nextBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}

// sleepCtx waits for d, returning false if the context ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
