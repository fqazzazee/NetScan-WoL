package hub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

// fakeAgent stands in for a real agent: it polls, receives, and answers.
func fakeAgent(t *testing.T, r *Registry, agentID string, reply func(*protocol.Command) *protocol.CommandResult) func() {
	t.Helper()
	inbox, release := r.Connect(agentID)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case cmd := <-inbox:
				if cmd == nil {
					return
				}
				res := reply(cmd)
				res.CommandID = cmd.ID
				res.AgentID = agentID
				r.Deliver(res)
			case <-done:
				return
			}
		}
	}()
	return func() { release() }
}

func TestDispatchRoundTrip(t *testing.T) {
	r := NewRegistry()
	release := fakeAgent(t, r, "agent-1", func(cmd *protocol.Command) *protocol.CommandResult {
		return &protocol.CommandResult{OK: true, Type: cmd.Type}
	})
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := r.Dispatch(ctx, "agent-1", &protocol.Command{Type: protocol.CmdPing})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !res.OK {
		t.Error("result was not OK")
	}
	if res.Type != protocol.CmdPing {
		t.Errorf("result type = %s, want ping", res.Type)
	}
}

func TestDispatchToUnknownAgent(t *testing.T) {
	r := NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := r.Dispatch(ctx, "nobody", &protocol.Command{Type: protocol.CmdPing}); err == nil {
		t.Fatal("dispatching to an unconnected agent succeeded")
	}
}

// TestDispatchTimesOut proves an unanswered command cannot park an HTTP
// handler forever.
func TestDispatchTimesOut(t *testing.T) {
	r := NewRegistry()
	// Connect without ever reading the inbox: the agent is present but mute.
	r.Connect("silent")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := r.Dispatch(ctx, "silent", &protocol.Command{Type: protocol.CmdPing}); err == nil {
		t.Fatal("a command that was never answered returned successfully")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Dispatch took %s to give up; the context deadline is not being honoured", elapsed)
	}
}

// TestDeliverRejectsForeignResults covers result injection: an agent must not
// be able to answer a command that was issued to a different agent.
func TestDeliverRejectsForeignResults(t *testing.T) {
	r := NewRegistry()
	r.Connect("agent-1")
	r.Connect("agent-2")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Issued to agent-1 and never legitimately answered.
		r.Dispatch(ctx, "agent-1", &protocol.Command{ID: "cmd-1", Type: protocol.CmdPing})
	}()

	time.Sleep(50 * time.Millisecond)
	err := r.Deliver(&protocol.CommandResult{CommandID: "cmd-1", AgentID: "agent-2", OK: true})
	if err == nil {
		t.Error("agent-2 was allowed to answer a command issued to agent-1")
	}
	wg.Wait()
}

func TestDeliverWithoutWaiter(t *testing.T) {
	r := NewRegistry()
	if err := r.Deliver(&protocol.CommandResult{CommandID: "never-issued", AgentID: "a"}); err == nil {
		t.Error("delivering a result nobody asked for was accepted")
	}
}

// TestInboxSurvivesBetweenPolls is the regression test for agents appearing to
// flap. The inbox must outlive a single poll, or a command issued while the
// agent is busy would be rejected as "not connected".
func TestInboxSurvivesBetweenPolls(t *testing.T) {
	r := NewRegistry()

	inbox, release := r.Connect("agent-1")
	release() // the poll returned; the agent is about to poll again
	if !r.Connected("agent-1") {
		t.Fatal("the agent was reported offline between two polls")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go func() {
		time.Sleep(30 * time.Millisecond)
		cmd := <-inbox
		r.Deliver(&protocol.CommandResult{CommandID: cmd.ID, AgentID: "agent-1", OK: true})
	}()

	if _, err := r.Dispatch(ctx, "agent-1", &protocol.Command{Type: protocol.CmdPing}); err != nil {
		t.Fatalf("a command issued between polls failed: %v", err)
	}

	// The same inbox must come back on the next poll.
	again, release2 := r.Connect("agent-1")
	defer release2()
	if again != inbox {
		t.Error("reconnecting produced a different inbox; queued commands would be lost")
	}
}

func TestDisconnectRemovesAgent(t *testing.T) {
	r := NewRegistry()
	r.Connect("agent-1")
	if !r.Connected("agent-1") {
		t.Fatal("agent is not connected after Connect")
	}
	r.Disconnect("agent-1")
	if r.Connected("agent-1") {
		t.Error("agent is still connected after Disconnect")
	}
}

// TestInboxOverflowIsReported keeps a backlog from silently swallowing work.
func TestInboxOverflowIsReported(t *testing.T) {
	r := NewRegistry()
	r.Connect("busy") // nothing ever reads

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var lastErr error
	for i := 0; i < inboxDepth+4; i++ {
		go r.Dispatch(context.Background(), "busy", &protocol.Command{Type: protocol.CmdPing})
	}
	time.Sleep(50 * time.Millisecond)
	_, lastErr = r.Dispatch(ctx, "busy", &protocol.Command{Type: protocol.CmdPing})
	if lastErr == nil {
		t.Error("dispatching past the inbox depth succeeded silently")
	}
}

func TestNewIDIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 32 {
			t.Fatalf("id is %d characters, want 32 (128 bits of hex)", len(id))
		}
		if seen[id] {
			t.Fatal("NewID returned a duplicate")
		}
		seen[id] = true
	}
}

func TestValidateSubnet(t *testing.T) {
	if err := validateSubnet("10.0.0.0/24"); err != nil {
		t.Errorf("a /24 was rejected: %v", err)
	}
	// Anything bigger than a /18 is refused, so a mistyped prefix cannot turn
	// into a flood of ARP probes.
	if err := validateSubnet("10.0.0.0/8"); err == nil {
		t.Error("a /8 was accepted for scanning")
	}
	if err := validateSubnet("not-a-cidr"); err == nil {
		t.Error("a malformed CIDR was accepted")
	}
	if err := validateSubnet("2001:db8::/64"); err == nil {
		t.Error("an IPv6 prefix was accepted; ARP is IPv4 only")
	}
}
