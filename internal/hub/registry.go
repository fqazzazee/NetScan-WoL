package hub

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

// Registry routes commands to connected agents.
//
// Agents dial out and hold a long poll open, so the hub never needs to reach
// an agent's address. That is what makes the same agent binary work behind
// NAT, inside a Kubernetes pod, and in an LXC container with no inbound
// firewall rule — the only requirement is that the agent can reach the hub.
//
// Each agent gets one inbox channel. A waiting poll takes from the inbox; a
// command issued while nothing is polling waits in the buffer until the agent
// comes back.
type Registry struct {
	mu      sync.Mutex
	agents  map[string]*agentChannel
	pending map[string]*pendingCommand
}

// inboxDepth bounds queued commands per agent. An agent that has been offline
// for an hour should not come back to a thousand stale scan requests, so the
// queue is short and overflow is reported to the caller immediately.
const inboxDepth = 16

// agentChannel is an agent's persistent command inbox.
//
// It deliberately outlives any single poll request. An agent that has just
// been handed a command is briefly not polling while it runs it, and if the
// inbox were torn down between polls the agent would flicker between
// "connected" and "offline" in the UI and any command issued in that gap would
// be rejected. Liveness is judged from lastPoll instead.
type agentChannel struct {
	inbox    chan *protocol.Command
	lastPoll time.Time
}

// pendingCommand is a dispatched command whose result has not arrived yet.
type pendingCommand struct {
	agentID string
	result  chan *protocol.CommandResult
	issued  time.Time
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		agents:  make(map[string]*agentChannel),
		pending: make(map[string]*pendingCommand),
	}
}

// Dispatch sends a command to an agent and waits for its result.
//
// The caller's context bounds the wait, so an HTTP request that is abandoned by
// the browser does not leave a goroutine parked forever.
func (r *Registry) Dispatch(ctx context.Context, agentID string, cmd *protocol.Command) (*protocol.CommandResult, error) {
	if cmd.ID == "" {
		id, err := NewID()
		if err != nil {
			return nil, err
		}
		cmd.ID = id
	}
	cmd.IssuedAt = time.Now()

	pending := &pendingCommand{
		agentID: agentID,
		// Buffered so the agent's result POST never blocks, even if the
		// dispatcher has already given up and walked away.
		result: make(chan *protocol.CommandResult, 1),
		issued: cmd.IssuedAt,
	}

	// The enqueue happens under the same lock that guards the agent map. The
	// send is non-blocking, so holding the lock costs nothing, and it is what
	// makes a simultaneous reconnect safe: Connect can swap the inbox knowing
	// no sender is mid-flight on the old one.
	r.mu.Lock()
	if !r.aliveLocked(agentID) {
		r.mu.Unlock()
		return nil, fmt.Errorf("agent %s is not connected", agentID)
	}
	ch := r.agents[agentID]
	select {
	case ch.inbox <- cmd:
	default:
		r.mu.Unlock()
		return nil, fmt.Errorf("agent %s has %d commands already queued; wait for it to catch up", agentID, inboxDepth)
	}
	r.pending[cmd.ID] = pending
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.pending, cmd.ID)
		r.mu.Unlock()
	}()

	select {
	case res := <-pending.result:
		return res, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("agent %s did not answer in time: %w", agentID, ctx.Err())
	}
}

// Connect marks an agent as actively polling and returns its inbox along with
// a function to call when the poll ends.
//
// The same inbox is returned across polls, so a command queued while the agent
// was busy is still waiting when it comes back.
func (r *Registry) Connect(agentID string) (<-chan *protocol.Command, func()) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ch, ok := r.agents[agentID]
	if !ok {
		ch = &agentChannel{inbox: make(chan *protocol.Command, inboxDepth)}
		r.agents[agentID] = ch
	}
	ch.lastPoll = time.Now()

	return ch.inbox, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		// Record when the poll ended rather than removing the entry: the agent
		// is about to poll again, and the connection is judged stale only if it
		// does not.
		if current, ok := r.agents[agentID]; ok && current == ch {
			current.lastPoll = time.Now()
		}
	}
}

// connectionTTL is how long after its last poll an agent is still treated as
// connected. Generous enough to cover a long scan plus the reconnect, short
// enough that a killed agent stops accepting commands promptly.
const connectionTTL = 3 * time.Minute

// Connected reports whether an agent has polled recently enough to be given
// work. It also reaps entries that have gone quiet, which is why it takes the
// write lock.
func (r *Registry) Connected(agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aliveLocked(agentID)
}

func (r *Registry) aliveLocked(agentID string) bool {
	ch, ok := r.agents[agentID]
	if !ok {
		return false
	}
	if time.Since(ch.lastPoll) > connectionTTL {
		delete(r.agents, agentID)
		return false
	}
	return true
}

// Disconnect drops an agent's inbox outright, used when an agent is removed or
// disabled so queued work does not linger.
func (r *Registry) Disconnect(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agents, agentID)
}

// Deliver hands a result back to whoever is waiting for it.
func (r *Registry) Deliver(res *protocol.CommandResult) error {
	r.mu.Lock()
	pending, ok := r.pending[res.CommandID]
	r.mu.Unlock()
	if !ok {
		// The waiter timed out, or the result is a replay. Either way there is
		// nobody to hand it to; say so rather than failing silently.
		return fmt.Errorf("no request is waiting for command %s", res.CommandID)
	}
	if pending.agentID != res.AgentID {
		// An agent answering a command issued to a different agent is either a
		// bug or an attempt to inject results; refuse it.
		return fmt.Errorf("command %s was issued to a different agent", res.CommandID)
	}
	select {
	case pending.result <- res:
	default:
	}
	return nil
}

// ConnectedIDs lists every agent currently considered connected.
func (r *Registry) ConnectedIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.agents))
	for id := range r.agents {
		if r.aliveLocked(id) {
			out = append(out, id)
		}
	}
	return out
}

// NewID returns a 128-bit random identifier rendered as hex, used for agent
// IDs, command IDs and scan record IDs.
func NewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate identifier: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
