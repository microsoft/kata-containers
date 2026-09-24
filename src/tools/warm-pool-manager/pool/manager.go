// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kata-containers/kata-containers/src/tools/warm-pool-manager/cri"
)

// ErrNoMemberAvailable is returned by Claim when no free ready member exists.
var ErrNoMemberAvailable = errors.New("no warm member available")

// Manager maintains a pool of warm kata pod-sandbox members and serves claims.
// It is a pure control plane over containerd (a CRI client): it never spawns a
// VMM, it only calls RunPodSandbox ahead of demand and reconciles.
type Manager struct {
	cfg      *Config
	strategy Strategy

	mu        sync.Mutex
	members   map[string]*Member
	tempSeq   uint64
	reconcile chan struct{}
	closed    atomic.Bool
}

// New builds a manager for the given config, dialing the CRI endpoint.
func New(client *cri.Client, cfg Config) (*Manager, error) {
	cfg.withDefaults()

	strat, err := newStrategy(client, &cfg)
	if err != nil {
		return nil, err
	}

	return &Manager{
		cfg:       &cfg,
		strategy:  strat,
		members:   make(map[string]*Member),
		reconcile: make(chan struct{}, 1),
	}, nil
}

// Strategy returns the active strategy (for logging).
func (m *Manager) Strategy() Strategy { return m.strategy }

// Run drives the maintenance loop until ctx is cancelled. It reconciles to the
// target pool size on a ticker and whenever a claim triggers a backfill.
func (m *Manager) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.cfg.ReconcileInterval)
	defer ticker.Stop()

	m.reconcileOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			m.closed.Store(true)
			return ctx.Err()
		case <-ticker.C:
			m.reconcileOnce(ctx)
		case <-m.reconcile:
			m.reconcileOnce(ctx)
		}
	}
}

// signal asks the loop to reconcile soon (non-blocking).
func (m *Manager) signal() {
	select {
	case m.reconcile <- struct{}{}:
	default:
	}
}

// countTowardTarget returns members that count against the pool target: free
// members plus in-flight creations.
func (m *Manager) countTowardTarget() int {
	n := 0
	for _, mem := range m.members {
		if mem.State == StateFree || mem.State == StateCreating {
			n++
		}
	}
	return n
}

// reconcileOnce prunes dead/expired members, refreshes readiness, and grows the
// pool back to the target size.
func (m *Manager) reconcileOnce(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	// 1. Select free members to recycle (expired or unhealthy) and members to
	//    reap (failed). Flip them to draining under the lock so nobody claims.
	m.mu.Lock()
	now := time.Now()
	var toDestroy []*Member
	var toCheck []*Member
	for _, mem := range m.members {
		switch mem.State {
		case StateFree:
			if m.cfg.MemberTTL > 0 && !mem.ExpiresAt.IsZero() && now.After(mem.ExpiresAt) {
				mem.State = StateDraining
				toDestroy = append(toDestroy, mem)
			} else {
				toCheck = append(toCheck, mem)
			}
		case StateFailed:
			mem.State = StateDraining
			toDestroy = append(toDestroy, mem)
		}
	}
	m.mu.Unlock()

	// 2. Destroy outside the lock.
	for _, mem := range toDestroy {
		m.destroyMember(ctx, mem)
	}

	// 3. Refresh readiness of free members outside the lock.
	for _, mem := range toCheck {
		ready, err := m.strategy.Ready(ctx, mem)
		if err != nil {
			log.Printf("readiness check failed for %s: %v", mem.Name, err)
			m.mu.Lock()
			mem.State = StateFailed
			m.mu.Unlock()
			m.signal()
			continue
		}
		m.mu.Lock()
		mem.Ready = ready
		m.mu.Unlock()
	}

	// 4. Grow back to target.
	m.mu.Lock()
	deficit := m.cfg.PoolSize - m.countTowardTarget()
	m.mu.Unlock()
	for i := 0; i < deficit; i++ {
		go m.growOne(ctx)
	}
}

// growOne reserves a slot, creates a member, and records it (or drops the slot
// on failure). Runs concurrently; the reserved slot prevents over-creation.
func (m *Manager) growOne(ctx context.Context) {
	if m.closed.Load() || ctx.Err() != nil {
		return
	}

	m.mu.Lock()
	m.tempSeq++
	key := fmt.Sprintf("creating-%d", m.tempSeq)
	placeholder := &Member{State: StateCreating, key: key}
	m.members[key] = placeholder
	m.mu.Unlock()

	mem, err := m.strategy.CreateMember(ctx)

	m.mu.Lock()
	delete(m.members, key)
	if err != nil {
		m.mu.Unlock()
		log.Printf("create member failed: %v", err)
		m.signal()
		return
	}
	m.members[mem.key] = mem
	log.Printf("created member %s (%s)", mem.Name, mem.ID)
	m.mu.Unlock()

	// Kick a readiness refresh promptly.
	m.signal()
}

// destroyMember tears down a member and removes it from the registry.
func (m *Manager) destroyMember(ctx context.Context, mem *Member) {
	if err := m.strategy.Destroy(ctx, mem); err != nil {
		log.Printf("destroy member %s failed: %v", mem.Name, err)
	}
	m.mu.Lock()
	delete(m.members, mem.key)
	m.mu.Unlock()
	log.Printf("destroyed member %s", mem.Name)
}

// Claim hands out a free ready member, activates it (Tier A attach / Tier B
// wake), and triggers a backfill. selector (may be nil) restricts the choice to
// members whose labels contain every selector key/value. Returns
// ErrNoMemberAvailable if no matching ready member exists.
func (m *Manager) Claim(ctx context.Context, selector map[string]string) (*Member, error) {
	m.mu.Lock()
	var chosen *Member
	for _, mem := range m.members {
		if mem.State == StateFree && mem.Ready && labelsMatch(mem.Labels, selector) {
			chosen = mem
			break
		}
	}
	if chosen == nil {
		m.mu.Unlock()
		return nil, ErrNoMemberAvailable
	}
	chosen.State = StateClaiming
	m.mu.Unlock()

	if err := m.strategy.Claim(ctx, chosen); err != nil {
		m.mu.Lock()
		chosen.State = StateFailed
		m.mu.Unlock()
		m.signal() // recycle + backfill
		return nil, fmt.Errorf("claim %s: %w", chosen.Name, err)
	}

	m.mu.Lock()
	chosen.State = StateClaimed
	m.mu.Unlock()
	m.signal() // backfill the consumed slot
	return chosen, nil
}

// Reserve hands out a free ready member's sandbox ID WITHOUT activating it: no
// container is attached and no VM is woken. The caller owns the next CRI steps
// (e.g. `crictl create <id> ...` + `crictl start`). selector (may be nil)
// restricts the choice as in Claim. A backfill is triggered so the pool refills
// the consumed slot. Intended for Tier A external-attach.
func (m *Manager) Reserve(ctx context.Context, selector map[string]string) (*Member, error) {
	m.mu.Lock()
	var chosen *Member
	for _, mem := range m.members {
		if mem.State == StateFree && mem.Ready && labelsMatch(mem.Labels, selector) {
			chosen = mem
			break
		}
	}
	if chosen == nil {
		m.mu.Unlock()
		return nil, ErrNoMemberAvailable
	}
	chosen.State = StateClaimed
	m.mu.Unlock()
	m.signal() // backfill the consumed slot
	return chosen, nil
}

// labelsMatch reports whether have contains every key/value in want. An empty
// want matches any member.
func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// Stats is a point-in-time snapshot of the pool.
type Stats struct {
	Target   int            `json:"target"`
	Tier     string         `json:"tier"`
	Total    int            `json:"total"`
	Free     int            `json:"free"`
	Ready    int            `json:"ready"`
	Claimed  int            `json:"claimed"`
	Creating int            `json:"creating"`
	Members  []MemberStatus `json:"members"`
}

// MemberStatus is a serializable view of a member.
type MemberStatus struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
	Ready bool   `json:"ready"`
}

// Stats returns a snapshot of the pool state.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := Stats{Target: m.cfg.PoolSize, Tier: string(m.cfg.Tier)}
	for _, mem := range m.members {
		s.Total++
		switch mem.State {
		case StateFree:
			s.Free++
			if mem.Ready {
				s.Ready++
			}
		case StateClaimed:
			s.Claimed++
		case StateCreating:
			s.Creating++
		}
		s.Members = append(s.Members, MemberStatus{
			ID:    mem.ID,
			Name:  mem.Name,
			State: string(mem.State),
			Ready: mem.Ready,
		})
	}
	return s
}

// Shutdown tears down every managed member. Call after Run returns.
func (m *Manager) Shutdown(ctx context.Context) {
	m.closed.Store(true)
	m.mu.Lock()
	members := make([]*Member, 0, len(m.members))
	for _, mem := range m.members {
		members = append(members, mem)
	}
	m.mu.Unlock()

	for _, mem := range members {
		m.destroyMember(ctx, mem)
	}
}
