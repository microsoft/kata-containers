// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist"
	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
)

const (
	slotIndexFile   = "slot.json"
	snapshotMarker  = "config.json" // presence signals a usable snapshot dir
	sandboxIDPrefix = "warmpool"
)

type slotState string

const (
	slotReady  slotState = "ready"
	slotFailed slotState = "failed"
)

// slot is one warm, restored-but-paused sandbox held ready in the pool.
type slot struct {
	ID          string            `json:"id"`
	SnapshotDir string            `json:"snapshotDir"`
	NetnsPath   string            `json:"netnsPath"`
	State       slotState         `json:"state"`
	CreatedAt   time.Time         `json:"createdAt"`
	netns       *placeholderNetns `json:"-"`
	sandbox     *vc.Sandbox       `json:"-"`
}

// Manager keeps `target` warm sandboxes restored and ready, reconciling the
// live count against the target on each tick.
type Manager struct {
	target      int
	snapshotDir string
	poolDir     string
	memMode     vc.ClhMemoryRestoreMode
	log         *logrus.Entry
	drv         persistapi.PersistDriver

	mu    sync.Mutex
	slots map[string]*slot
}

// NewManager builds a pool manager and initializes the persist driver.
func NewManager(target int, snapshotDir, poolDir string, memMode vc.ClhMemoryRestoreMode, log *logrus.Entry) (*Manager, error) {
	if target < 0 {
		return nil, fmt.Errorf("pool size must be >= 0, got %d", target)
	}
	if !memMode.IsValid() {
		return nil, fmt.Errorf("invalid memory restore mode %q", memMode)
	}
	drv, err := persist.GetDriver()
	if err != nil {
		return nil, fmt.Errorf("get persist driver: %w", err)
	}
	if err := os.MkdirAll(poolDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir pool dir %s: %w", poolDir, err)
	}
	return &Manager{
		target:      target,
		snapshotDir: snapshotDir,
		poolDir:     poolDir,
		memMode:     memMode,
		log:         log,
		drv:         drv,
		slots:       make(map[string]*slot),
	}, nil
}

// RecoverStale best-effort cleans up warm slots left behind by a previous
// manager instance. This POC does not re-adopt live VMMs (the *Sandbox handle
// is only held in-memory), so a manager restart tears the pool down and
// rebuilds it. Orphaned VMM processes from a crashed manager are a known POC
// limitation that production would solve with pidfiles/systemd scopes.
func (m *Manager) RecoverStale(ctx context.Context) {
	entries, err := os.ReadDir(m.poolDir)
	if err != nil {
		m.log.WithError(err).Warn("cannot list pool dir for recovery")
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		s, rerr := m.readSlotIndex(id)
		if rerr != nil {
			m.log.WithError(rerr).WithField("id", id).Warn("recover: unreadable slot index, removing")
			_ = os.RemoveAll(filepath.Join(m.poolDir, id))
			continue
		}
		m.log.WithField("id", id).Warn("recover: cleaning stale warm slot from previous run")
		// No live *Sandbox to Stop(); drop persist state and the placeholder netns.
		if derr := m.drv.Destroy(id); derr != nil {
			m.log.WithError(derr).WithField("id", id).Warn("recover: destroy persist state failed")
		}
		(&placeholderNetns{name: id, path: s.NetnsPath}).remove()
		_ = os.RemoveAll(filepath.Join(m.poolDir, id))
	}
}

// Reconcile brings the pool up to target size. It grows one slot at a time and
// stops early when no snapshot is available.
func (m *Manager) Reconcile(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ready := m.countReadyLocked()
	if ready >= m.target {
		return
	}

	if !m.snapshotPresent() {
		// Pool is short but there is nothing to restore from.
		m.log.WithFields(logrus.Fields{
			"have":         ready,
			"want":         m.target,
			"snapshot-dir": m.snapshotDir,
		}).Warn("cannot warm pool: no snapshot artifacts present")
		return
	}

	for ready < m.target {
		if ctx.Err() != nil {
			return
		}
		if err := m.growLocked(ctx); err != nil {
			m.log.WithError(err).Error("failed to grow warm pool; will retry next tick")
			return
		}
		ready++
	}
}

// growLocked restores one warm sandbox into a fresh placeholder netns.
// Caller must hold m.mu.
func (m *Manager) growLocked(ctx context.Context) (err error) {
	id, err := newSandboxID()
	if err != nil {
		return fmt.Errorf("generate sandbox id: %w", err)
	}
	log := m.log.WithField("id", id)

	ph, err := newPlaceholderNetns(id)
	if err != nil {
		return fmt.Errorf("create placeholder netns: %w", err)
	}
	defer func() {
		if err != nil {
			_ = ph.remove()
		}
	}()

	log.WithField("netns", ph.path).Info("restoring warm sandbox")
	sb, err := vc.RestoreSandbox(ctx, m.snapshotDir, vc.RestoreOpts{
		SandboxID:            id,
		NetNSPath:            ph.path,
		ClhMemoryRestoreMode: m.memMode,
	})
	if err != nil {
		return fmt.Errorf("restore sandbox: %w", err)
	}

	sl := &slot{
		ID:          id,
		SnapshotDir: m.snapshotDir,
		NetnsPath:   ph.path,
		State:       slotReady,
		CreatedAt:   time.Now().UTC(),
		netns:       ph,
		sandbox:     sb,
	}
	if werr := m.writeSlotIndex(sl); werr != nil {
		// Roll back the restore so we do not leak an untracked VMM.
		log.WithError(werr).Error("write slot index failed; aborting restore")
		m.teardownSlot(ctx, sl)
		err = werr
		return err
	}
	m.slots[id] = sl
	log.Info("warm sandbox ready")
	return nil
}

// Drain tears down every warm slot. Used on shutdown.
func (m *Manager) Drain(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, sl := range m.slots {
		m.log.WithField("id", id).Info("draining warm sandbox")
		m.teardownSlot(ctx, sl)
		delete(m.slots, id)
	}
}

// teardownSlot stops the VMM, drops persist state, removes the netns, and
// clears the pool index entry. Best-effort: logs but does not abort on
// individual failures. Caller must hold m.mu.
func (m *Manager) teardownSlot(ctx context.Context, sl *slot) {
	log := m.log.WithField("id", sl.ID)
	if sl.sandbox != nil {
		// AbortRestore stops the VMM and removes network endpoints for a
		// restored-but-not-finalized sandbox (keeps persist for retry).
		if err := sl.sandbox.AbortRestore(ctx); err != nil {
			log.WithError(err).Warn("abort restore during teardown failed")
		}
	}
	if err := m.drv.Destroy(sl.ID); err != nil {
		log.WithError(err).Warn("destroy persist state failed")
	}
	if sl.netns != nil {
		if err := sl.netns.remove(); err != nil {
			log.WithError(err).Warn("remove placeholder netns failed")
		}
	} else {
		(&placeholderNetns{name: sl.ID, path: sl.NetnsPath}).remove()
	}
	if err := os.RemoveAll(filepath.Join(m.poolDir, sl.ID)); err != nil {
		log.WithError(err).Warn("remove pool index entry failed")
	}
}

func (m *Manager) countReadyLocked() int {
	n := 0
	for _, sl := range m.slots {
		if sl.State == slotReady {
			n++
		}
	}
	return n
}

// snapshotPresent reports whether the snapshot dir looks usable.
func (m *Manager) snapshotPresent() bool {
	_, err := os.Stat(filepath.Join(m.snapshotDir, snapshotMarker))
	return err == nil
}

func (m *Manager) slotDir(id string) string { return filepath.Join(m.poolDir, id) }

func (m *Manager) writeSlotIndex(sl *slot) error {
	dir := m.slotDir(sl.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sl, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, slotIndexFile), data, 0o644)
}

func (m *Manager) readSlotIndex(id string) (*slot, error) {
	data, err := os.ReadFile(filepath.Join(m.slotDir(id), slotIndexFile))
	if err != nil {
		return nil, err
	}
	var sl slot
	if err := json.Unmarshal(data, &sl); err != nil {
		return nil, err
	}
	return &sl, nil
}

// newSandboxID returns a unique, kata-valid sandbox identifier.
func newSandboxID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return sandboxIDPrefix + "-" + hex.EncodeToString(buf), nil
}
