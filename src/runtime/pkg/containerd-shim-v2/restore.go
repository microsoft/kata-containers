// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
)

// RunRestore is the shim's "restore mode" entry point. launched with a snapshot dir (env
// KATA_RESTORE_FROM), the shim skips the normal containerd-driven shimapi.Run() loop and
// instead restores the snapshot into a kata-managed sandbox via vc.RestoreSandbox, becomes
// its long-lived owner (CLH + agent), serves the management API, and blocks until
// SIGTERM/SIGINT -> clean sandbox.Stop.
func RunRestore(snapshotDir string) error {
	ctx := context.Background()

	// minimal logging setup (normally done by New(); we are not under shimapi).
	shimLog = shimLog.WithFields(logrus.Fields{"restore-from": snapshotDir, "pid": os.Getpid()})
	vci.SetLogger(ctx, shimLog)
	katautils.SetLogger(ctx, shimLog, shimLog.Logger.Level)

	// load the node's kata runtime config (hypervisor binary paths, agent cfg, etc.).
	_, runtimeConfig, err := katautils.LoadConfiguration("", false)
	if err != nil {
		return fmt.Errorf("load kata configuration: %w", err)
	}

	// pass the node-authoritative hypervisor binary paths so the restored VM uses THIS
	// node's binaries rather than the snapshot source's. networking is best-effort.
	sandbox, err := vc.RestoreSandbox(ctx, snapshotDir, vc.RestoreOpts{
		SandboxID:      os.Getenv("KATA_RESTORE_SANDBOX_ID"), // optional --name; empty -> generated
		HypervisorPath: runtimeConfig.HypervisorConfig.HypervisorPath,
		KernelPath:     runtimeConfig.HypervisorConfig.KernelPath,
		ImagePath:      runtimeConfig.HypervisorConfig.ImagePath,
	})
	if err != nil {
		return fmt.Errorf("restore sandbox: %w", err)
	}

	// a service that OWNS the restored sandbox (mirrors New()'s field set).
	s := &service{
		id:         sandbox.ID(),
		pid:        uint32(os.Getpid()),
		ctx:        ctx,
		sandbox:    sandbox,
		containers: make(map[string]*container),
		events:     make(chan interface{}, chSize),
		ec:         make(chan exit, bufferSize),
		config:     &runtimeConfig,
	}

	// serve the management API so the restored sandbox is a real, manageable kata runtime
	// (metrics, agent-url, and /snapshot to re-snapshot the restored VM). startManagementServer
	// blocks on Serve(), so background it and wait on signals. the empty (non-nil) spec is
	// because the pprof handler dereferences ociSpec.Annotations.
	go s.startManagementServer(ctx, &specs.Spec{})

	if addr, err := ClientSocketAddress(s.id); err == nil {
		// print the management socket so the launcher can report it.
		fmt.Fprintln(os.Stdout, addr)
	}
	shimLog.WithField("sandbox", s.id).Info("restore: managed kata runtime serving; waiting for signal")

	// block until told to stop, then tear the sandbox down cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	shimLog.WithField("sandbox", s.id).Info("restore: signal received, stopping sandbox")
	if err := s.sandbox.Stop(ctx, true); err != nil {
		shimLog.WithError(err).Warn("restore: sandbox stop returned an error")
	}
	return nil
}

// ResolveRestoreSource maps a restore source (snapshot name or path) to a snapshot dir.
// a bare name (no separator) must resolve to a direct child of SnapshotBaseDir; a path is
// taken as given. in both cases the final path is symlink-resolved and re-checked so a
// symlink planted inside the base dir cannot escape it (TOCTOU), then verified to be a real
// snapshot dir (has config.json). lives here, not in the CLI, so the shim restore dispatch
// can reuse it.
func ResolveRestoreSource(from string, confineToBase bool) (string, error) {
	if from == "" {
		return "", fmt.Errorf("restore source is required")
	}
	dir := from
	if !strings.Contains(from, "/") {
		clean := filepath.Clean(filepath.Join(SnapshotBaseDir, from))
		if filepath.Dir(clean) != filepath.Clean(SnapshotBaseDir) {
			return "", fmt.Errorf("invalid snapshot name %q: must not contain path separators or ..", from)
		}
		dir = clean
	}
	// resolve symlinks then re-validate, so a symlinked entry cannot point the restore at an
	// arbitrary host dir after the name check passed.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve snapshot source %q: %w", dir, err)
	}
	// for a bare name, the resolved path must still be inside SnapshotBaseDir -- a symlink
	// planted under the base could otherwise resolve to any host dir. (a path input is an
	// explicit operator choice; annotation-sourced path values are confined separately.)
	if !strings.Contains(from, "/") {
		base := filepath.Clean(SnapshotBaseDir)
		if resolved != base && !strings.HasPrefix(resolved, base+string(os.PathSeparator)) {
			return "", fmt.Errorf("snapshot %q resolves outside %s", from, base)
		}
	}
	if _, err := os.Stat(filepath.Join(resolved, "config.json")); err != nil {
		return "", fmt.Errorf("not a snapshot dir (no config.json): %s", resolved)
	}
	// when the source is untrusted-ish (annotation-driven restore), confine ANY input -- path
	// or name -- to SnapshotBaseDir; the CLI passes false since a root operator may name an
	// explicit path.
	if confineToBase {
		base := filepath.Clean(SnapshotBaseDir)
		if resolved != base && !strings.HasPrefix(resolved, base+string(os.PathSeparator)) {
			return "", fmt.Errorf("restore source %q resolves outside %s", from, base)
		}
	}
	return resolved, nil
}
