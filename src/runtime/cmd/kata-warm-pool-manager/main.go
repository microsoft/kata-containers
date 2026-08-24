// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// kata-warm-pool-manager is a long-running host daemon that keeps a "warm
// pool" of pre-restored, paused kata sandboxes ready to serve deployments,
// reducing pod startup latency. POC scope: it only reconciles pool size
// (restore N sandboxes into placeholder network namespaces); handing a warm
// sandbox to a real pod is out of scope and tracked separately.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
)

const appName = "kata-warm-pool-manager"

var (
	poolSize          = flag.Int("pool-size", 1, "number of warm sandboxes to keep ready")
	snapshotDir       = flag.String("snapshot-dir", "/run/vc/vm/snapshots", "directory holding the snapshot artifacts to restore from")
	poolDir           = flag.String("pool-dir", "/run/kata/warm_pool", "manager-owned directory indexing warm slots")
	reconcileInterval = flag.Duration("reconcile-interval", 5*time.Second, "how often to reconcile the pool against the target size")
	memRestoreMode    = flag.String("memory-restore-mode", string(vc.ClhMemoryRestoreModeCopyOnWrite), "cloud-hypervisor memory restore mode: copy|ondemand|copyonwrite")
	logLevel          = flag.String("log-level", "info", "log level: trace|debug|info|warn|error")
)

func main() {
	flag.Parse()

	logger := logrus.WithFields(logrus.Fields{
		"name": appName,
		"pid":  os.Getpid(),
	})
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.Logger.SetLevel(level)
	logger.Logger.Formatter = &logrus.TextFormatter{TimestampFormat: time.RFC3339Nano}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Route virtcontainers logs through our logger.
	vc.SetLogger(ctx, logger)

	logger.WithFields(logrus.Fields{
		"pool-size":           *poolSize,
		"snapshot-dir":        *snapshotDir,
		"pool-dir":            *poolDir,
		"reconcile-interval":  reconcileInterval.String(),
		"memory-restore-mode": *memRestoreMode,
	}).Info("starting warm pool manager")

	mgr, err := NewManager(*poolSize, *snapshotDir, *poolDir, vc.ClhMemoryRestoreMode(*memRestoreMode), logger)
	if err != nil {
		logger.WithError(err).Fatal("failed to initialize warm pool manager")
	}

	// Drop warm slots left by a previous instance (POC: no live re-adoption).
	mgr.RecoverStale(ctx)

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.WithField("signal", sig.String()).Info("received signal, shutting down")
		cancel()
	}()

	ticker := time.NewTicker(*reconcileInterval)
	defer ticker.Stop()

	// Reconcile immediately, then on every tick until cancelled.
	mgr.Reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			drainCtx, drainCancel := context.WithTimeout(context.Background(), 30*time.Second)
			mgr.Drain(drainCtx)
			drainCancel()
			logger.Info("warm pool drained; exiting")
			return
		case <-ticker.C:
			mgr.Reconcile(ctx)
		}
	}
}
