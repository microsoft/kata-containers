// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	containerdshim "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/utils/shimclient"
	"github.com/urfave/cli"
)

// snapshotTimeout is the whole-request deadline for the snapshot PUT. A snapshot
// copies the full guest RAM to a fresh directory (O(N) in VM size, ~1s/GiB), so
// it must comfortably exceed the shim-side getClhSnapshotTimeout (max(30s,10s/GiB))
// plus pause/resume headroom. The default 3s exec timeout would abort mid-dump
// and orphan a partial RAM file. A generous fixed ceiling avoids needing the
// guest MemorySize client-side.
const snapshotTimeout = 300 * time.Second

var snapshotCLICommand = cli.Command{
	Name:  "snapshot",
	Usage: "snapshot a running Kata Containers sandbox VM",
	Subcommands: []cli.Command{
		createSnapshotCommand,
		deleteSnapshotCommand,
	},
}

var createSnapshotCommand = cli.Command{
	Name:      "create",
	Usage:     "snapshot a sandbox VM into a caller-chosen directory",
	ArgsUsage: "--path <dir> --sandbox-id <sbid>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:        "sandbox-id",
			Usage:       "the target sandbox to snapshot (required)",
			Destination: &sandboxID,
		},
		cli.StringFlag{
			Name:  "path",
			Usage: "full artifact directory; caller picks the location (required)",
		},
	},
	Action: func(c *cli.Context) error {
		if sandboxID == "" {
			return fmt.Errorf("--sandbox-id is required")
		}
		if err := katautils.VerifyContainerID(sandboxID); err != nil {
			return err
		}
		path := c.String("path")
		if path == "" {
			return fmt.Errorf("--path is required")
		}

		// the shim does the pause/save/snapshot/resume work; send the caller's
		// absolute directory as the request body and print the path it used.
		if err := shimclient.DoPut(sandboxID, snapshotTimeout, containerdshim.SnapshotURL,
			"application/octet-stream", []byte(path)); err != nil {
			return fmt.Errorf("Error observed when making snapshot request: %s", err)
		}

		fmt.Fprintln(defaultOutputFile, path)

		return nil
	},
}

var deleteSnapshotCommand = cli.Command{
	Name:      "delete",
	Usage:     "delete a snapshot directory",
	ArgsUsage: "--path <dir>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Usage: "snapshot directory to delete (required)",
		},
	},
	Action: func(c *cli.Context) error {
		path := c.String("path")
		if path == "" {
			return fmt.Errorf("--path is required")
		}
		// node-local removal; a snapshot can outlive its sandbox, so no shim round-trip.
		if !filepath.IsAbs(path) {
			return fmt.Errorf("--path must be absolute: %q", path)
		}
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("snapshot path %q: %w", path, err)
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("failed to delete snapshot %s: %s", path, err)
		}

		fmt.Fprintln(defaultOutputFile, path)

		return nil
	},
}
