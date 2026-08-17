// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
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
