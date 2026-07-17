// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	containerdshim "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2"
	"github.com/urfave/cli"
)

// restore is the user-facing CLI: a thin launcher. it does not touch CLH, the CLH API, or
// kata-agent-ctl. it validates the snapshot source then spawns containerd-shim-kata-v2 in
// restore mode (KATA_RESTORE_FROM=<dir>); that shim restores a kata-managed sandbox, serves
// its management API, and runs long-lived.

const shimBinaryName = "containerd-shim-kata-v2"

var restoreCLICommand = cli.Command{
	Name:      "restore",
	Usage:     "restore a snapshot as a running, kata-managed sandbox",
	ArgsUsage: "--path <dir>",
	Flags: []cli.Flag{
		cli.StringFlag{Name: "path", Usage: "snapshot directory to restore from (required)"},
		cli.StringFlag{Name: "from", Usage: "deprecated alias for --path", Hidden: true},
		cli.StringFlag{Name: "name", Usage: "sandbox id for the restore (default: generated)"},
		cli.StringFlag{Name: "shim-bin", Usage: "containerd-shim-kata-v2 binary (default: from PATH)", Hidden: true},
	},
	Subcommands: []cli.Command{restoreKillCommand},
	// runs when no subcommand matches.
	Action: func(c *cli.Context) error {
		from := c.String("path")
		if from == "" {
			from = c.String("from")
		}
		if from == "" {
			return fmt.Errorf("--path is required")
		}
		src, err := containerdshim.ResolveRestoreSource(from, false)
		if err != nil {
			return err
		}

		shimBin := c.String("shim-bin")
		if shimBin == "" {
			shimBin, err = exec.LookPath(shimBinaryName)
			if err != nil {
				return fmt.Errorf("%s not found on PATH: %w", shimBinaryName, err)
			}
		}

		// spawn the shim in restore mode, detached (own session) so it outlives this CLI.
		cmd := exec.Command(shimBin, "--restore-from", src)
		cmd.Env = append(os.Environ(), "KATA_RESTORE_FROM="+src)
		if name := c.String("name"); name != "" {
			cmd.Env = append(cmd.Env, "KATA_RESTORE_SANDBOX_ID="+name)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to launch %s in restore mode: %w", shimBinaryName, err)
		}

		fmt.Fprintf(defaultOutputFile, "restored sandbox shim launched (pid %d) from %s\n", cmd.Process.Pid, src)
		fmt.Fprintf(defaultOutputFile, "stop it with: kata-runtime restore kill %d\n", cmd.Process.Pid)
		return nil
	},
}

var restoreKillCommand = cli.Command{
	Name:      "kill",
	Usage:     "stop a restored sandbox by its shim pid (SIGTERM -> clean shutdown)",
	ArgsUsage: "<shim-pid>",
	Action: func(c *cli.Context) error {
		arg := c.Args().First()
		if arg == "" {
			return fmt.Errorf("shim pid is required: kata-runtime restore kill <shim-pid>")
		}
		pid, err := strconv.Atoi(arg)
		if err != nil {
			return fmt.Errorf("invalid shim pid %q: %w", arg, err)
		}
		// SIGTERM triggers the shim's clean teardown (sandbox.Stop) in RunRestore.
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			return fmt.Errorf("failed to signal shim pid %d: %w", pid, err)
		}
		fmt.Fprintf(defaultOutputFile, "sent SIGTERM to restore shim pid %d\n", pid)
		return nil
	},
}

