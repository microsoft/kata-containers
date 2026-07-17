// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"os"

	containerdtypes "github.com/containerd/containerd/api/types"
	shimapi "github.com/containerd/containerd/runtime/v2/shim"
	"google.golang.org/protobuf/proto"

	shim "github.com/kata-containers/kata-containers/src/runtime/pkg/containerd-shim-v2"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/types"
)

func shimConfig(config *shimapi.Config) {
	config.NoReaper = true
	config.NoSubreaper = true
}

func handleInfoFlag() {
	info := &containerdtypes.RuntimeInfo{
		Name: types.DefaultKataRuntimeName,
		Version: &containerdtypes.RuntimeVersion{
			Version:  katautils.VERSION,
			Revision: katautils.COMMIT,
		},
	}

	data, err := proto.Marshal(info)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal RuntimeInfo: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(data)
	os.Exit(0)
}

func main() {

	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("%s containerd shim (Golang): id: %q, version: %s, commit: %v\n", katautils.PROJECT, types.DefaultKataRuntimeName, katautils.VERSION, katautils.COMMIT)
		os.Exit(0)
	}

	if len(os.Args) == 2 && os.Args[1] == "-info" {
		handleInfoFlag()
	}

	// restore mode: with a snapshot dir, restore a managed sandbox and run long-lived
	// instead of the normal containerd shim loop.
	if restoreFrom := restoreFromArg(); restoreFrom != "" {
		if err := shim.RunRestore(restoreFrom); err != nil {
			fmt.Fprintf(os.Stderr, "restore failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	shimapi.Run(types.DefaultKataRuntimeName, shim.New, shimConfig)
}

// restoreFromArg returns the snapshot dir from KATA_RESTORE_FROM or --restore-from, else "".
func restoreFromArg() string {
	if v := os.Getenv("KATA_RESTORE_FROM"); v != "" {
		return v
	}
	args := os.Args[1:]
	for i, a := range args {
		if a == "--restore-from" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
