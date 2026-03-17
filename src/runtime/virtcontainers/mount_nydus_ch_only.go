//go:build linux && ch_only

// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package virtcontainers

func getVirtiofsDaemonForNydusHypervisor(sandbox *Sandbox) (VirtiofsDaemon, error) {
	if sandbox.GetHypervisorType() != string(ClhHypervisor) {
		return nil, errNydusdNotSupport
	}

	return sandbox.hypervisor.(*cloudHypervisor).virtiofsDaemon, nil
}
