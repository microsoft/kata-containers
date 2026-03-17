//go:build linux && !ch_only

// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package virtcontainers

func getVirtiofsDaemonForNydusHypervisor(sandbox *Sandbox) (VirtiofsDaemon, error) {
	var virtiofsDaemon VirtiofsDaemon
	switch sandbox.GetHypervisorType() {
	case string(QemuHypervisor):
		virtiofsDaemon = sandbox.hypervisor.(*qemu).virtiofsDaemon
	case string(ClhHypervisor):
		virtiofsDaemon = sandbox.hypervisor.(*cloudHypervisor).virtiofsDaemon
	default:
		return nil, errNydusdNotSupport
	}
	return virtiofsDaemon, nil
}
