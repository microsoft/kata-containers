//go:build linux && ch_only

// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package virtcontainers

const (
	// Keep shared configuration and Nydus helpers compiling when qemu/firecracker
	// backends are excluded from the build.
	nydusdAPISock        = "nydusd-api.sock"
	defaultGuestVSockCID = int64(0x3)
	QemuCCWVirtio        = "s390-ccw-virtio"
)
