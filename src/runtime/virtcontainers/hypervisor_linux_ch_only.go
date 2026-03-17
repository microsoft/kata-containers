//go:build linux && ch_only

// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package virtcontainers

import "fmt"

// NewHypervisor returns a Cloud Hypervisor-only hypervisor implementation.
func NewHypervisor(hType HypervisorType) (Hypervisor, error) {
	switch hType {
	case ClhHypervisor:
		return &cloudHypervisor{}, nil
	case MockHypervisor:
		return &mockHypervisor{}, nil
	default:
		return nil, fmt.Errorf("hypervisor type %s is not enabled in CH_ONLY build", hType)
	}
}