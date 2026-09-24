// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package pool

import "context"

// Strategy encapsulates the tier-specific member shape and claim action. Both
// implementations create members through the same RunPodSandbox path; they
// differ only in the member config and what "claim" does.
type Strategy interface {
	// Name identifies the strategy for logs.
	Name() string
	// CreateMember creates one warm member and returns it in StateFree.
	CreateMember(ctx context.Context) (*Member, error)
	// Ready reports whether a member is claimable.
	Ready(ctx context.Context, m *Member) (bool, error)
	// Claim activates a member for real work.
	//   Tier A: create + start the workload container.
	//   Tier B: wake the deferred-paused VM (exec no-op).
	Claim(ctx context.Context, m *Member) error
	// Destroy tears a member down (StopPodSandbox + RemovePodSandbox).
	Destroy(ctx context.Context, m *Member) error
}
