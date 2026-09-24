// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	"github.com/kata-containers/kata-containers/src/tools/warm-pool-manager/cri"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// logDirRoot is where CRI writes member sandbox/container logs.
const logDirRoot = "/var/log/warm-pool-manager"

// base holds the CRI plumbing shared by both tier strategies.
type base struct {
	client *cri.Client
	cfg    *Config
}

func shortID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// newPodConfig builds a member pod sandbox config. When cfg.PodTemplate is
// set it starts from a copy of the template and only overrides per-member
// fields (metadata, hostname, log dir) and merges labels/annotations.
func (b *base) newPodConfig(annotations map[string]string) *runtimeapi.PodSandboxConfig {
	id := shortID()
	name := fmt.Sprintf("warmpool-%s-%s", b.cfg.Tier, id)

	var cfg runtimeapi.PodSandboxConfig
	var tmplLabels, tmplAnns map[string]string
	if b.cfg.PodTemplate != nil {
		cfg = *b.cfg.PodTemplate // struct copy; nested slices are read-only
		tmplLabels = b.cfg.PodTemplate.Labels
		tmplAnns = b.cfg.PodTemplate.Annotations
	} else {
		cfg.Linux = &runtimeapi.LinuxPodSandboxConfig{
			SecurityContext: &runtimeapi.LinuxSandboxSecurityContext{
				NamespaceOptions: &runtimeapi.NamespaceOption{},
			},
		}
	}

	cfg.Metadata = &runtimeapi.PodSandboxMetadata{
		Name:      name,
		Uid:       id,
		Namespace: b.cfg.Namespace,
		Attempt:   0,
	}
	cfg.Hostname = name
	cfg.LogDirectory = filepath.Join(logDirRoot, name)

	labels := map[string]string{
		LabelManagedBy: LabelValue,
		LabelTier:      string(b.cfg.Tier),
	}
	for k, v := range tmplLabels {
		labels[k] = v
	}
	for k, v := range b.cfg.MemberLabels {
		labels[k] = v
	}
	cfg.Labels = labels

	anns := map[string]string{}
	for k, v := range tmplAnns {
		anns[k] = v
	}
	for k, v := range annotations {
		anns[k] = v
	}
	cfg.Annotations = anns

	return &cfg
}

// createPod runs the sandbox and returns a StateFree member handle.
func (b *base) createPod(ctx context.Context, annotations map[string]string) (*Member, error) {
	cctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()

	cfg := b.newPodConfig(annotations)
	id, err := b.client.RunPodSandbox(cctx, cfg, b.cfg.RuntimeHandler)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	m := &Member{
		ID:        id,
		Name:      cfg.Metadata.Name,
		State:     StateFree,
		Labels:    cfg.Labels,
		CreatedAt: now,
		podConfig: cfg,
		key:       id,
	}
	if b.cfg.MemberTTL > 0 {
		m.ExpiresAt = now.Add(b.cfg.MemberTTL)
	}
	return m, nil
}

// workloadImage is the image members run: the container template's image wins,
// else the -image flag.
func (b *base) workloadImage() string {
	if b.cfg.ContainerTemplate != nil && b.cfg.ContainerTemplate.GetImage().GetImage() != "" {
		return b.cfg.ContainerTemplate.Image.Image
	}
	return b.cfg.Image
}

// containerConfig builds the workload container config shared by both tiers.
// With cfg.ContainerTemplate set (e.g. the pyruntime workload) it copies the
// template and only overrides the container name and managed-by label.
func (b *base) containerConfig(name string) *runtimeapi.ContainerConfig {
	var cfg runtimeapi.ContainerConfig
	var tmplLabels map[string]string
	if b.cfg.ContainerTemplate != nil {
		cfg = *b.cfg.ContainerTemplate // struct copy; nested slices are read-only
		tmplLabels = b.cfg.ContainerTemplate.Labels
	} else {
		cfg.Image = &runtimeapi.ImageSpec{Image: b.cfg.Image}
		if len(b.cfg.Command) > 0 {
			cfg.Command = b.cfg.Command
		}
	}

	cfg.Metadata = &runtimeapi.ContainerMetadata{Name: name}
	labels := map[string]string{LabelManagedBy: LabelValue}
	for k, v := range tmplLabels {
		labels[k] = v
	}
	cfg.Labels = labels
	return &cfg
}

func (b *base) ready(ctx context.Context, m *Member) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()
	return b.client.PodSandboxReady(cctx, m.ID)
}

func (b *base) destroy(ctx context.Context, m *Member) error {
	if m.ID == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()

	// Stop reaps the (possibly paused) cloud-hypervisor; then remove the record.
	if err := b.client.StopPodSandbox(cctx, m.ID); err != nil {
		return err
	}
	return b.client.RemovePodSandbox(cctx, m.ID)
}

// --- Tier A: pause-only member; claim attaches a workload container ---------

type tierA struct{ base }

func newTierA(client *cri.Client, cfg *Config) *tierA {
	return &tierA{base{client: client, cfg: cfg}}
}

func (t *tierA) Name() string { return "tier-A (attach-on-claim)" }

func (t *tierA) CreateMember(ctx context.Context) (*Member, error) {
	// Ensure the workload image is present so claim latency is pull-free.
	if img := t.workloadImage(); img != "" {
		cctx, cancel := context.WithTimeout(ctx, t.cfg.CallTimeout)
		if _, err := t.client.PullImage(cctx, img); err != nil {
			cancel()
			return nil, err
		}
		cancel()
	}
	// A bare pod sandbox: VM + pause, no workload yet.
	return t.createPod(ctx, nil)
}

func (t *tierA) Ready(ctx context.Context, m *Member) (bool, error) {
	return t.ready(ctx, m)
}

func (t *tierA) Claim(ctx context.Context, m *Member) error {
	cctx, cancel := context.WithTimeout(ctx, t.cfg.CallTimeout)
	defer cancel()

	cid, err := t.client.CreateContainer(cctx, m.ID, t.containerConfig("workload"), m.podConfig)
	if err != nil {
		return err
	}
	if err := t.client.StartContainer(cctx, cid); err != nil {
		return err
	}
	m.WorkloadID = cid
	return nil
}

func (t *tierA) Destroy(ctx context.Context, m *Member) error {
	return t.destroy(ctx, m)
}

// --- Tier B: deferred-paused restore member; claim wakes the VM -------------

type tierB struct{ base }

func newTierB(client *cri.Client, cfg *Config) *tierB {
	return &tierB{base{client: client, cfg: cfg}}
}

func (t *tierB) Name() string { return "tier-B (deferred-restore, wake-on-claim)" }

func (t *tierB) CreateMember(ctx context.Context) (*Member, error) {
	if img := t.workloadImage(); img != "" {
		cctx, cancel := context.WithTimeout(ctx, t.cfg.CallTimeout)
		if _, err := t.client.PullImage(cctx, img); err != nil {
			cancel()
			return nil, err
		}
		cancel()
	}

	// Restore-configured sandbox: runtime-rs boots cloud-hypervisor and leaves
	// it deferred-paused (~16 MiB idle) by default.
	m, err := t.createPod(ctx, t.cfg.RestoreAnnotations)
	if err != nil {
		return nil, err
	}

	// Create + start the restore-adopted workload container so the VM has the
	// wake target; runtime-rs adopts it from the snapshot and keeps the VM
	// paused until claim.
	cctx, cancel := context.WithTimeout(ctx, t.cfg.CallTimeout)
	defer cancel()

	cid, err := t.client.CreateContainer(cctx, m.ID, t.containerConfig(t.cfg.WakeContainer), m.podConfig)
	if err != nil {
		_ = t.destroy(context.Background(), m)
		return nil, err
	}
	if err := t.client.StartContainer(cctx, cid); err != nil {
		_ = t.destroy(context.Background(), m)
		return nil, err
	}
	m.WorkloadID = cid
	return m, nil
}

func (t *tierB) Ready(ctx context.Context, m *Member) (bool, error) {
	// Deferred members report READY while their VM is paused, which is exactly
	// what we want: claimable, but cheap.
	return t.ready(ctx, m)
}

func (t *tierB) Claim(ctx context.Context, m *Member) error {
	cctx, cancel := context.WithTimeout(ctx, t.cfg.CallTimeout)
	defer cancel()

	// The exec no-op reaches the kata shim as StartProcess(Exec) -> wake_restore
	// resumes the paused VM and finalizes the deferred workloads.
	exit, _, stderr, err := t.client.ExecSync(cctx, m.WorkloadID, []string{"true"}, 30*time.Second)
	if err != nil {
		return err
	}
	if exit != 0 {
		return fmt.Errorf("wake exec exited %d: %s", exit, string(stderr))
	}
	return nil
}

func (t *tierB) Destroy(ctx context.Context, m *Member) error {
	return t.destroy(ctx, m)
}

// newStrategy selects the tier strategy.
func newStrategy(client *cri.Client, cfg *Config) (Strategy, error) {
	switch cfg.Tier {
	case TierA:
		return newTierA(client, cfg), nil
	case TierB:
		return newTierB(client, cfg), nil
	default:
		return nil, fmt.Errorf("unknown tier %q (want A or B)", cfg.Tier)
	}
}
