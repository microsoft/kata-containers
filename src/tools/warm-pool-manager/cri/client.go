// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

// Package cri is a thin wrapper over the containerd CRI (RuntimeService +
// ImageService) gRPC APIs. It is the only VM-creation primitive the warm-pool
// manager uses: every warm member is an ordinary kata pod sandbox created via
// RunPodSandbox, so containerd drives the usual shim-v2 -> cloud-hypervisor
// path. The manager never spawns a VMM itself.
package cri

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Client wraps a connection to a CRI runtime endpoint (the containerd socket).
type Client struct {
	conn    *grpc.ClientConn
	runtime runtimeapi.RuntimeServiceClient
	image   runtimeapi.ImageServiceClient
}

// Dial connects to the CRI endpoint. The endpoint may be given with or without
// a "unix://" scheme (e.g. "/run/containerd/containerd.sock").
func Dial(endpoint string) (*Client, error) {
	target := endpoint
	if !strings.Contains(target, "://") {
		target = "unix://" + target
	}

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial CRI endpoint %q: %w", endpoint, err)
	}

	return &Client{
		conn:    conn,
		runtime: runtimeapi.NewRuntimeServiceClient(conn),
		image:   runtimeapi.NewImageServiceClient(conn),
	}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Version verifies connectivity by calling the runtime Version RPC.
func (c *Client) Version(ctx context.Context) (string, error) {
	resp, err := c.runtime.Version(ctx, &runtimeapi.VersionRequest{})
	if err != nil {
		return "", fmt.Errorf("CRI Version: %w", err)
	}
	return fmt.Sprintf("%s %s", resp.RuntimeName, resp.RuntimeVersion), nil
}

// RunPodSandbox creates a pod sandbox with the given runtime handler and
// returns its ID. With handler="kata" this triggers the shim-v2 ->
// cloud-hypervisor boot exactly as kubelet would.
func (c *Client) RunPodSandbox(ctx context.Context, cfg *runtimeapi.PodSandboxConfig, handler string) (string, error) {
	resp, err := c.runtime.RunPodSandbox(ctx, &runtimeapi.RunPodSandboxRequest{
		Config:         cfg,
		RuntimeHandler: handler,
	})
	if err != nil {
		return "", fmt.Errorf("RunPodSandbox %q: %w", cfg.GetMetadata().GetName(), err)
	}
	return resp.PodSandboxId, nil
}

// StopPodSandbox stops the sandbox (and thus the VM). Safe on deferred-paused
// members: runtime-rs reaps the paused cloud-hypervisor on stop.
func (c *Client) StopPodSandbox(ctx context.Context, id string) error {
	if _, err := c.runtime.StopPodSandbox(ctx, &runtimeapi.StopPodSandboxRequest{PodSandboxId: id}); err != nil {
		return fmt.Errorf("StopPodSandbox %q: %w", id, err)
	}
	return nil
}

// RemovePodSandbox removes a stopped sandbox.
func (c *Client) RemovePodSandbox(ctx context.Context, id string) error {
	if _, err := c.runtime.RemovePodSandbox(ctx, &runtimeapi.RemovePodSandboxRequest{PodSandboxId: id}); err != nil {
		return fmt.Errorf("RemovePodSandbox %q: %w", id, err)
	}
	return nil
}

// PodSandboxReady reports whether the sandbox is in the READY state.
func (c *Client) PodSandboxReady(ctx context.Context, id string) (bool, error) {
	resp, err := c.runtime.PodSandboxStatus(ctx, &runtimeapi.PodSandboxStatusRequest{PodSandboxId: id})
	if err != nil {
		return false, fmt.Errorf("PodSandboxStatus %q: %w", id, err)
	}
	return resp.GetStatus().GetState() == runtimeapi.PodSandboxState_SANDBOX_READY, nil
}

// ListManagedPods returns the IDs of sandboxes carrying the given label filter.
// Used to adopt/reconcile pre-existing members after a manager restart.
func (c *Client) ListManagedPods(ctx context.Context, labels map[string]string) ([]*runtimeapi.PodSandbox, error) {
	resp, err := c.runtime.ListPodSandbox(ctx, &runtimeapi.ListPodSandboxRequest{
		Filter: &runtimeapi.PodSandboxFilter{LabelSelector: labels},
	})
	if err != nil {
		return nil, fmt.Errorf("ListPodSandbox: %w", err)
	}
	return resp.Items, nil
}

// CreateContainer creates a container inside a sandbox and returns its ID.
func (c *Client) CreateContainer(ctx context.Context, podID string, cfg *runtimeapi.ContainerConfig, sandboxCfg *runtimeapi.PodSandboxConfig) (string, error) {
	resp, err := c.runtime.CreateContainer(ctx, &runtimeapi.CreateContainerRequest{
		PodSandboxId:  podID,
		Config:        cfg,
		SandboxConfig: sandboxCfg,
	})
	if err != nil {
		return "", fmt.Errorf("CreateContainer in %q: %w", podID, err)
	}
	return resp.ContainerId, nil
}

// StartContainer starts a previously created container.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	if _, err := c.runtime.StartContainer(ctx, &runtimeapi.StartContainerRequest{ContainerId: id}); err != nil {
		return fmt.Errorf("StartContainer %q: %w", id, err)
	}
	return nil
}

// ExecSync runs a command synchronously in a container and returns its exit
// code. For Tier B this is the wake signal: an exec reaches the kata shim as
// StartProcess(Exec) and triggers wake_restore, resuming the paused VM.
func (c *Client) ExecSync(ctx context.Context, containerID string, cmd []string, timeout time.Duration) (int32, []byte, []byte, error) {
	resp, err := c.runtime.ExecSync(ctx, &runtimeapi.ExecSyncRequest{
		ContainerId: containerID,
		Cmd:         cmd,
		Timeout:     int64(timeout.Seconds()),
	})
	if err != nil {
		return -1, nil, nil, fmt.Errorf("ExecSync in %q: %w", containerID, err)
	}
	return resp.ExitCode, resp.Stdout, resp.Stderr, nil
}

// PullImage ensures an image is present and returns its resolved ref.
func (c *Client) PullImage(ctx context.Context, image string) (string, error) {
	resp, err := c.image.PullImage(ctx, &runtimeapi.PullImageRequest{
		Image: &runtimeapi.ImageSpec{Image: image},
	})
	if err != nil {
		return "", fmt.Errorf("PullImage %q: %w", image, err)
	}
	return resp.ImageRef, nil
}
