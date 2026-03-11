// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"fmt"
	"net"
	"os"
	sysexec "os/exec"
	"strings"
	"time"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/ttrpc"
)

const (
	shimForwardAddressEnv           = "KATA_SHIM_FORWARD_ADDRESS"
	shimForwardDownstreamIDEnv      = "KATA_SHIM_FORWARD_DOWNSTREAM_ID"
	shimForwardContainerdAddressEnv = "KATA_SHIM_FORWARD_CONTAINERD_ADDRESS"
	shimForwardPublishBinaryEnv     = "KATA_SHIM_FORWARD_PUBLISH_BINARY"
	shimForwardNamespaceEnv         = "KATA_SHIM_FORWARD_NAMESPACE"

	shimForwardDownstreamIDDefault      = "81f5e4319ce0d82748b32eff4e69130d238e8a7bc5fbe9d036bd03d3cae67b0d"
	shimForwardContainerdAddressDefault = "/run/containerd/containerd.sock"
	shimForwardPublishBinaryDefault     = "/opt/kata/bin/containerd-shim-kata-v2"
	shimForwardNamespaceDefault         = "k8s.io"

	shimForwardConnectTimeout = 250 * time.Millisecond
	shimForwardReadyTimeout   = 10 * time.Second
	shimForwardReadyPoll      = 100 * time.Millisecond
)

func (s *service) initForwardTaskClient(id string) error {
	/*
	forwardAddress := strings.TrimSpace(os.Getenv(shimForwardAddressEnv))
	if forwardAddress == "" {
		return nil
	}
	*/
	if id == shimForwardDownstreamIDDefault {
		return nil
	}
	forwardAddress := shimForwardContainerdAddressDefault

	socketPath := strings.TrimPrefix(forwardAddress, "unix://")
	if socketPath == "" {
		return nil
	}

	conn, err := net.DialTimeout("unix", socketPath, shimForwardConnectTimeout)
	if err != nil {
		if autoStartErr := s.startForwardDownstreamShim(); autoStartErr != nil {
			return fmt.Errorf("connect downstream shim %q failed: %w (autostart error: %v)", forwardAddress, err, autoStartErr)
		}

		conn, err = s.waitAndDialForwardSocket(socketPath)
		if err != nil {
			return fmt.Errorf("connect downstream shim after autostart %q failed: %w", forwardAddress, err)
		}
	}

	client := ttrpc.NewClient(conn)
	s.forwardTaskClient = taskAPI.NewTaskClient(client)
	s.forwardAddress = forwardAddress

	return nil
}

func (s *service) hasForwardTaskClient() bool {
	return s.forwardTaskClient != nil
}

func (s *service) waitAndDialForwardSocket(socketPath string) (net.Conn, error) {
	deadline := time.Now().Add(shimForwardReadyTimeout)

	for {
		conn, err := net.DialTimeout("unix", socketPath, shimForwardConnectTimeout)
		if err == nil {
			return conn, nil
		}

		if time.Now().After(deadline) {
			return nil, err
		}

		time.Sleep(shimForwardReadyPoll)
	}
}

func (s *service) startForwardDownstreamShim() error {
	if s.forwardShimCmd != nil && s.forwardShimCmd.Process != nil {
		return nil
	}

	downstreamID := readForwardSetting(shimForwardDownstreamIDEnv, shimForwardDownstreamIDDefault)
	containerdAddress := readForwardSetting(shimForwardContainerdAddressEnv, shimForwardContainerdAddressDefault)
	publishBinary := readForwardSetting(shimForwardPublishBinaryEnv, shimForwardPublishBinaryDefault)
	namespace := readForwardSetting(shimForwardNamespaceEnv, shimForwardNamespaceDefault)

	cmd := sysexec.Command(publishBinary,
		"-namespace", namespace,
		"-address", containerdAddress,
		"-publish-binary", publishBinary,
		"-id", downstreamID,
		"-debug",
	)
	cmd.Env = sanitizeForwardEnv(os.Environ())

	if err := cmd.Start(); err != nil {
		return err
	}

	s.forwardShimCmd = cmd
	shimLog.WithFields(map[string]interface{}{
		"pid":               cmd.Process.Pid,
		"downstream-id":     downstreamID,
		"containerd-address": containerdAddress,
		"namespace":         namespace,
	}).Info("started downstream shim for request forwarding")

	go func() {
		if waitErr := cmd.Wait(); waitErr != nil {
			shimLog.WithError(waitErr).Warn("forwarded downstream shim exited")
		}
	}()

	return nil
}

func readForwardSetting(envName, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return defaultValue
	}

	return value
}

func sanitizeForwardEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, item := range env {
		if strings.HasPrefix(item, "KATA_SHIM_FORWARD_") {
			continue
		}
		filtered = append(filtered, item)
	}

	return filtered
}
