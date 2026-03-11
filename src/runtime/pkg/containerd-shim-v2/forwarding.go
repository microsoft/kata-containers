// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"net"
	"os"
	"strings"

	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/ttrpc"
)

const shimForwardAddressEnv = "KATA_SHIM_FORWARD_ADDRESS"

func (s *service) initForwardTaskClient() error {
	forwardAddress := strings.TrimSpace(os.Getenv(shimForwardAddressEnv))
	if forwardAddress == "" {
		return nil
	}

	socketPath := strings.TrimPrefix(forwardAddress, "unix://")
	if socketPath == "" {
		return nil
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return err
	}

	client := ttrpc.NewClient(conn)
	s.forwardTaskClient = taskAPI.NewTaskClient(client)
	s.forwardAddress = forwardAddress

	return nil
}

func (s *service) hasForwardTaskClient() bool {
	return s.forwardTaskClient != nil
}
