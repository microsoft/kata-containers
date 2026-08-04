// Copyright (c) 2017 Intel Corporation
// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"errors"
	"testing"

	eventstypes "github.com/containerd/containerd/api/events"
	taskAPI "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/namespaces"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	vcAnnotations "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/annotations"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartRestoredWorkloadFailureExitsSandbox(t *testing.T) {
	finalizeErr := errors.New("restore network rewiring failed")
	stopped := false
	deleted := false
	sandbox := &vcmock.Sandbox{
		MockID: testSandboxID,
		FinalizeRestoreNetworkFunc: func() error {
			return finalizeErr
		},
		AbortRestoreFunc: func() error {
			stopped = true
			return nil
		},
		DeleteFunc: func() error {
			deleted = true
			return nil
		},
	}
	s := &service{
		id:              testSandboxID,
		sandbox:         sandbox,
		restoredSandbox: true,
		containers:      make(map[string]*container),
		events:          make(chan interface{}, 1),
		ctx:             namespaces.WithNamespace(context.Background(), "UnitTest"),
		hpid:            1234,
	}

	pause, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testSandboxID}, vc.PodSandbox, nil, false)
	require.NoError(t, err)
	pause.status = task.Status_CREATED
	workload, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testContainerID}, vc.PodContainer, nil, false)
	require.NoError(t, err)
	s.containers[pause.id] = pause
	s.containers[workload.id] = workload

	err = startContainer(context.Background(), s, workload)
	require.ErrorIs(t, err, finalizeErr)
	assert.True(t, s.restoreFailed)
	assert.True(t, stopped)
	assert.True(t, deleted)
	assert.Equal(t, task.Status_STOPPED, pause.status)
	assert.Equal(t, task.Status_STOPPED, workload.status)

	event := <-s.events
	exitEvent, ok := event.(*eventstypes.TaskExit)
	require.True(t, ok)
	assert.Equal(t, testSandboxID, exitEvent.ContainerID)
	assert.Equal(t, uint32(exitCode255), exitEvent.ExitStatus)

	err = startContainer(context.Background(), s, workload)
	assert.ErrorContains(t, err, "pod sandbox restore is terminal")
}

func TestFailedRestoredSandboxDoesNotPublishExitWhenStopFails(t *testing.T) {
	stopErr := errors.New("VMM could not be stopped")
	sandbox := &vcmock.Sandbox{
		MockID: testSandboxID,
		FinalizeRestoreNetworkFunc: func() error {
			return errors.New("restore network rewiring failed")
		},
		AbortRestoreFunc: func() error {
			return stopErr
		},
	}
	s := &service{
		id:              testSandboxID,
		sandbox:         sandbox,
		restoredSandbox: true,
		containers:      make(map[string]*container),
		events:          make(chan interface{}, 1),
		ctx:             namespaces.WithNamespace(context.Background(), "UnitTest"),
	}
	pause, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testSandboxID}, vc.PodSandbox, nil, false)
	require.NoError(t, err)
	workload, err := newContainer(s, &taskAPI.CreateTaskRequest{ID: testContainerID}, vc.PodContainer, nil, false)
	require.NoError(t, err)
	s.containers[pause.id] = pause
	s.containers[workload.id] = workload

	require.Error(t, startContainer(context.Background(), s, workload))
	assert.True(t, s.restoreFailed)
	assert.Equal(t, task.Status_CREATED, pause.status)
	select {
	case event := <-s.events:
		t.Fatalf("published false terminal event while VMM stop failed: %T", event)
	default:
	}
}

func TestStartStartSandboxSuccess(t *testing.T) {
	assert := assert.New(t)
	var err error

	sandbox := &vcmock.Sandbox{
		MockID: testSandboxID,
	}

	sandbox.StatusContainerFunc = func(contID string) (vc.ContainerStatus, error) {
		return vc.ContainerStatus{
			ID: sandbox.ID(),
			Annotations: map[string]string{
				vcAnnotations.ContainerTypeKey: string(vc.PodSandbox),
			},
		}, nil
	}

	defer func() {
		sandbox.StatusContainerFunc = nil
	}()

	s := &service{
		id:         testSandboxID,
		sandbox:    sandbox,
		containers: make(map[string]*container),
		ctx:        namespaces.WithNamespace(context.Background(), "UnitTest"),
	}

	reqCreate := &taskAPI.CreateTaskRequest{
		ID: testSandboxID,
	}
	s.containers[testSandboxID], err = newContainer(s, reqCreate, vc.PodSandbox, nil, false)
	assert.NoError(err)

	reqStart := &taskAPI.StartRequest{
		ID: testSandboxID,
	}

	sandbox.StartFunc = func() error {
		return nil
	}

	defer func() {
		sandbox.StartFunc = nil
	}()

	ctx := namespaces.WithNamespace(context.Background(), "UnitTest")
	_, err = s.Start(ctx, reqStart)
	assert.NoError(err)
}

func TestStartMissingAnnotation(t *testing.T) {
	assert := assert.New(t)
	var err error

	sandbox := &vcmock.Sandbox{
		MockID: testSandboxID,
	}

	sandbox.StatusContainerFunc = func(contID string) (vc.ContainerStatus, error) {
		return vc.ContainerStatus{
			ID:          sandbox.ID(),
			Annotations: map[string]string{},
		}, nil
	}

	defer func() {
		sandbox.StatusContainerFunc = nil
	}()

	s := &service{
		id:         testSandboxID,
		sandbox:    sandbox,
		containers: make(map[string]*container),
		ctx:        namespaces.WithNamespace(context.Background(), "UnitTest"),
	}

	reqCreate := &taskAPI.CreateTaskRequest{
		ID: testSandboxID,
	}
	s.containers[testSandboxID], err = newContainer(s, reqCreate, "", nil, false)
	assert.NoError(err)

	reqStart := &taskAPI.StartRequest{
		ID: testSandboxID,
	}

	sandbox.StartFunc = func() error {
		return nil
	}

	defer func() {
		sandbox.StartFunc = nil
	}()

	_, err = s.Start(s.ctx, reqStart)
	assert.Error(err)
	assert.False(vcmock.IsMockError(err))
}

func TestStartStartContainerSucess(t *testing.T) {
	assert := assert.New(t)
	var err error

	sandbox := &vcmock.Sandbox{
		MockID: testSandboxID,
	}

	sandbox.MockContainers = []*vcmock.Container{
		{
			MockID:      testContainerID,
			MockSandbox: sandbox,
		},
	}

	sandbox.StatusContainerFunc = func(contID string) (vc.ContainerStatus, error) {
		return vc.ContainerStatus{
			ID: testContainerID,
			Annotations: map[string]string{
				vcAnnotations.ContainerTypeKey: string(vc.PodContainer),
			},
		}, nil
	}

	defer func() {
		sandbox.StatusContainerFunc = nil
	}()

	sandbox.StartContainerFunc = func(contID string) (vc.VCContainer, error) {
		return sandbox.MockContainers[0], nil
	}

	defer func() {
		sandbox.StartContainerFunc = nil
	}()

	s := &service{
		id:         testSandboxID,
		sandbox:    sandbox,
		containers: make(map[string]*container),
		ctx:        namespaces.WithNamespace(context.Background(), "UnitTest"),
	}

	reqCreate := &taskAPI.CreateTaskRequest{
		ID: testContainerID,
	}
	s.containers[testContainerID], err = newContainer(s, reqCreate, vc.PodContainer, nil, false)
	assert.NoError(err)

	reqStart := &taskAPI.StartRequest{
		ID: testContainerID,
	}

	ctx := namespaces.WithNamespace(context.Background(), "UnitTest")
	_, err = s.Start(ctx, reqStart)
	assert.NoError(err)
}
