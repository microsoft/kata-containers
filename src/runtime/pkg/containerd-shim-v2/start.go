// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"context"
	"fmt"
	"time"

	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/types/task"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
)

func startContainer(ctx context.Context, s *service, c *container) (retErr error) {
	shimLog.WithField("container", c.id).Debug("start container")
	defer func() {
		if retErr != nil {
			// notify the wait goroutine to continue
			select {
			case c.exitCh <- exitCode255:
			default:
			}
		}
	}()
	// start a container
	if c.cType == "" {
		err := fmt.Errorf("Bug, the container %s type is empty", c.id)
		return err
	}

	if s.sandbox == nil {
		err := fmt.Errorf("Bug, the sandbox hasn't been created for this container %s", c.id)
		return err
	}
	if s.restoreFailed {
		return fmt.Errorf("kata restore failed: pod sandbox restore is terminal; recreate the pod sandbox")
	}

	if c.cType.IsSandbox() && s.restoredSandbox {
		c.status = task.Status_RUNNING
		c.restorePauseIOArmPending = true
		return nil
	}

	if c.cType.IsSandbox() {
		if err := s.sandbox.Start(ctx); err != nil {
			return err
		}
		var err error
		s.monitor, err = s.sandbox.Monitor(ctx)
		if err != nil {
			return err
		}
		go watchSandbox(ctx, s)

		// If no network endpoints were discovered during sandbox creation,
		// schedule an async rescan. This handles runtimes that configure
		// networking after task creation (e.g. Docker 26+ configures
		// networking after the Start response, and prestart hooks may
		// not have run yet on slower architectures).
		// RescanNetwork is idempotent — it returns immediately if
		// endpoints already exist.
		go func() {
			if err := s.sandbox.RescanNetwork(s.ctx); err != nil {
				shimLog.WithError(err).Error("async network rescan failed — container may lack networking")
			}
		}()

		go watchOOMEvents(ctx, s)
	} else if s.restoredSandbox {
		// The first workload start resumes the VM and restores its network
		// identity; later workload starts find the guest already live.
		if !s.restoreFinalized {
			defer func() {
				if retErr != nil && !s.restoreFinalized {
					s.failRestoredSandbox(retErr)
				}
			}()
			if err := s.sandbox.FinalizeRestoreNetwork(ctx); err != nil {
				return err
			}
			var err error
			s.monitor, err = s.sandbox.Monitor(ctx)
			if err != nil {
				return err
			}
			go watchSandbox(ctx, s)
			go watchOOMEvents(ctx, s)
			if err := armDeferredRestoredPauseTask(ctx, s); err != nil {
				return err
			}
			s.restoreFinalized = true
		}
	} else if _, err := s.sandbox.StartContainer(ctx, c.id); err != nil {
		return err
	}

	err := katautils.EnterNetNS(s.sandbox.GetNetNs(), func() error {
		return katautils.PostStartHooks(ctx, *c.spec, s.sandbox.ID(), c.bundle)
	})
	if err != nil {
		// log warning and continue, as defined in oci runtime spec
		// https://github.com/opencontainers/runtime-spec/blob/master/runtime.md#lifecycle
		shimLog.WithError(err).Warn("Failed to run post-start hooks")
	}

	c.status = task.Status_RUNNING

	stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, c.id)
	if err != nil {
		return err
	}

	c.stdinPipe = stdin

	if c.stdin != "" || c.stdout != "" || c.stderr != "" {
		tty, err := newTtyIO(ctx, s.namespace, c.id, c.stdin, c.stdout, c.stderr, c.terminal)
		if err != nil {
			return err
		}
		c.ttyio = tty

		go ioCopy(shimLog.WithField("container", c.id), c.exitIOch, c.stdinCloser, tty, stdin, stdout, stderr)
	} else {
		// close the io exit channel, since there is no io for this container,
		// otherwise the following wait goroutine will hang on this channel.
		close(c.exitIOch)
		// close the stdin closer channel to notify that it's safe to close process's
		// io.
		close(c.stdinCloser)
	}

	go wait(ctx, s, c, "")

	return nil
}

const restoredSandboxFailureCleanupTimeout = 30 * time.Second

// failRestoredSandbox makes a failed first workload start fatal to the pause
// task. CRI must recreate the pod sandbox rather than retry adoption in a VM
// that has already been stopped.
func (s *service) failRestoredSandbox(cause error) {
	if s.restoreFailed {
		return
	}
	s.restoreFailed = true

	cleanupCtx, cancel := context.WithTimeout(context.Background(), restoredSandboxFailureCleanupTimeout)
	defer cancel()
	shimLog.WithError(cause).Error("restored sandbox failed before first workload start completed")
	abortErr := s.sandbox.AbortRestore(cleanupCtx)
	if abortErr != nil {
		shimLog.WithError(abortErr).Warn("failed to abort terminal restored sandbox")
		return
	}
	if err := s.sandbox.Delete(cleanupCtx); err != nil {
		shimLog.WithError(err).Warn("failed to delete terminal restored sandbox")
	}

	exitedAt := time.Now()
	var pauseTask *container
	for _, taskContainer := range s.containers {
		taskContainer.status = task.Status_STOPPED
		taskContainer.exit = exitCode255
		taskContainer.exitTime = exitedAt
		select {
		case taskContainer.exitCh <- exitCode255:
		default:
		}
		if taskContainer.cType.IsSandbox() {
			pauseTask = taskContainer
		}
	}
	if pauseTask != nil {
		s.send(&eventstypes.TaskExit{
			ContainerID: pauseTask.id,
			ID:          pauseTask.id,
			Pid:         s.hpid,
			ExitStatus:  exitCode255,
			ExitedAt:    timestamppb.New(exitedAt),
		})
	}
}

// armDeferredRestoredPauseTask attaches pause-task I/O after the restored VM is resumed.
func armDeferredRestoredPauseTask(ctx context.Context, s *service) error {
	c := s.containers[s.id]
	if c == nil || !c.cType.IsSandbox() {
		return fmt.Errorf("kata restore failed: pause task %s is not registered", s.id)
	}
	if !c.restorePauseIOArmPending {
		return fmt.Errorf("kata restore failed: pause task %s is not pending IO arming", c.id)
	}

	stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, c.id)
	if err != nil {
		return fmt.Errorf("kata restore failed: open pause task IO: %w", err)
	}
	c.stdinPipe = stdin
	if c.stdin != "" || c.stdout != "" || c.stderr != "" {
		tty, err := newTtyIO(ctx, s.namespace, c.id, c.stdin, c.stdout, c.stderr, c.terminal)
		if err != nil {
			return fmt.Errorf("kata restore failed: create pause task IO: %w", err)
		}
		c.ttyio = tty
		go ioCopy(shimLog.WithField("container", c.id), c.exitIOch, c.stdinCloser, tty, stdin, stdout, stderr)
	} else {
		close(c.exitIOch)
		close(c.stdinCloser)
	}
	go wait(ctx, s, c, "")
	c.restorePauseIOArmPending = false
	return nil
}

func startExec(ctx context.Context, s *service, containerID, execID string) (e *exec, retErr error) {
	shimLog.WithFields(logrus.Fields{
		"container": containerID,
		"exec":      execID,
	}).Debug("start container execution")
	// start an exec
	c, err := s.getContainer(containerID)
	if err != nil {
		return nil, err
	}

	execs, err := c.getExec(execID)
	if err != nil {
		return nil, err
	}

	defer func() {
		if retErr != nil {
			// notify the wait goroutine to continue
			execs.exitCh <- exitCode255
		}
	}()

	_, proc, err := s.sandbox.EnterContainer(ctx, containerID, *execs.cmds)
	if err != nil {
		err := fmt.Errorf("cannot enter container %s, with err %s", containerID, err)
		return nil, err
	}
	execs.id = proc.Token

	execs.status = task.Status_RUNNING
	if execs.tty.height != 0 && execs.tty.width != 0 {
		err = s.sandbox.WinsizeProcess(ctx, c.id, execs.id, execs.tty.height, execs.tty.width)
		if err != nil {
			return nil, err
		}
	}

	stdin, stdout, stderr, err := s.sandbox.IOStream(c.id, execs.id)
	if err != nil {
		return nil, err
	}

	execs.stdinPipe = stdin

	tty, err := newTtyIO(ctx, s.namespace, execs.id, execs.tty.stdin, execs.tty.stdout, execs.tty.stderr, execs.tty.terminal)
	if err != nil {
		return nil, err
	}
	execs.ttyio = tty

	go ioCopy(shimLog.WithFields(logrus.Fields{
		"container": c.id,
		"exec":      execID,
	}), execs.exitIOch, execs.stdinCloser, tty, stdin, stdout, stderr)

	go wait(ctx, s, c, execID)

	return execs, nil
}
