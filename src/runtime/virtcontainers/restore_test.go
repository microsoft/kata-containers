package virtcontainers

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	persistapi "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/persist/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRestoreOptsApplyHypervisorOverrides(t *testing.T) {
	config := HypervisorConfig{
		HypervisorPath:       "/snapshot/cloud-hypervisor",
		KernelPath:           "/snapshot/vmlinuz",
		ImagePath:            "/snapshot/image",
		ClhMemoryRestoreMode: ClhMemoryRestoreModeCopy,
	}
	opts := RestoreOpts{
		HypervisorPath:       "/current/cloud-hypervisor",
		KernelPath:           "/current/vmlinuz",
		ImagePath:            "/current/image",
		DisableSeccomp:       true,
		ClhMemoryRestoreMode: ClhMemoryRestoreModeCopyOnWrite,
	}

	opts.applyHypervisorOverrides(&config)

	assert.Equal(t, opts.HypervisorPath, config.HypervisorPath)
	assert.Equal(t, opts.KernelPath, config.KernelPath)
	assert.Equal(t, opts.ImagePath, config.ImagePath)
	assert.True(t, config.DisableSeccomp)
	assert.Equal(t, opts.ClhMemoryRestoreMode, config.ClhMemoryRestoreMode)
}

func TestRekeySandboxAgentContainerIDMap(t *testing.T) {
	const (
		originalPauseID    = "original-pause"
		originalWorkloadID = "original-workload"
		firstPauseID       = "first-pause"
		firstWorkloadID    = "first-workload"
		secondPauseID      = "second-pause"
	)

	tests := []struct {
		name          string
		state         persistapi.SandboxState
		newID         string
		expectedMap   map[string]string
		expectedPaths map[string]string
	}{
		{
			name: "first restore initializes canonical agent IDs",
			state: persistapi.SandboxState{
				SandboxContainer: originalPauseID,
				Config: persistapi.SandboxConfig{ContainerConfigs: []persistapi.ContainerConfig{
					{
						ID: originalPauseID,
						Annotations: map[string]string{
							criContainerTypeAnnotation: criSandboxType,
						},
					},
					{ID: originalWorkloadID},
				}},
			},
			newID: firstPauseID,
			expectedMap: map[string]string{
				firstPauseID:       originalPauseID,
				originalWorkloadID: originalWorkloadID,
			},
			expectedPaths: map[string]string{
				ociBundlePathAnnotation: filepath.Join(containerdBundleBase, firstPauseID),
				criSandboxIDAnnotation:  firstPauseID,
			},
		},
		{
			name: "recursive restore retains canonical agent IDs",
			state: persistapi.SandboxState{
				SandboxContainer: firstPauseID,
				AgentContainerIDMap: map[string]string{
					firstPauseID:    originalPauseID,
					firstWorkloadID: originalWorkloadID,
				},
				Config: persistapi.SandboxConfig{ContainerConfigs: []persistapi.ContainerConfig{
					{
						ID: firstPauseID,
						Annotations: map[string]string{
							criContainerTypeAnnotation: criSandboxType,
						},
					},
					{ID: firstWorkloadID},
				}},
			},
			newID: secondPauseID,
			expectedMap: map[string]string{
				secondPauseID:   originalPauseID,
				firstWorkloadID: originalWorkloadID,
			},
			expectedPaths: map[string]string{
				ociBundlePathAnnotation: filepath.Join(containerdBundleBase, secondPauseID),
				criSandboxIDAnnotation:  secondPauseID,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, rekeySandboxAgentContainerIDMap(&test.state, test.newID))
			assert.Equal(t, test.newID, test.state.SandboxContainer)
			assert.Equal(t, test.expectedMap, test.state.AgentContainerIDMap)
			require.NotEmpty(t, test.state.Config.ContainerConfigs)
			assert.Equal(t, test.newID, test.state.Config.ContainerConfigs[0].ID)
			for key, value := range test.expectedPaths {
				assert.Equal(t, value, test.state.Config.ContainerConfigs[0].Annotations[key])
			}
		})
	}
}

func TestRekeyWorkloadAgentContainerID(t *testing.T) {
	sandbox := &Sandbox{agentContainerIDMap: map[string]string{
		"first-workload": "original-workload",
	}}

	agentID, err := sandbox.rekeyAgentContainerID("first-workload", "second-workload")
	require.NoError(t, err)
	assert.Equal(t, "original-workload", agentID)
	assert.Equal(t, map[string]string{"second-workload": "original-workload"}, sandbox.agentContainerIDMap)
}

func TestAgentContainerIDMapPersistence(t *testing.T) {
	source := &Sandbox{
		id: "host-sandbox",
		agentContainerIDMap: map[string]string{
			"host-sandbox":  "agent-sandbox",
			"host-workload": "agent-workload",
		},
	}
	persisted := persistapi.SandboxState{}
	source.dumpState(&persisted, map[string]persistapi.ContainerState{})

	source.agentContainerIDMap["host-workload"] = "changed-source"
	assert.Equal(t, "agent-workload", persisted.AgentContainerIDMap["host-workload"])

	restored := &Sandbox{}
	restored.loadState(persisted)
	persisted.AgentContainerIDMap["host-workload"] = "changed-persisted"
	assert.Equal(t, "agent-workload", restored.agentContainerIDMap["host-workload"])
}

func TestContainerAgentIDUsesSandboxMap(t *testing.T) {
	originalVirtLog := virtLog
	var logOutput bytes.Buffer
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)
	logger.SetOutput(&logOutput)
	virtLog = logrus.NewEntry(logger)
	t.Cleanup(func() { virtLog = originalVirtLog })

	sandbox := &Sandbox{agentContainerIDMap: map[string]string{
		"host-workload": "agent-workload",
	}}
	container := &Container{
		id:      "host-workload",
		sandbox: sandbox,
		process: Process{Token: "stale-process-token"},
	}

	assert.Equal(t, "agent-workload", container.agentID())
	assert.Empty(t, logOutput.String())

	delete(sandbox.agentContainerIDMap, container.id)
	assert.Equal(t, "host-workload", container.agentID())
	assert.Contains(t, logOutput.String(), "container has no canonical agent ID in the agent container ID map")

	logOutput.Reset()
	sandbox.agentContainerIDMap[container.id] = ""
	assert.Equal(t, "host-workload", container.agentID())
	assert.Contains(t, logOutput.String(), "container has no canonical agent ID in the agent container ID map")

	logOutput.Reset()
	container.sandbox = &Sandbox{}
	assert.Equal(t, "host-workload", container.agentID())
	assert.Empty(t, logOutput.String())
}

func TestRestoreContainerRekeysAgentContainerID(t *testing.T) {
	sandbox := newRestoreIdentityTestSandbox(t, "restore-map-success")
	defer cleanUp()

	container, err := sandbox.RestoreContainer(context.Background(), restoredWorkloadConfig("new-workload"))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"restore-map-success": "agent-pause",
		"new-workload":        "agent-workload",
	}, sandbox.agentContainerIDMap)
	assert.Equal(t, "new-workload", sandbox.config.Containers[1].ID)
	assert.Equal(t, "agent-workload", container.(*Container).process.Token)
	assert.Equal(t, "agent-workload", container.(*Container).agentID())
}

func TestRestoreContainerRollsBackAgentContainerID(t *testing.T) {
	sandbox := newRestoreIdentityTestSandbox(t, "restore-map-rollback")
	defer cleanUp()
	sandbox.store = failingPersistDriver{PersistDriver: sandbox.store}

	_, err := sandbox.RestoreContainer(context.Background(), restoredWorkloadConfig("new-workload"))
	require.ErrorContains(t, err, "persist adopted container mapping")
	assert.Equal(t, map[string]string{
		"restore-map-rollback": "agent-pause",
		"old-workload":         "agent-workload",
	}, sandbox.agentContainerIDMap)
	assert.Equal(t, "old-workload", sandbox.config.Containers[1].ID)
	assert.NotContains(t, sandbox.containers, "new-workload")
}

func newRestoreIdentityTestSandbox(t *testing.T, sandboxID string) *Sandbox {
	t.Helper()
	sandbox, err := testCreateSandbox(t, sandboxID, MockHypervisor, newHypervisorConfig(nil, nil), NetworkConfig{}, nil, nil)
	require.NoError(t, err)
	sandbox.config.Containers = []ContainerConfig{
		{ID: sandboxID},
		{
			ID: "old-workload",
			Annotations: map[string]string{
				criContainerNameAnnotation: "busybox",
			},
		},
	}
	sandbox.containers = map[string]*Container{
		sandboxID: {
			id:      sandboxID,
			sandbox: sandbox,
			config:  &sandbox.config.Containers[0],
		},
	}
	sandbox.agentContainerIDMap = map[string]string{
		sandboxID:      "agent-pause",
		"old-workload": "agent-workload",
	}
	return sandbox
}

func restoredWorkloadConfig(id string) ContainerConfig {
	return ContainerConfig{
		ID: id,
		Annotations: map[string]string{
			criContainerNameAnnotation: "busybox",
		},
	}
}

type failingPersistDriver struct {
	persistapi.PersistDriver
}

func (failingPersistDriver) ToDisk(persistapi.SandboxState, map[string]persistapi.ContainerState) error {
	return errors.New("injected persistence failure")
}
