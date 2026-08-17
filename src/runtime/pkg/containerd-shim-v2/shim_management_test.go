// Copyright (c) 2020 Ant Financial
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/vcmock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServeMetrics(t *testing.T) {
	assert := assert.New(t)

	sandbox := &vcmock.Sandbox{
		MockID: testSandboxID,
	}

	s := &service{
		id:         testSandboxID,
		sandbox:    sandbox,
		containers: make(map[string]*container),
	}

	rr := httptest.NewRecorder()
	r := &http.Request{}

	// case 1: normal
	sandbox.GetAgentMetricsFunc = func() (string, error) {
		return `# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 23
`, nil
	}

	defer func() {
		sandbox.GetAgentMetricsFunc = nil
	}()

	s.serveMetrics(rr, r)
	assert.Equal(200, rr.Code, "response code should be 200")
	body := rr.Body.String()

	assert.Equal(true, strings.Contains(body, "kata_agent_go_threads 23\n"))

	// case 2: GetAgentMetricsFunc return error
	sandbox.GetAgentMetricsFunc = func() (string, error) {
		return "", fmt.Errorf("some error occurred")
	}

	s.serveMetrics(rr, r)
	assert.Equal(200, rr.Code, "response code should be 200")
	body = rr.Body.String()
	assert.Equal(true, len(strings.Split(body, "\n")) > 0)
}

func TestMakeConfigSelfContainedRemovesMemoryBackingAndPackagesErofsDisks(t *testing.T) {
	snapshotDir := t.TempDir()
	erofsDir := t.TempDir()
	stableDir := t.TempDir()

	memoryRanges := filepath.Join(snapshotDir, "memory-ranges")
	stableDisk := filepath.Join(stableDir, "kata-containers.img")
	lowerDisk := filepath.Join(erofsDir, "layer.erofs")
	writableDisk := filepath.Join(erofsDir, "rwlayer.img")
	prefixedLowerDisk := filepath.Join(erofsDir, "1-layer.erofs")
	prefixedWritableDisk := filepath.Join(erofsDir, "3-3-rwlayer.img")
	require.NoError(t, os.WriteFile(memoryRanges, []byte("memory"), 0o600))
	require.NoError(t, os.WriteFile(stableDisk, []byte("base image"), 0o600))
	require.NoError(t, os.WriteFile(lowerDisk, []byte("read-only layer"), 0o600))
	require.NoError(t, os.WriteFile(writableDisk, []byte("writable layer"), 0o600))
	require.NoError(t, os.WriteFile(prefixedLowerDisk, []byte("prefixed read-only layer"), 0o600))
	require.NoError(t, os.WriteFile(prefixedWritableDisk, []byte("prefixed writable layer"), 0o600))

	config := map[string]interface{}{
		"memory": map[string]interface{}{
			"zones": []interface{}{map[string]interface{}{"file": "/old/memory"}},
		},
		"disks": []interface{}{
			map[string]interface{}{"id": "_disk0", "path": stableDisk},
			map[string]interface{}{"id": "_disk3", "path": lowerDisk},
			map[string]interface{}{"id": "_disk4", "path": writableDisk},
			map[string]interface{}{"id": "_disk5", "path": prefixedLowerDisk},
			map[string]interface{}{"id": "_disk6", "path": prefixedWritableDisk},
		},
	}
	configJSON, err := json.Marshal(config)
	require.NoError(t, err)
	configPath := filepath.Join(snapshotDir, "config.json")
	require.NoError(t, os.WriteFile(configPath, configJSON, 0o600))

	require.NoError(t, makeConfigSelfContained(snapshotDir))

	var restoredConfig struct {
		Memory struct {
			Zones []map[string]interface{} `json:"zones"`
		} `json:"memory"`
		Disks []struct {
			ID   string `json:"id"`
			Path string `json:"path"`
		} `json:"disks"`
	}
	updatedConfig, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(updatedConfig, &restoredConfig))
	require.Len(t, restoredConfig.Memory.Zones, 1)
	assert.NotContains(t, restoredConfig.Memory.Zones[0], "file")
	require.Len(t, restoredConfig.Disks, 5)
	assert.Equal(t, stableDisk, restoredConfig.Disks[0].Path)

	expectedLowerDisk := filepath.Join(snapshotDir, "disks", "1-layer.erofs")
	expectedWritableDisk := filepath.Join(snapshotDir, "disks", "2-rwlayer.img")
	expectedPrefixedLowerDisk := filepath.Join(snapshotDir, "disks", "3-layer.erofs")
	expectedPrefixedWritableDisk := filepath.Join(snapshotDir, "disks", "4-rwlayer.img")
	assert.Equal(t, expectedLowerDisk, restoredConfig.Disks[1].Path)
	assert.Equal(t, expectedWritableDisk, restoredConfig.Disks[2].Path)
	assert.Equal(t, expectedPrefixedLowerDisk, restoredConfig.Disks[3].Path)
	assert.Equal(t, expectedPrefixedWritableDisk, restoredConfig.Disks[4].Path)

	require.NoError(t, os.RemoveAll(erofsDir))
	lowerContent, err := os.ReadFile(expectedLowerDisk)
	require.NoError(t, err)
	assert.Equal(t, "read-only layer", string(lowerContent))
	writableContent, err := os.ReadFile(expectedWritableDisk)
	require.NoError(t, err)
	assert.Equal(t, "writable layer", string(writableContent))
	prefixedLowerContent, err := os.ReadFile(expectedPrefixedLowerDisk)
	require.NoError(t, err)
	assert.Equal(t, "prefixed read-only layer", string(prefixedLowerContent))
	prefixedWritableContent, err := os.ReadFile(expectedPrefixedWritableDisk)
	require.NoError(t, err)
	assert.Equal(t, "prefixed writable layer", string(prefixedWritableContent))
}
