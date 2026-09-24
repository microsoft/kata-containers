// Copyright © 2026, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

package pool

import (
	"fmt"
	"os"

	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"sigs.k8s.io/yaml"
)

// LoadPodSandboxConfig reads a CRI PodSandboxConfig from a YAML or JSON file.
// Field names follow the CRI proto JSON (snake_case), matching crictl's own
// pod config files.
func LoadPodSandboxConfig(path string) (*runtimeapi.PodSandboxConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pod config %q: %w", path, err)
	}
	var cfg runtimeapi.PodSandboxConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse pod config %q: %w", path, err)
	}
	return &cfg, nil
}

// LoadContainerConfig reads a CRI ContainerConfig from a YAML or JSON file,
// matching crictl's own container config files.
func LoadContainerConfig(path string) (*runtimeapi.ContainerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read container config %q: %w", path, err)
	}
	var cfg runtimeapi.ContainerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse container config %q: %w", path, err)
	}
	return &cfg, nil
}
