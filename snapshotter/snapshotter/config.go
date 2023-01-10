//go:build linux
// +build linux

/*
   Copyright The containerd Authors.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package snapshotter

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml"
)

// Config represents configuration options for the snapshotter.
type Config struct {
	// Root folder where the snapshotter stores all information.
	RootPath string `toml:"root_path"`

	// Path of the unix socket that the snapshotter listens to.
	SocketPath string `toml:"socket_path"`

	// Size of the read-write layer of a container
	ReadWriteLayerSizeInGB int64 `toml:"read_write_layer_size"`

	// Enable logging
	EnableLogging bool `toml:"enable_logging"`

	// Support regular containers
	SupportRegularContainers bool `toml:"support_regular_containers"`
}

// Default configuration
func DefaultConfig() *Config {
	return &Config{
		RootPath:                 "/var/lib/cc-snapshotter",
		SocketPath:               "/var/run/cc-snapshotter.sock",
		ReadWriteLayerSizeInGB:   128,
		EnableLogging:            true,
		SupportRegularContainers: true,
	}
}

// Load a config from given toml file.
func LoadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}

		return nil, err
	}

	config := Config{}
	file, err := toml.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open configuration file: %s: %w", path, err)
	}

	if err := file.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration TOML: %w", err)
	}

	if err := config.validateAndProcess(); err != nil {
		return nil, err
	}

	return &config, nil
}

// Validate and process loaded config.
func (c *Config) validateAndProcess() error {
	return nil
}
