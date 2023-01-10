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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

const MANIFEST_VERSION = "0.2"

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//! The names of these fields must not be changed without fixing virtcontainer.go !!!
type ImageInfo struct {
	// The OCI Image Ref of the image
	ImageRef string

	// The Raw Manifest of the image
	ManifestRaw []byte

	// The digest of the manifest
	ManifestDigest string

	// The digest of the image's OCI config
	ConfigDigest string

	// The RAW bytes of the OCI Config json
	ConfigRaw []byte
}

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//! The names of these fields must not be changed without fixing virtcontainer.go !!!
type ImageManifest struct {
	Version string

	// Path to disk image/device for each layer
	Layers []string

	// DMVerity root hash for each layer
	RootHashes []string

	// DiffID for each layer
	DiffIDs []string

	// ChainID for each layer
	ChainIDs []string

	// Path to disk image/device for the read-write top layer
	RWLayer string

	// The OCI Image Ref of the image
	ImageRef string

	// The Raw Manifest of the image
	ManifestRaw []byte

	// The digest of the manifest
	ManifestDigest string

	// The digest of the image's OCI config
	ConfigDigest string

	// The RAW bytes of the OCI Config json
	ConfigRaw []byte

	// List of images that share the same root-fs (ie topmost chain-id)
	ImageInfos []ImageInfo
}

func DefaultManifest() ImageManifest {
	return ImageManifest{
		Version: MANIFEST_VERSION,
	}
}

func (m *ImageManifest) Read(path string) error {
	jsonText, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("ImageManifest.Read failed. %w", err)
	}

	if err := json.Unmarshal(jsonText, &m); err != nil {
		return fmt.Errorf("ImageManifest.Read failed. %w", err)
	}

	return nil
}

func (m *ImageManifest) IsValid() bool {
	if m.Version != MANIFEST_VERSION {
		return false
	}

	// Ensure that layer information arrays have same length
	if len(m.Layers) != len(m.DiffIDs) || len(m.Layers) != len(m.DiffIDs) || len(m.Layers) != len(m.ChainIDs) {
		return false
	}

	if len(m.Layers) == 0 {
		return false
	}

	// Ensure that the disk images exist
	for i, layer := range m.Layers {
		_, err := os.Stat(layer)
		if err != nil {
			return false
		}

		// Ensure that diff ids and root hashes are non empty
		if len(m.RootHashes[i]) == 0 || len(m.DiffIDs[i]) == 0 || len(m.ChainIDs[i]) == 0 {
			return false
		}
	}

	// RWLayer doesn't need to be checked since it is set only
	// during container instantiation time.

	if len(m.ImageRef) == 0 {
		return false
	}

	// Check manifest and digest
	// TODO: See if we need to ensure that the digest matches manifest.
	if len(m.ManifestRaw) == 0 || len(m.ManifestDigest) == 0 {
		return false
	}

	// Check config and digest
	if len(m.ConfigRaw) == 0 || len(m.ConfigDigest) == 0 {
		return false
	}

	// Ensure that there is atleast one image info.
	if len(m.ImageInfos) == 0 {
		return false
	}

	return true
}

func (m *ImageManifest) Write(path string) error {
	jsonText, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("ImageManifest.Write failed. %w", err)
	}
	if LoggingEnabled {
		fmt.Printf("%s\n", jsonText)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0644); err != nil {
		return fmt.Errorf("ImageManifest.Write failed. %w", err)
	}

	if err := ioutil.WriteFile(path, jsonText, 0644); err != nil {
		return err
	}

	return nil
}
