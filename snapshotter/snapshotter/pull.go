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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	log "github.com/sirupsen/logrus"
)

// Fetch image from reference
func fetchImage(image string) (img v1.Image, err error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %s. %w", image, err)
	}

	img, err = remote.Image(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch image %q, make sure it exists. %w", image, err)
	}
	conf, _ := img.ConfigName()
	log.Debugf("Image id: %s", conf.String())
	return
}

func layerDiskImageName(chainId string) string {
	return strings.Split(chainId, ":")[1] + ".disk"
}

func layerManifestName(chainId string) string {
	return strings.Split(chainId, ":")[1] + ".json"
}

func moveFile(src string, dest string) error {
	// Try renaming file
	err := os.Rename(src, dest)
	if err == nil {
		return nil
	}

	// Rename failed. Copy file
	in, err := os.Open(src)
	if err != nil {
		return err
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, in)
	return err
}

// Download a given layer and convert it to a disk image. Return the root hash.
func downloadLayer(layerChainId string, layerNumber int, layer v1.Layer, storagePath string) (string, error) {
	diskImageName := layerDiskImageName(layerChainId)
	diskImagePath := filepath.Join(storagePath, diskImageName)

	// Check if the layer has already been downloaded.
	if _, err := os.Stat(diskImagePath); err == nil {
		rootHash, err := ReadRootHash(diskImagePath)
		if err == nil {
			fmt.Printf("Layer #%d, skipping pull of %s\n", layerNumber, diskImagePath)
			return rootHash, nil
		}
	}

	rc, err := layer.Uncompressed()
	if err != nil {
		return "", fmt.Errorf("failed to uncompress layer %s. %w", layerChainId, err)
	}

	// Use a temporary file for the download.
	tmpfile, err := ioutil.TempFile("", diskImageName)
	if err != nil {
		return "", fmt.Errorf("failed to temporary file for %s. %w", layerChainId, err)
	}
	tmpName := tmpfile.Name()
	defer os.Remove(tmpfile.Name())

	log.Debug("converting tar to layer disk image")
	rootHash, err := TarStreamToDiskImage(rc, tmpName)
	if err != nil {
		return "", fmt.Errorf("failed to convert tar to ext4. %w", err)
	}

	if err := moveFile(tmpName, diskImagePath); err != nil {
		// Check if the file has been created.
		if _, err1 := os.Stat(diskImagePath); err1 != nil {
			return "", fmt.Errorf("failed to rename %s to %s. %w", tmpName, diskImagePath, err)
		}
	}

	fmt.Fprintf(os.Stdout, "Pulled Layer %d: %s\nRootHash=%s\n", layerNumber, diskImagePath, rootHash)
	return rootHash, nil
}

func digest(str string) string {
	s := sha256.Sum256([]byte(str))
	return "sha256:" + hex.EncodeToString(s[:])
}

type pullResult struct {
	Error    error
	Number   int
	ParentId string
	ChainId  string
	RootHash string
}

func PullImage(image string, storagePath string) error {
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		return fmt.Errorf("failed to create storage directory. %w", err)
	}
	img, err := fetchImage(image)
	if err != nil {
		return fmt.Errorf("failed to fetch image. %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("failed to fetch image layers. %w", err)
	}

	chainId := ""
	ch := make(chan pullResult, len(layers))
	for layerNumber, layer := range layers {
		diffID, err := layer.DiffID()
		if err != nil {
			return fmt.Errorf("failed to get layer diffid. %w", err)
		}

		parentId := chainId

		// Compute chainid based on https://github.com/opencontainers/image-spec/blob/
		// main/config.md#layer-chainid
		if layerNumber == 0 {
			chainId = diffID.String()
		} else {
			chainId = digest(chainId + " " + diffID.String())
		}

		if err != nil {
			return fmt.Errorf("failed to read layer diff. %w", err)
		}
		go func(parentId string, layerChainId string, layerNumber int, layer v1.Layer) {
			rootHash, err := downloadLayer(layerChainId, layerNumber, layer, storagePath)
			ch <- pullResult{
				Error:    err,
				Number:   layerNumber,
				ParentId: parentId,
				ChainId:  layerChainId,
				RootHash: rootHash,
			}
		}(parentId, chainId, layerNumber, layer)
	}

	results := make([]pullResult, len(layers))
	for range layers {
		r := <-ch
		if r.Error != nil {
			err = fmt.Errorf("%w %w", r.Error, err)
		}
		results[r.Number] = r
	}

	if err != nil {
		return err
	}

	imageInfo := ImageInfo{}
	if manifestDigest, err := img.Digest(); err == nil {
		imageInfo.ManifestDigest = manifestDigest.String()
	} else {
		return fmt.Errorf("failed to read manifest digest. %w", err)
	}

	if rawManifest, err := img.RawManifest(); err == nil {
		imageInfo.ManifestRaw = rawManifest
	} else {
		return fmt.Errorf("failed to read raw manifest bytes. %w", err)
	}

	if configDigest, err := img.ConfigName(); err == nil {
		imageInfo.ConfigDigest = configDigest.String()
	} else {
		return fmt.Errorf("failed to read config digest. %w", err)
	}
	if rawConfig, err := img.RawConfigFile(); err == nil {
		imageInfo.ConfigRaw = rawConfig
	} else {
		return fmt.Errorf("failed to read raw config bytes. %w", err)
	}

	var layersVec []string
	var rootHashesVec []string

	for i, r := range results {
		diskImageName := layerDiskImageName(r.ChainId)
		diskImagePath := filepath.Join(storagePath, diskImageName)

		layersVec = append(layersVec, diskImagePath)
		rootHashesVec = append(rootHashesVec, r.RootHash)

		layer := layers[i]
		diffID, err := layer.DiffID()
		if err != nil {
			return fmt.Errorf("failed to get layer diffid. %w", err)
		}

		layerManifestPath := filepath.Join(storagePath, layerManifestName(r.ChainId))
		manifest := DefaultManifest()
		if manifest.Read(layerManifestPath) != nil || !manifest.IsValid() {
			// Manifest read failed or is not valid.
			// Clear it.
			manifest = DefaultManifest()
		}

		manifest.ImageRef = image

		// Set the current image information as the primary
		manifest.ManifestDigest = imageInfo.ManifestDigest
		manifest.ManifestRaw = imageInfo.ManifestRaw
		manifest.ConfigDigest = imageInfo.ConfigDigest
		manifest.ConfigRaw = imageInfo.ConfigRaw

		manifest.Layers = layersVec
		manifest.RootHashes = rootHashesVec
		manifest.DiffIDs = append(manifest.DiffIDs, diffID.String())
		manifest.ChainIDs = append(manifest.ChainIDs, r.ChainId)
		manifest.ImageInfos = append(manifest.ImageInfos, imageInfo)

		if err := manifest.Write(layerManifestPath); err != nil {
			return fmt.Errorf("failed to write layer manifest. %w", err)
		}
	}

	return nil
}
