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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/containerd/snapshots/storage"
	"github.com/containerd/continuity/fs"
)

type Snapshotter struct {
	Config
	ms *storage.MetaStore
}

const (
	// containerd
	// This label will be set only when pulling an image
	targetSnapshotLabel = "containerd.io/snapshot.ref"

	// CRI
	// targetRefLabel is a label which contains image reference and will be passed
	// to snapshotters.
	targetRefLabel = "containerd.io/snapshot/cri.image-ref"
	// targetManifestDigestLabel is a label which contains manifest digest and will be passed
	// to snapshotters.
	targetManifestDigestLabel = "containerd.io/snapshot/cri.manifest-digest"
	// targetLayerDigestLabel is a label which contains layer digest and will be passed
	// to snapshotters.
	targetLayerDigestLabel = "containerd.io/snapshot/cri.layer-digest"
	// targetImageLayersLabel is a label which contains layer digests contained in
	// the target image and will be passed to snapshotters for preparing layers in
	// parallel. Skipping some layers is allowed and only affects performance.
	targetImageLayersLabel = "containerd.io/snapshot/cri.image-layers"

	// Custom labels
	// List of mounts owned by an active snapshot
	snapshotMountsLabel = "containerd.io/snapshot/cc.mounts"
)

// Globals
var (
	LoggingEnabled bool = false
)

func NewSnapshotter(config *Config) (snapshots.Snapshotter, error) {
	if err := os.MkdirAll(config.RootPath, 0700); err != nil {
		return nil, fmt.Errorf("NewSnapshotter: failed to create root directory. %w", err)
	}

	ms, err := storage.NewMetaStore(filepath.Join(config.RootPath, "metadata.db"))
	if err != nil {
		return nil, fmt.Errorf("NewSnapshotter: failed to create metastore. %w", err)
	}

	if err := os.Mkdir(filepath.Join(config.RootPath, "snapshots"), 0700); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("NewSnapshotter: failed to create snapshots folder. %w", err)
	}

	if err := os.Mkdir(filepath.Join(config.RootPath, "layers"), 0700); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("NewSnapshotter: failed to create layers folder. %w", err)
	}

	LoggingEnabled = config.EnableLogging

	return &Snapshotter{
		Config: *config,
		ms:     ms,
	}, nil
}

/*
   containerd snapshotter interface methods
*/
func (s *Snapshotter) Close() error {
	return nil
}

func (s *Snapshotter) Stat(ctx context.Context, key string) (snapshots.Info, error) {
	ctx, t, err := s.ms.TransactionContext(ctx, false)
	if err != nil {
		return snapshots.Info{}, fmt.Errorf("Stat: TransactionContext failed. %w", err)
	}
	defer t.Rollback()

	_, info, _, err := storage.GetInfo(ctx, key)
	if err != nil {
		return snapshots.Info{}, fmt.Errorf("Stat: GetInfo failed. %w", err)
	}

	return info, nil
}

func (s *Snapshotter) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (snapshots.Info, error) {
	ctx, t, err := s.ms.TransactionContext(ctx, true)
	if err != nil {
		return snapshots.Info{}, fmt.Errorf("Update: TransactionContext failed. %w", err)
	}

	info, err = storage.UpdateInfo(ctx, info, fieldpaths...)
	if err != nil {
		t.Rollback()
		return snapshots.Info{}, fmt.Errorf("Update: UpdateInfo failed. %w", err)
	}

	if err := t.Commit(); err != nil {
		return snapshots.Info{}, fmt.Errorf("Update: Commit failed. %w", err)
	}

	return info, nil
}

func (s *Snapshotter) Usage(ctx context.Context, key string) (snapshots.Usage, error) {
	ctx, t, err := s.ms.TransactionContext(ctx, false)
	if err != nil {
		return snapshots.Usage{}, fmt.Errorf("Usage: TransactionContext failed. %w", err)
	}
	_, _, usage, err := storage.GetInfo(ctx, key)
	t.Rollback() // transaction no longer needed at this point.

	if err != nil {
		return snapshots.Usage{}, fmt.Errorf("Usage: GetInfo failed. %w", err)
	}

	return usage, nil
}

func (s *Snapshotter) Walk(ctx context.Context, fn snapshots.WalkFunc, fs ...string) error {
	ctx, t, err := s.ms.TransactionContext(ctx, false)
	if err != nil {
		return fmt.Errorf("Walk: TransactionContext failed. %w", err)
	}
	defer t.Rollback()
	return storage.WalkInfo(ctx, fn, fs...)
}

func (s *Snapshotter) Remove(ctx context.Context, key string) error {
	if LoggingEnabled {
		fmt.Printf("Removing snapshot with key=%s\n", key)
	}

	ctx, t, err := s.ms.TransactionContext(ctx, true)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if rerr := t.Rollback(); rerr != nil {
				fmt.Printf("Remove: failed to rollback transaction")
			}
		}
	}()

	id, info, _, err := storage.GetInfo(ctx, key)
	if err != nil {
		return fmt.Errorf("Remove: GetInfo failed. %w", err)
	}

	// Remove any mounts
	if mountsStr, exists := info.Labels[snapshotMountsLabel]; exists {
		unmount(strings.Split(mountsStr, ":"))
	}

	// Remove the snapshot folder
	snapshotPath := s.snapshotPath(id)
	if err = os.RemoveAll(snapshotPath); err != nil {
		return fmt.Errorf("Remove: Failed to remove snapshot folder %s. %w", snapshotPath, err)
	}

	_, _, err = storage.Remove(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to remove: %w", err)
	}

	return t.Commit()
}

func (s *Snapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	if LoggingEnabled {
		fmt.Printf("Preparing snapshot with key=%s, parent=%s\n", key, parent)
	}

	return s.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)
}

func (s *Snapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	if LoggingEnabled {
		fmt.Printf("Commiting snapshot with key=%s name=%s\n\n", key, name)
	}

	return fmt.Errorf("Commit is not supported by cc-snapshotter.")
}

// This is called for running a container
func (s *Snapshotter) Mounts(ctx context.Context, key string) ([]mount.Mount, error) {
	ctx, t, err := s.ms.TransactionContext(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("Mounts: TransactionContext failed. %w", err)
	}
	snap, err := storage.GetSnapshot(ctx, key)
	t.Rollback()
	if err != nil {
		return nil, fmt.Errorf("Mounts: failed to get active mount: %w", err)
	}

	return s.mounts(snap.ID), nil
}

func (s *Snapshotter) View(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	if LoggingEnabled {
		fmt.Printf("Viewing snapshot with key=%s, parent=%s\n", key, parent)
	}

	return s.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)
}

/*
   Helper methods
*/

// Path of the snapshot folder for a given shapshot id.
func (s *Snapshotter) snapshotPath(id string) string {
	return filepath.Join(s.RootPath, "snapshots", id)
}

// Unmount a list of mounts
func unmount(mounts []string) error {
	var rerr error

	for _, m := range mounts {
		cmd := exec.Command("umount", "-f", m)
		if err := cmd.Run(); err != nil {
			rerr = fmt.Errorf("failed to remove %s. %w %w", m, err, rerr)
		}
	}
	return rerr
}

// Mount layer disks
func (s *Snapshotter) createMounts(snap storage.Snapshot, manifest ImageManifest) ([]string, error) {
	var mounts []string

	var snapshotPath = s.snapshotPath(snap.ID)
	// Create read-only mounts
	for i, disk := range manifest.Layers {
		layerDir := filepath.Join(snapshotPath, fmt.Sprintf("layer_%d", i))
		if err := os.Mkdir(layerDir, 0755); err != nil {
			return mounts, fmt.Errorf("failed to create %s. %w", layerDir, err)
		}

		out, err := exec.Command("mount", "-o", "ro", disk, layerDir).Output()
		if err != nil {
			return mounts, fmt.Errorf("failed to mount %s to %s. %s. %w", disk, layerDir, out, err)
		}

		mounts = append(mounts, layerDir)
	}

	// Create upper, work and merged folders
	upperDir := filepath.Join(snapshotPath, "upper")
	workDir := filepath.Join(snapshotPath, "work")
	mergedDir := filepath.Join(snapshotPath, "merged")

	for _, dir := range []string{upperDir, workDir, mergedDir} {
		if err := os.Mkdir(dir, 0755); err != nil {
			return mounts, fmt.Errorf("failed to create %s. %w", dir, err)
		}
	}

	// Perform overlay mount
	// Kernel stacks lower directories in right to left order whereas OCI specifies left to right.
	// See https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html#multiple-lower-layers
	// Therefore, reverse order.
	lowerDir := mounts[len(mounts)-1]
	for i := len(mounts) - 2; i >= 0; i -= 1 {
		lowerDir = lowerDir + ":" + mounts[i]
	}

	options := fmt.Sprintf("lowerdir=%s,workdir=%s,upperdir=%s", lowerDir, workDir, upperDir)
	out, err := exec.Command("mount", "-t", "overlay", "overlay", "-o", options, mergedDir).Output()
	if err != nil {
		return mounts, fmt.Errorf("failed to create overlay %s. %s. %w", mergedDir, out, err)
	}

	return append(mounts, mergedDir), nil
}

// Create a snapshot
func (s *Snapshotter) createSnapshot(ctx context.Context, kind snapshots.Kind, key, parent string, opts []snapshots.Opt) (_ []mount.Mount, err error) {

	ctx, t, err := s.ms.TransactionContext(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("createSnapshot: TransactionContext failed. %w", err)
	}
	// On failure, rollback transaction
	rollback := true
	defer func() {
		if rollback {
			if rerr := t.Rollback(); rerr != nil {
				fmt.Printf("createSnapshot: failed to rollback transaction")
			}
		}
	}()

	// Read all supplied options
	var base snapshots.Info
	for _, opt := range opts {
		if err := opt(&base); err != nil {
			return nil, fmt.Errorf("Prepare: error applying options. %w", err)
		}
	}

	if targetKey, ok := base.Labels[targetSnapshotLabel]; ok {
		// Image pull
		imageRef, ok := base.Labels[targetRefLabel]
		if !ok {
			return nil, fmt.Errorf("createSnapshot: missing %s label", targetSnapshotLabel)
		}

		// Pull and create snapshots for all layers in the image
		layersDir := filepath.Join(s.RootPath, "layers")
		layerDiskPath := filepath.Join(layersDir, layerDiskImageName(targetKey))
		layerManifestPath := filepath.Join(layersDir, layerManifestName(targetKey))

		// Check if image needs to be pulled.
		pull := true
		if _, err := os.Stat(layerManifestPath); err == nil {
			manifest := DefaultManifest()
			if err := manifest.Read(layerManifestPath); err == nil {
				if manifest.IsValid() {
					pull = false
				}
			}
		}

		if pull {
			// Redownload image from reference
			if err := PullImage(imageRef, layersDir); err != nil {
				return nil, fmt.Errorf("createSnapshot: PullImage failed. %w", err)
			}
		}

		// First create an active snapshot
		_, err = storage.CreateSnapshot(ctx, snapshots.KindActive, key, parent, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create snapshot: %w", err)
		}

		// Compute usage.
		usage, err := fs.DiskUsage(ctx, layerDiskPath)
		if err != nil {
			return nil, fmt.Errorf("Commit: failed to compute disk usage for %s. %w", layerDiskPath, err)
		}

		// Commit the snapshot
		if _, err = storage.CommitActive(ctx, key, targetKey,
			snapshots.Usage(usage), opts...); err != nil {
			return nil, fmt.Errorf("Commit: failed to commit snapshot: %w", err)
		}
		fmt.Printf("Committed snapshot %s\n", targetKey)

		rollback = false
		if err = t.Commit(); err != nil {
			return nil, fmt.Errorf("createSnapshot: commit failed: %w", err)
		}

		return nil, errdefs.ErrAlreadyExists
	}

	if len(strings.Split(parent, ":")) < 2 {
		// The image was likely pulled using regular snapshotter.
		fmt.Printf("Parent snapshot not found. Maybe pulled using regular snapshotter?\n")
		return nil, errdefs.ErrNotFound
	}

	// Create a snapshot for running a container
	snap, err := storage.CreateSnapshot(ctx, snapshots.KindActive, key, parent, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot: %w", err)
	}

	var (
		mounts []string
		path   string
	)

	// Cleanup in temporary directory and snapshot directory in case of failure.
	defer func() {
		if err != nil {
			// Cleanup mounts
			unmount(mounts)

			// Remove snapshot directory
			if path != "" {
				if err1 := os.RemoveAll(path); err1 != nil {
					err = fmt.Errorf("createSnapshot: failed to remove snapshot dir %s %w. %w",
						path, err1, err)
				}
			}
		}
	}()

	// Create the snapshot directory
	path = s.snapshotPath(snap.ID)

	err = os.MkdirAll(path, 0755)
	if err != nil {
		return nil, fmt.Errorf("createSnapshot: failed to create snapshot dir %s: %w",
			path, err)
	}

	// Create a sparse disk image for the read-write layer.
	rwDiskPath := filepath.Join(path, "rw.disk")
	rw, err := os.Create(rwDiskPath)
	if err != nil {
		return nil, fmt.Errorf("createSnapshot: failed to create rw layer %s: %w",
			rwDiskPath, err)
	}
	defer rw.Close()

	// Resize the file to desired size. (sparse)
	if err = rw.Truncate(s.ReadWriteLayerSizeInGB * 1024 * 1024 * 1024); err != nil {
		return nil, fmt.Errorf("createSnapshot: failed to truncate rw layer %s: %w",
			rwDiskPath, err)
	}

	// Read the parent manifest.
	parentManifestPath := filepath.Join(s.RootPath, "layers", layerManifestName(parent))
	manifest := DefaultManifest()
	if err := manifest.Read(parentManifestPath); err != nil {
		return nil, fmt.Errorf("createSnapshot: failed to read parent manifest. %w", err)
	}

	// Populate the path to the top layer and write out the manifest.
	manifest.RWLayer = filepath.Join(path, "rw.disk")

	manifestPath := filepath.Join(path, ".cc.manifest.json")

	// Perform mounts if regular containers need to be supported.
	if s.SupportRegularContainers {
		if mounts, err = s.createMounts(snap, manifest); err != nil {
			return nil, err
		}
		manifestPath = filepath.Join(path, "merged", ".cc.manifest.json")
	}

	_, info, _, err := storage.GetInfo(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("createSnapshot: failed to fetch info. %w", err)
	}

	if info.Labels == nil {
		info.Labels = make(map[string]string)
	}

	// Write out the manifest.
	if err := manifest.Write(manifestPath); err != nil {
		return nil, fmt.Errorf("createSnapshot: failed to write manifest. %w", err)
	}
	fmt.Printf("Wrote: %s\n", manifestPath)

	// Store list of mounts in storage to ensure they are cleaned up.
	// Another strategy is read them from manifest file for cleanup.
	info.Labels[snapshotMountsLabel] = strings.Join(mounts, ":")

	_, err = storage.UpdateInfo(ctx, info)
	if err != nil {
		t.Rollback()
		return nil, err
	}

	rollback = false
	if err = t.Commit(); err != nil {
		return nil, fmt.Errorf("createSnapshot: commit failed: %w", err)
	}

	mounts = nil
	path = ""
	return s.mounts(snap.ID), nil
}

func (s *Snapshotter) mounts(id string) []mount.Mount {
	path := s.snapshotPath(id)
	return []mount.Mount{
		{
			Source: filepath.Join(path, "merged"),
			Type:   "bind",
			Options: []string{
				"rw",
				"rbind",
			},
		},
	}
}
