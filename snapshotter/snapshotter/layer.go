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
	"archive/tar"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/Microsoft/hcsshim/ext4/dmverity"
	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
)

const (
	//Format used for specifying dates
	DateFormat = "2006-01-02"
	// String representation of default date
	DefaultDateString = "2006-01-02"
)

// Convert a given directory to a tar file. If two directories have the same
// contents including timestamps, the the resulting tar files will be bitwise
// same. The function only handles contents that are defined in
// https://github.com/opencontainers/image-spec/blob/main/layer.md
func DirectoryToTar(dirPath string, tarPath string) error {
	// Convert path to absolute path so that WalkDir returns full path for each file
	dirPath, err := filepath.Abs(dirPath)
	if err != nil {
		return err
	}

	// Create default date object
	defaultDate, err := time.Parse(DateFormat, DefaultDateString)
	if err != nil {
		return fmt.Errorf("failed to create default date %s using format %s. %w",
			DefaultDateString, DateFormat, err)
	}

	// Create tarfile for writing
	tarFile, err := os.Create(tarPath)
	if err != nil {
		return fmt.Errorf("failed to create tar file %s. %w", tarPath, err)
	}
	defer tarFile.Close()

	// Create a tar writer.
	w := tar.NewWriter(tarFile)

	// Use WalkDir to iterate through the contents of the directory.
	// WalkDir guarantees lexicographical ordering.
	err = filepath.WalkDir(dirPath, func(path string, entry fs.DirEntry, err error) error {
		// Return early if there is an error
		if err != nil {
			return err
		}

		// Fetch the FileInfo from the entry.
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("failed to fetch Info from %v. %w", entry, err)
		}

		var header *tar.Header

		// If the file is a symlink, fetch the target.
		if (info.Mode() & fs.ModeSymlink) != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("failed to readlink %s. %w", path, err)
			}

			// Create header will set the target field to link.
			header, err = tar.FileInfoHeader(info, link)
		} else {
			// Create header.
			header, err = tar.FileInfoHeader(info, info.Name())
		}

		if err != nil {
			return fmt.Errorf("failed to create FileInfoHeader. %w", err)
		}

		// Remove the prefix (dirPath) from each path.
		relativePath := path[len(dirPath):]
		header.Name = relativePath

		if path == dirPath {
			// For root folder, set the modification time to default time.
			header.Name = "/"
			header.ModTime = defaultDate
		}

		// Set the access and change times to the modification time.
		// This is essential for reproducibility.
		// See: https://reproducible-builds.org/docs/archives/
		header.AccessTime = header.ModTime
		header.ChangeTime = header.ModTime

		// Write the header
		if err := w.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write header. %w", err)
		}

		// Skip writing contents if not a regular file.
		if !info.Mode().IsRegular() {
			return nil
		}

		// Write the contents of the file to the tar archive.
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file %s for copying. %w",
				path, err)
		}
		defer file.Close()

		_, err = io.Copy(w, file)
		if err != nil {
			return fmt.Errorf("failed to copy %s. %w", path, err)
		}
		return err
	})
	return err
}

// Compute md5 hash of given data
func computeMD5Hash(data []byte) [16]byte {
	var sum [16]byte
	hash := md5.Sum(data)
	// Retype to [16]byte
	copy(sum[:], hash[:16])
	return sum
}

// Compute the dmverity merkeltree and append to the disk image file.
func computeAndWriteHashDevice(diskImagePath string) (string, error) {
	w, err := os.OpenFile(diskImagePath, os.O_RDWR, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to open %s. %w", diskImagePath, err)
	}

	// Find the size of the disk image.
	ext4blocksize := 4096
	ext4size, err := w.Seek(0, io.SeekEnd)
	if err != nil {
		return "", fmt.Errorf("failed to seek end. %w", err)
	}

	// Rewind the stream and then read it all into a []byte for
	// dmverity processing
	_, err = w.Seek(0, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("failed to seek start. %w", err)
	}
	data, err := ioutil.ReadAll(w)
	if err != nil {
		return "", fmt.Errorf("failed to read all. %w", err)
	}

	// Compute merkeltree of the disk image
	mtree, err := dmverity.MerkleTree(data)
	if err != nil {
		return "", fmt.Errorf("failed to build merkle tree. %w", err)
	}

	// Write dmverity superblock and then the merkle tree after the end of the
	// ext4 filesystem
	_, err = w.Seek(0, io.SeekEnd)
	if err != nil {
		return "", fmt.Errorf("failed to seek end for writing dmverity data. %w", err)
	}

	// Create a new dmverity superblock object.
	superblock := dmverity.NewDMVeritySuperblock(uint64(ext4size))

	// By default, a random UUID is generated. Use the md5 of data so that the UUID is
	// reproducible.
	superblock.UUID = computeMD5Hash(data)

	// Write the dmverity superblock
	err = binary.Write(w, binary.LittleEndian, superblock)
	if err != nil {
		return "", fmt.Errorf("failed to write superblock. %w", err)
	}

	// Pad the superblock
	sbsize := int(unsafe.Sizeof(*superblock))
	padding := bytes.Repeat([]byte{0}, ext4blocksize-(sbsize%ext4blocksize))
	_, err = w.Write(padding)
	if err != nil {
		return "", fmt.Errorf("failed to pad superblock. %w", err)
	}

	// Write the merkeltree
	_, err = w.Write(mtree)
	if err != nil {
		return "", fmt.Errorf("failed to write dmverity merkeltree. %w", err)
	}

	return hex.EncodeToString(dmverity.RootHash(mtree)), nil
}

// Convert a tar stream to an ext4 file system disk image with dmverity-metadata
// appended
func TarStreamToDiskImage(r io.Reader, imagePath string) (string, error) {
	// Create image file
	imageFile, err := os.Create(imagePath)
	if err != nil {
		return "", fmt.Errorf("failed to create %s. %w", imagePath, err)
	}

	defer func() {
		if imageFile != nil {
			imageFile.Close()
		}
	}()

	options := []tar2ext4.Option{
		tar2ext4.ConvertWhiteout,
		tar2ext4.MaximumDiskSize(dmverity.RecommendedVHDSizeGB),
		// The implementation from hcsshim generates random uuid which makes
		// the vhd not reproducible. Hence, we generate verity information
		// ourselves.
		// tar2ext4.AppendDMVerity,

	}
	if err := tar2ext4.Convert(r, imageFile, options...); err != nil {
		return "", fmt.Errorf("failed to convert tar to ext4: %w", err)
	}
	imageFile.Close()
	imageFile = nil

	rootHash, err := computeAndWriteHashDevice(imagePath)
	if err != nil {
		return "", fmt.Errorf("hash device creation failed. %w", err)
	}

	return rootHash, nil
}

// Convert a tar file to an ext4 file system disk image with dmverity-metadata
// appended.
func TarToDiskImage(tarPath string, imagePath string) (string, error) {
	// Open tar file
	tarFile, err := os.Open(tarPath)
	if err != nil {
		return "", fmt.Errorf("failed to open %s. %w", tarPath, err)
	}
	defer tarFile.Close()
	return TarStreamToDiskImage(tarFile, imagePath)
}

// Read root hash from a disk image
func ReadRootHash(imagePath string) (string, error) {
	ext4SB, err := tar2ext4.ReadExt4SuperBlock(imagePath)
	if err != nil {
		return "", fmt.Errorf("failed to read ext4 super block. %w", err)
	}
	blockSize := 1024 * (1 << ext4SB.LogBlockSize)
	ext4SizeInBytes := int64(blockSize) * int64(ext4SB.BlocksCountLow)

	dmvsb, err := dmverity.ReadDMVerityInfo(imagePath, ext4SizeInBytes)
	if err != nil {
		return "", fmt.Errorf("failed to read dm-verity super block. %w", err)
	}

	return dmvsb.RootDigest, nil
}
