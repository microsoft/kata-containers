//go:build linux

package utils

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyFileSparse(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.img")
	destinationPath := filepath.Join(directory, "destination.img")

	const fileSize = int64(32 * 1024 * 1024)
	source, err := os.OpenFile(sourcePath, os.O_CREATE|os.O_RDWR, 0o640)
	require.NoError(t, err)
	require.NoError(t, source.Truncate(fileSize))
	requireWriteAt(t, source, []byte("beginning"), 0)
	requireWriteAt(t, source, make([]byte, 128*1024), fileSize/4)
	requireWriteAt(t, source, []byte("middle"), fileSize/2)
	requireWriteAt(t, source, []byte("end"), fileSize-3)
	require.NoError(t, source.Close())
	require.NoError(t, os.WriteFile(destinationPath, []byte("old destination"), 0o600))

	require.NoError(t, CopyFileSparse(sourcePath, destinationPath))

	destinationInfo, err := os.Stat(destinationPath)
	require.NoError(t, err)
	assert.Equal(t, fileSize, destinationInfo.Size())
	assert.Equal(t, os.FileMode(0o640), destinationInfo.Mode().Perm())

	destination, err := os.Open(destinationPath)
	require.NoError(t, err)
	defer destination.Close()
	assertReadAt(t, destination, []byte("beginning"), 0)
	assertReadAt(t, destination, []byte("middle"), fileSize/2)
	assertReadAt(t, destination, []byte("end"), fileSize-3)
	assertReadAt(t, destination, make([]byte, 16), fileSize/4)

	stat, ok := destinationInfo.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Less(t, stat.Blocks*512, fileSize/4, "destination should remain sparse")

	require.NoError(t, os.WriteFile(destinationPath, []byte("private"), 0o640))
	sourceContent := make([]byte, len("beginning"))
	source, err = os.Open(sourcePath)
	require.NoError(t, err)
	defer source.Close()
	_, err = source.ReadAt(sourceContent, 0)
	require.NoError(t, err)
	assert.Equal(t, "beginning", string(sourceContent))
}

func requireWriteAt(t *testing.T, file *os.File, data []byte, offset int64) {
	t.Helper()
	written, err := file.WriteAt(data, offset)
	require.NoError(t, err)
	require.Equal(t, len(data), written)
}

func assertReadAt(t *testing.T, file *os.File, expected []byte, offset int64) {
	t.Helper()
	actual := make([]byte, len(expected))
	read, err := file.ReadAt(actual, offset)
	require.NoError(t, err)
	require.Equal(t, len(expected), read)
	assert.Equal(t, expected, actual)
}
