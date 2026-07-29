package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const sparseCopyCommand = "/bin/cp"

// CopyFileSparse atomically copies a regular file while preserving holes.
func CopyFileSparse(sourcePath, destinationPath string) error {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source %s is not a regular file", sourcePath)
	}

	temporary, err := os.CreateTemp(filepath.Dir(destinationPath), ".sparse-copy-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = os.Remove(temporaryPath)
	}()

	if err := temporary.Close(); err != nil {
		return err
	}
	output, err := exec.Command(sparseCopyCommand, "--sparse=always", "--preserve=mode", "--", sourcePath, temporaryPath).CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return fmt.Errorf("sparse copy %s to %s: %w: %s", sourcePath, destinationPath, err, detail)
		}
		return fmt.Errorf("sparse copy %s to %s: %w", sourcePath, destinationPath, err)
	}

	copied, err := os.OpenFile(temporaryPath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	syncErr := copied.Sync()
	closeErr := copied.Close()
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temporaryPath, destinationPath)
}
