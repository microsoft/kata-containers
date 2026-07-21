// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package containerdshim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveRestoreSource resolves an annotation value within SnapshotBaseDir.
func resolveRestoreSource(from string) (string, error) {
	if from == "" {
		return "", fmt.Errorf("restore source is required")
	}
	dir := from
	if !strings.Contains(from, "/") {
		clean := filepath.Clean(filepath.Join(SnapshotBaseDir, from))
		if filepath.Dir(clean) != filepath.Clean(SnapshotBaseDir) {
			return "", fmt.Errorf("invalid snapshot name %q: must not contain path separators or ..", from)
		}
		dir = clean
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve snapshot source %q: %w", dir, err)
	}
	base := filepath.Clean(SnapshotBaseDir)
	if resolved != base && !strings.HasPrefix(resolved, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("restore source %q resolves outside %s", from, base)
	}
	return resolved, nil
}
