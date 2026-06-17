//go:build !windows

package util

import "os"

// SecureWriteFile writes data to path with 0600 permissions (owner read/write
// only). On Unix systems the kernel enforces this directly via the file mode.
func SecureWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}
