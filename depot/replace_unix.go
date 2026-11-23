//go:build !windows

package depot

import "os"

// replaceDepotFile renames a fully written temporary file over newPath. On
// Unix the rename is atomic, so the destination is never visible partially
// written.
func replaceDepotFile(tempPath, newPath string) error {
	return os.Rename(tempPath, newPath)
}
