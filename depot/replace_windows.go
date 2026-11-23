//go:build windows

package depot

import "os"

// replaceDepotFile renames a fully written temporary file over newPath.
// Windows cannot replace a read-only file, and depot files are normally
// read-only, so clear the read-only bit first and restore it if the rename
// fails.
func replaceDepotFile(tempPath, newPath string) error {
	info, err := os.Stat(newPath)
	if err != nil {
		if os.IsNotExist(err) {
			return os.Rename(tempPath, newPath)
		}
		return err
	}

	if err := os.Chmod(newPath, 0666); err != nil {
		return err
	}
	if err := os.Rename(tempPath, newPath); err != nil {
		_ = os.Chmod(newPath, info.Mode().Perm())
		return err
	}
	return nil
}
