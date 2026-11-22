/*-
 * Copyright 2015 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/square/certstrap/depot"
)

// stageRequestFile writes data to a temporary file next to path. The target is not
// touched until the caller renames the returned temporary file into place.
func stageRequestFile(path string, data []byte, perm os.FileMode) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	tempPath := file.Name()
	cleanup := func() {
		_ = file.Close()
		removeRequestFile(tempPath)
	}

	if _, err := file.Write(data); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", err
	}
	if err := file.Close(); err != nil {
		removeRequestFile(tempPath)
		return "", err
	}
	if err := os.Chmod(tempPath, perm); err != nil {
		removeRequestFile(tempPath)
		return "", err
	}

	return tempPath, nil
}

// backupRequestFile moves path aside so that a failed multi-file update can restore
// the previous contents.
func backupRequestFile(path string) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".bak-*")
	if err != nil {
		return "", err
	}
	backupPath := file.Name()
	if err := file.Close(); err != nil {
		removeRequestFile(backupPath)
		return "", err
	}
	if err := os.Remove(backupPath); err != nil {
		return "", err
	}
	if err := os.Rename(path, backupPath); err != nil {
		return "", err
	}
	return backupPath, nil
}

// commitRequestFiles publishes the private key and CSR as one request generation.
// The key is installed first and the CSR, which carries the generation
// metadata, is installed last. If any step fails, files created by this
// attempt are removed and a previously existing CSR is restored.
func commitRequestFiles(writeKey bool, keyPath string, keyBytes []byte, csrPath string, csrBytes []byte) error {
	var (
		keyTemp   string
		csrTemp   string
		csrBackup string
	)

	defer func() {
		if keyTemp != "" {
			removeRequestFile(keyTemp)
		}
		if csrTemp != "" {
			removeRequestFile(csrTemp)
		}
		if csrBackup != "" {
			if _, err := os.Lstat(csrPath); err == nil {
				removeRequestFile(csrBackup)
			} else if os.IsNotExist(err) {
				_ = os.Rename(csrBackup, csrPath)
			}
		}
	}()

	var err error
	if writeKey {
		keyTemp, err = stageRequestFile(keyPath, keyBytes, depot.BranchPerm)
		if err != nil {
			return fmt.Errorf("Save private key error: %w", err)
		}
	}

	csrTemp, err = stageRequestFile(csrPath, csrBytes, depot.LeafPerm)
	if err != nil {
		return fmt.Errorf("Save certificate request error: %w", err)
	}

	if info, err := os.Lstat(csrPath); err == nil {
		if info.IsDir() {
			return fmt.Errorf("Save certificate request error: %s is a directory", csrPath)
		}
		csrBackup, err = backupRequestFile(csrPath)
		if err != nil {
			return fmt.Errorf("Save certificate request error: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("Save certificate request error: %w", err)
	}

	if writeKey {
		if err := os.Rename(keyTemp, keyPath); err != nil {
			return fmt.Errorf("Save private key error: %w", err)
		}
		keyTemp = ""
	}

	if err := os.Rename(csrTemp, csrPath); err != nil {
		if writeKey {
			removeRequestFile(keyPath)
		}
		return fmt.Errorf("Save certificate request error: %w", err)
	}
	csrTemp = ""

	return nil
}

func removeRequestFile(path string) {
	// Read-only files cannot be deleted on Windows, so make the file writable
	// first. On Unix this is harmless and the file is removed either way.
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink == 0 {
		_ = os.Chmod(path, 0600)
	}
	_ = os.Remove(path)
}
