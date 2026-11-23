/*-
 * Copyright 2015 Square Inc.
 * Copyright 2014 CoreOS
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

package depot

import (
	"errors"
	"fmt"
	"os"
)

// stagedWrite is one file change queued in a Txn.
type stagedWrite struct {
	tag    *Tag
	data   []byte
	create bool
}

// Txn stages a set of depot writes and publishes them together in Commit.
// New contents are written to hidden temporary files in the depot, so a failed
// commit can be rolled back without exposing a partially written file. Each
// replaced file is committed with an atomic rename; the previous contents are
// kept until every file has been published.
//
// A Txn must only be committed once.
type Txn struct {
	depot  *FileDepot
	writes []stagedWrite
}

// NewTxn starts an empty write transaction against a file depot.
func NewTxn(d *FileDepot) *Txn {
	return &Txn{depot: d}
}

// NewTxn starts an empty write transaction against the depot.
func (d *FileDepot) NewTxn() *Txn {
	return NewTxn(d)
}

// Put stages creation of a new file. As with FileDepot.Put, Commit fails if a
// file already exists at the tag location.
func (t *Txn) Put(tag *Tag, data []byte) error {
	if data == nil {
		return errors.New("data is nil")
	}
	t.writes = append(t.writes, stagedWrite{tag: tag, data: append([]byte(nil), data...), create: true})
	return nil
}

// Replace stages replacement of an existing file. The current file is not
// touched until Commit, when it is atomically replaced. Commit fails if no
// file exists at the tag location.
func (t *Txn) Replace(tag *Tag, data []byte) error {
	if data == nil {
		return errors.New("data is nil")
	}
	t.writes = append(t.writes, stagedWrite{tag: tag, data: append([]byte(nil), data...), create: false})
	return nil
}

// stagedFile tracks the files involved in committing one staged write.
type stagedFile struct {
	name      string
	temp      string
	backup    string
	published bool
}

// Commit writes every staged file to a temporary file, then publishes them.
// If any step fails, published files are restored from their backups, staged
// temporary files are removed, and the depot is left as it was before Commit.
func (t *Txn) Commit() error {
	if err := os.MkdirAll(t.depot.dirPath, 0755); err != nil {
		return err
	}

	files := make([]*stagedFile, 0, len(t.writes))

	rollback := func(cause error) error {
		for i := len(files) - 1; i >= 0; i-- {
			f := files[i]
			if f.published {
				if f.backup != "" {
					if rerr := replaceDepotFile(f.backup, f.name); rerr != nil {
						cause = fmt.Errorf("%w; rollback failed for %v: %v", cause, f.name, rerr)
						continue
					}
					f.backup = ""
				} else {
					if rerr := removeDepotFile(f.name); rerr != nil && !os.IsNotExist(rerr) {
						cause = fmt.Errorf("%w; rollback failed for %v: %v", cause, f.name, rerr)
					}
				}
			}
			if f.temp != "" {
				_ = removeDepotFile(f.temp)
				f.temp = ""
			}
			if f.backup != "" {
				_ = removeDepotFile(f.backup)
				f.backup = ""
			}
		}
		return cause
	}

	// Stage and validate everything before publishing any file.
	for _, write := range t.writes {
		name := t.depot.path(write.tag.name)
		info, statErr := os.Stat(name)
		exists := statErr == nil
		if statErr != nil && !os.IsNotExist(statErr) {
			files = append(files, &stagedFile{name: name})
			return rollback(statErr)
		}
		if write.create && exists {
			files = append(files, &stagedFile{name: name})
			return rollback(&os.PathError{Op: "open", Path: name, Err: os.ErrExist})
		}
		if !write.create && !exists {
			files = append(files, &stagedFile{name: name})
			return rollback(&os.PathError{Op: "stat", Path: name, Err: os.ErrNotExist})
		}

		temp, tempErr := t.writeTemp(write.tag, write.data)
		f := &stagedFile{name: name, temp: temp, backup: ""}
		files = append(files, f)
		if tempErr != nil {
			return rollback(tempErr)
		}
		if exists {
			backup, backupErr := t.backupFile(name, info.Mode().Perm())
			f.backup = backup
			if backupErr != nil {
				return rollback(backupErr)
			}
		}
	}

	// All new files are complete on disk. Publish each one with a rename, which
	// is atomic for readers of that file.
	for _, f := range files {
		if rerr := replaceDepotFile(f.temp, f.name); rerr != nil {
			return rollback(rerr)
		}
		f.temp = ""
		f.published = true
	}

	// The transaction is complete. The old generations are no longer needed.
	for _, f := range files {
		if f.backup != "" {
			_ = removeDepotFile(f.backup)
			f.backup = ""
		}
	}
	return nil
}

// writeTemp writes data to a hidden temporary file and enforces the tag
// permissions before the file can be published.
func (t *Txn) writeTemp(tag *Tag, data []byte) (string, error) {
	temp, err := os.CreateTemp(t.depot.dirPath, ".txn-*")
	if err != nil {
		return "", err
	}
	tempName := temp.Name()

	cleanup := func(cause error) (string, error) {
		_ = temp.Close()
		_ = removeDepotFile(tempName)
		return "", cause
	}

	if _, err := temp.Write(data); err != nil {
		return cleanup(err)
	}
	if err := temp.Chmod(tag.perm); err != nil {
		return cleanup(err)
	}
	if err := temp.Sync(); err != nil {
		return cleanup(err)
	}
	fi, err := temp.Stat()
	if err != nil {
		return cleanup(err)
	}
	if !checkPermissions(tag.perm, fi.Mode()) {
		return cleanup(fmt.Errorf("permissions too lax for %v: required no more than %v, found %v", t.depot.path(tag.name), tag.perm, fi.Mode()))
	}
	if err := temp.Close(); err != nil {
		_ = removeDepotFile(tempName)
		return "", err
	}
	return tempName, nil
}

// backupFile copies name to a hidden temporary file so it can be restored if a
// later stage of the commit fails.
func (t *Txn) backupFile(name string, perm os.FileMode) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}

	backup, err := os.CreateTemp(t.depot.dirPath, ".txn-backup-*")
	if err != nil {
		return "", err
	}
	backupName := backup.Name()

	cleanup := func(cause error) (string, error) {
		_ = backup.Close()
		_ = removeDepotFile(backupName)
		return "", cause
	}

	if _, err := backup.Write(data); err != nil {
		return cleanup(err)
	}
	if err := backup.Chmod(perm); err != nil {
		return cleanup(err)
	}
	if err := backup.Sync(); err != nil {
		return cleanup(err)
	}
	if err := backup.Close(); err != nil {
		_ = removeDepotFile(backupName)
		return "", err
	}
	return backupName, nil
}
