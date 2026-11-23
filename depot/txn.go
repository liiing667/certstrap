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
	"io/fs"
	"os"
)

// stagedWrite is a single file change staged inside a Txn.
type stagedWrite struct {
	tag     *Tag
	data    []byte
	replace bool
}

// Txn is an atomic set of depot file writes. Writes are staged in hidden
// temporary files and only become visible at their final names when Commit
// succeeds. If any part of Commit fails, every change the transaction made is
// rolled back and the depot is left exactly as it was before Commit started.
//
// A Txn must only be committed once.
type Txn struct {
	depot     *FileDepot
	writes    []stagedWrite
	committed bool
}

// NewTxn starts an empty write transaction against the given file depot.
func NewTxn(d *FileDepot) *Txn {
	return &Txn{depot: d}
}

// NewTxn starts an empty write transaction against the depot.
func (d *FileDepot) NewTxn() *Txn {
	return NewTxn(d)
}

// Put stages creation of a new file. As with FileDepot.Put, an existing file
// at the tag location makes Commit fail; the transaction is then rolled back
// cleanly.
func (t *Txn) Put(tag *Tag, data []byte) error {
	if t == nil {
		return errors.New("transaction is nil")
	}
	if tag == nil {
		return errors.New("tag is nil")
	}
	if data == nil {
		return errors.New("data is nil")
	}
	t.writes = append(t.writes, stagedWrite{tag: tag, data: data})
	return nil
}

// Replace stages replacement of an existing file. The current file stays
// untouched until Commit, at which point it is swapped atomically for the new
// contents. Commit fails if no file exists at the tag location yet.
func (t *Txn) Replace(tag *Tag, data []byte) error {
	if t == nil {
		return errors.New("transaction is nil")
	}
	if tag == nil {
		return errors.New("tag is nil")
	}
	if data == nil {
		return errors.New("data is nil")
	}
	t.writes = append(t.writes, stagedWrite{tag: tag, data: data, replace: true})
	return nil
}

type stagedFile struct {
	name      string
	temp      *os.File
	perm      os.FileMode
	backup    string
	published bool
}

// Commit applies every staged write atomically. On failure it removes all
// temporary files, removes any final files it already published, and restores
// replaced files from their staged backups.
func (t *Txn) Commit() error {
	if t == nil {
		return errors.New("transaction is nil")
	}
	if t.committed {
		return errors.New("transaction already committed")
	}
	t.committed = true

	depotMutationMu.Lock()
	defer depotMutationMu.Unlock()

	if len(t.writes) == 0 {
		return nil
	}
	if t.depot == nil {
		return errors.New("transaction has no depot")
	}

	if err := os.MkdirAll(t.depot.dirPath, 0755); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(t.writes))
	files := make([]*stagedFile, 0, len(t.writes))

	rollback := func(cause error) error {
		for i := len(files) - 1; i >= 0; i-- {
			f := files[i]
			if f.temp != nil && !f.published {
				_ = f.temp.Close()
				_ = removeDepotFile(f.temp.Name())
				f.temp = nil
			}
			if f.published {
				_ = removeDepotFile(f.name)
				f.published = false
			}
			if f.backup != "" {
				if rerr := replaceDepotFile(f.backup, f.name); rerr != nil {
					cause = fmt.Errorf("%w; rollback failed for %v: %v", cause, f.name, rerr)
				} else {
					f.backup = ""
				}
			}
		}
		return cause
	}

	for _, write := range t.writes {
		if _, duplicate := seen[write.tag.name]; duplicate {
			return rollback(fmt.Errorf("duplicate transaction target %q", write.tag.name))
		}
		seen[write.tag.name] = struct{}{}

		name := t.depot.path(write.tag.name)
		f := &stagedFile{name: name, perm: write.tag.perm}

		fi, statErr := os.Stat(name)
		switch {
		case statErr == nil:
			if !write.replace {
				files = append(files, f)
				return rollback(&os.PathError{Op: "open", Path: name, Err: fs.ErrExist})
			}
			if fi.Mode().IsRegular() {
				// Preserve an existing more restrictive mode.
				if existing := fi.Mode().Perm(); existing&^f.perm == 0 {
					f.perm = existing
				}
			}
			backup, berr := os.CreateTemp(t.depot.dirPath, ".txn-backup-*")
			if berr != nil {
				files = append(files, f)
				return rollback(berr)
			}
			backupName := backup.Name()
			if cerr := backup.Close(); cerr != nil {
				_ = removeDepotFile(backupName)
				files = append(files, f)
				return rollback(cerr)
			}
			if rerr := removeDepotFile(backupName); rerr != nil {
				files = append(files, f)
				return rollback(rerr)
			}
			if rerr := os.Rename(name, backupName); rerr != nil {
				files = append(files, f)
				return rollback(rerr)
			}
			f.backup = backupName
		case errors.Is(statErr, fs.ErrNotExist):
			if write.replace {
				files = append(files, f)
				return rollback(&os.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist})
			}
		default:
			files = append(files, f)
			return rollback(statErr)
		}

		temp, terr := t.writeTemp(write.tag, write.data, f.perm)
		if terr != nil {
			files = append(files, f)
			return rollback(terr)
		}
		f.temp = temp
		files = append(files, f)
	}

	// All contents are staged and permission-checked. Publish each file with a
	// rename, which is atomic within the depot directory.
	for _, f := range files {
		if f.temp == nil {
			return rollback(fmt.Errorf("transaction lost staged data for %v", f.name))
		}
		tempName := f.temp.Name()
		if cerr := f.temp.Close(); cerr != nil {
			_ = removeDepotFile(tempName)
			f.temp = nil
			return rollback(cerr)
		}
		f.temp = nil
		if rerr := replaceDepotFile(tempName, f.name); rerr != nil {
			_ = removeDepotFile(tempName)
			return rollback(rerr)
		}
		f.published = true
	}

	// The transaction is complete; backups of replaced files are no longer
	// needed. A failure here can no longer affect the published generation.
	for _, f := range files {
		if f.backup != "" {
			_ = removeDepotFile(f.backup)
			f.backup = ""
		}
	}
	return nil
}

// writeTemp writes data to a hidden temporary file in the depot directory and
// enforces the tag permissions before the file is published under its final
// name. The returned file is still open; the caller closes it.
func (t *Txn) writeTemp(tag *Tag, data []byte, perm os.FileMode) (*os.File, error) {
	temp, err := os.CreateTemp(t.depot.dirPath, ".txn-*")
	if err != nil {
		return nil, err
	}

	cleanup := func(cause error) (*os.File, error) {
		_ = temp.Close()
		_ = removeDepotFile(temp.Name())
		return nil, cause
	}

	if _, err = temp.Write(data); err != nil {
		return cleanup(err)
	}
	if err = temp.Sync(); err != nil {
		return cleanup(err)
	}
	if err = temp.Chmod(perm); err != nil {
		return cleanup(err)
	}

	fi, err := temp.Stat()
	if err != nil {
		return cleanup(err)
	}
	if !checkPermissions(tag.perm, fi.Mode()) {
		return cleanup(fmt.Errorf("permissions too lax for %v: required no more than %v, found %v", t.depot.path(tag.name), tag.perm, fi.Mode()))
	}
	return temp, nil
}
