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
	"io"
	"io/fs"
	"os"
)

type txnWriteKind int

const (
	txnCreate txnWriteKind = iota
	txnReplace
)

// stagedWrite is a single file change staged inside a Txn.
type stagedWrite struct {
	tag  *Tag
	data []byte
	kind txnWriteKind
}

// Txn is an atomic set of depot file writes. Writes are staged in the
// depot directory as hidden temporary files and only become visible at their
// final names when Commit succeeds. If any stage of Commit fails, every
// change the transaction made is rolled back and the depot is left exactly as
// it was before Commit started.
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
// at the tag location makes Commit fail; the transaction is still rolled back
// cleanly in that case.
func (t *Txn) Put(tag *Tag, data []byte) error {
	if t.committed {
		return errors.New("transaction already committed")
	}
	if tag == nil {
		return errors.New("tag is nil")
	}
	if data == nil {
		return errors.New("data is nil")
	}
	t.writes = append(t.writes, stagedWrite{tag: tag, data: data, kind: txnCreate})
	return nil
}

// Replace stages replacement of an existing file. The current file stays
// untouched until Commit, at which point it is swapped atomically for the new
// contents. Commit fails if no file exists at the tag location yet.
func (t *Txn) Replace(tag *Tag, data []byte) error {
	if t.committed {
		return errors.New("transaction already committed")
	}
	if tag == nil {
		return errors.New("tag is nil")
	}
	if data == nil {
		return errors.New("data is nil")
	}
	t.writes = append(t.writes, stagedWrite{tag: tag, data: data, kind: txnReplace})
	return nil
}

// Commit applies every staged write atomically. On failure it removes all
// temporary files and any final files it already published, restores replaced
// files from their staged backups, and returns the first error encountered.
func (t *Txn) Commit() error {
	if t.committed {
		return errors.New("transaction already committed")
	}
	t.committed = true

	if len(t.writes) == 0 {
		return nil
	}

	if err := os.MkdirAll(t.depot.dirPath, 0755); err != nil {
		return err
	}

	type stagedFile struct {
		name      string
		temp      string
		backup    string
		committed bool
	}

	files := make([]*stagedFile, 0, len(t.writes))

	// rollback undoes everything done so far. Errors during rollback are
	// reported alongside the original failure instead of hiding it.
	rollback := func(cause error) error {
		var rollbackErr error
		for i := len(files) - 1; i >= 0; i-- {
			f := files[i]
			if f.committed {
				if rerr := removeTxnPath(f.name); rerr != nil && rollbackErr == nil {
					rollbackErr = rerr
				}
			}
			if f.backup != "" {
				// Restore the previous generation, whether or not the
				// replacement had already been published.
				if rerr := os.Rename(f.backup, f.name); rerr != nil {
					if rollbackErr == nil {
						rollbackErr = rerr
					}
				}
				f.backup = ""
			}
			if f.temp != "" {
				if rerr := removeTxnPath(f.temp); rerr != nil && rollbackErr == nil {
					rollbackErr = rerr
				}
				f.temp = ""
			}
		}
		if rollbackErr != nil {
			return fmt.Errorf("%w; rollback failed: %v", cause, rollbackErr)
		}
		return cause
	}

	for _, write := range t.writes {
		name := t.depot.path(write.tag.name)
		f := &stagedFile{name: name}
		files = append(files, f)

		if _, statErr := os.Lstat(name); statErr == nil {
			if write.kind == txnCreate {
				return rollback(&os.PathError{Op: "open", Path: name, Err: fs.ErrExist})
			}

			// Keep the existing file as a hidden backup so a failed commit can
			// restore the previous generation byte for byte. Renaming (rather
			// than copying) preserves the original file mode as well.
			backup, perr := os.CreateTemp(t.depot.dirPath, ".txn-backup-*")
			if perr != nil {
				return rollback(perr)
			}
			backupPath := backup.Name()
			if perr = backup.Close(); perr != nil {
				_ = removeTxnPath(backupPath)
				return rollback(perr)
			}
			// os.CreateTemp reserves a unique name; remove the placeholder so
			// the rename below works on platforms that refuse to replace an
			// existing destination.
			if perr = os.Remove(backupPath); perr != nil {
				return rollback(perr)
			}
			if perr = os.Rename(name, backupPath); perr != nil {
				return rollback(perr)
			}
			f.backup = backupPath
		} else if !os.IsNotExist(statErr) {
			return rollback(statErr)
		} else if write.kind == txnReplace {
			return rollback(&os.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist})
		}

		tempPath, terr := writeTemp(t.depot.dirPath, name, write.tag, write.data)
		if terr != nil {
			return rollback(terr)
		}
		f.temp = tempPath
	}

	// All data is staged and permission-checked. Publish the files. A rename
	// inside one directory is atomic, so each individual file either shows the
	// new contents or the old ones, never a partial write.
	for _, f := range files {
		if rerr := os.Rename(f.temp, f.name); rerr != nil {
			return rollback(rerr)
		}
		f.temp = ""
		f.committed = true
	}

	// Every file now has its new generation: drop the backups of replaced
	// files. The transaction is complete at this point, so a failure here can
	// no longer affect the committed result.
	for _, f := range files {
		if f.backup != "" {
			_ = removeTxnPath(f.backup)
			f.backup = ""
		}
	}

	return nil
}

// writeTemp writes data to a hidden temporary file in dir and enforces the tag
// permissions before the file is ever published under its final name. It
// returns the temporary path with the file closed.
func writeTemp(dir, finalName string, tag *Tag, data []byte) (string, error) {
	temp, err := os.CreateTemp(dir, ".txn-*")
	if err != nil {
		return "", err
	}
	tempPath := temp.Name()

	cleanup := func(cause error) (string, error) {
		_ = temp.Close()
		_ = removeTxnPath(tempPath)
		return "", cause
	}

	n, err := temp.Write(data)
	if err != nil {
		return cleanup(err)
	}
	if n != len(data) {
		return cleanup(io.ErrShortWrite)
	}
	if err = temp.Chmod(tag.perm); err != nil {
		return cleanup(err)
	}
	if err = temp.Sync(); err != nil {
		return cleanup(err)
	}
	fi, err := temp.Stat()
	if err != nil {
		return cleanup(err)
	}
	if !checkPermissions(tag.perm, fi.Mode()) {
		return cleanup(fmt.Errorf("permissions too lax for %v: required no more than %v, found %v", finalName, tag.perm, fi.Mode()))
	}
	if err = temp.Close(); err != nil {
		_ = removeTxnPath(tempPath)
		return "", err
	}
	return tempPath, nil
}

// removeTxnPath removes a staging or published file. On platforms where a
// read-only file cannot be unlinked directly, clear the read-only bit first.
func removeTxnPath(path string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	_ = os.Chmod(path, 0600)
	err = os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
