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
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// txnStagingPrefix is the prefix of the temporary staging directories
	// that transactions create inside the depot directory.
	txnStagingPrefix = ".certstrap-txn-"
	// lockFileName is the name of the file used to serialize transactions
	// against each other within a depot directory.
	lockFileName = ".certstrap-lock"
)

// Transaction stages a set of files and commits them into a FileDepot
// atomically and without clobbering existing files.
//
// Staged files are written to a private staging directory inside the depot
// and are given the exact permission bits required by their tag before they
// become visible. On commit they are hard-linked into place one by one, in
// the order they were staged. Hard-linking fails if the destination already
// exists, so a commit can never overwrite existing depot files. If any step
// fails, every file already linked by this transaction is removed again, so
// a failed transaction never leaves a partially updated depot behind.
//
// The depot is locked for the lifetime of a transaction, which serializes
// concurrent transactions and recovery against each other. If a transaction
// is interrupted (e.g. the process is killed), the next transaction removes
// the stale staging directory, and RecoverIncompleteCA can be used to remove
// any partially committed file set.
type Transaction struct {
	depot     *FileDepot
	dir       string
	lock      *os.File
	staged    []stagedFile
	committed []*Tag
	closed    bool
}

type stagedFile struct {
	tag  *Tag
	path string
}

// BeginTransaction locks the depot and returns a new Transaction. Staging
// directories left behind by interrupted transactions are removed before the
// new transaction starts.
func (d *FileDepot) BeginTransaction() (*Transaction, error) {
	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return nil, err
	}

	lock, err := os.OpenFile(d.path(lockFileName), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(lock); err != nil {
		lock.Close()
		return nil, err
	}

	if err := d.removeStaleStagingDirs(); err != nil {
		_ = unlockFile(lock)
		lock.Close()
		return nil, err
	}

	dir, err := os.MkdirTemp(d.dirPath, txnStagingPrefix)
	if err != nil {
		_ = unlockFile(lock)
		lock.Close()
		return nil, err
	}

	return &Transaction{depot: d, dir: dir, lock: lock}, nil
}

// Put stages data to be written to the depot location of tag when the
// transaction commits. The staged file receives the exact permission bits
// required by the tag, which the committed file will have as well.
func (t *Transaction) Put(tag *Tag, data []byte) error {
	if data == nil {
		return errors.New("data is nil")
	}
	if t.closed {
		return errors.New("transaction is closed")
	}

	name := filepath.Join(t.dir, tag.name)
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(name)
		return err
	}
	// Set the final permissions explicitly so they do not depend on the
	// umask and never differ from what the tag requires.
	if err := os.Chmod(name, tag.perm); err != nil {
		os.Remove(name)
		return err
	}

	t.staged = append(t.staged, stagedFile{tag: tag, path: name})
	return nil
}

// Commit moves all staged files into the depot in the order they were
// staged. It fails without overwriting anything if any of the target files
// already exists; files already linked by this transaction are removed
// again, so the depot is left in its original state.
func (t *Transaction) Commit() error {
	if t.closed {
		return errors.New("transaction is closed")
	}

	for _, s := range t.staged {
		target := t.depot.path(s.tag.name)
		if err := os.Link(s.path, target); err != nil {
			t.rollbackCommitted()
			t.close()
			return fmt.Errorf("commit %s: %w", s.tag.name, err)
		}
		t.committed = append(t.committed, s.tag)
	}

	// Best effort: make sure the new directory entries are durable.
	_ = syncDir(t.depot.dirPath)

	t.close()
	return nil
}

// Rollback removes all files committed so far and discards the staged
// files. It is a no-op once the transaction has been committed or rolled
// back. Removals are best effort: anything left behind is cleaned up by
// the next transaction or recovery.
func (t *Transaction) Rollback() {
	if t.closed {
		return
	}
	t.rollbackCommitted()
	t.close()
}

// rollbackCommitted removes the files this transaction has already linked
// into the depot, in reverse commit order.
func (t *Transaction) rollbackCommitted() {
	for i := len(t.committed) - 1; i >= 0; i-- {
		_ = removeFile(t.depot.path(t.committed[i].name))
	}
	t.committed = nil
}

// close discards the staging directory and releases the depot lock.
func (t *Transaction) close() {
	if t.closed {
		return
	}
	t.closed = true
	if t.dir != "" {
		os.RemoveAll(t.dir)
		t.dir = ""
	}
	if t.lock != nil {
		_ = unlockFile(t.lock)
		t.lock.Close()
		t.lock = nil
	}
}

// removeStaleStagingDirs removes staging directories left behind by
// transactions that were interrupted before they finished.
func (d *FileDepot) removeStaleStagingDirs() error {
	entries, err := os.ReadDir(d.dirPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), txnStagingPrefix) {
			if err := os.RemoveAll(d.path(entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// RecoverIncompleteCA removes CA files for name when only a subset of the
// files written by CA creation (certificate, private key, CRL) exists in
// the depot. Such a subset can only come from an interrupted or failed
// creation; it can never be used to sign and must not be combined with
// files from a later creation attempt, or the depot could end up with a
// certificate that does not match the private key, or a CRL that does not
// belong to the CA. It returns true when files were removed.
//
// A depot holding both the certificate and the private key is considered a
// complete CA and is left untouched.
func RecoverIncompleteCA(d *FileDepot, name string) (bool, error) {
	crtExists := fileExists(d.path(CrtTag(name).name))
	keyExists := fileExists(d.path(PrivKeyTag(name).name))
	crlExists := fileExists(d.path(CrlTag(name).name))

	switch {
	case crtExists && keyExists:
		// Complete CA: nothing to recover.
		return false, nil
	case !crtExists && !keyExists && !crlExists:
		// No CA files at all: nothing to recover.
		return false, nil
	}

	for _, tag := range []*Tag{CrtTag(name), PrivKeyTag(name), CrlTag(name)} {
		if err := removeFile(d.path(tag.name)); err != nil && !os.IsNotExist(err) {
			return false, err
		}
	}
	return true, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// removeFile removes a single depot file. On Windows, files created with
// read-only permission bits (such as 0444) must be made writable before
// they can be removed.
func removeFile(path string) error {
	err := os.Remove(path)
	if err != nil && runtime.GOOS == "windows" {
		if chmodErr := os.Chmod(path, 0666); chmodErr == nil {
			err = os.Remove(path)
		}
	}
	return err
}
