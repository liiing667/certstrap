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
	"path/filepath"
	"runtime"
)

const (
	// DefaultFileDepotDir is the default directory where .key/.csr/.crt files can be found
	DefaultFileDepotDir = "out"
)

// Tag includes name and permission requirement
// Permission requirement is used in two ways:
// 1. Set the permission for data when Put
// 2. Check the permission required when Get
// It is set to prevent attacks from other users for FileDepot.
// For example, 'evil' creates file ca.key with 0666 file perm,
// 'core' reads it and uses it as ca.key. It may cause the security
// problem of fake certificate and key.
type Tag struct {
	name string
	perm os.FileMode
}

// Depot is in charge of data storage
type Depot interface {
	Put(tag *Tag, data []byte) error
	Check(tag *Tag) bool
	Get(tag *Tag) ([]byte, error)
	Delete(tag *Tag) error
}

// FileDepot is a implementation of Depot using file system
type FileDepot struct {
	// Absolute path of directory that holds all files
	dirPath string
}

// NewFileDepot creates a new Depot at the specified path
func NewFileDepot(dir string) (*FileDepot, error) {
	dirpath, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	return &FileDepot{dirpath}, nil
}

func (d *FileDepot) path(name string) string {
	return filepath.Join(d.dirPath, name)
}

// Put inserts the data into the file specified by the tag
func (d *FileDepot) Put(tag *Tag, data []byte) error {
	if data == nil {
		return errors.New("data is nil")
	}

	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}

	name := d.path(tag.name)
	perm := tag.perm

	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		file.Close()
		_ = removeDepotFile(name)
		return err
	}

	file.Close()
	return nil
}

// Recover resolves interrupted depot mutations. This depot's transactions
// clean their staging files during Commit and rollback, so there is no durable
// journal to replay; the method exists for callers that recover depots before
// using them.
func (d *FileDepot) Recover() error {
	return nil
}

// Close releases resources held by the depot. FileDepot does not keep an open
// directory handle, so this is a no-op provided for lifecycle symmetry.
func (d *FileDepot) Close() error {
	return nil
}

// Dir returns the absolute path of the directory backing the depot.
func (d *FileDepot) Dir() string {
	return d.dirPath
}

// removeDepotFile removes a depot file even on platforms that refuse to delete
// read-only files without first clearing the write protection bit.
func removeDepotFile(name string) error {
	if name == "" {
		return nil
	}
	_ = os.Chmod(name, 0666)
	return os.Remove(name)
}

// Replace atomically replaces (or creates) the file specified by the tag. The
// new contents are written and permission-checked in a temporary file in the
// depot directory and only then renamed over the final name. Readers therefore
// observe either the previous generation or the complete new generation, never
// a partial write, and a failed replacement leaves the previous file intact.
func (d *FileDepot) Replace(tag *Tag, data []byte) error {
	depotMutationMu.Lock()
	defer depotMutationMu.Unlock()

	if tag == nil {
		return errors.New("tag is nil")
	}
	if data == nil {
		return errors.New("data is nil")
	}
	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}

	name := d.path(tag.name)
	mode := tag.perm
	if fi, statErr := os.Stat(name); statErr == nil && fi.Mode().IsRegular() {
		// Preserve an existing more restrictive mode instead of loosening it.
		if existing := fi.Mode().Perm(); existing&^tag.perm == 0 {
			mode = existing
		}
	}
	temp, err := os.CreateTemp(d.dirPath, "."+filepath.Base(tag.name)+".tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temp.Close()
			_ = removeDepotFile(tempName)
		}
	}()

	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	fi, err := temp.Stat()
	if err != nil {
		return err
	}
	if !checkPermissions(tag.perm, fi.Mode()) {
		return fmt.Errorf("permissions too lax for %v: required no more than %v, found %v", name, tag.perm, fi.Mode())
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replaceDepotFile(tempName, name); err != nil {
		return err
	}
	committed = true
	return nil
}

// replaceTag stores data for the tag, replacing any previous contents. Depots
// that implement Replace get an atomic replacement. Other Depot
// implementations keep the previous contents when the first write fails.
func replaceTag(d Depot, tag *Tag, data []byte) error {
	if replacer, ok := d.(interface {
		Replace(tag *Tag, data []byte) error
	}); ok {
		return replacer.Replace(tag, data)
	}

	err := d.Put(tag, data)
	if err == nil || !errors.Is(err, fs.ErrExist) {
		return err
	}

	previous, err := d.Get(tag)
	if err != nil {
		return err
	}
	if err := d.Delete(tag); err != nil {
		return err
	}
	if err := d.Put(tag, data); err != nil {
		if restoreErr := d.Put(tag, previous); restoreErr != nil {
			return fmt.Errorf("could not put %q: %w (could not restore previous contents: %v)", tag.name, err, restoreErr)
		}
		return err
	}
	return nil
}

// replaceDepotFile renames old over new. Windows cannot rename over an
// existing read-only file, so it removes the destination first there; other
// platforms use the atomic rename directly.
func replaceDepotFile(oldName, newName string) error {
	err := os.Rename(oldName, newName)
	if err == nil || runtime.GOOS != "windows" {
		return err
	}
	info, statErr := os.Stat(newName)
	if statErr != nil || info.IsDir() {
		return err
	}
	if chmodErr := os.Chmod(newName, 0666); chmodErr != nil {
		return err
	}
	if removeErr := os.Remove(newName); removeErr != nil {
		return err
	}
	return os.Rename(oldName, newName)
}

// Exists reports whether the file at the tag location exists, regardless of
// its permission mode. Mutation paths use this to find and repair stale files
// that a reader would reject for being too permissive.
func (d *FileDepot) Exists(tag *Tag) bool {
	if d == nil || tag == nil {
		return false
	}
	_, err := os.Stat(d.path(tag.name))
	return err == nil
}

// Check returns whether the file at the tag location exists and has permissions at least as restrictive as the given tag.
func (d *FileDepot) Check(tag *Tag) bool {
	name := d.path(tag.name)
	if fi, err := os.Stat(name); err == nil && checkPermissions(tag.perm, fi.Mode()) {
		return true
	}
	return false
}

func (d *FileDepot) check(tag *Tag) error {
	name := d.path(tag.name)
	fi, err := os.Stat(name)
	if err != nil {
		return err
	}
	if !checkPermissions(tag.perm, fi.Mode()) {
		return fmt.Errorf("permissions too lax for %v: required no more than %v, found %v", name, tag.perm, fi.Mode())
	}
	return nil
}

// checkPermissions returns true if the mode bits in file are a subset of required.
func checkPermissions(required, file fs.FileMode) bool {
	// Clear the bits of required from file. The check passes if there are no remaining bits set.
	return file&^required == 0
}

// Get reads the file specified by the tag
func (d *FileDepot) Get(tag *Tag) ([]byte, error) {
	if err := d.check(tag); err != nil {
		return nil, err
	}
	return os.ReadFile(d.path(tag.name))
}

// Delete removes the file specified by the tag
func (d *FileDepot) Delete(tag *Tag) error {
	return removeDepotFile(d.path(tag.name))
}

// List returns all tags in the specified depot
func (d *FileDepot) List() []*Tag {
	var tags = make([]*Tag, 0)

	//nolint:errcheck
	filepath.Walk(d.dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(d.dirPath, path)
		if err != nil {
			return nil
		}
		if rel != info.Name() {
			return nil
		}
		tags = append(tags, &Tag{info.Name(), info.Mode()})
		return nil
	})

	return tags
}

// File is a wrapper around a FileInfo and the files data bytes
type File struct {
	Info os.FileInfo
	Data []byte
}

// GetFile returns the File at the specified tag in the given depot
func (d *FileDepot) GetFile(tag *Tag) (*File, error) {
	if err := d.check(tag); err != nil {
		return nil, err
	}
	fi, err := os.Stat(d.path(tag.name))
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(d.path(tag.name))
	return &File{fi, b}, err
}
