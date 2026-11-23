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
	"strings"
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

// ValidateName returns an error if name cannot identify an object stored in
// a depot. Depot object names must be relative and must not climb out of the
// depot root through parent-directory references, so that a name always
// identifies one object confined to the depot.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("empty depot object name")
	}
	if filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return fmt.Errorf("invalid depot object name %q: absolute paths are not allowed", name)
	}
	if cleaned := filepath.Clean(name); cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return fmt.Errorf("invalid depot object name %q: name escapes the depot", name)
	}
	return nil
}

// resolvePath returns the canonical location of path: symlinks in every
// existing component are resolved, and components that do not exist yet are
// appended to the resolved location of their deepest existing ancestor.
func resolvePath(path string) (string, error) {
	components := []string{}
	current := path
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			return filepath.Join(append([]string{resolved}, components...)...), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("cannot resolve path %q", path)
		}
		components = append([]string{filepath.Base(current)}, components...)
		current = parent
	}
}

// resolve maps name to the absolute path of the depot object it identifies.
// The returned path is guaranteed to stay inside the depot root: the name
// must be relative and free of parent-directory references, and the depot
// directory and every existing path component are resolved, so that neither
// a path alias for the depot nor a symlink swapped in for a depot object can
// redirect the object outside the depot root. All file operations and error
// messages use this single resolved identity.
func (d *FileDepot) resolve(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}

	// Resolve the depot root itself, so that a depot reached through a
	// symlink or path alias is compared by its real location.
	root, err := resolvePath(d.dirPath)
	if err != nil {
		return "", err
	}

	resolved, err := resolvePath(filepath.Join(d.dirPath, name))
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid depot object name %q: path escapes the depot", name)
	}
	return resolved, nil
}

// Put inserts the data into the file specified by the tag
func (d *FileDepot) Put(tag *Tag, data []byte) error {
	if data == nil {
		return errors.New("data is nil")
	}

	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}

	name, err := d.resolve(tag.name)
	if err != nil {
		return err
	}

	perm := tag.perm

	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}

	file.Close()
	return nil
}

// Check returns whether the file at the tag location exists and has permissions at least as restrictive as the given tag.
func (d *FileDepot) Check(tag *Tag) bool {
	name, err := d.resolve(tag.name)
	if err != nil {
		return false
	}
	if fi, err := os.Stat(name); err == nil && checkPermissions(tag.perm, fi.Mode()) {
		return true
	}
	return false
}

func (d *FileDepot) check(tag *Tag) (string, error) {
	name, err := d.resolve(tag.name)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(name)
	if err != nil {
		return "", err
	}
	if !checkPermissions(tag.perm, fi.Mode()) {
		return "", fmt.Errorf("permissions too lax for %v: required no more than %v, found %v", name, tag.perm, fi.Mode())
	}
	return name, nil
}

// checkPermissions returns true if the mode bits in file are a subset of required.
func checkPermissions(required, file fs.FileMode) bool {
	// Clear the bits of required from file. The check passes if there are no remaining bits set.
	return file&^required == 0
}

// Get reads the file specified by the tag
func (d *FileDepot) Get(tag *Tag) ([]byte, error) {
	name, err := d.check(tag)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(name)
}

// Delete removes the file specified by the tag
func (d *FileDepot) Delete(tag *Tag) error {
	if _, err := d.resolve(tag.name); err != nil {
		return err
	}
	// Remove the depot entry itself rather than following a final symlink;
	// resolve already verified that the object stays inside the depot.
	return os.Remove(filepath.Join(d.dirPath, tag.name))
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
	name, err := d.check(tag)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(name)
	return &File{fi, b}, err
}
