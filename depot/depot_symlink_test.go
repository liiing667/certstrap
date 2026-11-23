//go:build !windows
// +build !windows

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
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestDepotSymlinkEscape checks that once a depot object is replaced by a
// symlink pointing outside the depot, no operation reads, writes or deletes
// the outside object.
func TestDepotSymlinkEscape(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)
	defer os.Remove("outside.pem")

	if err := os.WriteFile("outside.pem", []byte(data), 0600); err != nil {
		t.Fatal("Failed writing outside file:", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal("Failed creating depot dir:", err)
	}
	if err := os.Symlink("../outside.pem", filepath.Join(dir, "host.pem")); err != nil {
		t.Fatal("Failed creating symlink:", err)
	}

	link := &Tag{"host.pem", 0600}
	if _, err := d.Get(link); err == nil {
		t.Fatal("Expected Get to reject a symlink escaping the depot")
	}
	if _, err := d.GetFile(link); err == nil {
		t.Fatal("Expected GetFile to reject a symlink escaping the depot")
	}
	if d.Check(link) {
		t.Fatal("Expected Check to reject a symlink escaping the depot")
	}
	if err := d.Put(link, []byte(data)); err == nil {
		t.Fatal("Expected Put to reject a symlink escaping the depot")
	}
	if err := d.Delete(link); err == nil {
		t.Fatal("Expected Delete to reject a symlink escaping the depot")
	}

	b, err := os.ReadFile("outside.pem")
	if err != nil || !bytes.Equal(b, []byte(data)) {
		t.Fatal("The file outside the depot was read or modified")
	}
}

// TestDepotPathAlias checks that a depot reached through a symlink alias
// still resolves objects inside the real depot root, so normal names keep
// working while escapes are caught relative to the real location.
func TestDepotPathAlias(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	alias := dir + "-alias"
	defer os.Remove(alias)
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal("Failed creating depot path alias:", err)
	}

	ad, err := NewFileDepot(alias)
	if err != nil {
		t.Fatal("Failed init Depot through alias:", err)
	}

	dataRead, err := ad.Get(tag)
	if err != nil {
		t.Fatal("Failed getting file through aliased Depot:", err)
	}
	if !bytes.Equal(dataRead, []byte(data)) {
		t.Fatal("Failed getting the previous data through aliased Depot")
	}

	if err := ad.Put(tag2, []byte(data)); err != nil {
		t.Fatal("Failed putting file into aliased Depot:", err)
	}
	if dataRead, err := d.Get(tag2); err != nil || !bytes.Equal(dataRead, []byte(data)) {
		t.Fatal("Failed reading back file written through aliased Depot:", err)
	}

	if err := ad.Delete(tag2); err != nil {
		t.Fatal("Failed deleting file through aliased Depot:", err)
	}
	if d.Check(tag2) {
		t.Fatal("Expected the tag to be deleted")
	}
}

// TestDepotSymlinkSwapAfterCreate checks that replacing a depot object with
// a symlink after the depot was opened is detected on the next operation.
func TestDepotSymlinkSwapAfterCreate(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)
	defer os.Remove("outside.pem")

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}
	if _, err := d.Get(tag); err != nil {
		t.Fatal("Failed getting file from Depot:", err)
	}

	if err := os.WriteFile("outside.pem", []byte(data), 0600); err != nil {
		t.Fatal("Failed writing outside file:", err)
	}
	if err := os.Remove(filepath.Join(dir, tag.name)); err != nil {
		t.Fatal("Failed removing depot object:", err)
	}
	if err := os.Symlink("../outside.pem", filepath.Join(dir, tag.name)); err != nil {
		t.Fatal("Failed swapping in symlink:", err)
	}

	if _, err := d.Get(tag); err == nil {
		t.Fatal("Expected Get to reject a swapped-in symlink escaping the depot")
	}
	if d.Check(tag) {
		t.Fatal("Expected Check to reject a swapped-in symlink escaping the depot")
	}
}
