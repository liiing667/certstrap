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
	"os"
	"path/filepath"
	"testing"
)

// TestTxnCommitPublishesAllFiles checks that a transaction only exposes its
// files once every write is staged, and that the published files keep the
// permissions their tags demand.
func TestTxnCommitPublishesAllFiles(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	txn := NewTxn(d)
	if err := txn.Put(&Tag{"a.pem", 0600}, []byte("aaa")); err != nil {
		t.Fatal("staging a.pem failed:", err)
	}
	if err := txn.Put(&Tag{"b.pem", 0444}, []byte("bbb")); err != nil {
		t.Fatal("staging b.pem failed:", err)
	}

	// Nothing must be visible under a final name before commit.
	if _, err := os.Stat(filepath.Join(dir, "a.pem")); !os.IsNotExist(err) {
		t.Fatalf("a.pem visible before commit: %v", err)
	}

	if err := txn.Commit(); err != nil {
		t.Fatal("commit failed:", err)
	}

	for _, tc := range []struct {
		name string
		perm os.FileMode
		body string
	}{
		{"a.pem", 0600, "aaa"},
		{"b.pem", 0444, "bbb"},
	} {
		fi, err := os.Stat(filepath.Join(dir, tc.name))
		if err != nil {
			t.Fatalf("stat %s: %v", tc.name, err)
		}
		if fi.Mode() != tc.perm {
			t.Fatalf("%s perm = %o, want %o", tc.name, fi.Mode(), tc.perm)
		}
		got, err := os.ReadFile(filepath.Join(dir, tc.name))
		if err != nil {
			t.Fatalf("read %s: %v", tc.name, err)
		}
		if string(got) != tc.body {
			t.Fatalf("%s body = %q, want %q", tc.name, got, tc.body)
		}
	}

	if leftovers := findTxnTempFiles(t); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// TestTxnPutRejectsExistingFile keeps the no-overwrite semantics of
// FileDepot.Put: a Put against an existing name must fail the whole
// transaction without touching any of its other staged files.
func TestTxnPutRejectsExistingFile(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(&Tag{"a.pem", 0600}, []byte("original")); err != nil {
		t.Fatal("seed put failed:", err)
	}

	txn := NewTxn(d)
	if err := txn.Put(&Tag{"a.pem", 0600}, []byte("new")); err != nil {
		t.Fatal("staging failed:", err)
	}
	if err := txn.Put(&Tag{"b.pem", 0600}, []byte("b")); err != nil {
		t.Fatal("staging failed:", err)
	}

	err := txn.Commit()
	if err == nil || !os.IsExist(err) {
		t.Fatalf("commit err = %v, want an already-exists error", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "a.pem"))
	if err != nil {
		t.Fatal("reading a.pem:", err)
	}
	if string(got) != "original" {
		t.Fatalf("a.pem changed to %q, want the original generation", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.pem")); !os.IsNotExist(err) {
		t.Fatalf("b.pem should not have been published: %v", err)
	}
	if leftovers := findTxnTempFiles(t); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// TestTxnRollbackOnCommitFailure forces a commit to fail by removing write
// permission from the depot directory. No part of the transaction may survive.
func TestTxnRollbackOnCommitFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}

	d := getDepot(t)
	defer os.RemoveAll(dir)

	// Seed one file that the failing transaction must leave untouched.
	seed := &Tag{"seed.pem", 0600}
	if err := d.Put(seed, []byte("seed")); err != nil {
		t.Fatal("seed put failed:", err)
	}

	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal("chmod depot:", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })

	txn := NewTxn(d)
	if err := txn.Put(&Tag{"a.pem", 0600}, []byte("a")); err != nil {
		t.Fatal("staging failed:", err)
	}
	if err := txn.Put(&Tag{"b.pem", 0600}, []byte("b")); err != nil {
		t.Fatal("staging failed:", err)
	}
	if err := txn.Commit(); err == nil {
		t.Fatal("commit succeeded against a read-only depot, want failure")
	}

	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal("restore chmod:", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "seed.pem"))
	if err != nil || string(got) != "seed" {
		t.Fatalf("seed.pem = %q, %v; want untouched original", got, err)
	}
	for _, name := range []string{"a.pem", "b.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s survived a failed transaction: %v", name, err)
		}
	}
	if leftovers := findTxnTempFiles(t); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// TestTxnReplaceRestoresPreviousGeneration checks that Replace swaps the file
// atomically on success and restores the previous contents on failure, so a
// depot can never keep a mixed generation of CA material.
func TestTxnReplaceRestoresPreviousGeneration(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	tag := &Tag{"CA.crl", 0444}
	if err := d.Put(tag, []byte("generation-1")); err != nil {
		t.Fatal("seed put failed:", err)
	}

	ok := NewTxn(d)
	if err := ok.Replace(tag, []byte("generation-2")); err != nil {
		t.Fatal("staging replace failed:", err)
	}
	if err := ok.Commit(); err != nil {
		t.Fatal("replace commit failed:", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, tag.name))
	if err != nil || string(got) != "generation-2" {
		t.Fatalf("after replace body = %q, %v; want generation-2", got, err)
	}

	// A second transaction that fails must bring generation-2 back.
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal("chmod:", err)
	}
	failed := NewTxn(d)
	if err := failed.Replace(tag, []byte("generation-3")); err != nil {
		t.Fatal("staging replace failed:", err)
	}
	if err := failed.Commit(); err == nil {
		t.Fatal("replace succeeded against a read-only depot, want failure")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal("restore chmod:", err)
	}

	got, err = os.ReadFile(filepath.Join(dir, tag.name))
	if err != nil || string(got) != "generation-2" {
		t.Fatalf("after failed replace body = %q, %v; want generation-2 restored", got, err)
	}
	if leftovers := findTxnTempFiles(t); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// TestTxnReplaceMissingFileFails ensures Replace cannot create a file through
// the replace path and leaves no partial state behind.
func TestTxnReplaceMissingFileFails(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	txn := NewTxn(d)
	if err := txn.Replace(&Tag{"missing.pem", 0600}, []byte("x")); err != nil {
		t.Fatal("staging failed:", err)
	}
	if err := txn.Commit(); err == nil {
		t.Fatal("replace of a missing file succeeded, want failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.pem")); !os.IsNotExist(err) {
		t.Fatalf("missing.pem created by failed replace: %v", err)
	}
	if leftovers := findTxnTempFiles(t); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// TestTxnNilData mirrors FileDepot.Put's rejection of nil data.
func TestTxnNilData(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	txn := NewTxn(d)
	if err := txn.Put(&Tag{"nil.pem", 0600}, nil); err == nil {
		t.Fatal("Put(nil) succeeded, want error")
	}
	if err := txn.Replace(&Tag{"nil.pem", 0600}, nil); err == nil {
		t.Fatal("Replace(nil) succeeded, want error")
	}
}

// TestTxnMixedPutAndReplaceRollback stages a replacement of an existing file
// together with creation of new files, then forces the commit to fail. The
// replaced file must return to its previous generation and none of the new
// files may appear, so a command can never leave mixed CA generations behind.
func TestTxnMixedPutAndReplaceRollback(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}

	d := getDepot(t)
	defer os.RemoveAll(dir)

	crlTag := &Tag{"CA.crl", 0444}
	if err := d.Put(crlTag, []byte("old-crl")); err != nil {
		t.Fatal("seed CRL failed:", err)
	}

	txn := NewTxn(d)
	if err := txn.Put(&Tag{"host.crt", 0444}, []byte("new-cert")); err != nil {
		t.Fatal("stage cert failed:", err)
	}
	if err := txn.Replace(crlTag, []byte("new-crl")); err != nil {
		t.Fatal("stage CRL replace failed:", err)
	}

	// Block the final rename by removing write permission from the depot. The
	// temp files and the staged backup are all inside the same directory.
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal("chmod:", err)
	}
	err := txn.Commit()
	if err == nil {
		t.Fatal("commit succeeded against a read-only depot, want failure")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal("restore chmod:", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "CA.crl"))
	if err != nil || string(got) != "old-crl" {
		t.Fatalf("CA.crl = %q, %v; want old-crl restored", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "host.crt")); !os.IsNotExist(err) {
		t.Fatalf("host.crt survived the failed transaction: %v", err)
	}
	if leftovers := findTxnTempFiles(t); len(leftovers) != 0 {
		t.Fatalf("temporary/backup files left behind: %v", leftovers)
	}
}

func findTxnTempFiles(t *testing.T) []string {
	t.Helper()
	var found []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("read depot dir:", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if len(name) > 1 && name[0] == '.' {
			found = append(found, name)
		}
	}
	return found
}
