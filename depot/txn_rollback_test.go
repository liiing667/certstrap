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

// TestTxnRollbackRestoresReplacedFileMode forces a commit to fail after one
// replacement has already been staged. The replacement must be rolled back
// with both its contents and its permissions intact so later depot reads do
// not fail a permission check on the restored generation.
func TestTxnRollbackRestoresReplacedFileMode(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	crl := &Tag{"CA.crl", 0444}
	if err := d.Put(crl, []byte("old-crl")); err != nil {
		t.Fatal("seed CRL failed:", err)
	}
	existing := &Tag{"existing.crt", 0444}
	if err := d.Put(existing, []byte("old-cert")); err != nil {
		t.Fatal("seed certificate failed:", err)
	}

	txn := NewTxn(d)
	if err := txn.Replace(crl, []byte("new-crl")); err != nil {
		t.Fatal("stage CRL replacement failed:", err)
	}
	// This create collides with an existing file. The collision is only
	// discovered at Commit, after the CRL replacement was staged.
	if err := txn.Put(existing, []byte("new-cert")); err != nil {
		t.Fatal("stage certificate failed:", err)
	}
	if err := txn.Commit(); err == nil || !os.IsExist(err) {
		t.Fatalf("commit err = %v, want an already-exists error", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, crl.name))
	if err != nil || string(got) != "old-crl" {
		t.Fatalf("CA.crl = %q, %v; want old-crl restored", got, err)
	}
	fi, err := os.Stat(filepath.Join(dir, crl.name))
	if err != nil {
		t.Fatal("stat restored CA.crl:", err)
	}
	if fi.Mode().Perm() != crl.perm {
		t.Fatalf("restored CA.crl mode = %o, want %o", fi.Mode().Perm(), crl.perm)
	}
	if !d.Check(crl) {
		t.Fatal("restored CA.crl fails the depot permission check")
	}

	got, err = os.ReadFile(filepath.Join(dir, existing.name))
	if err != nil || string(got) != "old-cert" {
		t.Fatalf("existing.crt = %q, %v; want untouched original", got, err)
	}
	if leftovers := findTxnTempFiles(t); len(leftovers) != 0 {
		t.Fatalf("temporary/backup files left behind: %v", leftovers)
	}
}
