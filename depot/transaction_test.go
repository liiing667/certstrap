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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func newTxnDepot(t *testing.T) *FileDepot {
	t.Helper()
	d, err := NewFileDepot(filepath.Join(t.TempDir(), "depot"))
	if err != nil {
		t.Fatal("Failed init Depot:", err)
	}
	return d
}

func depotFileNames(t *testing.T, d *FileDepot) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(d.dirPath)
	if err != nil {
		t.Fatal("Failed reading depot dir:", err)
	}
	names := make(map[string]bool)
	for _, entry := range entries {
		names[entry.Name()] = true
	}
	return names
}

func TestTransactionCommit(t *testing.T) {
	d := newTxnDepot(t)

	txn, err := d.BeginTransaction()
	if err != nil {
		t.Fatal("Failed to begin transaction:", err)
	}
	if err := txn.Put(txnTag1, []byte("one")); err != nil {
		t.Fatal("Failed to stage file:", err)
	}
	if err := txn.Put(txnTag2, []byte("two")); err != nil {
		t.Fatal("Failed to stage file:", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatal("Failed to commit transaction:", err)
	}

	for _, tag := range []*Tag{txnTag1, txnTag2} {
		if !d.Check(tag) {
			t.Fatal("Expected committed file to pass check:", tag.name)
		}
	}
	b, err := d.Get(txnTag1)
	if err != nil {
		t.Fatal("Failed to get committed file:", err)
	}
	if !bytes.Equal(b, []byte("one")) {
		t.Fatal("Committed file has wrong content:", string(b))
	}

	if runtime.GOOS != "windows" {
		// The committed file must have exactly the permission bits of its
		// tag, independent of the umask.
		fi, err := os.Stat(d.path(txnTag1.name))
		if err != nil {
			t.Fatal("Failed to stat committed file:", err)
		}
		if fi.Mode().Perm() != txnTag1.perm {
			t.Fatalf("Committed file perm = %v, want %v", fi.Mode().Perm(), txnTag1.perm)
		}
	}

	// The staging directory must be gone; only the lock file and the
	// committed files may remain.
	names := depotFileNames(t, d)
	if len(names) != 3 || !names[lockFileName] || !names[txnTag1.name] || !names[txnTag2.name] {
		t.Fatal("Unexpected depot content after commit:", names)
	}
}

func TestTransactionCommitDoesNotClobber(t *testing.T) {
	d := newTxnDepot(t)

	if err := d.Put(txnTag2, []byte("original")); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	txn, err := d.BeginTransaction()
	if err != nil {
		t.Fatal("Failed to begin transaction:", err)
	}
	// txnTag1 is linked first and must be rolled back when linking the
	// already existing txnTag2 fails.
	if err := txn.Put(txnTag1, []byte("one")); err != nil {
		t.Fatal("Failed to stage file:", err)
	}
	if err := txn.Put(txnTag2, []byte("new")); err != nil {
		t.Fatal("Failed to stage file:", err)
	}

	err = txn.Commit()
	if err == nil {
		t.Fatal("Expected commit to fail on existing file")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatal("Expected commit to report an existing file, got:", err)
	}

	// The file linked before the failure must have been rolled back.
	if fileExists(d.path(txnTag1.name)) {
		t.Fatal("Expected rolled back file to be removed")
	}
	// The pre-existing file must be untouched.
	b, err := d.Get(txnTag2)
	if err != nil {
		t.Fatal("Failed to get pre-existing file:", err)
	}
	if !bytes.Equal(b, []byte("original")) {
		t.Fatal("Pre-existing file was modified:", string(b))
	}
	// The staging directory must be gone.
	for name := range depotFileNames(t, d) {
		if name != lockFileName && name != txnTag2.name {
			t.Fatal("Unexpected file in depot after failed commit:", name)
		}
	}
}

func TestTransactionRollback(t *testing.T) {
	d := newTxnDepot(t)

	txn, err := d.BeginTransaction()
	if err != nil {
		t.Fatal("Failed to begin transaction:", err)
	}
	if err := txn.Put(txnTag1, []byte("one")); err != nil {
		t.Fatal("Failed to stage file:", err)
	}
	txn.Rollback()

	if fileExists(d.path(txnTag1.name)) {
		t.Fatal("Expected no committed file after rollback")
	}
	if names := depotFileNames(t, d); len(names) != 1 || !names[lockFileName] {
		t.Fatal("Unexpected depot content after rollback:", names)
	}

	// The depot must still be usable after a rollback.
	txn, err = d.BeginTransaction()
	if err != nil {
		t.Fatal("Failed to begin transaction after rollback:", err)
	}
	if err := txn.Put(txnTag1, []byte("one")); err != nil {
		t.Fatal("Failed to stage file:", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatal("Failed to commit after rollback:", err)
	}
}

func TestTransactionRemovesStaleStagingDir(t *testing.T) {
	d := newTxnDepot(t)

	stale := d.path(txnStagingPrefix + "stale")
	if err := os.MkdirAll(stale, 0700); err != nil {
		t.Fatal("Failed to create stale staging dir:", err)
	}
	if err := os.WriteFile(filepath.Join(stale, txnTag1.name), []byte("stale"), 0600); err != nil {
		t.Fatal("Failed to write stale staged file:", err)
	}

	txn, err := d.BeginTransaction()
	if err != nil {
		t.Fatal("Failed to begin transaction:", err)
	}
	txn.Rollback()

	if fileExists(stale) {
		t.Fatal("Expected stale staging dir to be removed")
	}
}

func TestTransactionConcurrentCommit(t *testing.T) {
	d := newTxnDepot(t)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			txn, err := d.BeginTransaction()
			if err != nil {
				errs[i] = err
				return
			}
			data := []byte{'a' + byte(i)}
			for _, tag := range []*Tag{txnTag1, txnTag2, txnTag3} {
				if err := txn.Put(tag, data); err != nil {
					txn.Rollback()
					errs[i] = err
					return
				}
			}
			errs[i] = txn.Commit()
		}(i)
	}
	wg.Wait()

	// Exactly one transaction may win; all others must fail on the
	// already existing files.
	succeeded := 0
	for _, err := range errs {
		if err == nil {
			succeeded++
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal("Unexpected transaction error:", err)
		}
	}
	if succeeded != 1 {
		t.Fatal("Expected exactly one successful transaction, got", succeeded)
	}

	// All committed files must come from the same winning transaction.
	b1, err := d.Get(txnTag1)
	if err != nil {
		t.Fatal("Failed to get committed file:", err)
	}
	for _, tag := range []*Tag{txnTag2, txnTag3} {
		b, err := d.Get(tag)
		if err != nil {
			t.Fatal("Failed to get committed file:", err)
		}
		if !bytes.Equal(b, b1) {
			t.Fatal("Committed files come from different transactions")
		}
	}
}

func TestRecoverIncompleteCA(t *testing.T) {
	const name = "CA"

	put := func(t *testing.T, d *FileDepot, tags ...*Tag) {
		t.Helper()
		for _, tag := range tags {
			if err := d.Put(tag, []byte("data")); err != nil {
				t.Fatal("Failed putting file into Depot:", err)
			}
		}
	}
	exists := func(d *FileDepot, tags ...*Tag) bool {
		for _, tag := range tags {
			if !fileExists(d.path(tag.name)) {
				return false
			}
		}
		return true
	}

	t.Run("complete CA is kept", func(t *testing.T) {
		d := newTxnDepot(t)
		put(t, d, CrtTag(name), PrivKeyTag(name), CrlTag(name))

		recovered, err := RecoverIncompleteCA(d, name)
		if err != nil {
			t.Fatal("Failed to recover:", err)
		}
		if recovered {
			t.Fatal("Expected no recovery for a complete CA")
		}
		if !exists(d, CrtTag(name), PrivKeyTag(name), CrlTag(name)) {
			t.Fatal("Complete CA files must be kept")
		}
	})

	t.Run("empty depot is kept", func(t *testing.T) {
		d := newTxnDepot(t)

		recovered, err := RecoverIncompleteCA(d, name)
		if err != nil {
			t.Fatal("Failed to recover:", err)
		}
		if recovered {
			t.Fatal("Expected no recovery for an empty depot")
		}
	})

	partials := []struct {
		desc string
		tags []*Tag
	}{
		{"key only", []*Tag{PrivKeyTag(name)}},
		{"cert only", []*Tag{CrtTag(name)}},
		{"crl only", []*Tag{CrlTag(name)}},
		{"key and crl", []*Tag{PrivKeyTag(name), CrlTag(name)}},
		{"cert and crl", []*Tag{CrtTag(name), CrlTag(name)}},
	}
	for _, tc := range partials {
		t.Run(tc.desc+" are removed", func(t *testing.T) {
			d := newTxnDepot(t)
			put(t, d, tc.tags...)

			recovered, err := RecoverIncompleteCA(d, name)
			if err != nil {
				t.Fatal("Failed to recover:", err)
			}
			if !recovered {
				t.Fatal("Expected recovery for an incomplete CA")
			}
			for _, tag := range []*Tag{CrtTag(name), PrivKeyTag(name), CrlTag(name)} {
				if fileExists(d.path(tag.name)) {
					t.Fatal("Incomplete CA file must be removed:", tag.name)
				}
			}
		})
	}
}
