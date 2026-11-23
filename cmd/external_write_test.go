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

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExternalWriteRollbackRestoresPreviousFile checks that an output path
// supplied through --cert/--csr/--key is part of the command transaction. If
// another write in the same command fails, the previous file contents and
// permissions must be restored rather than deleted.
func TestExternalWriteRollbackRestoresPreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.crt")
	if err := os.WriteFile(path, []byte("previous-generation"), 0640); err != nil {
		t.Fatal("seed external file:", err)
	}

	w := &externalWrite{path: path, data: []byte("new-generation"), perm: 0644}
	if err := w.stage(); err != nil {
		t.Fatal("stage external write:", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "new-generation" {
		t.Fatalf("after stage = %q, %v; want new-generation", got, err)
	}

	w.rollback()

	got, err := os.ReadFile(path)
	if err != nil || string(got) != "previous-generation" {
		t.Fatalf("after rollback = %q, %v; want previous-generation", got, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal("stat restored external file:", err)
	}
	if fi.Mode().Perm() != 0640 {
		t.Fatalf("restored mode = %o, want 0640", fi.Mode().Perm())
	}
	assertNoExternalTxnFiles(t, dir)
}

// TestExternalWriteSkipExistingKeepsHistoricalKeyBehavior pins the old --key
// boundary: an existing key is read, never rewritten or rolled back.
func TestExternalWriteSkipExistingKeepsHistoricalKeyBehavior(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.key")
	if err := os.WriteFile(path, []byte("existing-key"), 0640); err != nil {
		t.Fatal("seed external key:", err)
	}

	w := &externalWrite{
		path:         path,
		data:         []byte("generated-key"),
		perm:         0440,
		skipExisting: true,
	}
	if err := w.stage(); err != nil {
		t.Fatal("stage external key:", err)
	}
	w.rollback()

	got, err := os.ReadFile(path)
	if err != nil || string(got) != "existing-key" {
		t.Fatalf("existing key = %q, %v; want unchanged existing-key", got, err)
	}
	assertNoExternalTxnFiles(t, dir)
}

// TestExternalWriteRejectsDirectory keeps the old error boundary for an
// output path that is a directory; the path must not be replaced by the
// staged file.
func TestExternalWriteRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.crt")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal("create output directory:", err)
	}

	w := &externalWrite{path: path, data: []byte("certificate"), perm: 0444}
	if err := w.stage(); err == nil {
		t.Fatal("stage succeeded for a directory output path")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal("stat output path:", err)
	}
	if !fi.IsDir() {
		t.Fatal("output path is no longer a directory")
	}
	assertNoExternalTxnFiles(t, dir)
}

func assertNoExternalTxnFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("read external output dir:", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".certstrap-txn-") {
			t.Fatalf("transaction temporary file left behind: %s", filepath.Join(dir, entry.Name()))
		}
	}
}
