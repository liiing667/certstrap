package depot

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUID34387TxnRollsBackCreateWhenAnotherTargetExists(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(&Tag{"existing.pem", LeafPerm}, []byte("old")); err != nil {
		t.Fatal("seed existing file:", err)
	}

	txn := NewTxn(d)
	if err := txn.Put(&Tag{"new.pem", BranchPerm}, []byte("new key")); err != nil {
		t.Fatal("stage new key:", err)
	}
	if err := txn.Put(&Tag{"existing.pem", LeafPerm}, []byte("replacement")); err != nil {
		t.Fatal("stage existing target:", err)
	}
	if err := txn.Commit(); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("commit error = %v, want already-exists error", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "new.pem")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("new.pem survived failed transaction: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "existing.pem"))
	if err != nil || string(data) != "old" {
		t.Fatalf("existing.pem = %q, %v; want old", data, err)
	}
	assertNoUID34387TxnArtifacts(t, dir)
}

func TestUID34387TxnReplaceRestoresPreviousGeneration(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	tag := &Tag{"CA.crl", LeafPerm}
	if err := d.Put(tag, []byte("old-crl")); err != nil {
		t.Fatal("seed CRL:", err)
	}

	txn := NewTxn(d)
	if err := txn.Replace(tag, []byte("new-crl")); err != nil {
		t.Fatal("stage replacement:", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("commit replacement: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, tag.name))
	if err != nil || string(data) != "new-crl" {
		t.Fatalf("replaced CRL = %q, %v; want new-crl", data, err)
	}
	assertNoUID34387TxnArtifacts(t, dir)
}

func assertNoUID34387TxnArtifacts(t *testing.T, dirname string) {
	t.Helper()
	entries, err := os.ReadDir(dirname)
	if err != nil {
		t.Fatal("read depot:", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".txn-") {
			t.Fatalf("transaction artifact left behind: %s", entry.Name())
		}
	}
}
