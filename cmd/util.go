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
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/howeyc/gopass"
	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

var (
	d        *depot.FileDepot
	depotDir string
)

// externalWrite is a file write outside the depot directory requested through
// an explicit --cert/--csr/--key flag. Such writes share the command's
// transaction: they are staged alongside depot writes and rolled back if any
// part of the commit fails.
type externalWrite struct {
	path string
	data []byte
	perm os.FileMode
	// skipExisting preserves the historical behavior of --key: a key that
	// already exists is never overwritten.
	skipExisting bool
	// tempPath is the fully written staging file, backupPath holds the
	// previous generation (if the destination already existed), and
	// published records whether this run replaced the destination.
	tempPath   string
	backupPath string
	published  bool
}

func (w *externalWrite) stage() error {
	if w.skipExisting && fileExists(w.path) {
		return nil
	}

	dir := filepath.Dir(w.path)
	temp, err := os.CreateTemp(dir, ".certstrap-txn-*")
	if err != nil {
		return err
	}
	w.tempPath = temp.Name()

	cleanup := func(cause error) error {
		_ = temp.Close()
		removeExternalPath(w.tempPath)
		w.tempPath = ""
		return cause
	}

	n, err := temp.Write(w.data)
	if err != nil {
		return cleanup(err)
	}
	if n != len(w.data) {
		return cleanup(io.ErrShortWrite)
	}
	if err = temp.Chmod(w.perm); err != nil {
		return cleanup(err)
	}
	if err = temp.Sync(); err != nil {
		return cleanup(err)
	}
	if err = temp.Close(); err != nil {
		return cleanup(err)
	}

	// Preserve the previous generation so a later failure in the same
	// command can restore it instead of deleting an output that may have
	// existed before this run.
	if fi, statErr := os.Lstat(w.path); statErr == nil {
		if fi.IsDir() {
			return cleanup(&os.PathError{Op: "open", Path: w.path, Err: errors.New("is a directory")})
		}
		backup, berr := os.CreateTemp(dir, ".certstrap-txn-backup-*")
		if berr != nil {
			return cleanup(berr)
		}
		backupPath := backup.Name()
		if berr = backup.Close(); berr != nil {
			removeExternalPath(backupPath)
			return cleanup(berr)
		}
		// Reserve a unique name, then let the rename move the original inode
		// (which preserves its mode) into place.
		if berr = os.Remove(backupPath); berr != nil {
			return cleanup(berr)
		}
		if berr = os.Rename(w.path, backupPath); berr != nil {
			return cleanup(berr)
		}
		w.backupPath = backupPath
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return cleanup(statErr)
	}

	if err = os.Rename(w.tempPath, w.path); err != nil {
		w.restoreBackup()
		return cleanup(err)
	}
	w.tempPath = ""
	w.published = true
	return nil
}

func (w *externalWrite) rollback() {
	if w.published {
		removeExternalPath(w.path)
		w.published = false
	}
	w.restoreBackup()
	if w.tempPath != "" {
		removeExternalPath(w.tempPath)
		w.tempPath = ""
	}
}

func (w *externalWrite) restoreBackup() {
	if w.backupPath != "" {
		_ = os.Rename(w.backupPath, w.path)
		w.backupPath = ""
	}
}

func (w *externalWrite) finalize() {
	if w.backupPath != "" {
		removeExternalPath(w.backupPath)
		w.backupPath = ""
	}
}

// removeExternalPath removes a staged or published output file. On platforms
// where a read-only file cannot be unlinked directly, clear the read-only bit
// first.
func removeExternalPath(path string) {
	if err := os.Remove(path); err == nil || os.IsNotExist(err) {
		return
	}
	_ = os.Chmod(path, 0600)
	_ = os.Remove(path)
}

// commitTransaction publishes every staged change for a command as one unit.
// External flag files and depot files only become their final contents once
// all of them can be written. The first failure rolls back every change
// already made and is returned to the caller, which is responsible for
// reporting it and exiting non-zero.
func commitTransaction(txn *depot.Txn, external ...*externalWrite) error {
	staged := make([]*externalWrite, 0, len(external))
	for _, w := range external {
		if w == nil {
			continue
		}
		if err := w.stage(); err != nil {
			w.rollback()
			for i := len(staged) - 1; i >= 0; i-- {
				staged[i].rollback()
			}
			return err
		}
		staged = append(staged, w)
	}

	if err := txn.Commit(); err != nil {
		for i := len(staged) - 1; i >= 0; i-- {
			staged[i].rollback()
		}
		return err
	}
	for _, w := range staged {
		w.finalize()
	}
	return nil
}

// InitDepot creates the depot directory, which stores key/csr/crt files
func InitDepot(path string) error {
	depotDir = path
	if d == nil {
		var err error
		if d, err = depot.NewFileDepot(path); err != nil {
			return err
		}
	}
	return nil
}

func createPassPhrase() ([]byte, error) {
	pass1, err := gopass.GetPasswdPrompt("Enter passphrase (empty for no passphrase): ", false, os.Stdin, os.Stdout)
	if err != nil {
		return nil, err
	}
	pass2, err := gopass.GetPasswdPrompt("Enter same passphrase again: ", false, os.Stdin, os.Stdout)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(pass1, pass2) {
		return nil, errors.New("Passphrases do not match.")
	}
	return pass1, nil
}

func askPassPhrase(name string) ([]byte, error) {
	pass, err := gopass.GetPasswdPrompt(fmt.Sprintf("Enter passphrase for %v (empty for no passphrase): ", name), false, os.Stdin, os.Stdout)
	if err != nil {
		return nil, err
	}
	return pass, nil
}

func getPassPhrase(c *cli.Context, name string) ([]byte, error) {
	if c.IsSet("passphrase") {
		return []byte(c.String("passphrase")), nil
	}
	return askPassPhrase(name)
}

func stageCertificate(c *cli.Context, txn *depot.Txn, name string, crt *pkix.Certificate) (*externalWrite, error) {
	if c.IsSet("cert") {
		bytes, err := crt.Export()
		if err != nil {
			return nil, err
		}
		return &externalWrite{path: c.String("cert"), data: bytes, perm: depot.LeafPerm}, nil
	}
	return nil, depot.PutCertificateInTxn(txn, name, crt)
}

func stageCertificateSigningRequest(c *cli.Context, txn *depot.Txn, name string, csr *pkix.CertificateSigningRequest) (*externalWrite, error) {
	if c.IsSet("csr") {
		bytes, err := csr.Export()
		if err != nil {
			return nil, err
		}
		return &externalWrite{path: c.String("csr"), data: bytes, perm: depot.LeafPerm}, nil
	}
	return nil, depot.PutCertificateSigningRequestInTxn(txn, name, csr)
}

func getCertificateSigningRequest(c *cli.Context, d *depot.FileDepot, name string) (*pkix.CertificateSigningRequest, error) {
	if c.IsSet("csr") {
		bytes, err := os.ReadFile(c.String("csr"))
		if err != nil {
			return nil, err
		}
		return pkix.NewCertificateSigningRequestFromPEM(bytes)
	}
	return depot.GetCertificateSigningRequest(d, name)
}

func stageEncryptedPrivateKey(c *cli.Context, txn *depot.Txn, name string, key *pkix.Key, passphrase []byte) (*externalWrite, error) {
	if c.IsSet("key") {
		if fileExists(c.String("key")) {
			return nil, nil
		}

		bytes, err := key.ExportEncryptedPrivate(passphrase)
		if err != nil {
			return nil, err
		}
		return &externalWrite{path: c.String("key"), data: bytes, perm: depot.BranchPerm, skipExisting: true}, nil
	}
	return nil, depot.PutEncryptedPrivateKeyInTxn(txn, name, key, passphrase)
}

func stagePrivateKey(c *cli.Context, txn *depot.Txn, name string, key *pkix.Key) (*externalWrite, error) {
	if c.IsSet("key") {
		if fileExists(c.String("key")) {
			return nil, nil
		}

		bytes, err := key.ExportPrivate()
		if err != nil {
			return nil, err
		}
		return &externalWrite{path: c.String("key"), data: bytes, perm: depot.BranchPerm, skipExisting: true}, nil
	}
	return nil, depot.PutPrivateKeyInTxn(txn, name, key)
}

func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return !os.IsNotExist(err)
}
