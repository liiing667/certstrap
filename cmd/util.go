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
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

var (
	d        *depot.FileDepot
	depotDir string
)

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

func removeFile(name string) error {
	if name == "" {
		return nil
	}
	_ = os.Chmod(name, 0666)
	return os.Remove(name)
}

// writeFileAtomic writes data to path without exposing a partially written
// file. If path already exists and is a regular file, its permission bits are
// preserved, matching the historical behavior of writing into an existing
// file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	mode := perm
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return os.WriteFile(path, data, perm)
		}
		if existing := info.Mode().Perm(); existing&^perm == 0 {
			// Preserve an existing more restrictive mode; never loosen it.
			mode = existing
		}
	}

	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temp.Close()
			_ = removeFile(tempName)
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
	if err := temp.Close(); err != nil {
		return err
	}
	if err := renameFile(tempName, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func renameFile(oldName, newName string) error {
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

func keyEvidence(key *pkix.Key, stage string) string {
	fingerprint := "unknown"
	algorithm := "unknown"
	if key != nil {
		if value, err := key.Fingerprint(); err == nil {
			fingerprint = value
		} else if key.Public != nil {
			if value, err := pkix.PublicKeyFingerprint(key.Public); err == nil {
				fingerprint = value
			}
		}
		if value, err := key.Algorithm(); err == nil {
			algorithm = value
		} else if key.Public != nil {
			if value, err := pkix.PublicKeyAlgorithm(key.Public); err == nil {
				algorithm = value
			}
		}
	}
	return fmt.Sprintf("key_fingerprint=%s algorithm=%s passphrase_stage=%s operation=%s permissions=%#o", fingerprint, algorithm, passphraseStage(stage), stage, depot.BranchPerm)
}

func passphraseStage(stage string) string {
	switch {
	case strings.Contains(stage, "decrypt"):
		return "decrypt"
	case strings.Contains(stage, "encrypt"):
		return "encrypt"
	default:
		return "plaintext"
	}
}

func stageCertificate(c *cli.Context, txn *depot.Txn, name string, crt *pkix.Certificate) error {
	if c.IsSet("cert") {
		bytes, err := crt.Export()
		if err != nil {
			return err
		}
		return writeFileAtomic(c.String("cert"), bytes, depot.LeafPerm)
	}
	return depot.PutCertificateInTxn(txn, name, crt)
}

func stageCertificateSigningRequest(c *cli.Context, txn *depot.Txn, name string, csr *pkix.CertificateSigningRequest) error {
	if c.IsSet("csr") {
		bytes, err := csr.Export()
		if err != nil {
			return err
		}
		return writeFileAtomic(c.String("csr"), bytes, depot.LeafPerm)
	}
	return depot.PutOrReplaceCertificateSigningRequestInTxn(txn, name, csr)
}

func externalKeyMatches(path string, key *pkix.Key, passphrase []byte) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.Mode().Perm()&^depot.BranchPerm != 0 {
		// A too-wide existing key must be rewritten so replacement can
		// enforce the required permission mode.
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	existing, err := pkix.NewKeyFromPrivateKeyPEM(data)
	if err == nil {
		if len(passphrase) > 0 {
			// The caller requested an encrypted key; rewrite the plaintext
			// file rather than silently keeping the old passphrase state.
			return false
		}
	} else if len(passphrase) > 0 {
		existing, err = pkix.NewKeyFromEncryptedPrivateKeyPEM(data, passphrase)
	}
	if err != nil {
		return false
	}
	want, err := key.Fingerprint()
	if err != nil {
		return false
	}
	got, err := existing.Fingerprint()
	if err != nil {
		return false
	}
	return got == want
}

func stageEncryptedPrivateKey(c *cli.Context, txn *depot.Txn, name string, key *pkix.Key, passphrase []byte) error {
	if c.IsSet("key") {
		if externalKeyMatches(c.String("key"), key, passphrase) {
			return nil
		}
		bytes, err := key.ExportEncryptedPrivate(passphrase)
		if err != nil {
			return fmt.Errorf("encrypted private key export failed (%s): %w", keyEvidence(key, "export-encrypted"), err)
		}
		if err := writeFileAtomic(c.String("key"), bytes, depot.BranchPerm); err != nil {
			return fmt.Errorf("encrypted private key write failed (%s): %w", keyEvidence(key, "write-encrypted"), err)
		}
		return nil
	}
	if err := depot.PutOrReplaceEncryptedPrivateKeyInTxn(txn, name, key, passphrase); err != nil {
		return fmt.Errorf("encrypted private key commit failed (%s): %w", keyEvidence(key, "commit-encrypted"), err)
	}
	return nil
}

func stagePrivateKey(c *cli.Context, txn *depot.Txn, name string, key *pkix.Key) error {
	if c.IsSet("key") {
		if externalKeyMatches(c.String("key"), key, nil) {
			return nil
		}
		bytes, err := key.ExportPrivate()
		if err != nil {
			return fmt.Errorf("plaintext private key export failed (%s): %w", keyEvidence(key, "export-plaintext"), err)
		}
		if err := writeFileAtomic(c.String("key"), bytes, depot.BranchPerm); err != nil {
			return fmt.Errorf("plaintext private key write failed (%s): %w", keyEvidence(key, "write-plaintext"), err)
		}
		return nil
	}
	if err := depot.PutOrReplacePrivateKeyInTxn(txn, name, key); err != nil {
		return fmt.Errorf("plaintext private key commit failed (%s): %w", keyEvidence(key, "commit-plaintext"), err)
	}
	return nil
}

// The put* helpers keep the historical package-level entry points used by
// tests and callers while routing them through one transaction.
//nolint:unused // kept for compatibility with package callers and tests.
func putCertificate(c *cli.Context, d *depot.FileDepot, name string, crt *pkix.Certificate) error {
	txn := depot.NewTxn(d)
	if err := stageCertificate(c, txn, name, crt); err != nil {
		return err
	}
	return txn.Commit()
}

//nolint:unused // kept for compatibility with package callers and tests.
func putCertificateSigningRequest(c *cli.Context, d *depot.FileDepot, name string, csr *pkix.CertificateSigningRequest) error {
	txn := depot.NewTxn(d)
	if err := stageCertificateSigningRequest(c, txn, name, csr); err != nil {
		return err
	}
	return txn.Commit()
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

//nolint:unused // kept for compatibility with package callers and tests.
func putEncryptedPrivateKey(c *cli.Context, d *depot.FileDepot, name string, key *pkix.Key, passphrase []byte) error {
	txn := depot.NewTxn(d)
	if err := stageEncryptedPrivateKey(c, txn, name, key, passphrase); err != nil {
		return err
	}
	return txn.Commit()
}

//nolint:unused // kept for compatibility with package callers and tests.
func putPrivateKey(c *cli.Context, d *depot.FileDepot, name string, key *pkix.Key) error {
	txn := depot.NewTxn(d)
	if err := stagePrivateKey(c, txn, name, key); err != nil {
		return err
	}
	return txn.Commit()
}

func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return !os.IsNotExist(err)
}
