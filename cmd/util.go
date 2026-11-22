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

func putCertificate(c *cli.Context, d *depot.FileDepot, name string, crt *pkix.Certificate) error {
	if c.IsSet("cert") {
		bytes, err := crt.Export()
		if err != nil {
			return err
		}
		return writeFileAtomic(c.String("cert"), bytes, depot.LeafPerm)
	}
	return depot.PutCertificate(d, name, crt)
}

// writeFileAtomic writes data to path without exposing a partially written
// file. The temporary file is created next to the destination so a rename is
// atomic on the same filesystem.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	mode := perm
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			// Preserve the legacy behavior for devices, FIFOs and symlinks;
			// atomic replacement only applies to regular files.
			return os.WriteFile(path, data, perm)
		}
		mode = info.Mode().Perm()
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		// Windows does not replace an existing file with Rename.
		if info, statErr := os.Stat(path); statErr == nil && !info.IsDir() {
			if removeErr := os.Remove(path); removeErr != nil {
				return err
			}
			return os.Rename(tmpName, path)
		}
		return err
	}
	return nil
}

func putCertificateSigningRequest(c *cli.Context, d *depot.FileDepot, name string, csr *pkix.CertificateSigningRequest) error {
	if c.IsSet("csr") {
		bytes, err := csr.Export()
		if err != nil {
			return err
		}
		return os.WriteFile(c.String("csr"), bytes, depot.LeafPerm)
	}
	return depot.PutCertificateSigningRequest(d, name, csr)
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

func putEncryptedPrivateKey(c *cli.Context, d *depot.FileDepot, name string, key *pkix.Key, passphrase []byte) error {
	if c.IsSet("key") {
		if fileExists(c.String("key")) {
			return nil
		}

		bytes, err := key.ExportEncryptedPrivate(passphrase)
		if err != nil {
			return err
		}
		return os.WriteFile(c.String("key"), bytes, depot.BranchPerm)
	}
	return depot.PutEncryptedPrivateKey(d, name, key, passphrase)
}

func putPrivateKey(c *cli.Context, d *depot.FileDepot, name string, key *pkix.Key) error {
	if c.IsSet("key") {
		if fileExists(c.String("key")) {
			return nil
		}

		bytes, err := key.ExportPrivate()
		if err != nil {
			return err
		}
		return os.WriteFile(c.String("key"), bytes, depot.BranchPerm)
	}
	return depot.PutPrivateKey(d, name, key)
}

func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return !os.IsNotExist(err)
}
