/*-
 * Copyright 2026 Square Inc.
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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/square/certstrap/pkix"
)

func TestStoredIdentityGetCertificateAuthorityRejectsMismatchedKey(t *testing.T) {
	d := getDepot(t)
	defer cleanupStoredIdentityTestDepot(t)

	caKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("Failed creating CA key:", err)
	}
	caCert, err := pkix.CreateCertificateAuthority(caKey, "CA", time.Now().AddDate(1, 0, 0), "test", "US", "", "", "CA", nil)
	if err != nil {
		t.Fatal("Failed creating CA certificate:", err)
	}
	otherKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("Failed creating second key:", err)
	}

	if err := PutCertificate(d, "CA", caCert); err != nil {
		t.Fatal("Failed putting CA certificate:", err)
	}
	if err := PutPrivateKey(d, "CA", otherKey); err != nil {
		t.Fatal("Failed putting mismatched CA key:", err)
	}

	if key, err := GetPrivateKey(d, "CA"); err == nil || key != nil {
		t.Fatal("Loaded a private key that does not match the stored certificate")
	} else {
		var identityErr *StoredIdentityError
		if !errors.As(err, &identityErr) {
			t.Fatalf("GetPrivateKey error = %v, want StoredIdentityError", err)
		}
	}

	ca, err := GetCertificateAuthority(d, "CA")
	if err == nil || ca != nil {
		t.Fatal("Loaded CA identity with a mismatched key")
	}
	if !strings.Contains(err.Error(), `CA "CA"`) || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Mismatch error does not preserve the CA name and key identity: %v", err)
	}

	if err := d.Delete(PrivKeyTag("CA")); err != nil {
		t.Fatal("Failed deleting mismatched CA key:", err)
	}
	if err := PutPrivateKey(d, "CA", caKey); err != nil {
		t.Fatal("Failed putting matching CA key:", err)
	}
	ca, err = GetCertificateAuthority(d, "CA")
	if err != nil {
		t.Fatal("Failed loading matching CA identity:", err)
	}
	if ca.Name != "CA" {
		t.Fatalf("CA name = %q, want CA", ca.Name)
	}
}

func TestStoredIdentityGetEncryptedCertificateAuthority(t *testing.T) {
	d := getDepot(t)
	defer cleanupStoredIdentityTestDepot(t)

	caKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("Failed creating CA key:", err)
	}
	caCert, err := pkix.CreateCertificateAuthority(caKey, "CA", time.Now().AddDate(1, 0, 0), "test", "US", "", "", "CA", nil)
	if err != nil {
		t.Fatal("Failed creating CA certificate:", err)
	}

	if err := PutCertificate(d, "CA", caCert); err != nil {
		t.Fatal("Failed putting CA certificate:", err)
	}
	if err := PutEncryptedPrivateKey(d, "CA", caKey, []byte("passphrase")); err != nil {
		t.Fatal("Failed putting encrypted CA key:", err)
	}
	encrypted, err := IsEncryptedPrivateKey(d, "CA")
	if err != nil {
		t.Fatal("Failed checking encrypted CA key:", err)
	}
	if !encrypted {
		t.Fatal("Encrypted CA key was not recognized as encrypted")
	}

	if _, err := GetCertificateAuthority(d, "CA"); err == nil {
		t.Fatal("Expected the plain CA identity loader to reject an encrypted key")
	}
	ca, err := GetEncryptedCertificateAuthority(d, "CA", []byte("passphrase"))
	if err != nil {
		t.Fatal("Failed loading encrypted CA identity:", err)
	}
	if ca.Name != "CA" {
		t.Fatalf("CA name = %q, want CA", ca.Name)
	}
	if _, err := GetEncryptedCertificateAuthority(d, "CA", []byte("wrong")); err == nil {
		t.Fatal("Loaded encrypted CA identity with the wrong passphrase")
	}
}

func cleanupStoredIdentityTestDepot(t *testing.T) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal("Failed removing test depot:", err)
	}
}
