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

package cmd

import (
	"errors"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

func setupSignerIdentityTestDepot(t *testing.T) {
	t.Helper()
	var err error
	d, err = depot.NewFileDepot(t.TempDir())
	if err != nil {
		t.Fatal("Failed creating test depot:", err)
	}
}

func signerIdentityCLIContext(t *testing.T, passphrase string) *cli.Context {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("passphrase", "", "")
	if err := fs.Parse([]string{"--passphrase", passphrase}); err != nil {
		t.Fatal("Failed parsing test flags:", err)
	}
	return cli.NewContext(nil, fs, nil)
}

func TestSignerIdentityLoadSigningCARejectsMismatchedKey(t *testing.T) {
	setupSignerIdentityTestDepot(t)

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
		t.Fatal("Failed creating other key:", err)
	}

	if err := depot.PutCertificate(d, "CA", caCert); err != nil {
		t.Fatal("Failed putting CA certificate:", err)
	}
	if err := depot.PutPrivateKey(d, "CA", otherKey); err != nil {
		t.Fatal("Failed putting mismatched CA key:", err)
	}

	ca, err := loadSigningCA(nil, "CA")
	if err == nil || ca != nil {
		t.Fatal("Loaded a CA identity with a mismatched private key")
	}
	if !strings.Contains(err.Error(), `CA "CA"`) || !strings.Contains(err.Error(), "does not match private signer") {
		t.Fatalf("Error does not preserve the CA name and signer identity: %v", err)
	}
}

func TestSignerIdentityLoadSigningCARejectsNonCA(t *testing.T) {
	setupSignerIdentityTestDepot(t)

	key, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("Failed creating key:", err)
	}
	csr, err := pkix.CreateCertificateSigningRequest(key, "leaf", nil, []string{"leaf.example"}, nil, "test", "US", "", "", "leaf")
	if err != nil {
		t.Fatal("Failed creating request:", err)
	}
	caKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("Failed creating CA key:", err)
	}
	caCert, err := pkix.CreateCertificateAuthority(caKey, "CA", time.Now().AddDate(1, 0, 0), "test", "US", "", "", "CA", nil)
	if err != nil {
		t.Fatal("Failed creating CA certificate:", err)
	}
	leafCert, err := pkix.CreateCertificateHost(caCert, caKey, csr, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal("Failed creating leaf certificate:", err)
	}

	if err := depot.PutCertificate(d, "leaf", leafCert); err != nil {
		t.Fatal("Failed putting leaf certificate:", err)
	}
	if err := depot.PutPrivateKey(d, "leaf", key); err != nil {
		t.Fatal("Failed putting leaf key:", err)
	}

	ca, err := loadSigningCA(nil, "leaf")
	if err == nil || ca != nil {
		t.Fatal("Loaded a non-CA certificate as a signing authority")
	}
	if !errors.Is(err, errSelectedCANotCA) {
		t.Fatalf("Error = %v, want %v", err, errSelectedCANotCA)
	}
}

func TestSignerIdentityLoadSigningCADistinguishesPassphraseFailure(t *testing.T) {
	setupSignerIdentityTestDepot(t)

	caKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("Failed creating CA key:", err)
	}
	caCert, err := pkix.CreateCertificateAuthority(caKey, "CA", time.Now().AddDate(1, 0, 0), "test", "US", "", "", "CA", nil)
	if err != nil {
		t.Fatal("Failed creating CA certificate:", err)
	}
	if err := depot.PutCertificate(d, "CA", caCert); err != nil {
		t.Fatal("Failed putting CA certificate:", err)
	}
	if err := depot.PutEncryptedPrivateKey(d, "CA", caKey, []byte("correct")); err != nil {
		t.Fatal("Failed putting encrypted CA key:", err)
	}

	ca, err := loadSigningCA(signerIdentityCLIContext(t, "wrong"), "CA")
	if err == nil || ca != nil {
		t.Fatal("Loaded an encrypted CA key with the wrong passphrase")
	}
	if !strings.Contains(err.Error(), `CA "CA"`) || !strings.Contains(err.Error(), "decrypt CA private key") {
		t.Fatalf("Passphrase error does not preserve the CA name and stage: %v", err)
	}

	ca, err = loadSigningCA(signerIdentityCLIContext(t, "correct"), "CA")
	if err != nil {
		t.Fatal("Failed loading CA identity with the correct passphrase:", err)
	}
	if ca.Name != "CA" {
		t.Fatalf("CA name = %q, want CA", ca.Name)
	}
}

func TestSignerIdentityVerifyPublishedCAIdentityDetectsRotation(t *testing.T) {
	setupSignerIdentityTestDepot(t)

	caKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("Failed creating CA key:", err)
	}
	caCert, err := pkix.CreateCertificateAuthority(caKey, "CA", time.Now().AddDate(1, 0, 0), "test", "US", "", "", "CA", nil)
	if err != nil {
		t.Fatal("Failed creating CA certificate:", err)
	}
	if err := depot.PutCertificate(d, "CA", caCert); err != nil {
		t.Fatal("Failed putting CA certificate:", err)
	}
	if err := depot.PutPrivateKey(d, "CA", caKey); err != nil {
		t.Fatal("Failed putting CA key:", err)
	}
	ca, err := loadSigningCA(nil, "CA")
	if err != nil {
		t.Fatal("Failed loading CA identity:", err)
	}
	if err := verifyPublishedCAIdentity(ca); err != nil {
		t.Fatal("Unchanged CA identity failed verification:", err)
	}

	newKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("Failed creating replacement key:", err)
	}
	newCert, err := pkix.CreateCertificateAuthority(newKey, "CA", time.Now().AddDate(1, 0, 0), "test", "US", "", "", "CA", nil)
	if err != nil {
		t.Fatal("Failed creating replacement certificate:", err)
	}
	if err := depot.DeleteCertificate(d, "CA"); err != nil {
		t.Fatal("Failed deleting old CA certificate:", err)
	}
	if err := depot.PutCertificate(d, "CA", newCert); err != nil {
		t.Fatal("Failed putting replacement CA certificate:", err)
	}
	if err := verifyPublishedCAIdentity(ca); err == nil {
		t.Fatal("Verified a CA identity after its certificate changed")
	}
}
