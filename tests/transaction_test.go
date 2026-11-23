//go:build integration

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

package tests

import (
	"os"
	"path"
	"strings"
	"testing"
)

// TestSignWriteFailureIsTransactional reproduces the reported defect: when the
// depot cannot be written, "certstrap sign" used to print its success message
// and still exit zero. The command must instead fail with a non-zero status,
// publish no certificate and leave no temporary files behind, so automation
// never observes a partial success.
func TestSignWriteFailureIsTransactional(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}

	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	stdout, stderr, err := run(binPath, "init", "--passphrase", passphrase, "--common-name", "CA")
	if err != nil {
		t.Fatalf("init failed: %v %v", stderr, err)
	}
	stdout, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", hostname)
	if err != nil {
		t.Fatalf("request-cert failed: %v %v", stderr, err)
	}

	if err := os.Chmod(depotDir, 0555); err != nil {
		t.Fatalf("chmod depot read-only: %v", err)
	}
	stdout, stderr, err = run(binPath, "sign", "--passphrase", passphrase, "--CA", "CA", hostname)
	restoreErr := os.Chmod(depotDir, 0755)
	if restoreErr != nil {
		t.Fatalf("restore depot permissions: %v", restoreErr)
	}

	if err == nil {
		t.Fatalf("sign succeeded against a read-only depot: stdout=%q", stdout)
	}
	if strings.Contains(stdout, "Created") {
		t.Fatalf("sign claimed success after write failure: stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "Save certificate error") {
		t.Fatalf("stderr = %q, want a save certificate error", stderr)
	}

	if _, statErr := os.Stat(path.Join(depotDir, hostname+".crt")); !os.IsNotExist(statErr) {
		t.Fatalf("certificate was published despite failed sign: %v", statErr)
	}
	assertNoTransactionLeftovers(t, depotDir)

	// The failed run must not poison the depot: the same command succeeds once
	// the depot is writable again.
	stdout, stderr, err = run(binPath, "sign", "--passphrase", passphrase, "--CA", "CA", hostname)
	if err != nil {
		t.Fatalf("retry sign failed: %v %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 1 {
		t.Fatalf("retry sign stdout = %q, want exactly one Created line", stdout)
	}
	if _, err = os.Stat(path.Join(depotDir, hostname+".crt")); err != nil {
		t.Fatalf("certificate missing after successful retry: %v", err)
	}
}

// TestInitWriteFailureLeavesNoPartialCA verifies that a CA generation is only
// ever visible as the complete crt/key/crl set: a write failure rolls all
// three files back and reports failure instead of a partial success.
func TestInitWriteFailureLeavesNoPartialCA(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}

	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if err := os.MkdirAll(depotDir, 0555); err != nil {
		t.Fatalf("create read-only depot: %v", err)
	}
	stdout, stderr, err := run(binPath, "init", "--passphrase", passphrase, "--common-name", "CA")
	if restoreErr := os.Chmod(depotDir, 0755); restoreErr != nil {
		t.Fatalf("restore depot permissions: %v", restoreErr)
	}

	if err == nil {
		t.Fatalf("init succeeded against a read-only depot: stdout=%q", stdout)
	}
	if strings.Contains(stdout, "Created") {
		t.Fatalf("init claimed success after write failure: stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "Save CA error") {
		t.Fatalf("stderr = %q, want a Save CA error", stderr)
	}

	entries, err := os.ReadDir(depotDir)
	if err != nil {
		t.Fatalf("read depot: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("depot holds partial CA files after failed init: %v", entries)
	}
	assertNoTransactionLeftovers(t, depotDir)
}

// TestInitFailureOnExistingCRLLeavesNoPartialCA forces the last write of a CA
// generation to fail. The certificate and key staged before it must not be
// published, so the depot cannot end up with a mixed generation.
func TestInitFailureOnExistingCRLLeavesNoPartialCA(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if err := os.MkdirAll(depotDir, 0755); err != nil {
		t.Fatalf("create depot: %v", err)
	}
	crlPath := path.Join(depotDir, "CA.crl")
	if err := os.WriteFile(crlPath, []byte("previous-crl-generation"), 0644); err != nil {
		t.Fatalf("write existing CRL: %v", err)
	}
	if err := os.Chmod(crlPath, 0644); err != nil {
		t.Fatalf("chmod existing CRL: %v", err)
	}

	stdout, stderr, err := run(binPath, "init", "--passphrase", passphrase, "--common-name", "CA")
	if err == nil {
		t.Fatalf("init succeeded with a CRL that already exists: stdout=%q", stdout)
	}
	if strings.Contains(stdout, "Created") {
		t.Fatalf("init claimed success after a failed CRL write: stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "Save CA error") {
		t.Fatalf("stderr = %q, want a Save CA error", stderr)
	}

	for _, name := range []string{"CA.crt", "CA.key"} {
		if _, statErr := os.Stat(path.Join(depotDir, name)); !os.IsNotExist(statErr) {
			t.Fatalf("%s was published despite the failed CA transaction: %v", name, statErr)
		}
	}
	got, readErr := os.ReadFile(crlPath)
	if readErr != nil || string(got) != "previous-crl-generation" {
		t.Fatalf("existing CRL = %q, %v; want untouched original", got, readErr)
	}
	assertNoTransactionLeftovers(t, depotDir)
}

// TestRequestCertWriteFailureRollsBack verifies that request-cert treats the
// CSR and key as one transaction: when the depot rejects writes, neither file
// is left behind and the command exits non-zero.
func TestRequestCertWriteFailureRollsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}

	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if err := os.MkdirAll(depotDir, 0555); err != nil {
		t.Fatalf("create read-only depot: %v", err)
	}
	stdout, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", hostname)
	if restoreErr := os.Chmod(depotDir, 0755); restoreErr != nil {
		t.Fatalf("restore depot permissions: %v", restoreErr)
	}

	if err == nil {
		t.Fatalf("request-cert succeeded against a read-only depot: stdout=%q", stdout)
	}
	if strings.Contains(stdout, "Created") {
		t.Fatalf("request-cert claimed success after write failure: stdout=%q", stdout)
	}
	if stderr == "" {
		t.Fatal("request-cert failed without reporting an error on stderr")
	}

	entries, err := os.ReadDir(depotDir)
	if err != nil {
		t.Fatalf("read depot: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("depot holds partial request files: %v", entries)
	}
	assertNoTransactionLeftovers(t, depotDir)
}

// TestRequestCertFailureOnExistingKeyLeavesNoCSR forces the key write of a
// request to fail after the CSR was staged. No partial request may be
// published, and the pre-existing key must remain untouched.
func TestRequestCertFailureOnExistingKeyLeavesNoCSR(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if err := os.MkdirAll(depotDir, 0755); err != nil {
		t.Fatalf("create depot: %v", err)
	}
	keyPath := path.Join(depotDir, hostname+".key")
	if err := os.WriteFile(keyPath, []byte("previous-key-generation"), 0644); err != nil {
		t.Fatalf("write existing key: %v", err)
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatalf("chmod existing key: %v", err)
	}

	stdout, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", hostname)
	if err == nil {
		t.Fatalf("request-cert succeeded with a key that already exists: stdout=%q", stdout)
	}
	if strings.Contains(stdout, "Created") {
		t.Fatalf("request-cert claimed success after a failed key write: stdout=%q", stdout)
	}
	if stderr == "" {
		t.Fatal("request-cert failed without reporting an error on stderr")
	}

	if _, statErr := os.Stat(path.Join(depotDir, hostname+".csr")); !os.IsNotExist(statErr) {
		t.Fatalf("CSR was published despite the failed request transaction: %v", statErr)
	}
	got, readErr := os.ReadFile(keyPath)
	if readErr != nil || string(got) != "previous-key-generation" {
		t.Fatalf("existing key = %q, %v; want untouched original", got, readErr)
	}
	assertNoTransactionLeftovers(t, depotDir)
}

// TestSignDuplicateAndMissingInputsStillFail pins the old command boundaries
// that the transactional rewrite must preserve.
func TestSignDuplicateAndMissingInputsStillFail(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if _, stderr, err := run(binPath, "init", "--passphrase", passphrase, "--common-name", "CA"); err != nil {
		t.Fatalf("init failed: %v %v", stderr, err)
	}
	if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", hostname); err != nil {
		t.Fatalf("request-cert failed: %v %v", stderr, err)
	}
	if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase, "--CA", "CA", hostname); err != nil {
		t.Fatalf("first sign failed: %v %v", stderr, err)
	}

	// Re-signing the same host must still be rejected without any rollback of
	// the existing certificate.
	_, stderr, err := run(binPath, "sign", "--passphrase", passphrase, "--CA", "CA", hostname)
	if err == nil {
		t.Fatal("duplicate sign succeeded, want failure")
	}
	if !strings.Contains(stderr, "already exists") {
		t.Fatalf("stderr = %q, want an already-exists error", stderr)
	}
	if _, err = os.Stat(path.Join(depotDir, hostname+".crt")); err != nil {
		t.Fatalf("existing certificate disappeared after duplicate sign: %v", err)
	}

	// A missing CSR and a missing CA must still be reported as failures.
	if _, stderr, err = run(binPath, "sign", "--passphrase", passphrase, "--CA", "CA", "ghost"); err == nil {
		t.Fatalf("sign with missing CSR succeeded: %q", stderr)
	}
	// A fresh host against a CA that does not exist must also fail.
	if _, stderr, err = run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", "orphan"); err != nil {
		t.Fatalf("request-cert for orphan failed: %v", stderr)
	}
	if _, stderr, err = run(binPath, "sign", "--passphrase", passphrase, "--CA", "no-ca", "orphan"); err == nil {
		t.Fatalf("sign with missing CA succeeded: %q", stderr)
	}
}

// TestSignLaxPermissionCertificateFailsCleanly keeps the historical permission
// boundary: a certificate whose mode is too lax is not accepted as an existing
// output, and the sign command must not claim success while leaving that stale
// file in place.
func TestSignLaxPermissionCertificateFailsCleanly(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if _, stderr, err := run(binPath, "init", "--passphrase", passphrase, "--common-name", "CA"); err != nil {
		t.Fatalf("init failed: %v %v", stderr, err)
	}
	if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", hostname); err != nil {
		t.Fatalf("request-cert failed: %v %v", stderr, err)
	}

	certPath := path.Join(depotDir, hostname+".crt")
	if err := os.WriteFile(certPath, []byte("stale-generation"), 0666); err != nil {
		t.Fatalf("write stale certificate: %v", err)
	}
	if err := os.Chmod(certPath, 0666); err != nil {
		t.Fatalf("chmod stale certificate: %v", err)
	}

	stdout, stderr, err := run(binPath, "sign", "--passphrase", passphrase, "--CA", "CA", hostname)
	if err == nil {
		t.Fatalf("sign succeeded with a too-lax existing certificate: stdout=%q", stdout)
	}
	if strings.Contains(stdout, "Created") {
		t.Fatalf("sign claimed success after failing to replace the stale certificate: stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "Save certificate error") {
		t.Fatalf("stderr = %q, want a save certificate error", stderr)
	}

	got, readErr := os.ReadFile(certPath)
	if readErr != nil || string(got) != "stale-generation" {
		t.Fatalf("stale certificate = %q, %v; want untouched original", got, readErr)
	}
	assertNoTransactionLeftovers(t, depotDir)
}

// TestRequestCertExternalCSRRolledBackWhenDepotWriteFails covers the combined
// command transaction: an explicit --csr output is published only if the depot
// write of the matching key also succeeds. The previous CSR must survive.
func TestRequestCertExternalCSRRolledBackWhenDepotWriteFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}

	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	externalDir := t.TempDir()
	csrPath := path.Join(externalDir, "external.csr")
	if err := os.WriteFile(csrPath, []byte("previous-csr-generation"), 0644); err != nil {
		t.Fatalf("write previous CSR: %v", err)
	}
	if err := os.Chmod(csrPath, 0644); err != nil {
		t.Fatalf("chmod previous CSR: %v", err)
	}
	if err := os.MkdirAll(depotDir, 0555); err != nil {
		t.Fatalf("create read-only depot: %v", err)
	}

	stdout, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", "external-host", "--csr", csrPath)
	if restoreErr := os.Chmod(depotDir, 0755); restoreErr != nil {
		t.Fatalf("restore depot permissions: %v", restoreErr)
	}
	if err == nil {
		t.Fatalf("request-cert succeeded against a read-only depot: stdout=%q", stdout)
	}
	if strings.Contains(stdout, "Created") {
		t.Fatalf("request-cert claimed success after a failed key write: stdout=%q", stdout)
	}
	if stderr == "" {
		t.Fatal("request-cert failed without reporting an error on stderr")
	}

	got, readErr := os.ReadFile(csrPath)
	if readErr != nil || string(got) != "previous-csr-generation" {
		t.Fatalf("external CSR = %q, %v; want previous generation restored", got, readErr)
	}

	entries, err := os.ReadDir(depotDir)
	if err != nil {
		t.Fatalf("read depot: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("depot holds partial request files: %v", entries)
	}
	assertNoTransactionLeftovers(t, depotDir)
	assertNoTransactionLeftovers(t, externalDir)
}

// TestRevokeWriteFailureKeepsPreviousCRL verifies that a revoked-certificate
// update cannot leave the CA with a missing or partially written CRL.
func TestRevokeWriteFailureKeepsPreviousCRL(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}

	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if _, stderr, err := run(binPath, "init", "--passphrase", passphrase, "--common-name", "CA"); err != nil {
		t.Fatalf("init failed: %v %v", stderr, err)
	}
	if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", hostname); err != nil {
		t.Fatalf("request-cert failed: %v %v", stderr, err)
	}
	if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase, "--CA", "CA", hostname); err != nil {
		t.Fatalf("sign failed: %v %v", stderr, err)
	}

	crlPath := path.Join(depotDir, "CA.crl")
	before, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("read CRL before revoke: %v", err)
	}
	beforeInfo, err := os.Stat(crlPath)
	if err != nil {
		t.Fatalf("stat CRL before revoke: %v", err)
	}

	if err := os.Chmod(depotDir, 0555); err != nil {
		t.Fatalf("chmod depot read-only: %v", err)
	}
	_, stderr, err := run(binPath, "revoke", "--passphrase", passphrase, "--CN", hostname, "--CA", "CA")
	if restoreErr := os.Chmod(depotDir, 0755); restoreErr != nil {
		t.Fatalf("restore depot permissions: %v", restoreErr)
	}
	if err == nil {
		t.Fatalf("revoke succeeded against a read-only depot: stderr=%q", stderr)
	}
	if stderr == "" {
		t.Fatal("revoke failed without reporting an error on stderr")
	}

	after, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("read CRL after revoke: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("CRL changed despite a failed revoke transaction")
	}
	afterInfo, err := os.Stat(crlPath)
	if err != nil {
		t.Fatalf("stat CRL after revoke: %v", err)
	}
	if afterInfo.Mode().Perm() != beforeInfo.Mode().Perm() {
		t.Fatalf("CRL mode = %o, want restored %o", afterInfo.Mode().Perm(), beforeInfo.Mode().Perm())
	}
	assertNoTransactionLeftovers(t, depotDir)
}

// TestExistingKeyInputDoesNotClaimKeyCreation pins the old --key output
// boundary: an existing key file is read, not regenerated, so the command must
// not print a second "Created" line for it.
func TestExistingKeyInputDoesNotClaimKeyCreation(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	externalDir := t.TempDir()
	keyPath := path.Join(externalDir, "host.key")
	csrPath := path.Join(externalDir, "host.csr")

	stdout, stderr, err := run(binPath, "request-cert", "--passphrase", "", "--common-name", "key-host", "--key", keyPath, "--csr", csrPath)
	if err != nil {
		t.Fatalf("first request-cert failed: %v %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("first request-cert stdout = %q, want key and CSR creation", stdout)
	}

	stdout, stderr, err = run(binPath, "request-cert", "--passphrase", "", "--common-name", "key-host", "--key", keyPath, "--csr", csrPath)
	if err != nil {
		t.Fatalf("second request-cert failed: %v %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 1 {
		t.Fatalf("second request-cert stdout = %q, want only the CSR creation", stdout)
	}
	if !strings.Contains(stdout, "Read "+keyPath) {
		t.Fatalf("second request-cert stdout = %q, want the existing key to be reported as read", stdout)
	}

	stdout, stderr, err = run(binPath, "init", "--passphrase", "", "--common-name", "CA", "--key", keyPath)
	if err != nil {
		t.Fatalf("init with existing key failed: %v %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("init with existing key stdout = %q, want only certificate and CRL creation", stdout)
	}
	if !strings.Contains(stdout, "Read "+keyPath) {
		t.Fatalf("init with existing key stdout = %q, want the key to be reported as read", stdout)
	}
}

func assertNoTransactionLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read depot dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".txn-") || strings.HasPrefix(name, ".certstrap-txn-") {
			t.Fatalf("transaction temporary file left behind: %s", path.Join(dir, name))
		}
	}
}
