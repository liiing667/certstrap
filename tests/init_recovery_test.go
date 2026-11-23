//go:build integration
// +build integration

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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func initCA(t *testing.T) (stdout, stderr string, err error) {
	t.Helper()
	return run(binPath, "init", "--passphrase", passphrase, "--common-name", "CA")
}

// checkDepotConsistent proves that the CA certificate, private key and CRL
// in the depot belong together by requesting and signing a certificate and
// verifying it against the CA certificate.
func checkDepotConsistent(t *testing.T) {
	t.Helper()

	stdout, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase, "--common-name", hostname)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 2 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	stdout, stderr, err = run(binPath, "sign", "--passphrase", passphrase, "--CA", "CA", hostname)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}
	if strings.Count(stdout, "Created") != 1 {
		t.Fatalf("Received incorrect create: %v", stdout)
	}

	caCert := parseCertFile(t, path.Join(depotDir, "CA.crt"))
	hostCert := parseCertFile(t, path.Join(depotDir, hostname+".crt"))
	if err := hostCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("Signed certificate does not match CA key: %v", err)
	}

	if runtime.GOOS != "windows" {
		checkPerm(t, path.Join(depotDir, "CA.key"), 0440)
		checkPerm(t, path.Join(depotDir, "CA.crt"), 0444)
		checkPerm(t, path.Join(depotDir, "CA.crl"), 0444)
	}
}

func parseCertFile(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	contents, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("Reading %s failed: %v", name, err)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		t.Fatalf("Decoding %s failed", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Parsing %s failed: %v", name, err)
	}
	return cert
}

func checkPerm(t *testing.T, name string, perm os.FileMode) {
	t.Helper()
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatalf("Stat %s failed: %v", name, err)
	}
	if fi.Mode().Perm() != perm {
		t.Fatalf("Perm of %s = %v, want %v", name, fi.Mode().Perm(), perm)
	}
}

// TestInitInterruptedRecovery simulates an interrupted init that left a
// private key (and CRL) behind without a certificate. The next init must
// recover the depot and create a consistent CA.
func TestInitInterruptedRecovery(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	_, stderr, err := initCA(t)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}

	// Simulate an interrupted initialization: the key (and CRL) exist,
	// but the certificate was never written.
	for _, name := range []string{"CA.crt", "CA.crl"} {
		if err := os.Remove(path.Join(depotDir, name)); err != nil {
			t.Fatalf("Remove %s failed: %v", name, err)
		}
	}

	_, stderr, err = initCA(t)
	if err != nil {
		t.Fatalf("Init did not recover the depot: %v, %v", stderr, err)
	}
	if !strings.Contains(stderr, "Removed incomplete CA") {
		t.Fatalf("Expected recovery notice, got: %v", stderr)
	}

	checkDepotConsistent(t)
}

// TestInitInterruptedRecoveryCertOnly simulates an interrupted init that
// left a certificate behind without its private key. The next init must
// recover the depot rather than combine the old certificate with a new key.
func TestInitInterruptedRecoveryCertOnly(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	_, stderr, err := initCA(t)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}

	for _, name := range []string{"CA.key", "CA.crl"} {
		if err := os.Remove(path.Join(depotDir, name)); err != nil {
			t.Fatalf("Remove %s failed: %v", name, err)
		}
	}

	_, stderr, err = initCA(t)
	if err != nil {
		t.Fatalf("Init did not recover the depot: %v, %v", stderr, err)
	}
	if !strings.Contains(stderr, "Removed incomplete CA") {
		t.Fatalf("Expected recovery notice, got: %v", stderr)
	}

	checkDepotConsistent(t)
}

// TestInitExistingCARefused makes sure a complete CA is never overwritten.
func TestInitExistingCARefused(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	_, stderr, err := initCA(t)
	if stderr != "" || err != nil {
		t.Fatalf("Received unexpected error: %v, %v", stderr, err)
	}

	crtBefore, err := os.ReadFile(path.Join(depotDir, "CA.crt"))
	if err != nil {
		t.Fatalf("Reading CA.crt failed: %v", err)
	}

	_, stderr, err = initCA(t)
	if err == nil {
		t.Fatal("Expected init to refuse an existing CA")
	}
	if !strings.Contains(stderr, "already exists") {
		t.Fatalf("Expected already exists error, got: %v", stderr)
	}

	crtAfter, err := os.ReadFile(path.Join(depotDir, "CA.crt"))
	if err != nil {
		t.Fatalf("Reading CA.crt failed: %v", err)
	}
	if string(crtBefore) != string(crtAfter) {
		t.Fatal("Existing CA certificate was modified")
	}

	checkDepotConsistent(t)
}

// TestInitConcurrent runs several initializations against the same depot
// concurrently. Exactly one may succeed, and the resulting depot must hold
// a consistent CA: no new certificate next to an old key and no CRL from a
// different CA.
func TestInitConcurrent(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = initCA(t)
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for _, err := range errs {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("Expected exactly one successful init, got %d", succeeded)
	}

	checkDepotConsistent(t)
}
