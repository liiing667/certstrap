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
	"strings"
	"testing"
)

// readDepotCert parses the named certificate from the test depot.
func readChainTestCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	contents, err := os.ReadFile(path.Join(depotDir, name+".crt"))
	if err != nil {
		t.Fatalf("read cert %q: %v", name, err)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		t.Fatalf("decode PEM for %q", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert %q: %v", name, err)
	}
	return cert
}

// verifyChainAsConsumer mirrors a final chain consumer: the root is trusted
// explicitly and all intermediates are offered through the intermediate pool.
func verifyChainAsChainConsumer(t *testing.T, leaf *x509.Certificate, root *x509.Certificate, intermediates ...*x509.Certificate) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(root)
	pool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		pool.AddCert(intermediate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("consumer chain verification failed: %v", err)
	}
}

// TestIntermediateChainWorkflow exercises a legal root -> intermediate -> leaf
// hierarchy and verifies it both at issuance time (the sign command itself)
// and from the perspective of an independent chain consumer.
func TestIntermediateChainWorkflow(t *testing.T) {
	for _, keySpec := range [][]string{
		nil,
		{"--curve", "P-256"},
		{"--curve", "P-521"},
		{"--curve", "Ed25519"},
		{"--key-bits", "2048"},
	} {
		name := "RSA-default"
		if len(keySpec) > 0 {
			name = strings.Join(keySpec, "-")
		}
		t.Run(name, func(t *testing.T) {
			os.RemoveAll(depotDir)
			defer os.RemoveAll(depotDir)

			args := []string{"init", "--passphrase", passphrase, "--common-name", "root",
				"--path-length", "1"}
			args = append(args, keySpec...)
			if _, stderr, err := run(binPath, args...); err != nil || stderr != "" {
				t.Fatalf("init root: %v %v", err, stderr)
			}

			if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase,
				"--common-name", "intermediate"); err != nil || stderr != "" {
				t.Fatalf("request intermediate: %v %v", err, stderr)
			}

			if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
				"--CA", "root", "--intermediate", "--path-length", "0", "intermediate"); err != nil || stderr != "" {
				t.Fatalf("sign intermediate: %v %v", err, stderr)
			}

			if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase,
				"--common-name", hostname); err != nil || stderr != "" {
				t.Fatalf("request host: %v %v", err, stderr)
			}

			if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
				"--CA", "intermediate", hostname); err != nil || stderr != "" {
				t.Fatalf("sign host: %v %v", err, stderr)
			}

			root := readChainTestCert(t, "root")
			intermediate := readChainTestCert(t, "intermediate")
			host := readChainTestCert(t, hostname)

			if !intermediate.IsCA || intermediate.MaxPathLen != 0 || !intermediate.MaxPathLenZero {
				t.Fatalf("intermediate constraints wrong: IsCA=%v MaxPathLen=%d Zero=%v",
					intermediate.IsCA, intermediate.MaxPathLen, intermediate.MaxPathLenZero)
			}
			if host.IsCA {
				t.Fatal("host certificate must not be a CA")
			}

			// Independent consumer-side verification of the full chain.
			verifyChainAsChainConsumer(t, host, root, intermediate)
			verifyChainAsChainConsumer(t, intermediate, root)
		})
	}
}

// TestPathLengthExceededRejected ensures an intermediate that would sit below
// an exhausted path length budget is never published, and the chain a consumer
// sees remains valid.
func TestPathLengthExceededRejected(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if _, stderr, err := run(binPath, "init", "--passphrase", passphrase,
		"--common-name", "root", "--path-length", "0"); err != nil || stderr != "" {
		t.Fatalf("init root: %v %v", err, stderr)
	}

	if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase,
		"--common-name", "intermediate"); err != nil || stderr != "" {
		t.Fatalf("request intermediate: %v %v", err, stderr)
	}

	// A root with pathLen 0 cannot authorize any intermediate beneath it.
	stdout, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
		"--CA", "root", "--intermediate", "intermediate")
	if err == nil {
		t.Fatalf("expected over-depth intermediate signing to fail, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "not allowed to sign certificates") &&
		!strings.Contains(stderr, "path length constraint exceeded") {
		t.Fatalf("unexpected error message: %q", stderr)
	}

	// Nothing must have been published for the rejected certificate.
	if _, err := os.Stat(path.Join(depotDir, "intermediate.crt")); !os.IsNotExist(err) {
		t.Fatalf("rejected intermediate must not be published, stat err=%v", err)
	}

	// A second-level intermediate below a pathLen-0 intermediate is likewise
	// refused. First build a legal first intermediate under an unlimited root.
	os.RemoveAll(depotDir)
	if _, stderr, err := run(binPath, "init", "--passphrase", passphrase,
		"--common-name", "root", "--exclude-path-length"); err != nil || stderr != "" {
		t.Fatalf("init unlimited root: %v %v", err, stderr)
	}
	if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase,
		"--common-name", "intermediate"); err != nil || stderr != "" {
		t.Fatalf("request intermediate: %v %v", err, stderr)
	}
	if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
		"--CA", "root", "--intermediate", "--path-length", "0", "intermediate"); err != nil || stderr != "" {
		t.Fatalf("sign first intermediate: %v %v", err, stderr)
	}
	if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase,
		"--common-name", "deep-intermediate"); err != nil || stderr != "" {
		t.Fatalf("request deep intermediate: %v %v", err, stderr)
	}
	if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
		"--CA", "intermediate", "--intermediate", "deep-intermediate"); err == nil {
		t.Fatalf("expected second-level intermediate to be rejected, stderr=%q", stderr)
	} else if !strings.Contains(stderr, "path length constraint exceeded") &&
		!strings.Contains(stderr, "not allowed to sign certificates") {
		t.Fatalf("unexpected error message: %q", stderr)
	}
	if _, err := os.Stat(path.Join(depotDir, "deep-intermediate.crt")); !os.IsNotExist(err) {
		t.Fatal("rejected second-level intermediate must not be published")
	}

	// The existing, legal chain still verifies on the consumer side.
	root := readChainTestCert(t, "root")
	intermediate := readChainTestCert(t, "intermediate")
	verifyChainAsChainConsumer(t, intermediate, root)
}

// TestNonCAIssuerRejectedAtSign ensures a leaf certificate selected as the
// signing CA is refused and no output certificate is written.
func TestNonCAIssuerRejectedAtSign(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if _, stderr, err := run(binPath, "init", "--passphrase", passphrase,
		"--common-name", "root"); err != nil || stderr != "" {
		t.Fatalf("init root: %v %v", err, stderr)
	}
	for _, name := range []string{"leaf", "target"} {
		if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase,
			"--common-name", name); err != nil || stderr != "" {
			t.Fatalf("request %s: %v %v", name, err, stderr)
		}
	}
	if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
		"--CA", "root", "leaf"); err != nil || stderr != "" {
		t.Fatalf("sign leaf: %v %v", err, stderr)
	}

	stdout, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
		"--CA", "leaf", "target")
	if err == nil {
		t.Fatalf("non-CA signing must fail, stdout=%q", stdout)
	}
	if !strings.Contains(stderr, "not allowed to sign certificates") {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
	if _, err := os.Stat(path.Join(depotDir, "target.crt")); !os.IsNotExist(err) {
		t.Fatal("certificate must not be published when the issuer is not a CA")
	}
}

// TestRetryAfterRejectionPublishesNothing verifies the transactional property:
// after a rejected signing attempt, retrying with the same request (or after
// switching to an authorized issuer) behaves correctly and never leaves
// partial artifacts behind.
func TestRetryAfterRejectionPublishesNothing(t *testing.T) {
	os.RemoveAll(depotDir)
	defer os.RemoveAll(depotDir)

	if _, stderr, err := run(binPath, "init", "--passphrase", passphrase,
		"--common-name", "limited", "--path-length", "0"); err != nil || stderr != "" {
		t.Fatalf("init limited root: %v %v", err, stderr)
	}
	if _, stderr, err := run(binPath, "init", "--passphrase", passphrase,
		"--common-name", "unlimited", "--exclude-path-length"); err != nil || stderr != "" {
		t.Fatalf("init unlimited root: %v %v", err, stderr)
	}
	if _, stderr, err := run(binPath, "request-cert", "--passphrase", passphrase,
		"--common-name", "intermediate"); err != nil || stderr != "" {
		t.Fatalf("request intermediate: %v %v", err, stderr)
	}

	// First attempt against the exhausted issuer must fail and publish nothing.
	if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
		"--CA", "limited", "--intermediate", "intermediate"); err == nil {
		t.Fatalf("first attempt should fail, stderr=%q", stderr)
	}
	if _, err := os.Stat(path.Join(depotDir, "intermediate.crt")); !os.IsNotExist(err) {
		t.Fatal("failed attempt must not leave a certificate behind")
	}

	// Retrying the same rejected request must fail identically.
	if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
		"--CA", "limited", "--intermediate", "intermediate"); err == nil {
		t.Fatalf("retry against the same bad issuer should fail, stderr=%q", stderr)
	}

	// Switching to an authorized issuer succeeds and the result verifies.
	if _, stderr, err := run(binPath, "sign", "--passphrase", passphrase,
		"--CA", "unlimited", "--intermediate", "--path-length", "0", "intermediate"); err != nil || stderr != "" {
		t.Fatalf("retry with authorized issuer should succeed: %v %v", err, stderr)
	}

	root := readChainTestCert(t, "unlimited")
	intermediate := readChainTestCert(t, "intermediate")
	verifyChainAsChainConsumer(t, intermediate, root)
}
