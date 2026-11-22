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

package pkix

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// buildOverDepthIntermediate crafts an intermediate directly with
// x509.CreateCertificate, bypassing the authorization gate. It reproduces the
// kind of invalid certificate the vulnerable build used to emit, so tests can
// prove the final-chain consumer rejects the over-depth path.
func buildOverDepthIntermediate(t *testing.T, issuer *Certificate, issuerKey *Key, csr *CertificateSigningRequest) *Certificate {
	t.Helper()

	rawIssuer, err := issuer.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	rawCSR, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		t.Fatal(err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-10 * time.Minute).UTC(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		RawSubject:            rawCSR.RawSubject,
		SubjectKeyId:          mustSubjectKeyID(t, rawCSR.PublicKey),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, rawIssuer, rawCSR.PublicKey, issuerKey.Private)
	if err != nil {
		t.Fatalf("craft over-depth intermediate: %v", err)
	}
	return NewCertificateFromDER(der)
}

func mustSubjectKeyID(t *testing.T, pub any) []byte {
	t.Helper()
	ski, err := GenerateSubjectKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	return ski
}

// createTestCA builds a self-signed root CA with the given path length
// settings. When excludePathLen is true no pathLenConstraint is encoded.
func createTestCA(t *testing.T, cn string, pathLen int, excludePathLen bool) (*Key, *Certificate) {
	t.Helper()
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatalf("create CA key: %v", err)
	}
	crt, err := CreateCertificateAuthorityWithOptions(
		key, "", time.Now().AddDate(1, 0, 0), "", "", "", "", cn, nil,
		WithPathlenOption(pathLen, excludePathLen),
	)
	if err != nil {
		t.Fatalf("create CA %q: %v", cn, err)
	}
	return key, crt
}

func createTestCSR(t *testing.T, cn string) (*Key, *CertificateSigningRequest) {
	t.Helper()
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatalf("create CSR key: %v", err)
	}
	csr, err := CreateCertificateSigningRequest(key, "", nil, nil, nil, "", "", "", "", cn)
	if err != nil {
		t.Fatalf("create CSR %q: %v", cn, err)
	}
	return key, csr
}

func TestCheckIssuerAuthorization(t *testing.T) {
	_, rootPathLenZero := createTestCA(t, "root-zero", 0, false)
	_, rootPathLenOne := createTestCA(t, "root-one", 1, false)
	_, rootNoPathLen := createTestCA(t, "root-none", 0, true)

	rootZeroRaw, err := rootPathLenZero.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	rootOneRaw, err := rootPathLenOne.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	rootNoLimitRaw, err := rootNoPathLen.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}

	// A leaf (non-CA) issuer must never be accepted.
	leafKey, leafCSR := createTestCSR(t, "leaf-csr")
	leaf, err := CreateCertificateHost(rootPathLenZero, leafKey, leafCSR, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Fatalf("create host cert: %v", err)
	}
	leafRaw, err := leaf.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}

	// A certificate with cA=true but without keyCertSign in its key usage.
	noCertSignRaw := buildCAWithoutCertSignUsage(t)

	tests := []struct {
		name      string
		issuer    *x509.Certificate
		childIsCA bool
		wantErr   bool
	}{
		{name: "root pathlen 0 signs leaf", issuer: rootZeroRaw, childIsCA: false, wantErr: false},
		{name: "root pathlen 0 signs CA (depth exhausted)", issuer: rootZeroRaw, childIsCA: true, wantErr: true},
		{name: "root pathlen 1 signs CA", issuer: rootOneRaw, childIsCA: true, wantErr: false},
		{name: "root without pathlen signs CA", issuer: rootNoLimitRaw, childIsCA: true, wantErr: false},
		{name: "root without pathlen signs leaf", issuer: rootNoLimitRaw, childIsCA: false, wantErr: false},
		{name: "non-CA leaf signs leaf", issuer: leafRaw, childIsCA: false, wantErr: true},
		{name: "non-CA leaf signs CA", issuer: leafRaw, childIsCA: true, wantErr: true},
		{name: "CA without keyCertSign signs leaf", issuer: noCertSignRaw, childIsCA: false, wantErr: true},
		{name: "CA without keyCertSign signs CA", issuer: noCertSignRaw, childIsCA: true, wantErr: true},
		{name: "nil issuer", issuer: nil, childIsCA: false, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckIssuerAuthorization(tc.issuer, tc.childIsCA)
			if tc.wantErr && err == nil {
				t.Fatal("expected authorization error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected authorization to pass, got %v", err)
			}
			if tc.wantErr {
				var authErr *AuthorizationError
				if tc.issuer != nil && !errors.As(err, &authErr) {
					t.Fatalf("expected *AuthorizationError, got %T: %v", err, err)
				}
			}
		})
	}
}

// buildCAWithoutCertSignUsage returns a self-signed certificate that asserts
// cA=true but whose key usage deliberately omits keyCertSign.
func buildCAWithoutCertSignUsage(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	ski, err := GenerateSubjectKeyID(key.Public)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-10 * time.Minute).UTC(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		Subject:               pkix.Name{CommonName: "no-keyCertSign"},
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public, key.Private)
	if err != nil {
		t.Fatalf("craft CA without keyCertSign: %v", err)
	}
	crt := NewCertificateFromDER(der)
	raw, err := crt.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestIntermediateDepthEnforcement reproduces the reported vulnerability:
// a second-level intermediate must be refused when the root's path length
// budget does not allow it, while a legal hierarchy must still be issued.
func TestIntermediateDepthEnforcement(t *testing.T) {
	// Root that allows exactly one non-self-issued intermediate beneath it.
	rootKey, root := createTestCA(t, "root", 1, false)

	// First intermediate is legal: the root still has depth budget.
	int1Key, int1CSR := createTestCSR(t, "intermediate-1")
	int1, err := CreateIntermediateCertificateAuthorityWithOptions(
		root, rootKey, int1CSR, time.Now().AddDate(1, 0, 0),
		WithPathlenOption(0, false),
	)
	if err != nil {
		t.Fatalf("first intermediate should be issued: %v", err)
	}

	// The first intermediate carries pathLen 0, so it cannot sign another CA.
	_, int2CSR := createTestCSR(t, "intermediate-2")
	if _, err := CreateIntermediateCertificateAuthorityWithOptions(
		int1, int1Key, int2CSR, time.Now().AddDate(1, 0, 0),
		WithPathlenOption(0, false),
	); err == nil {
		t.Fatal("second-level intermediate beyond path length must not be issued")
	} else {
		var authErr *AuthorizationError
		if !errors.As(err, &authErr) {
			t.Fatalf("expected *AuthorizationError, got %T: %v", err, err)
		}
	}

	// A root with no path length constraint allows the nested intermediate.
	unlimitedRootKey, unlimitedRoot := createTestCA(t, "unlimited-root", 0, true)
	uInt1Key, uInt1CSR := createTestCSR(t, "u-intermediate-1")
	uInt1, err := CreateIntermediateCertificateAuthorityWithOptions(
		unlimitedRoot, unlimitedRootKey, uInt1CSR, time.Now().AddDate(1, 0, 0),
		WithPathlenOption(0, true),
	)
	if err != nil {
		t.Fatalf("first intermediate under unlimited root should pass: %v", err)
	}
	_, uInt2CSR := createTestCSR(t, "u-intermediate-2")
	uInt2, err := CreateIntermediateCertificateAuthorityWithOptions(
		uInt1, uInt1Key, uInt2CSR, time.Now().AddDate(1, 0, 0),
		WithPathlenOption(0, false),
	)
	if err != nil {
		t.Fatalf("nested intermediate without path limit should pass: %v", err)
	}

	// Consumer-side verification of the full legal chain must succeed.
	roots := x509.NewCertPool()
	rootRaw, err := unlimitedRoot.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(rootRaw)
	intermediates := x509.NewCertPool()
	int1Raw, err := uInt1.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	intermediates.AddCert(int1Raw)
	if err := VerifyChain(uInt2, roots, intermediates); err != nil {
		t.Fatalf("legal nested chain must verify: %v", err)
	}

	// And the same consumer must reject the over-depth chain: hand the
	// pathLen-0 intermediate a child and verify against the limited root.
	limitedRootRaw, err := root.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	limitedRoots := x509.NewCertPool()
	limitedRoots.AddCert(limitedRootRaw)
	limitedIntermediates := x509.NewCertPool()
	int1LimitedRaw, err := int1.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	limitedIntermediates.AddCert(int1LimitedRaw)

	// Build the over-depth intermediate through a template directly, since the
	// safe API refuses it, to prove the consumer-side verifier also rejects it.
	overDepth := buildOverDepthIntermediate(t, int1, int1Key, int2CSR)
	if err := VerifyChain(overDepth, limitedRoots, limitedIntermediates); err == nil {
		t.Fatal("consumer must reject a chain that exceeds path length")
	}
}

// TestLeafIssuanceRejectsNonCAIssuer ensures host certificates cannot be
// minted by a non-CA or key-usage-invalid certificate.
func TestLeafIssuanceRejectsNonCAIssuer(t *testing.T) {
	rootKey, root := createTestCA(t, "root", 0, false)

	leafKey, leafCSR := createTestCSR(t, "host-csr")
	leaf, err := CreateCertificateHost(root, rootKey, leafCSR, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Fatalf("leaf from valid CA should be issued: %v", err)
	}

	// The leaf must verify directly against the root as a consumer would.
	rootRaw, err := root.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootRaw)
	if err := VerifyChain(leaf, roots, nil); err != nil {
		t.Fatalf("valid leaf chain must verify: %v", err)
	}

	// Using the leaf as an issuer must fail before any certificate is returned.
	_, otherCSR := createTestCSR(t, "other-csr")
	if _, err := CreateCertificateHost(leaf, leafKey, otherCSR, time.Now().AddDate(1, 0, 0)); err == nil {
		t.Fatal("non-CA issuer must not be able to sign a leaf")
	} else {
		var authErr *AuthorizationError
		if !errors.As(err, &authErr) {
			t.Fatalf("expected *AuthorizationError, got %T: %v", err, err)
		}
	}
}

// TestWithPathlenOptionEncodesZero verifies the regression where an explicit
// path length of zero was silently omitted, producing an unlimited CA.
func TestWithPathlenOptionEncodesZero(t *testing.T) {
	for _, exclude := range []bool{false, true} {
		key, err := CreateRSAKey(rsaBits)
		if err != nil {
			t.Fatal(err)
		}
		crt, err := CreateCertificateAuthorityWithOptions(
			key, "", time.Now().AddDate(1, 0, 0), "", "", "", "", "ca", nil,
			WithPathlenOption(0, exclude),
		)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := crt.GetRawCertificate()
		if err != nil {
			t.Fatal(err)
		}
		if exclude {
			if raw.MaxPathLen != -1 || raw.MaxPathLenZero {
				t.Fatalf("excludePathLen: got MaxPathLen=%d MaxPathLenZero=%v", raw.MaxPathLen, raw.MaxPathLenZero)
			}
			continue
		}
		if raw.MaxPathLen != 0 || !raw.MaxPathLenZero {
			t.Fatalf("explicit pathlen 0 must be encoded, got MaxPathLen=%d MaxPathLenZero=%v", raw.MaxPathLen, raw.MaxPathLenZero)
		}
	}
}

// TestVerifyChainRejectsBrokenPaths makes the consumer-side helper fail
// closed on unknown anchors and malformed inputs.
func TestVerifyChainRejectsBrokenPaths(t *testing.T) {
	rootKey, root := createTestCA(t, "anchor", 1, false)
	rootRaw, err := root.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}

	_, leafCSR := createTestCSR(t, "leaf")
	leaf, err := CreateCertificateHost(root, rootKey, leafCSR, time.Now().AddDate(1, 0, 0))
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}

	// A different, unrelated root must not validate the leaf.
	_, otherRoot := createTestCA(t, "other-anchor", 1, false)
	otherRaw, err := otherRoot.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	wrongRoots := x509.NewCertPool()
	wrongRoots.AddCert(otherRaw)
	if err := VerifyChain(leaf, wrongRoots, nil); err == nil {
		t.Fatal("leaf must not verify under an unrelated root")
	}

	// Nil roots are rejected explicitly rather than falling back to system
	// trust stores.
	if err := VerifyChain(leaf, nil, nil); err == nil {
		t.Fatal("nil root pool must be rejected")
	}

	// The correct anchor verifies.
	roots := x509.NewCertPool()
	roots.AddCert(rootRaw)
	if err := VerifyChain(leaf, roots, nil); err != nil {
		t.Fatalf("leaf must verify under its own root: %v", err)
	}
}
