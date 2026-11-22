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

package pkix

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"net"
	"net/url"
	"testing"
	"time"
)

func newTransactionTestCA(t *testing.T) (*Certificate, *Key) {
	t.Helper()
	key, err := CreateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := CreateCertificateAuthority(key, "CA", time.Now().Add(24*time.Hour), "", "", "", "", "CA", nil)
	if err != nil {
		t.Fatal(err)
	}
	return crt, key
}

func newTransactionTestCSR(t *testing.T, key *Key, dns string) *CertificateSigningRequest {
	t.Helper()
	uri, err := url.Parse("spiffe://example.org/service")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := CreateCertificateSigningRequest(key, "leaf", []net.IP{net.ParseIP("192.0.2.10")}, []string{dns}, []*url.URL{uri}, "", "", "", "", "leaf")
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func transactionRawPublicKey(t *testing.T, key *Key) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestIssuanceTransactionRejectsForgedCSRSignature(t *testing.T) {
	ca, caKey := newTransactionTestCA(t)
	leafKey, err := CreateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csr := newTransactionTestCSR(t, leafKey, "good.example")
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}

	forgedDER := append([]byte(nil), csr.derBytes...)
	forgedDER[len(forgedDER)-1] ^= 0xff
	forged := NewCertificateSigningRequestFromDER(forgedDER)
	if err := forged.CheckSignature(); err == nil {
		t.Fatal("forged CSR signature accepted")
	}
	if _, err := CreateCertificateHost(ca, caKey, forged, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("host issuance accepted a forged CSR")
	}
	if _, err := CreateIntermediateCertificateAuthority(ca, caKey, forged, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("intermediate issuance accepted a forged CSR")
	}
}

func TestIssuanceTransactionRejectsUnauthorizedCA(t *testing.T) {
	ca, caKey := newTransactionTestCA(t)
	leafKey, err := CreateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csr := newTransactionTestCSR(t, leafKey, "good.example")

	leaf, err := CreateCertificateHost(ca, caKey, csr, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCertificateHost(leaf, caKey, csr, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("non-CA certificate was allowed to sign")
	}

	otherKey, err := CreateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCertificateHost(ca, otherKey, csr, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("mismatched CA key was allowed to sign")
	}
}

func TestIssuanceTransactionBindsRequestSnapshotAndFinalCertificate(t *testing.T) {
	tests := []struct {
		name string
		key  func() (*Key, error)
	}{
		{name: "RSA", key: func() (*Key, error) { return CreateRSAKey(2048) }},
		{name: "ECDSA-P224", key: func() (*Key, error) { return CreateECDSAKey(elliptic.P224()) }},
		{name: "ECDSA-P256", key: func() (*Key, error) { return CreateECDSAKey(elliptic.P256()) }},
		{name: "Ed25519", key: CreateEd25519Key},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca, caKey := newTransactionTestCA(t)
			leafKey, err := tc.key()
			if err != nil {
				t.Fatal(err)
			}
			csr := newTransactionTestCSR(t, leafKey, "leaf.example")

			// Mutating a value returned by the accessor must not mutate the
			// request that is used for issuance.
			raw, err := csr.GetRawCertificateSigningRequest()
			if err != nil {
				t.Fatal(err)
			}
			raw.DNSNames = []string{"attacker.example"}
			raw.Raw[0] ^= 0xff
			raw.RawTBSCertificateRequest[0] ^= 0xff

			crt, err := CreateCertificateHost(ca, caKey, csr, time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			got, err := crt.GetRawCertificate()
			if err != nil {
				t.Fatal(err)
			}
			rawCA, err := ca.GetRawCertificate()
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got.RawSubjectPublicKeyInfo, transactionRawPublicKey(t, leafKey)) {
				t.Fatal("issued certificate public key does not match CSR")
			}
			if len(got.DNSNames) != 1 || got.DNSNames[0] != "leaf.example" {
				t.Fatalf("DNS SANs = %v", got.DNSNames)
			}
			if len(got.IPAddresses) != 1 || !got.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
				t.Fatalf("IP SANs = %v", got.IPAddresses)
			}
			if len(got.URIs) != 1 || got.URIs[0].String() != "spiffe://example.org/service" {
				t.Fatalf("URI SANs = %v", got.URIs)
			}
			if err := got.CheckSignatureFrom(rawCA); err != nil {
				t.Fatalf("certificate chain does not verify: %v", err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(rawCA)
			if _, err := got.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				t.Fatalf("certificate chain verification failed: %v", err)
			}
		})
	}
}

func TestIssuanceTransactionRechecksReplacedRequest(t *testing.T) {
	ca, caKey := newTransactionTestCA(t)
	leafKey, err := CreateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	first := newTransactionTestCSR(t, leafKey, "first.example")
	second := newTransactionTestCSR(t, leafKey, "second.example")

	// A previously verified request must not make a replacement request
	// inherit its proof of possession or SAN snapshot.
	if err := first.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	first.derBytes = append([]byte(nil), second.derBytes...)
	crt, err := CreateCertificateHost(ca, caKey, first, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, err := crt.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.DNSNames) != 1 || got.DNSNames[0] != "second.example" {
		t.Fatalf("replacement CSR was not used: DNS SANs = %v", got.DNSNames)
	}

	forgedDER := append([]byte(nil), second.derBytes...)
	forgedDER[len(forgedDER)-1] ^= 0xff
	first.derBytes = forgedDER
	if _, err := CreateCertificateHost(ca, caKey, first, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("failed retry reused an earlier verified request")
	}
}

func TestIssuanceTransactionSnapshotsCAIdentity(t *testing.T) {
	ca, caKey := newTransactionTestCA(t)
	rawCA, err := ca.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	originalSubject := append([]byte(nil), rawCA.RawSubject...)
	rawCA.RawSubject = []byte{0x30, 0x00}

	leafKey, err := CreateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csr := newTransactionTestCSR(t, leafKey, "ca-snapshot.example")
	crt, err := CreateCertificateHost(ca, caKey, csr, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, err := crt.GetRawCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.RawIssuer, originalSubject) {
		t.Fatal("issuer came from a mutated CA cache instead of the CA DER snapshot")
	}
}
