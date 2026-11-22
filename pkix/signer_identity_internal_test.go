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
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestCAIdentityNewCertificateAuthorityRejectsMismatchedKey(t *testing.T) {
	crtAuth, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}
	key, err := NewKeyFromPrivateKeyPEM([]byte(rsaPrivKeyAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse private key from PEM:", err)
	}
	otherKey, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating second RSA key:", err)
	}

	ca, err := NewCertificateAuthority("CA", crtAuth, key)
	if err != nil {
		t.Fatal("Failed creating matching CA identity:", err)
	}
	if ca.Name != "CA" || ca.Certificate != crtAuth || ca.Key != key {
		t.Fatal("CA identity did not preserve its name, certificate and key")
	}
	if !bytes.Equal(ca.AuthorityKeyID(), crtAuth.crt.SubjectKeyId) {
		t.Fatal("CA identity did not retain the certificate subject key ID")
	}

	ca, err = NewCertificateAuthority("CA", crtAuth, otherKey)
	if err == nil || ca != nil {
		t.Fatal("Created CA identity with a mismatched private key")
	}
	if !strings.Contains(err.Error(), "does not match private signer") {
		t.Fatalf("Mismatch error does not identify the signer mismatch: %v", err)
	}

	mixedKey := NewKey(crtAuth.crt.PublicKey, otherKey.Private)
	if _, err := NewCertificateAuthority("CA", crtAuth, mixedKey); err == nil {
		t.Fatal("Created CA identity with inconsistent Key public and private fields")
	}
}

func TestCAIdentityNewKeyFromPrivateKeyPEMRejectsNonSigner(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("Failed creating X25519 key:", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("Failed marshaling X25519 key:", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if parsed, err := NewKeyFromPrivateKeyPEM(keyPEM); err == nil || parsed != nil {
		t.Fatal("Parsed a non-signing private key as a certificate signer")
	}
}

func TestCAIdentityCreateCertificateHostRejectsMismatchedSigner(t *testing.T) {
	crtAuth, err := NewCertificateFromPEM([]byte(certAuthPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate from PEM:", err)
	}
	key, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating RSA key:", err)
	}
	csr, err := NewCertificateSigningRequestFromPEM([]byte(csrPEM))
	if err != nil {
		t.Fatal("Failed to parse certificate request from PEM:", err)
	}

	crt, err := CreateCertificateHost(crtAuth, key, csr, time.Now().Add(time.Hour))
	if err == nil || crt != nil {
		t.Fatal("Created host certificate with a private key that does not match the CA certificate")
	}
	if !strings.Contains(err.Error(), "does not match private signer") {
		t.Fatalf("Error does not identify the signer mismatch: %v", err)
	}
}

func TestCAIdentityCreateIntermediateAuthorityRejectsMismatchedSigner(t *testing.T) {
	rootKey, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating root key:", err)
	}
	rootCert, err := CreateCertificateAuthority(rootKey, "CA", time.Now().AddDate(1, 0, 0), "test", "US", "", "", "root", nil)
	if err != nil {
		t.Fatal("Failed creating root certificate:", err)
	}

	intermediateKey, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating intermediate key:", err)
	}
	csr, err := CreateCertificateSigningRequest(intermediateKey, "intermediate", nil, []string{"intermediate.example"}, nil, "test", "US", "", "", "intermediate")
	if err != nil {
		t.Fatal("Failed creating intermediate request:", err)
	}

	otherKey, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating mismatched key:", err)
	}
	intermediate, err := CreateIntermediateCertificateAuthority(rootCert, otherKey, csr, time.Now().AddDate(0, 1, 0))
	if err == nil || intermediate != nil {
		t.Fatal("Created intermediate certificate with a mismatched signer")
	}
	if !strings.Contains(err.Error(), "does not match private signer") {
		t.Fatalf("Error does not identify the signer mismatch: %v", err)
	}
}

func TestCAIdentityIssuedCertificate(t *testing.T) {
	tests := []struct {
		name string
		key  func() (*Key, error)
	}{
		{name: "RSA", key: func() (*Key, error) { return CreateRSAKey(rsaBits) }},
		{name: "ECDSA P-256", key: func() (*Key, error) { return CreateECDSAKey(elliptic.P256()) }},
		{name: "Ed25519", key: CreateEd25519Key},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caKey, err := tc.key()
			if err != nil {
				t.Fatal("Failed creating CA key:", err)
			}
			caCert, err := CreateCertificateAuthority(caKey, "CA", time.Now().AddDate(5, 0, 0), "test", "US", "", "", "CA", nil)
			if err != nil {
				t.Fatal("Failed creating CA certificate:", err)
			}

			hostKey, err := tc.key()
			if err != nil {
				t.Fatal("Failed creating host key:", err)
			}
			csr, err := CreateCertificateSigningRequest(hostKey, "host", nil, []string{"host.example"}, nil, "test", "US", "", "", "host")
			if err != nil {
				t.Fatal("Failed creating host request:", err)
			}
			hostCert, err := CreateCertificateHost(caCert, caKey, csr, time.Now().AddDate(1, 0, 0))
			if err != nil {
				t.Fatal("Failed creating host certificate:", err)
			}

			rawCA, err := caCert.GetRawCertificate()
			if err != nil {
				t.Fatal("Failed getting raw CA certificate:", err)
			}
			rawHost, err := hostCert.GetRawCertificate()
			if err != nil {
				t.Fatal("Failed getting raw host certificate:", err)
			}
			if !bytes.Equal(rawHost.RawIssuer, rawCA.RawSubject) {
				t.Fatal("Host certificate issuer does not match the CA subject")
			}
			if !bytes.Equal(rawHost.AuthorityKeyId, rawCA.SubjectKeyId) {
				t.Fatal("Host certificate AuthorityKeyId does not match the CA SubjectKeyId")
			}
			if err := rawHost.CheckSignatureFrom(rawCA); err != nil {
				t.Fatal("Host certificate signature does not verify against the CA:", err)
			}

			roots := x509.NewCertPool()
			roots.AddCert(rawCA)
			if _, err := rawHost.Verify(x509.VerifyOptions{
				Roots:     roots,
				DNSName:   "host.example",
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				t.Fatal("Client verification of host certificate failed:", err)
			}
		})
	}
}

func TestCAIdentityIntermediateChain(t *testing.T) {
	rootKey, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating root key:", err)
	}
	rootCert, err := CreateCertificateAuthorityWithOptions(rootKey, "CA", time.Now().AddDate(5, 0, 0), "test", "US", "", "", "root", nil, WithPathlenOption(1, false))
	if err != nil {
		t.Fatal("Failed creating root certificate:", err)
	}

	intermediateKey, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating intermediate key:", err)
	}
	intermediateCSR, err := CreateCertificateSigningRequest(intermediateKey, "intermediate", nil, nil, nil, "test", "US", "", "", "intermediate")
	if err != nil {
		t.Fatal("Failed creating intermediate request:", err)
	}
	intermediateCert, err := CreateIntermediateCertificateAuthorityWithOptions(rootCert, rootKey, intermediateCSR, time.Now().AddDate(1, 0, 0), WithPathlenOption(0, false))
	if err != nil {
		t.Fatal("Failed creating intermediate certificate:", err)
	}

	hostKey, err := CreateRSAKey(rsaBits)
	if err != nil {
		t.Fatal("Failed creating host key:", err)
	}
	hostCSR, err := CreateCertificateSigningRequest(hostKey, "host", nil, []string{"host.example"}, nil, "test", "US", "", "", "host")
	if err != nil {
		t.Fatal("Failed creating host request:", err)
	}
	hostCert, err := CreateCertificateHost(intermediateCert, intermediateKey, hostCSR, time.Now().AddDate(0, 1, 0))
	if err != nil {
		t.Fatal("Failed creating host certificate:", err)
	}

	rawRoot, err := rootCert.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed getting raw root certificate:", err)
	}
	rawIntermediate, err := intermediateCert.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed getting raw intermediate certificate:", err)
	}
	rawHost, err := hostCert.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed getting raw host certificate:", err)
	}

	if !bytes.Equal(rawIntermediate.RawIssuer, rawRoot.RawSubject) {
		t.Fatal("Intermediate issuer does not match the root subject")
	}
	if !bytes.Equal(rawIntermediate.AuthorityKeyId, rawRoot.SubjectKeyId) {
		t.Fatal("Intermediate AuthorityKeyId does not match the root SubjectKeyId")
	}
	if !bytes.Equal(rawHost.RawIssuer, rawIntermediate.RawSubject) {
		t.Fatal("Host issuer does not match the intermediate subject")
	}
	if !bytes.Equal(rawHost.AuthorityKeyId, rawIntermediate.SubjectKeyId) {
		t.Fatal("Host AuthorityKeyId does not match the intermediate SubjectKeyId")
	}

	roots := x509.NewCertPool()
	roots.AddCert(rawRoot)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(rawIntermediate)
	if _, err := rawHost.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "host.example",
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatal("Client verification of intermediate chain failed:", err)
	}
}
