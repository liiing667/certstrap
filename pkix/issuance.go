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
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// certificateRequestForIssuance creates the single immutable request snapshot
// used by every issuance entry point.
func certificateRequestForIssuance(csr *CertificateSigningRequest) (*verifiedCertificateRequest, error) {
	if csr == nil {
		return nil, errors.New("nil certificate signing request")
	}
	return csr.verifiedForIssuance()
}

// authorizeCA snapshots and checks the issuing certificate and its private
// key. The returned certificate is the exact issuer that must be used to sign
// and to verify the resulting certificate.
func authorizeCA(crtAuth *Certificate, keyAuth *Key) (*x509.Certificate, crypto.Signer, error) {
	if crtAuth == nil {
		return nil, nil, errors.New("nil CA certificate")
	}
	if keyAuth == nil {
		return nil, nil, errors.New("nil CA private key")
	}

	rawCrtAuth, err := crtAuth.rawSnapshot()
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !rawCrtAuth.IsCA {
		return nil, nil, errors.New("CA certificate is not allowed to sign certificates")
	}
	if rawCrtAuth.KeyUsage != 0 && rawCrtAuth.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("CA certificate is not allowed to sign certificates")
	}

	signer, ok := keyAuth.Private.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("CA private key does not implement crypto.Signer")
	}
	if !publicKeysEqual(rawCrtAuth.PublicKey, signer.Public()) {
		return nil, nil, errors.New("CA private key does not match CA certificate")
	}

	return rawCrtAuth, signer, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	aDER, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bDER, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aDER, bDER)
}

func certificateNotAfter(crtAuth *x509.Certificate, proposedExpiry time.Time) time.Time {
	// Certificate times are encoded at second precision. Keep a full second
	// of headroom so a certificate serialized at the same instant as its
	// issuer can never be encoded with a NotAfter after the CA's NotAfter.
	caExpiry := crtAuth.NotAfter.Add(-time.Second)
	if caExpiry.Before(proposedExpiry) {
		return caExpiry
	}
	return proposedExpiry
}

// finalizeIssuedCertificate verifies that the certificate produced for one
// request is actually the certificate of that request before it can be
// returned or written to disk.
func finalizeIssuedCertificate(derBytes []byte, request *verifiedCertificateRequest, crtAuth *x509.Certificate, wantCA bool) (*Certificate, error) {
	crt, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}
	if err := verifyIssuedCertificate(crt, request, crtAuth, wantCA); err != nil {
		return nil, err
	}
	return NewCertificateFromDER(derBytes), nil
}

func verifyIssuedCertificate(crt *x509.Certificate, request *verifiedCertificateRequest, crtAuth *x509.Certificate, wantCA bool) error {
	if crt == nil || request == nil || crtAuth == nil {
		return errors.New("incomplete certificate issuance transaction")
	}

	if !bytes.Equal(crt.RawSubject, request.rawSubject) {
		return errors.New("issued certificate subject does not match certificate request")
	}
	if !publicKeysEqual(crt.PublicKey, request.publicKey) {
		return errors.New("issued certificate public key does not match certificate request")
	}
	if !bytes.Equal(crt.RawIssuer, crtAuth.RawSubject) {
		return errors.New("issued certificate issuer does not match CA certificate")
	}
	if !certificateSANsMatch(crt, request) {
		return errors.New("issued certificate SANs do not match certificate request")
	}
	if crt.IsCA != wantCA {
		return errors.New("issued certificate CA identity does not match issuance template")
	}
	if !bytes.Equal(crt.SubjectKeyId, request.subjectKeyID) {
		return errors.New("issued certificate subject key ID does not match certificate request")
	}
	if len(crtAuth.SubjectKeyId) > 0 && !bytes.Equal(crt.AuthorityKeyId, crtAuth.SubjectKeyId) {
		return errors.New("issued certificate authority key ID does not match CA certificate")
	}
	if crt.NotAfter.After(crtAuth.NotAfter) {
		return errors.New("issued certificate expires after CA certificate")
	}
	if err := crt.CheckSignatureFrom(crtAuth); err != nil {
		return fmt.Errorf("issued certificate signature verification failed: %w", err)
	}

	return nil
}

func certificateSANsMatch(crt *x509.Certificate, request *verifiedCertificateRequest) bool {
	return sameStrings(crt.DNSNames, request.dnsNames) &&
		sameStrings(crt.EmailAddresses, request.emailAddresses) &&
		sameIPs(crt.IPAddresses, request.ipAddresses) &&
		sameURLs(crt.URIs, request.uris)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameIPs(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func sameURLs(a, b []*url.URL) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] == nil || b[i] == nil {
			if a[i] != nil || b[i] != nil {
				return false
			}
			continue
		}
		if a[i].String() != b[i].String() {
			return false
		}
	}
	return true
}
