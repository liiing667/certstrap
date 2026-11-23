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
	"math/big"
	"time"
)

// CreateCertificateHost creates certificate for host.
// The arguments include CA certificate, CA key, certificate request.
func CreateCertificateHost(crtAuth *Certificate, keyAuth *Key, csr *CertificateSigningRequest, proposedExpiry time.Time) (*Certificate, error) {
	return CreateCertificateHostAt(crtAuth, keyAuth, csr, proposedExpiry, time.Now().UTC())
}

// CreateCertificateHostAt creates a certificate for host using a single
// issuance-time snapshot for the issuer window, the leaf window and the final
// chain verification.
func CreateCertificateHostAt(crtAuth *Certificate, keyAuth *Key, csr *CertificateSigningRequest, proposedExpiry, issuedAt time.Time) (*Certificate, error) {
	rawCrtAuth, err := crtAuth.GetRawCertificate()
	if err != nil {
		return nil, err
	}

	notBefore, notAfter, err := issuanceWindow(rawCrtAuth, proposedExpiry, issuedAt)
	if err != nil {
		return nil, err
	}

	// Build CA based on RFC5280
	hostTemplate := x509.Certificate{
		// **SHOULD** be filled in a unique number
		SerialNumber: big.NewInt(0),
		// **SHOULD** be filled in host info
		Subject: pkix.Name{},
		// The whole validity window comes from the issuance snapshot.
		NotBefore: notBefore,
		NotAfter:  notAfter,
		// Used for certificate signing only
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		UnknownExtKeyUsage: nil,

		BasicConstraintsValid: false,

		// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
		// (excluding the tag, length, and number of unused bits)
		// **SHOULD** be filled in later
		SubjectKeyId: nil,

		// Subject Alternative Name
		DNSNames: nil,

		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	hostTemplate.SerialNumber.Set(serialNumber)

	rawCsr, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		return nil, err
	}

	// pkix.Name{} doesn't take ordering into account.
	// RawSubject works because CreateCertificate() first checks if
	// RawSubject has a value.
	hostTemplate.RawSubject = rawCsr.RawSubject

	hostTemplate.SubjectKeyId, err = GenerateSubjectKeyID(rawCsr.PublicKey)
	if err != nil {
		return nil, err
	}

	hostTemplate.IPAddresses = rawCsr.IPAddresses
	hostTemplate.DNSNames = rawCsr.DNSNames
	hostTemplate.URIs = rawCsr.URIs

	crtHostBytes, err := x509.CreateCertificate(rand.Reader, &hostTemplate, rawCrtAuth, rawCsr.PublicKey, keyAuth.Private)
	if err != nil {
		return nil, err
	}

	crtOut := NewCertificateFromDER(crtHostBytes)
	rawCrtOut, err := crtOut.GetRawCertificate()
	if err != nil {
		return nil, err
	}
	if err := verifyIssuedCertificateAt(rawCrtOut, rawCrtAuth, issuedAt); err != nil {
		return nil, err
	}
	return crtOut, nil
}
