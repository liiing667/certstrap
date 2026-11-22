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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

const (
	csrPEMBlockType    = "CERTIFICATE REQUEST"
	oldCsrPEMBlockType = "NEW CERTIFICATE REQUEST"
)

// ParseAndValidateIPs parses a comma-delimited list of IP addresses into an array of IP addresses
func ParseAndValidateIPs(ipList string) (res []net.IP, err error) {
	// IP list can potentially be a blank string, ""
	if len(ipList) > 0 {
		ips := strings.Split(ipList, ",")
		for _, ip := range ips {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				return nil, fmt.Errorf("Invalid IP address: %s", ip)
			}
			res = append(res, parsedIP)
		}
	}
	return
}

// ParseAndValidateURIs parses a comma-delimited list of URIs into an array of url.URLs
func ParseAndValidateURIs(uriList string) (res []*url.URL, err error) {
	if len(uriList) > 0 {
		uris := strings.Split(uriList, ",")
		for _, uri := range uris {
			parsedURI, err := url.Parse(uri)
			if err != nil {
				parsedURI = nil
			}
			if parsedURI == nil {
				return nil, fmt.Errorf("Invalid URI: %s", uri)
			}
			if !parsedURI.IsAbs() {
				return nil, fmt.Errorf("Invalid URI: %s", uri)
			}
			res = append(res, parsedURI)
		}
	}
	return
}

// CreateCertificateSigningRequest sets up a request to create a csr file with the given parameters
func CreateCertificateSigningRequest(key *Key, organizationalUnit string, ipList []net.IP, domainList []string, uriList []*url.URL, organization string, country string, province string, locality string, commonName string) (*CertificateSigningRequest, error) {
	csrPkixName := pkix.Name{CommonName: commonName}

	if len(organizationalUnit) > 0 {
		csrPkixName.OrganizationalUnit = []string{organizationalUnit}
	}
	if len(organization) > 0 {
		csrPkixName.Organization = []string{organization}
	}
	if len(country) > 0 {
		csrPkixName.Country = []string{country}
	}
	if len(province) > 0 {
		csrPkixName.Province = []string{province}
	}
	if len(locality) > 0 {
		csrPkixName.Locality = []string{locality}
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:     csrPkixName,
		IPAddresses: ipList,
		DNSNames:    domainList,
		URIs:        uriList,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key.Private)
	if err != nil {
		return nil, err
	}
	return NewCertificateSigningRequestFromDER(csrBytes), nil
}

// CertificateSigningRequest is a wrapper around a x509 CertificateRequest and
// the exact DER bytes it was parsed from. The DER bytes are the immutable
// source of truth for the request: every parse returns a fresh object, so a
// parsed request can never keep stale state from an earlier operation.
type CertificateSigningRequest struct {
	// derBytes is always set for valid Certificate
	derBytes []byte
}

// NewCertificateSigningRequestFromDER inits CertificateSigningRequest from DER-format bytes
func NewCertificateSigningRequestFromDER(derBytes []byte) *CertificateSigningRequest {
	return &CertificateSigningRequest{derBytes: append([]byte(nil), derBytes...)}
}

// NewCertificateSigningRequestFromPEM inits CertificateSigningRequest from PEM-format bytes
// data should contain at most one certificate
func NewCertificateSigningRequestFromPEM(data []byte) (*CertificateSigningRequest, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if (pemBlock.Type != csrPEMBlockType && pemBlock.Type != oldCsrPEMBlockType) || len(pemBlock.Headers) != 0 {
		return nil, errors.New("unmatched type or headers")
	}
	return &CertificateSigningRequest{derBytes: append([]byte(nil), pemBlock.Bytes...)}, nil
}

// parseRaw parses the request's immutable DER bytes. It deliberately does not
// cache the result: callers must not be able to observe a request, cache it,
// replace the request bytes, and then have the old parse reused.
func (c *CertificateSigningRequest) parseRaw() (*x509.CertificateRequest, error) {
	if c == nil || len(c.derBytes) == 0 {
		return nil, errors.New("empty certificate signing request")
	}
	derBytes := append([]byte(nil), c.derBytes...)
	return x509.ParseCertificateRequest(derBytes)
}

// GetRawCertificateSigningRequest returns a copy of this certificate request as an x509.CertificateRequest.
func (c *CertificateSigningRequest) GetRawCertificateSigningRequest() (*x509.CertificateRequest, error) {
	return c.parseRaw()
}

// CheckSignature verifies that the signature is a valid signature
// using the public key in CertificateSigningRequest.
func (c *CertificateSigningRequest) CheckSignature() error {
	cr, err := c.parseRaw()
	if err != nil {
		return err
	}
	if err := checkSignature(cr, cr.SignatureAlgorithm, cr.RawTBSCertificateRequest, cr.Signature); err != nil {
		return fmt.Errorf("certificate request signature verification failed: %w", err)
	}
	return nil
}

// checkSignature verifies a signature made by the key on a CSR, such
// as on the CSR itself.
func checkSignature(csr *x509.CertificateRequest, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	if csr == nil {
		return errors.New("nil certificate request")
	}
	verified := *csr
	verified.SignatureAlgorithm = algo
	verified.RawTBSCertificateRequest = signed
	verified.Signature = signature
	err := verified.CheckSignature()
	if err == nil {
		return nil
	}
	if algo != x509.SHA1WithRSA && algo != x509.ECDSAWithSHA1 {
		return err
	}

	// Older certstrap releases accepted SHA-1 CSRs. Keep that compatibility
	// even if the standard library's verification policy rejects SHA-1.
	digest := sha1.Sum(signed)
	switch algo {
	case x509.SHA1WithRSA:
		pub, ok := csr.PublicKey.(*rsa.PublicKey)
		if !ok {
			return x509.ErrUnsupportedAlgorithm
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest[:], signature)
	case x509.ECDSAWithSHA1:
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return x509.ErrUnsupportedAlgorithm
		}
		if !ecdsa.VerifyASN1(pub, digest[:], signature) {
			return errors.New("x509: ECDSA signature verification failure")
		}
		return nil
	default:
		return x509.ErrUnsupportedAlgorithm
	}
}

// verifiedCertificateRequest is the immutable result of parsing and verifying
// exactly one CSR. All certificate issuance inputs are copied out of that one
// parse, so proof of possession, public key, subject, SANs and subject key ID
// can never come from different requests or from a later mutation.
type verifiedCertificateRequest struct {
	publicKey      crypto.PublicKey
	rawSubject     []byte
	subjectKeyID   []byte
	dnsNames       []string
	emailAddresses []string
	ipAddresses    []net.IP
	uris           []*url.URL
}

// verifiedForIssuance parses and verifies one CSR, then snapshots every value
// that may be used by certificate issuance.
func (c *CertificateSigningRequest) verifiedForIssuance() (*verifiedCertificateRequest, error) {
	raw, err := c.parseRaw()
	if err != nil {
		return nil, err
	}
	if err := checkSignature(raw, raw.SignatureAlgorithm, raw.RawTBSCertificateRequest, raw.Signature); err != nil {
		return nil, fmt.Errorf("certificate request signature verification failed: %w", err)
	}
	if raw.PublicKey == nil || len(raw.RawSubjectPublicKeyInfo) == 0 {
		return nil, errors.New("certificate request does not contain a public key")
	}

	subjectKeyID, err := GenerateSubjectKeyID(raw.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("certificate request public key: %w", err)
	}

	return &verifiedCertificateRequest{
		publicKey:      raw.PublicKey,
		rawSubject:     append([]byte(nil), raw.RawSubject...),
		subjectKeyID:   subjectKeyID,
		dnsNames:       cloneStrings(raw.DNSNames),
		emailAddresses: cloneStrings(raw.EmailAddresses),
		ipAddresses:    cloneIPs(raw.IPAddresses),
		uris:           cloneURLs(raw.URIs),
	}, nil
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneIPs(values []net.IP) []net.IP {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]net.IP, len(values))
	for i, value := range values {
		cloned[i] = append(net.IP(nil), value...)
	}
	return cloned
}

func cloneURLs(values []*url.URL) []*url.URL {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]*url.URL, len(values))
	for i, value := range values {
		if value == nil {
			continue
		}
		copied := *value
		cloned[i] = &copied
	}
	return cloned
}

// Export returns PEM-format bytes
func (c *CertificateSigningRequest) Export() ([]byte, error) {
	pemBlock := &pem.Block{
		Type:    csrPEMBlockType,
		Headers: nil,
		Bytes:   c.derBytes,
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, pemBlock); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
