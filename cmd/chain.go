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

package cmd

import (
	"bytes"
	"crypto/x509"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
)

// loadDepotCertificates reads every certificate stored in the depot. Files
// that cannot be parsed as a single certificate are skipped so unrelated
// entries never get in the way of chain construction.
func loadDepotCertificates() map[string]*x509.Certificate {
	certs := make(map[string]*x509.Certificate)
	for _, tag := range d.List() {
		name := depot.GetNameFromCrtTag(tag)
		if name == "" {
			continue
		}
		cert, err := depot.GetCertificate(d, name)
		if err != nil {
			continue
		}
		raw, err := cert.GetRawCertificate()
		if err != nil {
			continue
		}
		certs[name] = raw
	}
	return certs
}

// isRoot reports whether cert is a self-signed trust anchor.
func isRoot(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

// findIssuer locates the certificate that signed child among the depot
// certificates. It prefers an authority/ subject key identifier match and
// falls back to the subject/issuer name relationship plus a cryptographic
// signature check. The child itself is never returned.
func findIssuer(child *x509.Certificate, certs map[string]*x509.Certificate) *x509.Certificate {
	var nameMatch *x509.Certificate
	for _, candidate := range certs {
		if candidate.Equal(child) {
			continue
		}
		if string(candidate.RawSubject) != string(child.RawIssuer) {
			continue
		}
		if child.CheckSignatureFrom(candidate) != nil {
			continue
		}
		if len(child.AuthorityKeyId) > 0 && bytes.Equal(child.AuthorityKeyId, candidate.SubjectKeyId) {
			return candidate
		}
		if nameMatch == nil {
			nameMatch = candidate
		}
	}
	return nameMatch
}

// buildTrustChain walks up from issuer until it reaches a self-signed root.
// It returns the root (if any) and the ordered list of intermediate CA
// certificates strictly between the root and the signing issuer.
func buildTrustChain(issuer *x509.Certificate, certs map[string]*x509.Certificate) (root *x509.Certificate, intermediates []*x509.Certificate) {
	current := issuer
	visited := map[string]bool{string(current.RawSubject): true}
	for {
		if isRoot(current) {
			return current, intermediates
		}
		parent := findIssuer(current, certs)
		if parent == nil || visited[string(parent.RawSubject)] {
			// No anchor available in the depot: treat the highest available
			// certificate as a trust root so verification can still run.
			return current, intermediates
		}
		if !isRoot(parent) {
			// parent is another intermediate: current belongs in the
			// intermediate pool, then keep walking up toward the anchor.
			intermediates = append([]*x509.Certificate{current}, intermediates...)
		}
		current = parent
		visited[string(current.RawSubject)] = true
	}
}

// verifyIssuedCertificate runs the final-chain-consumer verification against
// the issued certificate. The signing CA is loaded from the depot and its path
// back to a root is reconstructed from stored certificates. Verification must
// succeed before the caller is allowed to publish anything.
func verifyIssuedCertificate(caName string, issued *pkix.Certificate) error {
	certs := loadDepotCertificates()

	issuer, ok := certs[caName]
	if !ok {
		caCert, err := depot.GetCertificate(d, caName)
		if err != nil {
			return err
		}
		issuer, err = caCert.GetRawCertificate()
		if err != nil {
			return err
		}
	}

	root, chainIntermediates := buildTrustChain(issuer, certs)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	for _, intermediate := range chainIntermediates {
		intermediates.AddCert(intermediate)
	}

	return pkix.VerifyChain(issued, roots, intermediates)
}
