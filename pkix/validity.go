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
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// certificateBackdate is how far before the issuance snapshot a new
// certificate becomes valid. It absorbs small clock differences between the
// machines in a cluster.
const certificateBackdate = 10 * time.Minute

// CheckIssuerValidityAt reports whether issuer's validity window contains the
// supplied issuance snapshot. It does not inspect CA authorization; callers
// that need that check (for example CheckIssuerAuthorization) must apply it
// separately.
func CheckIssuerValidityAt(issuer *x509.Certificate, issuedAt time.Time) error {
	if issuer == nil {
		return errors.New("issuer certificate is nil")
	}
	if issuedAt.IsZero() {
		return errors.New("issuance time is zero")
	}
	if !issuer.NotBefore.Before(issuer.NotAfter) {
		return fmt.Errorf(
			"issuer certificate validity window is invalid: NotBefore %s is not before NotAfter %s",
			issuer.NotBefore.UTC().Format(time.RFC3339),
			issuer.NotAfter.UTC().Format(time.RFC3339),
		)
	}
	if issuedAt.Before(issuer.NotBefore) {
		return fmt.Errorf(
			"issuer certificate is not valid until %s, after the issuance time %s",
			issuer.NotBefore.UTC().Format(time.RFC3339),
			issuedAt.UTC().Format(time.RFC3339),
		)
	}
	if issuedAt.After(issuer.NotAfter) {
		return fmt.Errorf(
			"issuer certificate expired at %s, before the issuance time %s",
			issuer.NotAfter.UTC().Format(time.RFC3339),
			issuedAt.UTC().Format(time.RFC3339),
		)
	}
	return nil
}

// issuanceWindow derives the leaf validity window from one issuance snapshot.
// The leaf is backdated by certificateBackdate (but never before the issuer's
// NotBefore) and expires at proposedExpiry or the issuer's NotAfter, whichever
// is earlier. It returns an error instead of producing a certificate whose
// validity window is empty, backwards, or already expired at issuedAt.
func issuanceWindow(issuer *x509.Certificate, proposedExpiry, issuedAt time.Time) (time.Time, time.Time, error) {
	issuedAt = issuedAt.UTC()
	if err := CheckIssuerValidityAt(issuer, issuedAt); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if proposedExpiry.IsZero() {
		return time.Time{}, time.Time{}, errors.New("proposed expiration is zero")
	}
	proposedExpiry = proposedExpiry.UTC()
	if !proposedExpiry.After(issuedAt) {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"proposed expiration %s is not after the issuance time %s",
			proposedExpiry.Format(time.RFC3339),
			issuedAt.Format(time.RFC3339),
		)
	}

	notBefore := issuedAt.Add(-certificateBackdate)
	if notBefore.Before(issuer.NotBefore) {
		notBefore = issuer.NotBefore
	}

	notAfter := proposedExpiry
	if issuer.NotAfter.Before(notAfter) {
		notAfter = issuer.NotAfter
	}
	if !notAfter.After(issuedAt) {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"issuer certificate expires at %s, leaving no validity after the issuance time %s",
			issuer.NotAfter.UTC().Format(time.RFC3339),
			issuedAt.Format(time.RFC3339),
		)
	}
	if !notAfter.After(notBefore) {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"certificate validity window is empty: NotBefore %s is not before NotAfter %s",
			notBefore.UTC().Format(time.RFC3339),
			notAfter.UTC().Format(time.RFC3339),
		)
	}

	// ASN.1 (the encoding used by X.509) only supports years up to 9999.
	if notBefore.Year() > 9999 || notAfter.Year() > 9999 {
		return time.Time{}, time.Time{}, fmt.Errorf(
			"proposed certificate validity ends in year %d; expiry year must be less than or equal to 9999",
			notAfter.Year(),
		)
	}

	return notBefore.UTC(), notAfter.UTC(), nil
}

// verifyIssuedCertificateAt verifies a freshly serialized certificate exactly
// as a client would, using the same issuance snapshot that produced its
// validity window. Only the immediate issuer is needed: it is the trust anchor
// for this transaction, and its own window was checked before serialization.
func verifyIssuedCertificateAt(issued, issuer *x509.Certificate, issuedAt time.Time) error {
	if issued == nil {
		return errors.New("issued certificate is nil")
	}
	if err := CheckIssuerValidityAt(issuer, issuedAt); err != nil {
		return err
	}

	if err := issued.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("issued certificate signature check failed: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(issuer)

	chains, err := issued.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: issuedAt.UTC(),
		// The requested extended key usages depend on the leaf purpose. The
		// time and signature checks are common to all of them.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf(
			"issued certificate fails chain verification at %s: %w",
			issuedAt.UTC().Format(time.RFC3339),
			err,
		)
	}
	if len(chains) == 0 {
		return errors.New("issued certificate fails chain verification: no valid certification path found")
	}
	return nil
}

// VerifyIssuedCertificateAt verifies issued against issuer at the supplied
// issuance snapshot. It is exported so that the command layer can run the
// final chain-consumer check before publishing any certificate bytes.
func VerifyIssuedCertificateAt(issued, issuer *Certificate, issuedAt time.Time) error {
	if issued == nil {
		return errors.New("issued certificate is nil")
	}
	if issuer == nil {
		return errors.New("issuer certificate is nil")
	}
	rawIssued, err := issued.GetRawCertificate()
	if err != nil {
		return fmt.Errorf("failed to parse issued certificate: %w", err)
	}
	rawIssuer, err := issuer.GetRawCertificate()
	if err != nil {
		return fmt.Errorf("failed to parse issuer certificate: %w", err)
	}
	return verifyIssuedCertificateAt(rawIssued, rawIssuer, issuedAt)
}
