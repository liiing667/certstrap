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
	"crypto/x509"
	"errors"
	"fmt"
)

// AuthorizationError records why an issuer certificate is not allowed to
// authorize the issuance of another certificate. All checks that gate a
// signing transaction (CA boolean, key usage and path length) return this
// error type so callers can reject the request before anything is published.
type AuthorizationError struct {
	issuer string
	reason string
}

func (e *AuthorizationError) Error() string {
	return fmt.Sprintf("issuer %q is not authorized to sign this certificate: %s", e.issuer, e.reason)
}

// newAuthorizationError builds an AuthorizationError, deriving a stable issuer
// name from the certificate subject when possible.
func newAuthorizationError(issuer *x509.Certificate, reason string) error {
	name := ""
	if issuer != nil {
		name = issuer.Subject.String()
	}
	return &AuthorizationError{issuer: name, reason: reason}
}

// CheckIssuerAuthorization validates that issuer is allowed to authorize the
// issuance of a new certificate. The same rule set is applied regardless of
// whether the resulting certificate is a host/leaf certificate or another CA:
//
//   - The issuer must carry a basic constraints extension asserting cA=true
//     (RFC 5280 4.2.1.9). A leaf certificate can never be an issuer.
//   - The issuer key usage, when present, must assert keyCertSign
//     (RFC 5280 4.2.1.3).
//   - When the new certificate is itself a CA (childIsCA), the issuer's
//     pathLenConstraint must still permit one more non-self-issued
//     intermediate below it (RFC 5280 4.2.1.9).
//
// It returns nil when the issuance is authorized and an *AuthorizationError
// otherwise. It never writes to the depot; the caller is responsible for
// publishing only after the whole signing transaction succeeds.
func CheckIssuerAuthorization(issuer *x509.Certificate, childIsCA bool) error {
	if issuer == nil {
		return errors.New("issuer certificate is nil")
	}

	// RFC 5280 4.2.1.9: a certificate without the cA boolean asserted must not
	// be used to verify certificate signatures.
	if !issuer.BasicConstraintsValid || !issuer.IsCA {
		return newAuthorizationError(issuer, "certificate is not a CA (basic constraints cA=false)")
	}

	// RFC 5280 4.2.1.3: keyCertSign must be asserted when key usage is present.
	// A zero KeyUsage means the extension is absent, in which case the usage is
	// unrestricted.
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return newAuthorizationError(issuer, "key usage does not permit certificate signing (keyCertSign not set)")
	}

	// pathLenConstraint gives the maximum number of non-self-issued
	// intermediate certificates that may follow this certificate in a valid
	// path. MaxPathLen < 0 means the constraint was not encoded, i.e. no depth
	// limit. Signing another CA consumes one slot, so a present constraint
	// smaller than one means the depth budget is already exhausted.
	if childIsCA && issuer.MaxPathLen >= 0 && issuer.MaxPathLen < 1 {
		return newAuthorizationError(issuer, fmt.Sprintf(
			"path length constraint exceeded: issuer allows %d more non-self-issued intermediate certificate(s), signing a CA certificate requires 1",
			issuer.MaxPathLen))
	}

	return nil
}

// VerifyChain verifies the issued certificate against the supplied trust
// anchors using the same logic as a final chain consumer (crypto/x509
// Certificate.Verify). roots contains the trust anchor(s) and intermediates
// the CA certificates between the anchor and the issued certificate. It
// returns nil only when at least one complete, valid chain exists, which
// guarantees that non-CA issuers, exhausted path length constraints and any
// other chain defect are rejected before the certificate is published.
func VerifyChain(issued *Certificate, roots *x509.CertPool, intermediates *x509.CertPool) error {
	raw, err := issued.GetRawCertificate()
	if err != nil {
		return fmt.Errorf("failed to parse issued certificate: %w", err)
	}
	if roots == nil {
		return errors.New("no root certificate pool provided for chain verification")
	}

	chains, err := raw.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// The default key usage (ExtKeyUsageServerAuth) is inappropriate for
		// CA certificates. Any key usage is acceptable: the issuance decision
		// is based on basic constraints, key usage and path length, not EKU.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("issued certificate fails chain verification: %w", err)
	}
	if len(chains) == 0 {
		return errors.New("issued certificate fails chain verification: no valid certification path found")
	}
	return nil
}

// checkIssuedBy validates a freshly created certificate against its immediate
// issuer. It combines the explicit authorization gate with the standard
// library's signature and chain checks so that a certificate which a final
// consumer could not validate can never be returned to the caller.
func checkIssuedBy(issued *Certificate, issuer *x509.Certificate) error {
	rawIssued, err := issued.GetRawCertificate()
	if err != nil {
		return fmt.Errorf("failed to parse issued certificate: %w", err)
	}

	// The direct parent must itself be a CA permitted to sign certificates.
	if err := CheckIssuerAuthorization(issuer, rawIssued.IsCA); err != nil {
		return err
	}

	// CheckSignatureFrom enforces cA, basic constraints and keyCertSign exactly
	// as a consumer does while walking the chain.
	if err := rawIssued.CheckSignatureFrom(issuer); err != nil {
		return newAuthorizationError(issuer, fmt.Sprintf("signature/constraint check failed: %v", err))
	}

	// Full chain verification with the issuer as a trust anchor. For an
	// intermediate this also re-evaluates its own basic constraints; for a leaf
	// it validates the complete one-level path.
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	return VerifyChain(issued, roots, nil)
}
