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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
)

// CertificateAuthority binds a CA certificate, the private signer that is
// allowed to use it, and the depot name that selected both. All certificate
// issuance must use the signer and raw certificate captured here so that a
// key rotation cannot leave the issuer and signature pointing at different
// identities.
type CertificateAuthority struct {
	// Name is the depot name used to load the certificate and key.
	Name string
	// Certificate is the CA certificate selected by Name.
	Certificate *Certificate
	// Key is the private key selected by Name.
	Key *Key

	raw                    *x509.Certificate
	signer                 crypto.Signer
	authorityKeyID         []byte
	certificateFingerprint string
	signerFingerprint      string
}

// NewCertificateAuthority validates that cert and key are one CA identity.
// It fails closed when the certificate is not a CA, when the key cannot sign,
// or when the certificate and signer public keys differ.
func NewCertificateAuthority(name string, cert *Certificate, key *Key) (*CertificateAuthority, error) {
	const stage = "validate CA identity"

	if cert == nil {
		return nil, fmt.Errorf("CA %q: certificate is missing (stage: %s)", name, stage)
	}
	raw, err := cert.GetRawCertificate()
	if err != nil {
		return nil, fmt.Errorf("CA %q: parse certificate: %w (stage: %s)", name, err, stage)
	}
	if !raw.IsCA {
		return nil, fmt.Errorf("CA %q: certificate %q is not a CA (stage: %s)", name, raw.Subject.CommonName, stage)
	}
	if raw.KeyUsage != 0 && raw.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("CA %q: certificate %q is not allowed to sign certificates (stage: %s)", name, raw.Subject.CommonName, stage)
	}
	if bytes.Equal(raw.RawSubject, raw.RawIssuer) {
		if err := cert.CheckAuthority(); err != nil {
			return nil, fmt.Errorf("CA %q: self-issued CA certificate is not self-signed: %w (stage: %s)", name, err, stage)
		}
	}

	signer, signerPublic, err := signerAndPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("CA %q: %w (stage: %s)", name, err, stage)
	}

	certificatePublicID, err := publicKeyFingerprint(raw.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("CA %q: certificate public key: %w (stage: %s)", name, err, stage)
	}
	signerPublicID, err := publicKeyFingerprint(signerPublic)
	if err != nil {
		return nil, fmt.Errorf("CA %q: private signer public key: %w (stage: %s)", name, err, stage)
	}
	match, err := PublicKeysEqual(raw.PublicKey, signerPublic)
	if err != nil {
		return nil, fmt.Errorf("CA %q: compare certificate and private signer: %w (stage: %s)", name, err, stage)
	}
	if !match {
		return nil, fmt.Errorf(
			"CA %q: certificate public key %s does not match private signer public key %s (stage: %s)",
			name, certificatePublicID, signerPublicID, stage,
		)
	}

	authorityKeyID := append([]byte(nil), raw.SubjectKeyId...)
	if len(authorityKeyID) == 0 {
		authorityKeyID, err = GenerateSubjectKeyID(raw.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("CA %q: derive authority key identifier: %w (stage: %s)", name, err, stage)
		}
	}

	certificateDER := cert.derBytes
	if len(certificateDER) == 0 {
		certificateDER = raw.Raw
	}
	certificateFingerprint := sha256.Sum256(certificateDER)

	return &CertificateAuthority{
		Name:                   name,
		Certificate:            cert,
		Key:                    key,
		raw:                    raw,
		signer:                 signer,
		authorityKeyID:         authorityKeyID,
		certificateFingerprint: fmt.Sprintf("sha256:%x", certificateFingerprint[:]),
		signerFingerprint:      signerPublicID,
	}, nil
}

// RawCertificate returns the parsed CA certificate captured when the identity
// was created.
func (ca *CertificateAuthority) RawCertificate() *x509.Certificate {
	return ca.raw
}

// Signer returns the private signer captured when the identity was created.
func (ca *CertificateAuthority) Signer() crypto.Signer {
	return ca.signer
}

// AuthorityKeyID returns the key identifier that leaf certificates must put in
// their AuthorityKeyId extension. It is the CA SubjectKeyId when present and a
// key-derived identifier for older certificates without one.
func (ca *CertificateAuthority) AuthorityKeyID() []byte {
	return append([]byte(nil), ca.authorityKeyID...)
}

// CertificateFingerprint identifies the exact CA certificate used for signing.
func (ca *CertificateAuthority) CertificateFingerprint() string {
	return ca.certificateFingerprint
}

// SignerFingerprint identifies the public key of the private signer.
func (ca *CertificateAuthority) SignerFingerprint() string {
	return ca.signerFingerprint
}

// MatchesCertificate reports whether cert is the exact certificate captured by
// this CA identity.
func (ca *CertificateAuthority) MatchesCertificate(cert *Certificate) bool {
	if cert == nil {
		return false
	}
	raw, err := cert.GetRawCertificate()
	if err != nil {
		return false
	}
	currentDER := cert.derBytes
	if len(currentDER) == 0 {
		currentDER = raw.Raw
	}
	caDER := ca.Certificate.derBytes
	if len(caDER) == 0 {
		caDER = ca.raw.Raw
	}
	return bytes.Equal(currentDER, caDER)
}

// VerifyIssuedCertificate verifies that cert was issued by this CA identity:
// its issuer name, AuthorityKeyId and signature must all belong to the captured
// CA certificate. expectCA must match the Basic Constraints CA bit.
func (ca *CertificateAuthority) VerifyIssuedCertificate(cert *Certificate, expectCA bool) error {
	if cert == nil {
		return fmt.Errorf("CA %q: issued certificate is missing (stage: verify issued certificate)", ca.Name)
	}
	rawLeaf, err := cert.GetRawCertificate()
	if err != nil {
		return fmt.Errorf("CA %q: parse issued certificate: %w (stage: verify issued certificate)", ca.Name, err)
	}
	if rawLeaf.IsCA != expectCA {
		return fmt.Errorf(
			"CA %q: issued certificate %q has CA=%t, want CA=%t (stage: verify issued certificate)",
			ca.Name, rawLeaf.Subject.CommonName, rawLeaf.IsCA, expectCA,
		)
	}
	if err := cert.CheckSignatureFrom(ca.Certificate); err != nil {
		return fmt.Errorf("CA %q: issued certificate %q: %w (stage: verify issued certificate)", ca.Name, rawLeaf.Subject.CommonName, err)
	}
	return nil
}

// signerAndPublicKey extracts the crypto.Signer and verifies that the Key's
// exported public key agrees with the private signer.
func signerAndPublicKey(key *Key) (crypto.Signer, crypto.PublicKey, error) {
	if key == nil || isNilValue(key.Private) {
		return nil, nil, errors.New("private key is missing")
	}
	signer, ok := key.Private.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key type %T does not implement crypto.Signer", key.Private)
	}
	if ed, ok := signer.(ed25519.PrivateKey); ok && len(ed) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("Ed25519 private key has an invalid length")
	}
	public := signer.Public()
	if isNilValue(public) {
		return nil, nil, errors.New("private signer does not expose a public key")
	}
	if err := validateSignerPublicKey(public); err != nil {
		return nil, nil, err
	}
	if _, err := x509.MarshalPKIXPublicKey(public); err != nil {
		return nil, nil, fmt.Errorf("private signer public key: %w", err)
	}
	if isNilValue(key.Public) {
		return signer, public, nil
	}
	match, err := PublicKeysEqual(key.Public, public)
	if err != nil {
		return nil, nil, fmt.Errorf("compare key public key and private signer: %w", err)
	}
	if !match {
		keyID, keyErr := publicKeyFingerprint(key.Public)
		if keyErr != nil {
			keyID = fmt.Sprintf("%T", key.Public)
		}
		signerID, signerErr := publicKeyFingerprint(public)
		if signerErr != nil {
			signerID = fmt.Sprintf("%T", public)
		}
		return nil, nil, fmt.Errorf(
			"key public key %s does not match private signer public key %s",
			keyID, signerID,
		)
	}
	return signer, public, nil
}

func validateSignerPublicKey(public crypto.PublicKey) error {
	switch pub := public.(type) {
	case *rsa.PublicKey:
		if pub.N == nil || pub.N.Sign() <= 0 || pub.E < 2 {
			return errors.New("RSA public key is empty")
		}
	case *ecdsa.PublicKey:
		if pub.Curve == nil || pub.X == nil || pub.Y == nil {
			return errors.New("ECDSA public key is empty")
		}
	case ed25519.PublicKey:
		if len(pub) != ed25519.PublicKeySize {
			return errors.New("Ed25519 public key has an invalid length")
		}
	default:
		return fmt.Errorf("unsupported public key type %T", public)
	}
	return nil
}

// PublicKeysEqual reports whether two public keys have the same PKIX encoding.
func PublicKeysEqual(a, b crypto.PublicKey) (bool, error) {
	if isNilValue(a) || isNilValue(b) {
		return false, errors.New("public key is missing")
	}
	if err := validateSignerPublicKey(a); err != nil {
		return false, err
	}
	if err := validateSignerPublicKey(b); err != nil {
		return false, err
	}
	aDER, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false, fmt.Errorf("marshal public key %T: %w", a, err)
	}
	bDER, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false, fmt.Errorf("marshal public key %T: %w", b, err)
	}
	return bytes.Equal(aDER, bDER), nil
}

// PublicKeyFingerprint returns a stable SHA-256 identity for a public key.
func PublicKeyFingerprint(public crypto.PublicKey) (string, error) {
	return publicKeyFingerprint(public)
}

func publicKeyFingerprint(public crypto.PublicKey) (string, error) {
	if isNilValue(public) {
		return "", errors.New("public key is missing")
	}
	if err := validateSignerPublicKey(public); err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", fmt.Errorf("marshal public key %T: %w", public, err)
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("sha256:%x", sum[:]), nil
}

// isNilValue reports whether value is nil, including typed nil pointers and
// typed nil slices that implement crypto.Signer or crypto.PublicKey.
func isNilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// authorityForSigning builds an identity for the pkix signing helpers. The
// certificate subject is used as the display name so errors still identify the
// CA when callers do not have a depot name.
func authorityForSigning(cert *Certificate, key *Key) (*CertificateAuthority, error) {
	name := ""
	if cert != nil {
		if raw, err := cert.GetRawCertificate(); err == nil {
			if raw.Subject.CommonName != "" {
				name = raw.Subject.CommonName
			} else {
				name = raw.Subject.String()
			}
		}
	}
	return NewCertificateAuthority(name, cert, key)
}
