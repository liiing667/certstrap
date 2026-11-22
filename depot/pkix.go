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

package depot

import (
	"crypto"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/square/certstrap/pkix"
)

const (
	crtSuffix     = ".crt"
	csrSuffix     = ".csr"
	privKeySuffix = ".key"
	crlSuffix     = ".crl"
)

// CrtTag returns a tag corresponding to a certificate
func CrtTag(prefix string) *Tag {
	return &Tag{prefix + crtSuffix, LeafPerm}
}

// PrivKeyTag returns a tag corresponding to a private key
func PrivKeyTag(prefix string) *Tag {
	return &Tag{prefix + privKeySuffix, BranchPerm}
}

// CsrTag returns a tag corresponding to a certificate signature request file
func CsrTag(prefix string) *Tag {
	return &Tag{prefix + csrSuffix, LeafPerm}
}

// CrlTag returns a tag corresponding to a certificate revocation list
func CrlTag(prefix string) *Tag {
	return &Tag{prefix + crlSuffix, LeafPerm}
}

// GetNameFromCrtTag returns the host name from a certificate file tag
func GetNameFromCrtTag(tag *Tag) string {
	return getName(tag, crtSuffix)
}

// GetNameFromPrivKeyTag returns the host name from a private key file tag
func GetNameFromPrivKeyTag(tag *Tag) string {
	return getName(tag, privKeySuffix)
}

// GetNameFromCsrTag returns the host name from a certificate request file tag
func GetNameFromCsrTag(tag *Tag) string {
	return getName(tag, csrSuffix)
}

// GetNameFromCrlTag returns the host name from a certificate revocation list file tag
func GetNameFromCrlTag(tag *Tag) string {
	return getName(tag, crlSuffix)
}

// PutCertificate creates a certificate file for a given CA name in the depot
func PutCertificate(d Depot, name string, crt *pkix.Certificate) error {
	b, err := crt.Export()
	if err != nil {
		return err
	}
	return d.Put(CrtTag(name), b)
}

// CheckCertificate checks the depot for existence of a certificate file for a given CA name
func CheckCertificate(d Depot, name string) bool {
	return d.Check(CrtTag(name))
}

// GetCertificate retrieves a certificate file for a given name from the depot
func GetCertificate(d Depot, name string) (crt *pkix.Certificate, err error) {
	b, err := d.Get(CrtTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateFromPEM(b)
}

// GetCertificateAuthority retrieves the CA certificate and private key for a
// given name and verifies that they describe one signing identity. The
// validated identity is returned so callers do not accidentally pair a
// certificate with a later key rotation.
func GetCertificateAuthority(d Depot, name string) (*pkix.CertificateAuthority, error) {
	crt, err := GetCertificate(d, name)
	if err != nil {
		return nil, fmt.Errorf("get CA %q certificate: %w", name, err)
	}
	key, err := GetPrivateKey(d, name)
	if err != nil {
		return nil, fmt.Errorf("get CA %q private key: %w", name, err)
	}
	return pkix.NewCertificateAuthority(name, crt, key)
}

// GetEncryptedCertificateAuthority retrieves an encrypted CA private key and
// its certificate and verifies that they describe one signing identity.
func GetEncryptedCertificateAuthority(d Depot, name string, passphrase []byte) (*pkix.CertificateAuthority, error) {
	crt, err := GetCertificate(d, name)
	if err != nil {
		return nil, fmt.Errorf("get CA %q certificate: %w", name, err)
	}
	key, err := GetEncryptedPrivateKey(d, name, passphrase)
	if err != nil {
		return nil, fmt.Errorf("get encrypted CA %q private key: %w", name, err)
	}
	return pkix.NewCertificateAuthority(name, crt, key)
}

// DeleteCertificate removes a certificate file for a given name from the depot
func DeleteCertificate(d Depot, name string) error {
	return d.Delete(CrtTag(name))
}

// PutCertificateSigningRequest creates a certificate signing request file for a given name and csr in the depot
func PutCertificateSigningRequest(d Depot, name string, csr *pkix.CertificateSigningRequest) error {
	b, err := csr.Export()
	if err != nil {
		return err
	}
	return d.Put(CsrTag(name), b)
}

// CheckCertificateSigningRequest checks the depot for existence of a certificate signing request file for a given host name
func CheckCertificateSigningRequest(d Depot, name string) bool {
	return d.Check(CsrTag(name))
}

// GetCertificateSigningRequest retrieves a certificate signing request file for a given host name from the depot
func GetCertificateSigningRequest(d Depot, name string) (crt *pkix.CertificateSigningRequest, err error) {
	b, err := d.Get(CsrTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateSigningRequestFromPEM(b)
}

// DeleteCertificateSigningRequest removes a certificate signing request file for a given host name from the depot
func DeleteCertificateSigningRequest(d Depot, name string) error {
	return d.Delete(CsrTag(name))
}

// PutPrivateKey creates a private key file for a given name in the depot
func PutPrivateKey(d Depot, name string, key *pkix.Key) error {
	b, err := key.ExportPrivate()
	if err != nil {
		return err
	}
	return d.Put(PrivKeyTag(name), b)
}

// CheckPrivateKey checks the depot for existence of a private key file for a given name
func CheckPrivateKey(d Depot, name string) bool {
	return d.Check(PrivKeyTag(name))
}

// IsEncryptedPrivateKey reports whether the private key stored under name is
// encrypted. Callers use this to distinguish a missing or malformed key from a
// key that can be unlocked with a passphrase.
func IsEncryptedPrivateKey(d Depot, name string) (bool, error) {
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return false, nil
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return true, nil
	}
	for key, value := range block.Headers {
		if strings.EqualFold(key, "Proc-Type") && strings.Contains(strings.ToUpper(value), "ENCRYPTED") {
			return true, nil
		}
	}
	return false, nil
}

// GetPrivateKey retrieves a private key file for a given name from the depot.
// When a certificate with the same name exists, the key must match its public
// key; otherwise the load fails so a rotated key cannot be used with stale
// certificate material.
func GetPrivateKey(d Depot, name string) (key *pkix.Key, err error) {
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return nil, err
	}
	key, err = pkix.NewKeyFromPrivateKeyPEM(b)
	if err != nil {
		return nil, fmt.Errorf("private key %q: %w", name, err)
	}
	if err := checkStoredCertificateIdentity(d, name, key); err != nil {
		return nil, &StoredIdentityError{Err: err}
	}
	return key, nil
}

// PutEncryptedPrivateKey creates an encrypted private key file for a given name in the depot
func PutEncryptedPrivateKey(d Depot, name string, key *pkix.Key, passphrase []byte) error {
	b, err := key.ExportEncryptedPrivate(passphrase)
	if err != nil {
		return err
	}
	return d.Put(PrivKeyTag(name), b)
}

// GetEncryptedPrivateKey retrieves an encrypted private key file for a given
// name from the depot and verifies it against a certificate with the same name
// when one exists.
func GetEncryptedPrivateKey(d Depot, name string, passphrase []byte) (key *pkix.Key, err error) {
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return nil, err
	}
	key, err = pkix.NewKeyFromEncryptedPrivateKeyPEM(b, passphrase)
	if err != nil {
		return nil, fmt.Errorf("private key %q: %w", name, err)
	}
	if err := checkStoredCertificateIdentity(d, name, key); err != nil {
		return nil, &StoredIdentityError{Err: err}
	}
	return key, nil
}

// StoredIdentityError reports that a key was parsed successfully but cannot be
// used with the certificate stored under the same depot name.
type StoredIdentityError struct {
	Err error
}

func (e *StoredIdentityError) Error() string {
	return e.Err.Error()
}

func (e *StoredIdentityError) Unwrap() error {
	return e.Err
}

// StoredIdentityMismatchError reports that a stored certificate and stored
// private key share a name but do not contain the same public key.
type StoredIdentityMismatchError struct {
	Name                   string
	CertificatePublicKeyID string
	PrivateKeyID           string
}

func (e *StoredIdentityMismatchError) Error() string {
	return fmt.Sprintf(
		"certificate %q public key %s does not match private signer public key %s from the stored private key (stage: validate stored identity)",
		e.Name, e.CertificatePublicKeyID, e.PrivateKeyID,
	)
}

// checkStoredCertificateIdentity makes every key reader fail closed when the
// depot already holds a certificate for the same name whose public key differs
// from the private key. A missing certificate is allowed because request-cert
// stores the key before any certificate exists.
func checkStoredCertificateIdentity(d Depot, name string, key *pkix.Key) error {
	if !CheckCertificate(d, name) {
		return nil
	}
	crt, err := GetCertificate(d, name)
	if err != nil {
		return fmt.Errorf("read certificate %q for identity check: %w (stage: validate stored identity)", name, err)
	}
	rawCrt, err := crt.GetRawCertificate()
	if err != nil {
		return fmt.Errorf("parse certificate %q for identity check: %w (stage: validate stored identity)", name, err)
	}

	public := key.Public
	if public == nil {
		signer, ok := key.Private.(crypto.Signer)
		if !ok {
			return fmt.Errorf("private key %q does not implement crypto.Signer (stage: validate stored identity)", name)
		}
		public = signer.Public()
	}
	certificateID, err := pkix.PublicKeyFingerprint(rawCrt.PublicKey)
	if err != nil {
		return fmt.Errorf("fingerprint certificate %q public key: %w (stage: validate stored identity)", name, err)
	}
	privateID, err := pkix.PublicKeyFingerprint(public)
	if err != nil {
		return fmt.Errorf("fingerprint private key %q: %w (stage: validate stored identity)", name, err)
	}
	match, err := pkix.PublicKeysEqual(rawCrt.PublicKey, public)
	if err != nil {
		return fmt.Errorf("compare certificate %q and private key %q: %w (stage: validate stored identity)", name, name, err)
	}
	if !match {
		return &StoredIdentityMismatchError{
			Name:                   name,
			CertificatePublicKeyID: certificateID,
			PrivateKeyID:           privateID,
		}
	}
	return nil
}

// PutCertificateRevocationList creates a CRL file for a given name and ca in the depot
func PutCertificateRevocationList(d Depot, name string, crl *pkix.CertificateRevocationList) error {
	b, err := crl.Export()
	if err != nil {
		return err
	}
	return d.Put(CrlTag(name), b)
}

//GetCertificateRevocationList gets a CRL file for a given name and ca in the depot.
func GetCertificateRevocationList(d Depot, name string) (*pkix.CertificateRevocationList, error) {
	b, err := d.Get(CrlTag(name))
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificateRevocationListFromPEM(b)
}

func getName(tag *Tag, suffix string) string {
	name := strings.TrimSuffix(tag.name, suffix)
	if name == tag.name {
		return ""
	}
	return name
}
