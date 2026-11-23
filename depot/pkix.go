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
	"encoding/pem"
	"errors"
	"fmt"
	"os"
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

// StoredIdentityError reports that a stored key was parsed successfully but
// cannot be used with the certificate stored under the same depot name.
type StoredIdentityError struct {
	Err error
}

func (e *StoredIdentityError) Error() string {
	return e.Err.Error()
}

func (e *StoredIdentityError) Unwrap() error {
	return e.Err
}

// keyIdentityEvidence returns the identity and policy fields that key
// migration, encryption and consumer failures must retain. It deliberately
// includes the public-key fingerprint, algorithm, passphrase stage and the
// permission mode expected for key files.
func keyIdentityEvidence(key *pkix.Key, stage string) string {
	fingerprint := "unknown"
	algorithm := "unknown"
	if key != nil {
		if value, err := key.Fingerprint(); err == nil {
			fingerprint = value
		} else if key.Public != nil {
			if value, err := pkix.PublicKeyFingerprint(key.Public); err == nil {
				fingerprint = value
			}
		}
		if value, err := key.Algorithm(); err == nil {
			algorithm = value
		} else if key.Public != nil {
			if value, err := pkix.PublicKeyAlgorithm(key.Public); err == nil {
				algorithm = value
			}
		}
	}
	return fmt.Sprintf("key_fingerprint=%s algorithm=%s passphrase_stage=%s operation=%s permissions=%#o", fingerprint, algorithm, passphraseStage(stage), stage, BranchPerm)
}

func passphraseStage(stage string) string {
	switch {
	case strings.Contains(stage, "decrypt"):
		return "decrypt"
	case strings.Contains(stage, "encrypt"):
		return "encrypt"
	default:
		return "plaintext"
	}
}

// IsEncryptedPrivateKey reports whether the private key stored under name is
// encrypted. Callers use this to distinguish a malformed/unencrypted key from
// a key that can be unlocked with a passphrase, so a mismatch is not hidden by
// an unnecessary passphrase prompt.
func IsEncryptedPrivateKey(d Depot, name string) (bool, error) {
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return false, nil
	}
	return isEncryptedPEMBlock(block), nil
}

func isEncryptedPEMBlock(block *pem.Block) bool {
	if block == nil {
		return false
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return true
	}
	for key, value := range block.Headers {
		if strings.EqualFold(key, "Proc-Type") && strings.Contains(strings.ToUpper(value), "ENCRYPTED") {
			return true
		}
	}
	return false
}

// depotFileExists reports whether a final file exists even when its permission
// mode is too lax for a normal Get. Replacement still has to be able to repair
// such a file rather than being stuck behind the reader permission check.
func depotFileExists(d *FileDepot, tag *Tag) bool {
	if d == nil || tag == nil {
		return false
	}
	_, err := os.Stat(d.path(tag.name))
	return err == nil
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
		return fmt.Errorf("read certificate %q for identity check (%s): %w", name, keyIdentityEvidence(key, "identity-cert-read"), err)
	}
	if err := crt.ValidateKey(key); err != nil {
		return &StoredIdentityError{Err: fmt.Errorf("certificate %q does not match private key (%s): %w", name, keyIdentityEvidence(key, "consumer-check"), err)}
	}
	return nil
}

// checkStoredKeyIdentity validates a certificate about to be stored against a
// pre-existing unencrypted key. An encrypted key cannot be compared without its
// passphrase; key-first writes and all readers still enforce identity.
func checkStoredKeyIdentity(d Depot, name string, crt *pkix.Certificate) error {
	if !CheckPrivateKey(d, name) {
		return nil
	}
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return fmt.Errorf("read stored private key %q for identity check (%s): %w", name, keyIdentityEvidence(nil, "stored-key-read"), err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("private key %q is not PEM encoded", name)
	}
	if isEncryptedPEMBlock(block) {
		return nil
	}
	key, err := pkix.NewKeyFromPrivateKeyPEM(b)
	if err != nil {
		return fmt.Errorf("read private key %q for identity check (%s): %w", name, keyIdentityEvidence(nil, "stored-key-parse"), err)
	}
	if err := crt.ValidateKey(key); err != nil {
		return &StoredIdentityError{Err: fmt.Errorf("certificate %q does not match stored private key (%s): %w", name, keyIdentityEvidence(key, "certificate-write"), err)}
	}
	return nil
}

// errEncryptedKeyNotVerifiable is returned when a certificate replacement is
// requested while an encrypted key exists and cannot be checked without its
// passphrase. Callers that want to rotate encrypted key material must replace
// the key and certificate together.
var errEncryptedKeyNotVerifiable = errors.New("stored private key is encrypted; certificate replacement requires matching key material")

func checkStoredKeyIdentityForReplace(d Depot, name string, crt *pkix.Certificate) error {
	if !CheckPrivateKey(d, name) {
		return nil
	}
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return fmt.Errorf("read stored private key %q for identity check (%s): %w", name, keyIdentityEvidence(nil, "stored-key-read"), err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("private key %q is not PEM encoded", name)
	}
	if isEncryptedPEMBlock(block) {
		return &StoredIdentityError{Err: fmt.Errorf("%w (%s)", errEncryptedKeyNotVerifiable, keyIdentityEvidence(nil, "encrypted-key-replacement"))}
	}
	return checkStoredKeyIdentity(d, name, crt)
}

// PutCertificate creates a certificate file for a given CA name in the depot
func PutCertificate(d Depot, name string, crt *pkix.Certificate) error {
	if crt == nil {
		return errors.New("certificate is nil")
	}
	if CheckCertificate(d, name) {
		if err := checkStoredKeyIdentityForReplace(d, name, crt); err != nil {
			return err
		}
	} else if err := checkStoredKeyIdentity(d, name, crt); err != nil {
		return err
	}
	b, err := crt.Export()
	if err != nil {
		return err
	}
	return replaceTag(d, CrtTag(name), b)
}

// PutCertificateInTxn stages creation of a certificate file into t. The file
// is only published when the transaction commits.
func PutCertificateInTxn(t *Txn, name string, crt *pkix.Certificate) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if crt == nil {
		return errors.New("certificate is nil")
	}
	if err := checkStoredKeyIdentity(t.depot, name, crt); err != nil {
		return err
	}
	b, err := crt.Export()
	if err != nil {
		return err
	}
	return t.Put(CrtTag(name), b)
}

// ReplaceCertificate atomically replaces an existing certificate. If the name
// already has a private key, the certificate must match it.
func ReplaceCertificate(d Depot, name string, crt *pkix.Certificate) error {
	if crt == nil {
		return errors.New("certificate is nil")
	}
	if err := checkStoredKeyIdentityForReplace(d, name, crt); err != nil {
		return err
	}
	b, err := crt.Export()
	if err != nil {
		return err
	}
	return replaceTag(d, CrtTag(name), b)
}

// ReplaceCertificateInTxn stages replacement of an existing certificate file.
func ReplaceCertificateInTxn(t *Txn, name string, crt *pkix.Certificate) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if crt == nil {
		return errors.New("certificate is nil")
	}
	if err := checkStoredKeyIdentityForReplace(t.depot, name, crt); err != nil {
		return err
	}
	b, err := crt.Export()
	if err != nil {
		return err
	}
	return t.Replace(CrtTag(name), b)
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

// DeleteCertificate removes a certificate file for a given name from the depot
func DeleteCertificate(d Depot, name string) error {
	return d.Delete(CrtTag(name))
}

// PutCertificateSigningRequest creates a certificate signing request file for a given name and csr in the depot
func PutCertificateSigningRequest(d Depot, name string, csr *pkix.CertificateSigningRequest) error {
	if csr == nil {
		return errors.New("certificate signing request is nil")
	}
	b, err := csr.Export()
	if err != nil {
		return err
	}
	return replaceTag(d, CsrTag(name), b)
}

// PutCertificateSigningRequestInTxn stages creation of a CSR file into t.
func PutCertificateSigningRequestInTxn(t *Txn, name string, csr *pkix.CertificateSigningRequest) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if csr == nil {
		return errors.New("certificate signing request is nil")
	}
	b, err := csr.Export()
	if err != nil {
		return err
	}
	return t.Put(CsrTag(name), b)
}

// PutOrReplaceCertificateSigningRequestInTxn stages a CSR generation,
// replacing an existing CSR atomically when one is present. This lets an
// interrupted request-cert retry replace its stale half without first deleting
// it.
func PutOrReplaceCertificateSigningRequestInTxn(t *Txn, name string, csr *pkix.CertificateSigningRequest) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if csr == nil {
		return errors.New("certificate signing request is nil")
	}
	b, err := csr.Export()
	if err != nil {
		return err
	}
	if depotFileExists(t.depot, CsrTag(name)) {
		return t.Replace(CsrTag(name), b)
	}
	return t.Put(CsrTag(name), b)
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

// PutPrivateKey creates a private key file for a given name in the depot. A
// key that does not match an already stored certificate is rejected so a key
// rotation cannot silently change the algorithm behind a certificate.
func PutPrivateKey(d Depot, name string, key *pkix.Key) error {
	if err := key.Validate(); err != nil {
		return fmt.Errorf("private key validation failed (%s): %w", keyIdentityEvidence(key, "private-key-validate"), err)
	}
	if err := checkStoredCertificateIdentity(d, name, key); err != nil {
		return fmt.Errorf("private key write rejected (%s): %w", keyIdentityEvidence(key, "private-key-write"), err)
	}
	b, err := key.ExportPrivate()
	if err != nil {
		return fmt.Errorf("plaintext private key export failed (%s): %w", keyIdentityEvidence(key, "export-plaintext"), err)
	}
	return replaceTag(d, PrivKeyTag(name), b)
}

// PutPrivateKeyInTxn stages creation of a private key file into t.
func PutPrivateKeyInTxn(t *Txn, name string, key *pkix.Key) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if err := key.Validate(); err != nil {
		return fmt.Errorf("private key validation failed (%s): %w", keyIdentityEvidence(key, "private-key-validate"), err)
	}
	if err := checkStoredCertificateIdentity(t.depot, name, key); err != nil {
		return fmt.Errorf("private key write rejected (%s): %w", keyIdentityEvidence(key, "private-key-write"), err)
	}
	b, err := key.ExportPrivate()
	if err != nil {
		return fmt.Errorf("plaintext private key export failed (%s): %w", keyIdentityEvidence(key, "export-plaintext"), err)
	}
	return t.Put(PrivKeyTag(name), b)
}

// ReplacePrivateKey atomically replaces an existing private key. The key must
// still match the certificate stored under the same name.
func ReplacePrivateKey(d Depot, name string, key *pkix.Key) error {
	if err := key.Validate(); err != nil {
		return fmt.Errorf("private key validation failed (%s): %w", keyIdentityEvidence(key, "private-key-validate"), err)
	}
	if err := checkStoredCertificateIdentity(d, name, key); err != nil {
		return fmt.Errorf("private key replacement rejected (%s): %w", keyIdentityEvidence(key, "private-key-replace"), err)
	}
	b, err := key.ExportPrivate()
	if err != nil {
		return fmt.Errorf("plaintext private key export failed (%s): %w", keyIdentityEvidence(key, "export-plaintext"), err)
	}
	return replaceTag(d, PrivKeyTag(name), b)
}

// ReplacePrivateKeyInTxn stages replacement of an existing private key.
func ReplacePrivateKeyInTxn(t *Txn, name string, key *pkix.Key) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if err := key.Validate(); err != nil {
		return fmt.Errorf("private key validation failed (%s): %w", keyIdentityEvidence(key, "private-key-validate"), err)
	}
	if err := checkStoredCertificateIdentity(t.depot, name, key); err != nil {
		return fmt.Errorf("private key replacement rejected (%s): %w", keyIdentityEvidence(key, "private-key-replace"), err)
	}
	b, err := key.ExportPrivate()
	if err != nil {
		return fmt.Errorf("plaintext private key export failed (%s): %w", keyIdentityEvidence(key, "export-plaintext"), err)
	}
	return t.Replace(PrivKeyTag(name), b)
}

// PutOrReplacePrivateKeyInTxn stages a private key generation, replacing an
// existing key atomically when one is present. This is the retry-safe path for
// passphrase or algorithm changes: the previous key survives an export failure
// and is only replaced by a complete, identity-checked new key.
func PutOrReplacePrivateKeyInTxn(t *Txn, name string, key *pkix.Key) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if depotFileExists(t.depot, PrivKeyTag(name)) {
		return ReplacePrivateKeyInTxn(t, name, key)
	}
	return PutPrivateKeyInTxn(t, name, key)
}

// PutKeyPairInTxn stages a matching private key and certificate as one
// generation. The key is deliberately written before the certificate so a
// visible certificate always has its key in the same transaction. A non-empty
// passphrase stores the key encrypted; an empty passphrase stores it in the
// historical unencrypted PEM form.
func PutKeyPairInTxn(t *Txn, name string, key *pkix.Key, crt *pkix.Certificate, passphrase []byte) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if crt == nil {
		return errors.New("certificate is nil")
	}
	if err := crt.ValidateKey(key); err != nil {
		return fmt.Errorf("key/certificate identity check failed (%s): %w", keyIdentityEvidence(key, "migration-identity"), err)
	}
	var keyBytes []byte
	var err error
	stage := "migration-plaintext"
	if len(passphrase) > 0 {
		stage = "migration-encrypted"
		keyBytes, err = key.ExportEncryptedPrivate(passphrase)
	} else {
		keyBytes, err = key.ExportPrivate()
	}
	if err != nil {
		return fmt.Errorf("private key export failed (%s): %w", keyIdentityEvidence(key, stage), err)
	}
	crtBytes, err := crt.Export()
	if err != nil {
		return err
	}
	if depotFileExists(t.depot, PrivKeyTag(name)) {
		if err := t.Replace(PrivKeyTag(name), keyBytes); err != nil {
			return err
		}
	} else if err := t.Put(PrivKeyTag(name), keyBytes); err != nil {
		return err
	}
	if depotFileExists(t.depot, CrtTag(name)) {
		return t.Replace(CrtTag(name), crtBytes)
	}
	return t.Put(CrtTag(name), crtBytes)
}

// ReplaceKeyPair atomically replaces an existing key/certificate generation.
// The key and certificate must match. A non-empty passphrase stores the key
// encrypted.
func ReplaceKeyPair(d Depot, name string, key *pkix.Key, crt *pkix.Certificate, passphrase []byte) error {
	if crt == nil {
		return errors.New("certificate is nil")
	}
	if err := crt.ValidateKey(key); err != nil {
		return fmt.Errorf("key/certificate identity check failed (%s): %w", keyIdentityEvidence(key, "migration-identity"), err)
	}
	var keyBytes []byte
	var err error
	stage := "migration-plaintext"
	if len(passphrase) > 0 {
		stage = "migration-encrypted"
		keyBytes, err = key.ExportEncryptedPrivate(passphrase)
	} else {
		keyBytes, err = key.ExportPrivate()
	}
	if err != nil {
		return fmt.Errorf("private key export failed (%s): %w", keyIdentityEvidence(key, stage), err)
	}
	crtBytes, err := crt.Export()
	if err != nil {
		return err
	}
	if fd, ok := d.(*FileDepot); ok {
		txn := NewTxn(fd)
		if depotFileExists(fd, PrivKeyTag(name)) {
			if err := txn.Replace(PrivKeyTag(name), keyBytes); err != nil {
				return err
			}
		} else if err := txn.Put(PrivKeyTag(name), keyBytes); err != nil {
			return err
		}
		if depotFileExists(fd, CrtTag(name)) {
			if err := txn.Replace(CrtTag(name), crtBytes); err != nil {
				return err
			}
		} else if err := txn.Put(CrtTag(name), crtBytes); err != nil {
			return err
		}
		return txn.Commit()
	}
	previousKey, keyErr := d.Get(PrivKeyTag(name))
	if err := replaceTag(d, PrivKeyTag(name), keyBytes); err != nil {
		return err
	}
	if err := replaceTag(d, CrtTag(name), crtBytes); err != nil {
		if keyErr == nil {
			_ = replaceTag(d, PrivKeyTag(name), previousKey)
		} else {
			_ = d.Delete(PrivKeyTag(name))
		}
		return err
	}
	return nil
}

// PutKeyPair stores a matching key and certificate as one generation,
// creating or replacing both files atomically where the depot supports it.
func PutKeyPair(d Depot, name string, key *pkix.Key, crt *pkix.Certificate, passphrase []byte) error {
	return ReplaceKeyPair(d, name, key, crt, passphrase)
}

// MigrateKeyPair is an alias for ReplaceKeyPair used by migration callers.
func MigrateKeyPair(d Depot, name string, key *pkix.Key, crt *pkix.Certificate, passphrase []byte) error {
	return ReplaceKeyPair(d, name, key, crt, passphrase)
}

// CheckPrivateKey checks the depot for existence of a private key file for a given name
func CheckPrivateKey(d Depot, name string) bool {
	return d.Check(PrivKeyTag(name))
}

// GetPrivateKey retrieves a private key file for a given name from the depot.
// When a certificate with the same name exists, the key must match its public
// key; otherwise the load fails so rotated key material cannot be used with a
// stale certificate.
func GetPrivateKey(d Depot, name string) (key *pkix.Key, err error) {
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return nil, fmt.Errorf("private key read failed (%s): %w", keyIdentityEvidence(nil, "consumer-read"), err)
	}
	key, err = pkix.NewKeyFromPrivateKeyPEM(b)
	if err != nil {
		return nil, fmt.Errorf("private key %q parse failed (%s): %w", name, keyIdentityEvidence(nil, "consumer-parse"), err)
	}
	if err := checkStoredCertificateIdentity(d, name, key); err != nil {
		return nil, err
	}
	return key, nil
}

// PutEncryptedPrivateKey creates an encrypted private key file for a given name in the depot
func PutEncryptedPrivateKey(d Depot, name string, key *pkix.Key, passphrase []byte) error {
	if err := key.Validate(); err != nil {
		return fmt.Errorf("encrypted private key validation failed (%s): %w", keyIdentityEvidence(key, "encrypted-private-key-validate"), err)
	}
	if err := checkStoredCertificateIdentity(d, name, key); err != nil {
		return fmt.Errorf("encrypted private key write rejected (%s): %w", keyIdentityEvidence(key, "encrypted-private-key-write"), err)
	}
	b, err := key.ExportEncryptedPrivate(passphrase)
	if err != nil {
		return fmt.Errorf("encrypted private key export failed (%s): %w", keyIdentityEvidence(key, "export-encrypted"), err)
	}
	return replaceTag(d, PrivKeyTag(name), b)
}

// PutEncryptedPrivateKeyInTxn stages creation of an encrypted private key file into t.
func PutEncryptedPrivateKeyInTxn(t *Txn, name string, key *pkix.Key, passphrase []byte) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if err := key.Validate(); err != nil {
		return fmt.Errorf("encrypted private key validation failed (%s): %w", keyIdentityEvidence(key, "encrypted-private-key-validate"), err)
	}
	if err := checkStoredCertificateIdentity(t.depot, name, key); err != nil {
		return fmt.Errorf("encrypted private key write rejected (%s): %w", keyIdentityEvidence(key, "encrypted-private-key-write"), err)
	}
	b, err := key.ExportEncryptedPrivate(passphrase)
	if err != nil {
		return fmt.Errorf("encrypted private key export failed (%s): %w", keyIdentityEvidence(key, "export-encrypted"), err)
	}
	return t.Put(PrivKeyTag(name), b)
}

// ReplaceEncryptedPrivateKey atomically replaces an existing encrypted private
// key. The key must still match the certificate stored under the same name.
func ReplaceEncryptedPrivateKey(d Depot, name string, key *pkix.Key, passphrase []byte) error {
	if err := key.Validate(); err != nil {
		return fmt.Errorf("encrypted private key validation failed (%s): %w", keyIdentityEvidence(key, "encrypted-private-key-validate"), err)
	}
	if err := checkStoredCertificateIdentity(d, name, key); err != nil {
		return fmt.Errorf("encrypted private key replacement rejected (%s): %w", keyIdentityEvidence(key, "encrypted-private-key-replace"), err)
	}
	b, err := key.ExportEncryptedPrivate(passphrase)
	if err != nil {
		return fmt.Errorf("encrypted private key export failed (%s): %w", keyIdentityEvidence(key, "export-encrypted"), err)
	}
	return replaceTag(d, PrivKeyTag(name), b)
}

// ReplaceEncryptedPrivateKeyInTxn stages replacement of an encrypted private key.
func ReplaceEncryptedPrivateKeyInTxn(t *Txn, name string, key *pkix.Key, passphrase []byte) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if err := key.Validate(); err != nil {
		return fmt.Errorf("encrypted private key validation failed (%s): %w", keyIdentityEvidence(key, "encrypted-private-key-validate"), err)
	}
	if err := checkStoredCertificateIdentity(t.depot, name, key); err != nil {
		return fmt.Errorf("encrypted private key replacement rejected (%s): %w", keyIdentityEvidence(key, "encrypted-private-key-replace"), err)
	}
	b, err := key.ExportEncryptedPrivate(passphrase)
	if err != nil {
		return fmt.Errorf("encrypted private key export failed (%s): %w", keyIdentityEvidence(key, "export-encrypted"), err)
	}
	return t.Replace(PrivKeyTag(name), b)
}

// PutOrReplaceEncryptedPrivateKeyInTxn stages an encrypted key generation,
// replacing an existing key atomically when present. A failed export never
// touches the previous key.
func PutOrReplaceEncryptedPrivateKeyInTxn(t *Txn, name string, key *pkix.Key, passphrase []byte) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if depotFileExists(t.depot, PrivKeyTag(name)) {
		return ReplaceEncryptedPrivateKeyInTxn(t, name, key, passphrase)
	}
	return PutEncryptedPrivateKeyInTxn(t, name, key, passphrase)
}

// GetEncryptedPrivateKey retrieves an encrypted private key file for a given
// name from the depot and verifies it against a certificate with the same name
// when one exists.
func GetEncryptedPrivateKey(d Depot, name string, passphrase []byte) (key *pkix.Key, err error) {
	b, err := d.Get(PrivKeyTag(name))
	if err != nil {
		return nil, fmt.Errorf("encrypted private key read failed (%s): %w", keyIdentityEvidence(nil, "consumer-read-encrypted"), err)
	}
	key, err = pkix.NewKeyFromEncryptedPrivateKeyPEM(b, passphrase)
	if err != nil {
		return nil, fmt.Errorf("private key %q decryption failed (%s): %w", name, keyIdentityEvidence(nil, "consumer-decrypt"), err)
	}
	if err := checkStoredCertificateIdentity(d, name, key); err != nil {
		return nil, err
	}
	return key, nil
}

// PutCertificateRevocationList creates or replaces a CRL file for a given name
// and ca in the depot. Replacement is atomic for depots that support it, so a
// failed write leaves the previous complete CRL intact.
func PutCertificateRevocationList(d Depot, name string, crl *pkix.CertificateRevocationList) error {
	if crl == nil {
		return errors.New("certificate revocation list is nil")
	}
	b, err := crl.Export()
	if err != nil {
		return err
	}
	return replaceTag(d, CrlTag(name), b)
}

// ReplaceCertificateRevocationList creates or atomically replaces a CRL file.
func ReplaceCertificateRevocationList(d Depot, name string, crl *pkix.CertificateRevocationList) error {
	return PutCertificateRevocationList(d, name, crl)
}

// PutCertificateRevocationListInTxn stages creation of a CRL file into t.
func PutCertificateRevocationListInTxn(t *Txn, name string, crl *pkix.CertificateRevocationList) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if crl == nil {
		return errors.New("certificate revocation list is nil")
	}
	b, err := crl.Export()
	if err != nil {
		return err
	}
	return t.Put(CrlTag(name), b)
}

// ReplaceCertificateRevocationListInTxn stages replacement of a CRL file.
func ReplaceCertificateRevocationListInTxn(t *Txn, name string, crl *pkix.CertificateRevocationList) error {
	if t == nil || t.depot == nil {
		return errors.New("transaction has no depot")
	}
	if crl == nil {
		return errors.New("certificate revocation list is nil")
	}
	b, err := crl.Export()
	if err != nil {
		return err
	}
	return t.Replace(CrlTag(name), b)
}

// GetCertificateRevocationList gets a CRL file for a given name and ca in the depot.
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
