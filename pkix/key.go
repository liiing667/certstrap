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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"go.step.sm/crypto/pemutil"
)

// ErrKeyIdentityMismatch reports that a Key's public and private halves do
// not describe the same key.
var ErrKeyIdentityMismatch = errors.New("key public key does not match private key")

const (
	rsaPrivateKeyPEMBlockType            = "RSA PRIVATE KEY"
	pkcs8PrivateKeyPEMBlockType          = "PRIVATE KEY"
	encryptedPKCS8PrivateKeyPEMBLockType = "ENCRYPTED PRIVATE KEY"
)

// CreateRSAKey creates a new Key using RSA algorithm
func CreateRSAKey(rsaBits int) (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, err
	}

	return NewKey(&priv.PublicKey, priv), nil
}

// CreateECDSAKey creates a new ECDSA key on the given curve
func CreateECDSAKey(c elliptic.Curve) (*Key, error) {
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}

	return NewKey(&priv.PublicKey, priv), nil
}

// CreateEd25519Key creates a new Ed25519 key
func CreateEd25519Key() (*Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return NewKey(priv.Public(), priv), nil
}

// Key contains a public-private keypair
type Key struct {
	Public  crypto.PublicKey
	Private crypto.PrivateKey
}

func NewKeyFromSigner(signer crypto.Signer) *Key {
	if isNilValue(signer) {
		return &Key{Private: signer}
	}
	return &Key{Public: signer.Public(), Private: signer}
}

// NewKey returns a new public-private keypair Key type. If the public half is
// omitted it is derived from the private half when that is safe to do.
func NewKey(pub crypto.PublicKey, priv crypto.PrivateKey) *Key {
	if isNilValue(pub) && !isNilValue(priv) {
		if signer, ok := priv.(crypto.Signer); ok {
			switch ed := priv.(type) {
			case ed25519.PrivateKey:
				if len(ed) == ed25519.PrivateKeySize {
					pub = signer.Public()
				}
			case *ed25519.PrivateKey:
				if ed != nil && len(*ed) == ed25519.PrivateKeySize {
					pub = signer.Public()
				}
			default:
				pub = signer.Public()
			}
		}
	}
	return &Key{Public: pub, Private: priv}
}

// Signer returns the private key as a crypto.Signer. It fails closed for a
// missing key or an Ed25519 private key with an invalid length instead of
// letting a malformed key panic when its public half is derived.
func (k *Key) Signer() (crypto.Signer, error) {
	if k == nil || isNilValue(k.Private) {
		return nil, errors.New("private key is missing")
	}
	switch ed := k.Private.(type) {
	case ed25519.PrivateKey:
		if len(ed) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("Ed25519 private key has invalid length %d, want %d", len(ed), ed25519.PrivateKeySize)
		}
	case *ed25519.PrivateKey:
		if ed == nil || len(*ed) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("Ed25519 private key has invalid length, want %d", ed25519.PrivateKeySize)
		}
	}
	signer, ok := k.Private.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key type %T does not implement crypto.Signer", k.Private)
	}
	return signer, nil
}

// PublicKey returns the public key belonging to the private key. When both
// halves are present they must agree; a Key is never allowed to describe one
// algorithm publicly while signing with another.
func (k *Key) PublicKey() (crypto.PublicKey, error) {
	signer, err := k.Signer()
	if err != nil {
		return nil, err
	}
	derived := signer.Public()
	if err := validatePublicKey(derived); err != nil {
		return nil, fmt.Errorf("private key public half: %w", err)
	}
	if isNilValue(k.Public) {
		return derived, nil
	}
	if err := validatePublicKey(k.Public); err != nil {
		return nil, fmt.Errorf("key public half: %w", err)
	}
	match, err := PublicKeysEqual(k.Public, derived)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, ErrKeyIdentityMismatch
	}
	return k.Public, nil
}

// Validate verifies that the key describes one usable private/public pair and
// that the private half is structurally sound. All certificate and CRL
// creation goes through this check so a key cannot be exported or used with an
// unrelated certificate.
func (k *Key) Validate() error {
	if _, err := k.Signer(); err != nil {
		return err
	}
	switch priv := k.Private.(type) {
	case *rsa.PrivateKey:
		if err := priv.Validate(); err != nil {
			return fmt.Errorf("invalid RSA private key: %w", err)
		}
	case *ecdsa.PrivateKey:
		if priv.Curve == nil || priv.D == nil || priv.X == nil || priv.Y == nil {
			return errors.New("invalid ECDSA private key: missing curve or point")
		}
		// Sign and verify a fixed digest to prove the private scalar and public
		// point belong together without relying on the deprecated low-level
		// elliptic.Curve operations.
		digest := sha256.Sum256([]byte("certstrap ECDSA key validation"))
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			return fmt.Errorf("invalid ECDSA private key: %w", err)
		}
		if !ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig) {
			return errors.New("invalid ECDSA private key: public point does not match private scalar")
		}
	case ed25519.PrivateKey:
		if len(priv) != ed25519.PrivateKeySize {
			return fmt.Errorf("invalid Ed25519 private key length %d, want %d", len(priv), ed25519.PrivateKeySize)
		}
	case *ed25519.PrivateKey:
		if priv == nil || len(*priv) != ed25519.PrivateKeySize {
			return fmt.Errorf("invalid Ed25519 private key length, want %d", ed25519.PrivateKeySize)
		}
	}
	pub, err := k.PublicKey()
	if err != nil {
		return err
	}
	return validatePublicKey(pub)
}

// exportEvidence describes the public identity available on a key for export
// failures. It deliberately does not expose private key material.
func (k *Key) exportEvidence() string {
	fingerprint := "unknown"
	algorithm := "unknown"
	if k != nil {
		if value, err := k.Fingerprint(); err == nil {
			fingerprint = value
		} else if k.Public != nil {
			if value, err := PublicKeyFingerprint(k.Public); err == nil {
				fingerprint = value
			}
		}
		if value, err := k.Algorithm(); err == nil {
			algorithm = value
		} else if k.Public != nil {
			if value, err := PublicKeyAlgorithm(k.Public); err == nil {
				algorithm = value
			}
		}
	}
	return fmt.Sprintf("key_fingerprint=%s algorithm=%s", fingerprint, algorithm)
}

// Fingerprint returns a stable SHA-256 identity for the key's public half.
func (k *Key) Fingerprint() (string, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return "", err
	}
	return PublicKeyFingerprint(pub)
}

// Algorithm returns the algorithm of the key's validated public half.
func (k *Key) Algorithm() (string, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return "", err
	}
	return PublicKeyAlgorithm(pub)
}

// MatchesPublicKey reports whether pub is the key's validated public half.
func (k *Key) MatchesPublicKey(pub crypto.PublicKey) (bool, error) {
	own, err := k.PublicKey()
	if err != nil {
		return false, err
	}
	return PublicKeysEqual(own, pub)
}

// PublicKeyFingerprint returns a stable SHA-256 identity for a public key.
func PublicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	if err := validatePublicKey(pub); err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key %T: %w", pub, err)
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("sha256:%x", sum[:]), nil
}

// PublicKeysEqual reports whether two public keys have the same PKIX encoding.
func PublicKeysEqual(a, b crypto.PublicKey) (bool, error) {
	if isNilValue(a) || isNilValue(b) {
		return false, errors.New("public key is missing")
	}
	if err := validatePublicKey(a); err != nil {
		return false, err
	}
	if err := validatePublicKey(b); err != nil {
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

// PublicKeyAlgorithm returns the key algorithm for a supported public key.
func PublicKeyAlgorithm(pub crypto.PublicKey) (string, error) {
	if isNilValue(pub) {
		return "", errors.New("public key is missing")
	}
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RSA", nil
	case *ecdsa.PublicKey:
		return "ECDSA", nil
	case ed25519.PublicKey:
		return "Ed25519", nil
	default:
		return "", fmt.Errorf("unsupported public key type %T", pub)
	}
}

func validatePublicKey(pub crypto.PublicKey) error {
	if isNilValue(pub) {
		return errors.New("public key is missing")
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		if pub.N == nil || pub.N.Sign() <= 0 || pub.E < 2 {
			return errors.New("invalid RSA public key")
		}
	case *ecdsa.PublicKey:
		if pub.Curve == nil || pub.X == nil || pub.Y == nil {
			return errors.New("invalid ECDSA public key: missing curve or point")
		}
		if _, err := x509.MarshalPKIXPublicKey(pub); err != nil {
			return fmt.Errorf("invalid ECDSA public key: %w", err)
		}
	case ed25519.PublicKey:
		if len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid Ed25519 public key length %d, want %d", len(pub), ed25519.PublicKeySize)
		}
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
	return nil
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

// NewKeyFromPrivateKeyPEM inits Key from PEM-format rsa private key bytes
func NewKeyFromPrivateKeyPEM(data []byte) (*Key, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	var signer crypto.Signer
	switch pemBlock.Type {
	case rsaPrivateKeyPEMBlockType:
		priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		signer = priv
	case pkcs8PrivateKeyPEMBlockType:
		priv, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		parsed, ok := priv.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported private key type %T", priv)
		}
		signer = parsed
	default:
		return nil, fmt.Errorf("unknown PEM block type %q", pemBlock.Type)
	}
	return NewKeyFromSigner(signer), nil
}

// NewKeyFromEncryptedPrivateKeyPEM inits Key from encrypted PEM-format private key bytes
func NewKeyFromEncryptedPrivateKeyPEM(data []byte, password []byte) (*Key, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	var signer crypto.Signer
	switch pemBlock.Type {
	case rsaPrivateKeyPEMBlockType:
		b, err := x509.DecryptPEMBlock(pemBlock, password)
		if err != nil {
			return nil, err
		}
		priv, err := x509.ParsePKCS1PrivateKey(b)
		if err != nil {
			return nil, err
		}
		signer = priv
	case encryptedPKCS8PrivateKeyPEMBLockType:
		b, err := pemutil.DecryptPKCS8PrivateKey(pemBlock.Bytes, password)
		if err != nil {
			return nil, err
		}
		priv, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			return nil, err
		}
		parsed, ok := priv.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported private key type %T", priv)
		}
		signer = parsed
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", pemBlock.Type)
	}

	return NewKeyFromSigner(signer), nil
}

// ExportPrivate exports PEM-format private key. RSA keys are exported
// as PKCS#1, ECDSA and Ed25519 keys are exported as PKCS#8.
func (k *Key) ExportPrivate() ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("private key export rejected (%s passphrase_stage=plaintext): %w", k.exportEvidence(), err)
	}
	var privPEMBlock *pem.Block
	switch priv := k.Private.(type) {
	case *rsa.PrivateKey:
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		privPEMBlock = &pem.Block{
			Type:  rsaPrivateKeyPEMBlockType,
			Bytes: privBytes,
		}
	case *ecdsa.PrivateKey, ed25519.PrivateKey:
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		privPEMBlock = &pem.Block{
			Type:  pkcs8PrivateKeyPEMBlockType,
			Bytes: privBytes,
		}
	case *ed25519.PrivateKey:
		privBytes, err := x509.MarshalPKCS8PrivateKey(*priv)
		if err != nil {
			return nil, err
		}
		privPEMBlock = &pem.Block{
			Type:  pkcs8PrivateKeyPEMBlockType,
			Bytes: privBytes,
		}
	default:
		return nil, fmt.Errorf("unsupported key type %T", k.Private)
	}

	return pem.EncodeToMemory(privPEMBlock), nil
}

// ExportEncryptedPrivate exports encrypted PEM-format private key
func (k *Key) ExportEncryptedPrivate(password []byte) ([]byte, error) {
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("encrypted private key export rejected (%s passphrase_stage=encrypt): %w", k.exportEvidence(), err)
	}
	var privPEMBlock *pem.Block
	switch priv := k.Private.(type) {
	case *rsa.PrivateKey:
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		block, err := x509.EncryptPEMBlock(rand.Reader, rsaPrivateKeyPEMBlockType, privBytes, password, x509.PEMCipher3DES)
		if err != nil {
			return nil, err
		}
		privPEMBlock = block
	case *ecdsa.PrivateKey, ed25519.PrivateKey:
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		block, err := pemutil.EncryptPKCS8PrivateKey(rand.Reader, privBytes, password, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
		privPEMBlock = block
	case *ed25519.PrivateKey:
		privBytes, err := x509.MarshalPKCS8PrivateKey(*priv)
		if err != nil {
			return nil, err
		}
		block, err := pemutil.EncryptPKCS8PrivateKey(rand.Reader, privBytes, password, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
		privPEMBlock = block
	default:
		return nil, fmt.Errorf("unsupported key type %T", k.Private)
	}

	return pem.EncodeToMemory(privPEMBlock), nil
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

// subjectPublicKeyInfo reflects the ASN.1 structure of a PKIX public key.
type subjectPublicKeyInfo struct {
	Algorithm        asn1.RawValue
	SubjectPublicKey asn1.BitString
}

// ecdsaPublicKeyBytes returns the uncompressed point encoding of pub, as found
// in the subjectPublicKey BIT STRING of its PKIX encoding. Unlike
// ecdsa.PublicKey.ECDH, this supports P-224.
func ecdsaPublicKeyBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	return spki.SubjectPublicKey.Bytes, nil
}

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// Id is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
// ECDSA keys must use a named curve supported by x509.MarshalPKIXPublicKey.
func GenerateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	case *ecdsa.PublicKey:
		pubBytes, err = ecdsaPublicKeyBytes(pub)
		if err != nil {
			return nil, err
		}
	case ed25519.PublicKey:
		pubBytes = pub
	default:
		return nil, fmt.Errorf("unsupported key type %T", pub)
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}
