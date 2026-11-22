/*-
 * Copyright 2015 Square Inc.
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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

// requestGenerationOID identifies the non-critical CSR extension that binds a
// request's public key, private-key location and private-key bytes together.
// The extension is covered by the CSR signature.
var requestGenerationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1, 1}

// requestGeneration describes the material produced by one request-cert
// invocation. Sign uses it to make sure it consumes a CSR and the private key
// from that same invocation instead of pairing files left behind by different
// attempts.
type requestGeneration struct {
	Version   int    `json:"version"`
	ID        string `json:"id"`
	PublicKey []byte `json:"public_key"`
	KeyPath   string `json:"key_path,omitempty"`
	KeyDigest []byte `json:"key_digest"`
}

func newRequestGeneration(key *pkix.Key, keyPath string, keyBytes []byte) (requestGeneration, x509pkix.Extension, error) {
	var generation requestGeneration

	publicKey, err := x509.MarshalPKIXPublicKey(key.Public)
	if err != nil {
		return generation, x509pkix.Extension{}, err
	}

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return generation, x509pkix.Extension{}, err
	}

	digest := sha256.Sum256(keyBytes)
	generation = requestGeneration{
		Version:   1,
		ID:        hex.EncodeToString(id),
		PublicKey: publicKey,
		KeyPath:   keyPath,
		KeyDigest: digest[:],
	}

	jsonValue, err := json.Marshal(generation)
	if err != nil {
		return generation, x509pkix.Extension{}, err
	}
	value, err := asn1.Marshal(jsonValue)
	if err != nil {
		return generation, x509pkix.Extension{}, err
	}

	return generation, x509pkix.Extension{
		Id:    requestGenerationOID,
		Value: value,
	}, nil
}

// requestGenerationFromCSR returns the generation metadata embedded in a CSR.
// A nil result with a nil error means that the CSR was not produced by a
// request-cert invocation that recorded a generation.
func requestGenerationFromCSR(csr *pkix.CertificateSigningRequest) (*requestGeneration, error) {
	rawCSR, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		return nil, err
	}

	var extension *x509pkix.Extension
	for i := range rawCSR.Extensions {
		if rawCSR.Extensions[i].Id.Equal(requestGenerationOID) {
			if extension != nil {
				return nil, errors.New("certificate request contains multiple generation extensions")
			}
			extension = &rawCSR.Extensions[i]
		}
	}
	if extension == nil {
		return nil, nil
	}

	var jsonValue []byte
	rest, err := asn1.Unmarshal(extension.Value, &jsonValue)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate request generation: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("invalid certificate request generation: trailing data")
	}

	var generation requestGeneration
	if err := json.Unmarshal(jsonValue, &generation); err != nil {
		return nil, fmt.Errorf("invalid certificate request generation: %w", err)
	}
	if generation.Version != 1 {
		return nil, fmt.Errorf("unsupported certificate request generation version %d", generation.Version)
	}
	if generation.ID == "" || len(generation.PublicKey) == 0 || len(generation.KeyDigest) != sha256.Size {
		return nil, errors.New("incomplete certificate request generation")
	}

	return &generation, nil
}

// validateRequestGeneration verifies that the CSR and the private key it will
// be paired with belong to one request generation.
func validateRequestGeneration(c *cli.Context, csr *pkix.CertificateSigningRequest, name string) error {
	generation, err := requestGenerationFromCSR(csr)
	if err != nil {
		return err
	}

	rawCSR, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		return err
	}
	csrPublicKey, err := x509.MarshalPKIXPublicKey(rawCSR.PublicKey)
	if err != nil {
		return err
	}

	if generation == nil {
		if c.IsSet("key") {
			return validateRequestKeyOverride(c, csrPublicKey, nil)
		}
		return validateRequestPrivateKey(c, name, csrPublicKey)
	}

	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("certificate request signature is invalid: %w", err)
	}
	if !bytes.Equal(csrPublicKey, generation.PublicKey) {
		return errors.New("certificate request public key does not match its generation")
	}
	if c.IsSet("key") {
		return validateRequestKeyOverride(c, csrPublicKey, generation)
	}

	csrPath := ""
	if c.IsSet("csr") {
		csrPath = c.String("csr")
	}
	keyPaths := requestGenerationKeyPaths(name, generation.KeyPath, csrPath)
	var lastErr, readErr error
	readAny := false
	for _, keyPath := range keyPaths {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			lastErr = err
			if readErr == nil && !os.IsNotExist(err) {
				readErr = err
			}
			continue
		}
		readAny = true

		// If the key can be read directly, the public key is the strongest
		// identity check and also tolerates re-encoding the same key pair.
		if key, err := pkix.NewKeyFromPrivateKeyPEM(keyBytes); err == nil {
			publicKey, err := x509.MarshalPKIXPublicKey(key.Public)
			if err != nil {
				return err
			}
			if bytes.Equal(publicKey, generation.PublicKey) {
				return nil
			}
			if generation.KeyPath != "" && keyPath == generation.KeyPath {
				return fmt.Errorf("certificate request generation mismatch: private key %s does not belong to request %q", keyPath, name)
			}
			continue
		}

		// If the caller supplied a passphrase, an encrypted key can still be
		// checked by its public key even when its bytes were re-encoded.
		if passphrase := []byte(c.String("passphrase")); len(passphrase) > 0 {
			if key, err := pkix.NewKeyFromEncryptedPrivateKeyPEM(keyBytes, passphrase); err == nil {
				publicKey, err := x509.MarshalPKIXPublicKey(key.Public)
				if err != nil {
					return err
				}
				if bytes.Equal(publicKey, generation.PublicKey) {
					return nil
				}
				if generation.KeyPath != "" && keyPath == generation.KeyPath {
					return fmt.Errorf("certificate request generation mismatch: private key %s does not belong to request %q", keyPath, name)
				}
				continue
			}
		}

		// Encrypted keys are opaque without the request passphrase, so bind
		// them by the exact bytes recorded when the request was created.
		digest := sha256.Sum256(keyBytes)
		if bytes.Equal(digest[:], generation.KeyDigest) {
			return nil
		}
		if generation.KeyPath != "" && keyPath == generation.KeyPath {
			return fmt.Errorf("certificate request generation mismatch: private key %s does not belong to request %q", keyPath, name)
		}
	}

	if !readAny && lastErr != nil {
		if readErr != nil {
			return fmt.Errorf("read certificate request private key: %w", readErr)
		}
		return fmt.Errorf("certificate request %q generation is incomplete: private key is missing: %w", name, lastErr)
	}
	return fmt.Errorf("certificate request generation mismatch: private key does not belong to request %q", name)
}

func validateRequestKeyOverride(c *cli.Context, csrPublicKey []byte, generation *requestGeneration) error {
	keyPath := c.String("key")
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read certificate request private key %s: %w", keyPath, err)
	}

	key, err := pkix.NewKeyFromPrivateKeyPEM(keyBytes)
	if err != nil {
		passphrase := []byte(c.String("passphrase"))
		if len(passphrase) > 0 {
			key, err = pkix.NewKeyFromEncryptedPrivateKeyPEM(keyBytes, passphrase)
		}
	}
	if err != nil {
		if generation != nil {
			digest := sha256.Sum256(keyBytes)
			if bytes.Equal(digest[:], generation.KeyDigest) {
				return nil
			}
		}
		return fmt.Errorf("cannot read certificate request private key %s: %w", keyPath, err)
	}

	publicKey, err := x509.MarshalPKIXPublicKey(key.Public)
	if err != nil {
		return err
	}
	if !bytes.Equal(publicKey, csrPublicKey) {
		return fmt.Errorf("certificate request does not match private key %s", keyPath)
	}
	return nil
}

func requestGenerationKeyPaths(name, recordedPath, csrPath string) []string {
	paths := make([]string, 0, 3)
	add := func(path string) {
		if path == "" {
			return
		}
		for _, existing := range paths {
			if existing == path {
				return
			}
		}
		paths = append(paths, path)
	}

	if recordedPath != "" {
		add(recordedPath)
		if base := filepath.Base(recordedPath); base != "" {
			add(filepath.Join(requestDepotPhysicalDir(), base))
		}
	}
	if extension := filepath.Ext(csrPath); extension != "" {
		add(strings.TrimSuffix(csrPath, extension) + ".key")
	}
	add(filepath.Join(requestDepotPhysicalDir(), name+".key"))

	return paths
}

// validateRequestPrivateKey handles CSRs created before generation metadata was
// recorded. Depot-local requests must still have a matching private key so a
// CSR left behind by a failed request cannot be signed as if it were complete.
// Externally supplied CSRs (--csr) are still accepted without a depot key.
func validateRequestPrivateKey(c *cli.Context, name string, csrPublicKey []byte) error {
	keyPaths := []string{filepath.Join(requestDepotPhysicalDir(), name+".key")}
	if c.IsSet("csr") {
		csrPath := c.String("csr")
		if extension := filepath.Ext(csrPath); extension != "" {
			sibling := strings.TrimSuffix(csrPath, extension) + ".key"
			if sibling != keyPaths[0] {
				keyPaths = append(keyPaths, sibling)
			}
		}
	}

	var (
		lastErr      error
		readErr      error
		foundKey     bool
		unverifiable string
	)
	for _, keyPath := range keyPaths {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			lastErr = err
			if readErr == nil && !os.IsNotExist(err) {
				readErr = err
			}
			continue
		}
		foundKey = true

		key, err := pkix.NewKeyFromPrivateKeyPEM(keyBytes)
		if err != nil {
			passphrase := []byte(c.String("passphrase"))
			if len(passphrase) > 0 {
				key, err = pkix.NewKeyFromEncryptedPrivateKeyPEM(keyBytes, passphrase)
			}
		}
		if err != nil {
			unverifiable = keyPath
			continue
		}

		publicKey, err := x509.MarshalPKIXPublicKey(key.Public)
		if err != nil {
			return err
		}
		if bytes.Equal(publicKey, csrPublicKey) {
			return nil
		}
	}

	if !foundKey {
		if readErr != nil {
			return fmt.Errorf("read certificate request private key: %w", readErr)
		}
		if c.IsSet("csr") {
			// Externally supplied CSRs do not need a depot private key.
			return nil
		}
		return fmt.Errorf("certificate request %q generation is incomplete: private key is missing: %w", name, lastErr)
	}

	if unverifiable != "" {
		return fmt.Errorf("cannot verify certificate request %q generation against private key %s: private key is not readable with the provided passphrase", name, unverifiable)
	}
	return fmt.Errorf("certificate request %q generation does not match its private key", name)
}
