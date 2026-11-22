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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

var errSelectedCANotCA = errors.New("Selected CA certificate is not allowed to sign certificates.")

// NewSignCommand sets up a "sign" command to sign a CSR with a given CA for a new certificate
func NewSignCommand() cli.Command {
	return cli.Command{
		Name:        "sign",
		Usage:       "Sign certificate request",
		Description: "Sign certificate request with CA, and generate certificate for the host.",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "passphrase",
				Usage: "Passphrase to decrypt private-key PEM block of CA",
			},
			cli.IntFlag{
				Name:   "years",
				Hidden: true,
			},
			cli.StringFlag{
				Name:  "expires",
				Value: "2 years",
				Usage: "How long until the certificate expires (example: 1 year 2 days 3 months 4 hours)",
			},
			cli.StringFlag{
				Name:  "CA",
				Usage: "Name of CA to issue cert with",
			},
			cli.StringFlag{
				Name:  "csr",
				Usage: "Path to certificate request PEM file (if blank, will use --depot-path and default name)",
			},
			cli.StringFlag{
				Name:  "cert",
				Usage: "Path to certificate output PEM file (if blank, will use --depot-path and default name)",
			},
			cli.BoolFlag{
				Name:  "stdout",
				Usage: "Print certificate to stdout in addition to saving file",
			},
			cli.BoolFlag{
				Name:  "intermediate",
				Usage: "Whether generated certificate should be a intermediate",
			},
			cli.IntFlag{
				Name:  "path-length",
				Value: 0,
				Usage: "Maximum number of non-self-issued intermediate certificates that may follow this CA certificate in a valid certification path",
			},
		},
		Action: newSignAction,
	}
}

func newSignAction(c *cli.Context) {
	if len(c.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "One host name must be provided.")
		os.Exit(1)
	}

	formattedReqName := strings.Replace(c.Args()[0], " ", "_", -1)
	formattedCAName := strings.Replace(c.String("CA"), " ", "_", -1)

	if depot.CheckCertificate(d, formattedReqName) {
		fmt.Fprintf(os.Stderr, "Certificate \"%s\" already exists!\n", formattedReqName)
		os.Exit(1)
	}

	expires := c.String("expires")
	if years := c.Int("years"); years != 0 {
		expires = fmt.Sprintf("%s %d years", expires, years)
	}

	// Expiry parsing is a naive regex implementation
	// Token based parsing would provide better feedback but
	expiresTime, err := parseExpiry(expires)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid expiry: %s\n", err)
		os.Exit(1)
	}

	// Capture one CA certificate, private signer and name before reading the
	// request or building any leaf template. A key rotation or an incorrect
	// passphrase must fail before a half certificate can be published.
	ca, err := loadSigningCA(c, formattedCAName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	csr, err := getCertificateSigningRequest(c, d, formattedReqName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get certificate request error:", err)
		os.Exit(1)
	}

	var crtOut *pkix.Certificate
	if c.Bool("intermediate") {
		fmt.Fprintln(os.Stderr, "Building intermediate")

		opts := []pkix.Option{
			pkix.WithPathlenOption(c.Int("path-length"), false),
		}

		crtOut, err = pkix.CreateIntermediateCertificateAuthorityWithOptions(ca.Certificate, ca.Key, csr, expiresTime, opts...)
	} else {
		if c.IsSet("path-length") {
			fmt.Fprintln(os.Stderr, "The 'path-length' can only be used with 'intermediate' flag.")
			os.Exit(1)
		}

		crtOut, err = pkix.CreateCertificateHost(ca.Certificate, ca.Key, csr, expiresTime)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate error:", err)
		os.Exit(1)
	}

	if err = putCertificate(c, d, formattedReqName, crtOut); err != nil {
		fmt.Fprintln(os.Stderr, "Save certificate error:", err)
		os.Exit(1)
	}

	// The CA files can be rotated while the certificate is being built. Do not
	// leave a leaf whose issuer is no longer the CA identity published under
	// the selected name.
	if err = verifyPublishedCAIdentity(ca); err != nil {
		rollbackPublishedCertificate(c, formattedReqName, crtOut)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Created %s/%s.crt from %s/%s.csr signed by %s/%s.key\n", depotDir, formattedReqName, depotDir, formattedReqName, depotDir, formattedCAName)

	if c.Bool("stdout") {
		crtBytes, err := crtOut.Export()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Print certificate error:", err)
			os.Exit(1)
		}
		fmt.Println(string(crtBytes))
	}
}

// loadSigningCA captures one certificate and private key pair and binds them to
// the depot name. The certificate's public key and the private signer must
// match before any request or leaf template is read.
func loadSigningCA(c *cli.Context, name string) (*pkix.CertificateAuthority, error) {
	crt, err := depot.GetCertificate(d, name)
	if err != nil {
		return nil, fmt.Errorf("Get CA certificate error: CA %q: %w (stage: read CA certificate)", name, err)
	}
	rawCrt, err := crt.GetRawCertificate()
	if err != nil {
		return nil, fmt.Errorf("Get CA certificate error: CA %q: %w (stage: parse CA certificate)", name, err)
	}
	// We punt on checking BasicConstraintsValid and checking MaxPathLen. The
	// goal is to prevent accidentally creating invalid certificates, not
	// protecting against malicious input.
	if !rawCrt.IsCA {
		return nil, errSelectedCANotCA
	}

	key, err := depot.GetPrivateKey(d, name)
	if err != nil {
		var identityErr *depot.StoredIdentityError
		if errors.As(err, &identityErr) {
			return nil, fmt.Errorf("Get CA identity error: CA %q: %w", name, err)
		}
		encrypted, encryptedErr := depot.IsEncryptedPrivateKey(d, name)
		if encryptedErr != nil {
			return nil, fmt.Errorf("Get CA key error: CA %q: %w (stage: read CA private key)", name, err)
		}
		if !encrypted {
			return nil, fmt.Errorf("Get CA key error: CA %q: %w (stage: parse CA private key)", name, err)
		}
		pass, passErr := getPassPhrase(c, "CA key")
		if passErr != nil {
			return nil, fmt.Errorf("Get CA key error: CA %q: %w (stage: read CA key passphrase)", name, passErr)
		}
		key, err = depot.GetEncryptedPrivateKey(d, name, pass)
		if err != nil {
			if errors.As(err, &identityErr) {
				return nil, fmt.Errorf("Get CA identity error: CA %q: %w", name, err)
			}
			return nil, fmt.Errorf("Get CA key error: CA %q: %w (stage: decrypt CA private key)", name, err)
		}
	}

	ca, err := pkix.NewCertificateAuthority(name, crt, key)
	if err != nil {
		return nil, fmt.Errorf("Get CA identity error: %w", err)
	}
	return ca, nil
}

// verifyPublishedCAIdentity re-reads the selected CA certificate after the leaf
// has been written. If a rotation replaced the certificate while signing, the
// leaf no longer belongs to the published CA identity.
func verifyPublishedCAIdentity(ca *pkix.CertificateAuthority) error {
	current, err := depot.GetCertificate(d, ca.Name)
	if err != nil {
		return fmt.Errorf(
			"CA %q certificate cannot be reloaded after signing; refusing to publish a leaf whose issuer is no longer readable: %w (stage: verify CA identity before publish)",
			ca.Name, err,
		)
	}
	if !ca.MatchesCertificate(current) {
		return fmt.Errorf(
			"CA %q certificate changed during signing (signed with %s, published certificate is different); refusing to publish a leaf whose issuer does not match the current CA identity (stage: verify CA identity before publish)",
			ca.Name, ca.CertificateFingerprint(),
		)
	}
	return nil
}

func rollbackPublishedCertificate(c *cli.Context, name string, published *pkix.Certificate) {
	if c.IsSet("cert") {
		bytes, err := os.ReadFile(c.String("cert"))
		if err != nil {
			if !os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "Read unverified certificate error:", err)
			}
			return
		}
		current, err := pkix.NewCertificateFromPEM(bytes)
		if err != nil || !current.Equal(published) {
			return
		}
		if err := os.Remove(c.String("cert")); err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "Remove unverified certificate error:", err)
		}
		return
	}
	current, err := depot.GetCertificate(d, name)
	if err != nil || !current.Equal(published) {
		return
	}
	if err := depot.DeleteCertificate(d, name); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "Remove unverified certificate error:", err)
	}
}
