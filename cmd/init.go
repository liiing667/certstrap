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

// NewInitCommand sets up an "init" command to initialize a new CA
func NewInitCommand() cli.Command {
	return cli.Command{
		Name:        "init",
		Usage:       "Create Certificate Authority",
		Description: "Create Certificate Authority, including certificate, key and extra information file.",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "passphrase",
				Usage: "Passphrase to encrypt private key PEM block",
			},
			cli.IntFlag{
				Name:  "key-bits",
				Value: 4096,
				Usage: "Size (in bits) of RSA keypair to generate (example: 4096)",
			},
			cli.StringFlag{
				Name:  "curve",
				Usage: fmt.Sprintf("Elliptic curve name. Must be one of %s.", supportedCurves()),
			},
			cli.IntFlag{
				Name:   "years",
				Hidden: true,
			},
			cli.StringFlag{
				Name:  "expires",
				Value: "18 months",
				Usage: "How long until the certificate expires (example: 1 year 2 days 3 months 4 hours)",
			},
			cli.StringFlag{
				Name:  "organization, o",
				Usage: "Sets the Organization (O) field of the certificate",
			},
			cli.StringFlag{
				Name:  "organizational-unit, ou",
				Usage: "Sets the Organizational Unit (OU) field of the certificate",
			},
			cli.StringFlag{
				Name:  "country, c",
				Usage: "Sets the Country (C) field of the certificate",
			},
			cli.StringFlag{
				Name:  "common-name, cn",
				Usage: "Sets the Common Name (CN) field of the certificate",
			},
			cli.StringFlag{
				Name:  "province, st",
				Usage: "Sets the State/Province (ST) field of the certificate",
			},
			cli.StringFlag{
				Name:  "locality, l",
				Usage: "Sets the Locality (L) field of the certificate",
			},
			cli.StringFlag{
				Name:  "key",
				Usage: "Path to private key PEM file (if blank, will generate new key pair)",
			},
			cli.BoolFlag{
				Name:  "stdout",
				Usage: "Print certificate to stdout in addition to saving file",
			},
			cli.StringSliceFlag{
				Name:  "permit-domain",
				Usage: "Create a CA restricted to subdomains of this domain (can be specified multiple times)",
			},
			cli.IntFlag{
				Name:  "path-length",
				Value: 0,
				Usage: "Maximum number of non-self-issued intermediate certificates that may follow this CA certificate in a valid certification path",
			},
			cli.BoolFlag{
				Name:  "exclude-path-length",
				Usage: "Exclude 'Path Length Constraint' from this CA certificate",
			},
		},
		Action: initAction,
	}
}

func initAction(c *cli.Context) {
	if !c.IsSet("common-name") {
		fmt.Println("Must supply Common Name for CA")
		os.Exit(1)
	}

	formattedName := strings.Replace(c.String("common-name"), " ", "_", -1)

	if c.IsSet("path-length") && c.IsSet("exclude-path-length") {
		fmt.Fprintf(os.Stderr, "The \"path-length\" and \"exclude-path-length\" flags cannot be used together!\n")
		os.Exit(1)
	}

	var err error
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

	// Fast path: refuse to overwrite a complete CA before doing any work.
	// The authoritative check happens again below under the transaction
	// lock, after files left behind by an interrupted run are recovered.
	if depot.CheckCertificate(d, formattedName) && depot.CheckPrivateKey(d, formattedName) {
		fmt.Fprintf(os.Stderr, "CA with specified name \"%s\" already exists!\n", formattedName)
		os.Exit(1)
	}

	var passphrase []byte
	if c.IsSet("passphrase") {
		passphrase = []byte(c.String("passphrase"))
	} else {
		passphrase, err = createPassPhrase()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	var key *pkix.Key
	newKey := true
	switch {
	case c.IsSet("key"):
		newKey = false
		keyBytes, err := os.ReadFile(c.String("key"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Read Key error:", err)
			os.Exit(1)
		}

		key, err = pkix.NewKeyFromPrivateKeyPEM(keyBytes)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Read Key error:", err)
			os.Exit(1)
		}
		fmt.Printf("Read %s\n", c.String("key"))
	case c.IsSet("curve"):
		curve := c.String("curve")
		key, err = createKeyOnCurve(curve)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Create %s Key error: %v\n", curve, err)
			os.Exit(1)
		}
	default:
		key, err = pkix.CreateRSAKey(c.Int("key-bits"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Create RSA Key error:", err)
			os.Exit(1)
		}
	}

	opts := []pkix.Option{
		pkix.WithPathlenOption(c.Int("path-length"), c.Bool("exclude-path-length")),
	}

	crt, err := pkix.CreateCertificateAuthorityWithOptions(key, c.String("organizational-unit"), expiresTime, c.String("organization"), c.String("country"), c.String("province"), c.String("locality"), c.String("common-name"), c.StringSlice("permit-domain"), opts...)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate error:", err)
		os.Exit(1)
	}

	// Create an empty CRL, this is useful for Java apps which mandate a CRL.
	crl, err := pkix.CreateCertificateRevocationList(key, crt, expiresTime)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create CRL error:", err)
		os.Exit(1)
	}

	// Export everything before touching the depot, so the transaction only
	// has to move fully rendered artifacts into place.
	var keyBytes []byte
	if len(passphrase) > 0 {
		keyBytes, err = key.ExportEncryptedPrivate(passphrase)
	} else {
		keyBytes, err = key.ExportPrivate()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Export private key error:", err)
		os.Exit(1)
	}
	crtBytes, err := crt.Export()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Export certificate error:", err)
		os.Exit(1)
	}
	crlBytes, err := crl.Export()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Export CRL error:", err)
		os.Exit(1)
	}

	// The CA private key, certificate and revocation list (which records
	// the serial state of the CA) are committed to the depot in a single
	// recoverable transaction: either all of them appear with their final
	// permission bits, or none of them do. A failed, interrupted or
	// concurrent initialization can therefore never leave a new
	// certificate next to an old key, or a CRL that does not belong to
	// the CA.
	txn, err := d.BeginTransaction()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Begin depot transaction error:", err)
		os.Exit(1)
	}

	recovered, err := depot.RecoverIncompleteCA(d, formattedName)
	if err != nil {
		txn.Rollback()
		fmt.Fprintln(os.Stderr, "Recover incomplete CA error:", err)
		os.Exit(1)
	}
	if recovered {
		fmt.Fprintf(os.Stderr, "Removed incomplete CA \"%s\" left behind by an interrupted initialization\n", formattedName)
	}

	if depot.CheckCertificate(d, formattedName) || depot.CheckPrivateKey(d, formattedName) {
		txn.Rollback()
		fmt.Fprintf(os.Stderr, "CA with specified name \"%s\" already exists!\n", formattedName)
		os.Exit(1)
	}

	// The certificate is committed last: its presence in the depot marks
	// a complete CA, so readers never see a certificate without its key.
	if err = txn.Put(depot.PrivKeyTag(formattedName), keyBytes); err != nil {
		txn.Rollback()
		fmt.Fprintln(os.Stderr, "Stage private key error:", err)
		os.Exit(1)
	}
	if err = txn.Put(depot.CrlTag(formattedName), crlBytes); err != nil {
		txn.Rollback()
		fmt.Fprintln(os.Stderr, "Stage CRL error:", err)
		os.Exit(1)
	}
	if err = txn.Put(depot.CrtTag(formattedName), crtBytes); err != nil {
		txn.Rollback()
		fmt.Fprintln(os.Stderr, "Stage certificate error:", err)
		os.Exit(1)
	}

	if err = txn.Commit(); err != nil {
		if errors.Is(err, os.ErrExist) {
			// A concurrent initialization won the race; its CA is
			// complete and consistent, so just report it.
			fmt.Fprintf(os.Stderr, "CA with specified name \"%s\" already exists!\n", formattedName)
		} else {
			fmt.Fprintln(os.Stderr, "Save CA error:", err)
		}
		os.Exit(1)
	}

	if newKey {
		if len(passphrase) > 0 {
			fmt.Printf("Created %s/%s.key (encrypted by passphrase)\n", depotDir, formattedName)
		} else {
			fmt.Printf("Created %s/%s.key\n", depotDir, formattedName)
		}
	}
	fmt.Printf("Created %s/%s.crt\n", depotDir, formattedName)
	fmt.Printf("Created %s/%s.crl\n", depotDir, formattedName)

	if c.Bool("stdout") {
		fmt.Println(string(crtBytes))
	}
}
