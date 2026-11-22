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
	x509pkix "crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

// NewCertRequestCommand sets up a "request-cert" command to create a request for a new certificate (CSR)
func NewCertRequestCommand() cli.Command {
	return cli.Command{
		Name:        "request-cert",
		Usage:       "Create certificate request for host",
		Description: "Create certificate for host, including certificate signing request and key. Must sign the request in order to generate a certificate.",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "passphrase",
				Usage: "Passphrase to encrypt private-key PEM block",
			},
			cli.IntFlag{
				Name:  "key-bits",
				Value: 2048,
				Usage: "Size (in bits) of RSA keypair to generate (example: 4096)",
			},
			cli.StringFlag{
				Name:  "curve",
				Usage: fmt.Sprintf("Elliptic curve name. Must be one of %s.", supportedCurves()),
			},
			cli.StringFlag{
				Name:  "organization, o",
				Usage: "Sets the Organization (O) field of the certificate",
			},
			cli.StringFlag{
				Name:  "country, c",
				Usage: "Sets the Country (C) field of the certificate",
			},
			cli.StringFlag{
				Name:  "locality, l",
				Usage: "Sets the Locality (L) field of the certificate",
			},
			cli.StringFlag{
				Name:  "common-name, cn",
				Usage: "Sets the Common Name (CN) field of the certificate",
			},
			cli.StringFlag{
				Name:  "organizational-unit, ou",
				Usage: "Sets the Organizational Unit (OU) field of the certificate",
			},
			cli.StringFlag{
				Name:  "province, st",
				Usage: "Sets the State/Province (ST) field of the certificate",
			},
			cli.StringFlag{
				Name:  "ip",
				Usage: "IP addresses to add as subject alt name (comma separated)",
			},
			cli.StringFlag{
				Name:  "domain",
				Usage: "DNS entries to add as subject alt name (comma separated)",
			},
			cli.StringFlag{
				Name:  "uri",
				Usage: "URI values to add as subject alt name (comma separated)",
			},
			cli.StringFlag{
				Name:  "key",
				Usage: "Path to private key PEM file (if blank or if file doesn't exist, will generate new keypair)",
			},
			cli.StringFlag{
				Name:  "csr",
				Usage: "Path to CSR output PEM file (if blank, will use --depot-path and default name)",
			},
			cli.BoolFlag{
				Name:  "stdout",
				Usage: "Print signing request to stdout in addition to saving file",
			},
		},
		Action: newCertAction,
	}
}

func newCertAction(c *cli.Context) {
	var name = ""
	var err error

	// The CLI Context returns an empty string ("") if no value is available
	ips, err := pkix.ParseAndValidateIPs(c.String("ip"))

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// The CLI Context returns an empty string ("") if no value is available
	uris, err := pkix.ParseAndValidateURIs(c.String("uri"))

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	domains := strings.Split(c.String("domain"), ",")
	if c.String("domain") == "" {
		domains = nil
	}

	switch {
	case len(c.String("common-name")) != 0:
		name = c.String("common-name")
	case len(domains) != 0:
		name = domains[0]
	case len(uris) != 0:
		name = uris[0].String()
	default:
		fmt.Fprintln(os.Stderr, "Must provide Common Name, domain, or URI")
		os.Exit(1)
	}

	var formattedName = formatName(name)
	explicitCSR := c.IsSet("csr")
	explicitKey := c.IsSet("key")
	csrDisplayPath := fileName(c, "csr", requestDepotDir(), formattedName, "csr")
	keyDisplayPath := fileName(c, "key", requestDepotDir(), formattedName, "key")
	csrFilepath := csrDisplayPath
	keyFilepath := keyDisplayPath
	if !explicitCSR {
		csrFilepath = filepath.Join(requestDepotPhysicalDir(), formattedName+".csr")
	}
	if !explicitKey {
		keyFilepath = filepath.Join(requestDepotPhysicalDir(), formattedName+".key")
	}

	if sameRequestTargetPath(keyFilepath, csrFilepath) {
		fmt.Fprintln(os.Stderr, "Private key and certificate request paths must be different.")
		os.Exit(1)
	}

	// skip the check if the --csr option is specified
	if !explicitCSR && (depot.CheckCertificateSigningRequest(d, formattedName) || depot.CheckPrivateKey(d, formattedName)) {
		fmt.Fprintf(os.Stderr, "Certificate request \"%s\" already exists!\n", formattedName)
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

	// Generate a new key if one doesn't exist already. The key bytes that are
	// about to be published are kept in memory so that the CSR, the key file
	// and the generation metadata can only describe this one key pair.
	var key *pkix.Key
	var keyBytes []byte
	var writeKey bool
	var keyEncrypted bool
	switch {
	case explicitKey && fileExists(keyFilepath):
		keyBytes, err = os.ReadFile(keyFilepath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Read Key error:", err)
			os.Exit(1)
		}

		key, err = pkix.NewKeyFromPrivateKeyPEM(keyBytes)
		if err != nil && len(passphrase) > 0 {
			key, err = pkix.NewKeyFromEncryptedPrivateKeyPEM(keyBytes, passphrase)
			keyEncrypted = err == nil
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Read Key error:", err)
			os.Exit(1)
		}
	case c.IsSet("curve"):
		curve := c.String("curve")
		key, err = createKeyOnCurve(curve)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Create %s Key error: %v\n", curve, err)
			os.Exit(1)
		}
		writeKey = true
	default:
		key, err = pkix.CreateRSAKey(c.Int("key-bits"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Create RSA Key error:", err)
			os.Exit(1)
		}
		writeKey = true
	}

	if writeKey {
		keyEncrypted = len(passphrase) > 0
		if keyEncrypted {
			keyBytes, err = key.ExportEncryptedPrivate(passphrase)
		} else {
			keyBytes, err = key.ExportPrivate()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Save private key error:", err)
			os.Exit(1)
		}
	}

	// Validate both destinations before anything is written. The key is never
	// written over an existing file; an existing CSR is only replaced when the
	// caller explicitly selected its path with --csr.
	if writeKey {
		if err := prepareRequestTargetFile(keyFilepath, false, !explicitKey); err != nil {
			fmt.Fprintln(os.Stderr, "Save private key error:", err)
			os.Exit(1)
		}
	}
	if err := prepareRequestTargetFile(csrFilepath, explicitCSR, !explicitCSR); err != nil {
		fmt.Fprintln(os.Stderr, "Save certificate request error:", err)
		os.Exit(1)
	}

	generationKeyPath := ""
	if explicitKey {
		generationKeyPath, err = filepath.Abs(keyFilepath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Create certificate request error:", err)
			os.Exit(1)
		}
	}
	_, generationExtension, err := newRequestGeneration(key, generationKeyPath, keyBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate request error:", err)
		os.Exit(1)
	}

	csr, err := pkix.CreateCertificateSigningRequestWithExtensions(key, c.String("organizational-unit"), ips, domains, uris, c.String("organization"), c.String("country"), c.String("province"), c.String("locality"), name, []x509pkix.Extension{generationExtension})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate request error:", err)
		os.Exit(1)
	}

	csrBytes, err := csr.Export()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Create certificate request error:", err)
		os.Exit(1)
	}

	if err := commitRequestFiles(writeKey, keyFilepath, keyBytes, csrFilepath, csrBytes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if !writeKey {
		fmt.Printf("Read %s\n", keyDisplayPath)
	} else if keyEncrypted {
		fmt.Printf("Created %s (encrypted by passphrase)\n", keyDisplayPath)
	} else {
		fmt.Printf("Created %s\n", keyDisplayPath)
	}
	fmt.Printf("Created %s\n", csrDisplayPath)

	if c.Bool("stdout") {
		fmt.Println(string(csrBytes))
	}
}

func prepareRequestTargetFile(path string, allowOverwrite, createParent bool) error {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		if !allowOverwrite {
			return fmt.Errorf("%s already exists", path)
		}
		return nil
	case !os.IsNotExist(err):
		return err
	}

	if createParent {
		return os.MkdirAll(filepath.Dir(path), 0755)
	}
	return nil
}

func sameRequestTargetPath(first, second string) bool {
	firstPath, err := filepath.Abs(first)
	if err != nil {
		return first == second
	}
	secondPath, err := filepath.Abs(second)
	if err != nil {
		return first == second
	}
	return filepath.Clean(firstPath) == filepath.Clean(secondPath)
}

func formatName(name string) string {
	var filenameAcceptable, err = regexp.Compile("[^a-zA-Z0-9._-]+")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error compiling regex:", err)
		os.Exit(1)
	}
	return string(filenameAcceptable.ReplaceAll([]byte(name), []byte("_")))
}

func fileName(c *cli.Context, flagName, depotDir, name, ext string) string {
	if c.IsSet(flagName) {
		return c.String(flagName)
	}
	return fmt.Sprintf("%s/%s.%s", depotDir, name, ext)
}
