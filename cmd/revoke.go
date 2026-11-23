package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

type revokeCommand struct {
	ca, cn string
	reason string
	date   string
}

// revocationMu serializes read-modify-write CRL updates in this process.
// File depots additionally take an advisory lock so separate certstrap
// processes are serialized as well.
var revocationMu sync.Mutex

// NewRevokeCommand revokes the given certificate by adding it to the CA's CRL.
func NewRevokeCommand() cli.Command {
	return cli.Command{
		Name:        "revoke",
		Usage:       "Revoke certificate",
		Description: "Add certificate to the CA's CRL.",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "passphrase",
				Usage: "Passphrase to decrypt private-key PEM block of CA",
			},
			cli.StringFlag{
				Name:  "CN",
				Usage: "Common Name (CN) of certificate to revoke",
			},
			cli.StringFlag{
				Name:  "CA",
				Usage: "Name of CA under which certificate was issued",
			},
			cli.StringFlag{
				Name:  "reason, revocation-reason",
				Usage: "Reason for revocation (unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise)",
			},
			cli.StringFlag{
				Name:  "date, revocation-date",
				Usage: "Revocation date in RFC3339 or YYYY-MM-DD form (defaults to now)",
			},
		},
		Action: new(revokeCommand).run,
	}
}

func (c *revokeCommand) checkErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func (c *revokeCommand) parseArgs(ctx *cli.Context) error {
	if ctx.String("CA") == "" {
		return errors.New("CA name must be provided")
	}
	c.ca = strings.Replace(ctx.String("CA"), " ", "_", -1)

	if ctx.String("CN") == "" {
		return errors.New("CN name must be provided")
	}
	c.cn = strings.Replace(ctx.String("CN"), " ", "_", -1)

	c.reason = ctx.String("reason")
	if c.reason == "" {
		c.reason = ctx.String("revocation-reason")
	}
	c.date = ctx.String("date")
	if c.date == "" {
		c.date = ctx.String("revocation-date")
	}

	return nil
}

func (c *revokeCommand) run(ctx *cli.Context) {
	c.checkErr(c.runRevoke(ctx))
}

// runRevoke performs one complete revocation. The CRL is read, extended,
// signed and atomically replaced while holding the depot lock, so a failed
// write leaves the previous complete CRL in place for the next attempt.
func (c *revokeCommand) runRevoke(ctx *cli.Context) error {
	if err := c.parseArgs(ctx); err != nil {
		return err
	}

	caCert, err := c.CAx509Certificate()
	if err != nil {
		return err
	}

	cnCert, err := c.CNx509Certificate()
	if err != nil {
		return err
	}
	if cnCert.SerialNumber == nil || cnCert.SerialNumber.Sign() <= 0 {
		serial := "unknown"
		if cnCert.SerialNumber != nil {
			serial = cnCert.SerialNumber.String()
		}
		return fmt.Errorf("could not revoke certificate %q: stage=validate-serial serial=%s reason=%q date=%q CRL number=unknown: serial number is missing or not positive", c.cn, serial, c.reason, c.date)
	}

	reason, remove, err := parseRevocationReason(c.reason)
	if err != nil {
		return fmt.Errorf("could not revoke certificate %q: stage=validate-reason serial=%s reason=%q date=%q CRL number=unknown: %v", c.cn, cnCert.SerialNumber, c.reason, c.date, err)
	}

	now := time.Now()
	revocationTime, err := parseRevocationTime(c.date, now)
	if err != nil {
		return fmt.Errorf("could not revoke certificate %q: stage=validate-date serial=%s reason=%d(%s) date=%q CRL number=unknown: %v", c.cn, cnCert.SerialNumber, reason, revocationReasonName(reason), c.date, err)
	}

	revocationMu.Lock()
	defer revocationMu.Unlock()

	unlock, err := d.Lock()
	if err != nil {
		return fmt.Errorf("could not lock depot for revocation: stage=lock-depot ca=%q serial=%s reason=%d(%s) date=%s CRL number=unknown: %v", c.ca, cnCert.SerialNumber, reason, revocationReasonName(reason), revocationTime.UTC().Format(time.RFC3339), err)
	}
	defer unlock()

	current, err := c.revocationList()
	if err != nil {
		// A depot that predates init's empty CRL has no CRL yet. Starting from
		// an empty list creates CRL number 1 instead of failing the first
		// revocation.
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("could not read CA %q CRL: stage=read-crl serial=%s reason=%d(%s) date=%s CRL number=unknown: %v", c.ca, cnCert.SerialNumber, reason, revocationReasonName(reason), revocationTime.UTC().Format(time.RFC3339), err)
		}
		current = &x509.RevocationList{}
	}

	entry := &x509.RevocationListEntry{
		SerialNumber:   cnCert.SerialNumber,
		RevocationTime: revocationTime,
		ReasonCode:     reason,
	}
	next := nextRevocationListFor(current, entry, remove, now)

	return c.saveRevokedCertificatesFor(ctx, caCert, next, entry, remove)
}

func (c *revokeCommand) CAx509Certificate() (*x509.Certificate, error) {
	cert, err := depot.GetCertificate(d, c.ca)
	if err != nil {
		return nil, err
	}
	return cert.GetRawCertificate()
}

func (c *revokeCommand) CNx509Certificate() (*x509.Certificate, error) {
	cert, err := depot.GetCertificate(d, c.cn)
	if err != nil {
		return nil, err
	}
	return cert.GetRawCertificate()
}

func (c *revokeCommand) revocationList() (*x509.RevocationList, error) {
	list, err := depot.GetCertificateRevocationList(d, c.ca)
	if err != nil {
		return nil, err
	}

	current, err := parseRevocationList(list.DERBytes())
	if err != nil {
		return nil, fmt.Errorf("could not parse CRL for CA %q: %w", c.ca, err)
	}
	return current, nil
}

func (c *revokeCommand) saveRevokedCertificates(ctx *cli.Context, cert *x509.Certificate, template *x509.RevocationList) error {
	var entry *x509.RevocationListEntry
	if len(template.RevokedCertificateEntries) > 0 {
		last := template.RevokedCertificateEntries[len(template.RevokedCertificateEntries)-1]
		entry = &last
	}
	return c.saveRevokedCertificatesFor(ctx, cert, template, entry, false)
}

func (c *revokeCommand) saveRevokedCertificatesFor(ctx *cli.Context, cert *x509.Certificate, template *x509.RevocationList, entry *x509.RevocationListEntry, remove bool) error {
	details := fmt.Sprintf("ca=%q %s", c.ca, revocationFailureDetails(entry, template, remove))

	privateKey, err := depot.GetPrivateKey(d, c.ca)
	if err != nil {
		pass, err := getPassPhrase(ctx, "CA key")
		if err != nil {
			return fmt.Errorf("error retreiving passphrase when saving revoked certificates: stage=load-ca-key %s: %v", details, err)
		}
		privateKey, err = depot.GetEncryptedPrivateKey(d, c.ca, pass)
		if err != nil {
			return fmt.Errorf("get CA key error when saving revoked certificates: stage=load-ca-key %s: %v", details, err)
		}
	}

	signer, ok := privateKey.Private.(crypto.Signer)
	if !ok {
		return fmt.Errorf("could not create CRL: stage=sign-crl %s: CA private key does not implement crypto.Signer", details)
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, cert, signer)
	if err != nil {
		return fmt.Errorf("could not create CRL: stage=sign-crl %s: %v", details, err)
	}

	txn := depot.NewTxn(d)
	if depot.CheckCertificateRevocationList(d, c.ca) {
		err = depot.ReplaceCertificateRevocationListInTxn(txn, c.ca, pkix.NewCertificateRevocationListFromDER(crlBytes))
	} else {
		err = depot.PutCertificateRevocationListInTxn(txn, c.ca, pkix.NewCertificateRevocationListFromDER(crlBytes))
	}
	if err != nil {
		return fmt.Errorf("could not put revokation list: stage=stage-crl %s: %v", details, err)
	}
	if err = txn.Commit(); err != nil {
		return fmt.Errorf("could not put revokation list: stage=commit-crl %s: %v", details, err)
	}
	return nil
}

// revocationFailureDetails describes the CRL update for failure reporting.
func revocationFailureDetails(entry *x509.RevocationListEntry, template *x509.RevocationList, remove bool) string {
	action := "revoke"
	if remove {
		action = "remove"
	}
	serial := "unknown"
	reason := 0
	date := "unknown"
	if entry != nil {
		if entry.SerialNumber != nil {
			serial = entry.SerialNumber.String()
		}
		reason = entry.ReasonCode
		if !entry.RevocationTime.IsZero() {
			date = entry.RevocationTime.UTC().Format(time.RFC3339)
		}
	}
	number := "unknown"
	if template.Number != nil {
		number = template.Number.String()
	}
	return fmt.Sprintf("action=%s serial=%s reason=%d(%s) date=%s CRL number=%s", action, serial, reason, revocationReasonName(reason), date, number)
}

var revocationReasonCodes = map[string]int{
	"unspecified":          0,
	"keycompromise":        1,
	"cacompromise":         2,
	"affiliationchanged":   3,
	"superseded":           4,
	"cessationofoperation": 5,
	"certificatehold":      6,
	"removefromcrl":        8,
	"privilegewithdrawn":   9,
	"aacompromise":         10,
}

func parseRevocationReason(value string) (int, bool, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.NewReplacer("_", "", "-", "", " ", "").Replace(normalized)
	if normalized == "" {
		return 0, false, nil
	}
	if reason, ok := revocationReasonCodes[normalized]; ok {
		return reason, reason == 8, nil
	}
	number, err := strconv.Atoi(normalized)
	if err == nil {
		for _, reason := range revocationReasonCodes {
			if number == reason {
				return reason, reason == 8, nil
			}
		}
	}
	return 0, false, fmt.Errorf("invalid revocation reason %q: stage=validate-reason: use unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn or aACompromise", value)
}

func revocationReasonName(reason int) string {
	switch reason {
	case 0:
		return "unspecified"
	case 1:
		return "keyCompromise"
	case 2:
		return "cACompromise"
	case 3:
		return "affiliationChanged"
	case 4:
		return "superseded"
	case 5:
		return "cessationOfOperation"
	case 6:
		return "certificateHold"
	case 8:
		return "removeFromCRL"
	case 9:
		return "privilegeWithdrawn"
	case 10:
		return "aACompromise"
	default:
		return "unknown"
	}
}

func parseRevocationTime(value string, now time.Time) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return now, nil
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		parsed, err := time.Parse(layout, value)
		if err != nil {
			continue
		}
		if parsed.After(now) {
			return time.Time{}, fmt.Errorf("invalid revocation date %q: stage=validate-date: date is in the future", value)
		}
		return parsed, nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02", "2006/01/02", "20060102"} {
		parsed, err := time.ParseInLocation(layout, value, time.UTC)
		if err != nil {
			continue
		}
		if parsed.After(now) {
			return time.Time{}, fmt.Errorf("invalid revocation date %q: stage=validate-date: date is in the future", value)
		}
		return parsed, nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		parsed := time.Unix(seconds, 0).UTC()
		if parsed.After(now) {
			return time.Time{}, fmt.Errorf("invalid revocation date %q: stage=validate-date: date is in the future", value)
		}
		return parsed, nil
	}
	return time.Time{}, fmt.Errorf("invalid revocation date %q: stage=validate-date: use RFC3339, YYYY-MM-DD, or a Unix timestamp", value)
}
