package cmd

import (
	"crypto/x509"
	x509pkix "crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// crlValidity is how long a CRL written by revoke is valid for.
const crlValidity = 2 * 8760 * time.Hour

var (
	oidExtensionCRLNumber  = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtensionReasonCode = asn1.ObjectIdentifier{2, 5, 29, 21}
)

// v1CertificateList mirrors the CertificateList structure that the deprecated
// x509.ParseDERCRL decoded. Unlike x509.ParseRevocationList, it accepts CRLs
// without a version field, which certstrap releases built with old Go versions
// wrote.
type v1CertificateList struct {
	TBSCertList struct {
		Version             int `asn1:"optional,default:0"`
		Signature           x509pkix.AlgorithmIdentifier
		Issuer              x509pkix.RDNSequence
		ThisUpdate          time.Time
		NextUpdate          time.Time                     `asn1:"optional"`
		RevokedCertificates []x509pkix.RevokedCertificate `asn1:"optional"`
		Extensions          []x509pkix.Extension          `asn1:"tag:0,optional,explicit"`
	}
	SignatureAlgorithm x509pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// parseRevocationList parses a DER-encoded CRL. v1 CRLs written by old
// certstrap releases are also accepted, so that revoke keeps working with
// existing depots; any other CRL that x509.ParseRevocationList rejects is
// reported with its error.
//
// For a v1 CRL, only the fields that revoke carries over to the next CRL are
// set: Number and RevokedCertificateEntries. The raw encodings, issuer,
// validity period, CRL extensions and signature fields of the returned list
// are left unset.
func parseRevocationList(der []byte) (*x509.RevocationList, error) {
	list, err := x509.ParseRevocationList(der)
	if err == nil {
		return list, nil
	}

	var v1 v1CertificateList
	if rest, v1Err := asn1.Unmarshal(der, &v1); v1Err != nil || len(rest) != 0 || v1.TBSCertList.Version != 0 {
		return nil, err
	}
	return v1.toRevocationList()
}

// toRevocationList returns the parts of l that revoke carries over, in the
// form x509.ParseRevocationList returns them.
func (l *v1CertificateList) toRevocationList() (*x509.RevocationList, error) {
	list := &x509.RevocationList{}
	for _, ext := range l.TBSCertList.Extensions {
		if ext.Id.Equal(oidExtensionCRLNumber) {
			if err := unmarshalExtension(ext, &list.Number); err != nil {
				return nil, fmt.Errorf("malformed CRL number in v1 CRL: %v", err)
			}
		}
	}

	for _, revoked := range l.TBSCertList.RevokedCertificates {
		entry := x509.RevocationListEntry{
			SerialNumber:   revoked.SerialNumber,
			RevocationTime: revoked.RevocationTime,
			Extensions:     revoked.Extensions,
		}
		for _, ext := range revoked.Extensions {
			if ext.Id.Equal(oidExtensionReasonCode) {
				var reason asn1.Enumerated
				if err := unmarshalExtension(ext, &reason); err != nil {
					return nil, fmt.Errorf("malformed reason code in v1 CRL: %v", err)
				}
				entry.ReasonCode = int(reason)
			}
		}
		list.RevokedCertificateEntries = append(list.RevokedCertificateEntries, entry)
	}
	return list, nil
}

func unmarshalExtension(ext x509pkix.Extension, value any) error {
	rest, err := asn1.Unmarshal(ext.Value, value)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	return nil
}

// nextRevocationList returns the template for the CRL that replaces current
// once serial is revoked at now. The existing entries are kept in order, with
// their revocation times, reason codes and other extensions, and the new entry
// is appended. The CRL number is one more than current's, or 1 if current has
// none (as with CRLs written before certstrap numbered them) or a negative one.
//
// Reason codes are normalized rather than copied byte for byte, because
// x509.CreateRevocationList writes the reason code extension itself: an
// explicit unspecified (0) reason code is omitted, as RFC 5280 section 5.3.1
// recommends, and any other reason code is re-encoded as a non-critical
// extension after the entry's other extensions, which can change their order.
func nextRevocationList(current *x509.RevocationList, serial *big.Int, now time.Time) *x509.RevocationList {
	return nextRevocationListFor(current, &x509.RevocationListEntry{
		SerialNumber:   serial,
		RevocationTime: now,
	}, false, now)
}

// nextRevocationListFor returns the template for the CRL that replaces current.
// When remove is false, entry is appended after the existing entries. When
// remove is true, every existing entry with the same serial number is dropped
// instead, which is how removeFromCRL is represented in a complete CRL.
//
// A nil current is treated as an empty CRL, which is how revoke creates a CRL
// for a CA whose depot predates init's empty CRL.
func nextRevocationListFor(current *x509.RevocationList, entry *x509.RevocationListEntry, remove bool, now time.Time) *x509.RevocationList {
	if current == nil {
		current = &x509.RevocationList{}
	}

	entries := make([]x509.RevocationListEntry, 0, len(current.RevokedCertificateEntries)+1)
	for _, existing := range current.RevokedCertificateEntries {
		if remove && entry != nil && entry.SerialNumber != nil && existing.SerialNumber != nil && existing.SerialNumber.Cmp(entry.SerialNumber) == 0 {
			continue
		}
		extra := existing.ExtraExtensions
		if len(extra) == 0 {
			extra = existing.Extensions
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   existing.SerialNumber,
			RevocationTime: existing.RevocationTime,
			// x509.CreateRevocationList encodes the reason code extension
			// itself, and rejects it in ExtraExtensions.
			ReasonCode:      existing.ReasonCode,
			ExtraExtensions: withoutExtension(extra, oidExtensionReasonCode),
		})
	}
	if !remove && entry != nil {
		extra := entry.ExtraExtensions
		if len(extra) == 0 {
			extra = entry.Extensions
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   entry.SerialNumber,
			RevocationTime: entry.RevocationTime,
			ReasonCode:     entry.ReasonCode,
			// The reason code is always written from ReasonCode.
			ExtraExtensions: withoutExtension(extra, oidExtensionReasonCode),
		})
	}

	number := big.NewInt(1)
	if current.Number != nil && current.Number.Sign() > 0 {
		number.Add(current.Number, number)
	}

	return &x509.RevocationList{
		RevokedCertificateEntries: entries,
		Number:                    number,
		ThisUpdate:                now,
		NextUpdate:                now.Add(crlValidity),
	}
}

func withoutExtension(extensions []x509pkix.Extension, id asn1.ObjectIdentifier) []x509pkix.Extension {
	var kept []x509pkix.Extension
	for _, ext := range extensions {
		if !ext.Id.Equal(id) {
			kept = append(kept, ext)
		}
	}
	return kept
}
