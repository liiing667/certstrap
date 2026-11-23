//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package cmd

import (
	"flag"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli"
)

func newRevokeContextUID34386(t *testing.T, cn string, extra ...string) *cli.Context {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("CA", "", "")
	fs.String("CN", "", "")
	fs.String("passphrase", "", "")
	fs.String("reason", "", "")
	fs.String("revocation-reason", "", "")
	fs.String("date", "", "")
	fs.String("revocation-date", "", "")
	args := append([]string{"-CA", caName, "-CN", cn}, extra...)
	if err := fs.Parse(args); err != nil {
		t.Fatal("could not parse flags")
	}
	return cli.NewContext(nil, fs, nil)
}

func runRevokeErrUID34386(t *testing.T, cn string, extra ...string) error {
	t.Helper()
	return new(revokeCommand).runRevoke(newRevokeContextUID34386(t, cn, extra...))
}

// TestRevokeGenerationReasonDateRemoveUID34386 covers reason/date generation,
// preserving existing entries and values, duplicate revocations and
// removeFromCRL.
func TestRevokeGenerationReasonDateRemoveUID34386(t *testing.T) {
	setupDepot(t)
	setupCA(t, d, func() (*pkix.Key, error) { return pkix.CreateRSAKey(2048) })
	setupCN(t, d, cnName)
	setupCN(t, d, "cn2")

	revocationTime := time.Date(2020, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := runRevokeErrUID34386(t, cnName, "-reason", "keyCompromise", "-date", revocationTime.Format(time.RFC3339)); err != nil {
		t.Fatal("could not revoke certificate:", err)
	}
	list := revocationListFromDepot(t)
	assertRevoked(t, list, big.NewInt(2), cnName)
	if entry := list.RevokedCertificateEntries[0]; entry.ReasonCode != 1 || !entry.RevocationTime.Equal(revocationTime) {
		t.Fatalf("entry = (reason %d, date %v), want (reason 1, date %v)", entry.ReasonCode, entry.RevocationTime, revocationTime)
	}

	if err := runRevokeErrUID34386(t, "cn2"); err != nil {
		t.Fatal("could not revoke cn2:", err)
	}
	list = revocationListFromDepot(t)
	assertRevoked(t, list, big.NewInt(3), cnName, "cn2")
	if entry := list.RevokedCertificateEntries[0]; entry.ReasonCode != 1 || !entry.RevocationTime.Equal(revocationTime) {
		t.Fatalf("existing entry changed to (reason %d, date %v)", entry.ReasonCode, entry.RevocationTime)
	}

	if err := runRevokeErrUID34386(t, cnName); err != nil {
		t.Fatal("could not revoke duplicate:", err)
	}
	list = revocationListFromDepot(t)
	assertRevoked(t, list, big.NewInt(4), cnName, "cn2", cnName)

	if err := runRevokeErrUID34386(t, cnName, "-reason", "removeFromCRL"); err != nil {
		t.Fatal("could not removeFromCRL:", err)
	}
	list = revocationListFromDepot(t)
	assertRevoked(t, list, big.NewInt(5), "cn2")
}

// TestRevokeGenerationFirstCRLUID34386 covers a depot without init's empty CRL.
func TestRevokeGenerationFirstCRLUID34386(t *testing.T) {
	setupDepot(t)
	setupCA(t, d, func() (*pkix.Key, error) { return pkix.CreateRSAKey(2048) })
	setupCN(t, d, cnName)
	if err := d.Delete(depot.CrlTag(caName)); err != nil {
		t.Fatal("could not delete CRL:", err)
	}

	if err := runRevokeErrUID34386(t, cnName); err != nil {
		t.Fatal("could not create first CRL:", err)
	}
	assertRevoked(t, revocationListFromDepot(t), big.NewInt(1), cnName)
}

// TestRevokeGenerationCommitFailureUID34386 makes the second CRL write fail
// and checks that the previous complete CRL survives and the retry uses its
// number and entries.
func TestRevokeGenerationCommitFailureUID34386(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory write permissions are not enforceable")
	}

	setupDepot(t)
	setupCA(t, d, func() (*pkix.Key, error) { return pkix.CreateRSAKey(2048) })
	setupCN(t, d, cnName)
	setupCN(t, d, "cn2")
	if err := runRevokeErrUID34386(t, cnName); err != nil {
		t.Fatal("could not revoke first certificate:", err)
	}
	before := revocationListFromDepot(t)

	if err := os.Chmod(d.Dir(), 0555); err != nil {
		t.Fatal("could not make depot read-only:", err)
	}
	defer func() { _ = os.Chmod(d.Dir(), 0755) }()

	err := runRevokeErrUID34386(t, "cn2")
	if err == nil {
		t.Fatal("revocation succeeded with a read-only depot")
	}
	for _, want := range []string{"stage=commit-crl", "serial=", "reason=", "CRL number=3"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}

	if err := os.Chmod(d.Dir(), 0755); err != nil {
		t.Fatal("could not make depot writable:", err)
	}
	after := revocationListFromDepot(t)
	assertRevoked(t, after, before.Number, cnName)
	if !after.RevokedCertificateEntries[0].RevocationTime.Equal(before.RevokedCertificateEntries[0].RevocationTime) {
		t.Fatal("failed revocation changed the existing entry")
	}

	if err := runRevokeErrUID34386(t, "cn2"); err != nil {
		t.Fatal("could not retry revocation:", err)
	}
	assertRevoked(t, revocationListFromDepot(t), big.NewInt(3), cnName, "cn2")
}

// TestRevokeGenerationInvalidInputUID34386 checks that invalid reason and date
// values fail without publishing a different CRL.
func TestRevokeGenerationInvalidInputUID34386(t *testing.T) {
	setupDepot(t)
	setupCA(t, d, func() (*pkix.Key, error) { return pkix.CreateRSAKey(2048) })
	setupCN(t, d, cnName)
	if err := runRevokeErrUID34386(t, cnName); err != nil {
		t.Fatal("could not revoke first certificate:", err)
	}
	before, err := depot.GetCertificateRevocationList(d, caName)
	if err != nil {
		t.Fatal("could not get CRL:", err)
	}

	if err := runRevokeErrUID34386(t, "cn2", "-reason", "bogus"); err == nil {
		t.Fatal("revoked with an invalid reason")
	}
	if err := runRevokeErrUID34386(t, "cn2", "-date", time.Now().Add(time.Hour).Format(time.RFC3339)); err == nil {
		t.Fatal("revoked with a future date")
	}

	after, err := depot.GetCertificateRevocationList(d, caName)
	if err != nil {
		t.Fatal("could not get CRL after invalid input:", err)
	}
	if string(before.DERBytes()) != string(after.DERBytes()) {
		t.Fatal("CRL changed after invalid input")
	}
}

// TestRevokeGenerationConcurrentUID34386 checks that concurrent revocations
// both end up in one CRL generation instead of overwriting each other.
func TestRevokeGenerationConcurrentUID34386(t *testing.T) {
	setupDepot(t)
	setupCA(t, d, func() (*pkix.Key, error) { return pkix.CreateRSAKey(2048) })
	setupCN(t, d, cnName)
	setupCN(t, d, "cn2")

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, cn := range []string{cnName, "cn2"} {
		ctx := newRevokeContextUID34386(t, cn)
		wg.Add(1)
		go func(ctx *cli.Context) {
			defer wg.Done()
			errs <- new(revokeCommand).runRevoke(ctx)
		}(ctx)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("concurrent revocation failed:", err)
		}
	}

	list := revocationListFromDepot(t)
	if list.Number == nil || list.Number.Cmp(big.NewInt(3)) != 0 {
		t.Fatalf("CRL number = %v, want 3", list.Number)
	}
	if len(list.RevokedCertificateEntries) != 2 {
		t.Fatalf("got %d revoked certificates, want 2", len(list.RevokedCertificateEntries))
	}
	got := []string{
		list.RevokedCertificateEntries[0].SerialNumber.String(),
		list.RevokedCertificateEntries[1].SerialNumber.String(),
	}
	want := []string{certificateSerial(t, cnName).String(), certificateSerial(t, "cn2").String()}
	sort.Strings(got)
	sort.Strings(want)
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("revoked serials = %v, want %v", got, want)
	}
}
