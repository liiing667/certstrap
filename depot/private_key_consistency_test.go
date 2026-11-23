package depot

import (
	"crypto/elliptic"
	"os"
	"testing"
	"time"

	"github.com/square/certstrap/pkix"
)

func newUID34387CAKeyAndCert(t *testing.T, key *pkix.Key) *pkix.Certificate {
	t.Helper()
	crt, err := pkix.CreateCertificateAuthority(key, "", time.Now().AddDate(1, 0, 0), "", "", "", "", "CA", nil)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	return crt
}

func TestUID34387DepotBindsStoredKeyToCertificate(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	rsaKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("create RSA key:", err)
	}
	crt := newUID34387CAKeyAndCert(t, rsaKey)
	if err := PutPrivateKey(d, "CA", rsaKey); err != nil {
		t.Fatalf("put RSA key: %v", err)
	}
	if err := PutCertificate(d, "CA", crt); err != nil {
		t.Fatalf("put matching certificate: %v", err)
	}

	info, err := os.Stat(d.path(PrivKeyTag("CA").name))
	if err != nil {
		t.Fatal("stat stored key:", err)
	}
	if info.Mode().Perm() != BranchPerm {
		t.Fatalf("stored key mode = %o, want %o", info.Mode().Perm(), BranchPerm)
	}

	if err := PutEncryptedPrivateKey(d, "CA", rsaKey, []byte("new-passphrase")); err != nil {
		t.Fatalf("re-encrypt matching RSA key: %v", err)
	}
	if _, err := GetEncryptedPrivateKey(d, "CA", []byte("new-passphrase")); err != nil {
		t.Fatalf("read re-encrypted RSA key: %v", err)
	}

	ecdsaKey, err := pkix.CreateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatal("create ECDSA key:", err)
	}
	if err := d.Delete(PrivKeyTag("CA")); err != nil {
		t.Fatal("delete RSA key:", err)
	}
	if err := PutPrivateKey(d, "CA", ecdsaKey); err == nil {
		t.Fatal("wrote an ECDSA key under an RSA certificate name")
	}
	if err := PutEncryptedPrivateKey(d, "CA", ecdsaKey, []byte("passphrase")); err == nil {
		t.Fatal("wrote an encrypted ECDSA key under an RSA certificate name")
	}

	if err := PutPrivateKey(d, "CA", rsaKey); err != nil {
		t.Fatalf("restore RSA key: %v", err)
	}
	if err := ReplacePrivateKey(d, "CA", ecdsaKey); err == nil {
		t.Fatal("replaced an RSA key with an ECDSA key while the certificate stayed RSA")
	}
	ecdsaCert := newUID34387CAKeyAndCert(t, ecdsaKey)
	if err := PutCertificate(d, "CA", ecdsaCert); err == nil {
		t.Fatal("replaced an RSA certificate with an ECDSA certificate while the stored key stayed RSA")
	}
	storedCert, err := GetCertificate(d, "CA")
	if err != nil {
		t.Fatalf("read certificate after rejected replacement: %v", err)
	}
	if err := storedCert.ValidateKey(rsaKey); err != nil {
		t.Fatalf("rejected certificate replacement changed the stored certificate: %v", err)
	}

	ecdsaPEM, err := ecdsaKey.ExportPrivate()
	if err != nil {
		t.Fatal("export ECDSA key:", err)
	}
	if err := d.Delete(PrivKeyTag("CA")); err != nil {
		t.Fatal("delete RSA key before overwrite:", err)
	}
	if err := os.WriteFile(d.path(PrivKeyTag("CA").name), ecdsaPEM, 0600); err != nil {
		t.Fatal("overwrite stored key:", err)
	}
	if err := os.Chmod(d.path(PrivKeyTag("CA").name), BranchPerm); err != nil {
		t.Fatal("restore stored key mode:", err)
	}
	if _, err := GetPrivateKey(d, "CA"); err == nil {
		t.Fatal("GetPrivateKey returned a key that does not match the stored certificate")
	}
}

func TestUID34387DepotMigratesMatchingKeyPairAtomically(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	rsaKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("create RSA key:", err)
	}
	rsaCert := newUID34387CAKeyAndCert(t, rsaKey)
	if err := PutPrivateKey(d, "CA", rsaKey); err != nil {
		t.Fatal("put RSA key:", err)
	}
	if err := PutCertificate(d, "CA", rsaCert); err != nil {
		t.Fatal("put RSA certificate:", err)
	}

	ecdsaKey, err := pkix.CreateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatal("create ECDSA key:", err)
	}
	ecdsaCert := newUID34387CAKeyAndCert(t, ecdsaKey)
	if err := ReplaceKeyPair(d, "CA", ecdsaKey, ecdsaCert, []byte("passphrase")); err != nil {
		t.Fatalf("migrate matching key pair: %v", err)
	}

	storedKey, err := GetEncryptedPrivateKey(d, "CA", []byte("passphrase"))
	if err != nil {
		t.Fatalf("read migrated key: %v", err)
	}
	storedCert, err := GetCertificate(d, "CA")
	if err != nil {
		t.Fatalf("read migrated certificate: %v", err)
	}
	if err := storedCert.ValidateKey(storedKey); err != nil {
		t.Fatalf("migrated key and certificate do not match: %v", err)
	}

	// A mismatched pair must fail before either file is published.
	otherKey, err := pkix.CreateECDSAKey(elliptic.P384())
	if err != nil {
		t.Fatal("create other key:", err)
	}
	if err := ReplaceKeyPair(d, "CA", otherKey, ecdsaCert, nil); err == nil {
		t.Fatal("migrated a mismatched key/certificate pair")
	}
	currentKey, err := GetEncryptedPrivateKey(d, "CA", []byte("passphrase"))
	if err != nil {
		t.Fatalf("read key after rejected migration: %v", err)
	}
	currentCert, err := GetCertificate(d, "CA")
	if err != nil {
		t.Fatalf("read certificate after rejected migration: %v", err)
	}
	if err := currentCert.ValidateKey(currentKey); err != nil {
		t.Fatalf("rejected migration changed the stored generation: %v", err)
	}
}

func TestUID34387PutKeyPairInTxnRejectsMismatch(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	rsaKey, err := pkix.CreateRSAKey(1024)
	if err != nil {
		t.Fatal("create RSA key:", err)
	}
	ecdsaKey, err := pkix.CreateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatal("create ECDSA key:", err)
	}
	ecdsaCert := newUID34387CAKeyAndCert(t, ecdsaKey)

	txn := NewTxn(d)
	if err := PutKeyPairInTxn(txn, "CA", rsaKey, ecdsaCert, nil); err == nil {
		t.Fatal("staged a mismatched key/certificate pair")
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("empty transaction commit: %v", err)
	}
	if CheckPrivateKey(d, "CA") || CheckCertificate(d, "CA") {
		t.Fatal("rejected key pair was published")
	}
}
