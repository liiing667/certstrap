package pkix

import (
	"crypto/elliptic"
	"testing"
	"time"
)

func TestUID34387KeyIdentityValidationRejectsMixedKey(t *testing.T) {
	rsaKey, err := CreateRSAKey(1024)
	if err != nil {
		t.Fatal("create RSA key:", err)
	}
	ecdsaKey, err := CreateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatal("create ECDSA key:", err)
	}

	mixed := NewKey(ecdsaKey.Public, rsaKey.Private)
	if err := mixed.Validate(); err == nil {
		t.Fatal("mixed algorithm key passed validation")
	}
	if _, err := mixed.ExportPrivate(); err == nil {
		t.Fatal("mixed algorithm key exported as private PEM")
	}
	if _, err := mixed.ExportEncryptedPrivate([]byte("passphrase")); err == nil {
		t.Fatal("mixed algorithm key exported as encrypted private PEM")
	}
	if crt, err := CreateCertificateAuthority(mixed, "", time.Now().Add(time.Hour), "", "", "", "", "CA", nil); err == nil || crt != nil {
		t.Fatalf("mixed algorithm key created a CA: crt=%v err=%v", crt, err)
	}
}

func TestUID34387KeyIdentityDerivesMissingPublicHalf(t *testing.T) {
	rsaKey, err := CreateRSAKey(1024)
	if err != nil {
		t.Fatal("create RSA key:", err)
	}
	key := NewKey(nil, rsaKey.Private)
	if err := key.Validate(); err != nil {
		t.Fatalf("key with derived public half failed validation: %v", err)
	}
	if _, err := key.ExportPrivate(); err != nil {
		t.Fatalf("key with derived public half failed export: %v", err)
	}
}

func TestUID34387CertificateConsumersRejectMismatchedKey(t *testing.T) {
	caKey, err := CreateRSAKey(1024)
	if err != nil {
		t.Fatal("create CA key:", err)
	}
	caCert, err := CreateCertificateAuthority(caKey, "", time.Now().AddDate(1, 0, 0), "", "", "", "", "CA", nil)
	if err != nil {
		t.Fatal("create CA certificate:", err)
	}

	otherKey, err := CreateECDSAKey(elliptic.P256())
	if err != nil {
		t.Fatal("create other key:", err)
	}
	csr, err := CreateCertificateSigningRequest(otherKey, "", nil, nil, nil, "", "", "", "", "host")
	if err != nil {
		t.Fatal("create CSR:", err)
	}

	if crt, err := CreateCertificateHost(caCert, otherKey, csr, time.Now().Add(time.Hour)); err == nil || crt != nil {
		t.Fatalf("mismatched key created a host certificate: crt=%v err=%v", crt, err)
	}
	if crl, err := CreateCertificateRevocationList(otherKey, caCert, time.Now().Add(time.Hour)); err == nil || crl != nil {
		t.Fatalf("mismatched key created a CRL: crl=%v err=%v", crl, err)
	}
	if crt, err := CreateIntermediateCertificateAuthority(caCert, otherKey, csr, time.Now().Add(time.Hour)); err == nil || crt != nil {
		t.Fatalf("mismatched key created an intermediate: crt=%v err=%v", crt, err)
	}
}
