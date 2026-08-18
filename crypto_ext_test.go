package signedxml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/sirosfoundation/go-cryptoutil"
)

func TestSetCryptoExtensions(t *testing.T) {
	v, _ := NewValidator("")
	if v.cryptoExt != nil {
		t.Error("cryptoExt should be nil initially")
	}

	ext := cryptoutil.New()
	v.SetCryptoExtensions(ext)
	if v.cryptoExt != ext {
		t.Error("SetCryptoExtensions did not set the extensions")
	}

	v.SetCryptoExtensions(nil)
	if v.cryptoExt != nil {
		t.Error("SetCryptoExtensions(nil) should clear extensions")
	}
}

func TestParseCertificateWithoutExtensions(t *testing.T) {
	v, _ := NewValidator("")

	cert := generateTestCert(t)
	b64 := base64.StdEncoding.EncodeToString(cert.Raw)

	parsed, err := v.parseCertificate(b64)
	if err != nil {
		t.Fatalf("parseCertificate failed: %v", err)
	}
	if parsed.Subject.CommonName != "test-cert" {
		t.Errorf("expected CN=test-cert, got %q", parsed.Subject.CommonName)
	}
}

func TestParseCertificateWithExtensions(t *testing.T) {
	v, _ := NewValidator("")
	ext := cryptoutil.New()
	v.SetCryptoExtensions(ext)

	cert := generateTestCert(t)
	b64 := base64.StdEncoding.EncodeToString(cert.Raw)

	parsed, err := v.parseCertificate(b64)
	if err != nil {
		t.Fatalf("parseCertificate with extensions failed: %v", err)
	}
	if parsed.Subject.CommonName != "test-cert" {
		t.Errorf("expected CN=test-cert, got %q", parsed.Subject.CommonName)
	}
}

func TestParseCertificateExtensionFallback(t *testing.T) {
	// Test that when stdlib fails, extensions are tried
	v, _ := NewValidator("")
	ext := cryptoutil.New()
	called := false
	ext.Parsers = append(ext.Parsers, func(der []byte) (*x509.Certificate, error) {
		called = true
		return &x509.Certificate{
			Subject: pkix.Name{CommonName: "extension-parsed"},
		}, nil
	})
	v.SetCryptoExtensions(ext)

	// Feed garbage that stdlib can't parse but our extension handles
	b64 := base64.StdEncoding.EncodeToString([]byte{0x30, 0x03, 0x01, 0x01, 0xFF})

	parsed, err := v.parseCertificate(b64)
	if err != nil {
		t.Fatalf("expected extension parser to handle it, got: %v", err)
	}
	if !called {
		t.Error("extension parser was not called")
	}
	if parsed.Subject.CommonName != "extension-parsed" {
		t.Errorf("expected CN=extension-parsed, got %q", parsed.Subject.CommonName)
	}
}

func TestParseCertificateInvalidBase64(t *testing.T) {
	v, _ := NewValidator("")
	_, err := v.parseCertificate("not valid base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
