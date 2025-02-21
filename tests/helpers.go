package tests

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCertificate(t *testing.T) *x509.Certificate {
	pemBytes, err := os.ReadFile(filepath.Join("..", "testdata", "rsa.crt"))
	require.NoError(t, err)

	pemBlock, _ := pem.Decode(pemBytes)

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	require.NoError(t, err)

	return cert
}

func PrivateKey(t *testing.T) *rsa.PrivateKey {
	b64Bytes, err := os.ReadFile(filepath.Join("..", "testdata", "rsa.key.b64"))
	require.NoError(t, err)

	pemString, err := base64.StdEncoding.DecodeString(string(b64Bytes))
	require.NoError(t, err)

	pemBlock, _ := pem.Decode([]byte(pemString))

	key, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	require.NoError(t, err)

	return key
}
