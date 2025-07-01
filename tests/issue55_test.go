package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leifj/signedxml"

	"github.com/stretchr/testify/require"
)

func TestIssue55(t *testing.T) {
	xml, err := os.ReadFile(filepath.Join("testdata", "issue55.xml"))
	require.NoError(t, err)

	signer, err := signedxml.NewSigner(string(xml))
	require.NoError(t, err)

	// Sign
	key := PrivateKey(t)
	xmlStr, err := signer.Sign(key)
	require.NoError(t, err)

	// Validate
	validator, err := signedxml.NewValidator(xmlStr)
	require.NoError(t, err)

	cert := TestCertificate(t)
	validator.Certificates = append(validator.Certificates, *cert)

	refs, err := validator.ValidateReferences()
	require.Contains(t, err.Error(), "does not match the expected digestvalue of")
	require.Len(t, refs, 0)
}
