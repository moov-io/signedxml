package signedxml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestIsECDSAAlgorithm(t *testing.T) {
	tests := []struct {
		alg  x509.SignatureAlgorithm
		want bool
	}{
		{x509.ECDSAWithSHA1, true},
		{x509.ECDSAWithSHA256, true},
		{x509.ECDSAWithSHA384, true},
		{x509.ECDSAWithSHA512, true},
		{x509.SHA256WithRSA, false},
		{x509.SHA256WithRSAPSS, false},
		{x509.PureEd25519, false},
	}
	for _, tt := range tests {
		if got := isECDSAAlgorithm(tt.alg); got != tt.want {
			t.Errorf("isECDSAAlgorithm(%v) = %v, want %v", tt.alg, got, tt.want)
		}
	}
}

func TestConvertECDSARawToASN1(t *testing.T) {
	t.Run("P256_roundtrip", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("test data for ECDSA signature")
		r, s, err := ecdsa.Sign(rand.Reader, key, msg)
		if err != nil {
			t.Fatal(err)
		}

		// Build raw r||s (32 bytes each for P-256)
		raw := make([]byte, 64)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(raw[32-len(rBytes):32], rBytes)
		copy(raw[64-len(sBytes):64], sBytes)

		der, err := convertECDSARawToASN1(raw)
		if err != nil {
			t.Fatal(err)
		}

		// Parse back and verify r, s match
		var parsed struct{ R, S *big.Int }
		_, err = asn1.Unmarshal(der, &parsed)
		if err != nil {
			t.Fatalf("failed to unmarshal DER: %v", err)
		}
		if parsed.R.Cmp(r) != 0 {
			t.Errorf("r mismatch: got %v, want %v", parsed.R, r)
		}
		if parsed.S.Cmp(s) != 0 {
			t.Errorf("s mismatch: got %v, want %v", parsed.S, s)
		}

		// Verify with Go's ecdsa.Verify using the DER-decoded values
		if !ecdsa.Verify(&key.PublicKey, msg, parsed.R, parsed.S) {
			t.Error("signature verification failed after roundtrip")
		}
	})

	t.Run("P384_roundtrip", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("test P384")
		r, s, err := ecdsa.Sign(rand.Reader, key, msg)
		if err != nil {
			t.Fatal(err)
		}

		raw := make([]byte, 96)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(raw[48-len(rBytes):48], rBytes)
		copy(raw[96-len(sBytes):96], sBytes)

		der, err := convertECDSARawToASN1(raw)
		if err != nil {
			t.Fatal(err)
		}

		var parsed struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &parsed); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if !ecdsa.Verify(&key.PublicKey, msg, parsed.R, parsed.S) {
			t.Error("P-384 signature verification failed after roundtrip")
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		_, err := convertECDSARawToASN1([]byte{})
		if err == nil {
			t.Error("expected error for empty input")
		}
	})

	t.Run("odd_length", func(t *testing.T) {
		_, err := convertECDSARawToASN1(make([]byte, 63))
		if err == nil {
			t.Error("expected error for odd-length input")
		}
	})
}
