package xmlenc

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestAESKeyWrapUnwrap(t *testing.T) {
	// Test vectors from RFC 3394 Section 4.1
	// These are the official test vectors for validating AES Key Wrap implementations
	testCases := []struct {
		name       string
		kek        string // hex encoded
		plaintext  string // hex encoded
		ciphertext string // hex encoded
	}{
		{
			name:       "128-bit KEK with 128-bit data",
			kek:        "000102030405060708090A0B0C0D0E0F",
			plaintext:  "00112233445566778899AABBCCDDEEFF",
			ciphertext: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{
			name:       "192-bit KEK with 128-bit data",
			kek:        "000102030405060708090A0B0C0D0E0F1011121314151617",
			plaintext:  "00112233445566778899AABBCCDDEEFF",
			ciphertext: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		{
			name:       "256-bit KEK with 128-bit data",
			kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			plaintext:  "00112233445566778899AABBCCDDEEFF",
			ciphertext: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
		},
		{
			name:       "192-bit KEK with 192-bit data",
			kek:        "000102030405060708090A0B0C0D0E0F1011121314151617",
			plaintext:  "00112233445566778899AABBCCDDEEFF0001020304050607",
			ciphertext: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
		},
		{
			name:       "256-bit KEK with 256-bit data",
			kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			plaintext:  "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			ciphertext: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kek, _ := hex.DecodeString(tc.kek)
			plaintext, _ := hex.DecodeString(tc.plaintext)
			expectedCiphertext, _ := hex.DecodeString(tc.ciphertext)

			// Test wrap
			ciphertext, err := AESKeyWrap(kek, plaintext)
			if err != nil {
				t.Fatalf("AESKeyWrap failed: %v", err)
			}
			if !bytes.Equal(ciphertext, expectedCiphertext) {
				t.Errorf("AESKeyWrap mismatch:\ngot:  %X\nwant: %X", ciphertext, expectedCiphertext)
			}

			// Test unwrap
			unwrapped, err := AESKeyUnwrap(kek, ciphertext)
			if err != nil {
				t.Fatalf("AESKeyUnwrap failed: %v", err)
			}
			if !bytes.Equal(unwrapped, plaintext) {
				t.Errorf("AESKeyUnwrap mismatch:\ngot:  %X\nwant: %X", unwrapped, plaintext)
			}
		})
	}
}

func TestAESKeyWrapErrors(t *testing.T) {
	validKEK := make([]byte, 16)
	validPlaintext := make([]byte, 16)

	// Invalid KEK size
	_, err := AESKeyWrap(make([]byte, 15), validPlaintext)
	if err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize, got: %v", err)
	}

	// Invalid plaintext size (too small)
	_, err = AESKeyWrap(validKEK, make([]byte, 8))
	if err != ErrInvalidPlaintextSize {
		t.Errorf("expected ErrInvalidPlaintextSize, got: %v", err)
	}

	// Invalid plaintext size (not multiple of 8)
	_, err = AESKeyWrap(validKEK, make([]byte, 17))
	if err != ErrInvalidPlaintextSize {
		t.Errorf("expected ErrInvalidPlaintextSize, got: %v", err)
	}
}

func TestAESKeyUnwrapErrors(t *testing.T) {
	validKEK := make([]byte, 16)

	// Invalid KEK size
	_, err := AESKeyUnwrap(make([]byte, 15), make([]byte, 24))
	if err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize, got: %v", err)
	}

	// Invalid ciphertext size (too small)
	_, err = AESKeyUnwrap(validKEK, make([]byte, 16))
	if err != ErrInvalidCiphertextSize {
		t.Errorf("expected ErrInvalidCiphertextSize, got: %v", err)
	}

	// Integrity check failure (corrupted ciphertext)
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	ciphertext, _ := AESKeyWrap(kek, plaintext)
	ciphertext[0] ^= 0xFF // Corrupt the first byte
	_, err = AESKeyUnwrap(kek, ciphertext)
	if err != ErrIntegrityCheckFailed {
		t.Errorf("expected ErrIntegrityCheckFailed, got: %v", err)
	}
}

func TestAESKeyWrapRoundTrip(t *testing.T) {
	keySizes := []int{16, 24, 32}
	dataSizes := []int{16, 24, 32, 40, 48, 64, 128}

	for _, keySize := range keySizes {
		for _, dataSize := range dataSizes {
			t.Run("", func(t *testing.T) {
				kek := make([]byte, keySize)
				plaintext := make([]byte, dataSize)
				rand.Read(kek)
				rand.Read(plaintext)

				ciphertext, err := AESKeyWrap(kek, plaintext)
				if err != nil {
					t.Fatalf("wrap failed: %v", err)
				}

				// Ciphertext should be 8 bytes longer
				if len(ciphertext) != len(plaintext)+8 {
					t.Errorf("wrong ciphertext length: got %d, want %d", len(ciphertext), len(plaintext)+8)
				}

				unwrapped, err := AESKeyUnwrap(kek, ciphertext)
				if err != nil {
					t.Fatalf("unwrap failed: %v", err)
				}

				if !bytes.Equal(unwrapped, plaintext) {
					t.Error("round-trip failed: plaintext mismatch")
				}
			})
		}
	}
}

func TestAESGCMRoundTrip(t *testing.T) {
	keySizes := []int{16, 24, 32}

	for _, keySize := range keySizes {
		t.Run("", func(t *testing.T) {
			key := make([]byte, keySize)
			plaintext := []byte("Hello, World! This is a test message for AES-GCM encryption.")
			additionalData := []byte("additional authenticated data")

			rand.Read(key)

			ciphertext, err := AESGCMEncrypt(key, plaintext, additionalData)
			if err != nil {
				t.Fatalf("AESGCMEncrypt failed: %v", err)
			}

			decrypted, err := AESGCMDecrypt(key, ciphertext, additionalData)
			if err != nil {
				t.Fatalf("AESGCMDecrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Error("round-trip failed: plaintext mismatch")
			}
		})
	}
}

func TestAESGCMAuthenticationFailure(t *testing.T) {
	key := make([]byte, 16)
	plaintext := []byte("test message")
	rand.Read(key)

	ciphertext, err := AESGCMEncrypt(key, plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Corrupt the ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = AESGCMDecrypt(key, ciphertext, nil)
	if err == nil {
		t.Error("expected authentication failure")
	}
}

func TestAESCBCRoundTrip(t *testing.T) {
	keySizes := []int{16, 24, 32}
	plaintexts := []string{
		"A",
		"Hello",
		"Hello, World!",
		"Exactly16bytes!!", // Exactly one block
		"This is a much longer test message that spans multiple AES blocks.",
	}

	for _, keySize := range keySizes {
		for _, pt := range plaintexts {
			t.Run("", func(t *testing.T) {
				key := make([]byte, keySize)
				plaintext := []byte(pt)
				rand.Read(key)

				ciphertext, err := AESCBCEncrypt(key, plaintext)
				if err != nil {
					t.Fatalf("AESCBCEncrypt failed: %v", err)
				}

				decrypted, err := AESCBCDecrypt(key, ciphertext)
				if err != nil {
					t.Fatalf("AESCBCDecrypt failed: %v", err)
				}

				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("round-trip failed:\ngot:  %q\nwant: %q", decrypted, plaintext)
				}
			})
		}
	}
}

func BenchmarkAESKeyWrap(b *testing.B) {
	kek := make([]byte, 32)
	plaintext := make([]byte, 32)
	rand.Read(kek)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESKeyWrap(kek, plaintext)
	}
}

func BenchmarkAESKeyUnwrap(b *testing.B) {
	kek := make([]byte, 32)
	plaintext := make([]byte, 32)
	rand.Read(kek)
	rand.Read(plaintext)
	ciphertext, _ := AESKeyWrap(kek, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESKeyUnwrap(kek, ciphertext)
	}
}

func BenchmarkAESGCMEncrypt(b *testing.B) {
	key := make([]byte, 16)
	plaintext := make([]byte, 1024)
	rand.Read(key)
	rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESGCMEncrypt(key, plaintext, nil)
	}
}
