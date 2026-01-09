package xmlenc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestX25519KeyAgreementRoundTrip(t *testing.T) {
	// Generate recipient key pair
	curve := ecdh.X25519()
	recipientPrivate, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}
	recipientPublic := recipientPrivate.PublicKey()

	// Create content encryption key
	cek := make([]byte, 16) // AES-128
	rand.Read(cek)

	// Sender side: create key agreement and wrap CEK
	hkdfParams := DefaultHKDFParams([]byte("test info"))
	senderKA, err := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	if err != nil {
		t.Fatalf("failed to create sender key agreement: %v", err)
	}

	encryptedKey, err := senderKA.WrapKey(cek, AlgorithmAES128KW)
	if err != nil {
		t.Fatalf("failed to wrap key: %v", err)
	}

	// Verify EncryptedKey structure
	if encryptedKey.EncryptionMethod == nil || encryptedKey.EncryptionMethod.Algorithm != AlgorithmAES128KW {
		t.Error("wrong encryption method in EncryptedKey")
	}
	if encryptedKey.KeyInfo == nil || encryptedKey.KeyInfo.AgreementMethod == nil {
		t.Error("missing AgreementMethod in KeyInfo")
	}
	if encryptedKey.KeyInfo.AgreementMethod.Algorithm != AlgorithmX25519 {
		t.Error("wrong agreement method algorithm")
	}

	// Extract ephemeral public key from EncryptedKey
	ephemeralPubBytes := encryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
	ephemeralPublic, err := ParseX25519PublicKey(ephemeralPubBytes)
	if err != nil {
		t.Fatalf("failed to parse ephemeral public key: %v", err)
	}

	// Recipient side: recreate key agreement for decryption
	recipientKA := NewX25519KeyAgreementForDecrypt(recipientPrivate, ephemeralPublic, hkdfParams)

	// Unwrap the CEK
	decryptedCEK, err := recipientKA.UnwrapKey(encryptedKey)
	if err != nil {
		t.Fatalf("failed to unwrap key: %v", err)
	}

	// Verify the CEK matches
	if !bytes.Equal(decryptedCEK, cek) {
		t.Errorf("CEK mismatch:\ngot:  %x\nwant: %x", decryptedCEK, cek)
	}
}

func TestX25519DeriveKeyEncryptionKey(t *testing.T) {
	// Generate both parties' keys
	curve := ecdh.X25519()

	alicePrivate, _ := curve.GenerateKey(rand.Reader)
	alicePublic := alicePrivate.PublicKey()

	bobPrivate, _ := curve.GenerateKey(rand.Reader)
	bobPublic := bobPrivate.PublicKey()

	hkdfParams := &HKDFParams{
		PRF:       AlgorithmHMACSHA256,
		Salt:      []byte("test salt"),
		Info:      []byte("test info"),
		KeyLength: 256, // 256 bits
	}

	// Alice derives key using her private key and Bob's public key
	aliceKA := &X25519KeyAgreement{
		EphemeralPrivateKey: alicePrivate,
		RecipientPublicKey:  bobPublic,
		HKDFParams:          hkdfParams,
	}
	aliceKey, err := aliceKA.DeriveKeyEncryptionKey(32)
	if err != nil {
		t.Fatalf("Alice key derivation failed: %v", err)
	}

	// Bob derives key using his private key and Alice's public key
	bobKA := &X25519KeyAgreement{
		RecipientPrivateKey: bobPrivate,
		EphemeralPublicKey:  alicePublic,
		HKDFParams:          hkdfParams,
	}
	bobKey, err := bobKA.DeriveKeyEncryptionKey(32)
	if err != nil {
		t.Fatalf("Bob key derivation failed: %v", err)
	}

	// Both should derive the same key
	if !bytes.Equal(aliceKey, bobKey) {
		t.Errorf("derived keys don't match:\nAlice: %x\nBob:   %x", aliceKey, bobKey)
	}
}

func TestGenerateX25519KeyPair(t *testing.T) {
	privateKey, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	publicKey := privateKey.PublicKey()

	// X25519 keys should be 32 bytes
	if len(privateKey.Bytes()) != 32 {
		t.Errorf("private key wrong size: got %d, want 32", len(privateKey.Bytes()))
	}
	if len(publicKey.Bytes()) != 32 {
		t.Errorf("public key wrong size: got %d, want 32", len(publicKey.Bytes()))
	}
}

func TestParseX25519Keys(t *testing.T) {
	// Generate a key pair
	originalPrivate, _ := GenerateX25519KeyPair()
	originalPublic := originalPrivate.PublicKey()

	// Parse from bytes
	parsedPublic, err := ParseX25519PublicKey(originalPublic.Bytes())
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	parsedPrivate, err := ParseX25519PrivateKey(originalPrivate.Bytes())
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	// Verify they match
	if !bytes.Equal(parsedPublic.Bytes(), originalPublic.Bytes()) {
		t.Error("parsed public key doesn't match original")
	}
	if !bytes.Equal(parsedPrivate.Bytes(), originalPrivate.Bytes()) {
		t.Error("parsed private key doesn't match original")
	}
}

func TestEncryptedKeyXMLGeneration(t *testing.T) {
	// Generate recipient key
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	// Create and wrap a CEK
	cek := make([]byte, 16)
	rand.Read(cek)

	hkdfParams := DefaultHKDFParams([]byte("EU AS4 2.0"))
	ka, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	encryptedKey, _ := ka.WrapKey(cek, AlgorithmAES128KW)

	// Create a document wrapper for proper output
	doc := NewEncryptedKeyDocument(encryptedKey)
	xml, err := doc.WriteToString()
	if err != nil {
		t.Fatalf("failed to write XML: %v", err)
	}
	t.Logf("Generated XML:\n%s", xml)
}

func BenchmarkX25519KeyAgreement(b *testing.B) {
	curve := ecdh.X25519()
	recipientPrivate, _ := curve.GenerateKey(rand.Reader)
	recipientPublic := recipientPrivate.PublicKey()
	hkdfParams := DefaultHKDFParams(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ka, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
		ka.DeriveKeyEncryptionKey(16)
	}
}

func BenchmarkX25519WrapKey(b *testing.B) {
	curve := ecdh.X25519()
	recipientPrivate, _ := curve.GenerateKey(rand.Reader)
	recipientPublic := recipientPrivate.PublicKey()
	hkdfParams := DefaultHKDFParams(nil)
	cek := make([]byte, 16)
	rand.Read(cek)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ka, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
		ka.WrapKey(cek, AlgorithmAES128KW)
	}
}
