package xmlenc

import (
	"bytes"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// MockKeyWrapper for testing without actual key agreement
type MockKeyWrapper struct {
	CEK []byte
}

func (m *MockKeyWrapper) WrapKey(cek []byte, wrapAlgorithm string) (*EncryptedKey, error) {
	m.CEK = cek
	return &EncryptedKey{
		EncryptedType: EncryptedType{
			EncryptionMethod: &EncryptionMethod{
				Algorithm: wrapAlgorithm,
			},
			CipherData: &CipherData{
				CipherValue: cek, // For testing, just store the CEK
			},
		},
	}, nil
}

func (m *MockKeyWrapper) UnwrapKey(ek *EncryptedKey) ([]byte, error) {
	return ek.CipherData.CipherValue, nil
}

func TestEncryptDecryptElement(t *testing.T) {
	// Create test XML
	doc := etree.NewDocument()
	root := doc.CreateElement("Root")
	sensitive := root.CreateElement("Sensitive")
	sensitive.CreateElement("Secret").SetText("Very confidential data")
	sensitive.CreateElement("Code").SetText("12345")

	// Create encryptor with mock key wrapper
	keyWrapper := &MockKeyWrapper{}
	encryptor := NewEncryptor(AlgorithmAES128GCM, keyWrapper)

	// Encrypt the sensitive element
	ed, err := encryptor.EncryptElement(sensitive)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Verify EncryptedData structure
	if ed.Type != TypeElement {
		t.Errorf("wrong type: %s", ed.Type)
	}
	if ed.EncryptionMethod == nil || ed.EncryptionMethod.Algorithm != AlgorithmAES128GCM {
		t.Error("wrong encryption method")
	}
	if ed.CipherData == nil || len(ed.CipherData.CipherValue) == 0 {
		t.Error("missing cipher data")
	}
	if ed.KeyInfo == nil || ed.KeyInfo.EncryptedKey == nil {
		t.Error("missing KeyInfo with EncryptedKey")
	}

	// Decrypt
	decryptor := NewDecryptor(keyWrapper)
	decryptedElem, err := decryptor.DecryptElement(ed)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify decrypted content
	if decryptedElem.Tag != "Sensitive" {
		t.Errorf("wrong root tag: %s", decryptedElem.Tag)
	}
	secretElem := decryptedElem.FindElement("./Secret")
	if secretElem == nil || secretElem.Text() != "Very confidential data" {
		t.Error("Secret element content mismatch")
	}
	codeElem := decryptedElem.FindElement("./Code")
	if codeElem == nil || codeElem.Text() != "12345" {
		t.Error("Code element content mismatch")
	}
}

func TestEncryptDecryptWithX25519(t *testing.T) {
	// Generate recipient key pair
	recipientPrivate, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}
	recipientPublic := recipientPrivate.PublicKey()

	// Create test XML
	doc := etree.NewDocument()
	root := doc.CreateElement("Message")
	root.CreateElement("To").SetText("recipient@example.com")
	payload := root.CreateElement("Payload")
	payload.CreateElement("Data").SetText("Secret payload data")

	// Create encryptor with X25519 key agreement
	hkdfParams := DefaultHKDFParams([]byte("XML Encryption Test"))
	senderKA, err := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	if err != nil {
		t.Fatalf("failed to create key agreement: %v", err)
	}

	encryptor := NewEncryptor(AlgorithmAES128GCM, senderKA)

	// Encrypt
	ed, err := encryptor.EncryptElement(payload)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Generate XML to verify structure
	edDoc := NewEncryptedDataDocument(ed)
	xmlStr, _ := edDoc.WriteToString()
	t.Logf("EncryptedData XML:\n%s", xmlStr)

	// Verify it has AgreementMethod
	if ed.KeyInfo == nil || ed.KeyInfo.EncryptedKey == nil {
		t.Fatal("missing EncryptedKey")
	}
	if ed.KeyInfo.EncryptedKey.KeyInfo == nil || ed.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod == nil {
		t.Fatal("missing AgreementMethod")
	}
	if ed.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.Algorithm != AlgorithmX25519 {
		t.Errorf("wrong agreement algorithm: %s", ed.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.Algorithm)
	}

	// Extract ephemeral public key for decryption
	ephemeralPubBytes := ed.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
	ephemeralPublic, err := ParseX25519PublicKey(ephemeralPubBytes)
	if err != nil {
		t.Fatalf("failed to parse ephemeral public key: %v", err)
	}

	// Create recipient key agreement for decryption
	recipientKA := NewX25519KeyAgreementForDecrypt(recipientPrivate, ephemeralPublic, hkdfParams)
	decryptor := NewDecryptor(recipientKA)

	// Decrypt
	decryptedElem, err := decryptor.DecryptElement(ed)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify content
	if decryptedElem.Tag != "Payload" {
		t.Errorf("wrong tag: %s", decryptedElem.Tag)
	}
	dataElem := decryptedElem.FindElement("./Data")
	if dataElem == nil || dataElem.Text() != "Secret payload data" {
		t.Error("decrypted content mismatch")
	}
}

func TestEncryptDecryptCBC(t *testing.T) {
	keyWrapper := &MockKeyWrapper{}
	encryptor := NewEncryptor(AlgorithmAES128CBC, keyWrapper)

	// Create test element
	doc := etree.NewDocument()
	elem := doc.CreateElement("TestData")
	elem.SetText("Test content for CBC encryption")

	// Encrypt
	ed, err := encryptor.EncryptElement(elem)
	if err != nil {
		t.Fatalf("CBC encryption failed: %v", err)
	}

	if ed.EncryptionMethod.Algorithm != AlgorithmAES128CBC {
		t.Errorf("wrong algorithm: %s", ed.EncryptionMethod.Algorithm)
	}

	// Decrypt
	decryptor := NewDecryptor(keyWrapper)
	decryptedElem, err := decryptor.DecryptElement(ed)
	if err != nil {
		t.Fatalf("CBC decryption failed: %v", err)
	}

	if decryptedElem.Tag != "TestData" {
		t.Errorf("wrong tag: %s", decryptedElem.Tag)
	}
	if decryptedElem.Text() != "Test content for CBC encryption" {
		t.Errorf("content mismatch: %s", decryptedElem.Text())
	}
}

func TestEncryptElementInPlace(t *testing.T) {
	// Create test document
	doc := etree.NewDocument()
	root := doc.CreateElement("Document")
	header := root.CreateElement("Header")
	header.SetText("Public header")
	body := root.CreateElement("Body")
	secret := body.CreateElement("Secret")
	secret.SetText("Confidential")
	footer := root.CreateElement("Footer")
	footer.SetText("Public footer")

	// Encrypt the Secret element in place
	keyWrapper := &MockKeyWrapper{}
	encryptor := NewEncryptor(AlgorithmAES128GCM, keyWrapper)

	err := EncryptElementInPlace(secret, encryptor)
	if err != nil {
		t.Fatalf("in-place encryption failed: %v", err)
	}

	// Verify document structure
	xmlStr, _ := doc.WriteToString()
	if !strings.Contains(xmlStr, "EncryptedData") {
		t.Error("document should contain EncryptedData")
	}
	if strings.Contains(xmlStr, "Confidential") {
		t.Error("plaintext should not be visible")
	}
	if !strings.Contains(xmlStr, "Public header") {
		t.Error("header should still be visible")
	}
	if !strings.Contains(xmlStr, "Public footer") {
		t.Error("footer should still be visible")
	}

	t.Logf("Document after encryption:\n%s", xmlStr)
}

func TestKeyWrapAlgorithmForContentAlgorithm(t *testing.T) {
	tests := []struct {
		content string
		wrap    string
	}{
		{AlgorithmAES128GCM, AlgorithmAES128KW},
		{AlgorithmAES192GCM, AlgorithmAES192KW},
		{AlgorithmAES256GCM, AlgorithmAES256KW},
		{AlgorithmAES128CBC, AlgorithmAES128KW},
		{AlgorithmAES256CBC, AlgorithmAES256KW},
	}

	for _, tc := range tests {
		result := KeyWrapAlgorithmForContentAlgorithm(tc.content)
		if result != tc.wrap {
			t.Errorf("KeyWrapAlgorithmForContentAlgorithm(%s) = %s, want %s", tc.content, result, tc.wrap)
		}
	}
}

func TestEncryptedDataXMLRoundTrip(t *testing.T) {
	// Create EncryptedData
	ed := &EncryptedData{
		EncryptedType: EncryptedType{
			ID:   "enc-1",
			Type: TypeElement,
			EncryptionMethod: &EncryptionMethod{
				Algorithm: AlgorithmAES128GCM,
			},
			KeyInfo: &KeyInfo{
				EncryptedKey: &EncryptedKey{
					EncryptedType: EncryptedType{
						EncryptionMethod: &EncryptionMethod{
							Algorithm: AlgorithmAES128KW,
						},
						CipherData: &CipherData{
							CipherValue: []byte("wrapped-key-data"),
						},
					},
				},
			},
			CipherData: &CipherData{
				CipherValue: []byte("encrypted-content"),
			},
		},
	}

	// Convert to XML
	doc := NewEncryptedDataDocument(ed)
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("failed to write XML: %v", err)
	}

	t.Logf("Generated XML:\n%s", string(xmlBytes))

	// Parse back
	parsedDoc := etree.NewDocument()
	if err := parsedDoc.ReadFromBytes(xmlBytes); err != nil {
		t.Fatalf("failed to parse XML: %v", err)
	}

	parsedED, err := ParseEncryptedData(parsedDoc.Root())
	if err != nil {
		t.Fatalf("failed to parse EncryptedData: %v", err)
	}

	// Verify
	if parsedED.ID != ed.ID {
		t.Errorf("ID mismatch: got %s, want %s", parsedED.ID, ed.ID)
	}
	if parsedED.Type != ed.Type {
		t.Errorf("Type mismatch: got %s, want %s", parsedED.Type, ed.Type)
	}
	if parsedED.EncryptionMethod.Algorithm != ed.EncryptionMethod.Algorithm {
		t.Errorf("Algorithm mismatch")
	}
	if !bytes.Equal(parsedED.CipherData.CipherValue, ed.CipherData.CipherValue) {
		t.Error("CipherValue mismatch")
	}
}

func BenchmarkEncryptElement(b *testing.B) {
	doc := etree.NewDocument()
	elem := doc.CreateElement("Data")
	elem.SetText(strings.Repeat("X", 1000))

	keyWrapper := &MockKeyWrapper{}
	encryptor := NewEncryptor(AlgorithmAES128GCM, keyWrapper)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptor.EncryptElement(elem)
	}
}

func BenchmarkDecryptElement(b *testing.B) {
	// Create and encrypt element
	doc := etree.NewDocument()
	elem := doc.CreateElement("Data")
	elem.SetText(strings.Repeat("X", 1000))

	keyWrapper := &MockKeyWrapper{}
	encryptor := NewEncryptor(AlgorithmAES128GCM, keyWrapper)
	ed, _ := encryptor.EncryptElement(elem)

	decryptor := NewDecryptor(keyWrapper)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptor.DecryptElement(ed)
	}
}

func BenchmarkX25519EncryptDecrypt(b *testing.B) {
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()
	hkdfParams := DefaultHKDFParams(nil)

	doc := etree.NewDocument()
	elem := doc.CreateElement("Data")
	elem.SetText(strings.Repeat("X", 1000))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Encrypt
		senderKA, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
		encryptor := NewEncryptor(AlgorithmAES128GCM, senderKA)
		ed, _ := encryptor.EncryptElement(elem)

		// Decrypt
		ephemeralPubBytes := ed.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
		ephemeralPublic, _ := ParseX25519PublicKey(ephemeralPubBytes)
		recipientKA := NewX25519KeyAgreementForDecrypt(recipientPrivate, ephemeralPublic, hkdfParams)
		decryptor := NewDecryptor(recipientKA)
		decryptor.DecryptElement(ed)
	}
}
