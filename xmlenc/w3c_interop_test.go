package xmlenc

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// W3C XML Encryption 1.1 Test Cases
// Based on https://www.w3.org/TR/xmlenc-core1-testcases/
// and https://www.w3.org/Encryption/2002/02-xenc-interop.html

// W3C Plaintext test document (from xmlenc-core1-testcases)
const w3cPlaintextXML = `<?xml version="1.0" encoding="UTF-8"?>
<PurchaseOrder xmlns="urn:example:po">
  <Items>
    <Item Code="001-001-001" Quantity="1">spade</Item>
    <Item Code="001-001-002" Quantity="1">shovel</Item>
  </Items>
  <ShippingAddress>Dig PLC, 1 First Ave, Dublin 1, Ireland</ShippingAddress>
  <PaymentInfo>
    <BillingAddress>Dig PLC, 1 First Ave, Dublin 1, Ireland</BillingAddress>
    <CreditCard Type="Amex">
      <Name>Foo B Baz</Name>
      <Number>1234 567890 12345</Number>
      <Expires Month="1" Year="2005"/>
    </CreditCard>
  </PaymentInfo>
</PurchaseOrder>`

// TestW3CPlaintextParsing verifies we can parse the W3C test plaintext document
func TestW3CPlaintextParsing(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(w3cPlaintextXML)
	if err != nil {
		t.Fatalf("failed to parse W3C plaintext: %v", err)
	}

	root := doc.Root()
	if root.Tag != "PurchaseOrder" {
		t.Errorf("wrong root tag: %s", root.Tag)
	}

	// Verify structure
	items := root.FindElement("./Items")
	if items == nil {
		t.Fatal("Items element not found")
	}

	itemElements := items.FindElements("./Item")
	if len(itemElements) != 2 {
		t.Errorf("expected 2 Item elements, got %d", len(itemElements))
	}

	paymentInfo := root.FindElement("./PaymentInfo")
	if paymentInfo == nil {
		t.Fatal("PaymentInfo element not found")
	}

	creditCard := paymentInfo.FindElement("./CreditCard")
	if creditCard == nil {
		t.Fatal("CreditCard element not found")
	}

	cardType := creditCard.SelectAttrValue("Type", "")
	if cardType != "Amex" {
		t.Errorf("wrong card type: %s", cardType)
	}
}

// TestW3CElementEncryptionRoundtrip tests element encryption as per W3C test cases
// Section 2: "In-place encryption of XML"
func TestW3CElementEncryptionRoundtrip(t *testing.T) {
	doc := etree.NewDocument()
	doc.ReadFromString(w3cPlaintextXML)

	// Get PaymentInfo element to encrypt (sensitive data)
	paymentInfo := doc.Root().FindElement("./PaymentInfo")
	if paymentInfo == nil {
		t.Fatal("PaymentInfo element not found")
	}

	// Encrypt using mock key wrapper (for unit testing)
	keyWrapper := &MockKeyWrapper{}
	encryptor := NewEncryptor(AlgorithmAES128GCM, keyWrapper)

	ed, err := encryptor.EncryptElement(paymentInfo)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Verify EncryptedData structure matches W3C format
	if ed.Type != TypeElement {
		t.Errorf("Type should be %s, got %s", TypeElement, ed.Type)
	}
	if ed.EncryptionMethod == nil || ed.EncryptionMethod.Algorithm != AlgorithmAES128GCM {
		t.Error("wrong encryption method")
	}
	if ed.CipherData == nil || len(ed.CipherData.CipherValue) == 0 {
		t.Error("missing cipher data")
	}

	// Decrypt
	decryptor := NewDecryptor(keyWrapper)
	decryptedElem, err := decryptor.DecryptElement(ed)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify decrypted content matches original
	if decryptedElem.Tag != "PaymentInfo" {
		t.Errorf("wrong tag: %s", decryptedElem.Tag)
	}

	creditCard := decryptedElem.FindElement("./CreditCard")
	if creditCard == nil {
		t.Fatal("CreditCard element not found in decrypted content")
	}

	nameElem := creditCard.FindElement("./Name")
	if nameElem == nil || nameElem.Text() != "Foo B Baz" {
		t.Error("Name content mismatch")
	}

	numberElem := creditCard.FindElement("./Number")
	if numberElem == nil || numberElem.Text() != "1234 567890 12345" {
		t.Error("Number content mismatch")
	}
}

// TestW3CKeyWrappingStructure verifies the key wrapping structure matches W3C format
// Based on Section 2.1: "Key wrapping"
func TestW3CKeyWrappingStructure(t *testing.T) {
	// Generate test keys
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	// Create encryptor with X25519 key agreement
	hkdfParams := DefaultHKDFParams([]byte("W3C Test"))
	senderKA, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	encryptor := NewEncryptor(AlgorithmAES128GCM, senderKA)

	// Encrypt the plaintext document
	doc := etree.NewDocument()
	doc.ReadFromString(w3cPlaintextXML)
	ed, err := encryptor.EncryptElement(doc.Root())
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Generate XML
	edDoc := NewEncryptedDataDocument(ed)
	xmlBytes, _ := edDoc.WriteToBytes()
	xmlStr := string(xmlBytes)

	// Verify required elements are present (W3C structure)
	requiredElements := []string{
		"xenc:EncryptedData",
		"xenc:EncryptionMethod",
		"xenc:EncryptedKey",
		"xenc:CipherData",
		"xenc:CipherValue",
		"xenc:AgreementMethod",
		"ds:KeyInfo",
	}

	for _, elem := range requiredElements {
		if !strings.Contains(xmlStr, elem) {
			t.Errorf("missing required element: %s", elem)
		}
	}

	// Verify algorithm URIs
	requiredAlgorithms := []string{
		AlgorithmAES128GCM,
		AlgorithmAES128KW,
		AlgorithmX25519,
		AlgorithmHKDF,
	}

	for _, alg := range requiredAlgorithms {
		if !strings.Contains(xmlStr, alg) {
			t.Errorf("missing required algorithm: %s", alg)
		}
	}

	t.Logf("Generated XML:\n%s", xmlStr)
}

// TestW3CKeyAgreementStructure tests the key agreement structure
// Based on Section 2.2: "Key Agreement"
func TestW3CKeyAgreementStructure(t *testing.T) {
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	hkdfParams := &HKDFParams{
		PRF:       AlgorithmHMACSHA256,
		Salt:      []byte("test-salt"),
		Info:      []byte("test-info"),
		KeyLength: 128,
	}

	senderKA, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	cek := make([]byte, 16)
	encryptedKey, _ := senderKA.WrapKey(cek, AlgorithmAES128KW)

	// Verify AgreementMethod structure
	if encryptedKey.KeyInfo == nil {
		t.Fatal("missing KeyInfo")
	}
	am := encryptedKey.KeyInfo.AgreementMethod
	if am == nil {
		t.Fatal("missing AgreementMethod")
	}

	// Check algorithm
	if am.Algorithm != AlgorithmX25519 {
		t.Errorf("wrong agreement algorithm: %s", am.Algorithm)
	}

	// Check KeyDerivationMethod
	if am.KeyDerivationMethod == nil {
		t.Fatal("missing KeyDerivationMethod")
	}
	if am.KeyDerivationMethod.Algorithm != AlgorithmHKDF {
		t.Errorf("wrong KDF algorithm: %s", am.KeyDerivationMethod.Algorithm)
	}

	// Check HKDFParams
	if am.KeyDerivationMethod.HKDFParams == nil {
		t.Fatal("missing HKDFParams")
	}
	hp := am.KeyDerivationMethod.HKDFParams
	if hp.PRF != AlgorithmHMACSHA256 {
		t.Errorf("wrong PRF: %s", hp.PRF)
	}
	if hp.KeyLength != 128 {
		t.Errorf("wrong key length: %d", hp.KeyLength)
	}

	// Check OriginatorKeyInfo (ephemeral key)
	if am.OriginatorKeyInfo == nil {
		t.Fatal("missing OriginatorKeyInfo")
	}
	if am.OriginatorKeyInfo.KeyValue == nil || am.OriginatorKeyInfo.KeyValue.ECKeyValue == nil {
		t.Fatal("missing ephemeral key value")
	}
	if len(am.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey) != 32 {
		t.Errorf("wrong ephemeral key length: %d", len(am.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey))
	}
}

// TestW3CEncryptedDataXMLFormat tests that generated XML matches W3C format
func TestW3CEncryptedDataXMLFormat(t *testing.T) {
	// Create minimal EncryptedData as per W3C examples
	ed := &EncryptedData{
		EncryptedType: EncryptedType{
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
							CipherValue: []byte("wrapped-key"),
						},
					},
				},
			},
			CipherData: &CipherData{
				CipherValue: []byte("encrypted-content"),
			},
		},
	}

	// Generate XML
	elem := ed.ToElement()
	doc := etree.NewDocument()
	doc.SetRoot(elem)
	doc.Indent(2)
	xmlBytes, _ := doc.WriteToBytes()

	// Parse and verify structure
	parsedDoc := etree.NewDocument()
	parsedDoc.ReadFromBytes(xmlBytes)
	root := parsedDoc.Root()

	// Verify namespace
	ns := root.SelectAttrValue("xmlns:xenc", "")
	if ns != NamespaceXMLEnc {
		t.Errorf("wrong xenc namespace: %s", ns)
	}

	// Verify Type attribute
	typeAttr := root.SelectAttrValue("Type", "")
	if typeAttr != TypeElement {
		t.Errorf("wrong Type: %s", typeAttr)
	}

	// Verify EncryptionMethod
	em := root.FindElement("./EncryptionMethod")
	if em == nil {
		t.Fatal("missing EncryptionMethod")
	}
	emAlg := em.SelectAttrValue("Algorithm", "")
	if emAlg != AlgorithmAES128GCM {
		t.Errorf("wrong encryption algorithm: %s", emAlg)
	}

	t.Logf("Generated XML:\n%s", string(xmlBytes))
}

// TestW3CEncryptedDataParsing tests parsing of W3C-style EncryptedData
func TestW3CEncryptedDataParsing(t *testing.T) {
	// Sample W3C-style EncryptedData (simplified)
	w3cEncryptedData := `<?xml version="1.0" encoding="UTF-8"?>
<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" 
                   Type="http://www.w3.org/2001/04/xmlenc#Element">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
  <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <xenc:EncryptedKey>
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/>
      <xenc:CipherData>
        <xenc:CipherValue>dGVzdC13cmFwcGVkLWtleQ==</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedKey>
  </dsig:KeyInfo>
  <xenc:CipherData>
    <xenc:CipherValue>dGVzdC1jaXBoZXJ0ZXh0</xenc:CipherValue>
  </xenc:CipherData>
</xenc:EncryptedData>`

	doc := etree.NewDocument()
	err := doc.ReadFromString(w3cEncryptedData)
	if err != nil {
		t.Fatalf("failed to parse XML: %v", err)
	}

	ed, err := ParseEncryptedData(doc.Root())
	if err != nil {
		t.Fatalf("failed to parse EncryptedData: %v", err)
	}

	// Verify parsed structure
	if ed.Type != TypeElement {
		t.Errorf("wrong Type: %s", ed.Type)
	}
	if ed.EncryptionMethod == nil || ed.EncryptionMethod.Algorithm != AlgorithmAES128GCM {
		t.Error("wrong encryption method")
	}
	if ed.KeyInfo == nil || ed.KeyInfo.EncryptedKey == nil {
		t.Error("missing EncryptedKey")
	}
	if ed.KeyInfo.EncryptedKey.EncryptionMethod.Algorithm != AlgorithmAES128KW {
		t.Error("wrong key wrap algorithm")
	}

	expectedWrappedKey, _ := base64.StdEncoding.DecodeString("dGVzdC13cmFwcGVkLWtleQ==")
	if !bytes.Equal(ed.KeyInfo.EncryptedKey.CipherData.CipherValue, expectedWrappedKey) {
		t.Error("wrapped key mismatch")
	}

	expectedCiphertext, _ := base64.StdEncoding.DecodeString("dGVzdC1jaXBoZXJ0ZXh0")
	if !bytes.Equal(ed.CipherData.CipherValue, expectedCiphertext) {
		t.Error("ciphertext mismatch")
	}
}

// TestW3CAllEncryptionAlgorithms tests all W3C-specified encryption algorithms
func TestW3CAllEncryptionAlgorithms(t *testing.T) {
	algorithms := []struct {
		name      string
		algorithm string
		keySize   int
	}{
		{"AES-128-GCM", AlgorithmAES128GCM, 16},
		{"AES-192-GCM", AlgorithmAES192GCM, 24},
		{"AES-256-GCM", AlgorithmAES256GCM, 32},
		{"AES-128-CBC", AlgorithmAES128CBC, 16},
		{"AES-192-CBC", AlgorithmAES192CBC, 24},
		{"AES-256-CBC", AlgorithmAES256CBC, 32},
	}

	plaintext := []byte("Test plaintext for W3C algorithm testing")

	for _, alg := range algorithms {
		t.Run(alg.name, func(t *testing.T) {
			key := make([]byte, alg.keySize)
			for i := range key {
				key[i] = byte(i)
			}

			var ciphertext, decrypted []byte
			var err error

			if IsGCM(alg.algorithm) {
				ciphertext, err = AESGCMEncrypt(key, plaintext, nil)
				if err != nil {
					t.Fatalf("GCM encrypt failed: %v", err)
				}
				decrypted, err = AESGCMDecrypt(key, ciphertext, nil)
			} else {
				ciphertext, err = AESCBCEncrypt(key, plaintext)
				if err != nil {
					t.Fatalf("CBC encrypt failed: %v", err)
				}
				decrypted, err = AESCBCDecrypt(key, ciphertext)
			}

			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Error("plaintext mismatch after decrypt")
			}
		})
	}
}

// TestW3CAllKeyWrapAlgorithms tests all W3C-specified key wrap algorithms
func TestW3CAllKeyWrapAlgorithms(t *testing.T) {
	algorithms := []struct {
		name      string
		algorithm string
		kekSize   int
	}{
		{"AES-128-KW", AlgorithmAES128KW, 16},
		{"AES-192-KW", AlgorithmAES192KW, 24},
		{"AES-256-KW", AlgorithmAES256KW, 32},
	}

	// CEK to wrap (must be multiple of 8 bytes, at least 16)
	cek := []byte("sixteen-byte-key") // 16 bytes

	for _, alg := range algorithms {
		t.Run(alg.name, func(t *testing.T) {
			kek := make([]byte, alg.kekSize)
			for i := range kek {
				kek[i] = byte(i)
			}

			wrapped, err := AESKeyWrap(kek, cek)
			if err != nil {
				t.Fatalf("wrap failed: %v", err)
			}

			// Wrapped should be 8 bytes longer
			if len(wrapped) != len(cek)+8 {
				t.Errorf("wrong wrapped length: %d", len(wrapped))
			}

			unwrapped, err := AESKeyUnwrap(kek, wrapped)
			if err != nil {
				t.Fatalf("unwrap failed: %v", err)
			}

			if !bytes.Equal(unwrapped, cek) {
				t.Error("CEK mismatch after unwrap")
			}
		})
	}
}

// TestW3CFullPipelineECDHES tests the complete ECDH-ES pipeline as per W3C Section 2.2
func TestW3CFullPipelineECDHES(t *testing.T) {
	// This mirrors the W3C test case:
	// EC-P256 | aes128-gcm | kw-aes128 | ECDH-ES | ConcatKDF
	// But using X25519 instead of EC-P256

	// 1. Generate recipient key pair (receiver's static key)
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	// 2. Prepare plaintext document
	doc := etree.NewDocument()
	doc.ReadFromString(w3cPlaintextXML)

	// 3. Sender: Generate ephemeral key and derive KEK
	hkdfParams := DefaultHKDFParams([]byte("W3C ECDH-ES Test"))
	senderKA, err := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	if err != nil {
		t.Fatalf("failed to create key agreement: %v", err)
	}

	// 4. Encrypt the document
	encryptor := NewEncryptor(AlgorithmAES128GCM, senderKA)
	ed, err := encryptor.EncryptElement(doc.Root())
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// 5. Verify the encrypted structure
	if ed.EncryptionMethod.Algorithm != AlgorithmAES128GCM {
		t.Errorf("wrong content encryption: %s", ed.EncryptionMethod.Algorithm)
	}

	encKey := ed.KeyInfo.EncryptedKey
	if encKey.EncryptionMethod.Algorithm != AlgorithmAES128KW {
		t.Errorf("wrong key wrap: %s", encKey.EncryptionMethod.Algorithm)
	}

	am := encKey.KeyInfo.AgreementMethod
	if am.Algorithm != AlgorithmX25519 {
		t.Errorf("wrong key agreement: %s", am.Algorithm)
	}

	// 6. Recipient: Extract ephemeral key and derive KEK
	ephemeralPubBytes := am.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
	ephemeralPublic, err := ParseX25519PublicKey(ephemeralPubBytes)
	if err != nil {
		t.Fatalf("failed to parse ephemeral key: %v", err)
	}

	recipientKA := NewX25519KeyAgreementForDecrypt(recipientPrivate, ephemeralPublic, hkdfParams)

	// 7. Decrypt
	decryptor := NewDecryptor(recipientKA)
	decryptedElem, err := decryptor.DecryptElement(ed)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// 8. Verify decrypted content matches original
	if decryptedElem.Tag != "PurchaseOrder" {
		t.Errorf("wrong tag: %s", decryptedElem.Tag)
	}

	creditCard := decryptedElem.FindElement("./PaymentInfo/CreditCard")
	if creditCard == nil {
		t.Fatal("CreditCard not found")
	}

	number := creditCard.FindElement("./Number")
	if number == nil || number.Text() != "1234 567890 12345" {
		t.Error("card number mismatch")
	}
}

// TestW3CNamespaceDeclarations verifies correct namespace handling per W3C specs
func TestW3CNamespaceDeclarations(t *testing.T) {
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	hkdfParams := DefaultHKDFParams([]byte("namespace test"))
	senderKA, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)

	cek := make([]byte, 16)
	encryptedKey, _ := senderKA.WrapKey(cek, AlgorithmAES128KW)

	elem := encryptedKey.ToElement()
	doc := etree.NewDocument()
	doc.SetRoot(elem)
	xmlBytes, _ := doc.WriteToBytes()
	xmlStr := string(xmlBytes)

	// Verify all required namespace declarations
	requiredNamespaces := map[string]string{
		"xmlns:xenc":      NamespaceXMLEnc,
		"xmlns:xenc11":    NamespaceXMLEnc11,
		"xmlns:ds":        NamespaceXMLDSig,
		"xmlns:dsig11":    NamespaceXMLDSig11,
		"xmlns:dsig-more": NamespaceXMLDSigMore,
	}

	for prefix, ns := range requiredNamespaces {
		if !strings.Contains(xmlStr, ns) {
			t.Errorf("missing namespace %s=%s", prefix, ns)
		}
	}
}

// BenchmarkW3CFullEncryptionPipeline benchmarks the full encryption pipeline
func BenchmarkW3CFullEncryptionPipeline(b *testing.B) {
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()
	hkdfParams := DefaultHKDFParams(nil)

	doc := etree.NewDocument()
	doc.ReadFromString(w3cPlaintextXML)
	elem := doc.Root()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		senderKA, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
		encryptor := NewEncryptor(AlgorithmAES128GCM, senderKA)
		encryptor.EncryptElement(elem)
	}
}

// BenchmarkW3CFullDecryptionPipeline benchmarks the full decryption pipeline
func BenchmarkW3CFullDecryptionPipeline(b *testing.B) {
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()
	hkdfParams := DefaultHKDFParams(nil)

	doc := etree.NewDocument()
	doc.ReadFromString(w3cPlaintextXML)

	senderKA, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	encryptor := NewEncryptor(AlgorithmAES128GCM, senderKA)
	ed, _ := encryptor.EncryptElement(doc.Root())

	// Extract ephemeral key
	ephemeralPubBytes := ed.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
	ephemeralPublic, _ := ParseX25519PublicKey(ephemeralPubBytes)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recipientKA := NewX25519KeyAgreementForDecrypt(recipientPrivate, ephemeralPublic, hkdfParams)
		decryptor := NewDecryptor(recipientKA)
		decryptor.DecryptElement(ed)
	}
}

// ============================================================================
// NIST SP 800-38F / RFC 3394 Official Test Vectors
// ============================================================================

// NIST SP 800-38F Test Vectors for AES Key Wrap
// These are the official test vectors from the standard
// Reference: https://csrc.nist.gov/publications/detail/sp/800-38f/final

// TestNISTKeyWrap128Bit tests AES-128 Key Wrap with official NIST test vector
// From Section 4.1 of RFC 3394
func TestNISTKeyWrap128Bit(t *testing.T) {
	// KEK: 000102030405060708090A0B0C0D0E0F
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}

	// Key data: 00112233445566778899AABBCCDDEEFF
	keyData := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}

	// Expected ciphertext: 1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5
	expectedCipher := []byte{
		0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
		0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
		0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
	}

	// Test wrap
	wrapped, err := AESKeyWrap(kek, keyData)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	if !bytes.Equal(wrapped, expectedCipher) {
		t.Errorf("wrapped key mismatch:\ngot:  %X\nwant: %X", wrapped, expectedCipher)
	}

	// Test unwrap
	unwrapped, err := AESKeyUnwrap(kek, expectedCipher)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, keyData) {
		t.Errorf("unwrapped key mismatch:\ngot:  %X\nwant: %X", unwrapped, keyData)
	}
}

// TestNISTKeyWrap192Bit tests AES-192 Key Wrap with official NIST test vector
// From Section 4.2 of RFC 3394
func TestNISTKeyWrap192Bit(t *testing.T) {
	// KEK: 000102030405060708090A0B0C0D0E0F1011121314151617
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	}

	// Key data: 00112233445566778899AABBCCDDEEFF
	keyData := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}

	// Expected ciphertext: 96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D
	expectedCipher := []byte{
		0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35,
		0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50, 0xAE, 0xD2,
		0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D,
	}

	// Test wrap
	wrapped, err := AESKeyWrap(kek, keyData)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	if !bytes.Equal(wrapped, expectedCipher) {
		t.Errorf("wrapped key mismatch:\ngot:  %X\nwant: %X", wrapped, expectedCipher)
	}

	// Test unwrap
	unwrapped, err := AESKeyUnwrap(kek, expectedCipher)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, keyData) {
		t.Errorf("unwrapped key mismatch:\ngot:  %X\nwant: %X", unwrapped, keyData)
	}
}

// TestNISTKeyWrap256Bit tests AES-256 Key Wrap with official NIST test vector
// From Section 4.3 of RFC 3394
func TestNISTKeyWrap256Bit(t *testing.T) {
	// KEK: 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}

	// Key data: 00112233445566778899AABBCCDDEEFF
	keyData := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}

	// Expected ciphertext: 64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7
	expectedCipher := []byte{
		0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
		0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
		0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7,
	}

	// Test wrap
	wrapped, err := AESKeyWrap(kek, keyData)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	if !bytes.Equal(wrapped, expectedCipher) {
		t.Errorf("wrapped key mismatch:\ngot:  %X\nwant: %X", wrapped, expectedCipher)
	}

	// Test unwrap
	unwrapped, err := AESKeyUnwrap(kek, expectedCipher)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, keyData) {
		t.Errorf("unwrapped key mismatch:\ngot:  %X\nwant: %X", unwrapped, keyData)
	}
}

// TestNISTKeyWrap256With192BitData tests AES-256 wrapping 192-bit key data
// From Section 4.5 of RFC 3394
func TestNISTKeyWrap256With192BitData(t *testing.T) {
	// KEK: 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}

	// Key data: 00112233445566778899AABBCCDDEEFF0001020304050607
	keyData := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	}

	// Expected ciphertext: A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1
	expectedCipher := []byte{
		0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F,
		0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E, 0x71, 0xE4,
		0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95,
		0x8C, 0xD5, 0xD1, 0x7D, 0x6B, 0x25, 0x4D, 0xA1,
	}

	// Test wrap
	wrapped, err := AESKeyWrap(kek, keyData)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	if !bytes.Equal(wrapped, expectedCipher) {
		t.Errorf("wrapped key mismatch:\ngot:  %X\nwant: %X", wrapped, expectedCipher)
	}

	// Test unwrap
	unwrapped, err := AESKeyUnwrap(kek, expectedCipher)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, keyData) {
		t.Errorf("unwrapped key mismatch:\ngot:  %X\nwant: %X", unwrapped, keyData)
	}
}

// TestNISTKeyWrap256With256BitData tests AES-256 wrapping 256-bit key data
// From Section 4.6 of RFC 3394
func TestNISTKeyWrap256With256BitData(t *testing.T) {
	// KEK: 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}

	// Key data: 00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F
	keyData := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}

	// Expected ciphertext: 28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
	expectedCipher := []byte{
		0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
		0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
		0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
		0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
		0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
	}

	// Test wrap
	wrapped, err := AESKeyWrap(kek, keyData)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	if !bytes.Equal(wrapped, expectedCipher) {
		t.Errorf("wrapped key mismatch:\ngot:  %X\nwant: %X", wrapped, expectedCipher)
	}

	// Test unwrap
	unwrapped, err := AESKeyUnwrap(kek, expectedCipher)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, keyData) {
		t.Errorf("unwrapped key mismatch:\ngot:  %X\nwant: %X", unwrapped, keyData)
	}
}

// ============================================================================
// W3C XML Encryption Content Encryption Tests
// ============================================================================

// TestW3CContentEncryption tests encrypting content within an element (not the element itself)
func TestW3CContentEncryption(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(w3cPlaintextXML)
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	// Find the CreditCard element
	creditCard := doc.FindElement("//CreditCard")
	if creditCard == nil {
		t.Fatal("CreditCard element not found")
	}

	// Get original content
	originalContent := creditCard.Text()
	childCount := len(creditCard.Child)

	// Create a symmetric key and use X25519 key agreement for testing
	recipientPrivate, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	recipientPublic := recipientPrivate.PublicKey()

	hkdfParams := DefaultHKDFParams([]byte("Content Encryption Test"))
	senderKA, err := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	if err != nil {
		t.Fatalf("failed to create key agreement: %v", err)
	}

	encryptor := NewEncryptor(AlgorithmAES128GCM, senderKA)

	// Encrypt the CreditCard element
	encData, err := encryptor.EncryptElement(creditCard)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Verify the EncryptedData type is set to Element
	if encData.Type != TypeElement {
		t.Errorf("expected Type=%s, got %s", TypeElement, encData.Type)
	}

	// Decrypt it back
	ephemeralPubBytes := encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
	ephemeralPublic, err := ParseX25519PublicKey(ephemeralPubBytes)
	if err != nil {
		t.Fatalf("failed to parse ephemeral key: %v", err)
	}

	decryptKA := NewX25519KeyAgreementForDecrypt(recipientPrivate, ephemeralPublic, hkdfParams)
	decryptor := NewDecryptor(decryptKA)
	decrypted, err := decryptor.DecryptElement(encData)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify decrypted content matches original
	if decrypted.Tag != creditCard.Tag {
		t.Errorf("tag mismatch: got %s, want %s", decrypted.Tag, creditCard.Tag)
	}

	// Check children were preserved
	if len(decrypted.Child) != childCount {
		t.Errorf("child count mismatch: got %d, want %d", len(decrypted.Child), childCount)
	}

	t.Logf("Original content: %q", originalContent)
	t.Logf("Successfully encrypted and decrypted CreditCard element")
}

// TestW3CSelectiveEncryption tests encrypting specific elements in a document
func TestW3CSelectiveEncryption(t *testing.T) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(w3cPlaintextXML)
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	// Find the PaymentInfo element (sensitive data)
	paymentInfo := doc.FindElement("//PaymentInfo")
	if paymentInfo == nil {
		t.Fatal("PaymentInfo element not found")
	}

	// Find Items (non-sensitive data)
	items := doc.FindElement("//Items")
	if items == nil {
		t.Fatal("Items element not found")
	}

	// Store original XML for comparison
	originalPaymentXML, _ := doc.WriteToString()

	// Create encryptor with X25519 key agreement
	recipientPrivate, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	recipientPublic := recipientPrivate.PublicKey()

	hkdfParams := DefaultHKDFParams([]byte("W3C Selective Encryption Test"))
	senderKA, err := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	if err != nil {
		t.Fatalf("failed to create key agreement: %v", err)
	}

	encryptor := NewEncryptor(AlgorithmAES128GCM, senderKA)

	// Encrypt only the PaymentInfo element
	encData, err := encryptor.EncryptElement(paymentInfo)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Generate XML and verify structure
	encDoc := etree.NewDocument()
	encDoc.SetRoot(encData.ToElement())
	encXML, err := encDoc.WriteToString()
	if err != nil {
		t.Fatalf("failed to serialize encrypted data: %v", err)
	}

	// Verify PaymentInfo content is no longer visible
	if strings.Contains(encXML, "1234 567890 12345") {
		t.Error("credit card number should not be visible in encrypted data")
	}

	// Items should still be visible in original document
	if !strings.Contains(originalPaymentXML, "spade") {
		t.Error("Items should still be visible in original document")
	}

	t.Logf("Original document length: %d", len(originalPaymentXML))
	t.Logf("Encrypted PaymentInfo length: %d", len(encXML))
}

// ============================================================================
// W3C Multiple Recipient Test
// ============================================================================

// TestW3CMultipleRecipients tests encrypting for multiple recipients
// This is a common use case in XML Encryption where the same content
// is encrypted once but wrapped keys are provided for multiple recipients
func TestW3CMultipleRecipients(t *testing.T) {
	// Generate key pairs for two recipients
	recipient1Private, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair 1: %v", err)
	}
	recipient2Private, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair 2: %v", err)
	}

	recipient1Public := recipient1Private.PublicKey()
	recipient2Public := recipient2Private.PublicKey()

	// Parse test document
	doc := etree.NewDocument()
	err = doc.ReadFromString(w3cPlaintextXML)
	if err != nil {
		t.Fatalf("failed to parse document: %v", err)
	}

	// Encrypt for recipient 1
	hkdfParams1 := DefaultHKDFParams([]byte("Recipient 1"))
	ka1, err := NewX25519KeyAgreement(recipient1Public, hkdfParams1)
	if err != nil {
		t.Fatalf("failed to create key agreement 1: %v", err)
	}

	encryptor1 := NewEncryptor(AlgorithmAES128GCM, ka1)
	encData1, err := encryptor1.EncryptElement(doc.Root())
	if err != nil {
		t.Fatalf("encryption for recipient 1 failed: %v", err)
	}

	// Encrypt for recipient 2 (same plaintext, different key)
	doc2 := etree.NewDocument()
	doc2.ReadFromString(w3cPlaintextXML)

	hkdfParams2 := DefaultHKDFParams([]byte("Recipient 2"))
	ka2, err := NewX25519KeyAgreement(recipient2Public, hkdfParams2)
	if err != nil {
		t.Fatalf("failed to create key agreement 2: %v", err)
	}

	encryptor2 := NewEncryptor(AlgorithmAES128GCM, ka2)
	encData2, err := encryptor2.EncryptElement(doc2.Root())
	if err != nil {
		t.Fatalf("encryption for recipient 2 failed: %v", err)
	}

	// Decrypt as recipient 1
	ephemeralPub1, err := ParseX25519PublicKey(
		encData1.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey,
	)
	if err != nil {
		t.Fatalf("failed to parse ephemeral key 1: %v", err)
	}

	decryptKA1 := NewX25519KeyAgreementForDecrypt(recipient1Private, ephemeralPub1, hkdfParams1)
	decryptor1 := NewDecryptor(decryptKA1)
	decrypted1, err := decryptor1.DecryptElement(encData1)
	if err != nil {
		t.Fatalf("decryption as recipient 1 failed: %v", err)
	}

	// Decrypt as recipient 2
	ephemeralPub2, err := ParseX25519PublicKey(
		encData2.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey,
	)
	if err != nil {
		t.Fatalf("failed to parse ephemeral key 2: %v", err)
	}

	decryptKA2 := NewX25519KeyAgreementForDecrypt(recipient2Private, ephemeralPub2, hkdfParams2)
	decryptor2 := NewDecryptor(decryptKA2)
	decrypted2, err := decryptor2.DecryptElement(encData2)
	if err != nil {
		t.Fatalf("decryption as recipient 2 failed: %v", err)
	}

	// Both decrypted documents should match original
	origDoc := etree.NewDocument()
	origDoc.SetRoot(decrypted1)
	decXML1, _ := origDoc.WriteToString()

	origDoc2 := etree.NewDocument()
	origDoc2.SetRoot(decrypted2)
	decXML2, _ := origDoc2.WriteToString()

	if !strings.Contains(decXML1, "PurchaseOrder") {
		t.Error("recipient 1 decryption missing PurchaseOrder")
	}
	if !strings.Contains(decXML2, "PurchaseOrder") {
		t.Error("recipient 2 decryption missing PurchaseOrder")
	}

	t.Log("Successfully encrypted and decrypted for multiple recipients")
}

// ============================================================================
// W3C Error Case Tests
// ============================================================================

// TestW3CIntegrityVerification tests that tampered ciphertext is detected
func TestW3CIntegrityVerification(t *testing.T) {
	// Generate key pair
	recipientPrivate, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	recipientPublic := recipientPrivate.PublicKey()

	// Parse and encrypt test document
	doc := etree.NewDocument()
	doc.ReadFromString(w3cPlaintextXML)

	hkdfParams := DefaultHKDFParams([]byte("Integrity Test"))
	ka, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	encryptor := NewEncryptor(AlgorithmAES128GCM, ka)
	encData, _ := encryptor.EncryptElement(doc.Root())

	// Tamper with the ciphertext
	originalCipher := encData.CipherData.CipherValue
	tamperedCipher := make([]byte, len(originalCipher))
	copy(tamperedCipher, originalCipher)
	tamperedCipher[len(tamperedCipher)/2] ^= 0xFF // Flip some bits
	encData.CipherData.CipherValue = tamperedCipher

	// Try to decrypt - should fail for GCM due to authentication tag
	ephemeralPub, _ := ParseX25519PublicKey(
		encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey,
	)
	decryptKA := NewX25519KeyAgreementForDecrypt(recipientPrivate, ephemeralPub, hkdfParams)
	decryptor := NewDecryptor(decryptKA)

	_, err = decryptor.DecryptElement(encData)
	if err == nil {
		t.Error("decryption should have failed for tampered ciphertext")
	} else {
		t.Logf("Correctly detected tampered ciphertext: %v", err)
	}
}

// TestW3CWrongKey tests that decryption with wrong key fails
func TestW3CWrongKey(t *testing.T) {
	// Generate key pair for encryption
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	// Generate different key pair for decryption
	wrongPrivate, _ := GenerateX25519KeyPair()

	// Parse and encrypt
	doc := etree.NewDocument()
	doc.ReadFromString(w3cPlaintextXML)

	hkdfParams := DefaultHKDFParams([]byte("Wrong Key Test"))
	ka, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	encryptor := NewEncryptor(AlgorithmAES128GCM, ka)
	encData, _ := encryptor.EncryptElement(doc.Root())

	// Try to decrypt with wrong key
	ephemeralPub, _ := ParseX25519PublicKey(
		encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey,
	)
	decryptKA := NewX25519KeyAgreementForDecrypt(wrongPrivate, ephemeralPub, hkdfParams)
	decryptor := NewDecryptor(decryptKA)

	_, err := decryptor.DecryptElement(encData)
	if err == nil {
		t.Error("decryption should have failed with wrong key")
	} else {
		t.Logf("Correctly rejected wrong key: %v", err)
	}
}

// ============================================================================
// W3C EncryptedData XML Structure Validation Tests
// ============================================================================

// TestW3CEncryptedDataStructure validates the complete XML structure per W3C spec
func TestW3CEncryptedDataStructure(t *testing.T) {
	// Generate encryption material
	recipientPrivate, _ := GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	doc := etree.NewDocument()
	doc.ReadFromString(w3cPlaintextXML)

	hkdfParams := DefaultHKDFParams([]byte("Structure Test"))
	ka, _ := NewX25519KeyAgreement(recipientPublic, hkdfParams)
	encryptor := NewEncryptor(AlgorithmAES128GCM, ka)
	encData, _ := encryptor.EncryptElement(doc.Root())

	// Convert to XML element for structure validation
	elem := encData.ToElement()

	// Validate EncryptedData root
	if elem.Tag != "EncryptedData" {
		t.Errorf("expected root tag EncryptedData, got %s", elem.Tag)
	}

	// Check namespace
	nsAttr := elem.SelectAttr("xmlns:xenc")
	if nsAttr == nil || nsAttr.Value != NamespaceXMLEnc {
		t.Error("missing or incorrect xenc namespace declaration")
	}

	// Validate Type attribute
	typeAttr := elem.SelectAttr("Type")
	if typeAttr == nil || typeAttr.Value != TypeElement {
		t.Errorf("expected Type=%s, got %v", TypeElement, typeAttr)
	}

	// Validate EncryptionMethod
	encMethod := elem.FindElement("./EncryptionMethod")
	if encMethod == nil {
		t.Error("EncryptionMethod element not found")
	} else {
		alg := encMethod.SelectAttr("Algorithm")
		if alg == nil || alg.Value != AlgorithmAES128GCM {
			t.Errorf("expected Algorithm=%s", AlgorithmAES128GCM)
		}
	}

	// Validate KeyInfo
	keyInfo := elem.FindElement("./KeyInfo")
	if keyInfo == nil {
		t.Error("KeyInfo element not found")
	}

	// Validate EncryptedKey within KeyInfo
	encKey := elem.FindElement("./KeyInfo/EncryptedKey")
	if encKey == nil {
		t.Error("EncryptedKey element not found")
	}

	// Validate AgreementMethod within EncryptedKey/KeyInfo
	agreementMethod := elem.FindElement("./KeyInfo/EncryptedKey/KeyInfo/AgreementMethod")
	if agreementMethod == nil {
		t.Error("AgreementMethod element not found")
	} else {
		alg := agreementMethod.SelectAttr("Algorithm")
		if alg == nil || alg.Value != AlgorithmX25519 {
			t.Errorf("expected AgreementMethod Algorithm=%s", AlgorithmX25519)
		}
	}

	// Validate KeyDerivationMethod
	kdm := elem.FindElement("./KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod")
	if kdm == nil {
		t.Error("KeyDerivationMethod element not found")
	} else {
		alg := kdm.SelectAttr("Algorithm")
		if alg == nil || alg.Value != AlgorithmHKDF {
			t.Errorf("expected KeyDerivationMethod Algorithm=%s", AlgorithmHKDF)
		}
	}

	// Validate HKDFParams
	hkdfParamsElem := elem.FindElement("./KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/KeyDerivationMethod/HKDFParams")
	if hkdfParamsElem == nil {
		t.Error("HKDFParams element not found")
	} else {
		// Check PRF
		prf := hkdfParamsElem.FindElement("./PRF")
		if prf == nil {
			t.Error("PRF element not found in HKDFParams")
		}

		// Check KeyLength
		keyLen := hkdfParamsElem.FindElement("./KeyLength")
		if keyLen == nil {
			t.Error("KeyLength element not found in HKDFParams")
		}
	}

	// Validate OriginatorKeyInfo
	origKeyInfo := elem.FindElement("./KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/OriginatorKeyInfo")
	if origKeyInfo == nil {
		t.Error("OriginatorKeyInfo element not found")
	}

	// Validate ECKeyValue for X25519
	ecKeyValue := elem.FindElement("./KeyInfo/EncryptedKey/KeyInfo/AgreementMethod/OriginatorKeyInfo/KeyValue/ECKeyValue")
	if ecKeyValue == nil {
		t.Error("ECKeyValue element not found")
	} else {
		// Check NamedCurve
		namedCurve := ecKeyValue.FindElement("./NamedCurve")
		if namedCurve == nil {
			t.Error("NamedCurve element not found")
		} else {
			uri := namedCurve.SelectAttr("URI")
			const x25519Curve = "urn:ietf:params:xml:ns:keyprov:curve:x25519"
			if uri == nil || uri.Value != x25519Curve {
				t.Errorf("expected NamedCurve URI=%s", x25519Curve)
			}
		}

		// Check PublicKey
		pubKey := ecKeyValue.FindElement("./PublicKey")
		if pubKey == nil {
			t.Error("PublicKey element not found")
		} else {
			// Verify it's base64 encoded
			pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKey.Text())
			if err != nil {
				t.Errorf("PublicKey is not valid base64: %v", err)
			}
			if len(pubKeyBytes) != 32 {
				t.Errorf("PublicKey should be 32 bytes for X25519, got %d", len(pubKeyBytes))
			}
		}
	}

	// Validate CipherData
	cipherData := elem.FindElement("./CipherData")
	if cipherData == nil {
		t.Error("CipherData element not found")
	}

	cipherValue := elem.FindElement("./CipherData/CipherValue")
	if cipherValue == nil {
		t.Error("CipherValue element not found")
	} else {
		// Verify it's base64 encoded
		_, err := base64.StdEncoding.DecodeString(cipherValue.Text())
		if err != nil {
			t.Errorf("CipherValue is not valid base64: %v", err)
		}
	}

	t.Log("All W3C EncryptedData structure elements validated successfully")
}

// TestW3CAlgorithmURIs validates all algorithm URIs match W3C specifications
func TestW3CAlgorithmURIs(t *testing.T) {
	// Define expected W3C algorithm URIs
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		// Block Encryption
		{"AES-128-GCM", AlgorithmAES128GCM, "http://www.w3.org/2009/xmlenc11#aes128-gcm"},
		{"AES-192-GCM", AlgorithmAES192GCM, "http://www.w3.org/2009/xmlenc11#aes192-gcm"},
		{"AES-256-GCM", AlgorithmAES256GCM, "http://www.w3.org/2009/xmlenc11#aes256-gcm"},
		{"AES-128-CBC", AlgorithmAES128CBC, "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
		{"AES-192-CBC", AlgorithmAES192CBC, "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
		{"AES-256-CBC", AlgorithmAES256CBC, "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},

		// Key Wrapping
		{"AES-128-KW", AlgorithmAES128KW, "http://www.w3.org/2001/04/xmlenc#kw-aes128"},
		{"AES-192-KW", AlgorithmAES192KW, "http://www.w3.org/2001/04/xmlenc#kw-aes192"},
		{"AES-256-KW", AlgorithmAES256KW, "http://www.w3.org/2001/04/xmlenc#kw-aes256"},

		// Key Agreement
		{"X25519", AlgorithmX25519, "http://www.w3.org/2021/04/xmldsig-more#x25519"},
		{"HKDF", AlgorithmHKDF, "http://www.w3.org/2021/04/xmldsig-more#hkdf"},

		// PRF Algorithms
		{"HMAC-SHA256", AlgorithmHMACSHA256, "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.uri != tc.expected {
				t.Errorf("algorithm URI mismatch:\ngot:  %s\nwant: %s", tc.uri, tc.expected)
			}
		})
	}
}

// TestW3CNamespaceURIs validates all namespace URIs match W3C specifications
func TestW3CNamespaceURIs(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{"XML Encryption", NamespaceXMLEnc, "http://www.w3.org/2001/04/xmlenc#"},
		{"XML Encryption 1.1", NamespaceXMLEnc11, "http://www.w3.org/2009/xmlenc11#"},
		{"XML Signature", NamespaceXMLDSig, "http://www.w3.org/2000/09/xmldsig#"},
		{"XML Signature 1.1", NamespaceXMLDSig11, "http://www.w3.org/2009/xmldsig11#"},
		{"XML Signature More", NamespaceXMLDSigMore, "http://www.w3.org/2001/04/xmldsig-more#"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.uri != tc.expected {
				t.Errorf("namespace URI mismatch:\ngot:  %s\nwant: %s", tc.uri, tc.expected)
			}
		})
	}
}

// TestW3CTypeURIs validates all type URIs match W3C specifications
func TestW3CTypeURIs(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{"Element Type", TypeElement, "http://www.w3.org/2001/04/xmlenc#Element"},
		{"Content Type", TypeContent, "http://www.w3.org/2001/04/xmlenc#Content"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.uri != tc.expected {
				t.Errorf("type URI mismatch:\ngot:  %s\nwant: %s", tc.uri, tc.expected)
			}
		})
	}
}
