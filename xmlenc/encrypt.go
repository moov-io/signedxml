package xmlenc

import (
	"crypto/rand"
	"fmt"

	"github.com/beevik/etree"
)

// Encryptor provides XML Encryption operations
type Encryptor struct {
	// Algorithm is the content encryption algorithm (e.g., AlgorithmAES128GCM)
	Algorithm string
	// KeyWrapper handles key encryption (e.g., X25519KeyAgreement)
	KeyWrapper KeyWrapper
}

// KeyWrapper interface for key wrapping mechanisms
type KeyWrapper interface {
	// WrapKey wraps a content encryption key
	WrapKey(cek []byte, wrapAlgorithm string) (*EncryptedKey, error)
}

// NewEncryptor creates a new Encryptor with the specified algorithm and key wrapper
func NewEncryptor(algorithm string, keyWrapper KeyWrapper) *Encryptor {
	return &Encryptor{
		Algorithm:  algorithm,
		KeyWrapper: keyWrapper,
	}
}

// EncryptElement encrypts an XML element and replaces it with EncryptedData
func (e *Encryptor) EncryptElement(elem *etree.Element) (*EncryptedData, error) {
	return e.encrypt(elem, TypeElement)
}

// EncryptContent encrypts the content of an XML element
func (e *Encryptor) EncryptContent(elem *etree.Element) (*EncryptedData, error) {
	return e.encrypt(elem, TypeContent)
}

func (e *Encryptor) encrypt(elem *etree.Element, encType string) (*EncryptedData, error) {
	// Determine key size
	keySize := KeySize(e.Algorithm)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", e.Algorithm)
	}

	// Generate content encryption key (CEK)
	cek := make([]byte, keySize)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("failed to generate CEK: %w", err)
	}

	// Serialize the element/content to encrypt
	var plaintext []byte
	var err error
	if encType == TypeElement {
		doc := etree.NewDocument()
		doc.SetRoot(elem.Copy())
		plaintext, err = doc.WriteToBytes()
	} else {
		// For content encryption, serialize child elements
		doc := etree.NewDocument()
		for _, child := range elem.ChildElements() {
			doc.AddChild(child.Copy())
		}
		plaintext, err = doc.WriteToBytes()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to serialize element: %w", err)
	}

	// Encrypt the plaintext
	var ciphertext []byte
	if IsGCM(e.Algorithm) {
		ciphertext, err = AESGCMEncrypt(cek, plaintext, nil)
	} else {
		ciphertext, err = AESCBCEncrypt(cek, plaintext)
	}
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Wrap the CEK
	var keyInfo *KeyInfo
	if e.KeyWrapper != nil {
		wrapAlg := KeyWrapAlgorithmForContentAlgorithm(e.Algorithm)
		encKey, err := e.KeyWrapper.WrapKey(cek, wrapAlg)
		if err != nil {
			return nil, fmt.Errorf("key wrapping failed: %w", err)
		}
		keyInfo = &KeyInfo{
			EncryptedKey: encKey,
		}
	}

	// Build EncryptedData
	ed := &EncryptedData{
		EncryptedType: EncryptedType{
			Type: encType,
			EncryptionMethod: &EncryptionMethod{
				Algorithm: e.Algorithm,
			},
			KeyInfo: keyInfo,
			CipherData: &CipherData{
				CipherValue: ciphertext,
			},
		},
	}

	return ed, nil
}

// Decryptor provides XML Decryption operations
type Decryptor struct {
	// KeyUnwrapper handles key decryption
	KeyUnwrapper KeyUnwrapper
}

// KeyUnwrapper interface for key unwrapping mechanisms
type KeyUnwrapper interface {
	// UnwrapKey unwraps a content encryption key from EncryptedKey
	UnwrapKey(ek *EncryptedKey) ([]byte, error)
}

// NewDecryptor creates a new Decryptor with the specified key unwrapper
func NewDecryptor(keyUnwrapper KeyUnwrapper) *Decryptor {
	return &Decryptor{
		KeyUnwrapper: keyUnwrapper,
	}
}

// DecryptEncryptedData decrypts an EncryptedData structure and returns the plaintext
func (d *Decryptor) DecryptEncryptedData(ed *EncryptedData) ([]byte, error) {
	if ed.CipherData == nil || ed.CipherData.CipherValue == nil {
		return nil, fmt.Errorf("no cipher data")
	}

	// Get the content encryption key
	var cek []byte
	var err error

	if ed.KeyInfo != nil && ed.KeyInfo.EncryptedKey != nil {
		cek, err = d.KeyUnwrapper.UnwrapKey(ed.KeyInfo.EncryptedKey)
		if err != nil {
			return nil, fmt.Errorf("key unwrapping failed: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no key information available")
	}

	// Decrypt the content
	algorithm := ""
	if ed.EncryptionMethod != nil {
		algorithm = ed.EncryptionMethod.Algorithm
	}

	var plaintext []byte
	if IsGCM(algorithm) {
		plaintext, err = AESGCMDecrypt(cek, ed.CipherData.CipherValue, nil)
	} else {
		plaintext, err = AESCBCDecrypt(cek, ed.CipherData.CipherValue)
	}
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// DecryptElement decrypts an EncryptedData structure and returns the XML element
func (d *Decryptor) DecryptElement(ed *EncryptedData) (*etree.Element, error) {
	plaintext, err := d.DecryptEncryptedData(ed)
	if err != nil {
		return nil, err
	}

	// Parse the decrypted XML
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plaintext); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted XML: %w", err)
	}

	return doc.Root(), nil
}

// KeyWrapAlgorithmForContentAlgorithm returns the appropriate key wrap algorithm
// for a given content encryption algorithm based on key size.
func KeyWrapAlgorithmForContentAlgorithm(contentAlgorithm string) string {
	switch KeySize(contentAlgorithm) {
	case 16:
		return AlgorithmAES128KW
	case 24:
		return AlgorithmAES192KW
	case 32:
		return AlgorithmAES256KW
	default:
		return AlgorithmAES128KW
	}
}

// NewEncryptedDataDocument creates an etree.Document containing an EncryptedData element
func NewEncryptedDataDocument(ed *EncryptedData) *etree.Document {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(ed.ToElement())
	return doc
}

// NewEncryptedKeyDocument creates an etree.Document containing an EncryptedKey element
func NewEncryptedKeyDocument(ek *EncryptedKey) *etree.Document {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(ek.ToElement())
	return doc
}

// EncryptElementInPlace encrypts an element and replaces it in the document
func EncryptElementInPlace(elem *etree.Element, encryptor *Encryptor) error {
	ed, err := encryptor.EncryptElement(elem)
	if err != nil {
		return err
	}

	parent := elem.Parent()
	if parent == nil {
		return fmt.Errorf("element has no parent")
	}

	// Find the position of the element
	index := -1
	for i, child := range parent.ChildElements() {
		if child == elem {
			index = i
			break
		}
	}

	if index < 0 {
		return fmt.Errorf("element not found in parent")
	}

	// Remove the original element and insert EncryptedData
	parent.RemoveChild(elem)
	edElem := ed.ToElement()
	parent.InsertChildAt(index, edElem)

	return nil
}

// DecryptElementInPlace decrypts an EncryptedData element and replaces it in the document
func DecryptElementInPlace(edElem *etree.Element, decryptor *Decryptor) error {
	ed, err := ParseEncryptedData(edElem)
	if err != nil {
		return err
	}

	decryptedElem, err := decryptor.DecryptElement(ed)
	if err != nil {
		return err
	}

	parent := edElem.Parent()
	if parent == nil {
		return fmt.Errorf("EncryptedData element has no parent")
	}

	// Find the position
	index := -1
	for i, child := range parent.ChildElements() {
		if child == edElem {
			index = i
			break
		}
	}

	if index < 0 {
		return fmt.Errorf("EncryptedData element not found in parent")
	}

	// Replace EncryptedData with decrypted element
	parent.RemoveChild(edElem)
	parent.InsertChildAt(index, decryptedElem)

	return nil
}
