package xmlenc

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// X25519KeyAgreement performs X25519 ECDH key agreement and key derivation
// as specified for XML Encryption with the HKDF key derivation function.
type X25519KeyAgreement struct {
	// EphemeralPrivateKey is the sender's ephemeral private key (generated during Wrap)
	EphemeralPrivateKey *ecdh.PrivateKey
	// EphemeralPublicKey is the sender's ephemeral public key (included in OriginatorKeyInfo)
	EphemeralPublicKey *ecdh.PublicKey
	// RecipientPublicKey is the recipient's static public key
	RecipientPublicKey *ecdh.PublicKey
	// RecipientPrivateKey is for decryption (only set on recipient side)
	RecipientPrivateKey *ecdh.PrivateKey
	// HKDFParams contains the key derivation parameters
	HKDFParams *HKDFParams
}

// NewX25519KeyAgreement creates a new X25519 key agreement instance for encryption.
// It generates a fresh ephemeral key pair and uses the provided recipient public key.
func NewX25519KeyAgreement(recipientPublicKey *ecdh.PublicKey, hkdfParams *HKDFParams) (*X25519KeyAgreement, error) {
	curve := ecdh.X25519()

	// Generate ephemeral key pair
	ephemeralPrivateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	return &X25519KeyAgreement{
		EphemeralPrivateKey: ephemeralPrivateKey,
		EphemeralPublicKey:  ephemeralPrivateKey.PublicKey(),
		RecipientPublicKey:  recipientPublicKey,
		HKDFParams:          hkdfParams,
	}, nil
}

// NewX25519KeyAgreementForDecrypt creates a key agreement instance for decryption.
func NewX25519KeyAgreementForDecrypt(recipientPrivateKey *ecdh.PrivateKey, ephemeralPublicKey *ecdh.PublicKey, hkdfParams *HKDFParams) *X25519KeyAgreement {
	return &X25519KeyAgreement{
		EphemeralPublicKey:  ephemeralPublicKey,
		RecipientPrivateKey: recipientPrivateKey,
		RecipientPublicKey:  recipientPrivateKey.PublicKey(),
		HKDFParams:          hkdfParams,
	}
}

// DeriveKeyEncryptionKey derives a key encryption key (KEK) using X25519 ECDH and HKDF.
// This is used to encrypt/decrypt the content encryption key.
func (ka *X25519KeyAgreement) DeriveKeyEncryptionKey(keyLength int) ([]byte, error) {
	var sharedSecret []byte
	var err error

	if ka.EphemeralPrivateKey != nil {
		// Sender side: use ephemeral private key with recipient public key
		sharedSecret, err = ka.EphemeralPrivateKey.ECDH(ka.RecipientPublicKey)
	} else if ka.RecipientPrivateKey != nil {
		// Recipient side: use recipient private key with ephemeral public key
		sharedSecret, err = ka.RecipientPrivateKey.ECDH(ka.EphemeralPublicKey)
	} else {
		return nil, fmt.Errorf("no private key available for ECDH")
	}

	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive KEK using HKDF
	kek, err := deriveKeyHKDF(sharedSecret, ka.HKDFParams, keyLength)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return kek, nil
}

// deriveKeyHKDF derives a key using HKDF (RFC 5869)
func deriveKeyHKDF(secret []byte, params *HKDFParams, keyLength int) ([]byte, error) {
	// Use SHA-256 as default PRF
	hashFunc := sha256.New

	var salt []byte
	var info []byte

	if params != nil {
		salt = params.Salt
		info = params.Info
		if params.KeyLength > 0 {
			keyLength = params.KeyLength / 8 // Convert bits to bytes
		}
	}

	if keyLength <= 0 {
		keyLength = 16 // Default to 128 bits for AES-128
	}

	// HKDF-Extract and HKDF-Expand
	hkdfReader := hkdf.New(hashFunc, secret, salt, info)

	key := make([]byte, keyLength)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF failed: %w", err)
	}

	return key, nil
}

// WrapKey wraps a content encryption key (CEK) using X25519 key agreement.
// Returns the wrapped key and the EncryptedKey structure.
func (ka *X25519KeyAgreement) WrapKey(cek []byte, wrapAlgorithm string) (*EncryptedKey, error) {
	// Determine KEK size based on wrap algorithm
	kekSize := KeySize(wrapAlgorithm)
	if kekSize == 0 {
		return nil, fmt.Errorf("unsupported wrap algorithm: %s", wrapAlgorithm)
	}

	// Derive KEK
	kek, err := ka.DeriveKeyEncryptionKey(kekSize)
	if err != nil {
		return nil, err
	}

	// Wrap the CEK
	wrappedKey, err := AESKeyWrap(kek, cek)
	if err != nil {
		return nil, fmt.Errorf("key wrap failed: %w", err)
	}

	// Build EncryptedKey structure
	ek := &EncryptedKey{
		EncryptedType: EncryptedType{
			EncryptionMethod: &EncryptionMethod{
				Algorithm: wrapAlgorithm,
			},
			KeyInfo: &KeyInfo{
				AgreementMethod: &AgreementMethod{
					Algorithm: AlgorithmX25519,
					KeyDerivationMethod: &KeyDerivationMethod{
						Algorithm:  AlgorithmHKDF,
						HKDFParams: ka.HKDFParams,
					},
					OriginatorKeyInfo: &KeyInfo{
						KeyValue: &KeyValue{
							ECKeyValue: &ECKeyValue{
								NamedCurve: "urn:ietf:params:xml:ns:keyprov:curve:x25519",
								PublicKey:  ka.EphemeralPublicKey.Bytes(),
							},
						},
					},
				},
			},
			CipherData: &CipherData{
				CipherValue: wrappedKey,
			},
		},
	}

	return ek, nil
}

// UnwrapKey unwraps a content encryption key from an EncryptedKey structure.
func (ka *X25519KeyAgreement) UnwrapKey(ek *EncryptedKey) ([]byte, error) {
	if ek.CipherData == nil || ek.CipherData.CipherValue == nil {
		return nil, fmt.Errorf("no cipher value in EncryptedKey")
	}

	// Determine KEK size based on wrap algorithm
	wrapAlgorithm := ""
	if ek.EncryptionMethod != nil {
		wrapAlgorithm = ek.EncryptionMethod.Algorithm
	}

	kekSize := KeySize(wrapAlgorithm)
	if kekSize == 0 {
		return nil, fmt.Errorf("unsupported wrap algorithm: %s", wrapAlgorithm)
	}

	// Derive KEK
	kek, err := ka.DeriveKeyEncryptionKey(kekSize)
	if err != nil {
		return nil, err
	}

	// Unwrap the CEK
	cek, err := AESKeyUnwrap(kek, ek.CipherData.CipherValue)
	if err != nil {
		return nil, fmt.Errorf("key unwrap failed: %w", err)
	}

	return cek, nil
}

// ParseX25519PublicKey parses an X25519 public key from raw bytes
func ParseX25519PublicKey(data []byte) (*ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	return curve.NewPublicKey(data)
}

// ParseX25519PrivateKey parses an X25519 private key from raw bytes
func ParseX25519PrivateKey(data []byte) (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	return curve.NewPrivateKey(data)
}

// GenerateX25519KeyPair generates a new X25519 key pair
func GenerateX25519KeyPair() (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	return curve.GenerateKey(rand.Reader)
}

// DefaultHKDFParams returns default HKDF parameters for XML Encryption
func DefaultHKDFParams(info []byte) *HKDFParams {
	return &HKDFParams{
		PRF:       AlgorithmHMACSHA256,
		Salt:      nil, // Empty salt uses zero-filled salt
		Info:      info,
		KeyLength: 128, // 128 bits for AES-128-KW
	}
}
