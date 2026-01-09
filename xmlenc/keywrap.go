// Package xmlenc implements XML Encryption Syntax and Processing Version 1.1
package xmlenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// AES Key Wrap (RFC 3394)
// This implements the AES Key Wrap algorithm used by XML Encryption
// for wrapping symmetric keys with a key encryption key (KEK).
//
// Reference: https://www.rfc-editor.org/rfc/rfc3394

var (
	// ErrInvalidKeySize is returned when the key size is not valid for AES
	ErrInvalidKeySize = errors.New("invalid key size: must be 16, 24, or 32 bytes")
	// ErrInvalidPlaintextSize is returned when plaintext is too small or not aligned
	ErrInvalidPlaintextSize = errors.New("invalid plaintext size: must be >= 16 bytes and multiple of 8")
	// ErrInvalidCiphertextSize is returned when ciphertext is too small or not aligned
	ErrInvalidCiphertextSize = errors.New("invalid ciphertext size: must be >= 24 bytes and multiple of 8")
	// ErrIntegrityCheckFailed is returned when the integrity check fails during unwrap
	ErrIntegrityCheckFailed = errors.New("integrity check failed: invalid wrapped key")
)

// defaultIV is the default initial value specified in RFC 3394 section 2.2.3.1
var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// AESKeyWrap wraps a content encryption key (plaintext) with a key encryption key.
//
// The plaintext must be at least 16 bytes and a multiple of 8 bytes.
// The returned ciphertext will be 8 bytes longer than the plaintext.
//
// Algorithm: RFC 3394 Section 2.2.1
func AESKeyWrap(kek, plaintext []byte) ([]byte, error) {
	return AESKeyWrapWithIV(kek, plaintext, defaultIV)
}

// AESKeyWrapWithIV wraps a content encryption key with a custom IV.
// Most uses should prefer AESKeyWrap which uses the standard IV.
func AESKeyWrapWithIV(kek, plaintext, iv []byte) ([]byte, error) {
	// Validate inputs
	if len(kek) != 16 && len(kek) != 24 && len(kek) != 32 {
		return nil, ErrInvalidKeySize
	}
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, ErrInvalidPlaintextSize
	}
	if len(iv) != 8 {
		return nil, fmt.Errorf("invalid IV size: must be 8 bytes")
	}

	// Create AES cipher
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// n = number of 64-bit blocks in plaintext
	n := len(plaintext) / 8

	// Initialize variables
	// A = IV
	a := make([]byte, 8)
	copy(a, iv)

	// R[1..n] = P[1..n] (64-bit blocks from plaintext)
	r := make([][]byte, n+1)
	for i := 1; i <= n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[(i-1)*8:i*8])
	}

	// Key wrap algorithm per RFC 3394
	// For j = 0 to 5
	//   For i = 1 to n
	//     B = AES(K, A | R[i])
	//     A = MSB(64, B) ^ t where t = (n*j)+i
	//     R[i] = LSB(64, B)
	b := make([]byte, 16)
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			// B = AES(K, A | R[i])
			copy(b[:8], a)
			copy(b[8:], r[i])
			block.Encrypt(b, b)

			// t = (n*j)+i
			t := uint64(n*j + i)

			// A = MSB(64, B) ^ t
			copy(a, b[:8])
			// XOR with t (big-endian)
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)
			for k := 0; k < 8; k++ {
				a[k] ^= tBytes[k]
			}

			// R[i] = LSB(64, B)
			copy(r[i], b[8:])
		}
	}

	// Output: C[0] = A, C[i] = R[i]
	ciphertext := make([]byte, (n+1)*8)
	copy(ciphertext[:8], a)
	for i := 1; i <= n; i++ {
		copy(ciphertext[i*8:(i+1)*8], r[i])
	}

	return ciphertext, nil
}

// AESKeyUnwrap unwraps a wrapped key encrypted with AESKeyWrap.
//
// The ciphertext must be at least 24 bytes and a multiple of 8 bytes.
// The returned plaintext will be 8 bytes shorter than the ciphertext.
//
// Algorithm: RFC 3394 Section 2.2.2
func AESKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	return AESKeyUnwrapWithIV(kek, ciphertext, defaultIV)
}

// AESKeyUnwrapWithIV unwraps with a custom IV for verification.
// Most uses should prefer AESKeyUnwrap which uses the standard IV.
func AESKeyUnwrapWithIV(kek, ciphertext, expectedIV []byte) ([]byte, error) {
	// Validate inputs
	if len(kek) != 16 && len(kek) != 24 && len(kek) != 32 {
		return nil, ErrInvalidKeySize
	}
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, ErrInvalidCiphertextSize
	}
	if len(expectedIV) != 8 {
		return nil, fmt.Errorf("invalid IV size: must be 8 bytes")
	}

	// Create AES cipher
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// n = number of 64-bit blocks - 1 (first block is the integrity check value)
	n := len(ciphertext)/8 - 1

	// Initialize variables
	// A = C[0]
	a := make([]byte, 8)
	copy(a, ciphertext[:8])

	// R[1..n] = C[1..n]
	r := make([][]byte, n+1)
	for i := 1; i <= n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[i*8:(i+1)*8])
	}

	// Key unwrap algorithm per RFC 3394
	// For j = 5 to 0
	//   For i = n to 1
	//     B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
	//     A = MSB(64, B)
	//     R[i] = LSB(64, B)
	b := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// t = n*j+i
			t := uint64(n*j + i)

			// A ^ t
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)
			axort := make([]byte, 8)
			copy(axort, a)
			for k := 0; k < 8; k++ {
				axort[k] ^= tBytes[k]
			}

			// B = AES-1(K, (A ^ t) | R[i])
			copy(b[:8], axort)
			copy(b[8:], r[i])
			block.Decrypt(b, b)

			// A = MSB(64, B)
			copy(a, b[:8])

			// R[i] = LSB(64, B)
			copy(r[i], b[8:])
		}
	}

	// Verify integrity: A should equal expected IV
	for i := 0; i < 8; i++ {
		if a[i] != expectedIV[i] {
			return nil, ErrIntegrityCheckFailed
		}
	}

	// Output: P[i] = R[i]
	plaintext := make([]byte, n*8)
	for i := 1; i <= n; i++ {
		copy(plaintext[(i-1)*8:i*8], r[i])
	}

	return plaintext, nil
}

// AESGCMEncrypt encrypts plaintext using AES-GCM.
// The IV is generated randomly and prepended to the ciphertext.
// The returned data format is: IV (12 bytes) || ciphertext || tag (16 bytes)
func AESGCMEncrypt(key, plaintext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random IV
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt: nonce is prepended, tag is appended
	ciphertext := gcm.Seal(iv, iv, plaintext, additionalData)
	return ciphertext, nil
}

// AESGCMDecrypt decrypts ciphertext encrypted with AESGCMEncrypt.
// Expects format: IV (12 bytes) || ciphertext || tag (16 bytes)
func AESGCMDecrypt(key, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv, ciphertextAndTag := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, iv, ciphertextAndTag, additionalData)
	if err != nil {
		return nil, fmt.Errorf("GCM authentication failed: %w", err)
	}

	return plaintext, nil
}

// AESCBCEncrypt encrypts plaintext using AES-CBC with PKCS#7 padding.
// The IV is generated randomly and prepended to the ciphertext.
func AESCBCEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// PKCS#7 padding
	blockSize := block.BlockSize()
	padding := blockSize - len(plaintext)%blockSize
	padtext := make([]byte, len(plaintext)+padding)
	copy(padtext, plaintext)
	for i := len(plaintext); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	// Generate random IV
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt
	ciphertext := make([]byte, blockSize+len(padtext))
	copy(ciphertext[:blockSize], iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[blockSize:], padtext)

	return ciphertext, nil
}

// AESCBCDecrypt decrypts ciphertext encrypted with AESCBCEncrypt.
// Expects format: IV (16 bytes) || ciphertext
func AESCBCDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	blockSize := block.BlockSize()
	if len(ciphertext) < blockSize*2 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext not aligned to block size")
	}

	iv := ciphertext[:blockSize]
	ciphertextOnly := ciphertext[blockSize:]

	// Decrypt
	plaintext := make([]byte, len(ciphertextOnly))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertextOnly)

	// Remove PKCS#7 padding
	padding := int(plaintext[len(plaintext)-1])
	if padding > blockSize || padding == 0 {
		return nil, fmt.Errorf("invalid PKCS#7 padding")
	}
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, fmt.Errorf("invalid PKCS#7 padding")
		}
	}
	plaintext = plaintext[:len(plaintext)-padding]

	return plaintext, nil
}
