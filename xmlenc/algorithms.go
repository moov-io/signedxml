// Package xmlenc implements XML Encryption Syntax and Processing Version 1.1
// as specified in https://www.w3.org/TR/xmlenc-core1/
//
// This package provides encryption primitives that complement the XML Signature
// functionality in signedxml. Both share common infrastructure like
// canonicalization and KeyInfo handling.
package xmlenc

// Algorithm URIs for XML Encryption 1.1
// These are the standard algorithm identifiers as defined in the W3C XML Encryption specification
const (
	// Namespace URIs
	NamespaceXMLEnc      = "http://www.w3.org/2001/04/xmlenc#"
	NamespaceXMLEnc11    = "http://www.w3.org/2009/xmlenc11#"
	NamespaceXMLDSig     = "http://www.w3.org/2000/09/xmldsig#"
	NamespaceXMLDSig11   = "http://www.w3.org/2009/xmldsig11#"
	NamespaceXMLDSigMore = "http://www.w3.org/2001/04/xmldsig-more#"
	NamespaceXMLDSig2021 = "http://www.w3.org/2021/04/xmldsig-more#"

	// Block Encryption Algorithms
	AlgorithmAES128CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	AlgorithmAES192CBC = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	AlgorithmAES256CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	AlgorithmAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	AlgorithmAES192GCM = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	AlgorithmAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	AlgorithmTripleDES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"

	// Key Transport Algorithms
	AlgorithmRSAv15    = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	AlgorithmRSAOAEP   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	AlgorithmRSAOAEP11 = "http://www.w3.org/2009/xmlenc11#rsa-oaep"

	// Key Wrap Algorithms
	AlgorithmAES128KW    = "http://www.w3.org/2001/04/xmlenc#kw-aes128"
	AlgorithmAES192KW    = "http://www.w3.org/2001/04/xmlenc#kw-aes192"
	AlgorithmAES256KW    = "http://www.w3.org/2001/04/xmlenc#kw-aes256"
	AlgorithmTripleDESKW = "http://www.w3.org/2001/04/xmlenc#kw-tripledes"

	// Key Agreement Algorithms
	AlgorithmDH     = "http://www.w3.org/2001/04/xmlenc#dh"
	AlgorithmDHES   = "http://www.w3.org/2009/xmlenc11#dh-es"
	AlgorithmECDHES = "http://www.w3.org/2009/xmlenc11#ECDH-ES"
	AlgorithmX25519 = "http://www.w3.org/2021/04/xmldsig-more#x25519"

	// Key Derivation Algorithms
	AlgorithmConcatKDF = "http://www.w3.org/2009/xmlenc11#ConcatKDF"
	AlgorithmPBKDF2    = "http://www.w3.org/2009/xmlenc11#pbkdf2"
	AlgorithmHKDF      = "http://www.w3.org/2021/04/xmldsig-more#hkdf"

	// Digest Algorithms (from XML Signature, used in key derivation)
	AlgorithmSHA1       = "http://www.w3.org/2000/09/xmldsig#sha1"
	AlgorithmSHA256     = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgorithmSHA384     = "http://www.w3.org/2001/04/xmlenc#sha384"
	AlgorithmSHA512     = "http://www.w3.org/2001/04/xmlenc#sha512"
	AlgorithmHMACSHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"

	// MGF Algorithms (for RSA-OAEP)
	AlgorithmMGF1SHA1   = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
	AlgorithmMGF1SHA256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	AlgorithmMGF1SHA384 = "http://www.w3.org/2009/xmlenc11#mgf1sha384"
	AlgorithmMGF1SHA512 = "http://www.w3.org/2009/xmlenc11#mgf1sha512"

	// Type URIs
	TypeEncryptedKey = "http://www.w3.org/2001/04/xmlenc#EncryptedKey"
	TypeDerivedKey   = "http://www.w3.org/2009/xmlenc11#DerivedKey"
	TypeElement      = "http://www.w3.org/2001/04/xmlenc#Element"
	TypeContent      = "http://www.w3.org/2001/04/xmlenc#Content"
)

// KeySize returns the key size in bytes for the given algorithm URI.
// Returns 0 if the algorithm is not recognized or has variable key size.
func KeySize(algorithm string) int {
	switch algorithm {
	case AlgorithmAES128CBC, AlgorithmAES128GCM, AlgorithmAES128KW:
		return 16 // 128 bits
	case AlgorithmAES192CBC, AlgorithmAES192GCM, AlgorithmAES192KW:
		return 24 // 192 bits
	case AlgorithmAES256CBC, AlgorithmAES256GCM, AlgorithmAES256KW:
		return 32 // 256 bits
	case AlgorithmTripleDES, AlgorithmTripleDESKW:
		return 24 // 192 bits (3 x 64-bit keys)
	default:
		return 0
	}
}

// IsGCM returns true if the algorithm is an AES-GCM variant
func IsGCM(algorithm string) bool {
	switch algorithm {
	case AlgorithmAES128GCM, AlgorithmAES192GCM, AlgorithmAES256GCM:
		return true
	default:
		return false
	}
}

// IsKeyWrap returns true if the algorithm is a key wrap algorithm
func IsKeyWrap(algorithm string) bool {
	switch algorithm {
	case AlgorithmAES128KW, AlgorithmAES192KW, AlgorithmAES256KW, AlgorithmTripleDESKW:
		return true
	default:
		return false
	}
}

// IsKeyAgreement returns true if the algorithm is a key agreement algorithm
func IsKeyAgreement(algorithm string) bool {
	switch algorithm {
	case AlgorithmDH, AlgorithmDHES, AlgorithmECDHES, AlgorithmX25519:
		return true
	default:
		return false
	}
}
