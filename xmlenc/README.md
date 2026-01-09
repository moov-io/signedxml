# xmlenc - XML Encryption 1.1 for Go

This package implements XML Encryption Syntax and Processing Version 1.1 as specified in [W3C Recommendation](https://www.w3.org/TR/xmlenc-core1/).

## Features

- **AES Key Wrap** (RFC 3394) - AES-128/192/256-KW
- **X25519 Key Agreement** with HKDF key derivation
- **AES-GCM** and **AES-CBC** content encryption
- **Complete XML Encryption types**: EncryptedData, EncryptedKey, AgreementMethod, KeyDerivationMethod
- **XML serialization/parsing** compatible with standard XML Encryption documents

## Installation

```bash
go get github.com/leifj/signedxml/xmlenc
```

## Quick Start

### Encrypt an XML Element with X25519

```go
import (
    "github.com/beevik/etree"
    "github.com/leifj/signedxml/xmlenc"
)

// Generate or load recipient X25519 key
recipientPrivate, _ := xmlenc.GenerateX25519KeyPair()
recipientPublic := recipientPrivate.PublicKey()

// Create XML document
doc := etree.NewDocument()
root := doc.CreateElement("Message")
sensitive := root.CreateElement("SensitiveData")
sensitive.SetText("Confidential information")

// Encrypt with X25519 + AES-128-GCM
hkdfParams := xmlenc.DefaultHKDFParams([]byte("Application context"))
senderKA, _ := xmlenc.NewX25519KeyAgreement(recipientPublic, hkdfParams)
encryptor := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, senderKA)

encryptedData, _ := encryptor.EncryptElement(sensitive)

// Generate XML output
xmlDoc := xmlenc.NewEncryptedDataDocument(encryptedData)
xmlBytes, _ := xmlDoc.WriteToBytes()
```

### Decrypt an EncryptedData Element

```go
// Parse the EncryptedData from XML
doc := etree.NewDocument()
doc.ReadFromBytes(xmlBytes)
encryptedData, _ := xmlenc.ParseEncryptedData(doc.Root())

// Extract ephemeral public key from EncryptedKey
ephemeralPubBytes := encryptedData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.
    OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
ephemeralPublic, _ := xmlenc.ParseX25519PublicKey(ephemeralPubBytes)

// Create key agreement for decryption
recipientKA := xmlenc.NewX25519KeyAgreementForDecrypt(
    recipientPrivate, ephemeralPublic, hkdfParams)

// Decrypt
decryptor := xmlenc.NewDecryptor(recipientKA)
decryptedElement, _ := decryptor.DecryptElement(encryptedData)
```

### Use AES Key Wrap Directly

```go
// Wrap a key
kek := make([]byte, 16) // Key Encryption Key
plaintext := make([]byte, 16) // Key to wrap

ciphertext, _ := xmlenc.AESKeyWrap(kek, plaintext)

// Unwrap
unwrapped, _ := xmlenc.AESKeyUnwrap(kek, ciphertext)
```

## Supported Algorithms

### Block Encryption

| Algorithm | URI |
|-----------|-----|
| AES-128-GCM | `http://www.w3.org/2009/xmlenc11#aes128-gcm` |
| AES-192-GCM | `http://www.w3.org/2009/xmlenc11#aes192-gcm` |
| AES-256-GCM | `http://www.w3.org/2009/xmlenc11#aes256-gcm` |
| AES-128-CBC | `http://www.w3.org/2001/04/xmlenc#aes128-cbc` |
| AES-192-CBC | `http://www.w3.org/2001/04/xmlenc#aes192-cbc` |
| AES-256-CBC | `http://www.w3.org/2001/04/xmlenc#aes256-cbc` |

### Key Wrap

| Algorithm | URI |
|-----------|-----|
| AES-128-KW | `http://www.w3.org/2001/04/xmlenc#kw-aes128` |
| AES-192-KW | `http://www.w3.org/2001/04/xmlenc#kw-aes192` |
| AES-256-KW | `http://www.w3.org/2001/04/xmlenc#kw-aes256` |

### Key Agreement

| Algorithm | URI |
|-----------|-----|
| X25519 | `http://www.w3.org/2021/04/xmldsig-more#x25519` |
| ECDH-ES | `http://www.w3.org/2009/xmlenc11#ECDH-ES` |

### Key Derivation

| Algorithm | URI |
|-----------|-----|
| HKDF | `http://www.w3.org/2021/04/xmldsig-more#hkdf` |
| ConcatKDF | `http://www.w3.org/2009/xmlenc11#ConcatKDF` |

## EU eDelivery AS4 2.0 Compatibility

This package is designed to support the EU eDelivery AS4 2.0 interoperability profile which mandates:

- X25519 key agreement
- HKDF key derivation with HMAC-SHA256
- AES-128-KW key wrapping
- AES-128-GCM content encryption

Example for EU AS4 2.0:

```go
// EU AS4 2.0 Common Usage Profile
hkdfParams := &xmlenc.HKDFParams{
    PRF:       xmlenc.AlgorithmHMACSHA256,
    Info:      []byte("eDelivery AS4 2.0"),
    KeyLength: 128, // bits
}

senderKA, _ := xmlenc.NewX25519KeyAgreement(recipientPublicKey, hkdfParams)
encryptor := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, senderKA)
```

## XML Output Example

The generated XML follows the XML Encryption 1.1 specification:

```xml
<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" 
                   Type="http://www.w3.org/2001/04/xmlenc#Element">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <xenc:EncryptedKey>
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/>
      <ds:KeyInfo>
        <xenc:AgreementMethod Algorithm="http://www.w3.org/2021/04/xmldsig-more#x25519">
          <xenc11:KeyDerivationMethod xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" 
                                     Algorithm="http://www.w3.org/2021/04/xmldsig-more#hkdf">
            <dsig-more:HKDFParams xmlns:dsig-more="http://www.w3.org/2001/04/xmldsig-more#">
              <dsig-more:PRF Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>
              <dsig-more:Info>...</dsig-more:Info>
              <dsig-more:KeyLength>128</dsig-more:KeyLength>
            </dsig-more:HKDFParams>
          </xenc11:KeyDerivationMethod>
          <xenc:OriginatorKeyInfo>
            <ds:KeyValue>
              <dsig11:ECKeyValue xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
                <dsig11:NamedCurve URI="urn:ietf:params:xml:ns:keyprov:curve:x25519"/>
                <dsig11:PublicKey>...</dsig11:PublicKey>
              </dsig11:ECKeyValue>
            </ds:KeyValue>
          </xenc:OriginatorKeyInfo>
        </xenc:AgreementMethod>
      </ds:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>...</xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedKey>
  </ds:KeyInfo>
  <xenc:CipherData>
    <xenc:CipherValue>...</xenc:CipherValue>
  </xenc:CipherData>
</xenc:EncryptedData>
```

## References

- [XML Encryption Syntax and Processing Version 1.1](https://www.w3.org/TR/xmlenc-core1/)
- [RFC 3394: AES Key Wrap Algorithm](https://www.rfc-editor.org/rfc/rfc3394.html)
- [RFC 9231: Additional XML Security URIs](https://www.rfc-editor.org/rfc/rfc9231.html)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)

## License

MIT License - see parent signedxml package for details.
