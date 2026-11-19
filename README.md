[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

## moov-io/signedxml

[![GoDoc](https://godoc.org/github.com/moov-io/signedxml?status.svg)](https://godoc.org/github.com/moov-io/signedxml)
[![Build Status](https://github.com/moov-io/signedxml/workflows/Go/badge.svg)](https://github.com/moov-io/signedxml/actions)
[![Coverage Status](https://codecov.io/gh/moov-io/signedxml/branch/master/graph/badge.svg)](https://codecov.io/gh/moov-io/signedxml)
[![Go Report Card](https://goreportcard.com/badge/github.com/moov-io/signedxml)](https://goreportcard.com/report/github.com/moov-io/signedxml)
[![Repo Size](https://img.shields.io/github/languages/code-size/moov-io/signedxml?label=project%20size)](https://github.com/moov-io/signedxml)
[![MIT  License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/moov-io/signedxml/master/LICENSE.md)
[![Slack Channel](https://img.shields.io/badge/Slack-Moov-e01563)](https://slack.moov.io/)
[![Twitter](https://img.shields.io/twitter/follow/moov?style=social)](https://twitter.com/moov?lang=en)

The signedxml package transforms and validates signed xml documents. The main use case is to support Single Sign On protocols like SAML and WS-Federation.

The `xmlenc` subpackage provides XML Encryption 1.1 support for encrypting and decrypting XML documents.

Other packages that provide similar functionality rely on C libraries, which makes them difficult to run across platforms without significant configuration.  `signedxml` is written in pure go, and can be easily used on any platform. This package was originally created by [Matt Smith](https://github.com/ma314smith) and is in use at Moov Financial.

### Install

This project requires **Go 1.26 or higher**. The current `go.mod` also sets `toolchain go1.27.4`.

`go get github.com/moov-io/signedxml`

Runnable examples live in [`examples/`](examples/).

### Included Algorithms

- Hashes
  - http://www.w3.org/2001/04/xmldsig-more#md5
  - http://www.w3.org/2000/09/xmldsig#sha1
  - http://www.w3.org/2001/04/xmldsig-more#sha224
  - http://www.w3.org/2001/04/xmlenc#sha256
  - http://www.w3.org/2001/04/xmldsig-more#sha384
  - http://www.w3.org/2001/04/xmlenc#sha512


- Signatures

  Not every algorithm can be used for both signing and validation. `Signer.Sign` accepts a `crypto.Signer` for the algorithms in the Sign column (typically `*rsa.PrivateKey` or `ed25519.PrivateKey`). ECDSA and DSA keys are not supported for signing.

  | Algorithm | Sign | Validate | Notes |
  | --- | --- | --- | --- |
  | http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 | yes | yes | |
  | http://www.w3.org/2001/04/xmldsig-more#rsa-sha384 | yes | yes | |
  | http://www.w3.org/2001/04/xmldsig-more#rsa-sha512 | yes | yes | |
  | http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1 | yes | yes | RSA-PSS |
  | http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1 | yes | yes | RSA-PSS |
  | http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1 | yes | yes | RSA-PSS |
  | http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519 | yes | yes | Ed25519 |
  | http://www.w3.org/2000/09/xmldsig#rsa-sha1 | yes | yes | legacy / SHA-1 |
  | http://www.w3.org/2001/04/xmldsig-more#rsa-md5 | yes | no | legacy; Go's x509 library rejects MD5 signatures |
  | http://www.w3.org/2001/04/xmldsig-more#rsa-md2 | no | no | legacy; not implemented for signing |
  | http://www.w3.org/2000/09/xmldsig#dsa-sha1 | no | legacy | not implemented for signing |
  | http://www.w3.org/2000/09/xmldsig#dsa-sha256 | no | legacy | not implemented for signing |
  | http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1 | no | yes | legacy / SHA-1; not implemented for signing |
  | http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256 | no | yes | not implemented for signing |
  | http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384 | no | yes | not implemented for signing |
  | http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512 | no | yes | not implemented for signing |


- Canonicalization Methods/Transforms
  - http://www.w3.org/2000/09/xmldsig#enveloped-signature
  - http://www.w3.org/TR/2001/REC-xml-c14n-20010315
  - http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments
  - http://www.w3.org/2001/10/xml-exc-c14n#
  - http://www.w3.org/2001/10/xml-exc-c14n#WithComments
  - http://www.w3.org/2006/12/xml-c14n11
  - http://www.w3.org/2006/12/xml-c14n11#WithComments

### Examples

#### Validating signed XML
If your signed xml contains the signature and certificate, then you can just pass in the xml and call `ValidateReferences()`.
```go
validator, err := signedxml.NewValidator(`<YourXMLString></YourXMLString>`)
if err != nil {
    // handle error
}
refs, err := validator.ValidateReferences()
if err != nil {
    // handle error
}
// Use only the returned refs, not the original document. Callers that ignore
// the returned references and keep using the input XML are vulnerable to XML
// injection and signature wrapping.
```
`ValidateReferences()` verifies the DigestValue and SignatureValue in the xml document, and returns the signed payload(s). If the error value is `nil`, then the signed xml is valid.

The x509.Certificate that was successfully used to validate the xml will be available by calling:
```go
validator.SigningCert()
```

signedxml does not build a certificate chain or check expiry. Trust is the caller's responsibility:

- If you do not set `Validator.Certificates`, any self-signed certificate embedded in the XML can be used to validate the signature. After a successful call you **must** check `SigningCert()` against your own trust store.
- If you do set `Certificates`, only those certificates are tried. A signature produced by a different key fails with "Calculated signature does not match the SignatureValue provided", not a separate "untrusted signer" error.

#### Using an external Signature
If you need to specify an external Signature, you can use the `SetSignature()` function to assign it:
```go
validator.SetSignature(`<Signature></Signature>`)
```

#### Generating signed XML
The input XML must already contain a `Signature` element with the parameters set (except `DigestValue` and `SignatureValue`). By default references are looked up with an `ID` attribute (`ID="doc"` with `URI="#doc"`). Include `KeyInfo/X509Data/X509Certificate` if you want the validator to find the certificate in the document.

Minimal enveloped-signature template:

```xml
<?xml version="1.0"?>
<Document ID="doc">
  <Amount>100.00</Amount>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference URI="#doc">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue></SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate><!-- base64 DER of the signing certificate --></X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
</Document>
```

```go
signer, err := signedxml.NewSigner(xml)
if err != nil {
    // handle error
}
signedXML, err := signer.Sign(privateKey) // *rsa.PrivateKey or ed25519.PrivateKey
if err != nil {
    // handle error
}

validator, err := signedxml.NewValidator(signedXML)
if err != nil {
    // handle error
}
validator.Certificates = []x509.Certificate{trustedCert}
refs, err := validator.ValidateReferences()
```

A complete sign-and-validate example is in [`examples/example_test.go`](examples/example_test.go).

#### Generating signed XML with Ed25519
Use the same template, with `SignatureMethod` set to `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519`:

```go
import (
    "crypto/ed25519"
    "crypto/rand"
)

signer, err := signedxml.NewSigner(xml)
if err != nil {
    // handle error
}
_, privKey, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
    // handle error
}
signedXML, err := signer.Sign(privKey)
```

#### Implementing custom transforms
Additional Transform algorithms can be included by adding to the CanonicalizationAlgorithms map.  This interface will need to be implemented:
```go
type CanonicalizationAlgorithm interface {
	ProcessElement(inputXML *etree.Element, transformXML string) (outputXML string, err error)
	ProcessDocument(doc *etree.Document, transformXML string) (outputXML string, err error)
	Process(inputXML string, transformXML string) (outputXML string, err error)
}
```
Simple Example:
```go
type NoChangeCanonicalization struct{}

func (n NoChangeCanonicalization) Process(inputXML string,
	transformXML string) (outputXML string, err error) {
	return inputXML, nil
}

func (n NoChangeCanonicalization) ProcessElement(inputXML *etree.Element,
	transformXML string) (outputXML string, err error) {
	doc := etree.NewDocument()
	doc.SetRoot(inputXML.Copy())
	return n.ProcessDocument(doc, transformXML)
}

func (n NoChangeCanonicalization) ProcessDocument(doc *etree.Document,
	transformXML string) (outputXML string, err error) {
	return doc.WriteToString()
}

signedxml.CanonicalizationAlgorithms["http://myTransform"] = NoChangeCanonicalization{}
```

See `envelopedsignature.go` and `exclusivecanonicalization.go` for examples of actual implementations.

### Using a custom reference ID attribute
It is possible to set a custom reference ID attribute for both the signer and the validator. The default value is `"ID"`

Signer example:
```go
signer.SetReferenceIDAttribute("customId")
```

Validator example:
```go
validator.SetReferenceIDAttribute("customId")
```

## Getting help

 channel | info
 ------- | -------
Twitter [@moov](https://twitter.com/moov)	| You can follow Moov.io's Twitter feed to get updates on our project(s). You can also tweet us questions or just share blogs or stories.
[GitHub Issue](https://github.com/moov-io/signedxml/issues/new) | If you are able to reproduce a problem please open a GitHub Issue under the specific project that caused the error.
[moov-io slack](https://slack.moov.io/) | Join our slack channel to have an interactive discussion about the development of the project.

## Contributions

Contributions are welcome. Just fork the repo and send a pull request.

## Related Projects

- [Moov RTP20022](https://github.com/moov-io/rtp20022) implements ISO20022 messages in Go for Real Time Payments (RTP)
