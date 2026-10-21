package signedxml

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/beevik/etree"
)

// InsertXMLintoSignatureTemplate inserts xmlToBeInserted as a child of the
// first <Object> in xmlSignatureTemplate. No transforms are applied.
func InsertXMLintoSignatureTemplate(xmlSignatureTemplate, xmlToBeInserted string, unindent, addProcessInstructions bool) (string, error) {
	if xmlSignatureTemplate == "" || xmlToBeInserted == "" {
		return "", nil
	}

	sigDoc := etree.NewDocument()
	if addProcessInstructions {
		sigDoc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	}
	if err := sigDoc.ReadFromString(xmlSignatureTemplate); err != nil {
		return "", err
	}
	sig := sigDoc.Root()
	if sig == nil || sig.Tag != "Signature" {
		return "", errors.New("no root tag present in xmlSignatureTemplate or its root tag is not `Signature`")
	}
	obj := sig.FindElement(".//Object")
	if obj == nil {
		return "", errors.New("no 'Object' tag found in xmlSignatureTemplate, can't insert xmlToBeInserted")
	}

	sigTargetDoc := etree.NewDocument()
	if err := sigTargetDoc.ReadFromString(xmlToBeInserted); err != nil {
		return "", err
	}
	sigTarget := sigTargetDoc.Root()
	if sigTarget == nil {
		return "", errors.New("can't set root of the 'xmlToBeInserted' document")
	}

	obj.AddChild(sigTarget)
	if unindent {
		sigDoc.Unindent()
	}
	return sigDoc.WriteToString()
}

// InsertTextIntoSignatureTemplate sets the first <Object> text to the given value.
func InsertTextIntoSignatureTemplate(xmlSignatureTemplate, text string, unindent, addProcessInstructions bool) (string, error) {
	if xmlSignatureTemplate == "" || text == "" {
		return "", nil
	}

	sigDoc := etree.NewDocument()
	if addProcessInstructions {
		sigDoc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	}
	if err := sigDoc.ReadFromString(xmlSignatureTemplate); err != nil {
		return "", err
	}
	sig := sigDoc.Root()
	if sig == nil || sig.Tag != "Signature" {
		return "", errors.New("no root tag present in xmlSignatureTemplate or its root tag is not `Signature`")
	}
	obj := sig.FindElement(".//Object")
	if obj == nil {
		return "", errors.New("no 'Object' tag found in xmlSignatureTemplate, can't insert xmlToBeInserted")
	}

	obj.SetText(text)
	if unindent {
		sigDoc.Unindent()
	}
	return sigDoc.WriteToString()
}

// PrepPKCS8PrivateKey decodes PEM-encoded PKCS #8 private key bytes for Signer.Sign.
func PrepPKCS8PrivateKey(PEMKeyBytes []byte) (any, error) {
	if PEMKeyBytes == nil {
		return nil, errors.New("no private key bytes provided")
	}
	pemBlock, _ := pem.Decode(PEMKeyBytes)
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM private key")
	}
	return x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
}
