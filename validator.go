package signedxml

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/beevik/etree"
)

// OID for RSA-PSS: 1.2.840.113549.1.1.10
var oidRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

// rsaPSSPublicKeyInfo is used for parsing RSA-PSS public key from certificate
type rsaPSSPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// rsaPublicKeyASN1 is used for parsing the RSA public key structure
type rsaPublicKeyASN1 struct {
	N *big.Int
	E int
}

// tbsCertificateForPSS is used for parsing certificates with RSA-PSS keys
type tbsCertificateForPSS struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          rsaPSSPublicKeyInfo
}

// certificateForPSS is used for parsing certificates with RSA-PSS keys
type certificateForPSS struct {
	Raw            asn1.RawContent
	TBSCertificate tbsCertificateForPSS
}

// extractRSAPSSPublicKey extracts the RSA public key from a certificate that uses
// RSA-PSS OID for its public key. Go's x509 library doesn't support this natively.
func extractRSAPSSPublicKey(certDer []byte) (*rsa.PublicKey, error) {
	var cert certificateForPSS
	_, err := asn1.Unmarshal(certDer, &cert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if this is RSA-PSS
	if !cert.TBSCertificate.PublicKey.Algorithm.Algorithm.Equal(oidRSASSAPSS) {
		return nil, fmt.Errorf("not an RSA-PSS public key")
	}

	// Parse the RSA public key from the bit string
	var rsaPub rsaPublicKeyASN1
	_, err = asn1.Unmarshal(cert.TBSCertificate.PublicKey.PublicKey.Bytes, &rsaPub)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	return &rsa.PublicKey{
		N: rsaPub.N,
		E: rsaPub.E,
	}, nil
}

// Validator provides options for verifying a signed XML document
type Validator struct {
	Certificates []x509.Certificate
	signingCert  x509.Certificate
	signatureData
}

// NewValidator returns a *Validator for the XML provided
func NewValidator(xml string) (*Validator, error) {
	doc, err := parseXML(xml)
	if err != nil {
		return nil, err
	}
	v := &Validator{signatureData: signatureData{xml: doc}}
	return v, nil
}

// SetReferenceIDAttribute set the referenceIDAttribute
func (v *Validator) SetReferenceIDAttribute(refIDAttribute string) {
	v.signatureData.refIDAttribute = refIDAttribute
}

// SetXML is used to assign the XML document that the Validator will verify
func (v *Validator) SetXML(xml string) error {
	doc := etree.NewDocument()
	doc.ReadSettings.PreserveCData = true
	err := doc.ReadFromString(xml)
	v.xml = doc
	return err
}

// SigningCert returns the certificate, if any, that was used to successfully
// validate the signature of the XML document. This will be a zero value
// x509.Certificate before Validator.Validate is successfully called.
func (v *Validator) SigningCert() x509.Certificate {
	return v.signingCert
}

// ValidateReferences validates the Reference digest values, and the signature value
// over the SignedInfo.
//
// If the signature is enveloped in the XML, then it will be used.
// Otherwise, an external signature should be assigned using
// Validator.SetSignature.
//
// The references returned contain validated XML from the signature and must be used.
// Callers that ignore the returned references are vulnerable to XML injection.
func (v *Validator) ValidateReferences() ([]string, error) {
	if err := v.loadValuesFromXML(); err != nil {
		return nil, err
	}

	referenced, err := v.validateReferences()
	if err != nil {
		return nil, err
	}

	var ref []string
	for _, doc := range referenced {
		docStr, err := doc.WriteToString()
		if err != nil {
			return nil, err
		}
		ref = append(ref, docStr)
	}

	err = v.validateSignature()
	return ref, err
}

func (v *Validator) loadValuesFromXML() error {
	if v.signature == nil {
		if err := v.parseEnvelopedSignature(); err != nil {
			return err
		}
	}
	if err := v.parseSignedInfo(); err != nil {
		return err
	}
	if err := v.parseSigValue(); err != nil {
		return err
	}
	if err := v.parseSigAlgorithm(); err != nil {
		return err
	}
	if err := v.parseCanonAlgorithm(); err != nil {
		return err
	}
	if err := v.loadCertificates(); err != nil {
		return err
	}
	return nil
}

func (v *Validator) validateReferences() (referenced []*etree.Document, err error) {
	references := v.signedInfo.FindElements("./Reference")
	for _, ref := range references {
		doc := v.xml.Copy()

		transforms := ref.SelectElement("Transforms")
		if transforms != nil {
			for _, transform := range transforms.SelectElements("Transform") {
				doc, err = processTransform(transform, doc, ALL_TRANSFORMS)
				if err != nil {
					return nil, err
				}
			}
		}

		refUri := ref.SelectAttrValue("URI", "")
		doc, err = v.getReferencedXML(ref, doc)
		if err != nil {
			return nil, err
		}

		if transforms != nil {
			for _, transform := range transforms.SelectElements("Transform") {
				doc, err = processTransform(transform, doc, "c14n")
				if err != nil {
					return nil, err
				}
			}
		}

		referenced = append(referenced, doc)

		digestValueElement := ref.SelectElement("DigestValue")
		if digestValueElement == nil {
			return nil, fmt.Errorf("signedxml [%s]: unable to find DigestValue", refUri)
		}
		digestValue := digestValueElement.Text()
		calculatedValue, err := calculateHash(ref, doc)
		if err != nil {
			return nil, err
		}

		if calculatedValue != digestValue {
			return nil, fmt.Errorf("signedxml [%s]: Calculated digest (%s) does not match the"+
				" expected digestvalue of %s", refUri, calculatedValue, digestValue)
		}
	}
	return referenced, nil
}

func (v *Validator) validateSignature() error {
	canonSignedInfo, err := v.canonAlgorithm.ProcessElement(v.signedInfo, "")
	if err != nil {
		return err
	}

	b64, err := base64.StdEncoding.DecodeString(v.sigValue)
	if err != nil {
		return err
	}
	sig := []byte(b64)

	v.signingCert = x509.Certificate{}
	for _, cert := range v.Certificates {
		err := cert.CheckSignature(v.sigAlgorithm, []byte(canonSignedInfo), sig)
		if err == nil {
			v.signingCert = cert
			return nil
		}
		// If standard verification failed with "algorithm unimplemented" and we're using
		// RSA-PSS, try manual verification - this handles certificates with RSA-PSS public keys
		if cert.PublicKey == nil && isRSAPSSAlgorithm(v.sigAlgorithm) {
			verifyErr := v.verifyRSAPSSSignature(cert.Raw, []byte(canonSignedInfo), sig)
			if verifyErr == nil {
				v.signingCert = cert
				return nil
			}
		}
	}

	return errors.New("signedxml: Calculated signature does not match the " +
		"SignatureValue provided")
}

// isRSAPSSAlgorithm returns true if the algorithm is RSA-PSS
func isRSAPSSAlgorithm(alg x509.SignatureAlgorithm) bool {
	return alg == x509.SHA256WithRSAPSS || alg == x509.SHA384WithRSAPSS || alg == x509.SHA512WithRSAPSS
}

// verifyRSAPSSSignature manually verifies an RSA-PSS signature for certificates
// with RSA-PSS public keys that Go's x509 library can't handle
func (v *Validator) verifyRSAPSSSignature(certDer, data, sig []byte) error {
	rsaPub, err := extractRSAPSSPublicKey(certDer)
	if err != nil {
		return err
	}

	hash, ok := rsaPSSHashAlgorithms[v.sigAlgorithm]
	if !ok {
		return fmt.Errorf("unsupported RSA-PSS algorithm: %v", v.sigAlgorithm)
	}

	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Use PSSSaltLengthAuto for maximum compatibility
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       hash,
	}

	return rsa.VerifyPSS(rsaPub, hash, hashed, sig, opts)
}

func (v *Validator) loadCertificates() error {
	// If v.Certificates is already populated, then the client has already set it
	// to the desired cert. Otherwise, let's pull the public keys from the XML
	if len(v.Certificates) < 1 {
		keydata := v.xml.FindElements(".//X509Certificate")
		for _, key := range keydata {
			cert, err := getCertFromPEMString(key.Text())
			if err != nil {
				log.Printf("signedxml: Unable to load certificate: (%s). "+
					"Looking for another cert.", err)
			} else {
				v.Certificates = append(v.Certificates, *cert)
			}
		}
	}

	if len(v.Certificates) < 1 {
		return errors.New("signedxml: a certificate is required, but was not found")
	}
	return nil
}
