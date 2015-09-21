package signedxml

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/ma314smith/etree"
)

// Validator provides options for verifying a signed XML document
type Validator struct {
	xml            *etree.Document
	Certificates   []x509.Certificate
	signingCert    x509.Certificate
	signature      *etree.Element
	signedInfo     *etree.Element
	sigValue       string
	sigAlogrithm   x509.SignatureAlgorithm
	canonAlgorithm CanonicalizationAlgorithm
}

// NewValidator returns a *Validator for the XML provided
func NewValidator(xml string) (*Validator, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(xml)
	if err != nil {
		return nil, err
	}
	v := &Validator{xml: doc}
	return v, nil
}

// SetXML is used to assign the XML document that the Validator will verify
func (v *Validator) SetXML(xml string) error {
	doc := etree.NewDocument()
	err := doc.ReadFromString(xml)
	v.xml = doc
	return err
}

// SetSignature can be used to assign an external signature for the XML doc
// that Validator will verify
func (v *Validator) SetSignature(sig string) error {
	doc := etree.NewDocument()
	err := doc.ReadFromString(sig)
	v.signature = doc.Root()
	return err
}

// SigningCert returns the certificate, if any, that was used to successfully
// validate the signature of the XML document. This will be a zero value
// x509.Certificate before Validator.CheckSignature is successfully called.
func (v *Validator) SigningCert() x509.Certificate {
	return v.signingCert
}

// Validate validates the Reference digest values, and the signature value
// over the SignedInfo.
//
// If the signature is enveloped in the Validator.XML, then it will be used.
// Otherwise, an external signature should be assinged using
// Validator.SetSignature.
func (v *Validator) Validate() error {
	if err := v.loadValuesFromXML(); err != nil {
		return err
	}

	if err := v.validateReferences(); err != nil {
		return err
	}

	err := v.validateSignature()
	return err
}

func (v *Validator) loadValuesFromXML() error {
	if v.signature == nil {
		if err := v.setEnvelopedSignature(); err != nil {
			return err
		}
	}
	if err := v.setSignedInfo(); err != nil {
		return err
	}
	if err := v.setSigValue(); err != nil {
		return err
	}
	if err := v.setSigAlgorithm(); err != nil {
		return err
	}
	if err := v.setCanonAlgorithm(); err != nil {
		return err
	}
	if err := v.loadCertificates(); err != nil {
		return err
	}
	return nil
}

func (v *Validator) validateReferences() (err error) {
	references := v.signedInfo.FindElements("./Reference")
	for _, ref := range references {
		doc := v.xml.Copy()
		transforms := ref.SelectElement("Transforms")
		for _, transform := range transforms.SelectElements("Transform") {
			doc, err = processTransform(transform, doc)
			if err != nil {
				return err
			}
		}

		doc, err = v.getReferencedXML(ref, doc)
		if err != nil {
			return err
		}

		digestValueElement := ref.SelectElement("DigestValue")
		if digestValueElement == nil {
			return errors.New("signedxml: unable to find DigestValue")
		}
		digestValue := digestValueElement.Text()

		calculatedValue, err := calculateHash(ref, doc)
		if err != nil {
			return err
		}

		if calculatedValue != digestValue {
			return fmt.Errorf("signedxml: Calculated digest does not match the"+
				" expected digestvalue of %s", digestValue)
		}
	}
	return nil
}

func (v *Validator) getReferencedXML(reference *etree.Element, inputDoc *etree.Document) (outputDoc *etree.Document, err error) {
	uri := reference.SelectAttrValue("URI", "")
	// populate doc with the referenced xml from the Reference URI
	if uri == "" || uri == "#" {
		outputDoc = inputDoc
	} else {
		path := fmt.Sprintf(".//[@ID='%s']", strings.Replace(uri, "#", "", 1))
		e := inputDoc.FindElement(path)
		if e != nil {
			outputDoc = etree.CreateDocument(e).Copy()
		}
	}

	if outputDoc == nil {
		return nil, errors.New("signedxml: unable to find refereced xml")
	}

	return outputDoc, nil
}

func (v *Validator) validateSignature() error {
	signedInfo, err := etree.CreateDocument(v.signedInfo).WriteToString()
	if err != nil {
		return err
	}

	canonSignedInfo, err := v.canonAlgorithm.Process(signedInfo, "")
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
		err := cert.CheckSignature(v.sigAlogrithm, []byte(canonSignedInfo), sig)
		if err == nil {
			v.signingCert = cert
			return nil
		}
	}

	return errors.New("signedxml: Calculated signature does not match the " +
		"SignatureValue provided")
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

func (v *Validator) setEnvelopedSignature() error {
	sig := v.xml.FindElement(".//Signature")
	if sig != nil {
		v.signature = sig
	} else {
		return errors.New("signedxml: Unable to find a unique signature element " +
			"in the xml document. The signature must either be enveloped in the " +
			"xml doc or externally assigned to Validator.SetSignature")
	}
	return nil
}

func (v *Validator) setSignedInfo() error {
	v.signedInfo = nil
	v.signedInfo = v.signature.SelectElement("SignedInfo")
	if v.signedInfo == nil {
		return errors.New("signedxml: unable to find SignedInfo element")
	}

	// move the Signature level namespace down to SignedInfo so that the signature
	// value will match up
	if v.signedInfo.Space != "" {
		attr := v.signature.SelectAttr(v.signedInfo.Space)
		if attr != nil {
			v.signedInfo.Attr = []etree.Attr{*attr}
		}
	} else {
		attr := v.signature.SelectAttr("xmlns")
		if attr != nil {
			v.signedInfo.Attr = []etree.Attr{*attr}
		}
	}

	return nil
}

func (v *Validator) setSigValue() error {
	v.sigValue = ""
	sigValueElement := v.signature.SelectElement("SignatureValue")
	if sigValueElement != nil {
		v.sigValue = sigValueElement.Text()
		return nil
	}
	return errors.New("signedxml: unable to find SignatureValue")
}

func (v *Validator) setSigAlgorithm() error {
	v.sigAlogrithm = x509.UnknownSignatureAlgorithm
	sigMethod := v.signedInfo.SelectElement("SignatureMethod")

	var sigAlgoURI string
	if sigMethod == nil {
		return errors.New("Unable to find SignatureMethod element")
	}

	sigAlgoURI = sigMethod.SelectAttrValue("Algorithm", "")
	sigAlgo, ok := signatureAlgorithms[sigAlgoURI]
	if ok {
		v.sigAlogrithm = sigAlgo
		return nil
	}

	return errors.New("Unable to find Algorithm in SignatureMethod element")
}

func (v *Validator) setCanonAlgorithm() error {
	v.canonAlgorithm = nil
	canonMethod := v.signedInfo.SelectElement("CanonicalizationMethod")

	var canonAlgoURI string
	if canonMethod == nil {
		return errors.New("Unable to find CanonicalizationMethod element")
	}

	canonAlgoURI = canonMethod.SelectAttrValue("Algorithm", "")
	canonAlgo, ok := CanonicalizationAlgorithms[canonAlgoURI]
	if ok {
		v.canonAlgorithm = canonAlgo
		return nil
	}

	return errors.New("Unable to find Algorithm in " +
		"CanonicalizationMethod element")
}
