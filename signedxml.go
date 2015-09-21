// Package signedxml transforms and validates signedxml documents
package signedxml

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/ma314smith/etree"
)

var logger = log.New(os.Stdout, "DEBUG-SIGNEDXML: ", log.Ldate|log.Ltime|log.Lshortfile)

func init() {
	etree.SupportCanonicalXML = true

	hashAlgorithms = map[string]crypto.Hash{
		"http://www.w3.org/2001/04/xmldsig-more#md5":    crypto.MD5,
		"http://www.w3.org/2000/09/xmldsig#sha1":        crypto.SHA1,
		"http://www.w3.org/2001/04/xmldsig-more#sha224": crypto.SHA224,
		"http://www.w3.org/2001/04/xmlenc#sha256":       crypto.SHA256,
		"http://www.w3.org/2001/04/xmldsig-more#sha384": crypto.SHA384,
		"http://www.w3.org/2001/04/xmlenc#sha512":       crypto.SHA512,
		"http://www.w3.org/2001/04/xmlenc#ripemd160":    crypto.RIPEMD160,
	}

	signatureAlgorithms = map[string]x509.SignatureAlgorithm{
		"http://www.w3.org/2001/04/xmldsig-more#rsa-md2":      x509.MD2WithRSA,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-md5":      x509.MD5WithRSA,
		"http://www.w3.org/2000/09/xmldsig#rsa-sha1":          x509.SHA1WithRSA,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   x509.SHA256WithRSA,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   x509.SHA384WithRSA,
		"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   x509.SHA512WithRSA,
		"http://www.w3.org/2000/09/xmldsig#dsa-sha1":          x509.DSAWithSHA1,
		"http://www.w3.org/2000/09/xmldsig#dsa-sha256":        x509.DSAWithSHA256,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1":   x509.ECDSAWithSHA1,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": x509.ECDSAWithSHA256,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": x509.ECDSAWithSHA384,
		"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": x509.ECDSAWithSHA512,
	}

	CanonicalizationAlgorithms = map[string]CanonicalizationAlgorithm{
		"http://www.w3.org/2000/09/xmldsig#enveloped-signature": EnvelopedSignature{},
		"http://www.w3.org/2001/10/xml-exc-c14n#":               ExclusiveCanonicalization{},
		"http://www.w3.org/2001/10/xml-exc-c14n#WithComments":   ExclusiveCanonicalization{WithComments: true},
	}
}

// CanonicalizationAlgorithm defines an interface for processing an XML
// document into a standard format.
//
// If any child elements are in the Transform node, the entire transform node
// will be passed to the Process method through the transformXML parameter as an
// XML string. This is necessary for transforms that need additional processing
// data, like XPath (http://www.w3.org/TR/xmldsig-core/#sec-XPath). If there are
// no child elements in Transform (or CanonicalizationMethod), then an empty
// string will be passed through.
type CanonicalizationAlgorithm interface {
	Process(inputXML string, transformXML string) (outputXML string, err error)
}

// CanonicalizationAlgorithms maps the CanonicalizationMethod or
// Transform Algorithm URIs to a type that implements the
// CanonicalizationAlgorithm interface.
//
// Implementations are provided for the following transforms:
//  http://www.w3.org/2001/10/xml-exc-c14n# (ExclusiveCanonicalization)
//  http://www.w3.org/2001/10/xml-exc-c14n#WithComments (ExclusiveCanonicalizationWithComments)
//  http://www.w3.org/2000/09/xmldsig#enveloped-signature (EnvelopedSignature)
//
// Custom implementations can be added to the map
var CanonicalizationAlgorithms map[string]CanonicalizationAlgorithm
var hashAlgorithms map[string]crypto.Hash
var signatureAlgorithms map[string]x509.SignatureAlgorithm

func getCertFromPEMString(pemString string) (*x509.Certificate, error) {
	pubkey := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
		pemString)

	pemBlock, _ := pem.Decode([]byte(pubkey))
	if pemBlock == nil {
		return &x509.Certificate{}, errors.New("Could not parse Public Key PEM")
	}
	if pemBlock.Type != "PUBLIC KEY" {
		return &x509.Certificate{}, errors.New("Found wrong key type")
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	return cert, err
}

func processTransform(transform *etree.Element,
	docIn *etree.Document) (docOut *etree.Document, err error) {

	transformAlgoURI := transform.SelectAttrValue("Algorithm", "")
	if transformAlgoURI == "" {
		return nil, errors.New("signedxml: unable to find Algorithm in Transform")
	}

	transformAlgo, ok := CanonicalizationAlgorithms[transformAlgoURI]
	if !ok {
		return nil, fmt.Errorf("signedxml: unable to find matching transform"+
			"algorithm for %s in CanonicalizationAlgorithms", transformAlgoURI)
	}

	var transformContent string

	if transform.ChildElements() != nil {
		tDoc := etree.CreateDocument(transform)
		transformContent, err = tDoc.WriteToString()
		if err != nil {
			return nil, err
		}
	}

	docString, err := docIn.WriteToString()
	if err != nil {
		return nil, err
	}

	docString, err = transformAlgo.Process(docString, transformContent)
	if err != nil {
		return nil, err
	}

	docOut = etree.NewDocument()
	docOut.ReadFromString(docString)

	return docOut, nil
}

func calculateHash(reference *etree.Element, doc *etree.Document) (string, error) {
	digestMethodElement := reference.SelectElement("DigestMethod")
	if digestMethodElement == nil {
		return "", errors.New("signedxml: unable to find DigestMethod")
	}

	digestMethodURI := digestMethodElement.SelectAttrValue("Algorithm", "")
	if digestMethodURI == "" {
		return "", errors.New("signedxml: unable to find Algorithm in DigestMethod")
	}

	digestAlgo, ok := hashAlgorithms[digestMethodURI]
	if !ok {
		return "", fmt.Errorf("signedxml: unable to find matching hash"+
			"algorithm for %s in hashAlgorithms", digestMethodURI)
	}

	h := digestAlgo.New()
	docBytes, err := doc.WriteToBytes()
	if err != nil {
		return "", err
	}

	ioutil.WriteFile("C:/Temp/SignedXML/Suspect.xml", docBytes, 0644)
	//s, _ := doc.WriteToString()
	//logger.Println(s)

	h.Write(docBytes)
	d := h.Sum(nil)
	calculatedValue := base64.StdEncoding.EncodeToString(d)

	return calculatedValue, nil
}
