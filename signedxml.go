// Package signedxml transforms and validates signedxml documents
package signedxml

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/beevik/etree"
)

var logger = log.New(os.Stdout, "DEBUG-SIGNEDXML: ", log.Ldate|log.Ltime|log.Lshortfile)

func init() {
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

		// xmllib2 canonicalizers, added:
		// "http://www.w3.org/TR/xml-c14n":                                C14N10Canonicalizer{},
		// "http://www.w3.org/TR/xml-c14n#WithComments":                   C14N10Canonicalizer{WithComments: true},
		"http://www.w3.org/TR/2001/REC-xml-c14n-20010315":              C14N10Canonicalizer{},
		"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments": C14N10Canonicalizer{WithComments: true},
		// "http://www.w3.org/TR/xml-exc-c14n":                            C14N10ExclusiveCanonicalizer{},
		// "http://www.w3.org/TR/xml-exc-c14n#WithComments":               C14N10ExclusiveCanonicalizer{WithComments: true},
		"http://www.w3.org/2006/12/xml-c14n11":              C14N11Canonicalizer{},
		"http://www.w3.org/2006/12/xml-c14n11#WithComments": C14N11Canonicalizer{WithComments: true},
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

// signatureData provides options for verifying a signed XML document
type signatureData struct {
	xml            *etree.Document
	signature      *etree.Element
	signedInfo     *etree.Element
	sigValue       string
	sigAlgorithm   x509.SignatureAlgorithm
	canonAlgorithm CanonicalizationAlgorithm
	refIDAttribute string
}

// SetSignature can be used to assign an external signature for the XML doc
// that Validator will verify
func (s *signatureData) SetSignature(sig string) error {
	doc := etree.NewDocument()
	err := doc.ReadFromString(sig)
	s.signature = doc.Root()
	return err
}

func (s *signatureData) parseEnvelopedSignature() error {
	sig := s.xml.FindElement(".//Signature")
	if sig != nil {
		s.signature = sig
	} else {
		return errors.New("signedxml: Unable to find a unique signature element " +
			"in the xml document. The signature must either be enveloped in the " +
			"xml doc or externally assigned to Validator.SetSignature")
	}
	return nil
}

func (s *signatureData) parseSignedInfo() error {
	s.signedInfo = nil
	s.signedInfo = s.signature.SelectElement("SignedInfo")
	if s.signedInfo == nil {
		return errors.New("signedxml: unable to find SignedInfo element")
	}

	// move the Signature level namespace down to SignedInfo so that the signature
	// value will match up I.e: check if SignedInfo prefix is defined in Signature, copy it to SignInfo attrs
	if s.signedInfo.Space != "" { // if SignedInfo has a prefix
		attr := s.signature.SelectAttr(s.signedInfo.Space) // find prefix definition in Signature
		if attr != nil {
			s.signedInfo.Attr = []etree.Attr{*attr} // copy the definition to SignedInfo
		}
	} else { // if no prefix
		attr := s.signature.SelectAttr("xmlns") // select any attribute with root namespace, if there is such
		if attr != nil {
			s.signedInfo.Attr = []etree.Attr{*attr}
		}
	}

	// Copy SignedInfo xmlns: into itself if it does not exist and is defined as a root attribute
	// i.e. check if SignedInfo prefix is defined in root, copy it to SignedInfo attrs
	root := s.xml.Root()

	if root != nil {
		sigNS := root.SelectAttr("xmlns:" + s.signedInfo.Space)
		if sigNS != nil {
			if s.signedInfo.SelectAttr("xmlns:"+s.signedInfo.Space) == nil {
				s.signedInfo.CreateAttr("xmlns:"+s.signedInfo.Space, sigNS.Value)
			}
		}
	}

	// It is adding <Root> tag namespaces, even if it wasn't used in SignedInfo - mistake.
	// Solution: add all namespaces, which are used in the SignedInfo child tags
	// signedInfoDoc, err := populateElementWithNameSpaces(s.signedInfo, s.xml.Copy())
	// if err != nil {
	// 	return err
	// }
	// s.signedInfo.Parent().AddChild(signedInfoDoc.Root())
	// s.signedInfo.Parent().RemoveChildAt(0) // old signedInfo

	return nil
}

func (s *signatureData) parseSigValue() error {
	s.sigValue = ""
	sigValueElement := s.signature.SelectElement("SignatureValue")
	if sigValueElement != nil {
		s.sigValue = sigValueElement.Text()
		return nil
	}
	return errors.New("signedxml: unable to find SignatureValue")
}

func (s *signatureData) parseSigAlgorithm() error {
	s.sigAlgorithm = x509.UnknownSignatureAlgorithm
	sigMethod := s.signedInfo.SelectElement("SignatureMethod")

	var sigAlgoURI string
	if sigMethod == nil {
		return errors.New("signedxml: Unable to find SignatureMethod element")
	}

	sigAlgoURI = sigMethod.SelectAttrValue("Algorithm", "")
	if sigAlgoURI == "" {
		return errors.New("signedxml: Unable to find Algorithm in " +
			"SignatureMethod element")
	}

	sigAlgo, ok := signatureAlgorithms[sigAlgoURI]
	if ok {
		s.sigAlgorithm = sigAlgo
		return nil
	}

	return errors.New("signedxml: Unsupported Algorithm " + sigAlgoURI + " in " +
		"SignatureMethod")
}

func (s *signatureData) parseCanonAlgorithm() error {
	s.canonAlgorithm = nil
	canonMethod := s.signedInfo.SelectElement("CanonicalizationMethod")

	var canonAlgoURI string
	if canonMethod == nil {
		return errors.New("signedxml: Unable to find CanonicalizationMethod element")
	}

	canonAlgoURI = canonMethod.SelectAttrValue("Algorithm", "")
	if canonAlgoURI == "" {
		return errors.New("signedxml: Unable to find Algorithm in " +
			"CanonicalizationMethod element")
	}

	canonAlgo, ok := CanonicalizationAlgorithms[canonAlgoURI]
	if ok {
		s.canonAlgorithm = canonAlgo
		return nil
	}

	return errors.New("signedxml: Unsupported Algorithm " + canonAlgoURI + " in " +
		"CanonicalizationMethod")
}

func (s *signatureData) getReferencedXML(reference *etree.Element, inputDoc *etree.Document) (outputDoc *etree.Document, err error) {
	uri := reference.SelectAttrValue("URI", "")
	uri = strings.Replace(uri, "#", "", 1)
	// populate doc with the referenced xml from the Reference URI
	if uri == "" {
		outputDoc = inputDoc

		// // the above does not remove XML declarations from the root doc,
		// // this fixes it, though it should be done by canonicalization:
		// outputDoc = etree.NewDocument()
		// outputDoc.SetRoot(inputDoc.Root())

	} else {
		refIDAttribute := "ID"
		if s.refIDAttribute != "" {
			refIDAttribute = s.refIDAttribute
		}

		// path := fmt.Sprintf(".//[@%s='%s']", refIDAttribute, uri)
		// e := inputDoc.FindElement(path)
		// if e != nil {
		// 	outputDoc = etree.NewDocument()
		// 	outputDoc.SetRoot(e.Copy())
		if e := inputDoc.FindElement(fmt.Sprintf(".//[@%s='%s']", refIDAttribute, uri)); e != nil {
			outputDoc = etree.NewDocument()
			outputDoc.SetRoot(e.Copy())
		} else if e := inputDoc.FindElement(fmt.Sprintf(".//[@%s='%s']", strings.ToLower(refIDAttribute), uri)); e != nil {
			outputDoc = etree.NewDocument()
			outputDoc.SetRoot(e.Copy())
		} else if e := inputDoc.FindElement(fmt.Sprintf(".//[@%s='%s']", strings.Title(strings.ToLower(refIDAttribute)), uri)); e != nil {
			outputDoc = etree.NewDocument()
			outputDoc.SetRoot(e.Copy())
		} else {
			// SAML v1.1 Assertions use AssertionID
			path := fmt.Sprintf(".//[@AssertionID='%s']", uri)
			e := inputDoc.FindElement(path)
			if e != nil {
				outputDoc = etree.NewDocument()
				outputDoc.SetRoot(e.Copy())
			}
		}
	}

	if outputDoc == nil {
		return nil, errors.New("signedxml: unable to find refereced xml")
	}

	return outputDoc, nil
}

func LoadCertFromPEMString(pemString, pubKeyType string) (*x509.Certificate, error) {
	var pubkey string
	switch {
	case strings.EqualFold("PUBLIC KEY", pubKeyType):
		pubkey = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
			pemString)
	case strings.EqualFold("CERTIFICATE", pubKeyType):
		pubkey = fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----",
			pemString)
	}
	pemBlock, _ := pem.Decode([]byte(pubkey))
	if pemBlock == nil {
		return &x509.Certificate{}, errors.New("Could not parse Public Key PEM")
	}
	if pemBlock.Type != "PUBLIC KEY" && pemBlock.Type != "CERTIFICATE" {
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
		tDoc := etree.NewDocument()
		tDoc.SetRoot(transform.Copy())
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

// func calculateHash(reference *etree.Element, doc *etree.Document) (string, error) {
// 	digestMethodElement := reference.SelectElement("DigestMethod")
// 	if digestMethodElement == nil {
// 		return "", errors.New("signedxml: unable to find DigestMethod")
// 	}

// 	digestMethodURI := digestMethodElement.SelectAttrValue("Algorithm", "")
// 	if digestMethodURI == "" {
// 		return "", errors.New("signedxml: unable to find Algorithm in DigestMethod")
// 	}

// 	digestAlgo, ok := hashAlgorithms[digestMethodURI]
// 	if !ok {
// 		return "", fmt.Errorf("signedxml: unable to find matching hash"+
// 			"algorithm for %s in hashAlgorithms", digestMethodURI)
// 	}

// 	doc.WriteSettings.CanonicalEndTags = true
// 	doc.WriteSettings.CanonicalText = true
// 	doc.WriteSettings.CanonicalAttrVal = true

// 	h := digestAlgo.New()
// 	docBytes, err := doc.WriteToBytes()
// 	if err != nil {
// 		return "", err
// 	}

// 	// ioutil.WriteFile("C:/Temp/SignedXML/Suspect.xml", docBytes, 0644)
// 	// s, _ := doc.WriteToString()
// 	// logger.Println(s)

// 	h.Write(docBytes)
// 	d := h.Sum(nil)
// 	calculatedValue := base64.StdEncoding.EncodeToString(d)

// 	return calculatedValue, nil
// }

// calculates a hash of a TargetToBeHashed (*etree.Document or []byte), detecting
// the hash algorithm in the reference element. If successful, hash digest value in
// base64 encoded string is written to the reference element/DigestValue tag.
func CalculateHashFromRef(reference *etree.Element, targetToBeHashed interface{}) (string, error) {
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

	var targetBytes []byte
	var err error
	switch v := targetToBeHashed.(type) {
	case *etree.Document:
		v.WriteSettings.CanonicalEndTags = true
		v.WriteSettings.CanonicalText = true
		v.WriteSettings.CanonicalAttrVal = true
		targetBytes, err = v.WriteToBytes()
		if err != nil {
			return "", err
		}

	case []byte:
		targetBytes = v
	}

	// debug
	// fn := strconv.FormatInt(time.Now().UnixNano(), 10) + ".xml" // unix-time based filename
	// f, err := os.Create(fn)
	// if err != nil {
	// 	panic(err)
	// }
	// defer f.Close()
	// _, err = f.Write(targetBytes)
	// if err != nil {
	// 	panic(err)
	// }

	h := digestAlgo.New()                                   // hasher
	h.Write(targetBytes)                                    // calculate hash
	d := h.Sum(nil)                                         // digest
	calculatedValue := base64.StdEncoding.EncodeToString(d) // digest in base64

	return calculatedValue, nil
}

// calculates a hash of a targetToBeHashed ([]byte), detecting the hash algorithm
// by the URI string. The URI follows notation common for XML Signatures. If successfull,
// it outputs base64 encoded string of a target hash digest (fingerprint).
func CalculateHash(targetToBeHashed []byte, digestMethodURI string) (string, error) {

	digestAlgo, ok := hashAlgorithms[digestMethodURI]
	if !ok {
		return "", fmt.Errorf("signedxml: unable to find matching hash"+
			"algorithm for %s in hashAlgorithms", digestMethodURI)
	}

	h := digestAlgo.New()               // hasher
	_, err := h.Write(targetToBeHashed) // calculate hash
	if err != nil {
		return "", fmt.Errorf("signedxml: hashing error: %s", err)
	}
	d := h.Sum(nil)                                         // digest
	calculatedValue := base64.StdEncoding.EncodeToString(d) // digest in base64

	return calculatedValue, nil
}

// Copies all namespaces that related to the targetElement. It must have the following namespaces:
// - own namespaces (if it defines such): nothing todo here, typically, they're defined in attributes of that element;
// - if the element has a prefix, but no definition for it, then parent has this namespace defined;
// - if any of the sub-elementas have a prefix, which is different from targetElement, then some parent must define it.
// Needed before canonicalizing and calculating hash of the target Element.
// TargetElem is always a sub-tag (child) of RootDoc
func PopulateElementWithNameSpaces(targetElem *etree.Element, rootDoc *etree.Document) (err error) { //(outputDoc *etree.Document, err error) {

	// check that targetElem is a child of rootDoc
	if rootDoc.FindElement(".//"+targetElem.Tag) != nil {

		// Step 1: cycle through all prefixes used in the targetElement,
		// these will be namespace definitions we'll have to have in the element
		nsDefinitions := getUsedPrefixes(targetElem)

		// Step1.5: check if namespace definitions has an empty value (indicicator of
		// default namespace). If it doesn't exists, check if any parents above the element
		// have xmlns defined - if so, add this used nsDefinitions
		if _, ok := nsDefinitions[""]; !ok { // if no empty k name exists
			if checkIfParentsUseDefaultNS(targetElem, rootDoc) {
				nsDefinitions[""] = ""
			}
		}

		// Step 2: starting with the targetElem, work up the path until all
		// prefix keys (namespace names) have their corresponding definitions collected
		nsDefinitions = getNameSpaceDefinitions(nsDefinitions, targetElem, rootDoc)

		// Step 3: populate the targetElem with the namespaces, relevant for it
		// setNSDefinitionsDynamically(targetElem, nsDefinitions, []string{})
		setNSDefinitions(targetElem, nsDefinitions)

	} else if targetElem.FullTag() == rootDoc.FullTag() {
		targetElem = rootDoc.Root()
	} else {
		err = errors.New("targetElem is not in the rootDoc, cannot copy namespaces")
	}

	return
}

// MOD: setts namespaces on the element, given in nsdef
func setNSDefinitions(el *etree.Element, nsdef map[string]string) {
	for k, v := range nsdef {
		if k == "" {
			el.CreateAttr("xmlns", v)
		} else {
			el.CreateAttr("xmlns:"+k, v)
		}
	}
}

// too complext, aimed at setting namespace where it is used
func setNSDefinitionsDynamically(el *etree.Element, nsdef map[string]string, parentPrefixes []string) {

	if el.Space != "" && !isInArray(el.Space, parentPrefixes) {
		el.CreateAttr("xmlns:"+el.Space, nsdef[el.Space])
		parentPrefixes = append(parentPrefixes, el.Space)
	}

	for _, c := range el.ChildElements() {
		setNSDefinitionsDynamically(c, nsdef, parentPrefixes)
	}
}

// checks if items is in array
func isInArray(item string, array []string) bool {
	for _, i := range array {
		if item == i {
			return true
		}
	}
	return false
}

// returns a map, where its keys are the unique prefixes used in the
// element and its children
func getUsedPrefixes(el *etree.Element) (outMap map[string]string) {
	// Space is element tag prefix. If it's emtpy, then this element has root namespace.
	// if it's not empty, then it's defined somewhere up the element path.

	outMap = map[string]string{}
	outMap[el.Space] = "" // process element prefix
	for _, c := range el.ChildElements() {
		childMap := getUsedPrefixes(c) // process its children prefixes
		for k, v := range childMap {
			outMap[k] = v
		}
	}
	return outMap
}

// checks if any of the parents above define default namespace (attribute "xmlns=...")
func checkIfParentsUseDefaultNS(el *etree.Element, rootDoc *etree.Document) bool {
	if attr := el.SelectAttr("xmlns"); attr != nil {
		return true
	}
	upNext := rootDoc.FindElement(".//" + el.Tag).Parent()
	if upNext != nil {
		return checkIfParentsUseDefaultNS(upNext, rootDoc)
	}
	return false
}

// takes a map of prefixes and cycles up the path from the element to
// collect its definitions
func getNameSpaceDefinitions(prefixMap map[string]string, el *etree.Element, rootDoc *etree.Document) (outMap map[string]string) {
	var weHaveUnfilledValues bool

	for k, v := range prefixMap {
		if v == "" {
			weHaveUnfilledValues = true
			if attr := el.SelectAttr(k); attr != nil {
				prefixMap[k] = attr.Value
			} else if attr := el.SelectAttr("xmlns:" + k); attr != nil {
				prefixMap[k] = attr.Value
			} else if attr := el.SelectAttr("xmlns"); attr != nil { // root NS
				if _, ok := prefixMap[""]; ok { // make sure non-prefixed tags were in element
					prefixMap[""] = attr.Value
				}
			}
		}
	}
	upNext := rootDoc.FindElement(".//" + el.Tag).Parent()
	if weHaveUnfilledValues && upNext != nil {
		parentMap := getNameSpaceDefinitions(prefixMap, upNext, rootDoc)
		for k, v := range parentMap {
			if prefixMap[k] == "" && v != "" {
				prefixMap[k] = v
			}
		}
	}
	outMap = prefixMap
	return
}
