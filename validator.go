package signedxml

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"math/big"
	"regexp"
	"time"

	"github.com/beevik/etree"
)

// Validator provides options for verifying a signed XML document
type Validator struct {
	Certificates  []x509.Certificate
	RSAPublicKeys []*rsa.PublicKey
	signingCert   x509.Certificate
	signatureData
}

// NewValidator returns a *Validator for the XML provided
func NewValidator(xml string) (*Validator, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(xml)
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

// Validate validates the Reference digest values, and the signature value
// over the SignedInfo.
//
// Deprecated: Use ValidateReferences instead
func (v *Validator) Validate() error {
	_, err := v.ValidateReferences()
	// TODO: validate certificate digest at the SignedProperties - maybe elsewhere?
	return err
}

// ValidateReferences validates the Reference digest values, and the signature value
// over the SignedInfo.
//
// If the signature is enveloped in the XML, then it will be used.
// Otherwise, an external signature should be assigned using
// Validator.SetSignature.
//
// The references returned by this method can be used to verify what was signed.
func (v *Validator) ValidateReferences() ([]string, error) {
	if err := v.loadValuesFromXML(); err != nil {
		return nil, err
	}

	// referenced is array of cannonicalized reference elements whose digest is calculated
	// and compared to original ones. If err is nil, then all digests of references match.
	referenced, err := v.validateReferences()
	if err != nil {
		return nil, err
	}

	var ref []string // referenced elements -> ref string array
	for _, doc := range referenced {
		docStr, err := doc.WriteToString()
		if err != nil {
			return nil, err
		}
		ref = append(ref, docStr)
	}

	// checks SignatureValue using x509.Certificate{}.CheckSignature function.
	// Function params - canonicalized SignedInfo block, and the SignatureValue
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
		// transforms := ref.SelectElement("Transforms")
		// for _, transform := range transforms.SelectElements("Transform") {
		// 	doc, err = processTransform(transform, doc)
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// }

		// doc, err = v.getReferencedXML(ref, doc)
		// if err != nil {
		// 	return nil, err
		// }

		// MOD: 1. change order: 1st find the ref, then 3. transform
		//      2. if not root doc, add namespaces
		targetDoc, err := v.getReferencedXML(ref, doc)
		if err != nil {
			return nil, err
		}

		// 2. copy relevant namespaces if the targetDoc is not the root document
		if targetDoc.Root().Tag != v.xml.Root().Tag {

			// if targetDoc element is not root (i.e, root sub-tag or child) being "digested",
			// then populate with relevant namespaces
			err = PopulateElementWithNameSpaces(targetDoc.Root(), v.xml.Copy())
			if err != nil {
				return nil, err
			}
		}

		// 3. do the transforms
		transforms := ref.SelectElement("Transforms")
		if transforms != nil {
			for _, transform := range transforms.SelectElements("Transform") {
				targetDoc, err = processTransform(transform, targetDoc)
				if err != nil {
					return nil, err
				}
			}
		}

		// 4. canonicalization, defined at the signature level is mandatory for each
		// reference before calculating the hash. This is to avoid situations when canonicalization
		// is not explicitly defined in the <Transforms> of the Reference (it's implied).
		// source: https://www.di-mgt.com.au/xmldsig2.html
		targetDocStr, err := targetDoc.WriteToString()
		if err != nil {
			return nil, err
		}
		targetDocStr, err = v.canonAlgorithm.Process(targetDocStr, "")
		if err != nil {
			return nil, err
		}
		targetDoc2 := etree.NewDocument()
		targetDoc2.ReadFromString(targetDocStr)

		// continue with the old code:
		referenced = append(referenced, targetDoc2)

		digestValueElement := ref.SelectElement("DigestValue")
		if digestValueElement == nil {
			return nil, errors.New("signedxml: unable to find DigestValue")
		}
		digestValue := digestValueElement.Text()

		// calculatedValue, err := calculateHash(ref, doc)
		calculatedValue, err := CalculateHashFromRef(ref, targetDoc2)
		if err != nil {
			return nil, err
		}

		if calculatedValue != digestValue {
			return nil, fmt.Errorf("signedxml: Calculated digest does not match the"+
				" expected digestvalue of %s", digestValue)
		}
	}
	return referenced, nil
}

func (v *Validator) validateSignature() error {
	doc := etree.NewDocument()
	doc.SetRoot(v.signedInfo.Copy())
	signedInfo, err := doc.WriteToString()
	if err != nil {
		return err
	}

	canonSignedInfo, err := v.canonAlgorithm.Process(signedInfo, "")
	if err != nil {
		return err
	}

	// debug
	// fn := strconv.FormatInt(time.Now().UnixNano(), 10) + ".xml" // unix-time based filename
	// f, err := os.Create(fn)
	// if err != nil {
	// 	panic(err)
	// }
	// defer f.Close()
	// _, err = f.Write([]byte(canonSignedInfo))
	// if err != nil {
	// 	panic(err)
	// }

	signatureBytes, err := base64.StdEncoding.DecodeString(v.sigValue)
	if err != nil {
		return err
	}
	// sig := []byte(b64) // useless double conversion from bytes to bytes

	v.signingCert = x509.Certificate{}
	for _, cert := range v.Certificates {
		err := cert.CheckSignature(v.sigAlgorithm, []byte(canonSignedInfo), signatureBytes)
		if err == nil {
			v.signingCert = cert
			return nil
		}
	}

	// MOD: added RSA PublicKey checking of the signature
	if v.RSAPublicKeys != nil {
		signingAlgorithm, ok := signingAlgorithms[v.sigAlgorithm]
		if !ok {
			return errors.New("signedxml: unsupported algorithm")
		}
		hasher := signingAlgorithm.hash.New()
		hasher.Write([]byte(canonSignedInfo))
		digest := hasher.Sum(nil)
		// fmt.Println(base64.StdEncoding.EncodeToString(digest)) // debug

		for _, pubKey := range v.RSAPublicKeys {
			// err := rsa.VerifyPKCnotAfterv15(pubKey, crypto.Hash(v.sigAlgorithm), digest, signatureBytes)

			var cryptoHashId crypto.Hash
			switch v.sigAlgorithm.String() {
			case "MD5-RSA":
				cryptoHashId = crypto.MD5
			case "SHA1-RSA":
				cryptoHashId = crypto.SHA1
			case "SHA256-RSA", "SHA256-RSAPSS":
				cryptoHashId = crypto.SHA256
			case "SHA384-RSA", "SHA384-RSAPSS":
				cryptoHashId = crypto.SHA384
			case "SHA512-RSA", "SHA512-RSAPSS":
				cryptoHashId = crypto.SHA512
			default:
				return errors.New("unknown signature hash type")
			}

			err := rsa.VerifyPKCS1v15(pubKey, cryptoHashId, digest, signatureBytes)
			if err == nil {
				return nil // signature validated
			}
		}
	}

	return errors.New("signedxml: Calculated signature does not match the " +
		"SignatureValue provided")
}

func (v *Validator) loadCertificates() error {
	// If v.Certificates is already populated, then the client has already set it
	// to the desired cert. Otherwise, let's pull the public keys from the XML
	if len(v.Certificates) < 1 {
		switch {
		case len(v.xml.FindElements(".//X509Certificate")) >= 1:
			keydata := v.xml.FindElements(".//X509Certificate")
			for _, key := range keydata {
				cert, err := LoadCertFromPEMString(key.Text(), "CERTIFICATE")
				if err != nil {
					log.Printf("signedxml: Unable to load certificate: (%s). "+
						"Looking for another cert.", err)
					continue // don't append current cert: it will be nil due to error
				}

				// if certificate digest and digest method are present, validate the certificate
				// TODO: what if there are multiple certificates in the <SigningCertificate> ?
				var certDigest, digestMethodURI string
				if el := v.xml.FindElement(".//CertDigest/DigestMethod"); el != nil {
					digestMethodURI = el.SelectAttrValue("Algorithm", "")
				}
				if el := v.xml.FindElement(".//CertDigest/DigestValue"); el != nil {
					certDigest = el.Text()
				}
				err = ValidateCertificate(cert, certDigest, digestMethodURI, "", "")
				if err != nil {
					log.Printf("signedxml: certificate validation failed: (%s). "+
						"Looking for another cert.", err)
					continue // don't append current cert: it will be nil due to error
				}

				v.Certificates = append(v.Certificates, *cert)
			}

		case len(v.xml.FindElements(".//RSAKeyValue")) >= 1:
			keydata := v.xml.FindElements(".//RSAKeyValue")
			for _, key := range keydata {
				modulus := key.SelectElement("Modulus")
				if modulus == nil {
					log.Printf("signedxml: RSA Modulus not found, cannot load certificate. Looking for another cert.")
					continue
				}
				modulusBytes, err := base64.StdEncoding.DecodeString(modulus.Text())
				if err != nil {
					log.Printf("signedxml: can't b64 decode RSA modulus (%s). "+
						"Looking for another cert.", err)
					continue
				}
				exponent := key.SelectElement("Exponent")
				if exponent == nil {
					log.Printf("signedxml: RSA Exponent not found, cannot load certificate. Looking for another cert.")
					continue
				}

				// source: https://stackoverflow.com/questions/41127019/go-language-convert-modulus-exponent-to-x-509-certificate
				e := 65537
				// The default exponent is usually 65537, so just compare the
				// base64 for [1,0,1] or [0,1,0,1]
				if exponent.Text() != "AQAB" && exponent.Text() != "AAEAAQ" {
					// still need to decode the big-endian int
					log.Printf("signedxml: unusual RSA exponent ('%s', base64). "+
						"still need to decode it, looking for another cert.", exponent.Text())
					continue
				}
				pubKey := &rsa.PublicKey{
					N: new(big.Int).SetBytes(modulusBytes),
					E: e,
				}
				v.RSAPublicKeys = append(v.RSAPublicKeys, pubKey)

				// TODO: not sure if certificate validation is possible with RSA key

				// pubKeyDERBytes := pem.EncodeToMemory(&pem.Block{
				// 	Type:  "RSA PUBLIC KEY",
				// 	Bytes: x509.MarshalPKCnotAfterPublicKey(pub),
				// })
				// cert, err := x509.ParseCertificate(pubKeyDERBytes)

				// exponentBytes, err := base64.StdEncoding.DecodeString(exponent.Text())
				// if err != nil {
				// 	log.Printf("signedxml: can't b64 decode RSA exponent (%s). "+
				// 		"Looking for another cert.", err)
				// 	continue
				// }

				// // conversion to BigEndian
				// if len(exponentBytes) < 4 {
				// 	ndata := make([]byte, 4)
				// 	copy(ndata[4-len(exponentBytes):], exponentBytes)
				// 	exponentBytes = ndata
				// }

				// pubKey := &rsa.PublicKey{
				// 	N: new(big.Int).SetBytes(modulusBytes),
				// 	// E: int(binary.BigEndian.Uint32(exponentBytes[:])),
				// 	E: 65537,
				// }

			}
		}
	}

	if len(v.Certificates) < 1 && v.RSAPublicKeys == nil {
		return errors.New("signedxml: a X509 certificate or a RSA public key is required, but was not found")
	}
	return nil
}

func (v *Validator) SetValidationCertFromPEMString(certPEM string) error {
	cert, err := LoadCertFromPEMString(certPEM, "CERTIFICATE")
	if err != nil {
		return fmt.Errorf("signedxml: Unable to load certificate: (%s). ", err)
	}
	v.Certificates = append(v.Certificates, *cert)
	return nil
}

func (v *Validator) SetValidationCert(cert *x509.Certificate) {
	v.Certificates = append(v.Certificates, *cert)
}

// Validates certificate:
// 1. checks if it hasn't expired,
// 2. calculates certificate hash digest and compares to supplied certificate digest value.
// Params 'notBefore', 'notAfter' are optional, just for setting validity dates separately, else
// X509.Certificate container equivalent values are used
func ValidateCertificate(cert *x509.Certificate, certDigest, digestMethodURI, notBefore, notAfter string) (err error) {

	// setup of custom NotBefore and NotAfter dates
	if notBefore != "" && notAfter != "" {

		var layout string
		var t0, t1 time.Time

		r1 := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
		r3 := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$`)
		r4 := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`)
		r5 := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{1,9}$`)
		r6 := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

		switch {
		case r1.Match([]byte(notBefore)) || r3.Match([]byte(notBefore)):
			layout = time.RFC3339 // "2006-01-02T15:04:05+HH:MM"
		case r4.Match([]byte(notBefore)) || r5.Match([]byte(notBefore)):
			layout = "2006-01-02T15:04:05" // local tz
		case r6.Match([]byte(notBefore)):
			layout = "2006-01-02" // local tz
		}
		if r4.Match([]byte(notBefore)) || r5.Match([]byte(notBefore)) || r6.Match([]byte(notBefore)) {
			t0, err = time.ParseInLocation(layout, notBefore, time.UTC)
		} else if r1.Match([]byte(notBefore)) || r3.Match([]byte(notBefore)) {
			t0, err = time.Parse(layout, notBefore)
		}
		if err != nil {
			return fmt.Errorf("error parsing date string %s, error: %s", t0, err)
		}
		// assume that t1 is in the same format as t0
		if r4.Match([]byte(notAfter)) || r5.Match([]byte(notAfter)) || r6.Match([]byte(notAfter)) {
			t1, err = time.ParseInLocation(layout, notAfter, time.UTC)
		} else if r1.Match([]byte(notAfter)) || r3.Match([]byte(notAfter)) {
			t1, err = time.Parse(layout, notAfter)
		}
		if err != nil {
			return fmt.Errorf("error parsing date string %s, error: %s", t1, err)
		}

		cert.NotBefore = t0
		cert.NotAfter = t1
	}

	// checking if certificate expired
	if time.Now().Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not valid until %s; now is %s",
			cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"), time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired in %s; now is %s",
			cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	}

	// calculate certificate hash
	certDigestB64, err := CalculateHash(cert.Raw, digestMethodURI)
	if err != nil {
		return err
	}

	// check if hash matches
	if certDigest != certDigestB64 {
		return fmt.Errorf("certificate hash digest mismatch: xml uses certificate hash "+
			"digest '%s', while cert digest in db is '%s'", certDigest, certDigestB64)
	}

	return
}
