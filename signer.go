package signedxml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"github.com/beevik/etree"
)

var signingAlgorithms map[x509.SignatureAlgorithm]cryptoHash

func init() {
	signingAlgorithms = map[x509.SignatureAlgorithm]cryptoHash{
		// MD2 not supported
		// x509.MD2WithRSA: cryptoHash{algorithm: "rsa", hash: crypto.MD2},
		x509.MD5WithRSA:    cryptoHash{algorithm: "rsa", hash: crypto.MD5},
		x509.SHA1WithRSA:   cryptoHash{algorithm: "rsa", hash: crypto.SHA1},
		x509.SHA256WithRSA: cryptoHash{algorithm: "rsa", hash: crypto.SHA256},
		x509.SHA384WithRSA: cryptoHash{algorithm: "rsa", hash: crypto.SHA384},
		x509.SHA512WithRSA: cryptoHash{algorithm: "rsa", hash: crypto.SHA512},
		// DSA not supported
		// x509.DSAWithSHA1:  cryptoHash{algorithm: "dsa", hash: crypto.SHA1},
		// x509.DSAWithSHA256:cryptoHash{algorithm: "dsa", hash: crypto.SHA256},
		// Golang ECDSA support is lacking, can't seem to load private keys
		// x509.ECDSAWithSHA1:   cryptoHash{algorithm: "ecdsa", hash: crypto.SHA1},
		// x509.ECDSAWithSHA256: cryptoHash{algorithm: "ecdsa", hash: crypto.SHA256},
		// x509.ECDSAWithSHA384: cryptoHash{algorithm: "ecdsa", hash: crypto.SHA384},
		// x509.ECDSAWithSHA512: cryptoHash{algorithm: "ecdsa", hash: crypto.SHA512},
	}
}

type cryptoHash struct {
	algorithm string
	hash      crypto.Hash
}

// Signer provides options for signing an XML document
type Signer struct {
	signatureData
	privateKey interface{}
}

// NewSigner returns a *Signer for the XML provided
func NewSigner(xml string) (*Signer, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(xml)
	if err != nil {
		return nil, err
	}
	s := &Signer{signatureData: signatureData{xml: doc}}
	return s, nil
}

// Sign populates the XML digest and signature based on the parameters present and privateKey given
func (s *Signer) Sign(privateKey interface{}) (string, error) {
	s.privateKey = privateKey

	if s.signature == nil {
		if err := s.parseEnvelopedSignature(); err != nil {
			return "", err
		}
	}
	if err := s.parseSignedInfo(); err != nil { // changes to SignedInfo tag
		return "", err
	}
	if err := s.parseSigAlgorithm(); err != nil {
		return "", err
	}
	if err := s.parseCanonAlgorithm(); err != nil {
		return "", err
	}
	if err := s.setDigest(); err != nil { // changes to Document, SignedProperties
		return "", err
	}
	if err := s.setSignature(); err != nil {
		return "", err
	}

	xml, err := s.xml.WriteToString()
	if err != nil {
		return "", err
	}
	return xml, nil
}

// SetReferenceIDAttribute set the referenceIDAttribute
func (s *Signer) SetReferenceIDAttribute(refIDAttribute string) {
	s.signatureData.refIDAttribute = refIDAttribute
}

func (s *Signer) setDigest() (err error) {
	references := s.signedInfo.FindElements("./Reference")
	for _, ref := range references {
		doc := s.xml.Copy()
		// transforms := ref.SelectElement("Transforms")
		// if transforms != nil {
		// 	for _, transform := range transforms.SelectElements("Transform") {
		// 		doc, err = processTransform(transform, doc)
		// 		if err != nil {
		// 			return err
		// 		}
		// 	}
		// }

		// targetDoc, err := s.getReferencedXML(ref, doc)
		// if err != nil {
		// 	return err
		// }

		// MOD: 1. change order: 1st find the ref, then transform
		//      2. if not root doc, add namespaces
		targetDoc, err := s.getReferencedXML(ref, doc)
		if err != nil {
			return err
		}

		// copy relevant namespaces if the targetDoc is not the root document
		if targetDoc.Root().Tag != s.xml.Root().Tag {

			// if targetDoc element is not root (i.e, root sub-tag or child) being "digested",
			// then populate with relevant namespaces
			err = PopulateElementWithNameSpaces(targetDoc.Root(), s.xml.Copy())
			if err != nil {
				return err
			}
		}

		transforms := ref.SelectElement("Transforms")
		if transforms != nil {
			for _, transform := range transforms.SelectElements("Transform") {
				targetDoc, err = processTransform(transform, targetDoc)
				if err != nil {
					return err
				}
			}
		}

		// MOD: canonicalization, defined at the signature level is mandatory for each
		// reference before calculating the hash. This is to avoid situations when canonicalization
		// is not explicitly defined in the <Transforms> of the Reference (it's implied).
		// source: https://www.di-mgt.com.au/xmldsig2.html
		targetDocStr, err := targetDoc.WriteToString()
		if err != nil {
			return err
		}
		targetDocStr, err = s.canonAlgorithm.Process(targetDocStr, "")
		if err != nil {
			return err
		}
		targetDoc2 := etree.NewDocument()
		targetDoc2.ReadFromString(targetDocStr)

		// calculatedValue, err := calculateHash(ref, doc)
		calculatedValue, err := CalculateHashFromRef(ref, targetDoc2)
		if err != nil {
			return err
		}

		digestValueElement := ref.SelectElement("DigestValue")
		if digestValueElement == nil {
			return errors.New("signedxml: unable to find DigestValue")
		}
		digestValueElement.SetText(calculatedValue)
	}
	return nil
}

func (s *Signer) setSignature() error {
	doc := etree.NewDocument()
	doc.SetRoot(s.signedInfo.Copy())
	signedInfo, err := doc.WriteToString()
	if err != nil {
		return err
	}

	canonSignedInfo, err := s.canonAlgorithm.Process(signedInfo, "")
	if err != nil {
		return err
	}

	var digest, signature []byte
	//var h1, h2 *big.Int
	signingAlgorithm, ok := signingAlgorithms[s.sigAlgorithm]
	if !ok {
		return errors.New("signedxml: unsupported algorithm")
	}

	hasher := signingAlgorithm.hash.New()
	hasher.Write([]byte(canonSignedInfo))
	digest = hasher.Sum(nil)

	switch signingAlgorithm.algorithm {
	case "rsa":
		// "RSASSA-PKCS1-v1_5" as in Section 8.2 of RFC8017 (https://tools.ietf.org/html/rfc8017)
		signature, err = rsa.SignPKCS1v15(rand.Reader, s.privateKey.(*rsa.PrivateKey), signingAlgorithm.hash, digest)
		/*
			case "dsa":
				h1, h2, err = dsa.Sign(rand.Reader, s.privateKey.(*dsa.PrivateKey), digest)
			case "ecdsa":
				h1, h2, err = ecdsa.Sign(rand.Reader, s.privateKey.(*ecdsa.PrivateKey), digest)
		*/
	}
	if err != nil {
		return err
	}

	// DSA and ECDSA has not been validated
	/*
		if signature == nil && h1 != nil && h2 != nil {
			signature = append(h1.Bytes(), h2.Bytes()...)
		}
	*/

	b64 := base64.StdEncoding.EncodeToString(signature)
	sigValueElement := s.signature.SelectElement("SignatureValue")
	sigValueElement.SetText(b64)

	return nil
}
