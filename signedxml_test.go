package signedxml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/beevik/etree"
	. "github.com/smartystreets/goconvey/convey"
)

func TestSign(t *testing.T) {
	pemString, _ := os.ReadFile("./testdata/rsa.crt")
	pemBlock, _ := pem.Decode([]byte(pemString))
	cert, _ := x509.ParseCertificate(pemBlock.Bytes)

	b64Bytes, _ := os.ReadFile("./testdata/rsa.key.b64")
	pemString, _ = base64.StdEncoding.DecodeString(string(b64Bytes))
	pemBlock, _ = pem.Decode([]byte(pemString))
	key, _ := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)

	Convey("Given an XML, certificate, and RSA key", t, func() {
		xml, _ := os.ReadFile("./testdata/nosignature.xml")

		Convey("When generating the signature", func() {
			signer, _ := NewSigner(string(xml))
			xmlStr, err := signer.Sign(key)
			Convey("Then no error occurs", func() {
				So(err, ShouldBeNil)
			})
			Convey("And the signature should be valid", func() {
				validator, _ := NewValidator(xmlStr)
				validator.Certificates = append(validator.Certificates, *cert)
				refs, err := validator.ValidateReferences()
				So(err, ShouldBeNil)
				So(len(refs), ShouldEqual, 1)
			})
		})
	})

	Convey("Given an XML with http://www.w3.org/TR/2001/REC-xml-c14n-20010315 canonicalization, certificate, and RSA key", t, func() {
		xml, _ := os.ReadFile("./testdata/nosignature2.xml")

		Convey("When generating the signature", func() {
			signer, _ := NewSigner(string(xml))
			xmlStr, err := signer.Sign(key)
			Convey("Then no error occurs", func() {
				So(err, ShouldBeNil)
			})
			Convey("And the signature should be valid", func() {
				validator, _ := NewValidator(xmlStr)
				validator.Certificates = append(validator.Certificates, *cert)
				refs, err := validator.ValidateReferences()
				So(err, ShouldBeNil)
				So(len(refs), ShouldEqual, 1)
			})
		})
	})

	Convey("Given an XML with custom referenceIDAttribute, certificate, and RSA key", t, func() {
		xml, _ := os.ReadFile("./testdata/nosignature-custom-reference-id-attribute.xml")

		Convey("When generating the signature with custom referenceIDAttribute", func() {
			signer, _ := NewSigner(string(xml))
			signer.SetReferenceIDAttribute("customId")
			xmlStr, err := signer.Sign(key)
			Convey("Then no error occurs", func() {
				So(err, ShouldBeNil)
			})
			Convey("And the signature should be valid", func() {
				validator, _ := NewValidator(xmlStr)
				validator.Certificates = append(validator.Certificates, *cert)
				validator.SetReferenceIDAttribute("customId")
				refs, err := validator.ValidateReferences()
				So(err, ShouldBeNil)
				So(len(refs), ShouldEqual, 1)
			})
			Convey("And the signature should be valid, but validation fail if referenceIDAttribute NOT SET", func() {
				validator, _ := NewValidator(xmlStr)
				validator.Certificates = append(validator.Certificates, *cert)
				refs, err := validator.ValidateReferences()
				So(err, ShouldNotBeNil)
				So(len(refs), ShouldEqual, 0)
			})
		})

		Convey("When generating the signature referenceIDAttribute NOT SET", func() {
			signer, _ := NewSigner(string(xml))
			_, err := signer.Sign(key)
			Convey("Then an error should occur", func() {
				So(err, ShouldNotBeNil)
			})
		})

	})

	Convey("Signature at the Root level, surrounding the Object", t, func() {
		xml, _ := os.ReadFile(filepath.Join("testdata", "root-level-signature.xml"))

		doc := etree.NewDocument()
		doc.ReadFromBytes(xml)
		signature := doc.FindElement("//Signature")
		t.Logf("signature: %#v", signature)

		signer, _ := NewSigner(string(xml))
		signer.SetReferenceIDAttribute("Id")
		xmlStr, err := signer.Sign(key)
		So(err, ShouldBeNil)

		validator, _ := NewValidator(xmlStr)
		validator.SetReferenceIDAttribute("Id")
		validator.Certificates = append(validator.Certificates, *cert)
		refs, err := validator.ValidateReferences()
		So(err, ShouldBeNil)
		So(len(refs), ShouldEqual, 1)
	})
}

func TestValidate(t *testing.T) {
	Convey("Given valid signed XML", t, func() {
		cases := map[string]string{
			"(WSFed BBAuth Metadata)":    "./testdata/bbauth-metadata.xml",
			"(SAML External NS)":         "./testdata/saml-external-ns.xml",
			"(Signature w/Inclusive NS)": "./testdata/signature-with-inclusivenamespaces.xml",
			"(SAML)":                     "./testdata/valid-saml.xml",
			// this one doesn't appear to follow the spec... ( http://webservices20.blogspot.co.il/2013/06/validating-windows-mobile-app-store.html)
			//"(Windows Store Signature)":  "./testdata/windows-store-signature.xml",
			"(WSFed Generic Metadata)": "./testdata/wsfed-metadata.xml",
		}

		for description, test := range cases {
			Convey(fmt.Sprintf("When Validate is called %s", description), func() {
				xmlFile, err := os.Open(test)
				if err != nil {
					fmt.Println("Error opening file:", err)
				}
				defer xmlFile.Close()
				xmlBytes, _ := io.ReadAll(xmlFile)
				validator, _ := NewValidator(string(xmlBytes))
				refs, err := validator.ValidateReferences()
				Convey("Then no error occurs", func() {
					So(err, ShouldBeNil)
					So(validator.SigningCert().PublicKey, ShouldNotBeNil)
					So(len(refs), ShouldEqual, 1)
				})
			})
		}

		Convey("When Validate is called with an external Signature", func() {
			xmlFile, _ := os.Open("./testdata/bbauth-metadata.xml")
			sig := `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#_69b42076-409e-4476-af41-339962e49427"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>LPHoiAkLmA/TGIuVbgpwlFLXL+ymEBc7TS0fC9/PTQU=</DigestValue></Reference></SignedInfo><SignatureValue>d2CXq9GEeDKvMxdpxtTRKQ8TGeSWhJOVPs8LMD0ObeE1t/YGiAm9keorMiki4laxbWqAuOmwHK3qNHogRFgkIYi3fnuFBzMrahXf0n3A5PRXXW1m768Z92GKV09pGuygKUXCtXzwq0seDi6PnzMCJFzFXGQWnum0paa8Oz+6425Sn0zO0fT3ttp3AXeXGyNXwYPYcX1iEMB7klUlyiz2hmn8ngCIbTkru7uIeyPmQ5WD4SS/qQaL4yb3FZibXoe/eRXrbkG1NAJCw9OWw0jsvWncE1rKFaqEMbz21fXSDhh3Ls+p9yVf+xbCrpkT0FMqjTHpNRvccMPZe/hDGrHV7Q==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDNzCCAh+gAwIBAgIQQVK+d/vLK4ZNMDk15HGUoTANBgkqhkiG9w0BAQ0FADAoMSYwJAYDVQQDEx1CbGFja2JhdWQgQXV0aGVudGljYXRpb24gMjAyMjAeFw0wMDAxMDEwNDAwMDBaFw0yMjAxMDEwNDAwMDBaMCgxJjAkBgNVBAMTHUJsYWNrYmF1ZCBBdXRoZW50aWNhdGlvbiAyMDIyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArgByjSPVvP4DLf/l7QRz7G7Dhkdns0QjWslnWejHlFIezfkJ4NGPp0+5CRCFYBqAb7DhqyK77Ek5xdzmwgYb1X6GD6UDltWvN5BBFAw69I6/K0WjguFUxk19T7xdc8vTCNAMi+6Ys49O3EBNnI2fiqDoBdMjUTud1F04QY3N2rZWkjMrHV+CnzhoUwqsO/ABWrDbkPzBXdOOIbsKH0k0IP8q2+35pe1y2nxtB9f1fCyCmbUH2HINMHahDmxxanTW5Jy14yD/HSRTFQF9JMTeglomWq5q9VPx0NjsEJR+B5IkRCTf75LoYrrr/fvQm3aummmYPdHauXCBrcm0moX4ywIDAQABo10wWzBZBgNVHQEEUjBQgBDCHOfardZfhltQSbLqsukZoSowKDEmMCQGA1UEAxMdQmxhY2tiYXVkIEF1dGhlbnRpY2F0aW9uIDIwMjKCEEFSvnf7yyuGTTA5NeRxlKEwDQYJKoZIhvcNAQENBQADggEBADrOhfRiynRKGD7EHohpPrltFScJ9+QErYMhEvteqh3C48T99uKgDY8wTqv+PI08QUSZuhmmF2d+W7aRBo3t8ZZepIXCwDaKo/oUp2h5Y9O3vyGDguq5ptgDTmPNYDCwWtdt0TtQYeLtCQTJVbYByWL0eT+KdzQOkAi48cPEOObSc9Biga7LTCcbCVPeJlYzmHDQUhzBt2jcy5BGvmZloI5SsoZvve6ug74qNq8IJMyzJzUp3kRuB0ruKIioSDi1lc783LDT3LSXyIbOGw/vHBEBY4Ax7FK8CqXJ2TsYqVsyo8QypqXDnveLcgK+PNEAhezhxC9hyV8j1I8pfF72ABE=</X509Certificate></X509Data></KeyInfo></Signature>`
			defer xmlFile.Close()
			xmlBytes, _ := io.ReadAll(xmlFile)
			validator := Validator{}
			validator.SetXML(string(xmlBytes))
			validator.SetSignature(sig)
			refs, err := validator.ValidateReferences()
			Convey("Then no error occurs", func() {
				So(err, ShouldBeNil)
				So(validator.SigningCert().PublicKey, ShouldNotBeNil)
				So(len(refs), ShouldEqual, 1)
			})
		})

		Convey("When Validate is called with an external certificate and root xmlns", func() {
			xmlFile, _ := os.Open("./testdata/rootxmlns.xml")
			pemString, _ := os.ReadFile("./testdata/rootxmlns.crt")
			pemBlock, _ := pem.Decode([]byte(pemString))
			cert, _ := x509.ParseCertificate(pemBlock.Bytes)
			defer xmlFile.Close()
			xmlBytes, _ := io.ReadAll(xmlFile)
			validator := Validator{}
			validator.SetXML(string(xmlBytes))
			validator.Certificates = append(validator.Certificates, *cert)
			refs, err := validator.ValidateReferences()
			Convey("Then no error occurs", func() {
				So(err, ShouldBeNil)
				So(validator.SigningCert().PublicKey, ShouldNotBeNil)
				So(len(refs), ShouldEqual, 1)
			})
		})
	})

	Convey("Given invalid signed XML", t, func() {
		cases := map[string]string{
			"(Changed Content)":        "./testdata/invalid-signature-changed-content.xml",
			"(Non-existing Reference)": "./testdata/invalid-signature-non-existing-reference.xml",
		}
		for description, test := range cases {
			Convey(fmt.Sprintf("When ValidateReferences is called %s", description), func() {
				xmlBytes, err := os.ReadFile(test)
				if err != nil {
					fmt.Println("Error reading file:", err)
				}
				validator, _ := NewValidator(string(xmlBytes))

				refs, err := validator.ValidateReferences()
				Convey("Then an error occurs", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldContainSubstring, "signedxml:")
					t.Logf("%v  - %d", description, len(refs))
					So(len(refs), ShouldEqual, 0)
				})
			})
		}

		cases = map[string]string{
			"(Wrong Sig Value)": "./testdata/invalid-signature-signature-value.xml",
		}
		for description, test := range cases {
			Convey(fmt.Sprintf("When ValidateReferences is called %s", description), func() {
				xmlBytes, err := os.ReadFile(test)
				if err != nil {
					fmt.Println("Error reading file:", err)
				}
				validator, _ := NewValidator(string(xmlBytes))

				refs, err := validator.ValidateReferences()
				Convey("Then an error occurs", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldContainSubstring, "signedxml:")
					t.Logf("%v  - %d", description, len(refs))
					So(len(refs), ShouldEqual, 1)
				})
			})
		}
	})
}

func TestEnvelopedSignatureProcess(t *testing.T) {
	Convey("Given a document without a Signature elemement", t, func() {
		doc := "<doc></doc>"
		Convey("When ProcessDocument is called", func() {
			envSig := EnvelopedSignature{}
			_, err := envSig.Process(doc, "")
			Convey("Then an error occurs", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "signedxml:")
			})
		})
	})
}

func TestSignatureDataParsing(t *testing.T) {
	Convey("Given a document without a Signature elemement", t, func() {
		doc := etree.NewDocument()
		doc.CreateElement("root")
		Convey("When parseEnvelopedSignature is called", func() {
			sigData := signatureData{xml: doc}
			err := sigData.parseEnvelopedSignature()
			Convey("Then an error occurs", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "signedxml:")
			})
		})
	})

	Convey("Given a document without a SignedInfo elemement", t, func() {
		doc := etree.NewDocument()
		doc.CreateElement("root").CreateElement("Signature")
		sigData := signatureData{xml: doc}
		sigData.parseEnvelopedSignature()
		Convey("When parseSignedInfo is called", func() {
			err := sigData.parseSignedInfo()
			Convey("Then an error occurs", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "signedxml:")
			})
		})
	})

	Convey("Given a document without a SignatureValue elemement", t, func() {
		doc := etree.NewDocument()
		doc.CreateElement("root").CreateElement("Signature")
		sigData := signatureData{xml: doc}
		sigData.parseEnvelopedSignature()
		Convey("When parseSigValue is called", func() {
			err := sigData.parseSigValue()
			Convey("Then an error occurs", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "signedxml:")
			})
		})
	})

	Convey("Given a document without a SignatureMethod elemement", t, func() {
		doc := etree.NewDocument()
		doc.CreateElement("root").CreateElement("Signature").CreateElement("SignedInfo")
		sigData := signatureData{xml: doc}
		sigData.parseEnvelopedSignature()
		sigData.parseSignedInfo()
		Convey("When parseSigAlgorithm is called", func() {
			err := sigData.parseSigAlgorithm()
			Convey("Then an error occurs", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "signedxml:")
			})
		})
	})

	Convey("Given a document without a SignatureMethod Algorithm element", t, func() {
		doc := etree.NewDocument()
		doc.CreateElement("root").CreateElement("Signature").CreateElement("SignedInfo").CreateElement("SignatureMethod")
		sigData := signatureData{xml: doc}
		sigData.parseEnvelopedSignature()
		sigData.parseSignedInfo()
		Convey("When parseSigAlgorithm is called", func() {
			err := sigData.parseSigAlgorithm()
			Convey("Then an error occurs", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "signedxml:")
			})
		})
	})

	Convey("Given a document without a CanonicalizationMethod elemement", t, func() {
		doc := etree.NewDocument()
		doc.CreateElement("root").CreateElement("Signature").CreateElement("SignedInfo")
		sigData := signatureData{xml: doc}
		sigData.parseEnvelopedSignature()
		sigData.parseSignedInfo()
		Convey("When parseCanonAlgorithm is called", func() {
			err := sigData.parseCanonAlgorithm()
			Convey("Then an error occurs", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "signedxml:")
			})
		})
	})

	Convey("Given a document without a CanonicalizationMethod Algorithm element", t, func() {
		doc := etree.NewDocument()
		doc.CreateElement("root").CreateElement("Signature").CreateElement("SignedInfo").CreateElement("CanonicalizationMethod")
		sigData := signatureData{xml: doc}
		sigData.parseEnvelopedSignature()
		sigData.parseSignedInfo()
		Convey("When parseCanonAlgorithm is called", func() {
			err := sigData.parseCanonAlgorithm()
			Convey("Then an error occurs", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "signedxml:")
			})
		})
	})
}
