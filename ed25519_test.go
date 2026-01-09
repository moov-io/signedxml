package signedxml

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

// generateEd25519TestCert creates a self-signed Ed25519 certificate for testing
func generateEd25519TestCert() (*x509.Certificate, ed25519.PrivateKey, error) {
	// Generate Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Ed25519 Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// TestEd25519SignAndValidate tests Ed25519 XML signature signing and validation
func TestEd25519SignAndValidate(t *testing.T) {
	Convey("Given an Ed25519 certificate and key pair", t, func() {
		cert, privKey, err := generateEd25519TestCert()
		So(err, ShouldBeNil)
		So(cert, ShouldNotBeNil)
		So(privKey, ShouldNotBeNil)

		// Verify key type
		_, ok := cert.PublicKey.(ed25519.PublicKey)
		So(ok, ShouldBeTrue)

		Convey("And an XML document with Ed25519 signature algorithm", func() {
			// Create an XML template with Ed25519 signature algorithm
			// The signer will fill in the actual DigestValue and SignatureValue
			// Note: The default ID attribute looked up is "ID" (uppercase)
			xmlTemplate := `<?xml version="1.0" encoding="UTF-8"?>
<root ID="test-data" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <content>Test data for Ed25519 signature</content>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"/>
            <ds:Reference URI="#test-data">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>placeholder</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>placeholder</ds:SignatureValue>
    </ds:Signature>
</root>`

			Convey("When signing the document with Ed25519", func() {
				signer, err := NewSigner(xmlTemplate)
				So(err, ShouldBeNil)

				// Sign the document
				signedXML, err := signer.Sign(privKey)

				Convey("Then no error occurs", func() {
					So(err, ShouldBeNil)
					So(signedXML, ShouldNotBeEmpty)
				})

				Convey("And the signature should contain the Ed25519 algorithm", func() {
					So(signedXML, ShouldContainSubstring, "eddsa-ed25519")
				})

				Convey("And the signature should be valid", func() {
					validator, err := NewValidator(signedXML)
					So(err, ShouldBeNil)

					// Add the certificate for validation
					validator.Certificates = append(validator.Certificates, *cert)

					refs, err := validator.ValidateReferences()
					So(err, ShouldBeNil)
					So(len(refs), ShouldEqual, 1)
				})
			})
		})
	})
}

// TestEd25519AlgorithmMapping tests that Ed25519 algorithm URI is correctly mapped
func TestEd25519AlgorithmMapping(t *testing.T) {
	Convey("Given the signatureAlgorithms map", t, func() {
		Convey("The Ed25519 algorithm URI should map to PureEd25519", func() {
			alg, ok := signatureAlgorithms["http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"]
			So(ok, ShouldBeTrue)
			So(alg, ShouldEqual, x509.PureEd25519)
		})
	})
}

// TestEd25519SigningAlgorithmMapping tests that Ed25519 is in the signing algorithms map
func TestEd25519SigningAlgorithmMapping(t *testing.T) {
	Convey("Given the signingAlgorithms map", t, func() {
		Convey("PureEd25519 should be mapped with 'ed25519' algorithm type", func() {
			ch, ok := signingAlgorithms[x509.PureEd25519]
			So(ok, ShouldBeTrue)
			So(ch.algorithm, ShouldEqual, "ed25519")
			// Ed25519 doesn't use a hash - it's a "pure" signature scheme
			So(ch.hash, ShouldEqual, 0)
		})
	})
}

// TestEd25519TamperedSignature tests that tampered signatures are rejected
func TestEd25519TamperedSignature(t *testing.T) {
	Convey("Given a valid Ed25519 signed document", t, func() {
		cert, privKey, err := generateEd25519TestCert()
		So(err, ShouldBeNil)

		xmlTemplate := `<?xml version="1.0" encoding="UTF-8"?>
<root ID="test-data" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <content>Original content</content>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"/>
            <ds:Reference URI="#test-data">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>placeholder</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>placeholder</ds:SignatureValue>
    </ds:Signature>
</root>`

		signer, _ := NewSigner(xmlTemplate)
		signedXML, err := signer.Sign(privKey)
		So(err, ShouldBeNil)

		Convey("When the content is tampered with", func() {
			// Tamper with the content
			tamperedXML := strings.Replace(signedXML, "Original content", "Tampered content", 1)

			Convey("Then validation should fail", func() {
				validator, err := NewValidator(tamperedXML)
				So(err, ShouldBeNil)
				validator.Certificates = append(validator.Certificates, *cert)

				_, err = validator.ValidateReferences()
				So(err, ShouldNotBeNil)
			})
		})
	})
}
