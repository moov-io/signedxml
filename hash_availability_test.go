package signedxml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

const unavailableDigestURI = "http://example.test/unavailable-hash"

func loadTestRSAKey(t *testing.T) (*rsa.PrivateKey, x509.Certificate) {
	t.Helper()

	pemString, err := os.ReadFile("./testdata/rsa.crt")
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, _ := pem.Decode(pemString)
	if pemBlock == nil {
		t.Fatal("unable to decode testdata/rsa.crt")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	b64Bytes, err := os.ReadFile("./testdata/rsa.key.b64")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := base64.StdEncoding.DecodeString(string(b64Bytes))
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("unable to decode testdata/rsa.key.b64")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key, *cert
}

func documentWithDigest(algorithm string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<root ID="r">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference URI="#r">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="%s"/>
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue></SignatureValue>
  </Signature>
</root>`, algorithm)
}

func referenceFromXML(t *testing.T, xml string) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xml); err != nil {
		t.Fatal(err)
	}
	ref := doc.FindElement("//Reference")
	if ref == nil {
		t.Fatal("missing Reference element")
	}
	return ref
}

func TestUnavailableDigestAlgorithm(t *testing.T) {
	hashAlgorithms[unavailableDigestURI] = crypto.RIPEMD160
	t.Cleanup(func() {
		delete(hashAlgorithms, unavailableDigestURI)
	})

	xml := documentWithDigest(unavailableDigestURI)
	key, cert := loadTestRSAKey(t)

	t.Run("getDigestAlgorithm", func(t *testing.T) {
		_, err := getDigestAlgorithm(referenceFromXML(t, xml))
		if err == nil {
			t.Fatal("expected an error for an unavailable digest algorithm")
		}
		if !strings.Contains(err.Error(), "not available") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("ValidateReferences", func(t *testing.T) {
		validator, err := NewValidator(xml)
		if err != nil {
			t.Fatal(err)
		}
		validator.Certificates = []x509.Certificate{cert}

		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("unexpected panic: %v", rec)
			}
		}()

		_, err = validator.ValidateReferences()
		if err == nil {
			t.Fatal("expected an error for an unavailable digest algorithm")
		}
		if !strings.Contains(err.Error(), "not available") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Sign", func(t *testing.T) {
		signer, err := NewSigner(xml)
		if err != nil {
			t.Fatal(err)
		}

		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("unexpected panic: %v", rec)
			}
		}()

		_, err = signer.Sign(key)
		if err == nil {
			t.Fatal("expected an error for an unavailable digest algorithm")
		}
		if !strings.Contains(err.Error(), "not available") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestUnknownDigestMethod(t *testing.T) {
	const uri = "http://www.w3.org/2001/04/xmlenc#ripemd160"
	if _, ok := hashAlgorithms[uri]; ok {
		t.Fatalf("did not expect %s in hashAlgorithms", uri)
	}

	xml := documentWithDigest(uri)
	_, cert := loadTestRSAKey(t)

	t.Run("getDigestAlgorithm", func(t *testing.T) {
		_, err := getDigestAlgorithm(referenceFromXML(t, xml))
		if err == nil {
			t.Fatal("expected an error for an unknown digest algorithm")
		}
	})

	t.Run("ValidateReferences", func(t *testing.T) {
		validator, err := NewValidator(xml)
		if err != nil {
			t.Fatal(err)
		}
		validator.Certificates = []x509.Certificate{cert}

		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("unexpected panic: %v", rec)
			}
		}()

		_, err = validator.ValidateReferences()
		if err == nil {
			t.Fatal("expected an error for an unknown digest algorithm")
		}
	})
}

func TestRequireAvailableHash(t *testing.T) {
	if err := requireAvailableHash(crypto.SHA256); err != nil {
		t.Fatalf("SHA256 should be available: %v", err)
	}
	if err := requireAvailableHash(crypto.RIPEMD160); err == nil {
		t.Fatal("expected an error for an unavailable hash")
	}
	if err := requireAvailableHash(crypto.MD4); err == nil {
		t.Fatal("expected an error for an unavailable hash")
	}
}

func TestUnavailableSignatureHash(t *testing.T) {
	prev, ok := signingAlgorithms[x509.SHA256WithRSA]
	if !ok {
		t.Fatal("missing SHA256WithRSA signing algorithm")
	}
	signingAlgorithms[x509.SHA256WithRSA] = cryptoHash{algorithm: "rsa", hash: crypto.RIPEMD160}
	t.Cleanup(func() {
		signingAlgorithms[x509.SHA256WithRSA] = prev
	})

	xml := documentWithDigest("http://www.w3.org/2001/04/xmlenc#sha256")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(xml)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("unexpected panic: %v", rec)
		}
	}()

	_, err = signer.Sign(key)
	if err == nil {
		t.Fatal("expected an error for an unavailable signature hash")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Fatalf("unexpected error: %v", err)
	}
}
