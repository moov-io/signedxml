package signedxml

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func testRSACertificate(t *testing.T) x509.Certificate {
	t.Helper()
	pemString, err := os.ReadFile("./testdata/rsa.crt")
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, _ := pem.Decode(pemString)
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return *cert
}

func dummyReference(uri string) string {
	return `<Reference URI="` + uri + `">` +
		`<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>` +
		`<DigestValue>AAAA</DigestValue></Reference>`
}

func envelopeWithReferences(refs string) string {
	return `<root><t ID="r"/>` +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>` +
		`<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>` +
		`<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>` +
		refs +
		`</SignedInfo><SignatureValue>AAAA</SignatureValue></Signature></root>`
}

func validateEnvelope(t *testing.T, xml string) error {
	t.Helper()
	v, err := NewValidator(xml)
	if err != nil {
		t.Fatal(err)
	}
	v.Certificates = []x509.Certificate{testRSACertificate(t)}
	_, err = v.ValidateReferences()
	return err
}

func TestValidateReferencesRejectsTooManyReferences(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxReferences+1; i++ {
		b.WriteString(dummyReference("#r"))
	}
	err := validateEnvelope(t, envelopeWithReferences(b.String()))
	if err == nil {
		t.Fatal("expected error when SignedInfo exceeds the reference limit")
	}
	if !strings.Contains(err.Error(), "exceeds the limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateReferencesAllowsMaxReferences(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxReferences; i++ {
		b.WriteString(dummyReference("#r"))
	}
	err := validateEnvelope(t, envelopeWithReferences(b.String()))
	if err == nil {
		t.Fatal("expected digest mismatch inside the allowed reference count")
	}
	if strings.Contains(err.Error(), "exceeds the limit") {
		t.Fatalf("limit should not apply at %d references: %v", maxReferences, err)
	}
	if !strings.Contains(err.Error(), "Calculated digest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateReferencesNoTransformHash(t *testing.T) {
	// C14N 1.0 Rec of <t ID="r"></t> as hashed by calculateHashFromElement.
	const digest = "ixhGe5n3PBxjM/iIthV0pYIGaC4FapSE1VhzetMbPAk="
	ref := `<Reference URI="#r">` +
		`<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>` +
		`<DigestValue>` + digest + `</DigestValue></Reference>`
	err := validateEnvelope(t, envelopeWithReferences(ref))
	if err == nil {
		t.Fatal("expected signature failure after a matching digest")
	}
	if !strings.Contains(err.Error(), "signature does not match") {
		t.Fatalf("expected signature check after digest match, got: %v", err)
	}
}

func TestSignRejectsTooManyReferences(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxReferences+1; i++ {
		b.WriteString(dummyReference("#r"))
	}
	signer, err := NewSigner(envelopeWithReferences(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = signer.Sign(nil)
	if err == nil {
		t.Fatal("expected error when SignedInfo exceeds the reference limit")
	}
	if !strings.Contains(err.Error(), "exceeds the limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCloneIfSameDetachesLiveDocument(t *testing.T) {
	v, err := NewValidator(envelopeWithReferences(dummyReference("")))
	if err != nil {
		t.Fatal(err)
	}
	v.Certificates = []x509.Certificate{testRSACertificate(t)}
	if err := v.loadValuesFromXML(); err != nil {
		t.Fatal(err)
	}
	ref := v.signedInfo.FindElement("./Reference")
	if ref == nil {
		t.Fatal("missing Reference")
	}
	if referenceRequiresDocumentCopy(ref) {
		t.Fatal("empty-URI dummy ref should not require a working copy")
	}

	out, err := v.getReferencedXML(ref, v.xml)
	if err != nil {
		t.Fatal(err)
	}
	if out != v.xml {
		t.Fatal("empty URI should return the input document")
	}

	detached := cloneIfSame(v.xml, out)
	if detached == v.xml {
		t.Fatal("cloneIfSame must not return the live validator document")
	}
	detached.Root().CreateAttr("x", "1")
	if v.xml.Root().SelectAttrValue("x", "") == "1" {
		t.Fatal("mutating the returned document leaked into validator xml")
	}
}

func TestReferenceRequiresDocumentCopy(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		want bool
	}{
		{
			name: "no transforms",
			xml:  `<Reference URI="#r"><DigestValue>AAAA</DigestValue></Reference>`,
			want: false,
		},
		{
			name: "c14n only",
			xml: `<Reference URI="#r"><Transforms>` +
				`<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform>` +
				`</Transforms></Reference>`,
			want: false,
		},
		{
			name: "enveloped signature",
			xml: `<Reference URI="#r"><Transforms>` +
				`<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform>` +
				`<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform>` +
				`</Transforms></Reference>`,
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parseXML(tc.xml)
			if err != nil {
				t.Fatal(err)
			}
			got := referenceRequiresDocumentCopy(doc.Root())
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
