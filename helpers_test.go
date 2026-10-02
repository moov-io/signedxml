package signedxml

import (
	"strings"
	"testing"
)

func TestInsertXMLintoSignatureTemplate(t *testing.T) {
	tmpl := `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><Object></Object></Signature>`
	doc := `<payload id="1">hello</payload>`
	out, err := InsertXMLintoSignatureTemplate(tmpl, doc, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<payload id=\"1\">hello</payload>") {
		t.Fatalf("inserted XML missing: %s", out)
	}
}

func TestInsertTextIntoSignatureTemplate(t *testing.T) {
	tmpl := `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><Object></Object></Signature>`
	out, err := InsertTextIntoSignatureTemplate(tmpl, "plain-text", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "plain-text") {
		t.Fatalf("inserted text missing: %s", out)
	}
}

func TestInsertXMLintoSignatureTemplateMissingObject(t *testing.T) {
	_, err := InsertXMLintoSignatureTemplate(`<Signature></Signature>`, `<a/>`, false, false)
	if err == nil {
		t.Fatal("expected error when Object is missing")
	}
}
