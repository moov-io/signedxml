package signedxml

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func TestExclusiveCanonicalizationUnusedPrefixesOmitted(t *testing.T) {
	input := `<n1:e xmlns:n1="urn:n1" xmlns:unused="urn:x"><n2:e xmlns:n2="urn:n2" xmlns:also="urn:y">z</n2:e></n1:e>`
	got, err := ExclusiveCanonicalization{}.Process(input, "")
	if err != nil {
		t.Fatal(err)
	}
	want := `<n1:e xmlns:n1="urn:n1"><n2:e xmlns:n2="urn:n2">z</n2:e></n1:e>`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExclusiveCanonicalizationSiblingPrefixes(t *testing.T) {
	input := `<root><a:x xmlns:a="urn:a" a:v="1"/><a:y xmlns:a="urn:a" a:v="2"/></root>`
	got, err := ExclusiveCanonicalization{}.Process(input, "")
	if err != nil {
		t.Fatal(err)
	}
	want := `<root><a:x xmlns:a="urn:a" a:v="1"></a:x><a:y xmlns:a="urn:a" a:v="2"></a:y></root>`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExclusiveCanonicalizationPrefixRedefinitionRestored(t *testing.T) {
	// Child redefines prefix p; the following sibling must see the ancestor binding.
	input := `<a:e xmlns:a="urn:a" xmlns:p="urn:p1"><b:e xmlns:b="urn:b" xmlns:p="urn:p2" p:attr="x"/><c:e xmlns:c="urn:c" p:attr="y"/></a:e>`
	got, err := ExclusiveCanonicalization{}.Process(input, "")
	if err != nil {
		t.Fatal(err)
	}
	want := `<a:e xmlns:a="urn:a"><b:e xmlns:b="urn:b" xmlns:p="urn:p2" p:attr="x"></b:e><c:e xmlns:c="urn:c" xmlns:p="urn:p1" p:attr="y"></c:e></a:e>`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExclusiveCanonicalizationInclusiveNamespaces(t *testing.T) {
	input := `<foo:root xmlns:foo="urn:foo" xmlns:bar="urn:bar"><foo:child>x</foo:child></foo:root>`
	transform := `<Transform><InclusiveNamespaces PrefixList="bar"></InclusiveNamespaces></Transform>`
	got, err := ExclusiveCanonicalization{}.Process(input, transform)
	if err != nil {
		t.Fatal(err)
	}
	want := `<foo:root xmlns:bar="urn:bar" xmlns:foo="urn:foo"><foo:child>x</foo:child></foo:root>`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExclusiveCanonicalizationProcessElementInheritsAncestorNS(t *testing.T) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(`<parent xmlns:foo="urn:foo"><foo:child>text</foo:child></parent>`); err != nil {
		t.Fatal(err)
	}
	child := doc.FindElement("//foo:child")
	if child == nil {
		t.Fatal("missing foo:child")
	}
	got, err := ExclusiveCanonicalization{}.ProcessElement(child, "")
	if err != nil {
		t.Fatal(err)
	}
	want := `<foo:child xmlns:foo="urn:foo">text</foo:child>`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestExclusiveCanonicalizationNestedUnusedNamespacesLinearMemory(t *testing.T) {
	const depth = 250
	const nsPerLevel = 20
	xml := nestedUnusedNamespaces(depth, nsPerLevel)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	out, err := ExclusiveCanonicalization{}.Process(xml, "")
	if err != nil {
		t.Fatal(err)
	}

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	const maxAlloc = 64 << 20 // 64 MiB
	if allocated > maxAlloc {
		t.Fatalf("exclusive c14n allocated %d bytes for %d-byte input; want <%d (namespace map must not be copied per node)", allocated, len(xml), maxAlloc)
	}

	if strings.Contains(out, "xmlns:p") {
		t.Fatal("unused namespace prefixes must not be emitted")
	}
	if !strings.Contains(out, `xmlns:n1="urn:n1"`) {
		t.Fatal("visibly used prefix n1 should be rendered")
	}
}

func TestExclusiveCanonicalizationNamespaceLimit(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`<a:e xmlns:a="urn:a"`)
	for i := 0; i < maxInScopeNamespaces; i++ {
		fmt.Fprintf(&sb, ` xmlns:p%d="urn:%d"`, i, i)
	}
	sb.WriteString(`>x</a:e>`)

	_, err := ExclusiveCanonicalization{}.Process(sb.String(), "")
	if err == nil {
		t.Fatal("expected error when exceeding in-scope namespace limit")
	}
	if !strings.Contains(err.Error(), "in-scope namespaces") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateReferencesNestedNamespacesCompletes(t *testing.T) {
	pemString, err := os.ReadFile("./testdata/rsa.crt")
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, _ := pem.Decode(pemString)
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	xml := `<Response xmlns="urn:test">` + nestedUnusedNamespaces(80, 15) +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>` +
		`<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>` +
		`<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>` +
		`<Reference URI=""><Transforms>` +
		`<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform>` +
		`</Transforms>` +
		`<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>` +
		`<DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>` +
		`</Reference></SignedInfo><SignatureValue>AAAA</SignatureValue></Signature></Response>`

	v, err := NewValidator(xml)
	if err != nil {
		t.Fatal(err)
	}
	v.Certificates = []x509.Certificate{*cert}

	_, verr := v.ValidateReferences()
	if verr == nil {
		t.Fatal("expected digest or signature failure")
	}
}

func nestedUnusedNamespaces(depth, nsPerLevel int) string {
	var sb strings.Builder
	for d := 1; d <= depth; d++ {
		fmt.Fprintf(&sb, `<n%d:e`, d)
		for k := 0; k < nsPerLevel; k++ {
			fmt.Fprintf(&sb, ` xmlns:p%d_%d="urn:%d_%d"`, d, k, d, k)
		}
		fmt.Fprintf(&sb, ` xmlns:n%d="urn:n%d">`, d, d)
	}
	sb.WriteString("x")
	for d := depth; d >= 1; d-- {
		fmt.Fprintf(&sb, `</n%d:e>`, d)
	}
	return sb.String()
}

func testRSACert(t *testing.T) x509.Certificate {
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

func dummySignedXML(body, prefixList string) string {
	return `<Response xmlns="urn:test">` + body +
		`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>` +
		`<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>` +
		`<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>` +
		`<Reference URI=""><Transforms>` +
		`<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">` +
		`<InclusiveNamespaces PrefixList="` + prefixList + `"></InclusiveNamespaces>` +
		`</Transform></Transforms>` +
		`<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>` +
		`<DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>` +
		`</Reference></SignedInfo><SignatureValue>AAAA</SignatureValue></Signature></Response>`
}

func inclusiveTransform(prefixList string) string {
	return `<Transform><InclusiveNamespaces PrefixList="` + prefixList + `"></InclusiveNamespaces></Transform>`
}

func TestParseInclusivePrefixList(t *testing.T) {
	got, err := parseInclusivePrefixList("  bar \t bar\nfoo ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d unique prefixes, want 2: %v", len(got), got)
	}
	if _, ok := got["bar"]; !ok {
		t.Fatal("missing bar")
	}
	if _, ok := got["foo"]; !ok {
		t.Fatal("missing foo")
	}

	got, err = parseInclusivePrefixList(strings.TrimSpace(strings.Repeat("p ", 10000)))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d unique prefixes, want 1", len(got))
	}

	var over strings.Builder
	for i := 0; i <= maxInScopeNamespaces; i++ {
		if i > 0 {
			over.WriteByte(' ')
		}
		fmt.Fprintf(&over, "p%d", i)
	}
	_, err = parseInclusivePrefixList(over.String())
	if err == nil {
		t.Fatal("expected error when exceeding InclusiveNamespaces prefix limit")
	}
	if !strings.Contains(err.Error(), "InclusiveNamespaces prefixes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExclusiveCanonicalizationInclusiveNamespacesDuplicates(t *testing.T) {
	input := `<foo:root xmlns:foo="urn:foo" xmlns:bar="urn:bar"><foo:child>x</foo:child></foo:root>`
	want := `<foo:root xmlns:bar="urn:bar" xmlns:foo="urn:foo"><foo:child>x</foo:child></foo:root>`

	gotOnce, err := ExclusiveCanonicalization{}.Process(input, inclusiveTransform("bar"))
	if err != nil {
		t.Fatal(err)
	}
	gotDup, err := ExclusiveCanonicalization{}.Process(input, inclusiveTransform("bar bar bar"))
	if err != nil {
		t.Fatal(err)
	}
	if gotOnce != want {
		t.Fatalf("got %q, want %q", gotOnce, want)
	}
	if gotDup != gotOnce {
		t.Fatalf("duplicate PrefixList tokens must canonicalize the same as one token: got %q", gotDup)
	}
}

func TestExclusiveCanonicalizationPrefixListLimit(t *testing.T) {
	var sb strings.Builder
	for i := 0; i <= maxInScopeNamespaces; i++ {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "p%d", i)
	}

	_, err := ExclusiveCanonicalization{}.Process(`<a:e xmlns:a="urn:a">x</a:e>`, inclusiveTransform(sb.String()))
	if err == nil {
		t.Fatal("expected error when exceeding InclusiveNamespaces prefix limit")
	}
	if !strings.Contains(err.Error(), "InclusiveNamespaces prefixes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExclusiveCanonicalizationPrefixListAtLimit(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < maxInScopeNamespaces; i++ {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "p%d", i)
	}

	got, err := ExclusiveCanonicalization{}.Process(`<a:e xmlns:a="urn:a">x</a:e>`, inclusiveTransform(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `xmlns:a="urn:a"`) {
		t.Fatalf("got %q", got)
	}
}

func TestValidateReferencesPrefixListLimit(t *testing.T) {
	var sb strings.Builder
	for i := 0; i <= maxInScopeNamespaces; i++ {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "p%d", i)
	}

	v, err := NewValidator(dummySignedXML("<e/>", sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	v.Certificates = []x509.Certificate{testRSACert(t)}

	_, err = v.ValidateReferences()
	if err == nil {
		t.Fatal("expected error when exceeding InclusiveNamespaces prefix limit")
	}
	if !strings.Contains(err.Error(), "InclusiveNamespaces prefixes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateReferencesPrefixListRepeatedTokens(t *testing.T) {
	const elements = 10000
	const tokens = 250000
	body := strings.Repeat("<e/>", elements)
	repeated := strings.TrimSpace(strings.Repeat("p ", tokens))
	controlList := strings.Repeat("x", len(repeated))
	cert := testRSACert(t)

	run := func(name, list string) (time.Duration, error) {
		t.Helper()
		xml := dummySignedXML(body, list)
		start := time.Now()
		v, err := NewValidator(xml)
		if err != nil {
			t.Fatalf("%s: NewValidator: %v", name, err)
		}
		v.Certificates = []x509.Certificate{cert}
		_, err = v.ValidateReferences()
		return time.Since(start), err
	}

	controlTime, controlErr := run("control", controlList)
	if controlErr == nil || !strings.Contains(controlErr.Error(), "Calculated digest") {
		t.Fatalf("control: expected digest mismatch, got %v", controlErr)
	}

	bypassTime, bypassErr := run("repeated", repeated)
	if bypassErr == nil || !strings.Contains(bypassErr.Error(), "Calculated digest") {
		t.Fatalf("repeated: expected digest mismatch, got %v", bypassErr)
	}

	// Unpatched v1.4.1 walks every PrefixList token at every element (~500x).
	// Dedup plus the in-scope walk keeps the repeated list near the equal-size control.
	if bypassTime > 200*time.Millisecond && bypassTime > 10*controlTime {
		t.Fatalf("repeated PrefixList took %s vs control %s (ratio %.1fx); unique tokens must not be re-walked per element",
			bypassTime, controlTime, float64(bypassTime)/float64(controlTime))
	}
}
