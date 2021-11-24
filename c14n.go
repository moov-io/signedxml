package signedxml

import (
	"github.com/lestrrat-go/libxml2/clib"
	"github.com/lestrrat-go/libxml2/parser"
)

// C14N10Canonicalizer implements v1.0 inclusive canonicalization, with or without comments
type C14N10Canonicalizer struct {
	WithComments bool
}

// Process will canonicalize the inputXML
func (c C14N10Canonicalizer) Process(inputXML string, transformXML string) (outputXML string, err error) {
	// parse string with libxml2
	p := parser.New()
	doc, err := p.ParseString(inputXML)
	if err != nil {
		return "", err
	}

	// canonicalize
	canonicalString, err := clib.XMLC14NDocDumpMemory(doc, 0, c.WithComments) // http://xmlsoft.org/html/libxml-c14n.html#xmlC14NMode
	if err != nil {
		return "", err
	}

	return canonicalString, nil
}

// C14N11Canonicalizer implements v1.1 inclusive canonicalization, with or without comments
type C14N11Canonicalizer struct {
	WithComments bool
}

// Process will canonicalize the inputXML
func (c C14N11Canonicalizer) Process(inputXML string, transformXML string) (outputXML string, err error) {
	// parse string with libxml2
	p := parser.New()
	doc, err := p.ParseString(inputXML)
	if err != nil {
		return "", err
	}

	// canonicalize
	canonicalString, err := clib.XMLC14NDocDumpMemory(doc, 2, c.WithComments) // http://xmlsoft.org/html/libxml-c14n.html#xmlC14NMode
	if err != nil {
		return "", err
	}

	return canonicalString, nil
}

// C14N10ExclusiveCanonicalizer implements v1.0 exclusive canonicalation, with or without comments.
//
// It is known that callers cannot pass namespace-prefix array to this option.
type C14N10ExclusiveCanonicalizer struct {
	WithComments bool
}

// Process will canonicalize the inputXML
func (c C14N10ExclusiveCanonicalizer) Process(inputXML string, transformXML string) (outputXML string, err error) {
	// parse string with libxml2
	p := parser.New()
	doc, err := p.ParseString(inputXML)
	if err != nil {
		return "", err
	}

	// canonicalize
	canonicalString, err := clib.XMLC14NDocDumpMemory(doc, 1, c.WithComments) // http://xmlsoft.org/html/libxml-c14n.html#xmlC14NMode
	if err != nil {
		return "", err
	}

	return canonicalString, nil
}
