package signedxml

import (
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

type c14N10RecCanonicalizer struct {
	WithComments bool
}

func (c *c14N10RecCanonicalizer) Process(inputXML string, transformXML string) (outputXML string, err error) {
	doc := etree.NewDocument()
	doc.ReadFromString(inputXML)

	var canon dsig.Canonicalizer
	if c.WithComments {
		canon = dsig.MakeC14N10WithCommentsCanonicalizer()
	} else {
		canon = dsig.MakeC14N10RecCanonicalizer()
	}

	out, err := canon.Canonicalize(doc.Root())
	if err != nil {
		return "", err
	}
	return string(out), nil
}

type c14N11Canonicalizer struct {
	WithComments bool
}

func (c *c14N11Canonicalizer) Process(inputXML string, transformXML string) (outputXML string, err error) {
	doc := etree.NewDocument()
	doc.ReadFromString(inputXML)

	var canon dsig.Canonicalizer
	if c.WithComments {
		canon = dsig.MakeC14N11WithCommentsCanonicalizer()
	} else {
		canon = dsig.MakeC14N11Canonicalizer()
	}

	out, err := canon.Canonicalize(doc.Root())
	if err != nil {
		return "", err
	}
	return string(out), nil
}
