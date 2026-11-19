package examples

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/moov-io/signedxml"
)

func Example_validate() {
	xmlFile, err := os.Open("../testdata/valid-saml.xml")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer xmlFile.Close()

	xmlBytes, err := io.ReadAll(xmlFile)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	validator, err := signedxml.NewValidator(string(xmlBytes))
	if err != nil {
		fmt.Printf("Validation Error: %s\n", err)
		return
	}
	refs, err := validator.ValidateReferences()
	if err != nil {
		fmt.Printf("Validation Error: %s\n", err)
		return
	}
	if len(refs) == 0 {
		fmt.Println("ERROR: No Validated References")
		return
	}
	fmt.Println("Example Validation Succeeded")

	var input = `<?xml version="1.0"?>

<?xml-stylesheet   href="doc.xsl" type="text/xsl"   ?>

<!DOCTYPE doc SYSTEM "doc.dtd">

<doc>Hello, world!<!-- Comment 1 --></doc>

<?pi-without-data     ?>

<!-- Comment 2 -->

<!-- Comment 3 -->`

	var output = `<?xml-stylesheet href="doc.xsl" type="text/xsl"   ?>
<doc>Hello, world!</doc>
<?pi-without-data?>`

	transform := signedxml.ExclusiveCanonicalization{WithComments: false}
	resultXML, err := transform.Process(input, "")
	if err != nil {
		fmt.Printf("Transformation Error: %s\n", err)
		return
	}
	if resultXML == output {
		fmt.Println("Example Transformation Succeeded")
	} else {
		fmt.Println("Transformation Error: The transformed output did not match the expected output.")
	}
	// Output:
	// Example Validation Succeeded
	// Example Transformation Succeeded
}

func Example_signAndValidate() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		fmt.Println(err)
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		fmt.Println(err)
		return
	}

	xml := fmt.Sprintf(`<?xml version="1.0"?>
<Document ID="doc">
  <Amount>100.00</Amount>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference URI="#doc">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue></SignatureValue>
    <KeyInfo>
      <X509Data>
        <X509Certificate>%s</X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
</Document>`, base64.StdEncoding.EncodeToString(der))

	signer, err := signedxml.NewSigner(xml)
	if err != nil {
		fmt.Println(err)
		return
	}
	signedXML, err := signer.Sign(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	validator, err := signedxml.NewValidator(signedXML)
	if err != nil {
		fmt.Println(err)
		return
	}
	validator.Certificates = []x509.Certificate{*cert}
	refs, err := validator.ValidateReferences()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("validated %d reference(s)\n", len(refs))
	fmt.Println(validator.SigningCert().Subject.CommonName)
	// Output:
	// validated 1 reference(s)
	// example
}
