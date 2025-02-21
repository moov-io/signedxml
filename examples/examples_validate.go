package examples

import (
	"fmt"
	"io"
	"os"

	"github.com/moov-io/signedxml"
)

func ExampleValidate() {
	testValidator()
	testExclCanon()
}

func testValidator() {
	xmlFile, err := os.Open("../testdata/valid-saml.xml")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer xmlFile.Close()

	xmlBytes, _ := io.ReadAll(xmlFile)

	validator, err := signedxml.NewValidator(string(xmlBytes))
	if err != nil {
		fmt.Printf("Validation Error: %s", err)
	} else {
		refs, err := validator.ValidateReferences()
		if err != nil {
			fmt.Printf("Validation Error: %s\n", err)
		}
		if len(refs) == 0 {
			fmt.Println("ERROR: No Validated References")
		} else {
			fmt.Println("Example Validation Succeeded")
		}
	}
}

func testExclCanon() {
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
	} else {
		if resultXML == output {
			fmt.Println("Example Tranformation Succeeded")
		} else {
			fmt.Println("Transformation Error: The transformed output did not match the expected output.")
		}
	}
}
