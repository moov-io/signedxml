package examples

import (
	"fmt"
	"testing"

	"github.com/daugminas/signedxml"

	. "github.com/smartystreets/goconvey/convey"
)

var example31Input = `<?xml version="1.0"?>

<?xml-stylesheet   href="doc.xsl" type="text/xsl"   ?>

<!DOCTYPE doc SYSTEM "doc.dtd">

<doc>Hello, world!<!-- Comment 1 --></doc>

<?pi-without-data     ?>

<!-- Comment 2 -->

<!-- Comment 3 -->`

var example31Output = `<?xml-stylesheet href="doc.xsl" type="text/xsl"   ?>
<doc>Hello, world!</doc>
<?pi-without-data?>`

var example31OutputWithComments = `<?xml-stylesheet href="doc.xsl" type="text/xsl"   ?>
<doc>Hello, world!<!-- Comment 1 --></doc>
<?pi-without-data?>
<!-- Comment 2 -->
<!-- Comment 3 -->`

var example32Input = `<doc>
   <clean>   </clean>
   <dirty>   A   B   </dirty>
   <mixed>
      A
      <clean>   </clean>
      B
      <dirty>   A   B   </dirty>
      C
   </mixed>
</doc>`

var example32Output = `<doc>
   <clean>   </clean>
   <dirty>   A   B   </dirty>
   <mixed>
      A
      <clean>   </clean>
      B
      <dirty>   A   B   </dirty>
      C
   </mixed>
</doc>`

var example33Input = `<!DOCTYPE doc [<!ATTLIST e9 attr CDATA "default">]>
<doc>
   <e1   />
   <e2   ></e2>
   <e3   name = "elem3"   id="elem3"   />
   <e4   name="elem4"   id="elem4"   ></e4>
   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm" xmlns:b="http://www.ietf.org" xmlns:a="http://www.w3.org" xmlns="http://example.org"/>
   <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="" xmlns:a="http://www.w3.org">
            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
         </e8>
      </e7>
   </e6>
</doc>`

var example33Output = `<doc>
   <e1></e1>
   <e2></e2>
   <e3 id="elem3" name="elem3"></e3>
   <e4 id="elem4" name="elem4"></e4>
   <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
   <e6 xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="">
            <e9 xmlns:a="http://www.ietf.org" attr="default"></e9>
         </e8>
      </e7>
   </e6>
</doc>`

var example34Input = `<!DOCTYPE doc [
<!ATTLIST normId id ID #IMPLIED>
<!ATTLIST normNames attr NMTOKENS #IMPLIED>
]>
<doc>
   <text>First line&#x0d;&#10;Second line</text>
   <value>&#x32;</value>
   <compute><![CDATA[value>"0" && value<"10" ?"valid":"error"]]></compute>
   <compute expr='value>"0" &amp;&amp; value&lt;"10" ?"valid":"error"'>valid</compute>
   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>
   <normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>
</doc>`

var example34Output = `<doc>
   <text>First line&#xD;
Second line</text>
   <value>2</value>
   <compute>value&gt;"0" &amp;&amp; value&lt;"10" ?"valid":"error"</compute>
   <compute expr="value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;">valid</compute>
   <norm attr=" '    &#xD;&#xA;&#x9;   ' "></norm>
   <normNames attr="A &#xD;&#xA;&#x9; B"></normNames>
</doc>`

// modified to not include DTD processing. still tests for whitespace treated as
// CDATA
var example34ModifiedOutput = `<doc>
   <text>First line&#xD;
Second line</text>
   <value>2</value>
   <compute>value&gt;"0" &amp;&amp; value&lt;"10" ?"valid":"error"</compute>
   <compute expr="value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;">valid</compute>
   <norm attr=" '    &#xD;&#xA;&#x9;   ' "></norm>
   <normNames attr="   A    &#xD;&#xA;&#x9;   B   "></normNames>
</doc>`

var example35Input = `<!DOCTYPE doc [
<!ATTLIST doc attrExtEnt ENTITY #IMPLIED>
<!ENTITY ent1 "Hello">
<!ENTITY ent2 SYSTEM "world.txt">
<!ENTITY entExt SYSTEM "earth.gif" NDATA gif>
<!NOTATION gif SYSTEM "viewgif.exe">
]>
<doc attrExtEnt="entExt">
   &ent1;, &ent2;!
</doc>

<!-- Let world.txt contain "world" (excluding the quotes) -->`

var example35Output = `<doc attrExtEnt="entExt">
   Hello, world!
</doc>`

var example36Input = `<?xml version="1.0" encoding="ISO-8859-1"?>
<doc>&#169;</doc>`

var example36Output = "<doc>\u00A9</doc>"

var example37Input = `<!DOCTYPE doc [
<!ATTLIST e2 xml:space (default|preserve) 'preserve'>
<!ATTLIST e3 id ID #IMPLIED>
]>
<doc xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org">
   <e1>
      <e2 xmlns="">
         <e3 id="E3"/>
      </e2>
   </e1>
</doc>`

var example37SubsetExpression = `<!-- Evaluate with declaration xmlns:ietf="http://www.ietf.org" -->

(//. | //@* | //namespace::*)
[
   self::ietf:e1 or (parent::ietf:e1 and not(self::text() or self::e2))
   or
   count(id("E3")|ancestor-or-self::node()) = count(ancestor-or-self::node())
]`

var example37Output = `<e1 xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org"><e3 xmlns="" id="E3" xml:space="preserve"></e3></e1>`

type exampleXML struct {
	input        string
	output       string
	withComments bool
	expression   string
}

// test examples from the spec (www.w3.org/TR/2001/REC-xml-c14n-20010315#Examples)
func TestCanonicalizationExamples(t *testing.T) {
	Convey("Given XML Input", t, func() {
		cases := map[string]exampleXML{
			"(Example 3.1 w/o Comments)": {input: example31Input, output: example31Output},
			"(Example 3.1 w/Comments)":   {input: example31Input, output: example31OutputWithComments, withComments: true},
			"(Example 3.2)":              {input: example32Input, output: example32Output},
			// 3.3 is for Canonical NOT ExclusiveCanonical (one of the exceptions here: http://www.w3.org/TR/xml-exc-c14n/#sec-Specification)
			// "(Example 3.3)": {input: example33Input, output: example33Output},
			"(Example 3.4)": {input: example34Input, output: example34ModifiedOutput},
			// "(Example 3.5)": {input: example35Input, output: example35Output},
			// 3.6 will work, but requires a change to the etree package first:
			// http://stackoverflow.com/questions/6002619/unmarshal-an-iso-8859-1-xml-input-in-go
			// "(Example 3.6)": {input: example36Input, output: example36Output},
			"(Example 3.7)": {input: example37Input, output: example37Output, expression: example37SubsetExpression},
		}
		for description, test := range cases {
			Convey(fmt.Sprintf("When transformed %s", description), func() {
				transform := signedxml.ExclusiveCanonicalization{
					WithComments: test.withComments,
				}
				resultXML, err := transform.Process(test.input, "")
				Convey("Then the resulting XML match the example output", func() {
					So(err, ShouldBeNil)
					So(resultXML, ShouldEqual, test.output)
				})
			})
		}
	})
}

func TestTODO(t *testing.T) {
	// The XML specifications cover the following examples, but our library does not successfully transform.
	t.Logf("Input:\n%s\nOutput:\n%s\n", example33Input, example33Output) // Example 3.3
	t.Logf("Input:\n%s\nOutput:\n%s\n", example35Input, example35Output) // Example 3.5
	t.Logf("Input:\n%s\nOutput:\n%s\n", example36Input, example36Output) // Example 3.6
	t.Logf("Input:\n%s\nOutput:\n%s\n", example37Input, example37Output) // Example 3.7
}
