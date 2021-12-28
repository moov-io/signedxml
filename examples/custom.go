package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/beevik/etree"
	"github.com/daugminas/signedxml"
)

func testLBmsgValidator() {

	// read xml file
	// xmlFile, err := os.Open("../testdata/LB/ilpnot.xml")
	xmlFile, err := os.Open("../testdata/LB/iltsoinf.xml")
	// xmlFile, err := os.Open("../testdata/LB/roinvstg.xml")
	// xmlFile, err := os.Open("../testdata/LB/rsltnofinvstgtn.xml")
	if err != nil {
		panic(err)
	}
	defer xmlFile.Close()
	xmlBytes, _ := ioutil.ReadAll(xmlFile)

	// loax XML to validator
	validator, err := signedxml.NewValidator(string(xmlBytes))
	if err != nil {
		panic(err)
	}

	// read cert
	var certPEM string = "MIIFiDCCBHCgAwIBAgIKSZtmdgAAAAAA9TANBgkqhkiG9w0BAQUFADBdMQswCQYDVQQGEwJMVDEQMA4GA1UEBxMHVmlsbml1czEYMBYGA1UEChMPTGlldHV2b3MgYmFua2FzMQwwCgYDVQQLEwNNU0QxFDASBgNVBAMTC0xCLUxJVEFTLUNBMB4XDTExMDUyNjExMjMyOFoXDTQwMDgyNzA3NDMzM1owga8xMDAuBgoJkiaJk/IsZAEBDCBBNDI3QjFGM0M0MDFBMEQ0RTA0MzBBQzIwMzI5QTBENDEUMBIGA1UEBRMLMDAxMC8wMzUvMDExCzAJBgNVBAYTAkxUMRgwFgYDVQQKDA9MaWV0dXZvcyBiYW5rYXMxKTAnBgNVBAsMIE1va8SXamltbyBzaXN0ZW3FsyBkZXBhcnRhbWVudGFzMRMwEQYDVQQDDApURVNUIExJVEFTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl/bRLV1F9k1CCHPEedLbKVH3CDmrSlmNUfczG94tBabRdumiHTH14lopRkr6tS/2bN4xHU94Gd3Y9CdZ/lIBScJJVLlHJkZID8B7o4NyJXSSPOIg43fCbDO9q3eC/6WCTGklfmzhHxIOu5qqXetaWCtxDZKsLGJz625fRC/80Kw1JADMgQVl+mavj48LBQmkqfcHq5KDJQfHc1sthW+BGBdbNPE9wdGpmHQaCbt4fM3QczEhrHcDLSEvuFxUE9Z8WWLDs8GzrT4KPa5Y2MWZ5bdi2Rf3NiO46OLVuF97OcjsPQU5dx9jykd/ONTB8OOX1nEzK43d19zC8HkrlpFiYQIDAQABo4IB9TCCAfEwDgYDVR0PAQH/BAQDAgbAMIIBGwYDVR0gBIIBEjCCAQ4wggEKBgYEAI96AQIwgf8wgfwGCCsGAQUFBwICMIHvHoHsAFMAZQByAHQAaQBmAGkAawBhAHQAYQBzACAAbgBhAHUAZABvAGoAYQBtAGEAcwAgAHQAaQBrACAATABpAGUAdAB1AHYAbwBzACAAYgBhAG4AawBvACAAaQBuAGYAbwByAG0AYQBjAGkAbgEXAHMAZQAgAHMAaQBzAHQAZQBtAG8AcwBlAC4AIABGAG8AcgAgAHUAcwBhAGcAZQAgAGkAbgAgAHQAaABlACAASQBTACAAbwBmACAAdABoAGUAIABCAGEAbgBrACAAbwBmACAATABpAHQAaAB1AGEAbgBpAGEAIABvAG4AbAB5AC4wHQYDVR0OBBYEFCCU5ADFpsIgTc0MdhbwMr6oIAowMB8GA1UdIwQYMBaAFGCYgBf9iIkVmk22OnVwjPYOoFhzMDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly93d3cubGIubHQvcGtpL2NybC9MQi1MSVRBUy1DQS5jcmwwRQYIKwYBBQUHAQEEOTA3MDUGCCsGAQUFBzAChilodHRwOi8vd3d3LmxiLmx0L3BraS9jZXJ0L0xCLUxJVEFTLUNBLmNydDANBgkqhkiG9w0BAQUFAAOCAQEArS4jZ0TeVLGJmwYMsNJNSzlMZ5GlnDzOHfNm/6/Dx1v0RfYJhL57V6H5REDCJzzdzemXsWLtYgjnP2UN1wTMcFcnYdRdbf7qrgSWdRCCQQlb8UOHct02bLyfOG4YzIsTqpYvcsmMu4dePquOabgLplGnSVWSHYsSgtkFXv7CR9e9bJ7QNvxj9hHQEtdyDOySEzkca784EqWS7x9R7m8Cyjj5EcZIgVN7s31kadZN3hoyMoqEeVc07z5SbKYDKxX7JHigzQeXlKYxQScJYov0JdzwKuH5LSy5+8kNruqz7y/KHRXiscrq6wEDmgfSx8NWW8KSj3ng75Nr+ZFx4AVSQg=="
	cert, err := signedxml.LoadCertFromPEMString(certPEM, "CERTIFICATE")
	if err != nil {
		panic(err)
	}
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(xmlBytes)
	if err != nil {
		panic(err)
	}
	var certDigest, digestMethodURI string
	if el := doc.FindElement(".//CertDigest/DigestMethod"); el != nil {
		digestMethodURI = el.SelectAttrValue("Algorithm", "")
	}
	if el := doc.FindElement(".//CertDigest/DigestValue"); el != nil {
		certDigest = el.Text()
	}
	err = signedxml.ValidateCertificate(cert, certDigest, digestMethodURI, "", "")
	if err != nil {
		panic(err)
	}

	// set LB cert to validator - avoid fails in ref
	validator.SetValidationCert(cert)

	// validate XML references (digests & signature)
	err = validator.Validate()
	if err != nil {
		panic(err)
	}

	fmt.Println("Example Validation Succeeded")
}

func testOwnSignedDocValidator() {
	// xmlFile, err := os.Open("../testdata/own/minimal_signed.xml")
	// xmlFile, err := os.Open("../testdata/own/minimal_signed_RSAKeyValue.xml")
	xmlFile, err := os.Open("../testdata/own/pacs008_signed.xml")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer xmlFile.Close()

	xmlBytes, _ := ioutil.ReadAll(xmlFile)

	validator, err := signedxml.NewValidator(string(xmlBytes))
	if err != nil {
		fmt.Printf("Validation Error: %s", err)
	} else {
		err = validator.Validate()
		if err != nil {
			fmt.Printf("Validation Error: %s", err)
		} else {
			fmt.Println("Example Validation Succeeded")
		}
	}
}
