package xmlenc

import (
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
)

// EncryptedType is the abstract base type for EncryptedData and EncryptedKey
// as defined in the XML Encryption specification.
type EncryptedType struct {
	ID               string
	Type             string // TypeElement, TypeContent, or custom URI
	MimeType         string
	Encoding         string
	EncryptionMethod *EncryptionMethod
	KeyInfo          *KeyInfo
	CipherData       *CipherData
}

// EncryptedData represents the xenc:EncryptedData element
// which contains encrypted content (either element or content encryption).
type EncryptedData struct {
	EncryptedType
}

// EncryptedKey represents the xenc:EncryptedKey element
// which contains an encrypted key wrapped for a specific recipient.
type EncryptedKey struct {
	EncryptedType
	Recipient      string // Optional hint to the recipient
	CarriedKeyName string // Name for the key being carried
	ReferenceList  []DataReference
}

// EncryptionMethod specifies the algorithm used for encryption.
type EncryptionMethod struct {
	Algorithm    string // URI of the encryption algorithm
	KeySize      int    // Optional explicit key size
	OAEPParams   []byte // For RSA-OAEP: MGF and DigestMethod
	DigestMethod string // Digest algorithm for RSA-OAEP
	MGFAlgorithm string // MGF algorithm for RSA-OAEP 1.1
}

// CipherData contains either CipherValue (inline) or CipherReference (external)
type CipherData struct {
	CipherValue     []byte           // Base64-decoded encrypted content
	CipherReference *CipherReference // URI reference to encrypted content
}

// CipherReference points to external encrypted data
type CipherReference struct {
	URI        string
	Transforms []Transform
}

// Transform represents a transformation to be applied
type Transform struct {
	Algorithm string
}

// DataReference points to an EncryptedData element
type DataReference struct {
	URI string
}

// KeyInfo contains key identification information
// This is compatible with ds:KeyInfo from XML Signatures
type KeyInfo struct {
	ID              string
	EncryptedKey    *EncryptedKey
	AgreementMethod *AgreementMethod
	KeyName         string
	KeyValue        *KeyValue
	X509Data        *X509Data
	RetrievalMethod *RetrievalMethod
}

// KeyValue contains a public key value
type KeyValue struct {
	RSAKeyValue *RSAKeyValue
	ECKeyValue  *ECKeyValue
}

// RSAKeyValue contains RSA public key parameters
type RSAKeyValue struct {
	Modulus  []byte
	Exponent []byte
}

// ECKeyValue contains EC public key parameters
type ECKeyValue struct {
	NamedCurve string // OID or named curve identifier
	PublicKey  []byte
}

// X509Data contains X.509 certificate data
type X509Data struct {
	X509Certificate []byte // DER-encoded certificate
}

// RetrievalMethod indicates where to retrieve key info
type RetrievalMethod struct {
	URI  string
	Type string
}

// AgreementMethod represents xenc11:AgreementMethod for key agreement
type AgreementMethod struct {
	Algorithm           string // e.g., AlgorithmECDHES, AlgorithmX25519
	KeyDerivationMethod *KeyDerivationMethod
	OriginatorKeyInfo   *KeyInfo
	RecipientKeyInfo    *KeyInfo
	KANonce             []byte // Key Agreement Nonce
}

// KeyDerivationMethod specifies how to derive the key encryption key
type KeyDerivationMethod struct {
	Algorithm       string // e.g., AlgorithmHKDF, AlgorithmConcatKDF
	ConcatKDFParams *ConcatKDFParams
	HKDFParams      *HKDFParams
	PBKDF2Params    *PBKDF2Params
}

// ConcatKDFParams contains parameters for Concat KDF
type ConcatKDFParams struct {
	DigestMethod string
	AlgorithmID  []byte
	PartyUInfo   []byte
	PartyVInfo   []byte
	SuppPubInfo  []byte
	SuppPrivInfo []byte
}

// HKDFParams contains parameters for HKDF (RFC 5869)
type HKDFParams struct {
	PRF       string // PRF algorithm URI (e.g., HMAC-SHA256)
	Salt      []byte
	Info      []byte
	KeyLength int // Output key length in bits
}

// PBKDF2Params contains parameters for PBKDF2
type PBKDF2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int
	PRF            string
}

// DerivedKey represents xenc11:DerivedKey
type DerivedKey struct {
	ID                  string
	Type                string
	Recipient           string
	KeyDerivationMethod *KeyDerivationMethod
	ReferenceList       []DataReference
	MasterKeyName       string
}

// ToElement converts EncryptedData to an etree.Element
func (ed *EncryptedData) ToElement() *etree.Element {
	elem := etree.NewElement("xenc:EncryptedData")
	elem.CreateAttr("xmlns:xenc", NamespaceXMLEnc)

	if ed.ID != "" {
		elem.CreateAttr("Id", ed.ID)
	}
	if ed.Type != "" {
		elem.CreateAttr("Type", ed.Type)
	}
	if ed.MimeType != "" {
		elem.CreateAttr("MimeType", ed.MimeType)
	}

	if ed.EncryptionMethod != nil {
		ed.EncryptionMethod.appendTo(elem)
	}
	if ed.KeyInfo != nil {
		ed.KeyInfo.appendTo(elem)
	}
	if ed.CipherData != nil {
		ed.CipherData.appendTo(elem)
	}

	return elem
}

// ToElement converts EncryptedKey to an etree.Element
func (ek *EncryptedKey) ToElement() *etree.Element {
	elem := etree.NewElement("xenc:EncryptedKey")
	elem.CreateAttr("xmlns:xenc", NamespaceXMLEnc)

	if ek.ID != "" {
		elem.CreateAttr("Id", ek.ID)
	}
	if ek.Type != "" {
		elem.CreateAttr("Type", ek.Type)
	}
	if ek.Recipient != "" {
		elem.CreateAttr("Recipient", ek.Recipient)
	}

	if ek.EncryptionMethod != nil {
		ek.EncryptionMethod.appendTo(elem)
	}
	if ek.KeyInfo != nil {
		ek.KeyInfo.appendTo(elem)
	}
	if ek.CipherData != nil {
		ek.CipherData.appendTo(elem)
	}
	if ek.CarriedKeyName != "" {
		ckn := elem.CreateElement("xenc:CarriedKeyName")
		ckn.SetText(ek.CarriedKeyName)
	}
	if len(ek.ReferenceList) > 0 {
		rl := elem.CreateElement("xenc:ReferenceList")
		for _, ref := range ek.ReferenceList {
			dr := rl.CreateElement("xenc:DataReference")
			dr.CreateAttr("URI", ref.URI)
		}
	}

	return elem
}

func (em *EncryptionMethod) appendTo(parent *etree.Element) {
	elem := parent.CreateElement("xenc:EncryptionMethod")
	elem.CreateAttr("Algorithm", em.Algorithm)

	if em.KeySize > 0 {
		ks := elem.CreateElement("xenc:KeySize")
		ks.SetText(fmt.Sprintf("%d", em.KeySize))
	}
	if len(em.OAEPParams) > 0 {
		op := elem.CreateElement("xenc:OAEPparams")
		op.SetText(base64.StdEncoding.EncodeToString(em.OAEPParams))
	}
	if em.DigestMethod != "" {
		dm := elem.CreateElement("ds:DigestMethod")
		dm.CreateAttr("xmlns:ds", NamespaceXMLDSig)
		dm.CreateAttr("Algorithm", em.DigestMethod)
	}
	if em.MGFAlgorithm != "" {
		mgf := elem.CreateElement("xenc11:MGF")
		mgf.CreateAttr("xmlns:xenc11", NamespaceXMLEnc11)
		mgf.CreateAttr("Algorithm", em.MGFAlgorithm)
	}
}

func (cd *CipherData) appendTo(parent *etree.Element) {
	elem := parent.CreateElement("xenc:CipherData")

	if cd.CipherValue != nil {
		cv := elem.CreateElement("xenc:CipherValue")
		cv.SetText(base64.StdEncoding.EncodeToString(cd.CipherValue))
	} else if cd.CipherReference != nil {
		cr := elem.CreateElement("xenc:CipherReference")
		cr.CreateAttr("URI", cd.CipherReference.URI)
		// Add transforms if present
		if len(cd.CipherReference.Transforms) > 0 {
			transforms := cr.CreateElement("xenc:Transforms")
			for _, t := range cd.CipherReference.Transforms {
				tr := transforms.CreateElement("ds:Transform")
				tr.CreateAttr("xmlns:ds", NamespaceXMLDSig)
				tr.CreateAttr("Algorithm", t.Algorithm)
			}
		}
	}
}

func (ki *KeyInfo) appendTo(parent *etree.Element) {
	elem := parent.CreateElement("ds:KeyInfo")
	elem.CreateAttr("xmlns:ds", NamespaceXMLDSig)

	if ki.ID != "" {
		elem.CreateAttr("Id", ki.ID)
	}
	if ki.KeyName != "" {
		kn := elem.CreateElement("ds:KeyName")
		kn.SetText(ki.KeyName)
	}
	if ki.EncryptedKey != nil {
		ekElem := ki.EncryptedKey.ToElement()
		elem.AddChild(ekElem)
	}
	if ki.AgreementMethod != nil {
		ki.AgreementMethod.appendTo(elem)
	}
	if ki.X509Data != nil {
		x509 := elem.CreateElement("ds:X509Data")
		cert := x509.CreateElement("ds:X509Certificate")
		cert.SetText(base64.StdEncoding.EncodeToString(ki.X509Data.X509Certificate))
	}
	if ki.RetrievalMethod != nil {
		rm := elem.CreateElement("ds:RetrievalMethod")
		rm.CreateAttr("URI", ki.RetrievalMethod.URI)
		if ki.RetrievalMethod.Type != "" {
			rm.CreateAttr("Type", ki.RetrievalMethod.Type)
		}
	}
}

func (am *AgreementMethod) appendTo(parent *etree.Element) {
	elem := parent.CreateElement("xenc:AgreementMethod")
	elem.CreateAttr("Algorithm", am.Algorithm)

	if am.KeyDerivationMethod != nil {
		am.KeyDerivationMethod.appendTo(elem)
	}
	if len(am.KANonce) > 0 {
		kan := elem.CreateElement("xenc:KA-Nonce")
		kan.SetText(base64.StdEncoding.EncodeToString(am.KANonce))
	}
	if am.OriginatorKeyInfo != nil {
		oki := elem.CreateElement("xenc:OriginatorKeyInfo")
		// Add key info content
		if am.OriginatorKeyInfo.KeyValue != nil && am.OriginatorKeyInfo.KeyValue.ECKeyValue != nil {
			kv := oki.CreateElement("ds:KeyValue")
			kv.CreateAttr("xmlns:ds", NamespaceXMLDSig)
			ec := kv.CreateElement("dsig11:ECKeyValue")
			ec.CreateAttr("xmlns:dsig11", NamespaceXMLDSig11)
			if am.OriginatorKeyInfo.KeyValue.ECKeyValue.NamedCurve != "" {
				nc := ec.CreateElement("dsig11:NamedCurve")
				nc.CreateAttr("URI", am.OriginatorKeyInfo.KeyValue.ECKeyValue.NamedCurve)
			}
			pk := ec.CreateElement("dsig11:PublicKey")
			pk.SetText(base64.StdEncoding.EncodeToString(am.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey))
		}
	}
	if am.RecipientKeyInfo != nil {
		rki := elem.CreateElement("xenc:RecipientKeyInfo")
		if am.RecipientKeyInfo.X509Data != nil {
			x509 := rki.CreateElement("ds:X509Data")
			x509.CreateAttr("xmlns:ds", NamespaceXMLDSig)
			cert := x509.CreateElement("ds:X509Certificate")
			cert.SetText(base64.StdEncoding.EncodeToString(am.RecipientKeyInfo.X509Data.X509Certificate))
		}
	}
}

func (kdm *KeyDerivationMethod) appendTo(parent *etree.Element) {
	elem := parent.CreateElement("xenc11:KeyDerivationMethod")
	elem.CreateAttr("xmlns:xenc11", NamespaceXMLEnc11)
	elem.CreateAttr("Algorithm", kdm.Algorithm)

	if kdm.ConcatKDFParams != nil {
		params := elem.CreateElement("xenc11:ConcatKDFParams")
		if kdm.ConcatKDFParams.DigestMethod != "" {
			dm := params.CreateElement("ds:DigestMethod")
			dm.CreateAttr("xmlns:ds", NamespaceXMLDSig)
			dm.CreateAttr("Algorithm", kdm.ConcatKDFParams.DigestMethod)
		}
		// Add other params as needed
	}

	if kdm.HKDFParams != nil {
		params := elem.CreateElement("dsig-more:HKDFParams")
		params.CreateAttr("xmlns:dsig-more", NamespaceXMLDSigMore)
		if kdm.HKDFParams.PRF != "" {
			prf := params.CreateElement("dsig-more:PRF")
			prf.CreateAttr("Algorithm", kdm.HKDFParams.PRF)
		}
		if len(kdm.HKDFParams.Salt) > 0 {
			salt := params.CreateElement("dsig-more:Salt")
			// Salt can be specified or derived
			specified := salt.CreateElement("dsig-more:Specified")
			specified.SetText(base64.StdEncoding.EncodeToString(kdm.HKDFParams.Salt))
		}
		if len(kdm.HKDFParams.Info) > 0 {
			info := params.CreateElement("dsig-more:Info")
			info.SetText(base64.StdEncoding.EncodeToString(kdm.HKDFParams.Info))
		}
		if kdm.HKDFParams.KeyLength > 0 {
			kl := params.CreateElement("dsig-more:KeyLength")
			kl.SetText(fmt.Sprintf("%d", kdm.HKDFParams.KeyLength))
		}
	}
}

// ParseEncryptedData parses an xenc:EncryptedData element from an etree.Element
func ParseEncryptedData(elem *etree.Element) (*EncryptedData, error) {
	if elem == nil {
		return nil, fmt.Errorf("nil element")
	}

	ed := &EncryptedData{}
	ed.ID = elem.SelectAttrValue("Id", "")
	ed.Type = elem.SelectAttrValue("Type", "")
	ed.MimeType = elem.SelectAttrValue("MimeType", "")
	ed.Encoding = elem.SelectAttrValue("Encoding", "")

	// Parse EncryptionMethod
	if emElem := elem.FindElement("./EncryptionMethod"); emElem != nil {
		ed.EncryptionMethod = parseEncryptionMethod(emElem)
	}

	// Parse KeyInfo
	if kiElem := elem.FindElement("./KeyInfo"); kiElem != nil {
		var err error
		ed.KeyInfo, err = parseKeyInfo(kiElem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse KeyInfo: %w", err)
		}
	}

	// Parse CipherData
	if cdElem := elem.FindElement("./CipherData"); cdElem != nil {
		var err error
		ed.CipherData, err = parseCipherData(cdElem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CipherData: %w", err)
		}
	}

	return ed, nil
}

// ParseEncryptedKey parses an xenc:EncryptedKey element
func ParseEncryptedKey(elem *etree.Element) (*EncryptedKey, error) {
	if elem == nil {
		return nil, fmt.Errorf("nil element")
	}

	ek := &EncryptedKey{}
	ek.ID = elem.SelectAttrValue("Id", "")
	ek.Type = elem.SelectAttrValue("Type", "")
	ek.Recipient = elem.SelectAttrValue("Recipient", "")

	// Parse EncryptionMethod
	if emElem := elem.FindElement("./EncryptionMethod"); emElem != nil {
		ek.EncryptionMethod = parseEncryptionMethod(emElem)
	}

	// Parse KeyInfo
	if kiElem := elem.FindElement("./KeyInfo"); kiElem != nil {
		var err error
		ek.KeyInfo, err = parseKeyInfo(kiElem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse KeyInfo: %w", err)
		}
	}

	// Parse CipherData
	if cdElem := elem.FindElement("./CipherData"); cdElem != nil {
		var err error
		ek.CipherData, err = parseCipherData(cdElem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CipherData: %w", err)
		}
	}

	// Parse CarriedKeyName
	if cknElem := elem.FindElement("./CarriedKeyName"); cknElem != nil {
		ek.CarriedKeyName = cknElem.Text()
	}

	// Parse ReferenceList
	if rlElem := elem.FindElement("./ReferenceList"); rlElem != nil {
		for _, drElem := range rlElem.FindElements("./DataReference") {
			uri := drElem.SelectAttrValue("URI", "")
			if uri != "" {
				ek.ReferenceList = append(ek.ReferenceList, DataReference{URI: uri})
			}
		}
	}

	return ek, nil
}

func parseEncryptionMethod(elem *etree.Element) *EncryptionMethod {
	em := &EncryptionMethod{
		Algorithm: elem.SelectAttrValue("Algorithm", ""),
	}

	if ksElem := elem.FindElement("./KeySize"); ksElem != nil {
		fmt.Sscanf(ksElem.Text(), "%d", &em.KeySize)
	}
	if opElem := elem.FindElement("./OAEPparams"); opElem != nil {
		em.OAEPParams, _ = base64.StdEncoding.DecodeString(opElem.Text())
	}
	if dmElem := elem.FindElement("./DigestMethod"); dmElem != nil {
		em.DigestMethod = dmElem.SelectAttrValue("Algorithm", "")
	}
	if mgfElem := elem.FindElement("./MGF"); mgfElem != nil {
		em.MGFAlgorithm = mgfElem.SelectAttrValue("Algorithm", "")
	}

	return em
}

func parseCipherData(elem *etree.Element) (*CipherData, error) {
	cd := &CipherData{}

	if cvElem := elem.FindElement("./CipherValue"); cvElem != nil {
		var err error
		cd.CipherValue, err = base64.StdEncoding.DecodeString(cvElem.Text())
		if err != nil {
			return nil, fmt.Errorf("failed to decode CipherValue: %w", err)
		}
	} else if crElem := elem.FindElement("./CipherReference"); crElem != nil {
		cd.CipherReference = &CipherReference{
			URI: crElem.SelectAttrValue("URI", ""),
		}
	}

	return cd, nil
}

func parseKeyInfo(elem *etree.Element) (*KeyInfo, error) {
	ki := &KeyInfo{
		ID: elem.SelectAttrValue("Id", ""),
	}

	if knElem := elem.FindElement("./KeyName"); knElem != nil {
		ki.KeyName = knElem.Text()
	}

	if ekElem := elem.FindElement("./EncryptedKey"); ekElem != nil {
		var err error
		ki.EncryptedKey, err = ParseEncryptedKey(ekElem)
		if err != nil {
			return nil, err
		}
	}

	if x509Elem := elem.FindElement("./X509Data"); x509Elem != nil {
		if certElem := x509Elem.FindElement("./X509Certificate"); certElem != nil {
			cert, err := base64.StdEncoding.DecodeString(certElem.Text())
			if err != nil {
				return nil, fmt.Errorf("failed to decode X509Certificate: %w", err)
			}
			ki.X509Data = &X509Data{X509Certificate: cert}
		}
	}

	if amElem := elem.FindElement("./AgreementMethod"); amElem != nil {
		ki.AgreementMethod = parseAgreementMethod(amElem)
	}

	return ki, nil
}

func parseAgreementMethod(elem *etree.Element) *AgreementMethod {
	am := &AgreementMethod{
		Algorithm: elem.SelectAttrValue("Algorithm", ""),
	}

	if kanElem := elem.FindElement("./KA-Nonce"); kanElem != nil {
		am.KANonce, _ = base64.StdEncoding.DecodeString(kanElem.Text())
	}

	if kdmElem := elem.FindElement("./KeyDerivationMethod"); kdmElem != nil {
		am.KeyDerivationMethod = parseKeyDerivationMethod(kdmElem)
	}

	// Parse OriginatorKeyInfo (which contains KeyValue/ECKeyValue)
	if okiElem := elem.FindElement("./OriginatorKeyInfo"); okiElem != nil {
		am.OriginatorKeyInfo = &KeyInfo{}
		// Parse KeyValue with ECKeyValue
		if kvElem := okiElem.FindElement("./KeyValue"); kvElem != nil {
			am.OriginatorKeyInfo.KeyValue = &KeyValue{}
			if eckElem := kvElem.FindElement("./ECKeyValue"); eckElem != nil {
				am.OriginatorKeyInfo.KeyValue.ECKeyValue = &ECKeyValue{
					NamedCurve: eckElem.SelectAttrValue("NamedCurve", ""),
				}
				// Parse public key (dsig11:PublicKey)
				if pkElem := eckElem.FindElement("./PublicKey"); pkElem != nil {
					am.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey, _ = base64.StdEncoding.DecodeString(pkElem.Text())
				}
			}
		}
	}

	// Parse RecipientKeyInfo (similar structure)
	if rkiElem := elem.FindElement("./RecipientKeyInfo"); rkiElem != nil {
		am.RecipientKeyInfo = &KeyInfo{}
		if kvElem := rkiElem.FindElement("./KeyValue"); kvElem != nil {
			am.RecipientKeyInfo.KeyValue = &KeyValue{}
			if eckElem := kvElem.FindElement("./ECKeyValue"); eckElem != nil {
				am.RecipientKeyInfo.KeyValue.ECKeyValue = &ECKeyValue{
					NamedCurve: eckElem.SelectAttrValue("NamedCurve", ""),
				}
				if pkElem := eckElem.FindElement("./PublicKey"); pkElem != nil {
					am.RecipientKeyInfo.KeyValue.ECKeyValue.PublicKey, _ = base64.StdEncoding.DecodeString(pkElem.Text())
				}
			}
		}
	}

	return am
}

func parseKeyDerivationMethod(elem *etree.Element) *KeyDerivationMethod {
	kdm := &KeyDerivationMethod{
		Algorithm: elem.SelectAttrValue("Algorithm", ""),
	}

	// Parse ConcatKDFParams if present
	if paramsElem := elem.FindElement("./ConcatKDFParams"); paramsElem != nil {
		kdm.ConcatKDFParams = &ConcatKDFParams{}
		if dmElem := paramsElem.FindElement("./DigestMethod"); dmElem != nil {
			kdm.ConcatKDFParams.DigestMethod = dmElem.SelectAttrValue("Algorithm", "")
		}
	}

	// Parse HKDFParams if present
	if paramsElem := elem.FindElement("./HKDFParams"); paramsElem != nil {
		kdm.HKDFParams = &HKDFParams{}
		if prfElem := paramsElem.FindElement("./PRF"); prfElem != nil {
			kdm.HKDFParams.PRF = prfElem.SelectAttrValue("Algorithm", "")
		}
		if saltElem := paramsElem.FindElement("./Salt/Specified"); saltElem != nil {
			kdm.HKDFParams.Salt, _ = base64.StdEncoding.DecodeString(saltElem.Text())
		}
		if infoElem := paramsElem.FindElement("./Info"); infoElem != nil {
			kdm.HKDFParams.Info, _ = base64.StdEncoding.DecodeString(infoElem.Text())
		}
		if klElem := paramsElem.FindElement("./KeyLength"); klElem != nil {
			fmt.Sscanf(klElem.Text(), "%d", &kdm.HKDFParams.KeyLength)
		}
	}

	return kdm
}
