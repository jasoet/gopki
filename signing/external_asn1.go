// Package signing — file external_asn1.go.
//
// Private ASN.1 structure definitions for PKCS#7 SignedData (RFC 5652 / RFC 2315).
// These types are used by SignDocumentWithExternalSigner to manually marshal a
// PKCS#7 SignedData envelope around a signature produced by an external signer.
package signing

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// OIDs from RFC 5652 / PKCS#9.
var (
	oidPKCS7Data       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// attributeASN1 mirrors PKCS#9 Attribute.
//
//	Attribute ::= SEQUENCE { type OBJECT IDENTIFIER, values SET OF ANY }
type attributeASN1 struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// issuerAndSerialASN1 mirrors PKCS#7 IssuerAndSerialNumber.
type issuerAndSerialASN1 struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// signerInfoASN1 mirrors RFC 5652 SignerInfo.
//
//	SignerInfo ::= SEQUENCE {
//	  version          INTEGER,
//	  sid              IssuerAndSerialNumber,
//	  digestAlgorithm  AlgorithmIdentifier,
//	  signedAttrs      [0] IMPLICIT SET OF Attribute OPTIONAL,
//	  signatureAlgorithm AlgorithmIdentifier,
//	  signature        OCTET STRING,
//	  unsignedAttrs    [1] IMPLICIT SET OF Attribute OPTIONAL
//	}
type signerInfoASN1 struct {
	Version                   int
	IssuerAndSerial           issuerAndSerialASN1
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attributeASN1 `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attributeASN1 `asn1:"optional,tag:1"`
}

// encapsulatedContentInfoASN1 — detached form has Content omitted.
type encapsulatedContentInfoASN1 struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// signedDataASN1 mirrors RFC 5652 SignedData.
type signedDataASN1 struct {
	Version                    int
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo           encapsulatedContentInfoASN1
	Certificates               asn1.RawValue    `asn1:"optional,tag:0"`
	SignerInfos                []signerInfoASN1 `asn1:"set"`
}

// contentInfoASN1 mirrors RFC 5652 ContentInfo.
type contentInfoASN1 struct {
	ContentType asn1.ObjectIdentifier
	Content     signedDataASN1 `asn1:"explicit,tag:0"`
}
