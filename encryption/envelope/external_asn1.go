// Package envelope — file external_asn1.go.
//
// Private ASN.1 structure definitions for RFC 5652 CMS EnvelopedData.
// These types are used by EncryptWithExternalWrap / DecryptWithExternalWrap
// to manually marshal a standards-conformant CMS EnvelopedData envelope
// around a DEK wrapped by an external service.
package envelope

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// OIDs from RFC 5652 / 5754 / PKCS#1.
var (
	oidPKCS7Data      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7Enveloped = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidRSAESOAEP      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidPSpecified     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9}
	oidSHA256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidAES256GCM      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

type issuerAndSerialASN1 struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// oaepParamsASN1 — RFC 8017 RSAES-OAEP-params.
type oaepParamsASN1 struct {
	HashFunc    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MaskGenFunc pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	PSourceFunc pkix.AlgorithmIdentifier `asn1:"explicit,tag:2"`
}

// gcmParamsASN1 — RFC 5084 GCMParameters.
type gcmParamsASN1 struct {
	Nonce  []byte
	ICVLen int `asn1:"optional,default:12"`
}

// keyTransRecipientInfoASN1 — RFC 5652 §6.2.1.
type keyTransRecipientInfoASN1 struct {
	Version                int
	RID                    issuerAndSerialASN1
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// encryptedContentInfoASN1 — RFC 5652 §6.1.
type encryptedContentInfoASN1 struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"optional,implicit,tag:0"`
}

// envelopedDataASN1 — RFC 5652 §6.1.
type envelopedDataASN1 struct {
	Version              int
	RecipientInfos       []keyTransRecipientInfoASN1 `asn1:"set"`
	EncryptedContentInfo encryptedContentInfoASN1
}

// contentInfoASN1 mirrors RFC 5652 ContentInfo (Envelope variant).
type contentInfoASN1 struct {
	ContentType asn1.ObjectIdentifier
	Content     envelopedDataASN1 `asn1:"explicit,tag:0"`
}
