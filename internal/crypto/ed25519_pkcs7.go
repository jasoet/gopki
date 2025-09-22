package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// RFC 8419: Edwards-Curve Digital Signature Algorithm (EdDSA) Signatures in CMS
// https://tools.ietf.org/rfc/rfc8419.txt

// Ed25519 OIDs as defined in RFC 8419
var (
	// OID for Ed25519 signature algorithm
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

	// OID for SHA-512 digest algorithm (though Ed25519 doesn't use traditional hashing)
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// OID for PKCS#7 signedData
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// OID for PKCS#7 data
	oidData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// algorithmIdentifier represents an algorithm identifier
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// issuerAndSerialNumber represents the IssuerAndSerialNumber structure
type issuerAndSerialNumber struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// signerInfo represents a SignerInfo structure
type signerInfo struct {
	Version                   int
	Sid                       issuerAndSerialNumber
	DigestAlgorithm           algorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm algorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

// attribute represents an Attribute
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// signedData represents the SignedData structure
type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	ContentInfo      contentInfo
	Certificates     []asn1.RawValue `asn1:"optional,tag:0"`
	Crls             []asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo    `asn1:"set"`
}

// contentInfo represents the ContentInfo structure
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// CreateEd25519PKCS7Signature creates a PKCS#7 signature for Ed25519
func CreateEd25519PKCS7Signature(data []byte, privateKey ed25519.PrivateKey, certificate *x509.Certificate, detached bool) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	if certificate == nil {
		return nil, fmt.Errorf("certificate is required for PKCS#7 signatures")
	}

	// Sign the data with Ed25519
	signature := ed25519.Sign(privateKey, data)
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid Ed25519 signature size: expected %d, got %d", ed25519.SignatureSize, len(signature))
	}

	// Create digest algorithm identifier (Ed25519 doesn't use separate hashing, but PKCS#7 requires it)
	digestAlg := algorithmIdentifier{
		Algorithm: oidSHA512, // Use SHA-512 as placeholder per RFC 8419 recommendations
	}

	// Create signature algorithm identifier
	sigAlg := algorithmIdentifier{
		Algorithm: oidEd25519,
	}

	// Create issuer and serial number
	issuerAndSerial := issuerAndSerialNumber{
		IssuerName:   asn1.RawValue{FullBytes: certificate.RawIssuer},
		SerialNumber: certificate.SerialNumber,
	}

	// Create signer info
	signer := signerInfo{
		Version:                   1, // PKCS#7 version 1
		Sid:                       issuerAndSerial,
		DigestAlgorithm:           digestAlg,
		DigestEncryptionAlgorithm: sigAlg,
		EncryptedDigest:           signature, // Ed25519 signature goes here
	}

	// Create content info
	var ci contentInfo
	if detached {
		// For detached signatures, don't include the content
		ci = contentInfo{
			ContentType: oidData,
		}
	} else {
		// For attached signatures, include the content
		// Wrap data in OCTET STRING for PKCS#7 data content
		contentData, err := asn1.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal content: %w", err)
		}
		ci = contentInfo{
			ContentType: oidData,
			Content:     asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: contentData},
		}
	}

	// Include certificate in the PKCS#7 structure
	certRaw := asn1.RawValue{FullBytes: certificate.Raw}

	// Create signed data
	sd := signedData{
		Version:          1, // PKCS#7 version 1
		DigestAlgorithms: []algorithmIdentifier{digestAlg},
		ContentInfo:      ci,
		Certificates:     []asn1.RawValue{certRaw},
		SignerInfos:      []signerInfo{signer},
	}

	// Marshal signed data
	signedDataBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed data: %w", err)
	}

	// Create final content info wrapper with proper explicit tag
	// The Content field needs to be properly wrapped as explicit tag 0
	finalContentInfo := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: signedDataBytes},
	}

	// Marshal final PKCS#7 structure
	pkcs7Bytes, err := asn1.Marshal(finalContentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKCS#7 structure: %w", err)
	}

	return pkcs7Bytes, nil
}

// VerifyEd25519PKCS7Signature verifies an Ed25519 PKCS#7 signature
func VerifyEd25519PKCS7Signature(data []byte, pkcs7Data []byte) (*Ed25519PKCS7Info, error) {
	// Parse the PKCS#7 structure
	var ci contentInfo
	rest, err := asn1.Unmarshal(pkcs7Data, &ci)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#7 content info: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after PKCS#7 content info")
	}

	// Verify this is signed data
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("not a signed data PKCS#7 structure")
	}

	// Parse signed data - the content is wrapped in explicit tag, so use Bytes
	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed data: %w", err)
	}

	// Verify we have exactly one signer
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("expected exactly one signer, got %d", len(sd.SignerInfos))
	}

	signer := sd.SignerInfos[0]

	// Verify this is Ed25519
	if !signer.DigestEncryptionAlgorithm.Algorithm.Equal(oidEd25519) {
		return nil, fmt.Errorf("not an Ed25519 signature")
	}

	// Verify signature size
	if len(signer.EncryptedDigest) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid Ed25519 signature size: expected %d, got %d",
			ed25519.SignatureSize, len(signer.EncryptedDigest))
	}

	// Extract certificate
	if len(sd.Certificates) != 1 {
		return nil, fmt.Errorf("expected exactly one certificate, got %d", len(sd.Certificates))
	}

	cert, err := x509.ParseCertificate(sd.Certificates[0].FullBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify certificate has Ed25519 public key
	ed25519PubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain Ed25519 public key")
	}

	// Verify the signature
	if !ed25519.Verify(ed25519PubKey, data, signer.EncryptedDigest) {
		return nil, fmt.Errorf("Ed25519 signature verification failed")
	}

	// Return verification info
	info := &Ed25519PKCS7Info{
		Certificate: cert,
		Signature:   signer.EncryptedDigest,
		Verified:    true,
		SignedAt:    time.Now(), // PKCS#7 doesn't include timestamp by default
	}

	return info, nil
}

// Ed25519PKCS7Info contains information about a verified Ed25519 PKCS#7 signature
type Ed25519PKCS7Info struct {
	Certificate *x509.Certificate
	Signature   []byte
	Verified    bool
	SignedAt    time.Time
}

// IsEd25519PKCS7 checks if the given PKCS#7 data contains an Ed25519 signature
func IsEd25519PKCS7(pkcs7Data []byte) (bool, error) {
	var ci contentInfo
	_, err := asn1.Unmarshal(pkcs7Data, &ci)
	if err != nil {
		return false, fmt.Errorf("failed to parse PKCS#7 content info: %w", err)
	}

	if !ci.ContentType.Equal(oidSignedData) {
		return false, nil
	}

	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return false, fmt.Errorf("failed to parse signed data: %w", err)
	}

	// Check if any signer uses Ed25519
	for _, signer := range sd.SignerInfos {
		if signer.DigestEncryptionAlgorithm.Algorithm.Equal(oidEd25519) {
			return true, nil
		}
	}

	return false, nil
}

// ValidateEd25519PKCS7Structure validates the structure of an Ed25519 PKCS#7 signature without verifying the signature
func ValidateEd25519PKCS7Structure(pkcs7Data []byte) error {
	isEd25519, err := IsEd25519PKCS7(pkcs7Data)
	if err != nil {
		return fmt.Errorf("failed to check PKCS#7 type: %w", err)
	}

	if !isEd25519 {
		return fmt.Errorf("not an Ed25519 PKCS#7 signature")
	}

	// Parse and validate structure
	var ci contentInfo
	_, err = asn1.Unmarshal(pkcs7Data, &ci)
	if err != nil {
		return fmt.Errorf("failed to parse PKCS#7 content info: %w", err)
	}

	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return fmt.Errorf("failed to parse signed data: %w", err)
	}

	// Basic structure validation
	if len(sd.SignerInfos) == 0 {
		return fmt.Errorf("no signers found")
	}

	if len(sd.Certificates) == 0 {
		return fmt.Errorf("no certificates found")
	}

	// Validate Ed25519 signer
	for _, signer := range sd.SignerInfos {
		if signer.DigestEncryptionAlgorithm.Algorithm.Equal(oidEd25519) {
			if len(signer.EncryptedDigest) != ed25519.SignatureSize {
				return fmt.Errorf("invalid Ed25519 signature size: expected %d, got %d",
					ed25519.SignatureSize, len(signer.EncryptedDigest))
			}
		}
	}

	return nil
}
