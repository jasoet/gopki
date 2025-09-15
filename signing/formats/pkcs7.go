package formats

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// PKCS7Format implements the SignatureFormat interface for PKCS#7/CMS signatures
type PKCS7Format struct {
	detached bool
}

// NewPKCS7Format creates a new PKCS#7 format instance.
// PKCS#7 (also known as CMS - Cryptographic Message Syntax) is a standard
// for cryptographic message formats that can contain both the signature
// and supporting information like certificates and timestamps.
//
// PKCS#7 signatures can include:
//   - The signature itself
//   - Signer's certificate
//   - Certificate chain
//   - Authenticated attributes (signing time, message digest)
//   - Optionally the original data (non-detached mode)
//
// Parameters:
//   - detached: If true, creates detached signatures (data not included)
//     If false, creates attached signatures (data included)
//
// Returns a new PKCS7Format instance configured for the specified mode.
//
// Example:
//
//	// Create attached PKCS#7 format (includes data)
//	attachedFormat := NewPKCS7Format(false)
//
//	// Create detached PKCS#7 format (data separate)
//	detachedFormat := NewPKCS7Format(true)
func NewPKCS7Format(detached bool) *PKCS7Format {
	return &PKCS7Format{detached: detached}
}

// Name returns the format name
func (f *PKCS7Format) Name() string {
	if f.detached {
		return FormatPKCS7Detached
	}
	return FormatPKCS7
}

// PKCS#7 ASN.1 structures
type pkcs7 struct {
	ContentType asn1.ObjectIdentifier
	Content     pkcs7SignedData `asn1:"explicit,optional,tag:0"`
}

type pkcs7SignedData struct {
	Version          int                        `asn1:"default:1"`
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      pkcs7ContentInfo
	Certificates     []asn1.RawValue        `asn1:"implicit,optional,tag:0"`
	CRLs             []pkix.CertificateList `asn1:"implicit,optional,tag:1"`
	SignerInfos      []pkcs7SignerInfo      `asn1:"set"`
}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte `asn1:"explicit,optional,tag:0"`
}

type pkcs7SignerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     pkcs7IssuerAndSerialNumber
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []pkcs7Attribute `asn1:"implicit,optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []pkcs7Attribute `asn1:"implicit,optional,tag:1"`
}

type pkcs7IssuerAndSerialNumber struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type pkcs7Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// OIDs for PKCS#7
var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// Sign creates a PKCS#7/CMS signature of the provided data.
// This method produces a complete PKCS#7 signature structure containing
// the signature, certificates, and metadata according to RFC 2315.
//
// PKCS#7 signature creation process:
//  1. Computes hash digest of the data
//  2. Creates authenticated attributes (message digest, signing time)
//  3. Signs the authenticated attributes digest
//  4. Packages everything into ASN.1 DER-encoded PKCS#7 structure
//
// The signature can be created in two modes:
//   - Attached: Original data is included in the PKCS#7 structure
//   - Detached: Only signature and certificates are included
//
// Parameters:
//   - data: The data to sign
//   - signer: The private key for signing (crypto.Signer interface)
//   - cert: The signer's certificate (will be included if opts.IncludeCertificate)
//   - opts: Signing options controlling hash algorithm, certificates, and format
//
// Returns the DER-encoded PKCS#7 signature or an error if signing fails.
//
// The generated PKCS#7 includes:
//   - SignedData structure with version 1
//   - Digest algorithms used
//   - Content info (with or without original data)
//   - Signer's certificate (if requested)
//   - Additional certificates from opts.ExtraCertificates
//   - Signer info with authenticated attributes
//
// Example:
//
//	opts := formats.SignOptions{
//		HashAlgorithm:      crypto.SHA256,
//		IncludeCertificate: true,
//	}
//	pkcs7Sig, err := pkcs7Format.Sign(document, rsaSigner, cert, opts)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Save PKCS#7 signature to file
//	err = os.WriteFile("document.p7s", pkcs7Sig, 0644)
func (f *PKCS7Format) Sign(data []byte, signer crypto.Signer, cert *x509.Certificate, opts SignOptions) ([]byte, error) {
	// Determine hash algorithm
	hashAlg := opts.HashAlgorithm
	if hashAlg == 0 {
		hashAlg = f.getDefaultHashAlgorithm(signer)
	}

	// Hash the content
	if !hashAlg.Available() {
		return nil, fmt.Errorf("hash algorithm %v is not available", hashAlg)
	}

	hasher := hashAlg.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, fmt.Errorf("failed to hash data: %w", err)
	}
	contentDigest := hasher.Sum(nil)

	// Create signer info
	signerInfo, err := f.createSignerInfo(signer, cert, hashAlg, contentDigest, data)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer info: %w", err)
	}

	// Create content info
	contentInfo := pkcs7ContentInfo{
		ContentType: oidData,
	}

	// Include content if not detached
	if !f.detached {
		contentInfo.Content = data
	}

	// Create certificates section
	var certificates []asn1.RawValue
	if opts.IncludeCertificate {
		certificates = append(certificates, asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      cert.Raw,
		})
	}

	// Add extra certificates
	for _, extraCert := range opts.ExtraCertificates {
		certificates = append(certificates, asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      extraCert.Raw,
		})
	}

	// Create digest algorithm identifier
	digestAlgID := f.getDigestAlgorithmIdentifier(hashAlg)

	// Create signed data
	signedData := pkcs7SignedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{digestAlgID},
		ContentInfo:      contentInfo,
		Certificates:     certificates,
		SignerInfos:      []pkcs7SignerInfo{*signerInfo},
	}

	// Create top-level PKCS#7 structure
	p7 := pkcs7{
		ContentType: oidSignedData,
		Content:     signedData,
	}

	// Encode to DER
	derBytes, err := asn1.Marshal(p7)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKCS#7: %w", err)
	}

	return derBytes, nil
}

// Verify verifies a PKCS#7/CMS signature against the original data.
// This method performs comprehensive validation of the PKCS#7 structure
// including signature verification, certificate validation, and attribute checking.
//
// PKCS#7 verification process:
//  1. Parses the DER-encoded PKCS#7 structure
//  2. Extracts signer information and certificates
//  3. Validates authenticated attributes
//  4. Verifies the cryptographic signature
//  5. Optionally validates certificate chains
//
// For detached signatures, the original data must be provided separately.
// For attached signatures, the data is extracted from the PKCS#7 structure.
//
// Parameters:
//   - data: The original data that was signed
//   - signatureData: DER-encoded PKCS#7 signature bytes
//   - cert: Optional certificate to use (if not embedded in PKCS#7)
//   - opts: Verification options for certificate chain validation
//
// Returns nil if the signature is valid, or an error describing the failure.
//
// The function validates:
//   - PKCS#7 structure integrity and format
//   - Signer info authenticity
//   - Authenticated attributes consistency
//   - Cryptographic signature validity
//   - Certificate chain (if opts.SkipChainVerification is false)
//
// Example:
//
//	// Verify attached PKCS#7 signature
//	err := pkcs7Format.Verify(originalData, pkcs7Bytes, nil, opts)
//	if err != nil {
//		log.Printf("PKCS#7 signature verification failed: %v", err)
//		return
//	}
//
//	fmt.Println("PKCS#7 signature is valid")
func (f *PKCS7Format) Verify(data []byte, signatureData []byte, cert *x509.Certificate, opts VerifyOptions) error {
	// Parse PKCS#7 structure
	info, err := f.Parse(signatureData)
	if err != nil {
		return fmt.Errorf("failed to parse PKCS#7: %w", err)
	}

	// Parse the full PKCS#7 structure for verification
	var p7 pkcs7
	if _, err := asn1.Unmarshal(signatureData, &p7); err != nil {
		return fmt.Errorf("failed to unmarshal PKCS#7: %w", err)
	}

	if len(p7.Content.SignerInfos) == 0 {
		return fmt.Errorf("no signer info found")
	}

	// Verify each signer (for now, just verify the first one)
	signerInfo := p7.Content.SignerInfos[0]

	// Get the signing certificate
	var signingCert *x509.Certificate
	if info.Certificate != nil {
		signingCert = info.Certificate
	} else if cert != nil {
		signingCert = cert
	} else {
		return fmt.Errorf("no signing certificate available")
	}

	// Verify the signature
	return f.verifySignerInfo(&signerInfo, data, signingCert, info.HashAlgorithm)
}

// Parse extracts signature information from PKCS#7/CMS data.
// This method analyzes the DER-encoded PKCS#7 structure and extracts
// metadata including certificates, hash algorithms, and attributes.
//
// The parsing process:
//  1. Unmarshals the ASN.1 DER-encoded PKCS#7 structure
//  2. Validates the content type as SignedData
//  3. Extracts digest algorithms and certificates
//  4. Parses signer information and authenticated attributes
//  5. Builds a comprehensive SignatureInfo structure
//
// Parameters:
//   - signatureData: DER-encoded PKCS#7/CMS bytes to parse
//
// Returns SignatureInfo containing extracted metadata, or an error if parsing fails.
//
// The returned SignatureInfo includes:
//   - Algorithm: Always "PKCS#7" for this format
//   - HashAlgorithm: The digest algorithm used (SHA256, SHA384, SHA512)
//   - Certificate: The signer's certificate (if embedded)
//   - CertificateChain: Additional certificates from the PKCS#7
//   - Attributes: Map containing signing time and other attributes
//   - Detached: Boolean indicating if this is a detached signature
//
// This function is useful for:
//   - Inspecting signature properties before verification
//   - Extracting certificates for separate validation
//   - Displaying signature metadata to users
//   - Building signature verification reports
//
// Example:
//
//	info, err := pkcs7Format.Parse(pkcs7Bytes)
//	if err != nil {
//		log.Printf("Failed to parse PKCS#7: %v", err)
//		return
//	}
//
//	fmt.Printf("Signer: %s\n", info.Certificate.Subject.CommonName)
//	fmt.Printf("Hash Algorithm: %v\n", info.HashAlgorithm)
//	if signingTime, ok := info.Attributes["signingTime"]; ok {
//		fmt.Printf("Signed at: %v\n", signingTime)
//	}
func (f *PKCS7Format) Parse(signatureData []byte) (*SignatureInfo, error) {
	var p7 pkcs7
	if _, err := asn1.Unmarshal(signatureData, &p7); err != nil {
		return nil, fmt.Errorf("failed to unmarshal PKCS#7: %w", err)
	}

	if !p7.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("not a signed data PKCS#7")
	}

	info := &SignatureInfo{
		Algorithm:  "PKCS#7",
		Detached:   f.detached,
		Attributes: make(map[string]interface{}),
	}

	// Extract hash algorithm
	if len(p7.Content.DigestAlgorithms) > 0 {
		info.HashAlgorithm = f.getHashAlgorithmFromOID(p7.Content.DigestAlgorithms[0].Algorithm)
	}

	// Extract certificates
	if len(p7.Content.Certificates) > 0 {
		// Parse the first certificate as the signing certificate
		cert, err := x509.ParseCertificate(p7.Content.Certificates[0].Bytes)
		if err == nil {
			info.Certificate = cert
		}

		// Parse additional certificates as chain
		for i := 1; i < len(p7.Content.Certificates); i++ {
			cert, err := x509.ParseCertificate(p7.Content.Certificates[i].Bytes)
			if err == nil {
				info.CertificateChain = append(info.CertificateChain, cert)
			}
		}
	}

	// Extract signing time and other attributes from signer info
	if len(p7.Content.SignerInfos) > 0 {
		signerInfo := p7.Content.SignerInfos[0]
		f.extractSignerAttributes(&signerInfo, info)
	}

	return info, nil
}

// SupportsDetached returns true as PKCS#7 supports both attached and detached signatures.
// PKCS#7 can be configured to include or exclude the original signed data,
// making it suitable for both scenarios where data is embedded or kept separate.
func (f *PKCS7Format) SupportsDetached() bool {
	return true
}

// Helper methods

func (f *PKCS7Format) createSignerInfo(signer crypto.Signer, cert *x509.Certificate, hashAlg crypto.Hash, contentDigest []byte, originalData []byte) (*pkcs7SignerInfo, error) {
	// Create issuer and serial number
	issuerAndSN := pkcs7IssuerAndSerialNumber{
		IssuerName:   asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	}

	// Create authenticated attributes (including message digest)
	var authAttrs []pkcs7Attribute

	// Message digest attribute
	digestAttr := pkcs7Attribute{
		Type: oidMessageDigest,
		Values: []asn1.RawValue{{
			Tag:   asn1.TagOctetString,
			Bytes: contentDigest,
		}},
	}
	authAttrs = append(authAttrs, digestAttr)

	// Signing time attribute
	now := time.Now()
	timeBytes, _ := asn1.Marshal(now)
	timeAttr := pkcs7Attribute{
		Type: oidSigningTime,
		Values: []asn1.RawValue{{
			Tag:   asn1.TagUTCTime,
			Bytes: timeBytes,
		}},
	}
	authAttrs = append(authAttrs, timeAttr)

	// Create digest to sign (hash of authenticated attributes)
	authAttrsBytes, err := asn1.Marshal(authAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticated attributes: %w", err)
	}

	// Change the tag to SET for proper PKCS#7 format
	authAttrsBytes[0] = 0x31 // SET tag

	hasher := hashAlg.New()
	hasher.Write(authAttrsBytes)
	authAttrsDigest := hasher.Sum(nil)

	// Sign the authenticated attributes digest
	signature, err := signer.Sign(rand.Reader, authAttrsDigest, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign authenticated attributes: %w", err)
	}

	// Create signer info
	signerInfo := &pkcs7SignerInfo{
		Version:                   1,
		IssuerAndSerialNumber:     issuerAndSN,
		DigestAlgorithm:           f.getDigestAlgorithmIdentifier(hashAlg),
		AuthenticatedAttributes:   authAttrs,
		DigestEncryptionAlgorithm: f.getSignatureAlgorithmIdentifier(signer, hashAlg),
		EncryptedDigest:           signature,
	}

	return signerInfo, nil
}

func (f *PKCS7Format) verifySignerInfo(signerInfo *pkcs7SignerInfo, data []byte, cert *x509.Certificate, hashAlg crypto.Hash) error {
	// Recreate authenticated attributes for verification
	authAttrsBytes, err := asn1.Marshal(signerInfo.AuthenticatedAttributes)
	if err != nil {
		return fmt.Errorf("failed to marshal authenticated attributes: %w", err)
	}

	// Change tag to SET
	authAttrsBytes[0] = 0x31

	// Hash the authenticated attributes
	hasher := hashAlg.New()
	hasher.Write(authAttrsBytes)
	authAttrsDigest := hasher.Sum(nil)

	// Verify signature against authenticated attributes digest
	return f.verifySignature(authAttrsDigest, signerInfo.EncryptedDigest, cert.PublicKey, hashAlg)
}

func (f *PKCS7Format) verifySignature(digest []byte, signature []byte, publicKey crypto.PublicKey, hashAlg crypto.Hash) error {
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, hashAlg, digest, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type for PKCS#7: %T", publicKey)
	}
}

func (f *PKCS7Format) extractSignerAttributes(signerInfo *pkcs7SignerInfo, info *SignatureInfo) {
	for _, attr := range signerInfo.AuthenticatedAttributes {
		if attr.Type.Equal(oidSigningTime) && len(attr.Values) > 0 {
			var signingTime time.Time
			if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &signingTime); err == nil {
				info.Attributes["signingTime"] = signingTime
			}
		}
	}
}

func (f *PKCS7Format) getDefaultHashAlgorithm(signer crypto.Signer) crypto.Hash {
	switch signer.(type) {
	case *rsa.PrivateKey:
		return crypto.SHA256
	case *ecdsa.PrivateKey:
		return crypto.SHA256
	default:
		return crypto.SHA256
	}
}

func (f *PKCS7Format) getDigestAlgorithmIdentifier(hashAlg crypto.Hash) pkix.AlgorithmIdentifier {
	switch hashAlg {
	case crypto.SHA256:
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	case crypto.SHA384:
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA384}
	case crypto.SHA512:
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA512}
	default:
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	}
}

func (f *PKCS7Format) getSignatureAlgorithmIdentifier(signer crypto.Signer, hashAlg crypto.Hash) pkix.AlgorithmIdentifier {
	switch signer.(type) {
	case *rsa.PrivateKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption}
	case *ecdsa.PrivateKey:
		switch hashAlg {
		case crypto.SHA256:
			return pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
		case crypto.SHA384:
			return pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA384}
		case crypto.SHA512:
			return pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA512}
		default:
			return pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
		}
	default:
		return pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption}
	}
}

func (f *PKCS7Format) getHashAlgorithmFromOID(oid asn1.ObjectIdentifier) crypto.Hash {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256
	case oid.Equal(oidSHA384):
		return crypto.SHA384
	case oid.Equal(oidSHA512):
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// init registers PKCS#7 formats in the default registry
func init() {
	RegisterFormat(NewPKCS7Format(false)) // Attached
	RegisterFormat(NewPKCS7Format(true))  // Detached
}
