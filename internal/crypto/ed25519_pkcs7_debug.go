package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

// DebugCreateEd25519PKCS7Signature creates a debuggable Ed25519 PKCS#7 signature
func DebugCreateEd25519PKCS7Signature(data []byte, privateKey ed25519.PrivateKey, certificate *x509.Certificate, detached bool) ([]byte, error) {
	fmt.Printf("🐛 DEBUG: Starting Ed25519 PKCS#7 creation\n")
	fmt.Printf("   Data length: %d bytes\n", len(data))
	fmt.Printf("   Private key length: %d bytes\n", len(privateKey))
	fmt.Printf("   Detached: %v\n", detached)

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	if certificate == nil {
		return nil, fmt.Errorf("certificate is required for PKCS#7 signatures")
	}

	// Sign the data with Ed25519
	fmt.Printf("🐛 DEBUG: Creating Ed25519 signature\n")
	signature := ed25519.Sign(privateKey, data)
	fmt.Printf("   Signature length: %d bytes\n", len(signature))
	fmt.Printf("   Signature hex: %s\n", hex.EncodeToString(signature[:32])+"...")

	// RFC 8419: For Ed25519, no separate hashing is needed
	// The digest algorithm in SignerInfo should be absent or set to a placeholder
	fmt.Printf("🐛 DEBUG: Creating algorithm identifiers\n")

	// According to RFC 8419, for Ed25519, the digestAlgorithm can be omitted
	// or set to id-sha512 as a placeholder
	digestAlg := algorithmIdentifier{
		Algorithm: oidSHA512, // RFC 8419 recommends this as placeholder
	}

	// Ed25519 signature algorithm
	sigAlg := algorithmIdentifier{
		Algorithm: oidEd25519,
		// Ed25519 has no parameters - they should be absent
	}

	fmt.Printf("   DigestAlg OID: %v\n", digestAlg.Algorithm)
	fmt.Printf("   SignatureAlg OID: %v\n", sigAlg.Algorithm)

	// Create issuer and serial number
	fmt.Printf("🐛 DEBUG: Creating issuer and serial number\n")
	fmt.Printf("   Certificate subject: %s\n", certificate.Subject)
	fmt.Printf("   Certificate serial: %v\n", certificate.SerialNumber)
	fmt.Printf("   RawIssuer length: %d bytes\n", len(certificate.RawIssuer))

	issuerAndSerial := issuerAndSerialNumber{
		IssuerName:   asn1.RawValue{FullBytes: certificate.RawIssuer},
		SerialNumber: certificate.SerialNumber,
	}

	// Test marshal issuerAndSerial
	issuerBytes, err := asn1.Marshal(issuerAndSerial)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuerAndSerialNumber: %w", err)
	}
	fmt.Printf("   IssuerAndSerial marshaled: %d bytes\n", len(issuerBytes))

	// Create signer info
	fmt.Printf("🐛 DEBUG: Creating signer info\n")
	signer := signerInfo{
		Version:                   1, // PKCS#7 version 1
		Sid:                       issuerAndSerial,
		DigestAlgorithm:           digestAlg,
		DigestEncryptionAlgorithm: sigAlg,
		EncryptedDigest:           signature,
		// No authenticated attributes for Ed25519
	}

	// Test marshal signerInfo
	signerBytes, err := asn1.Marshal(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signerInfo: %w", err)
	}
	fmt.Printf("   SignerInfo marshaled: %d bytes\n", len(signerBytes))

	// Create content info
	fmt.Printf("🐛 DEBUG: Creating content info\n")
	var ci contentInfo
	if detached {
		// For detached signatures, content is omitted
		ci = contentInfo{
			ContentType: oidData,
			// Content field is omitted for detached
		}
	} else {
		// For attached signatures, include the content as OCTET STRING
		contentData, err := asn1.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal content data: %w", err)
		}
		fmt.Printf("   Content data marshaled: %d bytes\n", len(contentData))

		ci = contentInfo{
			ContentType: oidData,
			Content:     asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: contentData},
		}
	}

	// Test marshal contentInfo
	ciBytes, err := asn1.Marshal(ci)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal contentInfo: %w", err)
	}
	fmt.Printf("   ContentInfo marshaled: %d bytes\n", len(ciBytes))

	// Include certificate in the PKCS#7 structure
	fmt.Printf("🐛 DEBUG: Including certificate\n")
	fmt.Printf("   Certificate length: %d bytes\n", len(certificate.Raw))
	certRaw := asn1.RawValue{FullBytes: certificate.Raw}

	// Create signed data
	fmt.Printf("🐛 DEBUG: Creating signed data structure\n")
	sd := signedData{
		Version:          1, // PKCS#7 version 1
		DigestAlgorithms: []algorithmIdentifier{digestAlg},
		ContentInfo:      ci,
		Certificates:     []asn1.RawValue{certRaw},
		SignerInfos:      []signerInfo{signer},
		// CRLs are omitted
	}

	// Test marshal signedData - this is where the error likely occurs
	fmt.Printf("🐛 DEBUG: Marshaling signed data structure\n")
	signedDataBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed data: %w", err)
	}
	fmt.Printf("   SignedData marshaled: %d bytes\n", len(signedDataBytes))
	fmt.Printf("   SignedData hex (first 64 bytes): %s\n", hex.EncodeToString(signedDataBytes[:min(64, len(signedDataBytes))]))

	// Create final content info wrapper
	fmt.Printf("🐛 DEBUG: Creating final PKCS#7 wrapper\n")
	finalContentInfo := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: signedDataBytes},
	}

	// Marshal final PKCS#7 structure
	fmt.Printf("🐛 DEBUG: Marshaling final PKCS#7 structure\n")
	pkcs7Bytes, err := asn1.Marshal(finalContentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal final PKCS#7 structure: %w", err)
	}

	fmt.Printf("🐛 DEBUG: PKCS#7 creation successful!\n")
	fmt.Printf("   Final PKCS#7 length: %d bytes\n", len(pkcs7Bytes))
	fmt.Printf("   Final PKCS#7 hex (first 64 bytes): %s\n", hex.EncodeToString(pkcs7Bytes[:min(64, len(pkcs7Bytes))]))

	return pkcs7Bytes, nil
}

// DebugVerifyEd25519PKCS7Signature verifies with detailed debugging
func DebugVerifyEd25519PKCS7Signature(data []byte, pkcs7Data []byte) (*Ed25519PKCS7Info, error) {
	fmt.Printf("🐛 DEBUG: Starting Ed25519 PKCS#7 verification\n")
	fmt.Printf("   Data length: %d bytes\n", len(data))
	fmt.Printf("   PKCS#7 length: %d bytes\n", len(pkcs7Data))
	fmt.Printf("   PKCS#7 hex (first 64 bytes): %s\n", hex.EncodeToString(pkcs7Data[:min(64, len(pkcs7Data))]))

	// Parse the PKCS#7 structure
	fmt.Printf("🐛 DEBUG: Parsing outer contentInfo\n")
	var ci contentInfo
	rest, err := asn1.Unmarshal(pkcs7Data, &ci)
	if err != nil {
		fmt.Printf("   ERROR: Failed to parse outer contentInfo: %v\n", err)
		return nil, fmt.Errorf("failed to parse PKCS#7 content info: %w", err)
	}
	if len(rest) != 0 {
		fmt.Printf("   WARNING: %d bytes of trailing data\n", len(rest))
		return nil, fmt.Errorf("trailing data after PKCS#7 content info")
	}
	fmt.Printf("   ContentType: %v\n", ci.ContentType)
	fmt.Printf("   Content length: %d bytes\n", len(ci.Content.FullBytes))

	// Verify this is signed data
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("not a signed data PKCS#7 structure, got OID: %v", ci.ContentType)
	}

	// Parse signed data - the content is wrapped in explicit tag, so use Bytes
	fmt.Printf("🐛 DEBUG: Parsing signedData structure\n")
	var sd signedData
	rest, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		fmt.Printf("   ERROR: Failed to parse signedData: %v\n", err)
		fmt.Printf("   SignedData hex (first 128 bytes): %s\n", hex.EncodeToString(ci.Content.Bytes[:min(128, len(ci.Content.Bytes))]))
		return nil, fmt.Errorf("failed to parse signed data: %w", err)
	}
	fmt.Printf("   SignedData version: %d\n", sd.Version)
	fmt.Printf("   DigestAlgorithms count: %d\n", len(sd.DigestAlgorithms))
	fmt.Printf("   Certificates count: %d\n", len(sd.Certificates))
	fmt.Printf("   SignerInfos count: %d\n", len(sd.SignerInfos))

	// Verify we have exactly one signer
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("expected exactly one signer, got %d", len(sd.SignerInfos))
	}

	signer := sd.SignerInfos[0]
	fmt.Printf("🐛 DEBUG: Analyzing signer info\n")
	fmt.Printf("   Signer version: %d\n", signer.Version)
	fmt.Printf("   DigestAlgorithm: %v\n", signer.DigestAlgorithm.Algorithm)
	fmt.Printf("   SignatureAlgorithm: %v\n", signer.DigestEncryptionAlgorithm.Algorithm)
	fmt.Printf("   Signature length: %d bytes\n", len(signer.EncryptedDigest))

	// Verify this is Ed25519
	if !signer.DigestEncryptionAlgorithm.Algorithm.Equal(oidEd25519) {
		return nil, fmt.Errorf("not an Ed25519 signature, got OID: %v", signer.DigestEncryptionAlgorithm.Algorithm)
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

	fmt.Printf("🐛 DEBUG: Parsing certificate\n")
	cert, err := x509.ParseCertificate(sd.Certificates[0].FullBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	fmt.Printf("   Certificate subject: %s\n", cert.Subject)

	// Verify certificate has Ed25519 public key
	ed25519PubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain Ed25519 public key")
	}
	fmt.Printf("   Ed25519 public key length: %d bytes\n", len(ed25519PubKey))

	// Verify the signature
	fmt.Printf("🐛 DEBUG: Verifying Ed25519 signature\n")
	if !ed25519.Verify(ed25519PubKey, data, signer.EncryptedDigest) {
		return nil, fmt.Errorf("Ed25519 signature verification failed")
	}

	fmt.Printf("🐛 DEBUG: Verification successful!\n")
	return &Ed25519PKCS7Info{
		Certificate: cert,
		Signature:   signer.EncryptedDigest,
		Verified:    true,
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
