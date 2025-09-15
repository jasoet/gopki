package formats

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// RawFormat implements the SignatureFormat interface for raw signatures
type RawFormat struct{}

// NewRawFormat creates a new raw format instance.
// Raw format produces bare signature bytes without any container structure,
// metadata, or certificates. This is the simplest signature format.
//
// Raw signatures are:
//   - Always detached (data is not included)
//   - Minimal in size (just signature bytes)
//   - Algorithm-dependent in structure
//   - Suitable for simple verification scenarios
//
// Returns a new RawFormat instance ready for use.
//
// Example:
//
//	rawFormat := NewRawFormat()
//	signature, err := rawFormat.Sign(data, signer, cert, opts)
func NewRawFormat() *RawFormat {
	return &RawFormat{}
}

// Name returns the format name
func (f *RawFormat) Name() string {
	return FormatRaw
}

// Sign creates a raw signature of the provided data.
// This method produces bare signature bytes using the appropriate algorithm
// without any container format or metadata.
//
// Algorithm-specific behavior:
//   - RSA: Signs the hash digest using PKCS#1 v1.5 padding
//   - ECDSA: Signs the hash digest with ASN.1 DER encoding
//   - Ed25519: Signs the original message directly (no pre-hashing)
//
// Parameters:
//   - data: The data to sign
//   - signer: The private key for signing (crypto.Signer interface)
//   - cert: The certificate (used to determine algorithm, can be nil for raw)
//   - opts: Signing options (hash algorithm is required for RSA/ECDSA)
//
// Returns the raw signature bytes or an error if signing fails.
//
// The returned bytes are algorithm-specific:
//   - RSA: PKCS#1 v1.5 signature bytes
//   - ECDSA: ASN.1 DER-encoded signature
//   - Ed25519: 64-byte signature
//
// Example:
//
//	opts := formats.SignOptions{HashAlgorithm: crypto.SHA256}
//	rawSig, err := rawFormat.Sign(document, rsaSigner, nil, opts)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Save raw signature to file
//	err = os.WriteFile("document.sig", rawSig, 0644)
func (f *RawFormat) Sign(data []byte, signer crypto.Signer, cert *x509.Certificate, opts SignOptions) ([]byte, error) {
	// For raw format, we just return the signature bytes
	// Hash the data first (except for Ed25519)
	var signatureData []byte
	var err error

	switch signer.(type) {
	case ed25519.PrivateKey:
		// Ed25519 signs the message directly
		signatureData, err = signer.Sign(rand.Reader, data, crypto.Hash(0))
	default:
		// Other algorithms sign the hash
		if !opts.HashAlgorithm.Available() {
			return nil, fmt.Errorf("hash algorithm %v is not available", opts.HashAlgorithm)
		}

		hasher := opts.HashAlgorithm.New()
		if _, err := hasher.Write(data); err != nil {
			return nil, fmt.Errorf("failed to hash data: %w", err)
		}
		digest := hasher.Sum(nil)

		signatureData, err = signer.Sign(rand.Reader, digest, opts.HashAlgorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signatureData, nil
}

// Verify verifies a raw signature
func (f *RawFormat) Verify(data []byte, signatureData []byte, cert *x509.Certificate, opts VerifyOptions) error {
	publicKey := cert.PublicKey

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		return f.verifyRSA(data, signatureData, pub, opts)
	case *ecdsa.PublicKey:
		return f.verifyECDSA(data, signatureData, pub, opts)
	case ed25519.PublicKey:
		return f.verifyEd25519(data, signatureData, pub)
	default:
		return fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// Parse extracts signature information from raw signature data
func (f *RawFormat) Parse(signatureData []byte) (*SignatureInfo, error) {
	// Raw format doesn't contain metadata, so we return minimal info
	return &SignatureInfo{
		Algorithm: "unknown", // Cannot determine from raw signature
		Detached:  true,      // Raw signatures are always detached
	}, nil
}

// SupportsDetached returns true since raw signatures are always detached
func (f *RawFormat) SupportsDetached() bool {
	return true
}

// verifyRSA verifies an RSA signature
func (f *RawFormat) verifyRSA(data []byte, signature []byte, publicKey *rsa.PublicKey, opts VerifyOptions) error {
	// Determine hash algorithm from key size if not specified
	hashAlgo := opts.getDefaultHashAlgorithm("RSA", publicKey.Size()*8)

	hasher := hashAlgo.New()
	if _, err := hasher.Write(data); err != nil {
		return fmt.Errorf("failed to hash data: %w", err)
	}
	digest := hasher.Sum(nil)

	err := rsa.VerifyPKCS1v15(publicKey, hashAlgo, digest, signature)
	if err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// verifyECDSA verifies an ECDSA signature
func (f *RawFormat) verifyECDSA(data []byte, signature []byte, publicKey *ecdsa.PublicKey, opts VerifyOptions) error {
	// Determine hash algorithm from curve size if not specified
	hashAlgo := opts.getDefaultHashAlgorithm("ECDSA", publicKey.Curve.Params().BitSize)

	hasher := hashAlgo.New()
	if _, err := hasher.Write(data); err != nil {
		return fmt.Errorf("failed to hash data: %w", err)
	}
	digest := hasher.Sum(nil)

	if !ecdsa.VerifyASN1(publicKey, digest, signature) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// verifyEd25519 verifies an Ed25519 signature
func (f *RawFormat) verifyEd25519(data []byte, signature []byte, publicKey ed25519.PublicKey) error {
	if !ed25519.Verify(publicKey, data, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}

	return nil
}

// Helper method to get default hash algorithm
func (opts *VerifyOptions) getDefaultHashAlgorithm(algorithm string, keySize int) crypto.Hash {
	switch algorithm {
	case "RSA":
		if keySize >= 3072 {
			return crypto.SHA384
		}
		return crypto.SHA256
	case "ECDSA":
		switch keySize {
		case 521:
			return crypto.SHA512
		case 384:
			return crypto.SHA384
		default:
			return crypto.SHA256
		}
	case "Ed25519":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// init registers the raw format in the default registry
func init() {
	RegisterFormat(NewRawFormat())
}
