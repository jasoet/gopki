// Package signing provides raw cryptographic signing functionality
// for compact signatures suitable for QR codes and other size-constrained scenarios.
package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// Raw signing errors
var (
	ErrUnsupportedKeyType = errors.New("unsupported key type for raw signing")
	ErrInvalidPublicKey   = errors.New("invalid public key")
	ErrSignatureTooShort  = errors.New("signature too short")
)

// RawSignOptions configures raw signing operations
type RawSignOptions struct {
	// Hash algorithm to use (default: SHA256)
	HashAlgorithm crypto.Hash
	// Encode signature to base64 (default: false, returns raw bytes)
	Base64Encode bool
}

// DefaultRawSignOptions returns default options for raw signing
func DefaultRawSignOptions() RawSignOptions {
	return RawSignOptions{
		HashAlgorithm: crypto.SHA256,
		Base64Encode:  false,
	}
}

// SignRaw creates a raw cryptographic signature suitable for compact use cases like QR codes.
// This produces minimal-size signatures without PKCS#7 overhead.
//
// Signature sizes:
//   - ECDSA P-256: 64 bytes (R||S format, 32 bytes each)
//   - ECDSA P-384: 96 bytes (R||S format, 48 bytes each)
//   - Ed25519: 64 bytes
//   - RSA: Variable (typically 256 bytes for RSA-2048)
//
// Parameters:
//   - data: The data to sign
//   - keyPair: The key pair to use for signing
//   - opts: Signing options (use DefaultRawSignOptions() for defaults)
//
// Returns the raw signature bytes or base64-encoded string (if Base64Encode is true).
//
// Example:
//
//	keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	signature, err := SignRaw([]byte("data"), keyPair, DefaultRawSignOptions())
//	// Returns 64-byte signature for ECDSA P-256
func SignRaw[T keypair.KeyPair](data []byte, keyPair T, opts RawSignOptions) ([]byte, error) {
	if opts.HashAlgorithm == 0 {
		opts.HashAlgorithm = crypto.SHA256
	}

	// Hash the data
	hasher := opts.HashAlgorithm.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	var signature []byte
	var err error

	// Sign based on key type
	switch kp := any(keyPair).(type) {
	case *algo.ECDSAKeyPair:
		signature, err = signECDSARaw(kp.PrivateKey, digest)
	case *algo.Ed25519KeyPair:
		signature = ed25519.Sign(kp.PrivateKey, data)
	case *algo.RSAKeyPair:
		signature, err = rsa.SignPKCS1v15(rand.Reader, kp.PrivateKey, opts.HashAlgorithm, digest)
	default:
		return nil, ErrUnsupportedKeyType
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	if opts.Base64Encode {
		encoded := base64.StdEncoding.EncodeToString(signature)
		return []byte(encoded), nil
	}

	return signature, nil
}

// SignRawString is a convenience wrapper that returns base64-encoded signature as string.
//
// Example:
//
//	keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	signature, err := SignRawString([]byte("data"), keyPair, DefaultRawSignOptions())
//	// Returns base64-encoded signature string
func SignRawString[T keypair.KeyPair](data []byte, keyPair T, opts RawSignOptions) (string, error) {
	opts.Base64Encode = true
	sig, err := SignRaw(data, keyPair, opts)
	if err != nil {
		return "", err
	}
	return string(sig), nil
}

// VerifyRaw verifies a raw cryptographic signature.
//
// Parameters:
//   - data: The original data that was signed
//   - signature: The signature bytes (or base64-encoded string)
//   - publicKey: The public key to verify with
//   - opts: Verification options
//
// Returns true if the signature is valid, false otherwise.
//
// Example:
//
//	valid, err := VerifyRaw(data, signature, publicKey, DefaultRawSignOptions())
func VerifyRaw(data []byte, signature []byte, publicKey crypto.PublicKey, opts RawSignOptions) (bool, error) {
	if opts.HashAlgorithm == 0 {
		opts.HashAlgorithm = crypto.SHA256
	}

	// Check if signature is base64-encoded and decode if needed
	if opts.Base64Encode {
		decoded, err := base64.StdEncoding.DecodeString(string(signature))
		if err != nil {
			return false, fmt.Errorf("failed to decode base64 signature: %w", err)
		}
		signature = decoded
	}

	// Hash the data
	hasher := opts.HashAlgorithm.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Verify based on key type
	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSARaw(pub, digest, signature)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, data, signature), nil
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pub, opts.HashAlgorithm, digest, signature)
		return err == nil, err
	default:
		return false, ErrUnsupportedKeyType
	}
}

// VerifyRawString is a convenience wrapper for verifying base64-encoded signatures.
//
// Example:
//
//	valid, err := VerifyRawString(data, signatureBase64, publicKey, DefaultRawSignOptions())
func VerifyRawString(data []byte, signatureBase64 string, publicKey crypto.PublicKey, opts RawSignOptions) (bool, error) {
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	opts.Base64Encode = false // Already decoded
	return VerifyRaw(data, signature, publicKey, opts)
}

// VerifyRawWithPEM verifies a signature using a PEM-encoded public key.
//
// Example:
//
//	publicKeyPEM := []byte("-----BEGIN PUBLIC KEY-----\n...")
//	valid, err := VerifyRawWithPEM(data, signature, publicKeyPEM, DefaultRawSignOptions())
func VerifyRawWithPEM(data []byte, signature []byte, publicKeyPEM []byte, opts RawSignOptions) (bool, error) {
	publicKey, err := parsePublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return false, err
	}

	return VerifyRaw(data, signature, publicKey, opts)
}

// signECDSARaw signs data with ECDSA and returns signature in R||S format
func signECDSARaw(privateKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, err
	}

	// Determine signature size based on curve
	curveBytes := (privateKey.Curve.Params().BitSize + 7) / 8

	// Encode signature (R||S format)
	signature := make([]byte, curveBytes*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad R and S to curve size
	copy(signature[curveBytes-len(rBytes):curveBytes], rBytes)
	copy(signature[len(signature)-len(sBytes):], sBytes)

	return signature, nil
}

// verifyECDSARaw verifies an ECDSA signature in R||S format
func verifyECDSARaw(publicKey *ecdsa.PublicKey, digest []byte, signature []byte) (bool, error) {
	// Determine expected signature size
	curveBytes := (publicKey.Curve.Params().BitSize + 7) / 8
	expectedSize := curveBytes * 2

	if len(signature) != expectedSize {
		return false, fmt.Errorf("invalid signature length: expected %d bytes, got %d", expectedSize, len(signature))
	}

	// Split signature into R and S
	r := new(big.Int).SetBytes(signature[:curveBytes])
	s := new(big.Int).SetBytes(signature[curveBytes:])

	// Verify signature
	valid := ecdsa.Verify(publicKey, digest, r, s)
	return valid, nil
}

// parsePublicKeyFromPEM parses a PEM-encoded public key
func parsePublicKeyFromPEM(publicKeyPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, ErrInvalidPublicKey
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return publicKey, nil
}

// GetRawSignatureSize returns the expected signature size for a given key type.
//
// Returns:
//   - ECDSA P-256: 64 bytes
//   - ECDSA P-384: 96 bytes
//   - ECDSA P-521: 132 bytes
//   - Ed25519: 64 bytes
//   - RSA-2048: 256 bytes
//   - RSA-3072: 384 bytes
//   - RSA-4096: 512 bytes
func GetRawSignatureSize(publicKey crypto.PublicKey) (int, error) {
	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		curveBytes := (pub.Curve.Params().BitSize + 7) / 8
		return curveBytes * 2, nil
	case ed25519.PublicKey:
		return ed25519.SignatureSize, nil
	case *rsa.PublicKey:
		return pub.Size(), nil
	default:
		return 0, ErrUnsupportedKeyType
	}
}
