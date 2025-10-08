package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/jasoet/gopki/jose/internal/encoding"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// FromPublicKey creates a JWK from a Go standard library public key.
//
// Supported key types:
//   - *rsa.PublicKey
//   - *ecdsa.PublicKey
//   - ed25519.PublicKey
//
// Parameters:
//   - key: The public key to convert
//   - use: Key use ("sig" for signature, "enc" for encryption, or empty)
//   - kid: Key ID (optional identifier)
//
// Returns:
//   - *JWK: The JWK representation
//   - error: Any conversion error
//
// Example:
//
//	jwk, err := jwk.FromPublicKey(rsaKey.PublicKey, "sig", "rsa-2024-01")
func FromPublicKey(key keypair.GenericPublicKey, use, kid string) (*JWK, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return fromRSAPublicKey(k, use, kid)
	case *ecdsa.PublicKey:
		return fromECDSAPublicKey(k, use, kid)
	case ed25519.PublicKey:
		return fromEd25519PublicKey(k, use, kid)
	default:
		return nil, fmt.Errorf("%w: %T", ErrInvalidKeyType, key)
	}
}

// FromGoPKIKeyPair creates a JWK from a GoPKI key pair (public key only).
//
// Type parameter:
//   - K: Key pair type constrained to keypair.KeyPair interface
//
// Parameters:
//   - keyPair: The GoPKI key pair
//   - use: Key use ("sig" or "enc")
//   - kid: Key ID
//
// Returns:
//   - *JWK: The JWK representation (public key only)
//   - error: Any conversion error
//
// Example:
//
//	rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
//	jwk, err := jwk.FromGoPKIKeyPair(rsaKeys, "sig", "my-key-1")
func FromGoPKIKeyPair[K keypair.KeyPair](keyPair K, use, kid string) (*JWK, error) {
	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		return fromRSAPublicKey(kp.PublicKey, use, kid)
	case *algo.ECDSAKeyPair:
		return fromECDSAPublicKey(kp.PublicKey, use, kid)
	case *algo.Ed25519KeyPair:
		return fromEd25519PublicKey(kp.PublicKey, use, kid)
	default:
		return nil, fmt.Errorf("%w: %T", ErrInvalidKeyType, keyPair)
	}
}

// fromRSAPublicKey converts an RSA public key to JWK.
func fromRSAPublicKey(key *rsa.PublicKey, use, kid string) (*JWK, error) {
	if key == nil {
		return nil, fmt.Errorf("RSA public key is nil")
	}

	// Convert modulus to base64url
	nBytes := key.N.Bytes()
	n := encoding.EncodeBytes(nBytes)

	// Convert exponent to base64url
	eBytes := big.NewInt(int64(key.E)).Bytes()
	e := encoding.EncodeBytes(eBytes)

	return &JWK{
		KeyType: "RSA",
		Use:     use,
		KeyID:   kid,
		N:       n,
		E:       e,
	}, nil
}

// fromECDSAPublicKey converts an ECDSA public key to JWK.
func fromECDSAPublicKey(key *ecdsa.PublicKey, use, kid string) (*JWK, error) {
	if key == nil {
		return nil, fmt.Errorf("ECDSA public key is nil")
	}

	// Determine curve name
	curveName, err := getCurveName(key.Curve)
	if err != nil {
		return nil, err
	}

	// Convert coordinates to base64url
	// Pad coordinates to correct byte length for the curve
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	// Pad with leading zeros if needed
	if len(xBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(yBytes):], yBytes)
		yBytes = padded
	}

	x := encoding.EncodeBytes(xBytes)
	y := encoding.EncodeBytes(yBytes)

	return &JWK{
		KeyType: "EC",
		Use:     use,
		KeyID:   kid,
		Curve:   curveName,
		X:       x,
		Y:       y,
	}, nil
}

// fromEd25519PublicKey converts an Ed25519 public key to JWK.
func fromEd25519PublicKey(key ed25519.PublicKey, use, kid string) (*JWK, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("Ed25519 public key is empty")
	}

	// Ed25519 public keys are 32 bytes
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(key))
	}

	x := encoding.EncodeBytes([]byte(key))

	return &JWK{
		KeyType: "OKP",
		Use:     use,
		KeyID:   kid,
		Curve:   "Ed25519",
		X:       x,
	}, nil
}

// getCurveName returns the JWK curve name for an elliptic curve.
func getCurveName(curve elliptic.Curve) (string, error) {
	switch curve {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		// Try to match by parameters
		params := curve.Params()
		switch params.Name {
		case "P-256":
			return "P-256", nil
		case "P-384":
			return "P-384", nil
		case "P-521":
			return "P-521", nil
		default:
			return "", fmt.Errorf("%w: %s", ErrInvalidCurve, params.Name)
		}
	}
}
