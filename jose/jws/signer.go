package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/jasoet/gopki/jose/jwt"
)

// Signer represents a JWS signer for multi-signature support.
type Signer struct {
	// Key is the private key (can be *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, or []byte for HMAC)
	Key interface{}

	// Algorithm is the signing algorithm
	Algorithm jwt.Algorithm

	// KeyID is optional key identifier
	KeyID string

	// UnprotectedHeader contains additional unprotected header parameters
	UnprotectedHeader map[string]interface{}
}

// Sign signs the data and returns the signature bytes.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	switch key := s.Key.(type) {
	case *rsa.PrivateKey:
		return s.signRSA(data, key)

	case *ecdsa.PrivateKey:
		return s.signECDSA(data, key)

	case ed25519.PrivateKey:
		return ed25519.Sign(key, data), nil

	case []byte: // HMAC secret
		return s.signHMAC(data, key)

	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// signRSA signs data with RSA key.
func (s *Signer) signRSA(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	hash, err := s.Algorithm.HashFunc()
	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Check if PSS algorithm
	if s.Algorithm == jwt.PS256 || s.Algorithm == jwt.PS384 || s.Algorithm == jwt.PS512 {
		return rsa.SignPSS(rand.Reader, key, hash, hashed, nil)
	}

	return rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
}

// signECDSA signs data with ECDSA key.
func (s *Signer) signECDSA(data []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	hash, err := s.Algorithm.HashFunc()
	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	return ecdsa.SignASN1(rand.Reader, key, hashed)
}

// signHMAC signs data with HMAC.
func (s *Signer) signHMAC(data, secret []byte) ([]byte, error) {
	hash, err := s.Algorithm.HashFunc()
	if err != nil {
		return nil, err
	}

	hashNew := getHashNew(hash)
	mac := hmac.New(hashNew, secret)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// Verifier represents a JWS verifier for multi-signature support.
type Verifier struct {
	// Key is the public key (can be *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, or []byte for HMAC)
	Key interface{}

	// Algorithm is the expected signing algorithm
	Algorithm jwt.Algorithm

	// KeyID is optional key identifier for matching
	KeyID string
}

// Verify verifies the signature against the data.
func (v *Verifier) Verify(data, signature []byte) bool {
	switch key := v.Key.(type) {
	case *rsa.PublicKey:
		return v.verifyRSA(data, signature, key)

	case *ecdsa.PublicKey:
		return v.verifyECDSA(data, signature, key)

	case ed25519.PublicKey:
		return ed25519.Verify(key, data, signature)

	case []byte: // HMAC secret
		return v.verifyHMAC(data, signature, key)

	default:
		return false
	}
}

// verifyRSA verifies RSA signature.
func (v *Verifier) verifyRSA(data, signature []byte, key *rsa.PublicKey) bool {
	hash, err := v.Algorithm.HashFunc()
	if err != nil {
		return false
	}

	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Check if PSS algorithm
	if v.Algorithm == jwt.PS256 || v.Algorithm == jwt.PS384 || v.Algorithm == jwt.PS512 {
		err = rsa.VerifyPSS(key, hash, hashed, signature, nil)
		return err == nil
	}

	err = rsa.VerifyPKCS1v15(key, hash, hashed, signature)
	return err == nil
}

// verifyECDSA verifies ECDSA signature.
func (v *Verifier) verifyECDSA(data, signature []byte, key *ecdsa.PublicKey) bool {
	hash, err := v.Algorithm.HashFunc()
	if err != nil {
		return false
	}

	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	return ecdsa.VerifyASN1(key, hashed, signature)
}

// verifyHMAC verifies HMAC signature using constant-time comparison.
func (v *Verifier) verifyHMAC(data, signature, secret []byte) bool {
	hash, err := v.Algorithm.HashFunc()
	if err != nil {
		return false
	}

	hashNew := getHashNew(hash)
	mac := hmac.New(hashNew, secret)
	mac.Write(data)
	expected := mac.Sum(nil)

	// Use constant-time comparison
	return hmac.Equal(signature, expected)
}

// getHashNew returns the appropriate hash.Hash constructor function
func getHashNew(hash crypto.Hash) func() hash.Hash {
	switch hash {
	case crypto.SHA256:
		return sha256.New
	case crypto.SHA384:
		return sha512.New384
	case crypto.SHA512:
		return sha512.New
	default:
		return sha256.New
	}
}
