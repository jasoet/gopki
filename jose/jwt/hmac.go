package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// signHMAC creates an HMAC signature using the specified hash algorithm
func signHMAC(data []byte, secret []byte, hashAlg crypto.Hash) ([]byte, error) {
	var h func() hash.Hash

	switch hashAlg {
	case crypto.SHA256:
		h = sha256.New
	case crypto.SHA384:
		h = sha512.New384
	case crypto.SHA512:
		h = sha512.New
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %v", hashAlg)
	}

	mac := hmac.New(h, secret)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// verifyHMAC verifies an HMAC signature using constant-time comparison
// This prevents timing attacks by using hmac.Equal
func verifyHMAC(data, signature, secret []byte, hashAlg crypto.Hash) bool {
	expectedMAC, err := signHMAC(data, secret, hashAlg)
	if err != nil {
		return false
	}

	// CRITICAL: Use constant-time comparison to prevent timing attacks
	return hmac.Equal(signature, expectedMAC)
}
