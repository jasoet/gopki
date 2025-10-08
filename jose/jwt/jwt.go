package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/jasoet/gopki/keypair"
)

// Sign creates and signs a JWT using an asymmetric private key
// Type parameter K must be a supported private key type from keypair package
func Sign[K keypair.PrivateKey](claims *Claims, key K, alg Algorithm, opts *SignOptions) (string, error) {
	if opts == nil {
		opts = DefaultSignOptions()
	}

	// Validate algorithm
	if err := alg.Validate(); err != nil {
		return "", err
	}

	// HMAC algorithms must use SignWithSecret
	if alg.IsHMAC() {
		return "", fmt.Errorf("use SignWithSecret for HMAC algorithms")
	}

	// Create header
	header := Header{
		Algorithm: alg,
		Type:      "JWT",
		KeyID:     opts.KeyID,
	}

	// Encode header and claims
	headerStr, err := encodeSegment(header)
	if err != nil {
		return "", fmt.Errorf("encode header: %w", err)
	}

	claimsStr, err := encodeSegment(claims)
	if err != nil {
		return "", fmt.Errorf("encode claims: %w", err)
	}

	// Create signing input (header.payload)
	signingInput := headerStr + "." + claimsStr

	// Sign using the appropriate algorithm
	signature, err := signWithKey([]byte(signingInput), key, alg, opts)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	// Encode signature
	sigStr := base64URLEncode(signature)

	return signingInput + "." + sigStr, nil
}

// Verify verifies a JWT signature and validates claims
// Type parameter K must be a supported public key type from keypair package
func Verify[K keypair.PublicKey](tokenString string, key K, opts *VerifyOptions) (*Claims, error) {
	if opts == nil {
		opts = DefaultVerifyOptions()
	}

	// Parse token (validates structure and algorithm)
	token, err := Parse(tokenString)
	if err != nil {
		return nil, err
	}

	// Check expected algorithm (prevent algorithm confusion)
	if opts.ExpectedAlgorithm != "" && token.Header.Algorithm != opts.ExpectedAlgorithm {
		return nil, fmt.Errorf("%w: got %s, want %s",
			ErrAlgorithmMismatch, token.Header.Algorithm, opts.ExpectedAlgorithm)
	}

	// HMAC tokens must use VerifyWithSecret
	if token.Header.Algorithm.IsHMAC() {
		return nil, fmt.Errorf("use VerifyWithSecret for HMAC-signed tokens")
	}

	// Verify signature
	signingInput := []byte(token.SigningInput())
	valid, err := verifyWithKey(signingInput, token.Signature, key, token.Header.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}

	if !valid {
		return nil, ErrInvalidSignature
	}

	// Validate claims
	if err := token.Claims.Validate(opts.Validation); err != nil {
		return nil, err
	}

	return token.Claims, nil
}

// SignWithSecret signs a JWT using HMAC (symmetric key)
func SignWithSecret(claims *Claims, secret []byte, alg Algorithm) (string, error) {
	// Validate algorithm
	if err := alg.Validate(); err != nil {
		return "", err
	}

	// Only HMAC algorithms allowed
	if !alg.IsHMAC() {
		return "", fmt.Errorf("use Sign for asymmetric algorithms")
	}

	// Create header
	header := Header{
		Algorithm: alg,
		Type:      "JWT",
	}

	// Encode header and claims
	headerStr, err := encodeSegment(header)
	if err != nil {
		return "", err
	}

	claimsStr, err := encodeSegment(claims)
	if err != nil {
		return "", err
	}

	// Create signing input
	signingInput := headerStr + "." + claimsStr

	// Sign with HMAC
	hash, _ := alg.HashFunc()
	signature, err := signHMAC([]byte(signingInput), secret, hash)
	if err != nil {
		return "", err
	}

	sigStr := base64URLEncode(signature)
	return signingInput + "." + sigStr, nil
}

// VerifyWithSecret verifies an HMAC-signed JWT
func VerifyWithSecret(tokenString string, secret []byte, opts *VerifyOptions) (*Claims, error) {
	if opts == nil {
		opts = DefaultVerifyOptions()
	}

	// Parse token
	token, err := Parse(tokenString)
	if err != nil {
		return nil, err
	}

	// Must be HMAC algorithm
	if !token.Header.Algorithm.IsHMAC() {
		return nil, fmt.Errorf("token not HMAC-signed, use Verify instead")
	}

	// Check expected algorithm
	if opts.ExpectedAlgorithm != "" && token.Header.Algorithm != opts.ExpectedAlgorithm {
		return nil, fmt.Errorf("%w: got %s, want %s",
			ErrAlgorithmMismatch, token.Header.Algorithm, opts.ExpectedAlgorithm)
	}

	// Verify HMAC (constant-time comparison)
	hash, _ := token.Header.Algorithm.HashFunc()
	valid := verifyHMAC([]byte(token.SigningInput()), token.Signature, secret, hash)
	if !valid {
		return nil, ErrInvalidSignature
	}

	// Validate claims
	if err := token.Claims.Validate(opts.Validation); err != nil {
		return nil, err
	}

	return token.Claims, nil
}

// signWithKey signs data with the appropriate key type
func signWithKey[K keypair.PrivateKey](data []byte, key K, alg Algorithm, opts *SignOptions) ([]byte, error) {
	hash, err := alg.HashFunc()
	if err != nil {
		return nil, err
	}

	// Type switch to handle different key types
	switch k := any(key).(type) {
	case *rsa.PrivateKey:
		return signRSA(data, k, hash, opts.UsePSS)

	case *ecdsa.PrivateKey:
		return signECDSA(data, k, hash)

	case ed25519.PrivateKey:
		// Ed25519 signs the message directly
		return ed25519.Sign(k, data), nil

	default:
		return nil, fmt.Errorf("%w for algorithm %s", ErrInvalidKey, alg)
	}
}

// verifyWithKey verifies signature with the appropriate key type
func verifyWithKey[K keypair.PublicKey](data, signature []byte, key K, alg Algorithm) (bool, error) {
	hash, err := alg.HashFunc()
	if err != nil {
		return false, err
	}

	// Type switch to handle different key types
	switch k := any(key).(type) {
	case *rsa.PublicKey:
		valid, err := verifyRSA(data, signature, k, hash, alg.IsRSA() && (alg == PS256 || alg == PS384 || alg == PS512))
		return valid, err

	case *ecdsa.PublicKey:
		valid, err := verifyECDSA(data, signature, k)
		return valid, err

	case ed25519.PublicKey:
		return ed25519.Verify(k, data, signature), nil

	default:
		return false, fmt.Errorf("%w for algorithm %s", ErrInvalidKey, alg)
	}
}

// signRSA signs data with RSA private key
func signRSA(data []byte, key *rsa.PrivateKey, hash crypto.Hash, usePSS bool) ([]byte, error) {
	// Hash the data
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	if usePSS {
		// RSA-PSS signature
		return rsa.SignPSS(rand.Reader, key, hash, hashed, nil)
	}

	// RSA PKCS#1 v1.5 signature
	return rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
}

// verifyRSA verifies RSA signature
func verifyRSA(data, signature []byte, key *rsa.PublicKey, hash crypto.Hash, usePSS bool) (bool, error) {
	// Hash the data
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	if usePSS {
		// RSA-PSS verification
		err := rsa.VerifyPSS(key, hash, hashed, signature, nil)
		return err == nil, nil
	}

	// RSA PKCS#1 v1.5 verification
	err := rsa.VerifyPKCS1v15(key, hash, hashed, signature)
	return err == nil, nil
}

// signECDSA signs data with ECDSA private key
func signECDSA(data []byte, key *ecdsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	// Hash the data
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	// Sign
	return ecdsa.SignASN1(rand.Reader, key, hashed)
}

// verifyECDSA verifies ECDSA signature
func verifyECDSA(data, signature []byte, key *ecdsa.PublicKey) (bool, error) {
	// For ECDSA, we need to re-hash since VerifyASN1 expects the hash
	// The hash algorithm is determined by the curve and JWT algorithm
	var hash crypto.Hash
	switch key.Curve.Params().BitSize {
	case 256:
		hash = crypto.SHA256
	case 384:
		hash = crypto.SHA384
	case 521:
		hash = crypto.SHA512
	default:
		return false, fmt.Errorf("unsupported curve size: %d", key.Curve.Params().BitSize)
	}

	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	return ecdsa.VerifyASN1(key, hashed, signature), nil
}
