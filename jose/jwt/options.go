package jwt

// SignOptions configures JWT signing
type SignOptions struct {
	// KeyID to include in header (for key rotation)
	KeyID string

	// PSS configures RSA-PSS signing (if using PS256/384/512)
	// If true and using RSA, will use PSS instead of PKCS#1 v1.5
	UsePSS bool
}

// VerifyOptions configures JWT verification
type VerifyOptions struct {
	// Expected algorithm (rejects token if algorithm doesn't match)
	// This prevents algorithm confusion attacks
	ExpectedAlgorithm Algorithm

	// Claims validation options
	Validation *ValidationOptions
}

// DefaultSignOptions returns default sign options
func DefaultSignOptions() *SignOptions {
	return &SignOptions{}
}

// DefaultVerifyOptions returns default verify options
func DefaultVerifyOptions() *VerifyOptions {
	return &VerifyOptions{
		Validation: DefaultValidationOptions(),
	}
}
