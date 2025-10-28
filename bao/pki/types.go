// Package vault provides integration with Vault/OpenBao PKI secrets engine.
// It enables seamless interaction between GoPKI's type-safe cryptographic operations
// and centralized PKI management via Vault/OpenBao.
package pki

import (
	"fmt"
)

// IssuerInfo represents information about a Vault PKI issuer (CA).
type IssuerInfo struct {
	// IssuerID is the unique identifier
	IssuerID string

	// IssuerName is the human-readable name
	IssuerName string

	// KeyID is the associated key identifier
	KeyID string

	// Certificate is the issuer certificate (PEM format)
	Certificate string

	// CAChain is the certificate authority chain (PEM format)
	CAChain []string

	// ManualChain is a manually configured chain (issuer IDs)
	ManualChain []string

	// LeafNotAfterBehavior controls leaf certificate expiration handling ("err", "truncate", "permit")
	LeafNotAfterBehavior string

	// Usage specifies the issuer usage (read-only, issuing-certificates, crl-signing, ocsp-signing)
	Usage string

	// RevocationSignatureAlgorithm is the signature algorithm for revocation
	RevocationSignatureAlgorithm string

	// IssuingCertificates are the issuing certificate URLs
	IssuingCertificates []string

	// CRLDistributionPoints are the CRL distribution point URLs
	CRLDistributionPoints []string

	// OCSPServers are the OCSP server URLs
	OCSPServers []string

	// EnableAIAURLTemplating enables AIA URL templating
	EnableAIAURLTemplating bool
}

// KeyInfo represents information about a key in Vault.
type KeyInfo struct {
	// KeyID is the unique identifier
	KeyID string

	// KeyName is the human-readable name
	KeyName string

	// KeyType is the algorithm (rsa, ec, ed25519)
	KeyType string

	// KeyBits is the key size in bits
	KeyBits int
}

// VaultError represents a structured error from Vault API.
type VaultError struct {
	// Operation is the operation that failed
	Operation string

	// StatusCode is the HTTP status code
	StatusCode int

	// Errors are the error messages from Vault
	Errors []string

	// Err is the underlying error
	Err error
}

// Error implements the error interface.
func (e *VaultError) Error() string {
	if len(e.Errors) > 0 {
		return fmt.Sprintf("vault: %s failed (status %d): %v",
			e.Operation, e.StatusCode, e.Errors[0])
	}
	if e.Err != nil {
		return fmt.Sprintf("vault: %s failed (status %d): %v",
			e.Operation, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("vault: %s failed (status %d)",
		e.Operation, e.StatusCode)
}

// Unwrap returns the underlying error for error unwrapping.
func (e *VaultError) Unwrap() error {
	return e.Err
}
