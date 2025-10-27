package bao

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// ============================================================================
// Certificate Options
// ============================================================================

// GenerateCertificateOptions contains parameters for generating a certificate in OpenBao.
// OpenBao generates both the private key and certificate.
type GenerateCertificateOptions struct {
	CommonName        string   // Certificate common name (CN)
	AltNames          []string // DNS Subject Alternative Names
	IPSANs            []string // IP Subject Alternative Names
	URISANs           []string // URI Subject Alternative Names
	OtherSANs         []string // Other SANs with the format <oid>;UTF8:<value>
	TTL               string   // Certificate time-to-live (e.g., "720h", "30d")
	Format            string   // Certificate format ("pem", "der", "pem_bundle")
	PrivateKeyFormat  string   // Private key format ("", "pkcs8")
	ExcludeCNFromSANs bool     // Exclude CN from Subject Alternative Names
	NotAfter          string   // Explicit expiration time (RFC3339 format)
	KeyType           string   // Key type ("rsa", "ec", "ed25519") - auto-set by GenerateXXXCertificate methods
	KeyBits           int      // Key bits for RSA and ECDSA keys - auto-set by GenerateXXXCertificate methods
}

// SignCertificateOptions contains parameters for signing a CSR.
type SignCertificateOptions struct {
	CommonName        string   // Override CSR common name (optional)
	AltNames          []string // Additional DNS SANs (merged with CSR SANs)
	IPSANs            []string // Additional IP SANs (merged with CSR SANs)
	URISANs           []string // Additional URI SANs (merged with CSR SANs)
	OtherSANs         []string // Other SANs with the format <oid>;UTF8:<value>
	TTL               string   // Certificate time-to-live
	Format            string   // Certificate format
	ExcludeCNFromSANs bool     // Exclude CN from SANs
	NotAfter          string   // Explicit expiration time (RFC3339 format)
}

// SignVerbatimOptions contains parameters for signing a certificate verbatim.
type SignVerbatimOptions struct {
	TTL      string // Certificate time-to-live
	Format   string // Certificate format
	NotAfter string // Explicit expiration time (RFC3339 format)
}

// SignSelfIssuedOptions contains parameters for signing a self-issued certificate.
type SignSelfIssuedOptions struct {
	RequireMatchingCertificateAlgorithms bool // Require matching algorithms
}

// CertificateInfo represents certificate metadata from OpenBao.
type CertificateInfo struct {
	SerialNumber   string    // Certificate serial number
	Expiration     time.Time // Certificate expiration time
	Revoked        bool      // Whether the certificate is revoked
	RevocationTime int64     // Revocation time (Unix timestamp)
}

// ============================================================================
// CertificateClient[K] - Type-safe certificate operations
// ============================================================================

// CertificateClient provides type-safe certificate operations for OpenBao PKI.
// It uses generics to ensure compile-time type safety for certificate and key operations.
//
// Type parameter:
//   - K: KeyPair type constraint (keypair.KeyPair)
//
// Supported types:
//   - *algo.RSAKeyPair
//   - *algo.ECDSAKeyPair
//   - *algo.Ed25519KeyPair
//
// The keyPair field is populated when:
//   - Certificate is issued with GenerateXXXCertificate() (OpenBao generates key)
//   - Certificate is issued with IssueXXXCertificate() (local key used)
//
// The keyPair field is nil when:
//   - Certificate is signed with SignCSR() (key not provided)
//   - Certificate is retrieved with GetCertificate() (only metadata available)
type CertificateClient[K keypair.KeyPair] struct {
	client      *Client
	certificate *cert.Certificate
	certInfo    *CertificateInfo
	keyPair     K // Only set when certificate was issued with key generation
}

// Certificate returns the certificate.
func (cc *CertificateClient[K]) Certificate() *cert.Certificate {
	return cc.certificate
}

// CertificateInfo returns the certificate metadata.
func (cc *CertificateClient[K]) CertificateInfo() *CertificateInfo {
	return cc.certInfo
}

// KeyPair returns the cached key pair if available.
// Returns an error if the key pair is not cached (e.g., certificate was signed without key generation).
//
// The key pair is available when:
//   - Certificate was issued with GenerateXXXCertificate() (OpenBao generated key)
//   - Certificate was issued with IssueXXXCertificate() (local key used)
//
// The key pair is NOT available when:
//   - Certificate was signed with SignCSR() (key not included)
//   - Certificate was retrieved with GetCertificate() (only metadata retrieved)
//
// Example:
//
//	certClient, err := client.GenerateRSACertificate(ctx, "web-server", &GenerateCertificateOptions{...})
//	keyPair, err := certClient.KeyPair()  // Returns the keypair
//	// Use keyPair.PrivateKey, keyPair.PublicKey
func (cc *CertificateClient[K]) KeyPair() (K, error) {
	var zero K
	// Use reflection to check if keyPair is nil (handles typed nil properly)
	v := reflect.ValueOf(cc.keyPair)
	if !v.IsValid() || v.IsZero() {
		return zero, fmt.Errorf("bao: key pair not available (certificate was signed without key generation or retrieved without private key)")
	}
	return cc.keyPair, nil
}

// HasKeyPair returns true if the key pair is cached and available.
func (cc *CertificateClient[K]) HasKeyPair() bool {
	v := reflect.ValueOf(cc.keyPair)
	return v.IsValid() && !v.IsZero()
}

// Revoke revokes this certificate.
//
// Example:
//
//	certClient, _ := client.GetCertificate(ctx, "11:22:33:44:55")
//	err := certClient.Revoke(ctx)
func (cc *CertificateClient[K]) Revoke(ctx context.Context) error {
	if cc.certInfo == nil || cc.certInfo.SerialNumber == "" {
		return fmt.Errorf("bao: certificate info not available")
	}
	return cc.client.RevokeCertificate(ctx, cc.certInfo.SerialNumber)
}

// RevokeWithKey revokes this certificate using its private key.
//
// Example:
//
//	certClient, _ := client.GenerateRSACertificate(ctx, "web-server", &GenerateCertificateOptions{...})
//	err := certClient.RevokeWithKey(ctx)
func (cc *CertificateClient[K]) RevokeWithKey(ctx context.Context) error {
	if !cc.HasKeyPair() {
		return fmt.Errorf("bao: key pair not available for revocation")
	}
	return cc.client.revokeWithKey(ctx, cc.certificate, cc.keyPair)
}

// ============================================================================
// Client Methods - Type-agnostic operations
// ============================================================================

// ListCertificates lists all certificate serial numbers in OpenBao.
//
// Example:
//
//	serials, err := client.ListCertificates(ctx)
//	for _, serial := range serials {
//	    fmt.Println(serial)
//	}
func (c *Client) ListCertificates(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("%s/certs", c.config.Mount)
	secret, err := c.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: list certificates: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if keyStr, ok := key.(string); ok {
			result = append(result, keyStr)
		}
	}

	return result, nil
}

// GetCertificate retrieves a certificate from OpenBao by serial number.
// Returns only the certificate without type-safe wrapper.
//
// For type-safe operations, use GetRSACertificate(), GetECDSACertificate(), or GetEd25519Certificate().
//
// Example:
//
//	certificate, err := client.GetCertificate(ctx, "39:dd:2e:90:b7:23:1f:8d")
func (c *Client) GetCertificate(ctx context.Context, serial string) (*cert.Certificate, error) {
	if serial == "" {
		return nil, fmt.Errorf("bao: serial number is required")
	}

	path := fmt.Sprintf("%s/cert/%s", c.config.Mount, serial)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: get certificate: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: get certificate: not found")
	}

	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("bao: get certificate: invalid certificate data")
	}

	certificate, err := vaultCertToGoPKI(certificatePEM, "")
	if err != nil {
		return nil, fmt.Errorf("bao: get certificate: %w", err)
	}

	return certificate, nil
}

// GetRSACertificate retrieves an RSA certificate from OpenBao and returns a type-safe CertificateClient.
// The returned CertificateClient does not have a cached key pair (HasKeyPair() will be false).
//
// Note: This validates the certificate is RSA type at retrieval time.
//
// Example:
//
//	certClient, err := client.GetRSACertificate(ctx, "39:dd:2e:90:b7:23:1f:8d")
//	cert := certClient.Certificate()
//	err := certClient.Revoke(ctx)  // ✓ Works
//	err := certClient.RevokeWithKey(ctx)  // ✗ Fails - no key pair cached
func (c *Client) GetRSACertificate(ctx context.Context, serial string) (*CertificateClient[*algo.RSAKeyPair], error) {
	return getCertificateTyped[*algo.RSAKeyPair](ctx, c, serial, "RSA")
}

// GetECDSACertificate retrieves an ECDSA certificate from OpenBao and returns a type-safe CertificateClient.
// The returned CertificateClient does not have a cached key pair (HasKeyPair() will be false).
//
// Note: This validates the certificate is ECDSA type at retrieval time.
//
// Example:
//
//	certClient, err := client.GetECDSACertificate(ctx, "39:dd:2e:90:b7:23:1f:8d")
//	cert := certClient.Certificate()
//	err := certClient.Revoke(ctx)  // ✓ Works
func (c *Client) GetECDSACertificate(ctx context.Context, serial string) (*CertificateClient[*algo.ECDSAKeyPair], error) {
	return getCertificateTyped[*algo.ECDSAKeyPair](ctx, c, serial, "ECDSA")
}

// GetEd25519Certificate retrieves an Ed25519 certificate from OpenBao and returns a type-safe CertificateClient.
// The returned CertificateClient does not have a cached key pair (HasKeyPair() will be false).
//
// Note: This validates the certificate is Ed25519 type at retrieval time.
//
// Example:
//
//	certClient, err := client.GetEd25519Certificate(ctx, "39:dd:2e:90:b7:23:1f:8d")
//	cert := certClient.Certificate()
//	err := certClient.Revoke(ctx)  // ✓ Works
func (c *Client) GetEd25519Certificate(ctx context.Context, serial string) (*CertificateClient[*algo.Ed25519KeyPair], error) {
	return getCertificateTyped[*algo.Ed25519KeyPair](ctx, c, serial, "Ed25519")
}

// getCertificateTyped is the internal implementation for type-safe certificate retrieval.
func getCertificateTyped[K keypair.KeyPair](ctx context.Context, client *Client, serial string, expectedAlgo string) (*CertificateClient[K], error) {
	if serial == "" {
		return nil, fmt.Errorf("bao: serial number is required")
	}

	path := fmt.Sprintf("%s/cert/%s", client.config.Mount, serial)
	secret, err := client.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: get certificate: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: get certificate: not found")
	}

	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("bao: get certificate: invalid certificate data")
	}

	certificate, err := vaultCertToGoPKI(certificatePEM, "")
	if err != nil {
		return nil, fmt.Errorf("bao: get certificate: %w", err)
	}

	// Validate certificate algorithm matches expected type
	actualAlgo := certificate.Certificate.PublicKeyAlgorithm.String()
	if actualAlgo != expectedAlgo {
		return nil, fmt.Errorf("bao: certificate type mismatch: expected %s, got %s", expectedAlgo, actualAlgo)
	}

	// Extract certificate info from response
	certInfo := extractCertificateInfo(secret.Data)

	return &CertificateClient[K]{
		client:      client,
		certificate: certificate,
		certInfo:    certInfo,
		// keyPair is nil - not available from retrieval
	}, nil
}

// RevokeCertificate revokes a certificate by serial number.
//
// Example:
//
//	err := client.RevokeCertificate(ctx, "39:dd:2e:90:b7:23:1f:8d")
func (c *Client) RevokeCertificate(ctx context.Context, serial string) error {
	if serial == "" {
		return fmt.Errorf("bao: serial number is required")
	}

	reqBody := map[string]interface{}{
		"serial_number": serial,
	}

	path := fmt.Sprintf("%s/revoke", c.config.Mount)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("bao: revoke certificate: %w", err)
	}

	return nil
}

// revokeWithKey revokes a certificate using its private key.
// This is a private method. Use CertificateClient.RevokeWithKey() instead.
func (c *Client) revokeWithKey(ctx context.Context, certificate *cert.Certificate, keyPair interface{}) error {
	if certificate == nil {
		return fmt.Errorf("bao: certificate is required")
	}
	if keyPair == nil {
		return fmt.Errorf("bao: key pair is required")
	}

	// Convert certificate to PEM
	certPEM := string(certificate.PEMData)

	// Convert private key to PEM based on type
	var keyPEM string
	switch kp := keyPair.(type) {
	case *algo.RSAKeyPair:
		pemBytes, err := kp.PrivateKeyToPEM()
		if err != nil {
			return fmt.Errorf("bao: convert RSA private key to PEM: %w", err)
		}
		keyPEM = string(pemBytes)
	case *algo.ECDSAKeyPair:
		pemBytes, err := kp.PrivateKeyToPEM()
		if err != nil {
			return fmt.Errorf("bao: convert ECDSA private key to PEM: %w", err)
		}
		keyPEM = string(pemBytes)
	case *algo.Ed25519KeyPair:
		pemBytes, err := kp.PrivateKeyToPEM()
		if err != nil {
			return fmt.Errorf("bao: convert Ed25519 private key to PEM: %w", err)
		}
		keyPEM = string(pemBytes)
	default:
		return fmt.Errorf("bao: unsupported key pair type: %T", keyPair)
	}

	reqBody := map[string]interface{}{
		"certificate": certPEM,
		"private_key": keyPEM,
	}

	path := fmt.Sprintf("%s/revoke-with-key", c.config.Mount)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("bao: revoke with key: %w", err)
	}

	return nil
}

// ============================================================================
// Generate Certificate - Entry Points (OpenBao generates key)
// ============================================================================

// GenerateRSACertificate generates an RSA certificate with OpenBao creating the key pair.
// The private key is returned and cached in the CertificateClient.
//
// Example:
//
//	certClient, err := client.GenerateRSACertificate(ctx, "web-server", &GenerateCertificateOptions{
//	    CommonName: "app.example.com",
//	    AltNames:   []string{"www.app.example.com"},
//	    TTL:        "720h",
//	})
//	keyPair, _ := certClient.KeyPair()  // Get the generated keypair
func (c *Client) GenerateRSACertificate(ctx context.Context, role string, opts *GenerateCertificateOptions) (*CertificateClient[*algo.RSAKeyPair], error) {
	return generateCertificate[*algo.RSAKeyPair](ctx, c, role, opts)
}

// GenerateECDSACertificate generates an ECDSA certificate with OpenBao creating the key pair.
func (c *Client) GenerateECDSACertificate(ctx context.Context, role string, opts *GenerateCertificateOptions) (*CertificateClient[*algo.ECDSAKeyPair], error) {
	return generateCertificate[*algo.ECDSAKeyPair](ctx, c, role, opts)
}

// GenerateEd25519Certificate generates an Ed25519 certificate with OpenBao creating the key pair.
func (c *Client) GenerateEd25519Certificate(ctx context.Context, role string, opts *GenerateCertificateOptions) (*CertificateClient[*algo.Ed25519KeyPair], error) {
	return generateCertificate[*algo.Ed25519KeyPair](ctx, c, role, opts)
}

// generateCertificate is the internal implementation for certificate generation with OpenBao-generated key.
func generateCertificate[K keypair.KeyPair](ctx context.Context, client *Client, role string, opts *GenerateCertificateOptions) (*CertificateClient[K], error) {
	if role == "" {
		return nil, fmt.Errorf("bao: role is required")
	}
	if opts == nil {
		return nil, fmt.Errorf("bao: options are required")
	}
	if opts.CommonName == "" {
		return nil, fmt.Errorf("bao: common name is required")
	}

	// Auto-set key_type and key_bits based on generic type K if not already set
	if opts.KeyType == "" {
		var zero K
		switch any(zero).(type) {
		case *algo.RSAKeyPair:
			opts.KeyType = "rsa"
			if opts.KeyBits == 0 {
				opts.KeyBits = 2048 // Default RSA key size
			}
		case *algo.ECDSAKeyPair:
			opts.KeyType = "ec"
			if opts.KeyBits == 0 {
				opts.KeyBits = 256 // Default ECDSA key size (P-256)
			}
		case *algo.Ed25519KeyPair:
			opts.KeyType = "ed25519"
			// Ed25519 has fixed key size, no key_bits needed
		}
	}

	reqBody := buildCertificateRequestBody(opts)

	path := fmt.Sprintf("%s/issue/%s", client.config.Mount, role)
	secret, err := client.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: generate certificate: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: generate certificate: empty response")
	}

	return parseCertificateResponse[K](client, secret.Data, true)
}

// ============================================================================
// Issue Certificate - Entry Points (with local key)
// ============================================================================

// IssueRSACertificate issues a certificate using a locally generated RSA key pair.
// The private key never leaves the local system - only a CSR is sent to OpenBao.
//
// Example:
//
//	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
//	certClient, err := client.IssueRSACertificate(ctx, "web-server", keyPair, &GenerateCertificateOptions{
//	    CommonName: "app.example.com",
//	    AltNames:   []string{"www.app.example.com"},
//	    TTL:        "720h",
//	})
func (c *Client) IssueRSACertificate(ctx context.Context, role string, keyPair *algo.RSAKeyPair, opts *GenerateCertificateOptions) (*CertificateClient[*algo.RSAKeyPair], error) {
	return issueCertificateWithKeyPair[*algo.RSAKeyPair](ctx, c, role, keyPair, opts)
}

// IssueECDSACertificate issues a certificate using a locally generated ECDSA key pair.
func (c *Client) IssueECDSACertificate(ctx context.Context, role string, keyPair *algo.ECDSAKeyPair, opts *GenerateCertificateOptions) (*CertificateClient[*algo.ECDSAKeyPair], error) {
	return issueCertificateWithKeyPair[*algo.ECDSAKeyPair](ctx, c, role, keyPair, opts)
}

// IssueEd25519Certificate issues a certificate using a locally generated Ed25519 key pair.
func (c *Client) IssueEd25519Certificate(ctx context.Context, role string, keyPair *algo.Ed25519KeyPair, opts *GenerateCertificateOptions) (*CertificateClient[*algo.Ed25519KeyPair], error) {
	return issueCertificateWithKeyPair[*algo.Ed25519KeyPair](ctx, c, role, keyPair, opts)
}

// issueCertificateWithKeyPair is the internal implementation for issuing certificates with local key pairs.
func issueCertificateWithKeyPair[K keypair.KeyPair](ctx context.Context, client *Client, role string, keyPair K, opts *GenerateCertificateOptions) (*CertificateClient[K], error) {
	if role == "" {
		return nil, fmt.Errorf("bao: role is required")
	}
	if any(keyPair) == nil {
		return nil, fmt.Errorf("bao: key pair is required")
	}
	if opts == nil {
		return nil, fmt.Errorf("bao: options are required")
	}
	if opts.CommonName == "" {
		return nil, fmt.Errorf("bao: common name is required")
	}

	// Create CSR from key pair
	csrRequest := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		DNSNames:    opts.AltNames,
		IPAddresses: parseIPAddresses(opts.IPSANs),
	}

	// Create CSR using type assertions
	var csr *cert.CertificateSigningRequest
	var err error

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		csr, err = cert.CreateCSR(kp, csrRequest)
	case *algo.ECDSAKeyPair:
		csr, err = cert.CreateCSR(kp, csrRequest)
	case *algo.Ed25519KeyPair:
		csr, err = cert.CreateCSR(kp, csrRequest)
	default:
		return nil, fmt.Errorf("bao: unsupported key pair type: %T", keyPair)
	}

	if err != nil {
		return nil, fmt.Errorf("bao: create CSR: %w", err)
	}

	// Sign the CSR
	signOpts := &SignCertificateOptions{
		CommonName:        opts.CommonName,
		AltNames:          opts.AltNames,
		IPSANs:            opts.IPSANs,
		URISANs:           opts.URISANs,
		OtherSANs:         opts.OtherSANs,
		TTL:               opts.TTL,
		Format:            opts.Format,
		ExcludeCNFromSANs: opts.ExcludeCNFromSANs,
		NotAfter:          opts.NotAfter,
	}

	certificate, certInfo, err := client.signCSRInternal(ctx, role, csr, signOpts)
	if err != nil {
		return nil, err
	}

	return &CertificateClient[K]{
		client:      client,
		certificate: certificate,
		certInfo:    certInfo,
		keyPair:     keyPair,
	}, nil
}

// ============================================================================
// Issue Certificate with Key Reference - Entry Points (OpenBao-managed key)
// ============================================================================

// IssueRSACertificateWithKeyRef issues a certificate using an existing RSA key in OpenBao.
// The key is referenced by ID or name and stays securely in OpenBao.
// OpenBao creates the CSR internally and signs the certificate.
//
// The returned CertificateClient does NOT have a cached key pair (HasKeyPair() will be false).
//
// Example:
//
//	// Key already exists in OpenBao
//	keyClient, _ := client.GenerateRSAKey(ctx, &GenerateKeyOptions{KeyName: "my-key"})
//	keyRef := keyClient.KeyInfo().KeyID  // or KeyName
//
//	// Issue certificate using that key
//	certClient, err := client.IssueRSACertificateWithKeyRef(ctx, "web-server", keyRef, &GenerateCertificateOptions{
//	    CommonName: "app.example.com",
//	    AltNames:   []string{"www.app.example.com"},
//	    TTL:        "720h",
//	})
func (c *Client) IssueRSACertificateWithKeyRef(ctx context.Context, role string, keyRef string, opts *GenerateCertificateOptions) (*CertificateClient[*algo.RSAKeyPair], error) {
	return issueCertificateWithKeyRef[*algo.RSAKeyPair](ctx, c, role, keyRef, opts)
}

// IssueECDSACertificateWithKeyRef issues a certificate using an existing ECDSA key in OpenBao.
func (c *Client) IssueECDSACertificateWithKeyRef(ctx context.Context, role string, keyRef string, opts *GenerateCertificateOptions) (*CertificateClient[*algo.ECDSAKeyPair], error) {
	return issueCertificateWithKeyRef[*algo.ECDSAKeyPair](ctx, c, role, keyRef, opts)
}

// IssueEd25519CertificateWithKeyRef issues a certificate using an existing Ed25519 key in OpenBao.
func (c *Client) IssueEd25519CertificateWithKeyRef(ctx context.Context, role string, keyRef string, opts *GenerateCertificateOptions) (*CertificateClient[*algo.Ed25519KeyPair], error) {
	return issueCertificateWithKeyRef[*algo.Ed25519KeyPair](ctx, c, role, keyRef, opts)
}

// issueCertificateWithKeyRef is the internal implementation for issuing certificates with OpenBao-managed keys.
func issueCertificateWithKeyRef[K keypair.KeyPair](ctx context.Context, client *Client, role string, keyRef string, opts *GenerateCertificateOptions) (*CertificateClient[K], error) {
	if role == "" {
		return nil, fmt.Errorf("bao: role is required")
	}
	if keyRef == "" {
		return nil, fmt.Errorf("bao: key reference is required")
	}
	if opts == nil {
		return nil, fmt.Errorf("bao: options are required")
	}
	if opts.CommonName == "" {
		return nil, fmt.Errorf("bao: common name is required")
	}

	// Auto-set key_type and key_bits based on generic type K if not already set
	if opts.KeyType == "" {
		var zero K
		switch any(zero).(type) {
		case *algo.RSAKeyPair:
			opts.KeyType = "rsa"
			if opts.KeyBits == 0 {
				opts.KeyBits = 2048 // Default RSA key size
			}
		case *algo.ECDSAKeyPair:
			opts.KeyType = "ec"
			if opts.KeyBits == 0 {
				opts.KeyBits = 256 // Default ECDSA key size (P-256)
			}
		case *algo.Ed25519KeyPair:
			opts.KeyType = "ed25519"
			// Ed25519 has fixed key size, no key_bits needed
		}
	}

	// Build request body with type="existing" and key_ref
	reqBody := buildCertificateRequestBody(opts)
	reqBody["type"] = "existing"
	reqBody["key_ref"] = keyRef

	path := fmt.Sprintf("%s/issue/%s", client.config.Mount, role)
	secret, err := client.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: issue certificate with key ref: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: issue certificate with key ref: empty response")
	}

	// Parse response WITHOUT private key (key stays in OpenBao)
	return parseCertificateResponse[K](client, secret.Data, false)
}

// ============================================================================
// Sign CSR - Entry Points
// ============================================================================

// SignCSR signs a Certificate Signing Request using OpenBao.
// This allows you to generate the key pair locally and only send the CSR to OpenBao for signing.
//
// Example:
//
//	// Create CSR locally
//	keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{
//	    Subject: pkix.Name{CommonName: "service.example.com"},
//	})
//
//	// Sign with OpenBao
//	certificate, err := client.SignCSR(ctx, "web-server", csr, &SignCertificateOptions{
//	    TTL: "8760h", // 1 year
//	})
func (c *Client) SignCSR(ctx context.Context, role string, csr *cert.CertificateSigningRequest, opts *SignCertificateOptions) (*cert.Certificate, error) {
	certificate, _, err := c.signCSRInternal(ctx, role, csr, opts)
	return certificate, err
}

// signCSRInternal is the internal implementation for CSR signing.
func (c *Client) signCSRInternal(ctx context.Context, role string, csr *cert.CertificateSigningRequest, opts *SignCertificateOptions) (*cert.Certificate, *CertificateInfo, error) {
	if role == "" {
		return nil, nil, fmt.Errorf("bao: role is required")
	}
	if csr == nil {
		return nil, nil, fmt.Errorf("bao: CSR is required")
	}

	reqBody := map[string]interface{}{
		"csr": string(csr.PEMData),
	}

	if opts != nil {
		if opts.CommonName != "" {
			reqBody["common_name"] = opts.CommonName
		}
		if len(opts.AltNames) > 0 {
			reqBody["alt_names"] = joinStrings(opts.AltNames)
		}
		if len(opts.IPSANs) > 0 {
			reqBody["ip_sans"] = joinStrings(opts.IPSANs)
		}
		if len(opts.URISANs) > 0 {
			reqBody["uri_sans"] = joinStrings(opts.URISANs)
		}
		if len(opts.OtherSANs) > 0 {
			reqBody["other_sans"] = joinStrings(opts.OtherSANs)
		}
		if opts.TTL != "" {
			reqBody["ttl"] = opts.TTL
		}
		if opts.Format != "" {
			reqBody["format"] = opts.Format
		}
		if opts.ExcludeCNFromSANs {
			reqBody["exclude_cn_from_sans"] = true
		}
		if opts.NotAfter != "" {
			reqBody["not_after"] = opts.NotAfter
		}
	}

	path := fmt.Sprintf("%s/sign/%s", c.config.Mount, role)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("bao: sign CSR: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil, fmt.Errorf("bao: sign CSR: empty response")
	}

	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("bao: sign CSR: invalid certificate data")
	}

	issuingCAPEM := ""
	if ca, ok := secret.Data["issuing_ca"].(string); ok {
		issuingCAPEM = ca
	}

	certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("bao: sign CSR: %w", err)
	}

	certInfo := extractCertificateInfo(secret.Data)

	return certificate, certInfo, nil
}

// SignVerbatim signs a CSR verbatim without applying role constraints.
// This endpoint signs the CSR as-is, without enforcing role-based policies.
//
// Example:
//
//	csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{...})
//	certificate, err := client.SignVerbatim(ctx, csr, &SignVerbatimOptions{
//	    TTL: "8760h",
//	})
func (c *Client) SignVerbatim(ctx context.Context, csr *cert.CertificateSigningRequest, opts *SignVerbatimOptions) (*cert.Certificate, error) {
	if csr == nil {
		return nil, fmt.Errorf("bao: CSR is required")
	}

	reqBody := map[string]interface{}{
		"csr": string(csr.PEMData),
	}

	if opts != nil {
		if opts.TTL != "" {
			reqBody["ttl"] = opts.TTL
		}
		if opts.Format != "" {
			reqBody["format"] = opts.Format
		}
		if opts.NotAfter != "" {
			reqBody["not_after"] = opts.NotAfter
		}
	}

	path := fmt.Sprintf("%s/sign-verbatim", c.config.Mount)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: sign verbatim: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: sign verbatim: empty response")
	}

	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("bao: sign verbatim: invalid certificate data")
	}

	issuingCAPEM := ""
	if ca, ok := secret.Data["issuing_ca"].(string); ok {
		issuingCAPEM = ca
	}

	certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, fmt.Errorf("bao: sign verbatim: %w", err)
	}

	return certificate, nil
}

// SignSelfIssued signs a self-issued certificate.
// This is used for cross-signing scenarios where an intermediate CA needs to be signed by a different root.
//
// Example:
//
//	certificate, err := client.SignSelfIssued(ctx, selfIssuedCert, &SignSelfIssuedOptions{
//	    RequireMatchingCertificateAlgorithms: true,
//	})
func (c *Client) SignSelfIssued(ctx context.Context, certificate *cert.Certificate, opts *SignSelfIssuedOptions) (*cert.Certificate, error) {
	if certificate == nil {
		return nil, fmt.Errorf("bao: certificate is required")
	}

	reqBody := map[string]interface{}{
		"certificate": string(certificate.PEMData),
	}

	if opts != nil && opts.RequireMatchingCertificateAlgorithms {
		reqBody["require_matching_certificate_algorithms"] = true
	}

	path := fmt.Sprintf("%s/sign-self-issued", c.config.Mount)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: sign self-issued: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: sign self-issued: empty response")
	}

	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("bao: sign self-issued: invalid certificate data")
	}

	issuingCAPEM := ""
	if ca, ok := secret.Data["issuing_ca"].(string); ok {
		issuingCAPEM = ca
	}

	signedCert, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, fmt.Errorf("bao: sign self-issued: %w", err)
	}

	return signedCert, nil
}

// ============================================================================
// Sign CSR with Key Reference - Entry Points
// ============================================================================

// SignCSRWithKeyRef signs a CSR using a specific key reference in OpenBao.
// The key is referenced by ID or name and used for signing the CSR.
//
// Example:
//
//	keyClient, _ := client.GetRSAKey(ctx, "my-signing-key")
//	keyRef := keyClient.KeyInfo().KeyID
//
//	csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{...})
//	certificate, err := client.SignCSRWithKeyRef(ctx, "web-server", csr, keyRef, &SignCertificateOptions{
//	    TTL: "8760h",
//	})
func (c *Client) SignCSRWithKeyRef(ctx context.Context, role string, csr *cert.CertificateSigningRequest, keyRef string, opts *SignCertificateOptions) (*cert.Certificate, error) {
	if role == "" {
		return nil, fmt.Errorf("bao: role is required")
	}
	if csr == nil {
		return nil, fmt.Errorf("bao: CSR is required")
	}
	if keyRef == "" {
		return nil, fmt.Errorf("bao: key reference is required")
	}

	reqBody := map[string]interface{}{
		"csr":     string(csr.PEMData),
		"key_ref": keyRef,
	}

	if opts != nil {
		if opts.CommonName != "" {
			reqBody["common_name"] = opts.CommonName
		}
		if len(opts.AltNames) > 0 {
			reqBody["alt_names"] = joinStrings(opts.AltNames)
		}
		if len(opts.IPSANs) > 0 {
			reqBody["ip_sans"] = joinStrings(opts.IPSANs)
		}
		if len(opts.URISANs) > 0 {
			reqBody["uri_sans"] = joinStrings(opts.URISANs)
		}
		if len(opts.OtherSANs) > 0 {
			reqBody["other_sans"] = joinStrings(opts.OtherSANs)
		}
		if opts.TTL != "" {
			reqBody["ttl"] = opts.TTL
		}
		if opts.Format != "" {
			reqBody["format"] = opts.Format
		}
		if opts.ExcludeCNFromSANs {
			reqBody["exclude_cn_from_sans"] = true
		}
		if opts.NotAfter != "" {
			reqBody["not_after"] = opts.NotAfter
		}
	}

	path := fmt.Sprintf("%s/sign/%s", c.config.Mount, role)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: sign CSR with key ref: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: sign CSR with key ref: empty response")
	}

	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("bao: sign CSR with key ref: invalid certificate data")
	}

	issuingCAPEM := ""
	if ca, ok := secret.Data["issuing_ca"].(string); ok {
		issuingCAPEM = ca
	}

	certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, fmt.Errorf("bao: sign CSR with key ref: %w", err)
	}

	return certificate, nil
}

// SignVerbatimWithKeyRef signs a CSR verbatim using a specific key reference in OpenBao.
// This bypasses role constraints and signs the CSR as-is.
//
// Example:
//
//	keyRef := "my-ca-key"
//	csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{...})
//	certificate, err := client.SignVerbatimWithKeyRef(ctx, csr, keyRef, &SignVerbatimOptions{
//	    TTL: "8760h",
//	})
func (c *Client) SignVerbatimWithKeyRef(ctx context.Context, csr *cert.CertificateSigningRequest, keyRef string, opts *SignVerbatimOptions) (*cert.Certificate, error) {
	if csr == nil {
		return nil, fmt.Errorf("bao: CSR is required")
	}
	if keyRef == "" {
		return nil, fmt.Errorf("bao: key reference is required")
	}

	reqBody := map[string]interface{}{
		"csr":     string(csr.PEMData),
		"key_ref": keyRef,
	}

	if opts != nil {
		if opts.TTL != "" {
			reqBody["ttl"] = opts.TTL
		}
		if opts.Format != "" {
			reqBody["format"] = opts.Format
		}
		if opts.NotAfter != "" {
			reqBody["not_after"] = opts.NotAfter
		}
	}

	path := fmt.Sprintf("%s/sign-verbatim", c.config.Mount)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: sign verbatim with key ref: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: sign verbatim with key ref: empty response")
	}

	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("bao: sign verbatim with key ref: invalid certificate data")
	}

	issuingCAPEM := ""
	if ca, ok := secret.Data["issuing_ca"].(string); ok {
		issuingCAPEM = ca
	}

	certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, fmt.Errorf("bao: sign verbatim with key ref: %w", err)
	}

	return certificate, nil
}

// ============================================================================
// Helper functions
// ============================================================================

// buildCertificateRequestBody constructs the request body for certificate generation.
func buildCertificateRequestBody(opts *GenerateCertificateOptions) map[string]interface{} {
	reqBody := map[string]interface{}{
		"common_name": opts.CommonName,
	}

	if len(opts.AltNames) > 0 {
		reqBody["alt_names"] = joinStrings(opts.AltNames)
	}
	if len(opts.IPSANs) > 0 {
		reqBody["ip_sans"] = joinStrings(opts.IPSANs)
	}
	if len(opts.URISANs) > 0 {
		reqBody["uri_sans"] = joinStrings(opts.URISANs)
	}
	if len(opts.OtherSANs) > 0 {
		reqBody["other_sans"] = joinStrings(opts.OtherSANs)
	}
	if opts.TTL != "" {
		reqBody["ttl"] = opts.TTL
	}
	if opts.Format != "" {
		reqBody["format"] = opts.Format
	}
	if opts.PrivateKeyFormat != "" {
		reqBody["private_key_format"] = opts.PrivateKeyFormat
	}
	if opts.ExcludeCNFromSANs {
		reqBody["exclude_cn_from_sans"] = true
	}
	if opts.NotAfter != "" {
		reqBody["not_after"] = opts.NotAfter
	}
	if opts.KeyType != "" {
		reqBody["key_type"] = opts.KeyType
	}
	if opts.KeyBits > 0 {
		reqBody["key_bits"] = opts.KeyBits
	}

	return reqBody
}

// parseCertificateResponse parses OpenBao certificate response and constructs a CertificateClient.
func parseCertificateResponse[K keypair.KeyPair](client *Client, data map[string]interface{}, hasPrivateKey bool) (*CertificateClient[K], error) {
	certificatePEM, ok := data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("bao: invalid certificate data")
	}

	issuingCAPEM := ""
	if ca, ok := data["issuing_ca"].(string); ok {
		issuingCAPEM = ca
	}

	certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, fmt.Errorf("bao: parse certificate: %w", err)
	}

	certInfo := extractCertificateInfo(data)

	certClient := &CertificateClient[K]{
		client:      client,
		certificate: certificate,
		certInfo:    certInfo,
	}

	// Parse private key if present
	if hasPrivateKey {
		privateKeyPEM, ok := data["private_key"].(string)
		if !ok || privateKeyPEM == "" {
			return certClient, nil // Return without key pair if not present
		}

		keyPair, err := parsePrivateKeyPEM[K](privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("bao: parse private key: %w", err)
		}
		certClient.keyPair = keyPair
	}

	return certClient, nil
}

// parsePrivateKeyPEM parses a PEM-encoded private key and returns the appropriate KeyPair type.
func parsePrivateKeyPEM[K keypair.KeyPair](pemData string) (K, error) {
	var zero K

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return zero, fmt.Errorf("failed to decode PEM")
	}

	// Try parsing as different key types
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 for RSA
		rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if rsaErr == nil {
			keyPair := &algo.RSAKeyPair{
				PrivateKey: rsaKey,
				PublicKey:  &rsaKey.PublicKey,
			}
			return any(keyPair).(K), nil
		}

		// Try EC private key
		ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
		if ecErr == nil {
			keyPair := &algo.ECDSAKeyPair{
				PrivateKey: ecKey,
				PublicKey:  &ecKey.PublicKey,
			}
			return any(keyPair).(K), nil
		}

		return zero, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Successfully parsed as PKCS8, determine type
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		keyPair := &algo.RSAKeyPair{
			PrivateKey: key,
			PublicKey:  &key.PublicKey,
		}
		return any(keyPair).(K), nil
	case *ecdsa.PrivateKey:
		keyPair := &algo.ECDSAKeyPair{
			PrivateKey: key,
			PublicKey:  &key.PublicKey,
		}
		return any(keyPair).(K), nil
	case ed25519.PrivateKey:
		publicKey := key.Public().(ed25519.PublicKey)
		keyPair := &algo.Ed25519KeyPair{
			PrivateKey: key,
			PublicKey:  publicKey,
		}
		return any(keyPair).(K), nil
	default:
		return zero, fmt.Errorf("unsupported private key type: %T", key)
	}
}

// extractCertificateInfo extracts certificate metadata from OpenBao response.
func extractCertificateInfo(data map[string]interface{}) *CertificateInfo {
	info := &CertificateInfo{}

	if serial, ok := data["serial_number"].(string); ok {
		info.SerialNumber = serial
	}

	if exp, ok := data["expiration"].(float64); ok {
		info.Expiration = time.Unix(int64(exp), 0)
	} else if exp, ok := data["expiration"].(int64); ok {
		info.Expiration = time.Unix(exp, 0)
	}

	return info
}

// parseIPAddresses converts string IP addresses to net.IP.
func parseIPAddresses(ipStrings []string) []net.IP {
	var ips []net.IP
	for _, ipStr := range ipStrings {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// joinStrings joins a slice of strings with commas.
func joinStrings(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += "," + strs[i]
	}
	return result
}
