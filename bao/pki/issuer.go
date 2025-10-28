package pki

import (
	"context"
	"fmt"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

// ============================================================================
// Types & Structs
// ============================================================================

// CAOptions contains parameters for generating a CA certificate (root or intermediate).
type CAOptions struct {
	Type                string   // "internal" (OpenBao generates key) or "exported" (returns private key/CSR)
	CommonName          string   // Required
	Organization        []string // Optional
	Country             []string // Optional
	Locality            []string // Optional
	Province            []string // Optional
	StreetAddress       []string // Optional
	PostalCode          []string // Optional
	TTL                 string   // Time to live (e.g., "8760h" for 1 year)
	KeyType             string   // "rsa", "ec", "ed25519"
	KeyBits             int      // Key size (RSA: 2048/3072/4096, EC: 224/256/384/521)
	MaxPathLength       int      // Max depth of intermediate CAs (-1 = no limit, 0 = can only sign end-entity certs)
	ExcludeCNFromSANs   bool     // Exclude CN from SANs
	PermittedDNSDomains []string // Permitted DNS domains
	URISANs             []string // URI SANs
	IPSANs              []string // IP SANs
	AltNames            []string // DNS SANs
	IssuerName          string   // Name for the issuer
	KeyName             string   // Name for the key
	ManagedKeyName      string   // Name of managed key to use
	ManagedKeyID        string   // ID of managed key to use
	AddBasicConstraints bool     // Add basic constraints (for intermediate CAs)
}

// IssuerConfig contains configuration for updating an issuer.
type IssuerConfig struct {
	IssuerName                   string   // Issuer name
	LeafNotAfterBehavior         string   // "err", "truncate", "permit"
	Usage                        string   // Comma-separated: "read-only,issuing-certificates,crl-signing,ocsp-signing"
	RevocationSignatureAlgorithm string   // Signature algorithm
	IssuingCertificates          []string // Issuing certificate URLs
	CRLDistributionPoints        []string // CRL distribution point URLs
	OCSPServers                  []string // OCSP server URLs
	EnableAIAURLTemplating       bool     // Enable AIA URL templating
	ManualChain                  []string // Manual chain (issuer IDs)
}

// CABundle contains a CA certificate bundle for import.
type CABundle struct {
	PEMBundle string // PEM bundle containing certificate(s) and optionally private key
}

// GenerateCAResponse contains the response from generating a CA.
type GenerateCAResponse struct {
	Certificate    *cert.Certificate // Generated certificate
	IssuingCA      string            // Issuing CA certificate (PEM)
	CAChain        []string          // CA chain (PEM)
	SerialNumber   string            // Certificate serial number
	IssuerID       string            // Issuer UUID
	KeyID          string            // Key UUID
	PrivateKey     string            // Private key (only for "exported" type)
	PrivateKeyType string            // Private key type
	CSR            string            // CSR (only for "exported" intermediate)
}

// IssuerClient wraps an issuer and provides methods for managing it.
type IssuerClient struct {
	client *Client
	info   *IssuerInfo
}

// ============================================================================
// IssuerClient Methods
// ============================================================================

// ID returns the issuer ID.
func (ic *IssuerClient) ID() string {
	return ic.info.IssuerID
}

// Name returns the issuer name.
func (ic *IssuerClient) Name() string {
	return ic.info.IssuerName
}

// KeyID returns the key ID associated with this issuer.
func (ic *IssuerClient) KeyID() string {
	return ic.info.KeyID
}

// Certificate returns the issuer's certificate.
func (ic *IssuerClient) Certificate() (*cert.Certificate, error) {
	if ic.info.Certificate == "" {
		return nil, fmt.Errorf("bao: no certificate available")
	}
	return vaultCertToGoPKI(ic.info.Certificate, "")
}

// Info returns the complete issuer information.
func (ic *IssuerClient) Info() *IssuerInfo {
	return ic.info
}

// Update updates this issuer's configuration.
func (ic *IssuerClient) Update(ctx context.Context, config *IssuerConfig) error {
	return ic.client.UpdateIssuer(ctx, ic.info.IssuerID, config)
}

// Delete deletes this issuer from OpenBao.
func (ic *IssuerClient) Delete(ctx context.Context) error {
	return ic.client.DeleteIssuer(ctx, ic.info.IssuerID)
}

// SetAsDefault sets this issuer as the default issuer.
func (ic *IssuerClient) SetAsDefault(ctx context.Context) error {
	return ic.client.SetDefaultIssuer(ctx, ic.info.IssuerID)
}

// UpdateName updates the issuer's name.
func (ic *IssuerClient) UpdateName(ctx context.Context, name string) error {
	config := &IssuerConfig{
		IssuerName: name,
	}
	err := ic.Update(ctx, config)
	if err == nil {
		ic.info.IssuerName = name
	}
	return err
}

// UpdateUsage updates the issuer's usage.
func (ic *IssuerClient) UpdateUsage(ctx context.Context, usage string) error {
	config := &IssuerConfig{
		Usage: usage,
	}
	return ic.Update(ctx, config)
}

// AddIssuingCertificateURL adds an issuing certificate URL.
func (ic *IssuerClient) AddIssuingCertificateURL(ctx context.Context, url string) error {
	urls := append(ic.info.IssuingCertificates, url)
	config := &IssuerConfig{
		IssuingCertificates: urls,
	}
	err := ic.Update(ctx, config)
	if err == nil {
		ic.info.IssuingCertificates = urls
	}
	return err
}

// AddCRLDistributionPoint adds a CRL distribution point URL.
func (ic *IssuerClient) AddCRLDistributionPoint(ctx context.Context, url string) error {
	urls := append(ic.info.CRLDistributionPoints, url)
	config := &IssuerConfig{
		CRLDistributionPoints: urls,
	}
	err := ic.Update(ctx, config)
	if err == nil {
		ic.info.CRLDistributionPoints = urls
	}
	return err
}

// AddOCSPServer adds an OCSP server URL.
func (ic *IssuerClient) AddOCSPServer(ctx context.Context, url string) error {
	urls := append(ic.info.OCSPServers, url)
	config := &IssuerConfig{
		OCSPServers: urls,
	}
	err := ic.Update(ctx, config)
	if err == nil {
		ic.info.OCSPServers = urls
	}
	return err
}

// CreateRole creates a new role configured to use this issuer.
// This is a convenience method that links IssuerClient with RoleClient.
//
// The role's IssuerRef is automatically set to this issuer's ID.
//
// Example:
//
//	issuer, _ := client.GetIssuer(ctx, "my-ca")
//	role, err := issuer.CreateRole(ctx, "web-server", &RoleOptions{
//	    AllowedDomains: []string{"example.com"},
//	    AllowSubdomains: true,
//	    TTL: "720h",
//	})
func (ic *IssuerClient) CreateRole(ctx context.Context, name string, opts *RoleOptions) (*RoleClient, error) {
	if opts == nil {
		opts = &RoleOptions{}
	}

	// Set issuer ref to this issuer's ID
	opts.IssuerRef = ic.ID()

	// Create the role
	err := ic.client.CreateRole(ctx, name, opts)
	if err != nil {
		return nil, fmt.Errorf("bao: create role for issuer: %w", err)
	}

	// Return role client
	return ic.client.GetRole(ctx, name)
}

// IssueRSACertificate issues an RSA certificate using this issuer.
// A temporary role may be created if no default role exists for this issuer.
//
// Example:
//
//	issuer, _ := client.GetIssuer(ctx, "my-ca")
//	certClient, err := issuer.IssueRSACertificate(ctx, "my-rsa-key", &GenerateCertificateOptions{
//	    CommonName: "app.example.com",
//	    TTL:        "720h",
//	})
func (ic *IssuerClient) IssueRSACertificate(ctx context.Context, keyRef string, opts *GenerateCertificateOptions) (*CertificateClient[*algo.RSAKeyPair], error) {
	// Get or create a default role for this issuer
	roleName, err := ic.getOrCreateDefaultRole(ctx)
	if err != nil {
		return nil, fmt.Errorf("bao: get default role for issuer: %w", err)
	}

	return ic.client.IssueRSACertificateWithKeyRef(ctx, roleName, keyRef, opts)
}

// IssueECDSACertificate issues an ECDSA certificate using this issuer.
// A temporary role may be created if no default role exists for this issuer.
//
// Example:
//
//	issuer, _ := client.GetIssuer(ctx, "my-ca")
//	certClient, err := issuer.IssueECDSACertificate(ctx, "my-ec-key", &GenerateCertificateOptions{
//	    CommonName: "app.example.com",
//	    TTL:        "720h",
//	})
func (ic *IssuerClient) IssueECDSACertificate(ctx context.Context, keyRef string, opts *GenerateCertificateOptions) (*CertificateClient[*algo.ECDSAKeyPair], error) {
	// Get or create a default role for this issuer
	roleName, err := ic.getOrCreateDefaultRole(ctx)
	if err != nil {
		return nil, fmt.Errorf("bao: get default role for issuer: %w", err)
	}

	return ic.client.IssueECDSACertificateWithKeyRef(ctx, roleName, keyRef, opts)
}

// IssueEd25519Certificate issues an Ed25519 certificate using this issuer.
// A temporary role may be created if no default role exists for this issuer.
//
// Example:
//
//	issuer, _ := client.GetIssuer(ctx, "my-ca")
//	certClient, err := issuer.IssueEd25519Certificate(ctx, "my-ed25519-key", &GenerateCertificateOptions{
//	    CommonName: "app.example.com",
//	    TTL:        "720h",
//	})
func (ic *IssuerClient) IssueEd25519Certificate(ctx context.Context, keyRef string, opts *GenerateCertificateOptions) (*CertificateClient[*algo.Ed25519KeyPair], error) {
	// Get or create a default role for this issuer
	roleName, err := ic.getOrCreateDefaultRole(ctx)
	if err != nil {
		return nil, fmt.Errorf("bao: get default role for issuer: %w", err)
	}

	return ic.client.IssueEd25519CertificateWithKeyRef(ctx, roleName, keyRef, opts)
}

// SignCSR signs a CSR using this issuer.
// A temporary role may be created if no default role exists for this issuer.
//
// Example:
//
//	issuer, _ := client.GetIssuer(ctx, "my-ca")
//	csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{...})
//	certificate, err := issuer.SignCSR(ctx, csr, &SignCertificateOptions{
//	    TTL: "8760h",
//	})
func (ic *IssuerClient) SignCSR(ctx context.Context, csr *cert.CertificateSigningRequest, opts *SignCertificateOptions) (*cert.Certificate, error) {
	// Get or create a default role for this issuer
	roleName, err := ic.getOrCreateDefaultRole(ctx)
	if err != nil {
		return nil, fmt.Errorf("bao: get default role for issuer: %w", err)
	}

	return ic.client.SignCSR(ctx, roleName, csr, opts)
}

// getOrCreateDefaultRole gets or creates a default role for this issuer.
// It looks for a role named "issuer-<issuer-name>-default" or creates one if it doesn't exist.
func (ic *IssuerClient) getOrCreateDefaultRole(ctx context.Context) (string, error) {
	roleName := fmt.Sprintf("issuer-%s-default", ic.Name())

	// Try to get existing role
	role, err := ic.client.GetRole(ctx, roleName)
	if err == nil && role != nil {
		return roleName, nil
	}

	// Create default role
	// Note: KeyType is not set, allowing OpenBao to accept key_type from the request
	defaultOpts := &RoleOptions{
		IssuerRef:           ic.ID(),
		TTL:                 "8760h",
		MaxTTL:              "8760h",
		AllowAnyName:        true,
		AllowIPSANs:         true,
		AllowSubdomains:     true,
		AllowBareDomains:    true,
		ServerFlag:          true,
		ClientFlag:          true,
		CodeSigningFlag:     true,
		EmailProtectionFlag: true,
	}

	err = ic.client.CreateRole(ctx, roleName, defaultOpts)
	if err != nil {
		return "", fmt.Errorf("bao: create default role for issuer: %w", err)
	}

	return roleName, nil
}

// ============================================================================
// CAOptionsBuilder - Builder Pattern for CA Configuration
// ============================================================================

// CAOptionsBuilder provides a fluent API for building CAOptions.
type CAOptionsBuilder struct {
	opts *CAOptions
}

// NewRootCABuilder creates a new builder for root CA options.
func NewRootCABuilder(commonName string) *CAOptionsBuilder {
	return &CAOptionsBuilder{
		opts: &CAOptions{
			CommonName: commonName,
			Type:       "internal",
		},
	}
}

// NewIntermediateCABuilder creates a new builder for intermediate CA options.
func NewIntermediateCABuilder(commonName string) *CAOptionsBuilder {
	return &CAOptionsBuilder{
		opts: &CAOptions{
			CommonName:          commonName,
			Type:                "internal",
			AddBasicConstraints: true,
		},
	}
}

// WithOrganization sets the organization.
func (b *CAOptionsBuilder) WithOrganization(org ...string) *CAOptionsBuilder {
	b.opts.Organization = org
	return b
}

// WithCountry sets the country.
func (b *CAOptionsBuilder) WithCountry(country ...string) *CAOptionsBuilder {
	b.opts.Country = country
	return b
}

// WithLocality sets the locality.
func (b *CAOptionsBuilder) WithLocality(locality ...string) *CAOptionsBuilder {
	b.opts.Locality = locality
	return b
}

// WithProvince sets the province.
func (b *CAOptionsBuilder) WithProvince(province ...string) *CAOptionsBuilder {
	b.opts.Province = province
	return b
}

// WithTTL sets the TTL.
func (b *CAOptionsBuilder) WithTTL(ttl string) *CAOptionsBuilder {
	b.opts.TTL = ttl
	return b
}

// WithKeyType sets the key type and bits.
func (b *CAOptionsBuilder) WithKeyType(keyType string, bits int) *CAOptionsBuilder {
	b.opts.KeyType = keyType
	b.opts.KeyBits = bits
	return b
}

// WithMaxPathLength sets the maximum path length for certificate chains.
func (b *CAOptionsBuilder) WithMaxPathLength(length int) *CAOptionsBuilder {
	b.opts.MaxPathLength = length
	return b
}

// WithIssuerName sets the issuer name.
func (b *CAOptionsBuilder) WithIssuerName(name string) *CAOptionsBuilder {
	b.opts.IssuerName = name
	return b
}

// WithKeyName sets the key name.
func (b *CAOptionsBuilder) WithKeyName(name string) *CAOptionsBuilder {
	b.opts.KeyName = name
	return b
}

// WithPermittedDNSDomains sets permitted DNS domains.
func (b *CAOptionsBuilder) WithPermittedDNSDomains(domains ...string) *CAOptionsBuilder {
	b.opts.PermittedDNSDomains = domains
	return b
}

// WithAltNames sets alternative names.
func (b *CAOptionsBuilder) WithAltNames(names ...string) *CAOptionsBuilder {
	b.opts.AltNames = names
	return b
}

// AsExported sets the type to "exported" (returns private key).
func (b *CAOptionsBuilder) AsExported() *CAOptionsBuilder {
	b.opts.Type = "exported"
	return b
}

// Build returns the built CAOptions.
func (b *CAOptionsBuilder) Build() *CAOptions {
	return b.opts
}

// ============================================================================
// Internal Types for API Responses
// ============================================================================

// vaultGenerateCAResponse represents OpenBao's response from generate endpoints.
type vaultGenerateCAResponse struct {
	Data struct {
		Certificate    string   `json:"certificate"`
		IssuingCA      string   `json:"issuing_ca"`
		CAChain        []string `json:"ca_chain"`
		SerialNumber   string   `json:"serial_number"`
		IssuerID       string   `json:"issuer_id"`
		KeyID          string   `json:"key_id"`
		PrivateKey     string   `json:"private_key,omitempty"`
		PrivateKeyType string   `json:"private_key_type,omitempty"`
		CSR            string   `json:"csr,omitempty"`
	} `json:"data"`
}

// vaultIssuerResponse represents OpenBao's response from issuer endpoints.
type vaultIssuerResponse struct {
	Data struct {
		IssuerID                     string   `json:"issuer_id"`
		IssuerName                   string   `json:"issuer_name"`
		KeyID                        string   `json:"key_id"`
		Certificate                  string   `json:"certificate"`
		CAChain                      []string `json:"ca_chain"`
		ManualChain                  []string `json:"manual_chain"`
		LeafNotAfterBehavior         string   `json:"leaf_not_after_behavior"`
		Usage                        string   `json:"usage"`
		RevocationSignatureAlgorithm string   `json:"revocation_signature_algorithm"`
		IssuingCertificates          []string `json:"issuing_certificates"`
		CRLDistributionPoints        []string `json:"crl_distribution_points"`
		OCSPServers                  []string `json:"ocsp_servers"`
		EnableAIAURLTemplating       bool     `json:"enable_aia_url_templating"`
	} `json:"data"`
}

// vaultListResponse represents Vault's response from list endpoints.
type vaultListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

// GenerateRootCA generates a self-signed root CA certificate in Vault.
// The type can be "internal" (Vault generates and stores the key) or "exported" (returns private key).
//
// Example:
//
//	rootCA, err := client.GenerateRootCA(ctx, &vault.CAOptions{
//	    Type:         "internal",
//	    CommonName:   "Example Root CA",
//	    Organization: []string{"Example Org"},
//	    Country:      []string{"US"},
//	    TTL:          "87600h", // 10 years
//	    KeyType:      "rsa",
//	    KeyBits:      4096,
//	})
func (c *Client) GenerateRootCA(ctx context.Context, opts *CAOptions) (*GenerateCAResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("bao: CA options are required")
	}
	if opts.CommonName == "" {
		return nil, fmt.Errorf("bao: common name is required")
	}
	if opts.Type == "" {
		opts.Type = "internal" // Default to internal
	}
	if opts.Type != "internal" && opts.Type != "exported" {
		return nil, fmt.Errorf("bao: type must be 'internal' or 'exported', got '%s'", opts.Type)
	}

	// Build request body
	reqBody := buildCARequestBody(opts)

	// Use SDK to generate root CA
	path := fmt.Sprintf("%s/root/generate/%s", c.config.Mount, opts.Type)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: generate root CA: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: generate root CA: empty response")
	}

	// Extract response data
	certificatePEM, _ := secret.Data["certificate"].(string)
	issuingCAPEM, _ := secret.Data["issuing_ca"].(string)
	serialNumber, _ := secret.Data["serial_number"].(string)
	issuerID, _ := secret.Data["issuer_id"].(string)
	keyID, _ := secret.Data["key_id"].(string)
	privateKey, _ := secret.Data["private_key"].(string)
	privateKeyType, _ := secret.Data["private_key_type"].(string)

	// Extract CA chain
	var caChain []string
	if chainData, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, item := range chainData {
			if certStr, ok := item.(string); ok {
				caChain = append(caChain, certStr)
			}
		}
	}

	// Convert certificate
	certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, fmt.Errorf("bao: generate root CA: %w", err)
	}

	return &GenerateCAResponse{
		Certificate:    certificate,
		IssuingCA:      issuingCAPEM,
		CAChain:        caChain,
		SerialNumber:   serialNumber,
		IssuerID:       issuerID,
		KeyID:          keyID,
		PrivateKey:     privateKey,
		PrivateKeyType: privateKeyType,
	}, nil
}

// GenerateIntermediateCA generates an intermediate CA certificate.
// The type can be "internal" (Vault generates and stores the key) or "exported" (returns CSR).
//
// For "internal" type, the intermediate CA is generated and signed immediately.
// For "exported" type, a CSR is returned which must be signed separately.
//
// Example:
//
//	intermediate, err := client.GenerateIntermediateCA(ctx, &bao.CAOptions{
//	    Type:                "internal",
//	    CommonName:          "Example Intermediate CA",
//	    Organization:        []string{"Example Org"},
//	    TTL:                 "43800h", // 5 years
//	    KeyType:             "rsa",
//	    KeyBits:             2048,
//	    AddBasicConstraints: true,
//	})
func (c *Client) GenerateIntermediateCA(ctx context.Context, opts *CAOptions) (*GenerateCAResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("bao: intermediate CA options are required")
	}
	if opts.CommonName == "" {
		return nil, fmt.Errorf("bao: common name is required")
	}
	if opts.Type == "" {
		opts.Type = "internal" // Default to internal
	}
	if opts.Type != "internal" && opts.Type != "exported" {
		return nil, fmt.Errorf("bao: type must be 'internal' or 'exported', got '%s'", opts.Type)
	}

	// Build request body
	reqBody := buildCARequestBody(opts)

	// Use SDK to generate intermediate CA
	path := fmt.Sprintf("%s/intermediate/generate/%s", c.config.Mount, opts.Type)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: generate intermediate CA: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: generate intermediate CA: empty response")
	}

	// Extract response data
	certificatePEM, _ := secret.Data["certificate"].(string)
	issuingCAPEM, _ := secret.Data["issuing_ca"].(string)
	serialNumber, _ := secret.Data["serial_number"].(string)
	issuerID, _ := secret.Data["issuer_id"].(string)
	keyID, _ := secret.Data["key_id"].(string)
	privateKey, _ := secret.Data["private_key"].(string)
	privateKeyType, _ := secret.Data["private_key_type"].(string)
	csr, _ := secret.Data["csr"].(string)

	// Extract CA chain
	var caChain []string
	if chainData, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, item := range chainData {
			if certStr, ok := item.(string); ok {
				caChain = append(caChain, certStr)
			}
		}
	}

	response := &GenerateCAResponse{
		SerialNumber:   serialNumber,
		IssuerID:       issuerID,
		KeyID:          keyID,
		PrivateKey:     privateKey,
		PrivateKeyType: privateKeyType,
		CSR:            csr,
		IssuingCA:      issuingCAPEM,
		CAChain:        caChain,
	}

	// For exported type, CSR is returned instead of certificate
	if opts.Type == "exported" {
		return response, nil
	}

	// For internal type, certificate is returned
	if certificatePEM != "" {
		certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
		if err != nil {
			return nil, fmt.Errorf("bao: generate intermediate CA: %w", err)
		}
		response.Certificate = certificate
	}

	return response, nil
}

// SignIntermediateCSR signs an intermediate CA CSR using the root CA.
//
// Example:
//
//	certificate, err := client.SignIntermediateCSR(ctx, csr, &vault.CAOptions{
//	    CommonName: "Example Intermediate CA",
//	    TTL:        "43800h", // 5 years
//	})
func (c *Client) SignIntermediateCSR(ctx context.Context, csr *cert.CertificateSigningRequest, opts *CAOptions) (*cert.Certificate, error) {
	if csr == nil {
		return nil, fmt.Errorf("bao: CSR is required")
	}
	if opts == nil {
		opts = &CAOptions{}
	}

	// Build request body
	reqBody := map[string]interface{}{
		"csr": string(csr.PEMData),
	}

	// Add optional fields
	if opts.CommonName != "" {
		reqBody["common_name"] = opts.CommonName
	}
	if opts.TTL != "" {
		reqBody["ttl"] = opts.TTL
	}
	if opts.MaxPathLength >= 0 {
		reqBody["max_path_length"] = opts.MaxPathLength
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
	if opts.ExcludeCNFromSANs {
		reqBody["exclude_cn_from_sans"] = true
	}

	// Use SDK to sign intermediate CSR
	path := fmt.Sprintf("%s/root/sign-intermediate", c.config.Mount)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: sign intermediate CSR: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: sign intermediate CSR: empty response")
	}

	// Extract certificate data
	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("bao: sign intermediate CSR: invalid certificate data")
	}
	issuingCAPEM, _ := secret.Data["issuing_ca"].(string)

	// Convert certificate
	certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, fmt.Errorf("bao: sign intermediate CSR: %w", err)
	}

	return certificate, nil
}

// ImportCA imports an existing CA bundle into Vault.
// The bundle should contain the certificate and optionally the private key in PEM format.
//
// Example:
//
//	issuerInfo, err := client.ImportCA(ctx, &vault.CABundle{
//	    PEMBundle: certificatePEM + privateKeyPEM,
//	})
func (c *Client) ImportCA(ctx context.Context, bundle *CABundle) (*IssuerClient, error) {
	if bundle == nil || bundle.PEMBundle == "" {
		return nil, fmt.Errorf("bao: CA bundle is required")
	}

	// Build request body
	reqBody := map[string]interface{}{
		"pem_bundle": bundle.PEMBundle,
	}

	// Use SDK to import CA
	path := fmt.Sprintf("%s/config/ca", c.config.Mount)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("bao: import CA: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: import CA: empty response")
	}

	// Extract imported issuers
	importedIssuers := []string{}
	if issuersData, ok := secret.Data["imported_issuers"].([]interface{}); ok {
		for _, item := range issuersData {
			if issuerStr, ok := item.(string); ok {
				importedIssuers = append(importedIssuers, issuerStr)
			}
		}
	}

	// Get the first imported issuer
	if len(importedIssuers) == 0 {
		return nil, fmt.Errorf("bao: no issuers imported")
	}

	issuerID := importedIssuers[0]

	// Retrieve issuer details
	issuerClient, err := c.GetIssuer(ctx, issuerID)
	if err != nil {
		return nil, fmt.Errorf("bao: import CA: %w", err)
	}

	return issuerClient, nil
}

// GetIssuer retrieves issuer information by ID or name and returns an IssuerClient.
//
// Example:
//
//	issuerClient, err := client.GetIssuer(ctx, "issuer-id-or-name")
//	cert := issuerClient.Certificate()
func (c *Client) GetIssuer(ctx context.Context, issuerRef string) (*IssuerClient, error) {
	if issuerRef == "" {
		return nil, fmt.Errorf("bao: issuer reference is required")
	}

	// Use SDK to get issuer
	path := fmt.Sprintf("%s/issuer/%s", c.config.Mount, issuerRef)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: get issuer: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: get issuer: not found")
	}

	// Extract issuer data with type assertions
	issuerID, _ := secret.Data["issuer_id"].(string)
	issuerName, _ := secret.Data["issuer_name"].(string)
	keyID, _ := secret.Data["key_id"].(string)
	certificate, _ := secret.Data["certificate"].(string)
	leafNotAfterBehavior, _ := secret.Data["leaf_not_after_behavior"].(string)
	usage, _ := secret.Data["usage"].(string)
	revocationSignatureAlgorithm, _ := secret.Data["revocation_signature_algorithm"].(string)
	enableAIAURLTemplating, _ := secret.Data["enable_aia_url_templating"].(bool)

	// Extract array fields
	var caChain, manualChain, issuingCertificates, crlDistributionPoints, ocspServers []string

	if data, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, item := range data {
			if str, ok := item.(string); ok {
				caChain = append(caChain, str)
			}
		}
	}
	if data, ok := secret.Data["manual_chain"].([]interface{}); ok {
		for _, item := range data {
			if str, ok := item.(string); ok {
				manualChain = append(manualChain, str)
			}
		}
	}
	if data, ok := secret.Data["issuing_certificates"].([]interface{}); ok {
		for _, item := range data {
			if str, ok := item.(string); ok {
				issuingCertificates = append(issuingCertificates, str)
			}
		}
	}
	if data, ok := secret.Data["crl_distribution_points"].([]interface{}); ok {
		for _, item := range data {
			if str, ok := item.(string); ok {
				crlDistributionPoints = append(crlDistributionPoints, str)
			}
		}
	}
	if data, ok := secret.Data["ocsp_servers"].([]interface{}); ok {
		for _, item := range data {
			if str, ok := item.(string); ok {
				ocspServers = append(ocspServers, str)
			}
		}
	}

	issuerInfo := &IssuerInfo{
		IssuerID:                     issuerID,
		IssuerName:                   issuerName,
		KeyID:                        keyID,
		Certificate:                  certificate,
		CAChain:                      caChain,
		ManualChain:                  manualChain,
		LeafNotAfterBehavior:         leafNotAfterBehavior,
		Usage:                        usage,
		RevocationSignatureAlgorithm: revocationSignatureAlgorithm,
		IssuingCertificates:          issuingCertificates,
		CRLDistributionPoints:        crlDistributionPoints,
		OCSPServers:                  ocspServers,
		EnableAIAURLTemplating:       enableAIAURLTemplating,
	}

	return &IssuerClient{
		client: c,
		info:   issuerInfo,
	}, nil
}

// ListIssuers lists all issuer IDs in the PKI mount.
//
// Example:
//
//	issuers, err := client.ListIssuers(ctx)
//	for _, issuerID := range issuers {
//	    fmt.Println(issuerID)
//	}
func (c *Client) ListIssuers(ctx context.Context) ([]string, error) {
	// Use SDK to list issuers
	path := fmt.Sprintf("%s/issuers", c.config.Mount)
	secret, err := c.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: list issuers: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	// Extract keys from response
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	// Convert to string slice
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if keyStr, ok := key.(string); ok {
			result = append(result, keyStr)
		}
	}

	return result, nil
}

// UpdateIssuer updates issuer configuration.
//
// Example:
//
//	err := client.UpdateIssuer(ctx, "issuer-id", &vault.IssuerConfig{
//	    IssuerName:           "My Issuer",
//	    LeafNotAfterBehavior: "truncate",
//	    Usage:                "issuing-certificates,crl-signing",
//	})
func (c *Client) UpdateIssuer(ctx context.Context, issuerRef string, config *IssuerConfig) error {
	if issuerRef == "" {
		return fmt.Errorf("bao: issuer reference is required")
	}
	if config == nil {
		return fmt.Errorf("bao: issuer config is required")
	}

	// Build request body
	reqBody := make(map[string]interface{})
	if config.IssuerName != "" {
		reqBody["issuer_name"] = config.IssuerName
	}
	if config.LeafNotAfterBehavior != "" {
		reqBody["leaf_not_after_behavior"] = config.LeafNotAfterBehavior
	}
	if config.Usage != "" {
		reqBody["usage"] = config.Usage
	}
	if config.RevocationSignatureAlgorithm != "" {
		reqBody["revocation_signature_algorithm"] = config.RevocationSignatureAlgorithm
	}
	if len(config.IssuingCertificates) > 0 {
		reqBody["issuing_certificates"] = config.IssuingCertificates
	}
	if len(config.CRLDistributionPoints) > 0 {
		reqBody["crl_distribution_points"] = config.CRLDistributionPoints
	}
	if len(config.OCSPServers) > 0 {
		reqBody["ocsp_servers"] = config.OCSPServers
	}
	if config.EnableAIAURLTemplating {
		reqBody["enable_aia_url_templating"] = true
	}
	if len(config.ManualChain) > 0 {
		reqBody["manual_chain"] = config.ManualChain
	}

	// Use SDK to update issuer
	path := fmt.Sprintf("%s/issuer/%s", c.config.Mount, issuerRef)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("bao: update issuer: %w", err)
	}

	return nil
}

// DeleteIssuer deletes an issuer from Vault.
// Note: This will fail if the issuer is the default issuer.
//
// Example:
//
//	err := client.DeleteIssuer(ctx, "issuer-id")
func (c *Client) DeleteIssuer(ctx context.Context, issuerRef string) error {
	if issuerRef == "" {
		return fmt.Errorf("bao: issuer reference is required")
	}

	// Use SDK to delete issuer
	path := fmt.Sprintf("%s/issuer/%s", c.config.Mount, issuerRef)
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("bao: delete issuer: %w", err)
	}

	return nil
}

// SetDefaultIssuer sets the default issuer for the PKI mount.
//
// Example:
//
//	err := client.SetDefaultIssuer(ctx, "issuer-id")
func (c *Client) SetDefaultIssuer(ctx context.Context, issuerRef string) error {
	if issuerRef == "" {
		return fmt.Errorf("bao: issuer reference is required")
	}

	// Build request body
	reqBody := map[string]interface{}{
		"default": issuerRef,
	}

	// Use SDK to set default issuer
	path := fmt.Sprintf("%s/config/issuers", c.config.Mount)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("bao: set default issuer: %w", err)
	}

	return nil
}

// GetDefaultIssuer retrieves the default issuer ID for the PKI mount.
//
// Example:
//
//	issuerID, err := client.GetDefaultIssuer(ctx)
func (c *Client) GetDefaultIssuer(ctx context.Context) (string, error) {
	// Use SDK to get default issuer
	path := fmt.Sprintf("%s/config/issuers", c.config.Mount)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", fmt.Errorf("bao: get default issuer: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("bao: get default issuer: not configured")
	}

	// Extract default issuer
	defaultIssuer, _ := secret.Data["default"].(string)
	return defaultIssuer, nil
}

// Helper functions

func buildCARequestBody(opts *CAOptions) map[string]interface{} {
	reqBody := map[string]interface{}{
		"common_name": opts.CommonName,
	}

	// Add optional fields
	if len(opts.Organization) > 0 {
		reqBody["organization"] = opts.Organization
	}
	if len(opts.Country) > 0 {
		reqBody["country"] = opts.Country
	}
	if len(opts.Locality) > 0 {
		reqBody["locality"] = opts.Locality
	}
	if len(opts.Province) > 0 {
		reqBody["province"] = opts.Province
	}
	if len(opts.StreetAddress) > 0 {
		reqBody["street_address"] = opts.StreetAddress
	}
	if len(opts.PostalCode) > 0 {
		reqBody["postal_code"] = opts.PostalCode
	}
	if opts.TTL != "" {
		reqBody["ttl"] = opts.TTL
	}
	if opts.KeyType != "" {
		reqBody["key_type"] = opts.KeyType
	}
	if opts.KeyBits > 0 {
		reqBody["key_bits"] = opts.KeyBits
	}
	if opts.MaxPathLength >= 0 {
		reqBody["max_path_length"] = opts.MaxPathLength
	}
	if opts.ExcludeCNFromSANs {
		reqBody["exclude_cn_from_sans"] = true
	}
	if len(opts.PermittedDNSDomains) > 0 {
		reqBody["permitted_dns_domains"] = opts.PermittedDNSDomains
	}
	if len(opts.URISANs) > 0 {
		reqBody["uri_sans"] = joinStrings(opts.URISANs)
	}
	if len(opts.IPSANs) > 0 {
		reqBody["ip_sans"] = joinStrings(opts.IPSANs)
	}
	if len(opts.AltNames) > 0 {
		reqBody["alt_names"] = joinStrings(opts.AltNames)
	}
	if opts.IssuerName != "" {
		reqBody["issuer_name"] = opts.IssuerName
	}
	if opts.KeyName != "" {
		reqBody["key_name"] = opts.KeyName
	}
	if opts.ManagedKeyName != "" {
		reqBody["managed_key_name"] = opts.ManagedKeyName
	}
	if opts.ManagedKeyID != "" {
		reqBody["managed_key_id"] = opts.ManagedKeyID
	}
	if opts.AddBasicConstraints {
		reqBody["add_basic_constraints"] = true
	}

	return reqBody
}
