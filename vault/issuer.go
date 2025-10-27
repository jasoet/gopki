package vault

import (
	"context"
	"fmt"

	"github.com/jasoet/gopki/cert"
)

// CAOptions contains parameters for generating a CA certificate.
type CAOptions struct {
	Type              string   // "internal" (Vault generates key) or "exported" (returns CSR)
	CommonName        string   // Required
	Organization      []string // Optional
	Country           []string // Optional
	Locality          []string // Optional
	Province          []string // Optional
	StreetAddress     []string // Optional
	PostalCode        []string // Optional
	TTL               string   // Time to live (e.g., "8760h" for 1 year)
	KeyType           string   // "rsa", "ec", "ed25519"
	KeyBits           int      // Key size (RSA: 2048/3072/4096, EC: 224/256/384/521)
	MaxPathLength     int      // Max depth of intermediate CAs (-1 = no limit, 0 = can only sign end-entity certs)
	ExcludeCNFromSANs bool     // Exclude CN from SANs
	PermittedDNSDomains []string // Permitted DNS domains
	URISANs           []string // URI SANs
	IPSANs            []string // IP SANs
	AltNames          []string // DNS SANs
	IssuerName        string   // Name for the issuer
	KeyName           string   // Name for the key
	ManagedKeyName    string   // Name of managed key to use
	ManagedKeyID      string   // ID of managed key to use
}

// IntermediateCAOptions contains parameters for generating an intermediate CA.
type IntermediateCAOptions struct {
	Type              string   // "internal" or "exported"
	CommonName        string   // Required
	Organization      []string // Optional
	Country           []string // Optional
	Locality          []string // Optional
	Province          []string // Optional
	StreetAddress     []string // Optional
	PostalCode        []string // Optional
	TTL               string   // Time to live
	KeyType           string   // "rsa", "ec", "ed25519"
	KeyBits           int      // Key size
	MaxPathLength     int      // Max depth of intermediate CAs
	ExcludeCNFromSANs bool     // Exclude CN from SANs
	PermittedDNSDomains []string // Permitted DNS domains
	URISANs           []string // URI SANs
	IPSANs            []string // IP SANs
	AltNames          []string // DNS SANs
	IssuerName        string   // Name for the issuer
	KeyName           string   // Name for the key
	AddBasicConstraints bool   // Add basic constraints
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
	Certificate  *cert.Certificate // Generated certificate
	IssuingCA    string            // Issuing CA certificate (PEM)
	CAChain      []string          // CA chain (PEM)
	SerialNumber string            // Certificate serial number
	IssuerID     string            // Issuer UUID
	KeyID        string            // Key UUID
	PrivateKey   string            // Private key (only for "exported" type)
	PrivateKeyType string          // Private key type
	CSR          string            // CSR (only for "exported" intermediate)
}

// vaultGenerateCAResponse represents Vault's response from generate endpoints.
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

// vaultIssuerResponse represents Vault's response from issuer endpoints.
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
		return nil, fmt.Errorf("vault: CA options are required")
	}
	if opts.CommonName == "" {
		return nil, fmt.Errorf("vault: common name is required")
	}
	if opts.Type == "" {
		opts.Type = "internal" // Default to internal
	}
	if opts.Type != "internal" && opts.Type != "exported" {
		return nil, fmt.Errorf("vault: type must be 'internal' or 'exported', got '%s'", opts.Type)
	}

	// Build request body
	reqBody := buildCARequestBody(opts)

	// Use SDK to generate root CA
	path := fmt.Sprintf("%s/root/generate/%s", c.config.Mount, opts.Type)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("vault: generate root CA: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: generate root CA: empty response")
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
		return nil, fmt.Errorf("vault: generate root CA: %w", err)
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
//	intermediate, err := client.GenerateIntermediateCA(ctx, &vault.IntermediateCAOptions{
//	    Type:         "internal",
//	    CommonName:   "Example Intermediate CA",
//	    Organization: []string{"Example Org"},
//	    TTL:          "43800h", // 5 years
//	    KeyType:      "rsa",
//	    KeyBits:      2048,
//	})
func (c *Client) GenerateIntermediateCA(ctx context.Context, opts *IntermediateCAOptions) (*GenerateCAResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("vault: intermediate CA options are required")
	}
	if opts.CommonName == "" {
		return nil, fmt.Errorf("vault: common name is required")
	}
	if opts.Type == "" {
		opts.Type = "internal" // Default to internal
	}
	if opts.Type != "internal" && opts.Type != "exported" {
		return nil, fmt.Errorf("vault: type must be 'internal' or 'exported', got '%s'", opts.Type)
	}

	// Build request body
	reqBody := buildIntermediateCARequestBody(opts)

	// Use SDK to generate intermediate CA
	path := fmt.Sprintf("%s/intermediate/generate/%s", c.config.Mount, opts.Type)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("vault: generate intermediate CA: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: generate intermediate CA: empty response")
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
			return nil, fmt.Errorf("vault: generate intermediate CA: %w", err)
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
		return nil, fmt.Errorf("vault: CSR is required")
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
		return nil, fmt.Errorf("vault: sign intermediate CSR: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: sign intermediate CSR: empty response")
	}

	// Extract certificate data
	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("vault: sign intermediate CSR: invalid certificate data")
	}
	issuingCAPEM, _ := secret.Data["issuing_ca"].(string)

	// Convert certificate
	certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, fmt.Errorf("vault: sign intermediate CSR: %w", err)
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
func (c *Client) ImportCA(ctx context.Context, bundle *CABundle) (*IssuerInfo, error) {
	if bundle == nil || bundle.PEMBundle == "" {
		return nil, fmt.Errorf("vault: CA bundle is required")
	}

	// Build request body
	reqBody := map[string]interface{}{
		"pem_bundle": bundle.PEMBundle,
	}

	// Use SDK to import CA
	path := fmt.Sprintf("%s/config/ca", c.config.Mount)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("vault: import CA: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: import CA: empty response")
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
		return nil, fmt.Errorf("vault: no issuers imported")
	}

	issuerID := importedIssuers[0]

	// Retrieve issuer details
	issuerInfo, err := c.GetIssuer(ctx, issuerID)
	if err != nil {
		return nil, fmt.Errorf("vault: import CA: %w", err)
	}

	return issuerInfo, nil
}

// GetIssuer retrieves issuer information by ID or name.
//
// Example:
//
//	issuer, err := client.GetIssuer(ctx, "issuer-id-or-name")
func (c *Client) GetIssuer(ctx context.Context, issuerRef string) (*IssuerInfo, error) {
	if issuerRef == "" {
		return nil, fmt.Errorf("vault: issuer reference is required")
	}

	// Use SDK to get issuer
	path := fmt.Sprintf("%s/issuer/%s", c.config.Mount, issuerRef)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault: get issuer: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: get issuer: not found")
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

	return &IssuerInfo{
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
		return nil, fmt.Errorf("vault: list issuers: %w", err)
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
		return fmt.Errorf("vault: issuer reference is required")
	}
	if config == nil {
		return fmt.Errorf("vault: issuer config is required")
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
		return fmt.Errorf("vault: update issuer: %w", err)
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
		return fmt.Errorf("vault: issuer reference is required")
	}

	// Use SDK to delete issuer
	path := fmt.Sprintf("%s/issuer/%s", c.config.Mount, issuerRef)
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("vault: delete issuer: %w", err)
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
		return fmt.Errorf("vault: issuer reference is required")
	}

	// Build request body
	reqBody := map[string]interface{}{
		"default": issuerRef,
	}

	// Use SDK to set default issuer
	path := fmt.Sprintf("%s/config/issuers", c.config.Mount)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("vault: set default issuer: %w", err)
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
		return "", fmt.Errorf("vault: get default issuer: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault: get default issuer: not configured")
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

	return reqBody
}

func buildIntermediateCARequestBody(opts *IntermediateCAOptions) map[string]interface{} {
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
	if opts.AddBasicConstraints {
		reqBody["add_basic_constraints"] = true
	}

	return reqBody
}
