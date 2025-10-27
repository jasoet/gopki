package vault

import (
	"context"
	"fmt"
)

// RoleOptions contains parameters for creating or updating a role.
type RoleOptions struct {
	IssuerRef                     string   // Issuer to use for this role
	TTL                           string   // Time to live (e.g., "720h")
	MaxTTL                        string   // Maximum TTL (e.g., "8760h")
	AllowLocalhost                bool     // Allow localhost in certificates
	AllowedDomains                []string // Allowed domains
	AllowedDomainsTemplate        bool     // Allow templating in domain names
	AllowBareDomains              bool     // Allow bare domains (no subdomains)
	AllowSubdomains               bool     // Allow subdomains
	AllowGlobDomains              bool     // Allow glob patterns in domains
	AllowWildcardCertificates     bool     // Allow wildcard certificates
	AllowAnyName                  bool     // Allow any common name
	EnforceHostnames              bool     // Enforce hostname format
	AllowIPSANs                   bool     // Allow IP SANs
	AllowedIPSANs                 []string // Allowed IP SANs (CIDR blocks)
	AllowedURISANs                []string // Allowed URI SANs
	AllowedOtherSANs              []string // Allowed other SANs
	AllowedSerialNumbers          []string // Allowed serial numbers
	ServerFlag                    bool     // Set server auth extended key usage
	ClientFlag                    bool     // Set client auth extended key usage
	CodeSigningFlag               bool     // Set code signing extended key usage
	EmailProtectionFlag           bool     // Set email protection extended key usage
	KeyType                       string   // "rsa", "ec", "ed25519", "any"
	KeyBits                       int      // Key size
	SignatureBits                 int      // Signature bits (for RSA PSS)
	UsePSS                        bool     // Use RSA-PSS for RSA keys
	KeyUsage                      []string // Key usage extensions
	ExtKeyUsage                   []string // Extended key usage extensions
	ExtKeyUsageOIDs               []string // Extended key usage OIDs
	UseCSRCommonName              bool     // Use CN from CSR
	UseCSRSANs                    bool     // Use SANs from CSR
	OrganizationUnit              []string // Organization unit
	Organization                  []string // Organization
	Country                       []string // Country
	Locality                      []string // Locality
	Province                      []string // Province
	StreetAddress                 []string // Street address
	PostalCode                    []string // Postal code
	GenerateLease                 bool     // Generate lease for certificate
	NoStore                       bool     // Don't store certificate
	RequireCN                     bool     // Require common name
	PolicyIdentifiers             []string // Policy identifiers
	BasicConstraintsValidForNonCA bool     // Allow basic constraints for non-CA
	NotBeforeDuration             string   // Not before duration
	CNValidations                 []string // CN validation rules
	AllowedUserIDs                []string // Allowed user IDs
}

// Role represents a Vault PKI role configuration.
type Role struct {
	Name string
	*RoleOptions
}

// vaultRoleResponse represents Vault's response from role endpoints.
type vaultRoleResponse struct {
	Data RoleOptions `json:"data"`
}

// CreateRole creates or updates a role in Vault.
// Roles define policies for certificate issuance.
//
// Example:
//
//	err := client.CreateRole(ctx, "web-server", &vault.RoleOptions{
//	    TTL:              "720h",
//	    MaxTTL:           "8760h",
//	    AllowedDomains:   []string{"example.com"},
//	    AllowSubdomains:  true,
//	    ServerFlag:       true,
//	    ClientFlag:       false,
//	    KeyType:          "rsa",
//	    KeyBits:          2048,
//	})
func (c *Client) CreateRole(ctx context.Context, name string, opts *RoleOptions) error {
	if name == "" {
		return fmt.Errorf("vault: role name is required")
	}
	if opts == nil {
		return fmt.Errorf("vault: role options are required")
	}

	// Build request body
	reqBody := buildRoleRequestBody(opts)

	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/roles/%s", c.config.Mount, name)
	resp, err := c.doRequest(ctx, "POST", path, reqBody)
	if err != nil {
		return fmt.Errorf("vault: create role: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("vault: create role failed (status %d)", resp.StatusCode)
	}

	return nil
}

// GetRole retrieves role configuration by name.
//
// Example:
//
//	role, err := client.GetRole(ctx, "web-server")
func (c *Client) GetRole(ctx context.Context, name string) (*Role, error) {
	if name == "" {
		return nil, fmt.Errorf("vault: role name is required")
	}

	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/roles/%s", c.config.Mount, name)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: get role: %w", err)
	}

	// Parse response
	var vaultResp vaultRoleResponse
	if err := c.parseResponse(resp, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: get role: %w", err)
	}

	return &Role{
		Name:        name,
		RoleOptions: &vaultResp.Data,
	}, nil
}

// ListRoles lists all role names in the PKI mount.
//
// Example:
//
//	roles, err := client.ListRoles(ctx)
//	for _, roleName := range roles {
//	    fmt.Println(roleName)
//	}
func (c *Client) ListRoles(ctx context.Context) ([]string, error) {
	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/roles", c.config.Mount)
	resp, err := c.doRequest(ctx, "LIST", path, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: list roles: %w", err)
	}

	// Parse response
	var vaultResp vaultListResponse
	if err := c.parseResponse(resp, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: list roles: %w", err)
	}

	return vaultResp.Data.Keys, nil
}

// DeleteRole deletes a role from Vault.
//
// Example:
//
//	err := client.DeleteRole(ctx, "web-server")
func (c *Client) DeleteRole(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("vault: role name is required")
	}

	// Make request to Vault
	path := fmt.Sprintf("/v1/%s/roles/%s", c.config.Mount, name)
	resp, err := c.doRequest(ctx, "DELETE", path, nil)
	if err != nil {
		return fmt.Errorf("vault: delete role: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("vault: delete role failed (status %d)", resp.StatusCode)
	}

	return nil
}

// Helper function to build role request body
func buildRoleRequestBody(opts *RoleOptions) map[string]interface{} {
	reqBody := make(map[string]interface{})

	// Add all non-zero fields
	if opts.IssuerRef != "" {
		reqBody["issuer_ref"] = opts.IssuerRef
	}
	if opts.TTL != "" {
		reqBody["ttl"] = opts.TTL
	}
	if opts.MaxTTL != "" {
		reqBody["max_ttl"] = opts.MaxTTL
	}
	if opts.AllowLocalhost {
		reqBody["allow_localhost"] = true
	}
	if len(opts.AllowedDomains) > 0 {
		reqBody["allowed_domains"] = opts.AllowedDomains
	}
	if opts.AllowedDomainsTemplate {
		reqBody["allowed_domains_template"] = true
	}
	if opts.AllowBareDomains {
		reqBody["allow_bare_domains"] = true
	}
	if opts.AllowSubdomains {
		reqBody["allow_subdomains"] = true
	}
	if opts.AllowGlobDomains {
		reqBody["allow_glob_domains"] = true
	}
	if opts.AllowWildcardCertificates {
		reqBody["allow_wildcard_certificates"] = true
	}
	if opts.AllowAnyName {
		reqBody["allow_any_name"] = true
	}
	if opts.EnforceHostnames {
		reqBody["enforce_hostnames"] = true
	}
	if opts.AllowIPSANs {
		reqBody["allow_ip_sans"] = true
	}
	if len(opts.AllowedIPSANs) > 0 {
		reqBody["allowed_ip_sans"] = opts.AllowedIPSANs
	}
	if len(opts.AllowedURISANs) > 0 {
		reqBody["allowed_uri_sans"] = opts.AllowedURISANs
	}
	if len(opts.AllowedOtherSANs) > 0 {
		reqBody["allowed_other_sans"] = opts.AllowedOtherSANs
	}
	if len(opts.AllowedSerialNumbers) > 0 {
		reqBody["allowed_serial_numbers"] = opts.AllowedSerialNumbers
	}
	if opts.ServerFlag {
		reqBody["server_flag"] = true
	}
	if opts.ClientFlag {
		reqBody["client_flag"] = true
	}
	if opts.CodeSigningFlag {
		reqBody["code_signing_flag"] = true
	}
	if opts.EmailProtectionFlag {
		reqBody["email_protection_flag"] = true
	}
	if opts.KeyType != "" {
		reqBody["key_type"] = opts.KeyType
	}
	if opts.KeyBits > 0 {
		reqBody["key_bits"] = opts.KeyBits
	}
	if opts.SignatureBits > 0 {
		reqBody["signature_bits"] = opts.SignatureBits
	}
	if opts.UsePSS {
		reqBody["use_pss"] = true
	}
	if len(opts.KeyUsage) > 0 {
		reqBody["key_usage"] = opts.KeyUsage
	}
	if len(opts.ExtKeyUsage) > 0 {
		reqBody["ext_key_usage"] = opts.ExtKeyUsage
	}
	if len(opts.ExtKeyUsageOIDs) > 0 {
		reqBody["ext_key_usage_oids"] = opts.ExtKeyUsageOIDs
	}
	if opts.UseCSRCommonName {
		reqBody["use_csr_common_name"] = true
	}
	if opts.UseCSRSANs {
		reqBody["use_csr_sans"] = true
	}
	if len(opts.OrganizationUnit) > 0 {
		reqBody["ou"] = opts.OrganizationUnit
	}
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
	if opts.GenerateLease {
		reqBody["generate_lease"] = true
	}
	if opts.NoStore {
		reqBody["no_store"] = true
	}
	if opts.RequireCN {
		reqBody["require_cn"] = true
	}
	if len(opts.PolicyIdentifiers) > 0 {
		reqBody["policy_identifiers"] = opts.PolicyIdentifiers
	}
	if opts.BasicConstraintsValidForNonCA {
		reqBody["basic_constraints_valid_for_non_ca"] = true
	}
	if opts.NotBeforeDuration != "" {
		reqBody["not_before_duration"] = opts.NotBeforeDuration
	}
	if len(opts.CNValidations) > 0 {
		reqBody["cn_validations"] = opts.CNValidations
	}
	if len(opts.AllowedUserIDs) > 0 {
		reqBody["allowed_user_ids"] = opts.AllowedUserIDs
	}

	return reqBody
}
