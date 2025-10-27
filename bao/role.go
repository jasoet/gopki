package bao

import (
	"context"
	"encoding/json"
	"fmt"
)

// ============================================================================
// Types & Structs
// ============================================================================

// RoleOptions contains parameters for creating or updating a role.
type RoleOptions struct {
	IssuerRef                     string   `json:"issuer_ref,omitempty"`                         // Issuer to use for this role
	TTL                           string   `json:"ttl,omitempty"`                                // Time to live (e.g., "720h")
	MaxTTL                        string   `json:"max_ttl,omitempty"`                            // Maximum TTL (e.g., "8760h")
	AllowLocalhost                bool     `json:"allow_localhost,omitempty"`                    // Allow localhost in certificates
	AllowedDomains                []string `json:"allowed_domains,omitempty"`                    // Allowed domains
	AllowedDomainsTemplate        bool     `json:"allowed_domains_template,omitempty"`           // Allow templating in domain names
	AllowBareDomains              bool     `json:"allow_bare_domains,omitempty"`                 // Allow bare domains (no subdomains)
	AllowSubdomains               bool     `json:"allow_subdomains,omitempty"`                   // Allow subdomains
	AllowGlobDomains              bool     `json:"allow_glob_domains,omitempty"`                 // Allow glob patterns in domains
	AllowWildcardCertificates     bool     `json:"allow_wildcard_certificates,omitempty"`        // Allow wildcard certificates
	AllowAnyName                  bool     `json:"allow_any_name,omitempty"`                     // Allow any common name
	EnforceHostnames              bool     `json:"enforce_hostnames,omitempty"`                  // Enforce hostname format
	AllowIPSANs                   bool     `json:"allow_ip_sans,omitempty"`                      // Allow IP SANs
	AllowedIPSANs                 []string `json:"allowed_ip_sans,omitempty"`                    // Allowed IP SANs (CIDR blocks)
	AllowedURISANs                []string `json:"allowed_uri_sans,omitempty"`                   // Allowed URI SANs
	AllowedOtherSANs              []string `json:"allowed_other_sans,omitempty"`                 // Allowed other SANs
	AllowedSerialNumbers          []string `json:"allowed_serial_numbers,omitempty"`             // Allowed serial numbers
	ServerFlag                    bool     `json:"server_flag,omitempty"`                        // Set server auth extended key usage
	ClientFlag                    bool     `json:"client_flag,omitempty"`                        // Set client auth extended key usage
	CodeSigningFlag               bool     `json:"code_signing_flag,omitempty"`                  // Set code signing extended key usage
	EmailProtectionFlag           bool     `json:"email_protection_flag,omitempty"`              // Set email protection extended key usage
	KeyType                       string   `json:"key_type,omitempty"`                           // "rsa", "ec", "ed25519", "any"
	KeyBits                       int      `json:"key_bits,omitempty"`                           // Key size
	SignatureBits                 int      `json:"signature_bits,omitempty"`                     // Signature bits (for RSA PSS)
	UsePSS                        bool     `json:"use_pss,omitempty"`                            // Use RSA-PSS for RSA keys
	KeyUsage                      []string `json:"key_usage,omitempty"`                          // Key usage extensions
	ExtKeyUsage                   []string `json:"ext_key_usage,omitempty"`                      // Extended key usage extensions
	ExtKeyUsageOIDs               []string `json:"ext_key_usage_oids,omitempty"`                 // Extended key usage OIDs
	UseCSRCommonName              bool     `json:"use_csr_common_name,omitempty"`                // Use CN from CSR
	UseCSRSANs                    bool     `json:"use_csr_sans,omitempty"`                       // Use SANs from CSR
	OrganizationUnit              []string `json:"ou,omitempty"`                                 // Organization unit
	Organization                  []string `json:"organization,omitempty"`                       // Organization
	Country                       []string `json:"country,omitempty"`                            // Country
	Locality                      []string `json:"locality,omitempty"`                           // Locality
	Province                      []string `json:"province,omitempty"`                           // Province
	StreetAddress                 []string `json:"street_address,omitempty"`                     // Street address
	PostalCode                    []string `json:"postal_code,omitempty"`                        // Postal code
	GenerateLease                 bool     `json:"generate_lease,omitempty"`                     // Generate lease for certificate
	NoStore                       bool     `json:"no_store,omitempty"`                           // Don't store certificate
	RequireCN                     bool     `json:"require_cn,omitempty"`                         // Require common name
	PolicyIdentifiers             []string `json:"policy_identifiers,omitempty"`                 // Policy identifiers
	BasicConstraintsValidForNonCA bool     `json:"basic_constraints_valid_for_non_ca,omitempty"` // Allow basic constraints for non-CA
	NotBeforeDuration             string   `json:"not_before_duration,omitempty"`                // Not before duration
	CNValidations                 []string `json:"cn_validations,omitempty"`                     // CN validation rules
	AllowedUserIDs                []string `json:"allowed_user_ids,omitempty"`                   // Allowed user IDs
}

// Role represents a OpenBao PKI role configuration.
// Deprecated: Use RoleClient instead for method chaining and convenience methods.
type Role struct {
	Name string
	*RoleOptions
}

// RoleClient wraps a role and provides methods for managing it.
type RoleClient struct {
	client *Client
	name   string
	opts   *RoleOptions
}

// ============================================================================
// RoleClient Methods
// ============================================================================

// Name returns the role name.
func (rc *RoleClient) Name() string {
	return rc.name
}

// Options returns the role options.
func (rc *RoleClient) Options() *RoleOptions {
	return rc.opts
}

// Update updates this role with new options.
//
// Example:
//
// opts := roleClient.Options()
// opts.TTL = "1440h"
// err := roleClient.Update(ctx, opts)
func (rc *RoleClient) Update(ctx context.Context, opts *RoleOptions) error {
	if opts == nil {
		return fmt.Errorf("bao: role options are required")
	}

	reqBody := buildRoleRequestBody(opts)
	path := fmt.Sprintf("%s/roles/%s", rc.client.config.Mount, rc.name)
	_, err := rc.client.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("bao: update role: %w", err)
	}

	// Update cached options
	rc.opts = opts
	return nil
}

// Delete deletes this role from OpenBao.
//
// Example:
//
// roleClient, _ := client.GetRole(ctx, "web-server")
// err := roleClient.Delete(ctx)
func (rc *RoleClient) Delete(ctx context.Context) error {
	path := fmt.Sprintf("%s/roles/%s", rc.client.config.Mount, rc.name)
	_, err := rc.client.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("bao: delete role: %w", err)
	}
	return nil
}

// Clone creates a copy of this role's options.
// The returned options can be used to create a new role.
//
// Example:
//
// roleClient, _ := client.GetRole(ctx, "web-server")
// newOpts := roleClient.Clone()
// err := client.CreateRole(ctx, "web-server-staging", newOpts)
func (rc *RoleClient) Clone() *RoleOptions {
	if rc.opts == nil {
		return &RoleOptions{}
	}

	// Create a deep copy
	clone := *rc.opts

	// Copy slices
	if len(rc.opts.AllowedDomains) > 0 {
		clone.AllowedDomains = make([]string, len(rc.opts.AllowedDomains))
		copy(clone.AllowedDomains, rc.opts.AllowedDomains)
	}
	if len(rc.opts.AllowedIPSANs) > 0 {
		clone.AllowedIPSANs = make([]string, len(rc.opts.AllowedIPSANs))
		copy(clone.AllowedIPSANs, rc.opts.AllowedIPSANs)
	}
	if len(rc.opts.AllowedURISANs) > 0 {
		clone.AllowedURISANs = make([]string, len(rc.opts.AllowedURISANs))
		copy(clone.AllowedURISANs, rc.opts.AllowedURISANs)
	}
	if len(rc.opts.KeyUsage) > 0 {
		clone.KeyUsage = make([]string, len(rc.opts.KeyUsage))
		copy(clone.KeyUsage, rc.opts.KeyUsage)
	}
	if len(rc.opts.ExtKeyUsage) > 0 {
		clone.ExtKeyUsage = make([]string, len(rc.opts.ExtKeyUsage))
		copy(clone.ExtKeyUsage, rc.opts.ExtKeyUsage)
	}
	if len(rc.opts.Organization) > 0 {
		clone.Organization = make([]string, len(rc.opts.Organization))
		copy(clone.Organization, rc.opts.Organization)
	}

	return &clone
}

// ToRole converts RoleClient to deprecated Role struct for backward compatibility.
// Deprecated: Use RoleClient methods directly.
func (rc *RoleClient) ToRole() *Role {
	return &Role{
		Name:        rc.name,
		RoleOptions: rc.opts,
	}
}

// ============================================================================
// RoleClient Convenience Methods
// ============================================================================

// SetTTL updates the TTL for this role.
//
// Example:
//
// roleClient.SetTTL(ctx, "1440h")
func (rc *RoleClient) SetTTL(ctx context.Context, ttl string) error {
	opts := rc.Clone()
	opts.TTL = ttl
	return rc.Update(ctx, opts)
}

// SetMaxTTL updates the maximum TTL for this role.
//
// Example:
//
// roleClient.SetMaxTTL(ctx, "8760h")
func (rc *RoleClient) SetMaxTTL(ctx context.Context, maxTTL string) error {
	opts := rc.Clone()
	opts.MaxTTL = maxTTL
	return rc.Update(ctx, opts)
}

// AddAllowedDomain adds a domain to the allowed domains list.
//
// Example:
//
// roleClient.AddAllowedDomain(ctx, "example.com")
func (rc *RoleClient) AddAllowedDomain(ctx context.Context, domain string) error {
	opts := rc.Clone()
	// Check if domain already exists
	for _, d := range opts.AllowedDomains {
		if d == domain {
			return nil // Already exists
		}
	}
	opts.AllowedDomains = append(opts.AllowedDomains, domain)
	return rc.Update(ctx, opts)
}

// RemoveAllowedDomain removes a domain from the allowed domains list.
//
// Example:
//
// roleClient.RemoveAllowedDomain(ctx, "old.example.com")
func (rc *RoleClient) RemoveAllowedDomain(ctx context.Context, domain string) error {
	opts := rc.Clone()
	filtered := make([]string, 0, len(opts.AllowedDomains))
	for _, d := range opts.AllowedDomains {
		if d != domain {
			filtered = append(filtered, d)
		}
	}
	opts.AllowedDomains = filtered
	return rc.Update(ctx, opts)
}

// EnableServerAuth enables server authentication for this role.
//
// Example:
//
// roleClient.EnableServerAuth(ctx)
func (rc *RoleClient) EnableServerAuth(ctx context.Context) error {
	opts := rc.Clone()
	opts.ServerFlag = true
	return rc.Update(ctx, opts)
}

// DisableServerAuth disables server authentication for this role.
//
// Example:
//
// roleClient.DisableServerAuth(ctx)
func (rc *RoleClient) DisableServerAuth(ctx context.Context) error {
	opts := rc.Clone()
	opts.ServerFlag = false
	return rc.Update(ctx, opts)
}

// EnableClientAuth enables client authentication for this role.
//
// Example:
//
// roleClient.EnableClientAuth(ctx)
func (rc *RoleClient) EnableClientAuth(ctx context.Context) error {
	opts := rc.Clone()
	opts.ClientFlag = true
	return rc.Update(ctx, opts)
}

// DisableClientAuth disables client authentication for this role.
//
// Example:
//
// roleClient.DisableClientAuth(ctx)
func (rc *RoleClient) DisableClientAuth(ctx context.Context) error {
	opts := rc.Clone()
	opts.ClientFlag = false
	return rc.Update(ctx, opts)
}

// EnableCodeSigning enables code signing for this role.
//
// Example:
//
// roleClient.EnableCodeSigning(ctx)
func (rc *RoleClient) EnableCodeSigning(ctx context.Context) error {
	opts := rc.Clone()
	opts.CodeSigningFlag = true
	return rc.Update(ctx, opts)
}

// ============================================================================
// Client Methods - CRUD Operations
// ============================================================================

// CreateRole creates or updates a role in OpenBao.
// Roles define policies for certificate issuance.
//
// Example:
//
//	err := client.CreateRole(ctx, "web-server", &bao.RoleOptions{
//	   TTL:              "720h",
//	   MaxTTL:           "8760h",
//	   AllowedDomains:   []string{"example.com"},
//	   AllowSubdomains:  true,
//	   ServerFlag:       true,
//	   KeyType:          "rsa",
//	   KeyBits:          2048,
//	})
func (c *Client) CreateRole(ctx context.Context, name string, opts *RoleOptions) error {
	if name == "" {
		return fmt.Errorf("bao: role name is required")
	}
	if opts == nil {
		return fmt.Errorf("bao: role options are required")
	}

	reqBody := buildRoleRequestBody(opts)
	path := fmt.Sprintf("%s/roles/%s", c.config.Mount, name)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("bao: create role: %w", err)
	}

	return nil
}

// UpdateRole explicitly updates an existing role in OpenBao.
// This is semantically clearer than CreateRole for update operations.
//
// Example:
//
// opts.TTL = "1440h"
// err := client.UpdateRole(ctx, "web-server", opts)
func (c *Client) UpdateRole(ctx context.Context, name string, opts *RoleOptions) error {
	return c.CreateRole(ctx, name, opts)
}

// GetRole retrieves role configuration by name and returns a RoleClient.
//
// Example:
//
// roleClient, err := client.GetRole(ctx, "web-server")
// ttl := roleClient.Options().TTL
// err = roleClient.SetTTL(ctx, "1440h")
func (c *Client) GetRole(ctx context.Context, name string) (*RoleClient, error) {
	if name == "" {
		return nil, fmt.Errorf("bao: role name is required")
	}

	path := fmt.Sprintf("%s/roles/%s", c.config.Mount, name)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: get role: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("bao: get role: not found")
	}

	// Parse role options using helper function
	roleOpts := parseRoleOptions(secret.Data)

	return &RoleClient{
		client: c,
		name:   name,
		opts:   roleOpts,
	}, nil
}

// ListRoles lists all role names in the PKI mount.
//
// Example:
//
// roles, err := client.ListRoles(ctx)
//
//	for _, roleName := range roles {
//	   fmt.Println(roleName)
//	}
func (c *Client) ListRoles(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("%s/roles", c.config.Mount)
	secret, err := c.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("bao: list roles: %w", err)
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

// DeleteRole deletes a role from OpenBao.
//
// Example:
//
// err := client.DeleteRole(ctx, "web-server")
func (c *Client) DeleteRole(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("bao: role name is required")
	}

	path := fmt.Sprintf("%s/roles/%s", c.config.Mount, name)
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("bao: delete role: %w", err)
	}

	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// parseRoleOptions extracts role options from OpenBao response data.
func parseRoleOptions(data map[string]interface{}) *RoleOptions {
	opts := &RoleOptions{}

	// Extract string fields
	opts.IssuerRef = extractStringField(data, "issuer_ref")
	opts.TTL = extractStringField(data, "ttl")
	opts.MaxTTL = extractStringField(data, "max_ttl")
	opts.KeyType = extractStringField(data, "key_type")
	opts.NotBeforeDuration = extractStringField(data, "not_before_duration")

	// Extract boolean fields
	opts.AllowLocalhost = extractBoolField(data, "allow_localhost")
	opts.AllowedDomainsTemplate = extractBoolField(data, "allowed_domains_template")
	opts.AllowBareDomains = extractBoolField(data, "allow_bare_domains")
	opts.AllowSubdomains = extractBoolField(data, "allow_subdomains")
	opts.AllowGlobDomains = extractBoolField(data, "allow_glob_domains")
	opts.AllowWildcardCertificates = extractBoolField(data, "allow_wildcard_certificates")
	opts.AllowAnyName = extractBoolField(data, "allow_any_name")
	opts.EnforceHostnames = extractBoolField(data, "enforce_hostnames")
	opts.AllowIPSANs = extractBoolField(data, "allow_ip_sans")
	opts.ServerFlag = extractBoolField(data, "server_flag")
	opts.ClientFlag = extractBoolField(data, "client_flag")
	opts.CodeSigningFlag = extractBoolField(data, "code_signing_flag")
	opts.EmailProtectionFlag = extractBoolField(data, "email_protection_flag")
	opts.UsePSS = extractBoolField(data, "use_pss")
	opts.UseCSRCommonName = extractBoolField(data, "use_csr_common_name")
	opts.UseCSRSANs = extractBoolField(data, "use_csr_sans")
	opts.GenerateLease = extractBoolField(data, "generate_lease")
	opts.NoStore = extractBoolField(data, "no_store")
	opts.RequireCN = extractBoolField(data, "require_cn")
	opts.BasicConstraintsValidForNonCA = extractBoolField(data, "basic_constraints_valid_for_non_ca")

	// Extract int fields
	opts.KeyBits = extractIntField(data, "key_bits")
	opts.SignatureBits = extractIntField(data, "signature_bits")

	// Extract array fields
	opts.AllowedDomains = extractStringSliceField(data, "allowed_domains")
	opts.AllowedIPSANs = extractStringSliceField(data, "allowed_ip_sans")
	opts.AllowedURISANs = extractStringSliceField(data, "allowed_uri_sans")
	opts.AllowedOtherSANs = extractStringSliceField(data, "allowed_other_sans")
	opts.AllowedSerialNumbers = extractStringSliceField(data, "allowed_serial_numbers")
	opts.KeyUsage = extractStringSliceField(data, "key_usage")
	opts.ExtKeyUsage = extractStringSliceField(data, "ext_key_usage")
	opts.ExtKeyUsageOIDs = extractStringSliceField(data, "ext_key_usage_oids")
	opts.OrganizationUnit = extractStringSliceField(data, "ou")
	opts.Organization = extractStringSliceField(data, "organization")
	opts.Country = extractStringSliceField(data, "country")
	opts.Locality = extractStringSliceField(data, "locality")
	opts.Province = extractStringSliceField(data, "province")
	opts.StreetAddress = extractStringSliceField(data, "street_address")
	opts.PostalCode = extractStringSliceField(data, "postal_code")
	opts.PolicyIdentifiers = extractStringSliceField(data, "policy_identifiers")
	opts.CNValidations = extractStringSliceField(data, "cn_validations")
	opts.AllowedUserIDs = extractStringSliceField(data, "allowed_user_ids")

	return opts
}

// extractStringField extracts a string field from response data.
func extractStringField(data map[string]interface{}, key string) string {
	if v, ok := data[key].(string); ok {
		return v
	}
	return ""
}

// extractBoolField extracts a boolean field from response data.
func extractBoolField(data map[string]interface{}, key string) bool {
	if v, ok := data[key].(bool); ok {
		return v
	}
	return false
}

// extractIntField extracts an integer field from response data.
// Handles json.Number, float64, int, and int64.
func extractIntField(data map[string]interface{}, key string) int {
	if v, ok := data[key].(float64); ok {
		return int(v)
	}
	if v, ok := data[key].(int); ok {
		return v
	}
	if v, ok := data[key].(int64); ok {
		return int(v)
	}
	if v, ok := data[key].(json.Number); ok {
		if intVal, err := v.Int64(); err == nil {
			return int(intVal)
		}
	}
	return 0
}

// extractStringSliceField extracts a string slice field from response data.
func extractStringSliceField(data map[string]interface{}, key string) []string {
	if v, ok := data[key].([]interface{}); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

// buildRoleRequestBody constructs the request body for role creation/update.
func buildRoleRequestBody(opts *RoleOptions) map[string]interface{} {
	reqBody := make(map[string]interface{})

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

// ============================================================================
// Role Templates (Pre-configured roles for common use cases)
// ============================================================================

// NewWebServerRole creates a pre-configured role for web servers.
//
// Example:
//
// opts := bao.NewWebServerRole("example.com")
// err := client.CreateRole(ctx, "web-server", opts)
func NewWebServerRole(domain string) *RoleOptions {
	return &RoleOptions{
		TTL:              "720h",  // 30 days
		MaxTTL:           "8760h", // 1 year
		AllowedDomains:   []string{domain},
		AllowSubdomains:  true,
		AllowBareDomains: true,
		ServerFlag:       true,
		ClientFlag:       false,
		KeyType:          "rsa",
		KeyBits:          2048,
		KeyUsage:         []string{"DigitalSignature", "KeyAgreement", "KeyEncipherment"},
	}
}

// NewClientCertRole creates a pre-configured role for client certificates.
//
// Example:
//
// opts := bao.NewClientCertRole("example.com")
// err := client.CreateRole(ctx, "client-cert", opts)
func NewClientCertRole(domain string) *RoleOptions {
	return &RoleOptions{
		TTL:             "720h",  // 30 days
		MaxTTL:          "8760h", // 1 year
		AllowedDomains:  []string{domain},
		AllowSubdomains: true,
		ServerFlag:      false,
		ClientFlag:      true,
		KeyType:         "rsa",
		KeyBits:         2048,
		KeyUsage:        []string{"DigitalSignature"},
	}
}

// NewCodeSigningRole creates a pre-configured role for code signing certificates.
//
// Example:
//
// opts := bao.NewCodeSigningRole("example.com")
// err := client.CreateRole(ctx, "code-signing", opts)
func NewCodeSigningRole(domain string) *RoleOptions {
	return &RoleOptions{
		TTL:             "8760h",  // 1 year
		MaxTTL:          "26280h", // 3 years
		AllowedDomains:  []string{domain},
		AllowSubdomains: false,
		ServerFlag:      false,
		ClientFlag:      false,
		CodeSigningFlag: true,
		KeyType:         "rsa",
		KeyBits:         2048,
		KeyUsage:        []string{"DigitalSignature"},
	}
}
