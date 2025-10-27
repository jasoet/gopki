package bao

import (
	"context"
	"encoding/json"
	"fmt"
)

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

	// Use SDK to create role
	path := fmt.Sprintf("%s/roles/%s", c.config.Mount, name)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("vault: create role: %w", err)
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

	// Use SDK to get role
	path := fmt.Sprintf("%s/roles/%s", c.config.Mount, name)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault: get role: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: get role: not found")
	}

	// Extract role data into RoleOptions
	roleOpts := &RoleOptions{}

	// Extract string fields
	if v, ok := secret.Data["issuer_ref"].(string); ok {
		roleOpts.IssuerRef = v
	}
	if v, ok := secret.Data["ttl"].(string); ok {
		roleOpts.TTL = v
	}
	if v, ok := secret.Data["max_ttl"].(string); ok {
		roleOpts.MaxTTL = v
	}
	if v, ok := secret.Data["key_type"].(string); ok {
		roleOpts.KeyType = v
	}
	if v, ok := secret.Data["not_before_duration"].(string); ok {
		roleOpts.NotBeforeDuration = v
	}

	// Extract boolean fields
	if v, ok := secret.Data["allow_localhost"].(bool); ok {
		roleOpts.AllowLocalhost = v
	}
	if v, ok := secret.Data["allowed_domains_template"].(bool); ok {
		roleOpts.AllowedDomainsTemplate = v
	}
	if v, ok := secret.Data["allow_bare_domains"].(bool); ok {
		roleOpts.AllowBareDomains = v
	}
	if v, ok := secret.Data["allow_subdomains"].(bool); ok {
		roleOpts.AllowSubdomains = v
	}
	if v, ok := secret.Data["allow_glob_domains"].(bool); ok {
		roleOpts.AllowGlobDomains = v
	}
	if v, ok := secret.Data["allow_wildcard_certificates"].(bool); ok {
		roleOpts.AllowWildcardCertificates = v
	}
	if v, ok := secret.Data["allow_any_name"].(bool); ok {
		roleOpts.AllowAnyName = v
	}
	if v, ok := secret.Data["enforce_hostnames"].(bool); ok {
		roleOpts.EnforceHostnames = v
	}
	if v, ok := secret.Data["allow_ip_sans"].(bool); ok {
		roleOpts.AllowIPSANs = v
	}
	if v, ok := secret.Data["server_flag"].(bool); ok {
		roleOpts.ServerFlag = v
	}
	if v, ok := secret.Data["client_flag"].(bool); ok {
		roleOpts.ClientFlag = v
	}
	if v, ok := secret.Data["code_signing_flag"].(bool); ok {
		roleOpts.CodeSigningFlag = v
	}
	if v, ok := secret.Data["email_protection_flag"].(bool); ok {
		roleOpts.EmailProtectionFlag = v
	}
	if v, ok := secret.Data["use_pss"].(bool); ok {
		roleOpts.UsePSS = v
	}
	if v, ok := secret.Data["use_csr_common_name"].(bool); ok {
		roleOpts.UseCSRCommonName = v
	}
	if v, ok := secret.Data["use_csr_sans"].(bool); ok {
		roleOpts.UseCSRSANs = v
	}
	if v, ok := secret.Data["generate_lease"].(bool); ok {
		roleOpts.GenerateLease = v
	}
	if v, ok := secret.Data["no_store"].(bool); ok {
		roleOpts.NoStore = v
	}
	if v, ok := secret.Data["require_cn"].(bool); ok {
		roleOpts.RequireCN = v
	}
	if v, ok := secret.Data["basic_constraints_valid_for_non_ca"].(bool); ok {
		roleOpts.BasicConstraintsValidForNonCA = v
	}

	// Extract int fields - handle json.Number, float64, int, and int64
	if v, ok := secret.Data["key_bits"].(float64); ok {
		roleOpts.KeyBits = int(v)
	} else if v, ok := secret.Data["key_bits"].(int); ok {
		roleOpts.KeyBits = v
	} else if v, ok := secret.Data["key_bits"].(int64); ok {
		roleOpts.KeyBits = int(v)
	} else if v, ok := secret.Data["key_bits"].(json.Number); ok {
		if intVal, err := v.Int64(); err == nil {
			roleOpts.KeyBits = int(intVal)
		}
	}
	if v, ok := secret.Data["signature_bits"].(float64); ok {
		roleOpts.SignatureBits = int(v)
	} else if v, ok := secret.Data["signature_bits"].(int); ok {
		roleOpts.SignatureBits = v
	} else if v, ok := secret.Data["signature_bits"].(int64); ok {
		roleOpts.SignatureBits = int(v)
	} else if v, ok := secret.Data["signature_bits"].(json.Number); ok {
		if intVal, err := v.Int64(); err == nil {
			roleOpts.SignatureBits = int(intVal)
		}
	}

	// Extract array fields
	if v, ok := secret.Data["allowed_domains"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.AllowedDomains = append(roleOpts.AllowedDomains, str)
			}
		}
	}
	if v, ok := secret.Data["allowed_ip_sans"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.AllowedIPSANs = append(roleOpts.AllowedIPSANs, str)
			}
		}
	}
	if v, ok := secret.Data["allowed_uri_sans"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.AllowedURISANs = append(roleOpts.AllowedURISANs, str)
			}
		}
	}
	if v, ok := secret.Data["allowed_other_sans"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.AllowedOtherSANs = append(roleOpts.AllowedOtherSANs, str)
			}
		}
	}
	if v, ok := secret.Data["allowed_serial_numbers"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.AllowedSerialNumbers = append(roleOpts.AllowedSerialNumbers, str)
			}
		}
	}
	if v, ok := secret.Data["key_usage"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.KeyUsage = append(roleOpts.KeyUsage, str)
			}
		}
	}
	if v, ok := secret.Data["ext_key_usage"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.ExtKeyUsage = append(roleOpts.ExtKeyUsage, str)
			}
		}
	}
	if v, ok := secret.Data["ext_key_usage_oids"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.ExtKeyUsageOIDs = append(roleOpts.ExtKeyUsageOIDs, str)
			}
		}
	}
	if v, ok := secret.Data["ou"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.OrganizationUnit = append(roleOpts.OrganizationUnit, str)
			}
		}
	}
	if v, ok := secret.Data["organization"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.Organization = append(roleOpts.Organization, str)
			}
		}
	}
	if v, ok := secret.Data["country"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.Country = append(roleOpts.Country, str)
			}
		}
	}
	if v, ok := secret.Data["locality"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.Locality = append(roleOpts.Locality, str)
			}
		}
	}
	if v, ok := secret.Data["province"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.Province = append(roleOpts.Province, str)
			}
		}
	}
	if v, ok := secret.Data["street_address"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.StreetAddress = append(roleOpts.StreetAddress, str)
			}
		}
	}
	if v, ok := secret.Data["postal_code"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.PostalCode = append(roleOpts.PostalCode, str)
			}
		}
	}
	if v, ok := secret.Data["policy_identifiers"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.PolicyIdentifiers = append(roleOpts.PolicyIdentifiers, str)
			}
		}
	}
	if v, ok := secret.Data["cn_validations"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.CNValidations = append(roleOpts.CNValidations, str)
			}
		}
	}
	if v, ok := secret.Data["allowed_user_ids"].([]interface{}); ok {
		for _, item := range v {
			if str, ok := item.(string); ok {
				roleOpts.AllowedUserIDs = append(roleOpts.AllowedUserIDs, str)
			}
		}
	}

	return &Role{
		Name:        name,
		RoleOptions: roleOpts,
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
	// Use SDK to list roles
	path := fmt.Sprintf("%s/roles", c.config.Mount)
	secret, err := c.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault: list roles: %w", err)
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

// DeleteRole deletes a role from Vault.
//
// Example:
//
//	err := client.DeleteRole(ctx, "web-server")
func (c *Client) DeleteRole(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("vault: role name is required")
	}

	// Use SDK to delete role
	path := fmt.Sprintf("%s/roles/%s", c.config.Mount, name)
	_, err := c.client.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("vault: delete role: %w", err)
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
