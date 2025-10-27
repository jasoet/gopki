package vault

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"net"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

// vaultIssueResponse represents Vault's response from the issue endpoint.
type vaultIssueResponse struct {
	Data struct {
		Certificate    string   `json:"certificate"`
		IssuingCA      string   `json:"issuing_ca"`
		CAChain        []string `json:"ca_chain"`
		PrivateKey     string   `json:"private_key,omitempty"`
		PrivateKeyType string   `json:"private_key_type,omitempty"`
		SerialNumber   string   `json:"serial_number"`
		Expiration     int64    `json:"expiration"`
	} `json:"data"`
}

// vaultSignResponse represents Vault's response from the sign endpoint.
type vaultSignResponse struct {
	Data struct {
		Certificate  string   `json:"certificate"`
		IssuingCA    string   `json:"issuing_ca"`
		CAChain      []string `json:"ca_chain"`
		SerialNumber string   `json:"serial_number"`
		Expiration   int64    `json:"expiration"`
	} `json:"data"`
}

// IssueCertificateWithKeyPair issues a certificate from Vault using a locally generated key pair.
// The private key never leaves the local system - only a CSR is sent to Vault.
//
// The keyPair parameter must be one of: *algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair.
//
// Example:
//
//	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
//	certificate, err := client.IssueCertificateWithKeyPair(ctx, "web-server", keyPair, &vault.IssueOptions{
//	    CommonName: "app.example.com",
//	    AltNames:   []string{"www.app.example.com"},
//	    TTL:        "720h",
//	})
func (c *Client) IssueCertificateWithKeyPair(
	ctx context.Context,
	role string,
	keyPair interface{},
	opts *IssueOptions,
) (*cert.Certificate, error) {
	if role == "" {
		return nil, fmt.Errorf("vault: role is required")
	}
	if opts == nil {
		return nil, fmt.Errorf("vault: options are required")
	}

	// Create CSR from key pair
	csrRequest := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		DNSNames:     opts.AltNames,
		IPAddresses:  parseIPAddresses(opts.IPSANs),
		EmailAddress: opts.URISANs, // Note: Vault uses URISANs for email
	}

	// Create CSR using type assertions (Go doesn't support generic methods)
	var csr *cert.CertificateSigningRequest
	var err error

	switch kp := keyPair.(type) {
	case *algo.RSAKeyPair:
		csr, err = cert.CreateCSR(kp, csrRequest)
	case *algo.ECDSAKeyPair:
		csr, err = cert.CreateCSR(kp, csrRequest)
	case *algo.Ed25519KeyPair:
		csr, err = cert.CreateCSR(kp, csrRequest)
	default:
		return nil, fmt.Errorf("vault: unsupported key pair type: %T", keyPair)
	}

	if err != nil {
		return nil, fmt.Errorf("vault: create CSR: %w", err)
	}

	// Sign the CSR with Vault
	signOpts := &SignOptions{
		CommonName:        opts.CommonName,
		AltNames:          opts.AltNames,
		IPSANs:            opts.IPSANs,
		URISANs:           opts.URISANs,
		TTL:               opts.TTL,
		Format:            opts.Format,
		ExcludeCNFromSANs: opts.ExcludeCNFromSANs,
	}

	return c.SignCSR(ctx, role, csr, signOpts)
}

// SignCSR signs a Certificate Signing Request using Vault.
// This allows you to generate the key pair locally and only send the CSR to Vault for signing.
//
// Example:
//
//	// Create CSR locally
//	keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{
//	    Subject: pkix.Name{CommonName: "service.example.com"},
//	})
//
//	// Sign with Vault
//	certificate, err := client.SignCSR(ctx, "web-server", csr, &vault.SignOptions{
//	    TTL: "8760h", // 1 year
//	})
func (c *Client) SignCSR(
	ctx context.Context,
	role string,
	csr *cert.CertificateSigningRequest,
	opts *SignOptions,
) (*cert.Certificate, error) {
	if role == "" {
		return nil, fmt.Errorf("vault: role is required")
	}
	if csr == nil {
		return nil, fmt.Errorf("vault: CSR is required")
	}

	// Build request body
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
		if opts.TTL != "" {
			reqBody["ttl"] = opts.TTL
		}
		if opts.Format != "" {
			reqBody["format"] = opts.Format
		}
		if opts.ExcludeCNFromSANs {
			reqBody["exclude_cn_from_sans"] = true
		}
	}

	// Use SDK to sign CSR
	path := fmt.Sprintf("%s/sign/%s", c.config.Mount, role)
	secret, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("vault: sign CSR: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: sign CSR: empty response")
	}

	// Extract certificate data from response
	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("vault: sign CSR: invalid certificate data")
	}

	issuingCAPEM := ""
	if ca, ok := secret.Data["issuing_ca"].(string); ok {
		issuingCAPEM = ca
	}

	// Convert to GoPKI certificate
	certificate, err := vaultCertToGoPKI(certificatePEM, issuingCAPEM)
	if err != nil {
		return nil, fmt.Errorf("vault: sign CSR: %w", err)
	}

	return certificate, nil
}

// GetCertificate retrieves a certificate from Vault by serial number.
//
// Example:
//
//	certificate, err := client.GetCertificate(ctx, "39:dd:2e:90:b7:23:1f:8d")
func (c *Client) GetCertificate(ctx context.Context, serial string) (*cert.Certificate, error) {
	if serial == "" {
		return nil, fmt.Errorf("vault: serial number is required")
	}

	// Use SDK to read certificate
	path := fmt.Sprintf("%s/cert/%s", c.config.Mount, serial)
	secret, err := c.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault: get certificate: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault: get certificate: not found")
	}

	// Extract certificate data from response
	certificatePEM, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("vault: get certificate: invalid certificate data")
	}

	// Convert to GoPKI certificate
	certificate, err := vaultCertToGoPKI(certificatePEM, "")
	if err != nil {
		return nil, fmt.Errorf("vault: get certificate: %w", err)
	}

	return certificate, nil
}

// ListCertificates lists all certificate serial numbers in Vault.
//
// Example:
//
//	serials, err := client.ListCertificates(ctx)
//	for _, serial := range serials {
//	    fmt.Println(serial)
//	}
func (c *Client) ListCertificates(ctx context.Context) ([]string, error) {
	// Use SDK to list certificates
	path := fmt.Sprintf("%s/certs", c.config.Mount)
	secret, err := c.client.Logical().ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault: list certificates: %w", err)
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

// RevokeCertificate revokes a certificate by serial number.
//
// Example:
//
//	err := client.RevokeCertificate(ctx, "39:dd:2e:90:b7:23:1f:8d")
func (c *Client) RevokeCertificate(ctx context.Context, serial string) error {
	if serial == "" {
		return fmt.Errorf("vault: serial number is required")
	}

	// Build request body
	reqBody := map[string]interface{}{
		"serial_number": serial,
	}

	// Use SDK to revoke certificate
	path := fmt.Sprintf("%s/revoke", c.config.Mount)
	_, err := c.client.Logical().WriteWithContext(ctx, path, reqBody)
	if err != nil {
		return fmt.Errorf("vault: revoke certificate: %w", err)
	}

	return nil
}

// Helper functions

func parseIPAddresses(ipStrings []string) []net.IP {
	var ips []net.IP
	for _, ipStr := range ipStrings {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

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
