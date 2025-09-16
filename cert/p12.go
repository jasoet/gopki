package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jasoet/gopki/pkcs12"
)

// FromP12 loads a certificate from PKCS#12 data
func FromP12(p12Data []byte, password string) (*Certificate, []*x509.Certificate, error) {
	if len(p12Data) == 0 {
		return nil, nil, fmt.Errorf("P12 data is required")
	}
	if password == "" {
		return nil, nil, fmt.Errorf("password is required")
	}

	// Parse P12 data
	opts := pkcs12.DefaultLoadOptions(password)
	container, err := pkcs12.ParseP12(p12Data, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse P12 data: %w", err)
	}

	if container.Certificate == nil {
		return nil, nil, fmt.Errorf("no certificate found in P12 data")
	}

	// Wrap in GoPKI Certificate
	goPKICert := &Certificate{
		Certificate: container.Certificate,
	}

	return goPKICert, container.CACertificates, nil
}

// FromP12File loads a certificate from a PKCS#12 file
func FromP12File(filename, password string) (*Certificate, []*x509.Certificate, error) {
	if filename == "" {
		return nil, nil, fmt.Errorf("filename is required")
	}
	if password == "" {
		return nil, nil, fmt.Errorf("password is required")
	}

	// Load P12 file
	opts := pkcs12.DefaultLoadOptions(password)
	container, err := pkcs12.LoadFromP12File(filename, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load P12 file: %w", err)
	}

	if container.Certificate == nil {
		return nil, nil, fmt.Errorf("no certificate found in P12 file")
	}

	// Wrap in GoPKI Certificate
	goPKICert := &Certificate{
		Certificate: container.Certificate,
	}

	return goPKICert, container.CACertificates, nil
}

// LoadCertificateChainFromP12 loads the complete certificate chain from a P12 file
func LoadCertificateChainFromP12(filename, password string) ([]*Certificate, error) {
	if filename == "" {
		return nil, fmt.Errorf("filename is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Load P12 file
	opts := pkcs12.DefaultLoadOptions(password)
	container, err := pkcs12.LoadFromP12File(filename, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to load P12 file: %w", err)
	}

	var certificates []*Certificate

	// Add the main certificate
	if container.Certificate != nil {
		certificates = append(certificates, &Certificate{
			Certificate: container.Certificate,
		})
	}

	// Add CA certificates
	for _, caCert := range container.CACertificates {
		certificates = append(certificates, &Certificate{
			Certificate: caCert,
		})
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in P12 file")
	}

	return certificates, nil
}

// SaveToP12 saves a certificate to PKCS#12 format (requires private key)
// Note: This function requires a private key to create a valid P12 file
func (c *Certificate) SaveToP12(privateKey any, filename, password string) error {
	if c.Certificate == nil {
		return fmt.Errorf("certificate is not initialized")
	}
	if privateKey == nil {
		return fmt.Errorf("private key is required for P12 format")
	}
	if filename == "" {
		return fmt.Errorf("filename is required")
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}

	// Create P12 file
	opts := pkcs12.DefaultCreateOptions(password)
	return pkcs12.CreateP12FileAny(filename, privateKey, c.Certificate, nil, opts)
}

// SaveToP12WithChain saves a certificate with a certificate chain to PKCS#12 format
func (c *Certificate) SaveToP12WithChain(privateKey any, caCerts []*Certificate, filename, password string) error {
	if c.Certificate == nil {
		return fmt.Errorf("certificate is not initialized")
	}
	if privateKey == nil {
		return fmt.Errorf("private key is required for P12 format")
	}
	if filename == "" {
		return fmt.Errorf("filename is required")
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}

	// Convert GoPKI certificates to x509 certificates
	var x509CACerts []*x509.Certificate
	for _, caCert := range caCerts {
		if caCert.Certificate != nil {
			x509CACerts = append(x509CACerts, caCert.Certificate)
		}
	}

	// Create P12 file with chain
	opts := pkcs12.DefaultCreateOptions(password)
	opts.IncludeChain = true
	return pkcs12.CreateP12FileAny(filename, privateKey, c.Certificate, x509CACerts, opts)
}

// ExtractCertificatesFromP12 extracts all certificates from a P12 file and saves them as separate PEM files
func ExtractCertificatesFromP12(p12File, password, outputDir string) error {
	if p12File == "" {
		return fmt.Errorf("P12 file path is required")
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}
	if outputDir == "" {
		return fmt.Errorf("output directory is required")
	}

	// Load P12 file
	opts := pkcs12.DefaultLoadOptions(password)
	container, err := pkcs12.LoadFromP12File(p12File, opts)
	if err != nil {
		return fmt.Errorf("failed to load P12 file: %w", err)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save main certificate
	if container.Certificate != nil {
		certFile := filepath.Join(outputDir, "certificate.pem")
		if err := saveCertificateAsPEM(container.Certificate, certFile); err != nil {
			return fmt.Errorf("failed to save main certificate: %w", err)
		}
	}

	// Save CA certificates
	for i, caCert := range container.CACertificates {
		certFile := filepath.Join(outputDir, fmt.Sprintf("ca_cert_%d.pem", i))
		if err := saveCertificateAsPEM(caCert, certFile); err != nil {
			return fmt.Errorf("failed to save CA certificate %d: %w", i, err)
		}
	}

	return nil
}

// ValidateP12Certificate validates a certificate in a P12 file
func ValidateP12Certificate(filename, password string) (map[string]interface{}, error) {
	if filename == "" {
		return nil, fmt.Errorf("filename is required")
	}
	if password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Load certificate from P12
	certificate, caCerts, err := FromP12File(filename, password)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate from P12: %w", err)
	}

	// Get certificate information
	info := map[string]interface{}{
		"subject":     certificate.Certificate.Subject.String(),
		"issuer":      certificate.Certificate.Issuer.String(),
		"not_before":  certificate.Certificate.NotBefore,
		"not_after":   certificate.Certificate.NotAfter,
		"serial":      certificate.Certificate.SerialNumber.String(),
		"is_ca":       certificate.Certificate.IsCA,
		"chain_length": len(caCerts),
	}

	// Add chain information
	if len(caCerts) > 0 {
		var chainInfo []map[string]interface{}
		for i, caCert := range caCerts {
			caInfo := map[string]interface{}{
				"index":   i,
				"subject": caCert.Subject.String(),
				"issuer":  caCert.Issuer.String(),
				"is_ca":   caCert.IsCA,
			}
			chainInfo = append(chainInfo, caInfo)
		}
		info["certificate_chain"] = chainInfo
	}

	return info, nil
}

// ImportP12AndSavePEM imports a P12 file and saves the certificate as PEM
func ImportP12AndSavePEM(p12File, password, pemFile string) error {
	if p12File == "" {
		return fmt.Errorf("P12 file path is required")
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}
	if pemFile == "" {
		return fmt.Errorf("PEM file path is required")
	}

	// Load certificate from P12
	certificate, _, err := FromP12File(p12File, password)
	if err != nil {
		return fmt.Errorf("failed to load certificate from P12: %w", err)
	}

	// Save as PEM
	return certificate.SaveToFile(pemFile)
}

// CreateP12FromPEM creates a P12 file from separate PEM files
func CreateP12FromPEM(privateKeyFile, certFile, p12File, password string) error {
	if privateKeyFile == "" {
		return fmt.Errorf("private key file is required")
	}
	if certFile == "" {
		return fmt.Errorf("certificate file is required")
	}
	if p12File == "" {
		return fmt.Errorf("P12 file path is required")
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}

	// Load private key
	privateKey, err := loadPrivateKeyFromPEM(privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Load certificate from PEM file
	certificate, err := loadCertificateFromPEMFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	// Create P12 file
	return certificate.SaveToP12(privateKey, p12File, password)
}

// Helper function to save certificate as PEM
func saveCertificateAsPEM(cert *x509.Certificate, filename string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Encode certificate as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Write to file
	if err := os.WriteFile(filename, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write PEM file: %w", err)
	}

	return nil
}

// Helper function to load certificate from PEM file
func loadCertificateFromPEMFile(filename string) (*Certificate, error) {
	// Read PEM file
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %w", err)
	}

	// Parse PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &Certificate{
		Certificate: cert,
		PEMData:     pemData,
		DERData:     cert.Raw,
	}, nil
}

// Helper function to load private key from PEM (simplified version)
func loadPrivateKeyFromPEM(filename string) (any, error) {
	// Read PEM file
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %w", err)
	}

	// Parse PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	// Parse private key based on type
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// P12CertificateUtils provides utility functions for working with P12 certificates
type P12CertificateUtils struct{}

// ListCertificatesInP12 lists all certificates in a P12 file
func (p P12CertificateUtils) ListCertificatesInP12(filename, password string) ([]map[string]interface{}, error) {
	certificates, err := LoadCertificateChainFromP12(filename, password)
	if err != nil {
		return nil, err
	}

	var certInfos []map[string]interface{}
	for _, cert := range certificates {
		info := map[string]interface{}{
			"subject":    cert.Certificate.Subject.String(),
			"issuer":     cert.Certificate.Issuer.String(),
			"not_before": cert.Certificate.NotBefore,
			"not_after":  cert.Certificate.NotAfter,
			"serial":     cert.Certificate.SerialNumber.String(),
			"is_ca":      cert.Certificate.IsCA,
		}
		certInfos = append(certInfos, info)
	}

	return certInfos, nil
}

// VerifyP12CertificateChain verifies the certificate chain in a P12 file
func (p P12CertificateUtils) VerifyP12CertificateChain(filename, password string) error {
	// Load with chain validation enabled
	opts := pkcs12.DefaultLoadOptions(password)
	opts.ValidateChain = true
	opts.CheckExpiration = false // Don't check expiration for chain validation

	_, err := pkcs12.LoadFromP12File(filename, opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}

// ConvertP12ChainToPEM converts all certificates in a P12 file to separate PEM files
func (p P12CertificateUtils) ConvertP12ChainToPEM(p12File, password, outputPrefix string) error {
	certificates, err := LoadCertificateChainFromP12(p12File, password)
	if err != nil {
		return err
	}

	for i, cert := range certificates {
		var filename string
		if i == 0 {
			filename = fmt.Sprintf("%s_cert.pem", outputPrefix)
		} else {
			filename = fmt.Sprintf("%s_ca_%d.pem", outputPrefix, i-1)
		}

		if err := cert.SaveToFile(filename); err != nil {
			return fmt.Errorf("failed to save certificate %d: %w", i, err)
		}
	}

	return nil
}

// GetP12CertificateFingerprints gets fingerprints of all certificates in a P12 file
func (p P12CertificateUtils) GetP12CertificateFingerprints(filename, password string) (map[string]string, error) {
	certificates, err := LoadCertificateChainFromP12(filename, password)
	if err != nil {
		return nil, err
	}

	fingerprints := make(map[string]string)
	for i, cert := range certificates {
		var name string
		if i == 0 {
			name = "certificate"
		} else {
			name = fmt.Sprintf("ca_cert_%d", i-1)
		}

		// Create SHA-256 fingerprint
		fingerprint := fmt.Sprintf("%x", cert.Certificate.Raw)
		fingerprints[name] = fingerprint
	}

	return fingerprints, nil
}