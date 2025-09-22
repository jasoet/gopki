package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"math/big"
	"net"
	"os"
	"time"
)

// Certificate represents an X.509 certificate with support for both PEM and DER formats.
// It contains the parsed certificate and the raw data in both text (PEM) and binary (DER) formats.
type Certificate struct {
	Certificate *x509.Certificate // The parsed X.509 certificate
	PEMData     []byte            // PEM-encoded certificate data (Base64 text format)
	DERData     []byte            // DER-encoded certificate data (binary format)
}

// CertificateRequest contains the parameters for creating a new X.509 certificate.
// It supports both end-entity and CA certificates with configurable extensions and constraints.
type CertificateRequest struct {
	Subject      pkix.Name     // Certificate subject information (CN, O, OU, etc.)
	DNSNames     []string      // Subject Alternative Names - DNS names
	IPAddresses  []net.IP      // Subject Alternative Names - IP addresses
	EmailAddress []string      // Subject Alternative Names - email addresses
	ValidFrom    time.Time     // Certificate validity start time (defaults to now)
	ValidFor     time.Duration // Certificate validity duration (e.g., 365*24*time.Hour for 1 year)

	// CA-specific fields (optional)
	IsCA           bool // Set to true to create a CA certificate
	MaxPathLen     int  // Maximum depth of intermediate CAs (0 = can only sign end-entity certs, -1 = no limit)
	MaxPathLenZero bool // Set to true to explicitly set MaxPathLen to 0

	// Advanced certificate usage fields (optional)
	KeyUsage    x509.KeyUsage      // Custom key usage flags (if not set, defaults based on IsCA)
	ExtKeyUsage []x509.ExtKeyUsage // Custom extended key usage (if not set, defaults based on IsCA)
}

// CreateSelfSignedCertificate creates a new self-signed X.509 certificate using the provided key pair.
// The certificate is signed by its own private key, making it suitable for testing, development,
// or as a root CA certificate.
//
// Type parameter T must be one of: *algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair.
//
// The returned Certificate contains both PEM and DER encoded data and can be saved in either format.
//
// Example:
//
//	keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
//	cert, err := CreateSelfSignedCertificate(keyPair, CertificateRequest{
//		Subject: pkix.Name{CommonName: "example.com"},
//		DNSNames: []string{"example.com", "www.example.com"},
//		ValidFor: 365 * 24 * time.Hour,
//	})
func CreateSelfSignedCertificate[T keypair.KeyPair](keyPair T, request CertificateRequest) (*Certificate, error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	case *algo.ECDSAKeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	case *algo.Ed25519KeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	default:
		return nil, fmt.Errorf("unsupported key pair type")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	if request.ValidFrom.IsZero() {
		request.ValidFrom = time.Now()
	}

	if request.ValidFor == 0 {
		request.ValidFor = 365 * 24 * time.Hour // Default 1 year
	}

	// Determine key usage
	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage

	// Check if custom key usage is provided
	if request.KeyUsage != 0 {
		keyUsage = request.KeyUsage
	} else if request.IsCA {
		// CA certificate
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		// End-entity certificate
		keyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	}

	// Check if custom extended key usage is provided
	if request.ExtKeyUsage != nil {
		extKeyUsage = request.ExtKeyUsage
	} else if request.IsCA {
		// CAs typically don't need extended key usage
		extKeyUsage = nil
	} else {
		// End-entity certificate - for TLS/authentication
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               request.Subject,
		NotBefore:             request.ValidFrom,
		NotAfter:              request.ValidFrom.Add(request.ValidFor),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  request.IsCA,
		DNSNames:              request.DNSNames,
		IPAddresses:           request.IPAddresses,
		EmailAddresses:        request.EmailAddress,
	}

	// Set MaxPathLen for CA certificates
	if request.IsCA {
		if request.MaxPathLenZero {
			template.MaxPathLen = 0
			template.MaxPathLenZero = true
		} else if request.MaxPathLen >= 0 {
			template.MaxPathLen = request.MaxPathLen
		}
		// If MaxPathLen is -1, we don't set it (no limit)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &Certificate{
		Certificate: cert,
		PEMData:     certPEM,
		DERData:     certDER,
	}, nil
}

// CreateCACertificate creates a new Certificate Authority (CA) certificate.
// The certificate is configured with CA-specific extensions and can be used to sign other certificates.
//
// The certificate will have:
// - BasicConstraints extension with CA=true
// - KeyUsage extension with CertSign and CRLSign
// - Configurable path length constraints for intermediate CAs
//
// Type parameter T must be one of: *algo.RSAKeyPair, *algo.ECDSAKeyPair, or *algo.Ed25519KeyPair.
//
// Example:
//
//	keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](4096)
//	caCert, err := CreateCACertificate(keyPair, CertificateRequest{
//		Subject: pkix.Name{CommonName: "My Root CA"},
//		ValidFor: 10 * 365 * 24 * time.Hour, // 10 years
//		IsCA: true,
//		MaxPathLen: 2, // Allow 2 levels of intermediate CAs
//	})
func CreateCACertificate[T keypair.KeyPair](keyPair T, request CertificateRequest) (*Certificate, error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey

	switch kp := any(keyPair).(type) {
	case *algo.RSAKeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	case *algo.ECDSAKeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	case *algo.Ed25519KeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	default:
		return nil, fmt.Errorf("unsupported key pair type")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	if request.ValidFrom.IsZero() {
		request.ValidFrom = time.Now()
	}

	if request.ValidFor == 0 {
		request.ValidFor = 10 * 365 * 24 * time.Hour // Default 10 years for CA
	}

	// Set MaxPathLen based on request or use default
	maxPathLen := 0
	maxPathLenZero := true

	if request.MaxPathLen > 0 {
		maxPathLen = request.MaxPathLen
		maxPathLenZero = false
	} else if request.MaxPathLen == -1 {
		// -1 means no limit, don't set MaxPathLen
		maxPathLenZero = false
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               request.Subject,
		NotBefore:             request.ValidFrom,
		NotAfter:              request.ValidFrom.Add(request.ValidFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLenZero,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &Certificate{
		Certificate: cert,
		PEMData:     certPEM,
		DERData:     certDER,
	}, nil
}

// SignCertificate creates a new certificate signed by a Certificate Authority (CA).
// This function creates an end-entity or intermediate CA certificate using the provided CA certificate
// and private key to sign the new certificate.
//
// Parameters:
//   - caCert: The CA certificate used to sign the new certificate
//   - caKeyPair: The CA's private key pair for signing
//   - request: Certificate request containing subject info and extensions
//   - subjectPublicKey: The public key to be certified (from the entity requesting the certificate)
//
// The resulting certificate will be signed by the CA and contain the subject's public key.
//
// Example:
//
//	// Create CA certificate first
//	caCert, _ := CreateCACertificate(caKeyPair, caRequest)
//
//	// Create end-entity certificate signed by CA
//	entityKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
//	cert, err := SignCertificate(caCert, caKeyPair, CertificateRequest{
//		Subject: pkix.Name{CommonName: "server.example.com"},
//		DNSNames: []string{"server.example.com"},
//		ValidFor: 365 * 24 * time.Hour,
//	}, entityKeyPair.PublicKey)
func SignCertificate[T keypair.KeyPair](caCert *Certificate, caKeyPair T, request CertificateRequest, subjectPublicKey crypto.PublicKey) (*Certificate, error) {
	var caPrivateKey crypto.PrivateKey

	switch kp := any(caKeyPair).(type) {
	case *algo.RSAKeyPair:
		caPrivateKey = kp.PrivateKey
	case *algo.ECDSAKeyPair:
		caPrivateKey = kp.PrivateKey
	case *algo.Ed25519KeyPair:
		caPrivateKey = kp.PrivateKey
	default:
		return nil, fmt.Errorf("unsupported CA key pair type")
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	if request.ValidFrom.IsZero() {
		request.ValidFrom = time.Now()
	}

	if request.ValidFor == 0 {
		if request.IsCA {
			request.ValidFor = 5 * 365 * 24 * time.Hour // Default 5 years for intermediate CA
		} else {
			request.ValidFor = 365 * 24 * time.Hour // Default 1 year for end-entity
		}
	}

	// Determine key usage based on whether this is a CA certificate
	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage

	// Check if custom key usage is provided
	if request.KeyUsage != 0 {
		keyUsage = request.KeyUsage
	} else if request.IsCA {
		// CA certificate - can sign other certificates
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		// End-entity certificate - for TLS/authentication
		keyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	}

	// Check if custom extended key usage is provided
	if request.ExtKeyUsage != nil {
		extKeyUsage = request.ExtKeyUsage
	} else if request.IsCA {
		// CAs typically don't need extended key usage
		extKeyUsage = nil
	} else {
		// End-entity certificate - for TLS/authentication
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               request.Subject,
		NotBefore:             request.ValidFrom,
		NotAfter:              request.ValidFrom.Add(request.ValidFor),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  request.IsCA,
		DNSNames:              request.DNSNames,
		IPAddresses:           request.IPAddresses,
		EmailAddresses:        request.EmailAddress,
	}

	// Set MaxPathLen for CA certificates
	if request.IsCA {
		if request.MaxPathLenZero {
			template.MaxPathLen = 0
			template.MaxPathLenZero = true
		} else if request.MaxPathLen >= 0 {
			template.MaxPathLen = request.MaxPathLen
		}
		// If MaxPathLen is -1, we don't set it (no limit)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert.Certificate, subjectPublicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &Certificate{
		Certificate: cert,
		PEMData:     certPEM,
		DERData:     certDER,
	}, nil
}

// SaveToFile saves the certificate to a file in PEM format.
// The file will be created with 0600 permissions (readable/writable by owner only).
//
// Example:
//
//	err := certificate.SaveToFile("certificate.pem")
func (c *Certificate) SaveToFile(filename string) error {
	return os.WriteFile(filename, c.PEMData, 0600)
}

// LoadCertificateFromFile loads a certificate from a PEM-formatted file.
// The function reads the file and parses the PEM data to create a Certificate object
// with both PEM and DER data populated.
//
// Example:
//
//	certificate, err := LoadCertificateFromFile("certificate.pem")
func LoadCertificateFromFile(filename string) (*Certificate, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to load PEM data: %v", err)
	}

	return ParseCertificateFromPEM(pemData)
}

// ParseCertificateFromPEM parses a certificate from PEM-encoded data.
// The function decodes the PEM block and creates a Certificate object with both
// PEM and DER data populated.
//
// The PEM data should contain a "CERTIFICATE" block:
//
//	-----BEGIN CERTIFICATE-----
//	...base64 encoded certificate data...
//	-----END CERTIFICATE-----
//
// Example:
//
//	certificate, err := ParseCertificateFromPEM(pemBytes)
func ParseCertificateFromPEM(pemData []byte) (*Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM block type: %s, expected CERTIFICATE", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return &Certificate{
		Certificate: cert,
		PEMData:     pemData,
		DERData:     block.Bytes, // DER data is in the PEM block's Bytes
	}, nil
}

// VerifyCertificate verifies that a certificate was signed by a Certificate Authority (CA).
// It checks the certificate's signature against the provided CA certificate and validates
// the certificate chain.
//
// The function performs the following verifications:
// - Signature verification using the CA's public key
// - Certificate validity period (not expired)
// - Certificate chain validation
//
// Example:
//
//	err := VerifyCertificate(serverCert, caCert)
//	if err != nil {
//		log.Printf("Certificate verification failed: %v", err)
//	}
func VerifyCertificate(cert *Certificate, caCert *Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(caCert.Certificate)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err := cert.Certificate.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	return nil
}

// DER Format Support Functions

// SaveToDERFile saves the certificate to a file in DER (binary) format.
// The file will be created with 0600 permissions (readable/writable by owner only).
// DER format is more compact than PEM (typically 30% smaller) and faster to parse.
//
// Example:
//
//	err := certificate.SaveToDERFile("certificate.der")
func (c *Certificate) SaveToDERFile(filename string) error {
	return os.WriteFile(filename, c.DERData, 0600)
}

// LoadCertificateFromDERFile loads a certificate from a DER-formatted file.
// The function reads the binary DER file and creates a Certificate object with both
// PEM and DER data populated.
//
// Example:
//
//	certificate, err := LoadCertificateFromDERFile("certificate.der")
func LoadCertificateFromDERFile(filename string) (*Certificate, error) {
	derData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to load DER data: %v", err)
	}

	return ParseCertificateFromDER(derData)
}

// ParseCertificateFromDER parses a certificate from DER-encoded (binary) data.
// The function parses the binary ASN.1 data and creates a Certificate object with both
// PEM and DER data populated.
//
// Example:
//
//	certificate, err := ParseCertificateFromDER(derBytes)
func ParseCertificateFromDER(derData []byte) (*Certificate, error) {
	cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate: %v", err)
	}

	// Convert DER to PEM for consistency
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derData,
	})

	return &Certificate{
		Certificate: cert,
		PEMData:     certPEM,
		DERData:     derData,
	}, nil
}

// ToDER returns the DER-encoded (binary) certificate data.
// DER format is more compact than PEM and suitable for binary storage or transmission.
//
// Example:
//
//	derData := certificate.ToDER()
//	fmt.Printf("Certificate size: %d bytes\n", len(derData))
func (c *Certificate) ToDER() []byte {
	return c.DERData
}

// ToPEM returns the PEM-encoded (Base64 text) certificate data.
// PEM format is human-readable and widely supported by certificate management tools.
// The returned data includes the "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----" headers.
//
// Example:
//
//	pemData := certificate.ToPEM()
//	fmt.Printf("Certificate in PEM format:\n%s", pemData)
func (c *Certificate) ToPEM() []byte {
	return c.PEMData
}

// ConvertPEMToDER converts PEM-encoded certificate data to DER (binary) format.
// This function extracts the Base64-decoded certificate data from PEM format,
// removing the headers and returning the raw binary DER data.
//
// The conversion results in a smaller file size (typically 30% reduction) and
// faster parsing compared to PEM format.
//
// Example:
//
//	derData, err := ConvertPEMToDER(pemBytes)
//	if err != nil {
//		log.Fatal("Conversion failed:", err)
//	}
func ConvertPEMToDER(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM block type: %s, expected CERTIFICATE", block.Type)
	}

	return block.Bytes, nil
}

// ConvertDERToPEM converts DER-encoded (binary) certificate data to PEM format.
// This function validates the DER certificate data and wraps it in PEM headers
// with Base64 encoding for text-based storage and transmission.
//
// The resulting PEM format is human-readable and compatible with most certificate
// management tools and applications.
//
// Example:
//
//	pemData, err := ConvertDERToPEM(derBytes)
//	if err != nil {
//		log.Fatal("Conversion failed:", err)
//	}
//	fmt.Printf("Certificate in PEM format:\n%s", pemData)
func ConvertDERToPEM(derData []byte) ([]byte, error) {
	// Validate that this is a valid certificate
	_, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, fmt.Errorf("invalid DER certificate data: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derData,
	})

	return certPEM, nil
}
