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

type Certificate struct {
	Certificate *x509.Certificate
	PEMData     []byte
}

type CertificateRequest struct {
	Subject      pkix.Name
	DNSNames     []string
	IPAddresses  []net.IP
	EmailAddress []string
	ValidFrom    time.Time
	ValidFor     time.Duration

	// CA-specific fields (optional)
	IsCA           bool // Set to true to create a CA certificate
	MaxPathLen     int  // Maximum depth of intermediate CAs (0 = can only sign end-entity certs, -1 = no limit)
	MaxPathLenZero bool // Set to true to explicitly set MaxPathLen to 0
}

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

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               request.Subject,
		NotBefore:             request.ValidFrom,
		NotAfter:              request.ValidFrom.Add(request.ValidFor),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              request.DNSNames,
		IPAddresses:           request.IPAddresses,
		EmailAddresses:        request.EmailAddress,
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
	}, nil
}

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
	}, nil
}

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

	if request.IsCA {
		// CA certificate - can sign other certificates
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		// CAs typically don't need extended key usage
		extKeyUsage = nil
	} else {
		// End-entity certificate - for TLS/authentication
		keyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
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
	}, nil
}

func (c *Certificate) SaveToFile(filename string) error {
	return os.WriteFile(filename, c.PEMData, 0600)
}

func LoadCertificateFromFile(filename string) (*Certificate, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to load PEM data: %v", err)
	}

	return ParseCertificateFromPEM(pemData)
}

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
	}, nil
}

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
