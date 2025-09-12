package keypair

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/jasoet/gopki/pkg/utils"
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
}

func CreateSelfSignedCertificate(keyPair interface{}, request CertificateRequest) (*Certificate, error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey

	switch kp := keyPair.(type) {
	case *RSAKeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	case *ECDSAKeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	case *Ed25519KeyPair:
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

func CreateCACertificate(keyPair interface{}, request CertificateRequest) (*Certificate, error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey

	switch kp := keyPair.(type) {
	case *RSAKeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	case *ECDSAKeyPair:
		privateKey = kp.PrivateKey
		publicKey = kp.PublicKey
	case *Ed25519KeyPair:
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

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               request.Subject,
		NotBefore:             request.ValidFrom,
		NotAfter:              request.ValidFrom.Add(request.ValidFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
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

func SignCertificate(caCert *Certificate, caKeyPair interface{}, request CertificateRequest, subjectPublicKey crypto.PublicKey) (*Certificate, error) {
	var caPrivateKey crypto.PrivateKey

	switch kp := caKeyPair.(type) {
	case *RSAKeyPair:
		caPrivateKey = kp.PrivateKey
	case *ECDSAKeyPair:
		caPrivateKey = kp.PrivateKey
	case *Ed25519KeyPair:
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
	return utils.SavePEMToFile(c.PEMData, filename)
}

func LoadCertificateFromFile(filename string) (*Certificate, error) {
	pemData, err := utils.LoadPEMFromFile(filename)
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