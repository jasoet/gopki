//go:build compatibility

package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/compatibility"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// Test data for certificate compatibility tests
var (
	testSubject = "CN=Test Certificate,O=GoPKI,C=US"
	testSAN     = "DNS:localhost,DNS:example.com,IP:127.0.0.1"
	caSubject   = "CN=Test CA,O=GoPKI,C=US"
)

func TestSelfSignedCertificateCompatibility(t *testing.T) {
	t.Logf("🔐 Running Self-Signed Certificate OpenSSL Compatibility Tests...")
	t.Logf("   Testing self-signed certificate generation and validation")

	t.Run("RSA_2048", func(t *testing.T) {
		t.Logf("Testing RSA-2048 self-signed certificate compatibility")
		testSelfSignedCertificateRSA(t, "RSA-2048", algo.KeySize2048)
	})

	t.Run("RSA_4096", func(t *testing.T) {
		t.Logf("Testing RSA-4096 self-signed certificate compatibility")
		testSelfSignedCertificateRSA(t, "RSA-4096", algo.KeySize4096)
	})

	t.Run("ECDSA_P256", func(t *testing.T) {
		t.Logf("Testing ECDSA-P256 self-signed certificate compatibility")
		testSelfSignedCertificateECDSA(t, "ECDSA-P256", algo.P256)
	})

	t.Run("ECDSA_P384", func(t *testing.T) {
		t.Logf("Testing ECDSA-P384 self-signed certificate compatibility")
		testSelfSignedCertificateECDSA(t, "ECDSA-P384", algo.P384)
	})

	t.Run("Ed25519", func(t *testing.T) {
		t.Logf("Testing Ed25519 self-signed certificate compatibility")
		testSelfSignedCertificateEd25519(t, "Ed25519")
	})
}

func testSelfSignedCertificateRSA(t *testing.T, algName string, keySize algo.KeySize) {
	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("GoPKI_Generate_OpenSSL_Validate", func(t *testing.T) {
		// Generate RSA key pair with GoPKI
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize)
		require.NoError(t, err, "Failed to generate RSA key pair with GoPKI")

		// Create self-signed certificate with GoPKI
		certRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Test Certificate",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			DNSNames:     []string{"localhost", "example.com"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
			EmailAddress: []string{"test@example.com"},
			ValidFrom:    time.Now(),
			ValidFor:     365 * 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), certRequest)
		require.NoError(t, err, "Failed to create self-signed certificate with GoPKI")

		// Validate certificate with OpenSSL
		err = helper.ValidateCertificateWithOpenSSL(certificate.PEMData)
		assert.NoError(t, err, "OpenSSL validation failed for GoPKI-generated certificate")

		t.Logf("✓ GoPKI %s self-signed certificate validated by OpenSSL", algName)
	})

	t.Run("OpenSSL_Generate_GoPKI_Validate", func(t *testing.T) {
		// Generate key pair with GoPKI for OpenSSL to use
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize)
		require.NoError(t, err, "Failed to generate key pair")

		privatePEM, _, err := manager.ToPEM()
		require.NoError(t, err, "Failed to convert private key to PEM")

		// Generate self-signed certificate with OpenSSL
		certPEM, err := helper.GenerateSelfSignedCertWithOpenSSL(privatePEM, testSubject, testSAN)
		require.NoError(t, err, "Failed to generate self-signed certificate with OpenSSL")

		// Validate certificate with GoPKI
		parsedCert, err := cert.ParseCertificateFromPEM(certPEM)
		require.NoError(t, err, "Failed to parse OpenSSL-generated certificate with GoPKI")

		// Verify certificate structure
		assert.NotNil(t, parsedCert.Certificate, "Certificate should be parsed")
		assert.Contains(t, parsedCert.Certificate.Subject.CommonName, "Test Certificate")

		t.Logf("✓ OpenSSL %s self-signed certificate parsed and validated by GoPKI", algName)
	})

	t.Run("Format_Conversion", func(t *testing.T) {
		// Generate certificate with GoPKI
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize)
		require.NoError(t, err, "Failed to generate key pair")

		certRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Format Test Certificate",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			ValidFor: 365 * 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), certRequest)
		require.NoError(t, err, "Failed to create certificate")

		// Test PEM to DER conversion
		derData, err := helper.ConvertCertPEMToDERWithOpenSSL(certificate.PEMData)
		require.NoError(t, err, "Failed to convert PEM to DER with OpenSSL")

		// Test DER to PEM conversion
		pemData, err := helper.ConvertCertDERToPEMWithOpenSSL(derData)
		require.NoError(t, err, "Failed to convert DER to PEM with OpenSSL")

		// Validate converted certificate
		err = helper.ValidateCertificateWithOpenSSL(pemData)
		assert.NoError(t, err, "Failed to validate converted certificate")

		t.Logf("✓ %s certificate format conversion compatibility verified", algName)
	})
}

func testSelfSignedCertificateECDSA(t *testing.T, algName string, curve algo.ECDSACurve) {
	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("GoPKI_Generate_OpenSSL_Validate", func(t *testing.T) {
		// Generate ECDSA key pair with GoPKI
		manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](curve)
		require.NoError(t, err, "Failed to generate ECDSA key pair with GoPKI")

		// Create self-signed certificate with GoPKI
		certRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Test Certificate",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			DNSNames:     []string{"localhost", "example.com"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
			EmailAddress: []string{"test@example.com"},
			ValidFrom:    time.Now(),
			ValidFor:     365 * 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), certRequest)
		require.NoError(t, err, "Failed to create self-signed certificate with GoPKI")

		// Validate certificate with OpenSSL
		err = helper.ValidateCertificateWithOpenSSL(certificate.PEMData)
		assert.NoError(t, err, "OpenSSL validation failed for GoPKI-generated certificate")

		t.Logf("✓ GoPKI %s self-signed certificate validated by OpenSSL", algName)
	})

	t.Run("OpenSSL_Generate_GoPKI_Validate", func(t *testing.T) {
		// Generate key pair with GoPKI for OpenSSL to use
		manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](curve)
		require.NoError(t, err, "Failed to generate key pair")

		privatePEM, _, err := manager.ToPEM()
		require.NoError(t, err, "Failed to convert private key to PEM")

		// Generate self-signed certificate with OpenSSL
		certPEM, err := helper.GenerateSelfSignedCertWithOpenSSL(privatePEM, testSubject, testSAN)
		require.NoError(t, err, "Failed to generate self-signed certificate with OpenSSL")

		// Validate certificate with GoPKI
		parsedCert, err := cert.ParseCertificateFromPEM(certPEM)
		require.NoError(t, err, "Failed to parse OpenSSL-generated certificate with GoPKI")

		// Verify certificate structure
		assert.NotNil(t, parsedCert.Certificate, "Certificate should be parsed")
		assert.Contains(t, parsedCert.Certificate.Subject.CommonName, "Test Certificate")

		t.Logf("✓ OpenSSL %s self-signed certificate parsed and validated by GoPKI", algName)
	})
}

func testSelfSignedCertificateEd25519(t *testing.T, algName string) {
	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("GoPKI_Generate_OpenSSL_Validate", func(t *testing.T) {
		// Generate Ed25519 key pair with GoPKI
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate Ed25519 key pair with GoPKI")

		// Create self-signed certificate with GoPKI
		certRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Test Certificate",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			DNSNames:     []string{"localhost", "example.com"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
			EmailAddress: []string{"test@example.com"},
			ValidFrom:    time.Now(),
			ValidFor:     365 * 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), certRequest)
		require.NoError(t, err, "Failed to create self-signed certificate with GoPKI")

		// Validate certificate with OpenSSL
		err = helper.ValidateCertificateWithOpenSSL(certificate.PEMData)
		assert.NoError(t, err, "OpenSSL validation failed for GoPKI-generated certificate")

		t.Logf("✓ GoPKI %s self-signed certificate validated by OpenSSL", algName)
	})

	t.Run("OpenSSL_Generate_GoPKI_Validate", func(t *testing.T) {
		// Generate key pair with GoPKI for OpenSSL to use
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
		require.NoError(t, err, "Failed to generate key pair")

		privatePEM, _, err := manager.ToPEM()
		require.NoError(t, err, "Failed to convert private key to PEM")

		// Generate self-signed certificate with OpenSSL
		certPEM, err := helper.GenerateSelfSignedCertWithOpenSSL(privatePEM, testSubject, testSAN)
		require.NoError(t, err, "Failed to generate self-signed certificate with OpenSSL")

		// Validate certificate with GoPKI
		parsedCert, err := cert.ParseCertificateFromPEM(certPEM)
		require.NoError(t, err, "Failed to parse OpenSSL-generated certificate with GoPKI")

		// Verify certificate structure
		assert.NotNil(t, parsedCert.Certificate, "Certificate should be parsed")
		assert.Contains(t, parsedCert.Certificate.Subject.CommonName, "Test Certificate")

		t.Logf("✓ OpenSSL %s self-signed certificate parsed and validated by GoPKI", algName)
	})
}

func TestCACertificateCompatibility(t *testing.T) {
	t.Logf("🏛️ Running CA Certificate OpenSSL Compatibility Tests...")
	t.Logf("   Testing CA certificate generation and validation")

	t.Run("RSA_4096_CA", func(t *testing.T) {
		testCACertificateRSA(t, "RSA-4096", algo.KeySize4096)
	})

	t.Run("ECDSA_P384_CA", func(t *testing.T) {
		testCACertificateECDSA(t, "ECDSA-P384", algo.P384)
	})
}

func testCACertificateRSA(t *testing.T, algName string, keySize algo.KeySize) {
	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("GoPKI_Generate_OpenSSL_Validate", func(t *testing.T) {
		// Generate CA key pair with GoPKI
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize)
		require.NoError(t, err, "Failed to generate CA key pair")

		// Create CA certificate with GoPKI
		caRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Test CA",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},

			ValidFor:   10 * 365 * 24 * time.Hour, // 10 years
			IsCA:       true,
			MaxPathLen: 2,
		}

		caCert, err := cert.CreateCACertificate(manager.KeyPair(), caRequest)
		require.NoError(t, err, "Failed to create CA certificate with GoPKI")

		// Validate CA certificate with OpenSSL
		err = helper.ValidateCertificateWithOpenSSL(caCert.PEMData)
		assert.NoError(t, err, "OpenSSL validation failed for GoPKI-generated CA certificate")

		// Verify CA extensions are present
		assert.True(t, caCert.Certificate.IsCA, "Certificate should be marked as CA")
		assert.Equal(t, 2, caCert.Certificate.MaxPathLen, "MaxPathLen should be 2")

		t.Logf("✓ GoPKI %s CA certificate validated by OpenSSL", algName)
	})

	t.Run("OpenSSL_Generate_GoPKI_Validate", func(t *testing.T) {
		// Generate CA key pair with GoPKI for OpenSSL to use
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize)
		require.NoError(t, err, "Failed to generate CA key pair")

		privatePEM, _, err := manager.ToPEM()
		require.NoError(t, err, "Failed to convert CA private key to PEM")

		// Generate CA certificate with OpenSSL
		caCertPEM, err := helper.GenerateCACertWithOpenSSL(privatePEM, caSubject)
		require.NoError(t, err, "Failed to generate CA certificate with OpenSSL")

		// Validate CA certificate with GoPKI
		parsedCACert, err := cert.ParseCertificateFromPEM(caCertPEM)
		require.NoError(t, err, "Failed to parse OpenSSL-generated CA certificate with GoPKI")

		// Verify CA properties
		assert.True(t, parsedCACert.Certificate.IsCA, "Certificate should be marked as CA")
		assert.Contains(t, parsedCACert.Certificate.Subject.CommonName, "Test CA")

		t.Logf("✓ OpenSSL %s CA certificate parsed and validated by GoPKI", algName)
	})
}

func testCACertificateECDSA(t *testing.T, algName string, curve algo.ECDSACurve) {
	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("GoPKI_Generate_OpenSSL_Validate", func(t *testing.T) {
		// Generate CA key pair with GoPKI
		manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](curve)
		require.NoError(t, err, "Failed to generate CA key pair")

		// Create CA certificate with GoPKI
		caRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Test CA",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			ValidFor:   10 * 365 * 24 * time.Hour, // 10 years
			IsCA:       true,
			MaxPathLen: 2,
		}

		caCert, err := cert.CreateCACertificate(manager.KeyPair(), caRequest)
		require.NoError(t, err, "Failed to create CA certificate with GoPKI")

		// Validate CA certificate with OpenSSL
		err = helper.ValidateCertificateWithOpenSSL(caCert.PEMData)
		assert.NoError(t, err, "OpenSSL validation failed for GoPKI-generated CA certificate")

		// Verify CA extensions are present
		assert.True(t, caCert.Certificate.IsCA, "Certificate should be marked as CA")
		assert.Equal(t, 2, caCert.Certificate.MaxPathLen, "MaxPathLen should be 2")

		t.Logf("✓ GoPKI %s CA certificate validated by OpenSSL", algName)
	})
}

func TestCertificateSigningCompatibility(t *testing.T) {
	t.Logf("✍️ Running Certificate Signing OpenSSL Compatibility Tests...")
	t.Logf("   Testing certificate signing and chain validation")

	t.Run("RSA_Certificate_Signing", func(t *testing.T) {
		testCertificateSigningRSA(t, "RSA", algo.KeySize2048)
	})

	t.Run("ECDSA_Certificate_Signing", func(t *testing.T) {
		testCertificateSigningECDSA(t, "ECDSA", algo.P256)
	})
}

func testCertificateSigningRSA(t *testing.T, algName string, keySize algo.KeySize) {
	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("GoPKI_CA_Signs_OpenSSL_Validates", func(t *testing.T) {
		// Create CA with GoPKI
		caManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize)
		require.NoError(t, err, "Failed to generate CA key pair")

		caRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Test CA",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			ValidFor:   10 * 365 * 24 * time.Hour,
			IsCA:       true,
			MaxPathLen: 1,
		}

		caCert, err := cert.CreateCACertificate(caManager.KeyPair(), caRequest)
		require.NoError(t, err, "Failed to create CA certificate")

		// Create end-entity certificate signed by CA
		entityManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize)
		require.NoError(t, err, "Failed to generate entity key pair")

		entityRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Test Server",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			DNSNames:    []string{"server.example.com"},
			IPAddresses: []net.IP{net.IPv4(192, 168, 1, 100)},
			ValidFor:    365 * 24 * time.Hour,
		}

		entityCert, err := cert.SignCertificate(caCert, caManager.KeyPair(), entityRequest, entityManager.PublicKey())
		require.NoError(t, err, "Failed to sign certificate with GoPKI CA")

		// Verify certificate chain with OpenSSL
		err = helper.VerifyCertificateChainWithOpenSSL(entityCert.PEMData, caCert.PEMData)
		assert.NoError(t, err, "OpenSSL chain verification failed for GoPKI-signed certificate")

		t.Logf("✓ GoPKI %s CA-signed certificate verified by OpenSSL", algName)
	})
}

func testCertificateSigningECDSA(t *testing.T, algName string, curve algo.ECDSACurve) {
	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("GoPKI_CA_Signs_OpenSSL_Validates", func(t *testing.T) {
		// Create CA with GoPKI
		caManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](curve)
		require.NoError(t, err, "Failed to generate CA key pair")

		caRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Test CA",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			ValidFor:   10 * 365 * 24 * time.Hour,
			IsCA:       true,
			MaxPathLen: 1,
		}

		caCert, err := cert.CreateCACertificate(caManager.KeyPair(), caRequest)
		require.NoError(t, err, "Failed to create CA certificate")

		// Create end-entity certificate signed by CA
		entityManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](curve)
		require.NoError(t, err, "Failed to generate entity key pair")

		entityRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Test Server",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			DNSNames:    []string{"server.example.com"},
			IPAddresses: []net.IP{net.IPv4(192, 168, 1, 100)},
			ValidFor:    365 * 24 * time.Hour,
		}

		entityCert, err := cert.SignCertificate(caCert, caManager.KeyPair(), entityRequest, entityManager.PublicKey())
		require.NoError(t, err, "Failed to sign certificate with GoPKI CA")

		// Verify certificate chain with OpenSSL
		err = helper.VerifyCertificateChainWithOpenSSL(entityCert.PEMData, caCert.PEMData)
		assert.NoError(t, err, "OpenSSL chain verification failed for GoPKI-signed certificate")

		t.Logf("✓ GoPKI %s CA-signed certificate verified by OpenSSL", algName)
	})
}

func TestSubjectAlternativeNames(t *testing.T) {
	t.Logf("🌐 Running Subject Alternative Names (SAN) Compatibility Tests...")
	t.Logf("   Testing SAN extension compatibility")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("Multi_SAN_Certificate", func(t *testing.T) {
		// Generate key pair
		manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		require.NoError(t, err, "Failed to generate key pair")

		// Create certificate with multiple SAN types
		certRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Multi-SAN Certificate",
				Organization: []string{"GoPKI Test"},
				Country:      []string{"US"},
			},
			DNSNames: []string{
				"example.com",
				"www.example.com",
				"api.example.com",
				"*.staging.example.com",
			},
			IPAddresses: []net.IP{
				net.IPv4(192, 168, 1, 1),
				net.IPv4(10, 0, 0, 1),
				net.ParseIP("2001:db8::1"),
			},
			EmailAddress: []string{
				"admin@example.com",
				"support@example.com",
			},
			ValidFor: 365 * 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), certRequest)
		require.NoError(t, err, "Failed to create multi-SAN certificate")

		// Validate certificate with OpenSSL
		err = helper.ValidateCertificateWithOpenSSL(certificate.PEMData)
		assert.NoError(t, err, "OpenSSL validation failed for multi-SAN certificate")

		// Verify SAN extensions are properly parsed
		assert.Len(t, certificate.Certificate.DNSNames, 4, "Should have 4 DNS names")
		assert.Len(t, certificate.Certificate.IPAddresses, 3, "Should have 3 IP addresses")
		assert.Len(t, certificate.Certificate.EmailAddresses, 2, "Should have 2 email addresses")

		t.Logf("✓ Multi-SAN certificate validated by OpenSSL")
	})
}

func TestCertificateFormatCompatibility(t *testing.T) {
	t.Logf("💾 Running Certificate Format Compatibility Tests...")
	t.Logf("   Testing PEM/DER format interoperability")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("Bidirectional_Format_Conversion", func(t *testing.T) {
		// Generate certificate with GoPKI
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		require.NoError(t, err, "Failed to generate key pair")

		certRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "Format Test Certificate",
				Organization: []string{"GoPKI"},
				Country:      []string{"US"},
			},
			ValidFor: 365 * 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), certRequest)
		require.NoError(t, err, "Failed to create certificate")

		// Test GoPKI format conversion
		derFromGoPKI := certificate.ToDER()
		pemFromGoPKI := certificate.ToPEM()

		// Test OpenSSL format conversion
		derFromOpenSSL, err := helper.ConvertCertPEMToDERWithOpenSSL(pemFromGoPKI)
		require.NoError(t, err, "Failed to convert PEM to DER with OpenSSL")

		pemFromOpenSSL, err := helper.ConvertCertDERToPEMWithOpenSSL(derFromOpenSSL)
		require.NoError(t, err, "Failed to convert DER to PEM with OpenSSL")

		// Cross-validate formats
		assert.Equal(t, derFromGoPKI, derFromOpenSSL, "DER data should match between GoPKI and OpenSSL")

		// Parse converted certificate back with GoPKI
		parsedCert, err := cert.ParseCertificateFromPEM(pemFromOpenSSL)
		require.NoError(t, err, "Failed to parse OpenSSL-converted certificate")

		assert.Equal(t, certificate.Certificate.Subject.CommonName, parsedCert.Certificate.Subject.CommonName)

		t.Logf("✓ Bidirectional format conversion compatibility verified")
	})
}

func TestCompatibilityEdgeCases(t *testing.T) {
	t.Logf("⚠️ Running Certificate Compatibility Edge Cases...")
	t.Logf("   Testing error conditions and edge cases")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Run("Invalid_Certificate_Data", func(t *testing.T) {
		invalidPEM := []byte(`-----BEGIN CERTIFICATE-----
INVALID_BASE64_DATA_HERE
-----END CERTIFICATE-----`)

		err := helper.ValidateCertificateWithOpenSSL(invalidPEM)
		assert.Error(t, err, "OpenSSL should reject invalid certificate data")

		_, err = cert.ParseCertificateFromPEM(invalidPEM)
		assert.Error(t, err, "GoPKI should reject invalid certificate data")

		t.Logf("✓ Invalid certificate data handling verified")
	})

	t.Run("Expired_Certificate_Handling", func(t *testing.T) {
		// Generate certificate with past validity period
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		require.NoError(t, err, "Failed to generate key pair")

		certRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "Expired Certificate",
			},
			ValidFrom: time.Now().Add(-2 * 365 * 24 * time.Hour), // Started 2 years ago
			ValidFor:  365 * 24 * time.Hour,                      // Valid for 1 year (expired 1 year ago)
		}

		expiredCert, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), certRequest)
		require.NoError(t, err, "Failed to create expired certificate")

		// Certificate should parse but validation should indicate expiry
		parsedCert, err := cert.ParseCertificateFromPEM(expiredCert.PEMData)
		require.NoError(t, err, "Expired certificate should still parse")

		assert.True(t, time.Now().After(parsedCert.Certificate.NotAfter), "Certificate should be expired")

		t.Logf("✓ Expired certificate handling verified")
	})
}
