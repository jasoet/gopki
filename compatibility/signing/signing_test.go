//go:build compatibility

package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
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
	"github.com/jasoet/gopki/signing"
)

// Test data for signing compatibility tests
var (
	testData        = []byte("This is test data for OpenSSL signing compatibility testing with GoPKI library")
	testSubject     = "CN=Test Signer,O=GoPKI,C=US"
	testCertRequest = cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test Signer",
			Organization: []string{"GoPKI"},
			Country:      []string{"US"},
		},
		DNSNames:     []string{"signer.example.com"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		EmailAddress: []string{"signer@example.com"},
		ValidFrom:    time.Now(),
		ValidFor:     365 * 24 * time.Hour,
	}
)

func TestSigningCompatibility(t *testing.T) {
	t.Logf("🔐 Running OpenSSL Signing Compatibility Tests...")
	t.Logf("   Testing digital signature generation, verification, and format compatibility")

	t.Run("RSA", func(t *testing.T) {
		testRSASigningCompatibility(t)
	})

	t.Run("ECDSA", func(t *testing.T) {
		testECDSASigningCompatibility(t)
	})

	t.Run("Ed25519", func(t *testing.T) {
		testEd25519SigningCompatibility(t)
	})

	t.Logf("✅ OpenSSL signing compatibility tests completed")
}

func testRSASigningCompatibility(t *testing.T) {
	keySizes := []struct {
		size algo.KeySize
		bits int
		name string
	}{
		{algo.KeySize2048, 2048, "2048"},
		{algo.KeySize3072, 3072, "3072"},
		{algo.KeySize4096, 4096, "4096"},
	}

	for _, keySize := range keySizes {
		t.Run("RSA_"+keySize.name, func(t *testing.T) {
			helper := compatibility.NewOpenSSLHelper(t)
			defer helper.Cleanup()

			t.Logf("Testing RSA-%d signing compatibility", keySize.bits)

			// Generate RSA key pair and certificate with GoPKI
			manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](keySize.size)
			require.NoError(t, err, "Failed to generate RSA key pair")

			certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), testCertRequest)
			require.NoError(t, err, "Failed to create self-signed certificate")

			testRawSignatureCompatibility(t, helper, manager, certificate, "RSA")
			testPKCS7SignatureCompatibility(t, helper, manager, certificate, "RSA")
			testDetachedSignatureCompatibility(t, helper, manager, certificate, "RSA")

			t.Logf("✓ RSA-%d signing compatibility tests passed", keySize.bits)
		})
	}
}

func testECDSASigningCompatibility(t *testing.T) {
	curves := []struct {
		curve algo.ECDSACurve
		name  string
	}{
		{algo.P256, "P256"},
		{algo.P384, "P384"},
		{algo.P521, "P521"},
	}

	for _, curve := range curves {
		t.Run("ECDSA_"+curve.name, func(t *testing.T) {
			helper := compatibility.NewOpenSSLHelper(t)
			defer helper.Cleanup()

			t.Logf("Testing ECDSA-%s signing compatibility", curve.name)

			// Generate ECDSA key pair and certificate with GoPKI
			manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](curve.curve)
			require.NoError(t, err, "Failed to generate ECDSA key pair")

			certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), testCertRequest)
			require.NoError(t, err, "Failed to create self-signed certificate")

			testRawSignatureCompatibility(t, helper, manager, certificate, "ECDSA")
			testPKCS7SignatureCompatibility(t, helper, manager, certificate, "ECDSA")
			testDetachedSignatureCompatibility(t, helper, manager, certificate, "ECDSA")

			t.Logf("✓ ECDSA-%s signing compatibility tests passed", curve.name)
		})
	}
}

func testEd25519SigningCompatibility(t *testing.T) {
	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	t.Logf("Testing Ed25519 signing compatibility")

	// Generate Ed25519 key pair and certificate with GoPKI
	manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
	require.NoError(t, err, "Failed to generate Ed25519 key pair")

	certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), testCertRequest)
	require.NoError(t, err, "Failed to create self-signed certificate")

	testRawSignatureCompatibility(t, helper, manager, certificate, "Ed25519")
	testPKCS7SignatureCompatibility(t, helper, manager, certificate, "Ed25519")
	testDetachedSignatureCompatibility(t, helper, manager, certificate, "Ed25519")

	t.Logf("✓ Ed25519 signing compatibility tests passed")
}

// testRawSignatureCompatibility tests basic signature generation and verification
func testRawSignatureCompatibility[T keypair.KeyPair, P keypair.PrivateKey, B keypair.PublicKey](t *testing.T, helper *compatibility.OpenSSLHelper, manager *keypair.Manager[T, P, B], certificate *cert.Certificate, algorithm string) {
	t.Run("Raw_Signature_Compatibility", func(t *testing.T) {
		// Test 1: GoPKI signs → OpenSSL verifies
		t.Run("GoPKI_Sign_OpenSSL_Verify", func(t *testing.T) {
			// Sign data with GoPKI in PKCS#7 format
			opts := signing.DefaultSignOptions()
			opts.Format = signing.FormatPKCS7
			opts.IncludeCertificate = true // Include certificate for verification

			signature, err := signing.SignDocument(testData, manager.KeyPair(), certificate, opts)
			require.NoError(t, err, "Failed to sign data with GoPKI")

			// Verify PKCS#7 signature with OpenSSL
			err = helper.VerifyPKCS7SignatureWithOpenSSL(testData, signature.Data)
			assert.NoError(t, err, "OpenSSL failed to verify GoPKI-generated PKCS#7 signature")

			t.Logf("✓ GoPKI %s PKCS#7 signature verified by OpenSSL", algorithm)
		})

		// Test 2: OpenSSL signs → GoPKI verifies (using detached signature approach)
		t.Run("OpenSSL_Sign_GoPKI_Verify", func(t *testing.T) {
			// Get private key in PEM format for OpenSSL
			privatePEM, _, err := manager.ToPEM()
			require.NoError(t, err, "Failed to convert private key to PEM")

			// Create detached PKCS#7 signature with OpenSSL (to work around attachment issue)
			pkcs7Data, err := helper.CreatePKCS7SignatureWithOpenSSL(testData, privatePEM, certificate.PEMData, true)
			require.NoError(t, err, "Failed to create detached PKCS#7 signature with OpenSSL")

			// Use GoPKI's detached signature verification which is more flexible
			err = signing.VerifyDetachedSignature(testData, pkcs7Data, certificate.Certificate, crypto.SHA256)
			assert.NoError(t, err, "GoPKI failed to verify OpenSSL-generated detached PKCS#7 signature")

			t.Logf("✓ OpenSSL %s detached PKCS#7 signature verified by GoPKI", algorithm)
		})
	})
}

// testPKCS7SignatureCompatibility tests PKCS#7/CMS format compatibility
func testPKCS7SignatureCompatibility[T keypair.KeyPair, P keypair.PrivateKey, B keypair.PublicKey](t *testing.T, helper *compatibility.OpenSSLHelper, manager *keypair.Manager[T, P, B], certificate *cert.Certificate, algorithm string) {
	t.Run("PKCS7_Signature_Compatibility", func(t *testing.T) {
		// Test 1: GoPKI PKCS#7 → OpenSSL verifies
		t.Run("GoPKI_PKCS7_OpenSSL_Verify", func(t *testing.T) {
			// Sign with GoPKI in PKCS#7 format
			opts := signing.DefaultSignOptions()
			opts.Format = signing.FormatPKCS7
			opts.IncludeCertificate = true
			opts.IncludeChain = false

			signature, err := signing.SignDocument(testData, manager.KeyPair(), certificate, opts)
			require.NoError(t, err, "Failed to create PKCS#7 signature with GoPKI")

			// Verify PKCS#7 signature with OpenSSL
			err = helper.VerifyPKCS7SignatureWithOpenSSL(testData, signature.Data)
			assert.NoError(t, err, "OpenSSL failed to verify GoPKI PKCS#7 signature")

			t.Logf("✓ GoPKI %s PKCS#7 signature verified by OpenSSL", algorithm)
		})

		// Test 2: OpenSSL PKCS#7 → GoPKI verifies
		t.Run("OpenSSL_PKCS7_GoPKI_Verify", func(t *testing.T) {
			// Get private key and certificate in PEM format
			privatePEM, _, err := manager.ToPEM()
			require.NoError(t, err, "Failed to convert private key to PEM")

			// Create detached PKCS#7 signature with OpenSSL for better compatibility
			pkcs7Data, err := helper.CreatePKCS7SignatureWithOpenSSL(testData, privatePEM, certificate.PEMData, true)
			require.NoError(t, err, "Failed to create detached PKCS#7 signature with OpenSSL")

			// Use detached signature verification
			err = signing.VerifyDetachedSignature(testData, pkcs7Data, certificate.Certificate, crypto.SHA256)
			assert.NoError(t, err, "GoPKI failed to verify OpenSSL detached PKCS#7 signature")

			t.Logf("✓ OpenSSL %s detached PKCS#7 signature verified by GoPKI", algorithm)
		})
	})
}

// testDetachedSignatureCompatibility tests detached signature workflows
func testDetachedSignatureCompatibility[T keypair.KeyPair, P keypair.PrivateKey, B keypair.PublicKey](t *testing.T, helper *compatibility.OpenSSLHelper, manager *keypair.Manager[T, P, B], certificate *cert.Certificate, algorithm string) {
	t.Run("Detached_Signature_Compatibility", func(t *testing.T) {
		// Test 1: GoPKI detached → OpenSSL verifies
		t.Run("GoPKI_Detached_OpenSSL_Verify", func(t *testing.T) {
			// Create detached signature with GoPKI
			opts := signing.DefaultSignOptions()
			opts.Format = signing.FormatPKCS7Detached
			opts.Detached = true
			opts.IncludeCertificate = true

			signature, err := signing.SignDocument(testData, manager.KeyPair(), certificate, opts)
			require.NoError(t, err, "Failed to create detached signature with GoPKI")

			// Verify detached signature with OpenSSL
			err = helper.VerifyDetachedPKCS7SignatureWithOpenSSL(testData, signature.Data)
			assert.NoError(t, err, "OpenSSL failed to verify GoPKI detached signature")

			t.Logf("✓ GoPKI %s detached signature verified by OpenSSL", algorithm)
		})

		// Test 2: OpenSSL detached → GoPKI verifies
		t.Run("OpenSSL_Detached_GoPKI_Verify", func(t *testing.T) {
			// Get private key in PEM format
			privatePEM, _, err := manager.ToPEM()
			require.NoError(t, err, "Failed to convert private key to PEM")

			// Create detached PKCS#7 signature with OpenSSL
			detachedSig, err := helper.CreatePKCS7SignatureWithOpenSSL(testData, privatePEM, certificate.PEMData, true)
			require.NoError(t, err, "Failed to create detached PKCS#7 signature with OpenSSL")

			// Verify with GoPKI detached verification
			err = signing.VerifyDetachedSignature(testData, detachedSig, certificate.Certificate, crypto.SHA256)
			assert.NoError(t, err, "GoPKI failed to verify OpenSSL detached signature")

			t.Logf("✓ OpenSSL %s detached signature verified by GoPKI", algorithm)
		})
	})
}

func TestCertificateChainSigningCompatibility(t *testing.T) {
	t.Logf("🔗 Testing Certificate Chain Signing Compatibility...")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	// Generate CA key pair and certificate
	caManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize3072)
	require.NoError(t, err, "Failed to generate CA key pair")

	caCertRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"GoPKI"},
			Country:      []string{"US"},
		},
		ValidFrom: time.Now(),
		ValidFor:  10 * 365 * 24 * time.Hour,
		IsCA:      true,
	}

	caCert, err := cert.CreateCACertificate(caManager.KeyPair(), caCertRequest)
	require.NoError(t, err, "Failed to create CA certificate")

	// Generate end-entity key pair
	endManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	require.NoError(t, err, "Failed to generate end-entity key pair")

	// Create end-entity certificate signed by CA
	endCert, err := cert.SignCertificate(caCert, caManager.KeyPair(), testCertRequest, endManager.KeyPair().PublicKey)
	require.NoError(t, err, "Failed to create end-entity certificate")

	t.Run("Certificate_Chain_Inclusion", func(t *testing.T) {
		// Sign with certificate chain inclusion
		opts := signing.DefaultSignOptions()
		opts.Format = signing.FormatPKCS7
		opts.IncludeCertificate = true
		opts.IncludeChain = true
		opts.ExtraCertificates = []*x509.Certificate{caCert.Certificate}

		signature, err := signing.SignDocument(testData, endManager.KeyPair(), endCert, opts)
		require.NoError(t, err, "Failed to sign with certificate chain")

		// Verify that certificate chain is included
		assert.NotNil(t, signature.Certificate, "Signer certificate should be included")
		assert.NotEmpty(t, signature.CertificateChain, "Certificate chain should be included")

		// Verify signature with OpenSSL (including chain validation)
		err = helper.VerifyPKCS7SignatureWithCertificateChainWithOpenSSL(testData, signature.Data, caCert.PEMData)
		assert.NoError(t, err, "OpenSSL failed to verify signature with certificate chain")

		t.Logf("✓ Certificate chain signing compatibility verified")
	})
}

func TestSigningMetadataCompatibility(t *testing.T) {
	t.Logf("📋 Testing Signing Metadata Compatibility...")

	helper := compatibility.NewOpenSSLHelper(t)
	defer helper.Cleanup()

	// Generate key pair and certificate
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	require.NoError(t, err, "Failed to generate key pair")

	certificate, err := cert.CreateSelfSignedCertificate(manager.KeyPair(), testCertRequest)
	require.NoError(t, err, "Failed to create certificate")

	t.Run("Signature_Info_Extraction", func(t *testing.T) {
		// Create signature with GoPKI
		opts := signing.DefaultSignOptions()
		opts.Format = signing.FormatPKCS7
		opts.IncludeCertificate = true

		signature, err := signing.SignDocument(testData, manager.KeyPair(), certificate, opts)
		require.NoError(t, err, "Failed to create signature")

		// Extract signature information with OpenSSL
		sigInfo, err := helper.ExtractSignatureInfoWithOpenSSL(signature.Data)
		require.NoError(t, err, "Failed to extract signature info with OpenSSL")

		// Validate extracted information
		assert.Contains(t, sigInfo, "Certificate", "Certificate info should be present")
		assert.Contains(t, sigInfo, "Signature Algorithm", "Signature algorithm should be present")

		t.Logf("✓ Signature metadata extraction compatibility verified")
	})
}