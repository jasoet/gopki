package pkcs12

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestToP12KeyPairFunctions(t *testing.T) {
	tempDir := t.TempDir()
	password := "test123"

	// Helper function to create certificate
	createCertificate := func(keyPair keypair.GenericKeyPair) *x509.Certificate {
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test Certificate",
				Organization: []string{"Test Org"},
				Country:      []string{"US"},
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SerialNumber: big.NewInt(1),
		}

		var publicKey any
		var privateKey any

		switch kp := keyPair.(type) {
		case *algo.RSAKeyPair:
			publicKey = kp.PublicKey
			privateKey = kp.PrivateKey
		case *algo.ECDSAKeyPair:
			publicKey = kp.PublicKey
			privateKey = kp.PrivateKey
		case *algo.Ed25519KeyPair:
			publicKey = kp.PublicKey
			privateKey = kp.PrivateKey
		default:
			t.Fatalf("Unsupported key pair type: %T", keyPair)
			return nil
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		certificate, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		return certificate
	}

	t.Run("ToP12KeyPair RSA", func(t *testing.T) {
		// Generate RSA key pair
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		rsaKeys := manager.KeyPair()

		// Create certificate
		certificate := createCertificate(rsaKeys)

		// Test ToP12KeyPair generic function
		p12Data, err := ToP12KeyPair(rsaKeys, certificate, password)
		if err != nil {
			t.Fatalf("ToP12KeyPair failed: %v", err)
		}

		if len(p12Data) == 0 {
			t.Error("P12 data is empty")
		}

		// Test ToP12RSAKeyPair specific function
		p12DataRSA, err := ToP12RSAKeyPair(rsaKeys, certificate, password)
		if err != nil {
			t.Fatalf("ToP12RSAKeyPair failed: %v", err)
		}

		if len(p12DataRSA) == 0 {
			t.Error("P12 RSA data is empty")
		}
	})

	t.Run("ToP12KeyPair ECDSA", func(t *testing.T) {
		// Generate ECDSA key pair
		manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}
		ecdsaKeys := manager.KeyPair()

		// Create certificate
		certificate := createCertificate(ecdsaKeys)

		// Test ToP12KeyPair generic function
		p12Data, err := ToP12KeyPair(ecdsaKeys, certificate, password)
		if err != nil {
			t.Fatalf("ToP12KeyPair failed: %v", err)
		}

		if len(p12Data) == 0 {
			t.Error("P12 data is empty")
		}

		// Test ToP12ECDSAKeyPair specific function
		p12DataECDSA, err := ToP12ECDSAKeyPair(ecdsaKeys, certificate, password)
		if err != nil {
			t.Fatalf("ToP12ECDSAKeyPair failed: %v", err)
		}

		if len(p12DataECDSA) == 0 {
			t.Error("P12 ECDSA data is empty")
		}
	})

	t.Run("ToP12KeyPair Ed25519", func(t *testing.T) {
		// Generate Ed25519 key pair
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}
		ed25519Keys := manager.KeyPair()

		// Create certificate
		certificate := createCertificate(ed25519Keys)

		// Test ToP12KeyPair generic function
		p12Data, err := ToP12KeyPair(ed25519Keys, certificate, password)
		if err != nil {
			t.Fatalf("ToP12KeyPair failed: %v", err)
		}

		if len(p12Data) == 0 {
			t.Error("P12 data is empty")
		}

		// Test ToP12Ed25519KeyPair specific function
		p12DataEd25519, err := ToP12Ed25519KeyPair(ed25519Keys, certificate, password)
		if err != nil {
			t.Fatalf("ToP12Ed25519KeyPair failed: %v", err)
		}

		if len(p12DataEd25519) == 0 {
			t.Error("P12 Ed25519 data is empty")
		}
	})

	t.Run("ToP12KeyPairFile", func(t *testing.T) {
		// Generate RSA key pair
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		rsaKeys := manager.KeyPair()

		// Create certificate
		certificate := createCertificate(rsaKeys)

		// Test ToP12KeyPairFile
		p12File := filepath.Join(tempDir, "test_rsa.p12")
		err = ToP12KeyPairFile(rsaKeys, certificate, p12File, password)
		if err != nil {
			t.Fatalf("ToP12KeyPairFile failed: %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(p12File); os.IsNotExist(err) {
			t.Error("P12 file was not created")
		}

		// Verify file size
		fileInfo, err := os.Stat(p12File)
		if err != nil {
			t.Fatalf("Failed to stat P12 file: %v", err)
		}
		if fileInfo.Size() == 0 {
			t.Error("P12 file is empty")
		}
	})
}

func TestFromP12KeyPairFunctions(t *testing.T) {
	tempDir := t.TempDir()
	password := "test123"

	// Helper function to create certificate using x509 directly
	createSelfSignedCertificate := func(keyPair keypair.GenericKeyPair) *x509.Certificate {
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test Certificate",
				Organization: []string{"Test Org"},
				Country:      []string{"US"},
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SerialNumber: big.NewInt(1),
		}

		var publicKey any
		var privateKey any

		switch kp := keyPair.(type) {
		case *algo.RSAKeyPair:
			publicKey = kp.PublicKey
			privateKey = kp.PrivateKey
		case *algo.ECDSAKeyPair:
			publicKey = kp.PublicKey
			privateKey = kp.PrivateKey
		case *algo.Ed25519KeyPair:
			publicKey = kp.PublicKey
			privateKey = kp.PrivateKey
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		certificate, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		return certificate
	}

	t.Run("FromP12KeyPair RSA Round Trip", func(t *testing.T) {
		// Generate RSA key pair
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		originalKeys := manager.KeyPair()

		// Create certificate
		originalCert := createSelfSignedCertificate(originalKeys)

		// Export to P12
		p12Data, err := ToP12KeyPair(originalKeys, originalCert, password)
		if err != nil {
			t.Fatalf("ToP12KeyPair failed: %v", err)
		}

		// Import using generic function
		loadedKeys, loadedCert, caCerts, err := FromP12KeyPair[*algo.RSAKeyPair](p12Data, password)
		if err != nil {
			t.Fatalf("FromP12KeyPair failed: %v", err)
		}

		// Verify loaded keys
		if loadedKeys == nil {
			t.Fatal("Loaded keys are nil")
		}
		if loadedKeys.PrivateKey == nil {
			t.Error("Loaded private key is nil")
		}
		if loadedKeys.PublicKey == nil {
			t.Error("Loaded public key is nil")
		}

		// Verify certificate
		if loadedCert == nil {
			t.Fatal("Loaded certificate is nil")
		}
		if loadedCert.Subject.CommonName != "Test Certificate" {
			t.Error("Certificate subject mismatch")
		}

		// Verify CA certificates
		if len(caCerts) != 0 {
			t.Errorf("Expected 0 CA certificates, got %d", len(caCerts))
		}

		// Test type-specific function
		loadedKeysRSA, loadedCertRSA, caCertsRSA, err := FromP12RSAKeyPair(p12Data, password)
		if err != nil {
			t.Fatalf("FromP12RSAKeyPair failed: %v", err)
		}

		if loadedKeysRSA == nil {
			t.Fatal("Loaded RSA keys are nil")
		}
		if loadedCertRSA == nil {
			t.Fatal("Loaded RSA certificate is nil")
		}
		if len(caCertsRSA) != 0 {
			t.Errorf("Expected 0 RSA CA certificates, got %d", len(caCertsRSA))
		}
	})

	t.Run("FromP12KeyPair ECDSA Round Trip", func(t *testing.T) {
		// Generate ECDSA key pair
		manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}
		originalKeys := manager.KeyPair()

		// Create certificate
		originalCert := createSelfSignedCertificate(originalKeys)

		// Export to P12
		p12Data, err := ToP12KeyPair(originalKeys, originalCert, password)
		if err != nil {
			t.Fatalf("ToP12KeyPair failed: %v", err)
		}

		// Import using generic function
		loadedKeys, loadedCert, _, err := FromP12KeyPair[*algo.ECDSAKeyPair](p12Data, password)
		if err != nil {
			t.Fatalf("FromP12KeyPair failed: %v", err)
		}

		// Verify loaded keys
		if loadedKeys == nil {
			t.Fatal("Loaded keys are nil")
		}
		if loadedKeys.PrivateKey == nil {
			t.Error("Loaded private key is nil")
		}
		if loadedKeys.PublicKey == nil {
			t.Error("Loaded public key is nil")
		}

		// Verify certificate
		if loadedCert == nil {
			t.Fatal("Loaded certificate is nil")
		}
		if loadedCert.Subject.CommonName != "Test Certificate" {
			t.Error("Certificate subject mismatch")
		}

		// Test type-specific function
		loadedKeysECDSA, _, _, err := FromP12ECDSAKeyPair(p12Data, password)
		if err != nil {
			t.Fatalf("FromP12ECDSAKeyPair failed: %v", err)
		}

		if loadedKeysECDSA == nil {
			t.Fatal("Loaded ECDSA keys are nil")
		}
	})

	t.Run("FromP12KeyPair Ed25519 Round Trip", func(t *testing.T) {
		// Generate Ed25519 key pair
		manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}
		originalKeys := manager.KeyPair()

		// Create certificate
		originalCert := createSelfSignedCertificate(originalKeys)

		// Export to P12
		p12Data, err := ToP12KeyPair(originalKeys, originalCert, password)
		if err != nil {
			t.Fatalf("ToP12KeyPair failed: %v", err)
		}

		// Import using generic function
		loadedKeys, loadedCert, _, err := FromP12KeyPair[*algo.Ed25519KeyPair](p12Data, password)
		if err != nil {
			t.Fatalf("FromP12KeyPair failed: %v", err)
		}

		// Verify loaded keys
		if loadedKeys == nil {
			t.Fatal("Loaded keys are nil")
		}
		if len(loadedKeys.PrivateKey) == 0 {
			t.Error("Loaded private key is empty")
		}
		if len(loadedKeys.PublicKey) == 0 {
			t.Error("Loaded public key is empty")
		}

		// Verify certificate
		if loadedCert == nil {
			t.Fatal("Loaded certificate is nil")
		}

		// Test type-specific function
		loadedKeysEd25519, _, _, err := FromP12Ed25519KeyPair(p12Data, password)
		if err != nil {
			t.Fatalf("FromP12Ed25519KeyPair failed: %v", err)
		}

		if loadedKeysEd25519 == nil {
			t.Fatal("Loaded Ed25519 keys are nil")
		}
	})

	t.Run("FromP12KeyPairFile", func(t *testing.T) {
		// Generate RSA key pair and create P12 file
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		rsaKeys := manager.KeyPair()

		certificate := createSelfSignedCertificate(rsaKeys)

		p12File := filepath.Join(tempDir, "test_file.p12")
		err = ToP12KeyPairFile(rsaKeys, certificate, p12File, password)
		if err != nil {
			t.Fatalf("ToP12KeyPairFile failed: %v", err)
		}

		// Load using FromP12KeyPairFile generic function
		loadedKeys, loadedCert, caCerts, err := FromP12KeyPairFile[*algo.RSAKeyPair](p12File, password)
		if err != nil {
			t.Fatalf("FromP12KeyPairFile failed: %v", err)
		}

		// Verify loaded data
		if loadedKeys == nil {
			t.Fatal("Loaded keys are nil")
		}
		if loadedCert == nil {
			t.Fatal("Loaded certificate is nil")
		}
		if len(caCerts) != 0 {
			t.Errorf("Expected 0 CA certificates, got %d", len(caCerts))
		}
	})
}

func TestImportFromP12KeyPairWithValidation(t *testing.T) {
	tempDir := t.TempDir()
	password := "test123"

	// Helper function to create certificate
	createValidationCertificate := func(keyPair keypair.GenericKeyPair) *x509.Certificate {
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Validation Test",
				Organization: []string{"Test Org"},
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SerialNumber: big.NewInt(1),
		}

		var publicKey any
		var privateKey any

		switch kp := keyPair.(type) {
		case *algo.RSAKeyPair:
			publicKey = kp.PublicKey
			privateKey = kp.PrivateKey
		case *algo.ECDSAKeyPair:
			publicKey = kp.PublicKey
			privateKey = kp.PrivateKey
		case *algo.Ed25519KeyPair:
			publicKey = kp.PublicKey
			privateKey = kp.PrivateKey
		}

		certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		certificate, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		return certificate
	}

	t.Run("Valid P12 Import", func(t *testing.T) {
		// Generate RSA key pair
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		rsaKeys := manager.KeyPair()

		// Create certificate
		certificate := createValidationCertificate(rsaKeys)

		// Create P12 file
		p12File := filepath.Join(tempDir, "validation_test.p12")
		err = ToP12KeyPairFile(rsaKeys, certificate, p12File, password)
		if err != nil {
			t.Fatalf("ToP12KeyPairFile failed: %v", err)
		}

		// Import with validation
		loadedKeys, loadedCert, caCerts, err := ImportFromP12KeyPairWithValidation[*algo.RSAKeyPair](p12File, password)
		if err != nil {
			t.Fatalf("ImportFromP12KeyPairWithValidation failed: %v", err)
		}

		// Verify loaded data
		if loadedKeys == nil {
			t.Fatal("Loaded keys are nil")
		}
		if loadedCert == nil {
			t.Fatal("Loaded certificate is nil")
		}
		if loadedCert.Subject.CommonName != "Validation Test" {
			t.Error("Certificate subject mismatch")
		}
		if len(caCerts) != 0 {
			t.Errorf("Expected 0 CA certificates, got %d", len(caCerts))
		}
	})
}

func TestP12KeyPairErrorCases(t *testing.T) {
	password := "test123"

	t.Run("ToP12KeyPair Error Cases", func(t *testing.T) {
		manager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		rsaKeys := manager.KeyPair()

		// Create a test certificate directly
		template := &x509.Certificate{
			Subject:      pkix.Name{CommonName: "Test"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SerialNumber: big.NewInt(1),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, rsaKeys.PublicKey, rsaKeys.PrivateKey)
		certificate, _ := x509.ParseCertificate(certDER)

		// Nil key pair
		_, err := ToP12KeyPair[*algo.RSAKeyPair](nil, certificate, password)
		if err == nil {
			t.Error("Expected error for nil key pair")
		}

		// Nil certificate
		_, err = ToP12KeyPair(rsaKeys, nil, password)
		if err == nil {
			t.Error("Expected error for nil certificate")
		}

		// Empty password
		_, err = ToP12KeyPair(rsaKeys, certificate, "")
		if err == nil {
			t.Error("Expected error for empty password")
		}
	})

	t.Run("FromP12KeyPair Error Cases", func(t *testing.T) {
		// Empty data
		_, _, _, err := FromP12KeyPair[*algo.RSAKeyPair]([]byte{}, password)
		if err == nil {
			t.Error("Expected error for empty P12 data")
		}

		// Empty password
		_, _, _, err = FromP12KeyPair[*algo.RSAKeyPair]([]byte("dummy"), "")
		if err == nil {
			t.Error("Expected error for empty password")
		}

		// Invalid P12 data
		_, _, _, err = FromP12KeyPair[*algo.RSAKeyPair]([]byte("invalid p12 data"), password)
		if err == nil {
			t.Error("Expected error for invalid P12 data")
		}
	})

	t.Run("Type Mismatch Error", func(t *testing.T) {
		// Create RSA P12 data
		manager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		rsaKeys := manager.KeyPair()

		// Create certificate directly
		template := &x509.Certificate{
			Subject:      pkix.Name{CommonName: "Type Test"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SerialNumber: big.NewInt(1),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, rsaKeys.PublicKey, rsaKeys.PrivateKey)
		certificate, _ := x509.ParseCertificate(certDER)
		p12Data, _ := ToP12KeyPair(rsaKeys, certificate, password)

		// Try to load as ECDSA (should fail)
		_, _, _, err := FromP12KeyPair[*algo.ECDSAKeyPair](p12Data, password)
		if err == nil {
			t.Error("Expected error for type mismatch (RSA P12 loaded as ECDSA)")
		}

		// Try to load as Ed25519 (should fail)
		_, _, _, err = FromP12KeyPair[*algo.Ed25519KeyPair](p12Data, password)
		if err == nil {
			t.Error("Expected error for type mismatch (RSA P12 loaded as Ed25519)")
		}
	})

	t.Run("FromP12KeyPairFile Error Cases", func(t *testing.T) {
		// Non-existent file
		_, _, _, err := FromP12KeyPairFile[*algo.RSAKeyPair]("nonexistent.p12", password)
		if err == nil {
			t.Error("Expected error for non-existent file")
		}

		// Empty filename
		_, _, _, err = FromP12KeyPairFile[*algo.RSAKeyPair]("", password)
		if err == nil {
			t.Error("Expected error for empty filename")
		}

		// Empty password
		_, _, _, err = FromP12KeyPairFile[*algo.RSAKeyPair]("dummy.p12", "")
		if err == nil {
			t.Error("Expected error for empty password")
		}
	})
}

func TestExportKeyPairWithChain(t *testing.T) {
	tempDir := t.TempDir()
	password := "test123"

	t.Run("Export with Certificate Chain", func(t *testing.T) {
		// Generate RSA key pair
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		rsaKeys := manager.KeyPair()

		// Create main certificate
		template := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "End Entity Cert",
				Organization: []string{"Test Org"},
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SerialNumber: big.NewInt(1),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, rsaKeys.PublicKey, rsaKeys.PrivateKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}
		certificate, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		// Create a dummy CA certificate for the chain
		caManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		caKeys := caManager.KeyPair()
		caTemplate := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "Test CA",
				Organization: []string{"CA Org"},
			},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SerialNumber: big.NewInt(2),
			IsCA:         true,
		}
		caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKeys.PublicKey, caKeys.PrivateKey)
		if err != nil {
			t.Fatalf("Failed to create CA certificate: %v", err)
		}
		caCertificate, err := x509.ParseCertificate(caCertDER)
		if err != nil {
			t.Fatalf("Failed to parse CA certificate: %v", err)
		}

		// Export with chain
		p12File := filepath.Join(tempDir, "chain_test.p12")
		caCerts := []*x509.Certificate{caCertificate}
		err = ExportKeyPairWithChain(rsaKeys, certificate, caCerts, p12File, password)
		if err != nil {
			t.Fatalf("ExportKeyPairWithChain failed: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(p12File); os.IsNotExist(err) {
			t.Error("P12 file with chain was not created")
		}

		// Load and verify the chain was included
		loadedKeys, loadedCert, loadedCaCerts, err := FromP12KeyPairFile[*algo.RSAKeyPair](p12File, password)
		if err != nil {
			t.Fatalf("Failed to load P12 with chain: %v", err)
		}

		if loadedKeys == nil {
			t.Fatal("Loaded keys are nil")
		}
		if loadedCert == nil {
			t.Fatal("Loaded certificate is nil")
		}
		if len(loadedCaCerts) == 0 {
			t.Error("Expected CA certificates in chain, got none")
		}
	})
}

func TestConvertP12ToPEM(t *testing.T) {
	tempDir := t.TempDir()
	password := "test123"

	t.Run("Convert RSA P12 to PEM", func(t *testing.T) {
		// Generate RSA key pair and create P12
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		rsaKeys := manager.KeyPair()

		// Create certificate directly
		template := &x509.Certificate{
			Subject:      pkix.Name{CommonName: "Convert Test"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SerialNumber: big.NewInt(1),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, rsaKeys.PublicKey, rsaKeys.PrivateKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}
		certificate, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		p12File := filepath.Join(tempDir, "convert_test.p12")
		err = ToP12KeyPairFile(rsaKeys, certificate, p12File, password)
		if err != nil {
			t.Fatalf("ToP12KeyPairFile failed: %v", err)
		}

		// Convert to PEM
		privateKeyFile := filepath.Join(tempDir, "converted_private.pem")
		certFile := filepath.Join(tempDir, "converted_cert.pem")

		err = ConvertP12KeyPairToPEM(p12File, password, privateKeyFile, certFile)
		if err != nil {
			t.Fatalf("ConvertP12KeyPairToPEM failed: %v", err)
		}

		// Verify PEM files were created
		if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
			t.Error("Private key PEM file was not created")
		}
		if _, err := os.Stat(privateKeyFile + ".pub"); os.IsNotExist(err) {
			t.Error("Public key PEM file was not created")
		}
	})
}
