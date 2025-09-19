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

// TestToP12KeyPairFileErrorHandling tests error handling in ToP12KeyPairFile function
func TestToP12KeyPairFileErrorHandling(t *testing.T) {
	tempDir := t.TempDir()
	password := "test123"

	// Generate RSA key pair for testing
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}
	rsaKeys := manager.KeyPair()

	// Create a test certificate
	certificate := createTestCertificate(t, rsaKeys)

	t.Run("NilKeyPairError", func(t *testing.T) {
		filename := filepath.Join(tempDir, "nil_keypair.p12")
		err := ToP12KeyPairFile[*algo.RSAKeyPair](nil, certificate, filename, password)
		if err == nil {
			t.Error("Expected error when key pair is nil")
		}
		if err != nil && !contains(err.Error(), "key pair is required") {
			t.Errorf("Expected 'key pair is required' error, got: %v", err)
		}
	})

	t.Run("NilCertificateError", func(t *testing.T) {
		filename := filepath.Join(tempDir, "nil_cert.p12")
		err := ToP12KeyPairFile(rsaKeys, nil, filename, password)
		if err == nil {
			t.Error("Expected error when certificate is nil")
		}
		if err != nil && !contains(err.Error(), "certificate is required") {
			t.Errorf("Expected 'certificate is required' error, got: %v", err)
		}
	})

	t.Run("EmptyPasswordError", func(t *testing.T) {
		filename := filepath.Join(tempDir, "empty_password.p12")
		err := ToP12KeyPairFile(rsaKeys, certificate, filename, "")
		if err == nil {
			t.Error("Expected error when password is empty")
		}
		if err != nil && !contains(err.Error(), "password is required") {
			t.Errorf("Expected password error, got: %v", err)
		}
	})

	t.Run("MultipleAlgorithmTypes", func(t *testing.T) {
		// Test ECDSA
		ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA keys: %v", err)
		}
		ecdsaKeys := ecdsaManager.KeyPair()
		ecdsaCert := createTestCertificate(t, ecdsaKeys)

		ecdsaFilename := filepath.Join(tempDir, "ecdsa_test.p12")
		err = ToP12KeyPairFile(ecdsaKeys, ecdsaCert, ecdsaFilename, password)
		if err != nil {
			t.Errorf("Failed to create ECDSA P12 file: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(ecdsaFilename); os.IsNotExist(err) {
			t.Error("ECDSA P12 file was not created")
		}

		// Test Ed25519
		ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 keys: %v", err)
		}
		ed25519Keys := ed25519Manager.KeyPair()
		ed25519Cert := createTestCertificate(t, ed25519Keys)

		ed25519Filename := filepath.Join(tempDir, "ed25519_test.p12")
		err = ToP12KeyPairFile(ed25519Keys, ed25519Cert, ed25519Filename, password)
		if err != nil {
			t.Errorf("Failed to create Ed25519 P12 file: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(ed25519Filename); os.IsNotExist(err) {
			t.Error("Ed25519 P12 file was not created")
		}
	})

	t.Run("FilePermissions", func(t *testing.T) {
		filename := filepath.Join(tempDir, "permissions_test.p12")
		err := ToP12KeyPairFile(rsaKeys, certificate, filename, password)
		if err != nil {
			t.Errorf("Failed to create P12 file: %v", err)
			return
		}

		// Check file exists
		fileInfo, err := os.Stat(filename)
		if err != nil {
			t.Errorf("Failed to stat P12 file: %v", err)
			return
		}

		// Verify file has content
		if fileInfo.Size() == 0 {
			t.Error("P12 file should not be empty")
		}
	})

	t.Run("OverwriteExistingFile", func(t *testing.T) {
		filename := filepath.Join(tempDir, "overwrite_test.p12")

		// Create file first time
		err := ToP12KeyPairFile(rsaKeys, certificate, filename, password)
		if err != nil {
			t.Errorf("Failed to create P12 file first time: %v", err)
			return
		}

		// Get file info
		firstInfo, err := os.Stat(filename)
		if err != nil {
			t.Errorf("Failed to stat first P12 file: %v", err)
			return
		}

		// Wait a moment to ensure different timestamp
		time.Sleep(10 * time.Millisecond)

		// Overwrite the file
		err = ToP12KeyPairFile(rsaKeys, certificate, filename, password)
		if err != nil {
			t.Errorf("Failed to overwrite P12 file: %v", err)
			return
		}

		// Verify file was overwritten (check that it still exists)
		secondInfo, err := os.Stat(filename)
		if err != nil {
			t.Errorf("Failed to stat overwritten P12 file: %v", err)
			return
		}

		if secondInfo.Size() == 0 {
			t.Error("Overwritten P12 file should not be empty")
		}

		// Files should have similar sizes (both contain the same key and cert)
		sizeDiff := secondInfo.Size() - firstInfo.Size()
		if sizeDiff < -100 || sizeDiff > 100 {
			t.Errorf("Overwritten file size differs significantly: first=%d, second=%d", firstInfo.Size(), secondInfo.Size())
		}
	})
}

// TestConvertP12KeyPairToPEMErrorHandling tests error handling in ConvertP12KeyPairToPEM
func TestConvertP12KeyPairToPEMErrorHandling(t *testing.T) {
	tempDir := t.TempDir()
	password := "test123"

	t.Run("NonExistentFile", func(t *testing.T) {
		nonExistentFile := filepath.Join(tempDir, "nonexistent.p12")
		privateKeyFile := filepath.Join(tempDir, "private.pem")
		certFile := filepath.Join(tempDir, "cert.pem")

		err := ConvertP12KeyPairToPEM(nonExistentFile, password, privateKeyFile, certFile)
		if err == nil {
			t.Error("Expected error when P12 file does not exist")
		}
		if err != nil && !contains(err.Error(), "failed to read P12 file") {
			t.Errorf("Expected file read error, got: %v", err)
		}
	})

	t.Run("InvalidP12Data", func(t *testing.T) {
		// Create a file with invalid P12 data
		invalidP12File := filepath.Join(tempDir, "invalid.p12")
		err := os.WriteFile(invalidP12File, []byte("this is not valid P12 data"), 0644)
		if err != nil {
			t.Fatalf("Failed to create invalid P12 file: %v", err)
		}

		privateKeyFile := filepath.Join(tempDir, "private_invalid.pem")
		certFile := filepath.Join(tempDir, "cert_invalid.pem")

		err = ConvertP12KeyPairToPEM(invalidP12File, password, privateKeyFile, certFile)
		if err == nil {
			t.Error("Expected error when P12 data is invalid")
		}
		if err != nil && !contains(err.Error(), "failed to load P12 with any key type") {
			t.Errorf("Expected P12 load error, got: %v", err)
		}
	})

	t.Run("WrongPassword", func(t *testing.T) {
		// First create a valid P12 file
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		rsaKeys := manager.KeyPair()
		certificate := createTestCertificate(t, rsaKeys)

		p12File := filepath.Join(tempDir, "correct_password.p12")
		err = ToP12KeyPairFile(rsaKeys, certificate, p12File, password)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Try to convert with wrong password
		privateKeyFile := filepath.Join(tempDir, "private_wrong_pwd.pem")
		certFile := filepath.Join(tempDir, "cert_wrong_pwd.pem")

		err = ConvertP12KeyPairToPEM(p12File, "wrongpassword", privateKeyFile, certFile)
		if err == nil {
			t.Error("Expected error when using wrong password")
		}
	})

	t.Run("EmptyPrivateKeyFile", func(t *testing.T) {
		// Create a valid P12 file
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		rsaKeys := manager.KeyPair()
		certificate := createTestCertificate(t, rsaKeys)

		p12File := filepath.Join(tempDir, "empty_private_key.p12")
		err = ToP12KeyPairFile(rsaKeys, certificate, p12File, password)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Convert with empty private key file (should still work for cert only)
		certFile := filepath.Join(tempDir, "cert_only.pem")
		err = ConvertP12KeyPairToPEM(p12File, password, "", certFile)
		if err != nil {
			t.Errorf("Should be able to convert cert only: %v", err)
		}

		// Verify cert file was created
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			t.Error("Certificate file was not created")
		}
	})

	t.Run("EmptyCertFile", func(t *testing.T) {
		// Create a valid P12 file
		manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		rsaKeys := manager.KeyPair()
		certificate := createTestCertificate(t, rsaKeys)

		p12File := filepath.Join(tempDir, "empty_cert.p12")
		err = ToP12KeyPairFile(rsaKeys, certificate, p12File, password)
		if err != nil {
			t.Fatalf("Failed to create P12 file: %v", err)
		}

		// Convert with empty cert file (should still work for key only)
		privateKeyFile := filepath.Join(tempDir, "private_only.pem")
		err = ConvertP12KeyPairToPEM(p12File, password, privateKeyFile, "")
		if err != nil {
			t.Errorf("Should be able to convert key only: %v", err)
		}

		// Verify private key file was created
		if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
			t.Error("Private key file was not created")
		}
	})
}

// Helper function to create a test certificate for a given key pair
func createTestCertificate(t *testing.T, keyPair keypair.GenericKeyPair) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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
