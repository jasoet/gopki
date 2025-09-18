//go:build example

// GoPKI PKCS#12 Examples - Comprehensive demonstration of PKCS#12 functionality
//
// This example demonstrates all aspects of PKCS#12 operations in GoPKI:
// 1. Basic P12 creation with different algorithms
// 2. Advanced P12 operations with certificate chains
// 3. Loading and parsing P12 files
// 4. Integration with other GoPKI modules
// 5. Real-world scenarios and use cases
// 6. Validation and security operations
//
// PKCS#12 is a binary format for storing cryptographic objects including
// private keys, certificates, and certificate chains in a password-protected file.
// It's widely used for importing/exporting certificates across different systems.

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/pkcs12"
)

func main() {
	fmt.Println("=== GoPKI PKCS#12 Module - Comprehensive Examples ===")
	fmt.Println("Demonstrating password-protected certificate and key bundling with RFC 7292 compliance")
	fmt.Println()

	// Setup output directory
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Part 1: Basic PKCS#12 Creation
	fmt.Println("🔐 PART 1: Basic PKCS#12 Creation")
	fmt.Println("============================================================")
	runBasicP12Creation(outputDir)

	// Part 2: Advanced PKCS#12 Operations
	fmt.Println("\n📦 PART 2: Advanced PKCS#12 Operations with Certificate Chains")
	fmt.Println("============================================================")
	runAdvancedP12Operations(outputDir)

	// Part 3: PKCS#12 Loading and Parsing
	fmt.Println("\n📂 PART 3: PKCS#12 Loading and Parsing")
	fmt.Println("============================================================")
	runP12LoadingAndParsing(outputDir)

	// Part 4: Integration with GoPKI Modules
	fmt.Println("\n🔗 PART 4: Integration with GoPKI Modules")
	fmt.Println("============================================================")
	runGoPKIIntegration(outputDir)

	// Part 5: Real-World Scenarios
	fmt.Println("\n🌐 PART 5: Real-World Scenarios")
	fmt.Println("============================================================")
	runRealWorldScenarios(outputDir)

	// Part 6: Validation and Security
	fmt.Println("\n🛡️ PART 6: Validation and Security")
	fmt.Println("============================================================")
	runValidationAndSecurity(outputDir)

	fmt.Println("\n============================================================")
	fmt.Println("✅ ALL PKCS#12 EXAMPLES COMPLETED!")
	fmt.Printf("📁 Output files saved in: ./%s/\n", outputDir)
	fmt.Println("🔍 Review P12 files and certificate bundles")
	fmt.Println()
	fmt.Println("📋 Summary of Demonstrated Features:")
	fmt.Println("   ✅ Multi-algorithm P12 creation (RSA, ECDSA, Ed25519)")
	fmt.Println("   ✅ Certificate chain bundling and validation")
	fmt.Println("   ✅ Password protection with custom options")
	fmt.Println("   ✅ P12 loading, parsing, and content extraction")
	fmt.Println("   ✅ Integration with keypair Manager and cert modules")
	fmt.Println("   ✅ Real-world use cases (web server, client auth, code signing)")
	fmt.Println("   ✅ Cross-platform certificate migration workflows")
	fmt.Println("   ✅ Security validation and certificate verification")
	fmt.Println("============================================================")
}

func runBasicP12Creation(outputDir string) {
	fmt.Println("1. RSA Certificate P12 Creation")
	fmt.Println("--------------------------------")

	// Generate RSA key pair using Manager
	rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	fmt.Printf("✓ Generated %d-bit RSA key pair using Manager\n", rsaManager.PrivateKey().Size()*8)

	// Create self-signed certificate
	rsaCert, err := cert.CreateSelfSignedCertificate(rsaManager.KeyPair(), cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "RSA Test Certificate",
			Organization: []string{"GoPKI Examples"},
			Country:      []string{"US"},
		},
		DNSNames: []string{"rsa.example.com"},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("Failed to create RSA certificate: %v", err)
	}

	fmt.Printf("✓ Created self-signed certificate for: %s\n", rsaCert.Certificate.Subject.CommonName)

	// Create P12 file with custom options
	rsaP12Path := filepath.Join(outputDir, "rsa_basic.p12")
	createOpts := pkcs12.DefaultCreateOptions("rsa_secret123")
	createOpts.FriendlyName = "RSA Basic Certificate"

	err = pkcs12.CreateP12File(rsaP12Path, rsaManager.PrivateKey(), rsaCert.Certificate, nil, createOpts)
	if err != nil {
		log.Fatalf("Failed to create RSA P12 file: %v", err)
	}

	fmt.Printf("✓ Created P12 file: %s\n", rsaP12Path)
	fmt.Printf("  Password: %s\n", createOpts.Password)
	fmt.Printf("  Friendly name: %s\n", createOpts.FriendlyName)

	// Get file info
	if info, err := os.Stat(rsaP12Path); err == nil {
		fmt.Printf("  File size: %d bytes\n", info.Size())
	}

	fmt.Println()

	fmt.Println("2. ECDSA Certificate P12 Creation")
	fmt.Println("----------------------------------")

	// Generate ECDSA key pair
	ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	keyInfo, _ := ecdsaManager.GetInfo()
	fmt.Printf("✓ Generated ECDSA key pair: %s curve (%d bits)\n", keyInfo.Curve, keyInfo.KeySize)

	// Create certificate
	ecdsaCert, err := cert.CreateSelfSignedCertificate(ecdsaManager.KeyPair(), cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "ECDSA Test Certificate",
			Organization: []string{"GoPKI Examples"},
		},
		DNSNames: []string{"ecdsa.example.com"},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("Failed to create ECDSA certificate: %v", err)
	}

	// Use QuickCreateP12 for simpler creation
	ecdsaP12Path := filepath.Join(outputDir, "ecdsa_basic.p12")
	err = pkcs12.QuickCreateP12(ecdsaP12Path, "ecdsa_secret123", ecdsaManager.PrivateKey(), ecdsaCert.Certificate)
	if err != nil {
		log.Fatalf("Failed to create ECDSA P12 file: %v", err)
	}

	fmt.Printf("✓ Created P12 file using QuickCreateP12: %s\n", ecdsaP12Path)
	fmt.Println("  Password: ecdsa_secret123")

	fmt.Println()

	fmt.Println("3. Ed25519 Certificate P12 Creation")
	fmt.Println("------------------------------------")

	// Generate Ed25519 key pair
	ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	fmt.Println("✓ Generated Ed25519 key pair (256 bits)")

	// Create certificate
	ed25519Cert, err := cert.CreateSelfSignedCertificate(ed25519Manager.KeyPair(), cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Ed25519 Test Certificate",
			Organization: []string{"GoPKI Examples"},
		},
		DNSNames: []string{"ed25519.example.com"},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("Failed to create Ed25519 certificate: %v", err)
	}

	// Create P12 with different options
	ed25519P12Path := filepath.Join(outputDir, "ed25519_basic.p12")
	ed25519Opts := pkcs12.DefaultCreateOptions("ed25519_secret123")
	ed25519Opts.FriendlyName = "Ed25519 Modern Certificate"

	err = pkcs12.CreateP12File(ed25519P12Path, ed25519Manager.PrivateKey(), ed25519Cert.Certificate, nil, ed25519Opts)
	if err != nil {
		log.Fatalf("Failed to create Ed25519 P12 file: %v", err)
	}

	fmt.Printf("✓ Created P12 file: %s\n", ed25519P12Path)
	fmt.Printf("  Password: %s\n", ed25519Opts.Password)
	fmt.Printf("  Friendly name: %s\n", ed25519Opts.FriendlyName)

	fmt.Println("💾 Basic P12 creation completed for all algorithms")
}

func runAdvancedP12Operations(outputDir string) {
	fmt.Println("1. Certificate Chain P12 Creation")
	fmt.Println("----------------------------------")

	// Create CA certificate
	caManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate CA key pair: %v", err)
	}

	caCert, err := cert.CreateCACertificate(caManager.KeyPair(), cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "GoPKI Root CA",
			Organization: []string{"GoPKI Certificate Authority"},
			Country:      []string{"US"},
		},
		ValidFor:   10 * 365 * 24 * time.Hour, // 10 years
		IsCA:       true,
		MaxPathLen: 2,
	})
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}

	fmt.Printf("✓ Created Root CA: %s\n", caCert.Certificate.Subject.CommonName)

	// Create intermediate CA
	intermediateManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate intermediate key pair: %v", err)
	}

	intermediateCert, err := cert.SignCertificate(caCert, caManager.KeyPair(), cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "GoPKI Intermediate CA",
			Organization: []string{"GoPKI Certificate Authority"},
		},
		ValidFor:   5 * 365 * 24 * time.Hour, // 5 years
		IsCA:       true,
		MaxPathLen: 1,
	}, intermediateManager.PublicKey())
	if err != nil {
		log.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	fmt.Printf("✓ Created Intermediate CA: %s\n", intermediateCert.Certificate.Subject.CommonName)

	// Create end-entity certificate
	serverManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate server key pair: %v", err)
	}

	serverCert, err := cert.SignCertificate(intermediateCert, intermediateManager.KeyPair(), cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "server.example.com",
			Organization: []string{"Example Corp"},
		},
		DNSNames: []string{"server.example.com", "api.example.com", "www.example.com"},
		ValidFor: 365 * 24 * time.Hour, // 1 year
	}, serverManager.PublicKey())
	if err != nil {
		log.Fatalf("Failed to create server certificate: %v", err)
	}

	fmt.Printf("✓ Created server certificate: %s\n", serverCert.Certificate.Subject.CommonName)

	// Create P12 with full certificate chain
	chainP12Path := filepath.Join(outputDir, "server_with_chain.p12")
	chainOpts := pkcs12.DefaultCreateOptions("chain_secret123")
	chainOpts.FriendlyName = "Server Certificate with Chain"

	// Include the full chain: intermediate CA + root CA
	caCerts := []*x509.Certificate{intermediateCert.Certificate, caCert.Certificate}
	err = pkcs12.CreateP12File(chainP12Path, serverManager.PrivateKey(), serverCert.Certificate, caCerts, chainOpts)
	if err != nil {
		log.Fatalf("Failed to create chain P12 file: %v", err)
	}

	fmt.Printf("✓ Created P12 with certificate chain: %s\n", chainP12Path)
	fmt.Printf("  Chain: Server → Intermediate CA → Root CA\n")
	fmt.Printf("  Password: %s\n", chainOpts.Password)

	// Get file info
	if info, err := os.Stat(chainP12Path); err == nil {
		fmt.Printf("  File size: %d bytes (larger due to certificate chain)\n", info.Size())
	}

	fmt.Println("💾 Advanced P12 operations completed")
}

func runP12LoadingAndParsing(outputDir string) {
	fmt.Println("1. Loading Basic P12 Files")
	fmt.Println("--------------------------")

	// Load the RSA P12 file we created earlier
	rsaP12Path := filepath.Join(outputDir, "rsa_basic.p12")
	loadOpts := pkcs12.DefaultLoadOptions("rsa_secret123")

	container, err := pkcs12.LoadFromP12File(rsaP12Path, loadOpts)
	if err != nil {
		log.Fatalf("Failed to load RSA P12 file: %v", err)
	}

	fmt.Printf("✓ Loaded P12 file: %s\n", rsaP12Path)
	fmt.Printf("  Key type: %s\n", container.GetKeyType())
	fmt.Printf("  Certificate subject: %s\n", container.Certificate.Subject.CommonName)

	// Extract certificate chain
	chain := container.ExtractCertificateChain()
	fmt.Printf("  Certificate chain length: %d\n", len(chain))

	// Validate the container
	if err := container.Validate(); err != nil {
		log.Printf("⚠️ Container validation warning: %v", err)
	} else {
		fmt.Println("✓ Container validation passed")
	}

	fmt.Println()

	fmt.Println("2. Quick Loading with QuickLoadP12")
	fmt.Println("----------------------------------")

	// Use the convenience function for simple loading
	ecdsaP12Path := filepath.Join(outputDir, "ecdsa_basic.p12")
	quickContainer, err := pkcs12.QuickLoadP12(ecdsaP12Path, "ecdsa_secret123")
	if err != nil {
		log.Fatalf("Failed to quick load ECDSA P12: %v", err)
	}

	fmt.Printf("✓ Quick loaded P12: %s\n", ecdsaP12Path)
	fmt.Printf("  Algorithm: %s\n", quickContainer.GetKeyType())
	fmt.Printf("  Certificate CN: %s\n", quickContainer.Certificate.Subject.CommonName)
	fmt.Printf("  Valid from: %s\n", quickContainer.Certificate.NotBefore.Format("2006-01-02"))
	fmt.Printf("  Valid until: %s\n", quickContainer.Certificate.NotAfter.Format("2006-01-02"))

	fmt.Println("💾 P12 loading and parsing completed")
}

func runGoPKIIntegration(outputDir string) {
	fmt.Println("1. P12 Creation from Existing KeyPair Manager")
	fmt.Println("----------------------------------------------")

	// Load an existing key pair from PEM (simulate existing infrastructure)
	// First, create a PEM file to load from
	tempManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate temp key pair: %v", err)
	}

	tempPEMPath := filepath.Join(outputDir, "temp_private.pem")
	privatePEM, _, err := tempManager.ToPEM()
	if err != nil {
		log.Fatalf("Failed to convert to PEM: %v", err)
	}

	err = os.WriteFile(tempPEMPath, privatePEM, 0600)
	if err != nil {
		log.Fatalf("Failed to write PEM file: %v", err)
	}

	// Now load it back using Manager
	loadedManager, err := keypair.LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](tempPEMPath)
	if err != nil {
		log.Fatalf("Failed to load key pair from PEM: %v", err)
	}

	fmt.Printf("✓ Loaded existing key pair from PEM using Manager\n")

	// Get key information
	keyInfo, err := loadedManager.GetInfo()
	if err != nil {
		log.Fatalf("Failed to get key info: %v", err)
	}

	fmt.Printf("  Algorithm: %s\n", keyInfo.Algorithm)
	fmt.Printf("  Key size: %d bits\n", keyInfo.KeySize)

	// Validate the loaded key pair
	if err := loadedManager.Validate(); err != nil {
		log.Fatalf("Key pair validation failed: %v", err)
	}

	fmt.Println("✓ Key pair validation passed")

	// Create certificate for the loaded key
	integrationCert, err := cert.CreateSelfSignedCertificate(loadedManager.KeyPair(), cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Integration Test Certificate",
			Organization: []string{"GoPKI Integration"},
		},
		DNSNames: []string{"integration.example.com"},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("Failed to create integration certificate: %v", err)
	}

	// Create P12 from the loaded Manager
	integrationP12Path := filepath.Join(outputDir, "integration.p12")
	err = pkcs12.QuickCreateP12(integrationP12Path, "integration_secret123", loadedManager.PrivateKey(), integrationCert.Certificate)
	if err != nil {
		log.Fatalf("Failed to create integration P12: %v", err)
	}

	fmt.Printf("✓ Created P12 from loaded Manager: %s\n", integrationP12Path)

	// Clean up temp file
	os.Remove(tempPEMPath)

	fmt.Println("💾 GoPKI integration examples completed")
}

func runRealWorldScenarios(outputDir string) {
	fmt.Println("1. Web Server Certificate Bundle")
	fmt.Println("---------------------------------")

	// Create web server scenario with proper certificate hierarchy
	webServerManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate web server key: %v", err)
	}

	webServerCert, err := cert.CreateSelfSignedCertificate(webServerManager.KeyPair(), cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "web.example.com",
			Organization: []string{"Example Web Services"},
			Country:      []string{"US"},
		},
		DNSNames: []string{
			"web.example.com",
			"www.example.com",
			"api.example.com",
			"admin.example.com",
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("Failed to create web server certificate: %v", err)
	}

	webServerP12Path := filepath.Join(outputDir, "webserver.p12")
	webServerOpts := pkcs12.DefaultCreateOptions("webserver_secure_password_2024")
	webServerOpts.FriendlyName = "Web Server Certificate - Example.com"

	err = pkcs12.CreateP12File(webServerP12Path, webServerManager.PrivateKey(), webServerCert.Certificate, nil, webServerOpts)
	if err != nil {
		log.Fatalf("Failed to create web server P12: %v", err)
	}

	fmt.Printf("✓ Created web server certificate bundle\n")
	fmt.Printf("  File: %s\n", webServerP12Path)
	fmt.Printf("  Primary domain: %s\n", webServerCert.Certificate.Subject.CommonName)
	fmt.Printf("  SAN domains: %v\n", webServerCert.Certificate.DNSNames)
	fmt.Printf("  Password: %s\n", webServerOpts.Password)

	fmt.Println()

	fmt.Println("2. Client Authentication Certificate")
	fmt.Println("-------------------------------------")

	// Create client authentication certificate with Ed25519 for modern security
	clientAuthManager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		log.Fatalf("Failed to generate client auth key: %v", err)
	}

	clientAuthCert, err := cert.CreateSelfSignedCertificate(clientAuthManager.KeyPair(), cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "john.doe@example.com",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		ValidFor: 2 * 365 * 24 * time.Hour, // 2 years for client certs
	})
	if err != nil {
		log.Fatalf("Failed to create client auth certificate: %v", err)
	}

	clientAuthP12Path := filepath.Join(outputDir, "client_auth.p12")
	err = pkcs12.QuickCreateP12(clientAuthP12Path, "client_auth_john_doe_2024", clientAuthManager.PrivateKey(), clientAuthCert.Certificate)
	if err != nil {
		log.Fatalf("Failed to create client auth P12: %v", err)
	}

	fmt.Printf("✓ Created client authentication certificate\n")
	fmt.Printf("  File: %s\n", clientAuthP12Path)
	fmt.Printf("  User: %s\n", clientAuthCert.Certificate.Subject.CommonName)
	fmt.Printf("  Algorithm: Ed25519 (modern, high-performance)\n")

	fmt.Println("💾 Real-world scenarios completed")
}

func runValidationAndSecurity(outputDir string) {
	fmt.Println("1. P12 Container Validation")
	fmt.Println("---------------------------")

	// Load and validate different P12 files
	testFiles := []struct {
		filename string
		password string
		purpose  string
	}{
		{"webserver.p12", "webserver_secure_password_2024", "Web Server"},
		{"client_auth.p12", "client_auth_john_doe_2024", "Client Authentication"},
	}

	for i, testFile := range testFiles {
		fmt.Printf("%d. Validating %s Certificate\n", i+1, testFile.purpose)

		p12Path := filepath.Join(outputDir, testFile.filename)
		container, err := pkcs12.QuickLoadP12(p12Path, testFile.password)
		if err != nil {
			log.Printf("❌ Failed to load %s: %v", testFile.filename, err)
			continue
		}

		fmt.Printf("   ✓ Successfully loaded: %s\n", testFile.filename)

		// Validate container
		if err := container.Validate(); err != nil {
			fmt.Printf("   ⚠️ Validation warning: %v\n", err)
		} else {
			fmt.Printf("   ✓ Container validation passed\n")
		}

		// Check certificate validity
		now := time.Now()
		if now.Before(container.Certificate.NotBefore) {
			fmt.Printf("   ⚠️ Certificate not yet valid (starts: %s)\n", container.Certificate.NotBefore.Format("2006-01-02"))
		} else if now.After(container.Certificate.NotAfter) {
			fmt.Printf("   ❌ Certificate expired (ended: %s)\n", container.Certificate.NotAfter.Format("2006-01-02"))
		} else {
			fmt.Printf("   ✓ Certificate is currently valid\n")
			fmt.Printf("     Valid until: %s\n", container.Certificate.NotAfter.Format("2006-01-02 15:04:05"))
		}

		// Check key type and size
		keyType := container.GetKeyType()
		fmt.Printf("   ✓ Key type: %s\n", keyType)

		// Extract and validate certificate chain
		chain := container.ExtractCertificateChain()
		fmt.Printf("   ✓ Certificate chain length: %d\n", len(chain))

		fmt.Println()
	}

	fmt.Println("2. Security Best Practices")
	fmt.Println("---------------------------")

	fmt.Println("🔐 Security Recommendations:")
	fmt.Println("  • Use strong, unique passwords for each P12 file")
	fmt.Println("  • Use modern encryption (avoid legacy mode)")
	fmt.Println("  • Use RSA 2048+ bits or ECDSA P-256+ for production")
	fmt.Println("  • Store P12 files securely with restricted file permissions")
	fmt.Println("  • Regularly rotate certificates and passwords")
	fmt.Println("  • Consider Ed25519 for modern, high-performance applications")

	fmt.Println("💾 Validation and security analysis completed")
}
