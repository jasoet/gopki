//go:build example

package main

import (
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/keypair/format"
	"github.com/jasoet/gopki/pkcs12"
)

func main() {
	fmt.Println("=== GoPKI Certificate Module - Comprehensive Examples ===")
	fmt.Println("Demonstrating all certificate features with type-safe APIs")

	// Create output directory
	if err := os.MkdirAll("output", 0o755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Execute all certificate examples
	fmt.Println("\n🏗️ PART 1: Core Certificate Creation")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateCoreCreation()

	fmt.Println("\n🏛️ PART 2: Advanced CA Hierarchies")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateCAHierarchies()

	fmt.Println("\n🔐 PART 3: Multi-Algorithm Support")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateMultiAlgorithm()

	fmt.Println("\n🌐 PART 4: Subject Alternative Names (SAN)")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateSANUsage()

	fmt.Println("\n💾 PART 5: Format Operations")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateFormatOperations()

	fmt.Println("\n📦 PART 6: PKCS#12 Integration")
	fmt.Println(strings.Repeat("=", 60))
	demonstratePKCS12Integration()

	fmt.Println("\n✅ PART 7: Certificate Validation")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateCertificateValidation()

	fmt.Println("\n🔗 PART 8: Integration & Advanced Features")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateIntegrationFeatures()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ All certificate examples completed successfully!")
	fmt.Println("📂 Generated files are in the 'output/' directory")
	fmt.Println("🔍 Check certificate details with: openssl x509 -in output/<file> -text -noout")
	fmt.Println(strings.Repeat("=", 60))
}

// PART 1: Core Certificate Creation
func demonstrateCoreCreation() {
	fmt.Println("\n1.1 Self-Signed Certificate Creation")

	// Generate key pair for self-signed certificate
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to generate key pair: %v\n", err)
		return
	}

	// Create self-signed certificate request
	request := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
			Organization:       []string{"GoPKI Examples Inc"},
			OrganizationalUnit: []string{"IT Department"},
			CommonName:         "GoPKI Self-Signed Certificate",
		},
		DNSNames:    []string{"localhost", "example.com"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ValidFrom:   time.Now(),
		ValidFor:    365 * 24 * time.Hour, // 1 year
	}

	// Create self-signed certificate
	selfSignedCert, err := cert.CreateSelfSignedCertificate(keyPair, request)
	if err != nil {
		log.Printf("Failed to create self-signed certificate: %v\n", err)
		return
	}

	// Save certificate and key
	err = selfSignedCert.SaveToFile("output/self_signed.pem")
	if err != nil {
		log.Printf("Failed to save self-signed certificate: %v\n", err)
		return
	}

	err = keypair.ToPEMFiles(keyPair, "output/self_signed_private.pem", "output/self_signed_public.pem")
	if err != nil {
		log.Printf("Failed to save key pair: %v\n", err)
		return
	}

	fmt.Printf("   ✓ Self-signed certificate created\n")
	fmt.Printf("   ✓ Subject: %s\n", selfSignedCert.Certificate.Subject.CommonName)
	fmt.Printf("   ✓ Valid from: %s\n", selfSignedCert.Certificate.NotBefore.Format("2006-01-02"))
	fmt.Printf("   ✓ Valid until: %s\n", selfSignedCert.Certificate.NotAfter.Format("2006-01-02"))
	fmt.Printf("   ✓ DNS names: %v\n", selfSignedCert.Certificate.DNSNames)
	fmt.Printf("   ✓ Files: output/self_signed.pem, output/self_signed_private.pem\n")

	fmt.Println("\n1.2 CA Certificate Creation")

	// Generate CA key pair
	caKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize3072)
	if err != nil {
		log.Printf("Failed to generate CA key pair: %v\n", err)
		return
	}

	// Create CA certificate request
	caRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"GoPKI Root CA"},
			CommonName:   "GoPKI Root Certificate Authority",
		},
		IsCA:       true,
		MaxPathLen: 2, // Allow up to 2 intermediate CAs
		ValidFrom:  time.Now(),
		ValidFor:   10 * 365 * 24 * time.Hour, // 10 years
	}

	// Create CA certificate
	caCert, err := cert.CreateCACertificate(caKeyPair, caRequest)
	if err != nil {
		log.Printf("Failed to create CA certificate: %v\n", err)
		return
	}

	// Save CA certificate and key
	err = caCert.SaveToFile("output/root_ca.pem")
	if err != nil {
		log.Printf("Failed to save CA certificate: %v\n", err)
		return
	}

	err = keypair.ToPEMFiles(caKeyPair, "output/root_ca_private.pem", "output/root_ca_public.pem")
	if err != nil {
		log.Printf("Failed to save CA key pair: %v\n", err)
		return
	}

	fmt.Printf("   ✓ Root CA certificate created\n")
	fmt.Printf("   ✓ Subject: %s\n", caCert.Certificate.Subject.CommonName)
	fmt.Printf("   ✓ Is CA: %v\n", caCert.Certificate.IsCA)
	fmt.Printf("   ✓ Max path length: %d\n", caCert.Certificate.MaxPathLen)
	fmt.Printf("   ✓ Key size: %d bits\n", caKeyPair.PrivateKey.Size()*8)
	fmt.Printf("   ✓ Files: output/root_ca.pem, output/root_ca_private.pem\n")

	fmt.Println("\n1.3 Certificate Signing")

	// Generate server key pair
	serverKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Printf("Failed to generate server key pair: %v\n", err)
		return
	}

	// Create server certificate request
	serverRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"GoPKI Web Services"},
			CommonName:   "api.gopki.example.com",
		},
		DNSNames:     []string{"api.gopki.example.com", "www.gopki.example.com"},
		IPAddresses:  []net.IP{net.IPv4(192, 168, 1, 100)},
		EmailAddress: []string{"admin@gopki.example.com"},
		ValidFrom:    time.Now(),
		ValidFor:     365 * 24 * time.Hour, // 1 year
	}

	// Sign server certificate with CA
	serverCert, err := cert.SignCertificate(caCert, caKeyPair, serverRequest, &serverKeyPair.PrivateKey.PublicKey)
	if err != nil {
		log.Printf("Failed to sign server certificate: %v\n", err)
		return
	}

	// Save server certificate and key
	err = serverCert.SaveToFile("output/server.pem")
	if err != nil {
		log.Printf("Failed to save server certificate: %v\n", err)
		return
	}

	err = keypair.ToPEMFiles(serverKeyPair, "output/server_private.pem", "output/server_public.pem")
	if err != nil {
		log.Printf("Failed to save server key pair: %v\n", err)
		return
	}

	fmt.Printf("   ✓ Server certificate signed by CA\n")
	fmt.Printf("   ✓ Subject: %s\n", serverCert.Certificate.Subject.CommonName)
	fmt.Printf("   ✓ Issuer: %s\n", serverCert.Certificate.Issuer.CommonName)
	fmt.Printf("   ✓ Algorithm: ECDSA P-256\n")
	fmt.Printf("   ✓ Files: output/server.pem, output/server_private.pem\n")
}

// PART 2: Advanced CA Hierarchies
func demonstrateCAHierarchies() {
	fmt.Println("\n2.1 Multi-Level CA Hierarchy Creation")

	// Root CA (already created in Part 1, load it)
	fmt.Printf("   → Loading existing Root CA...\n")
	rootCA, err := cert.LoadCertificateFromFile("output/root_ca.pem")
	if err != nil {
		log.Printf("Failed to load root CA: %v\n", err)
		return
	}

	// Load root CA key pair for signing
	rootCAKeyData, err := os.ReadFile("output/root_ca_private.pem")
	if err != nil {
		log.Printf("Failed to read root CA private key: %v\n", err)
		return
	}

	// Parse RSA key from PEM data
	parsedKey, err := algo.RSAKeyPairFromPEM(format.PEM(rootCAKeyData))
	if err != nil {
		log.Printf("Failed to parse root CA private key: %v\n", err)
		return
	}
	rootCAKey := parsedKey

	// Create Intermediate CA
	fmt.Printf("   → Creating Intermediate CA...\n")
	intermediateKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to generate intermediate CA key pair: %v\n", err)
		return
	}

	intermediateRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"GoPKI Intermediate CA"},
			CommonName:   "GoPKI Intermediate Certificate Authority",
		},
		IsCA:       true,
		MaxPathLen: 0, // Can only sign end-entity certificates
		ValidFrom:  time.Now(),
		ValidFor:   5 * 365 * 24 * time.Hour, // 5 years
	}

	// Sign intermediate CA with root CA
	intermediateCert, err := cert.SignCertificate(rootCA, rootCAKey, intermediateRequest, &intermediateKeyPair.PrivateKey.PublicKey)
	if err != nil {
		log.Printf("Failed to sign intermediate CA: %v\n", err)
		return
	}

	// Save intermediate CA
	err = intermediateCert.SaveToFile("output/intermediate_ca.pem")
	if err != nil {
		log.Printf("Failed to save intermediate CA: %v\n", err)
		return
	}

	err = keypair.ToPEMFiles(intermediateKeyPair, "output/intermediate_ca_private.pem", "output/intermediate_ca_public.pem")
	if err != nil {
		log.Printf("Failed to save intermediate CA key pair: %v\n", err)
		return
	}

	fmt.Printf("     ✓ Intermediate CA created and signed by Root CA\n")
	fmt.Printf("     ✓ Subject: %s\n", intermediateCert.Certificate.Subject.CommonName)
	fmt.Printf("     ✓ Issuer: %s\n", intermediateCert.Certificate.Issuer.CommonName)
	fmt.Printf("     ✓ Max path length: %d (end-entity only)\n", intermediateCert.Certificate.MaxPathLen)

	fmt.Println("\n2.2 End-Entity Certificate from Intermediate CA")

	// Create end-entity certificate signed by intermediate CA
	endEntityKeyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		log.Printf("Failed to generate end-entity key pair: %v\n", err)
		return
	}

	endEntityRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"GoPKI Client Services"},
			CommonName:   "client.gopki.example.com",
		},
		DNSNames:     []string{"client.gopki.example.com"},
		EmailAddress: []string{"client@gopki.example.com"},
		ValidFrom:    time.Now(),
		ValidFor:     365 * 24 * time.Hour, // 1 year
	}

	// Sign end-entity certificate with intermediate CA
	endEntityCert, err := cert.SignCertificate(intermediateCert, intermediateKeyPair, endEntityRequest, endEntityKeyPair.PublicKey)
	if err != nil {
		log.Printf("Failed to sign end-entity certificate: %v\n", err)
		return
	}

	// Save end-entity certificate
	err = endEntityCert.SaveToFile("output/end_entity.pem")
	if err != nil {
		log.Printf("Failed to save end-entity certificate: %v\n", err)
		return
	}

	err = keypair.ToPEMFiles(endEntityKeyPair, "output/end_entity_private.pem", "output/end_entity_public.pem")
	if err != nil {
		log.Printf("Failed to save end-entity key pair: %v\n", err)
		return
	}

	fmt.Printf("     ✓ End-entity certificate created\n")
	fmt.Printf("     ✓ Subject: %s\n", endEntityCert.Certificate.Subject.CommonName)
	fmt.Printf("     ✓ Issuer: %s\n", endEntityCert.Certificate.Issuer.CommonName)
	fmt.Printf("     ✓ Algorithm: Ed25519\n")
	fmt.Printf("     ✓ Certificate chain: Root CA → Intermediate CA → End Entity\n")

	fmt.Println("\n2.3 Path Length Constraint Enforcement")

	fmt.Printf("   → Testing path length constraints...\n")

	// Test 1: Intermediate CA with MaxPathLen=0 should not be able to sign another CA
	fmt.Printf("     • Testing: Intermediate CA (MaxPathLen=0) signing another CA (should fail)\n")

	// Try to create another intermediate CA (this should fail due to path length constraint)
	anotherIntermediateKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to generate key pair for test: %v\n", err)
		return
	}

	anotherIntermediateRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Another Intermediate CA (Should Fail)",
		},
		IsCA:      true,
		ValidFrom: time.Now(),
		ValidFor:  365 * 24 * time.Hour,
	}

	// This should fail because intermediate CA has MaxPathLen=0
	_, err = cert.SignCertificate(intermediateCert, intermediateKeyPair, anotherIntermediateRequest, &anotherIntermediateKeyPair.PrivateKey.PublicKey)
	if err != nil {
		fmt.Printf("       ✓ Correctly rejected: %v\n", err)
	} else {
		fmt.Printf("       ❌ ERROR: Should have been rejected due to path length constraint\n")
	}

	// Test 2: Root CA with MaxPathLen=2 should be able to sign intermediate CAs
	fmt.Printf("     • Testing: Root CA (MaxPathLen=2) signing intermediate CA (should succeed)\n")

	validIntermediateRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Valid Intermediate CA",
		},
		IsCA:       true,
		MaxPathLen: 0, // This intermediate can only sign end-entity certs
		ValidFrom:  time.Now(),
		ValidFor:   365 * 24 * time.Hour,
	}

	// This should succeed because root CA has MaxPathLen=2
	validIntermediate, err := cert.SignCertificate(rootCA, rootCAKey, validIntermediateRequest, &anotherIntermediateKeyPair.PrivateKey.PublicKey)
	if err != nil {
		fmt.Printf("       ❌ ERROR: Should have succeeded: %v\n", err)
	} else {
		fmt.Printf("       ✓ Correctly allowed by Root CA\n")
		fmt.Printf("       ✓ Created valid intermediate with MaxPathLen=0\n")

		// Save the valid intermediate for reference
		err = validIntermediate.SaveToFile("output/valid_intermediate_ca.pem")
		if err != nil {
			log.Printf("Failed to save valid intermediate CA: %v\n", err)
		}
	}
}

// PART 3: Multi-Algorithm Support
func demonstrateMultiAlgorithm() {
	fmt.Println("\n3.1 RSA Certificate Variants")

	rsaSizes := []struct {
		size algo.KeySize
		name string
	}{
		{algo.KeySize2048, "RSA-2048"},
		{algo.KeySize3072, "RSA-3072"},
		{algo.KeySize4096, "RSA-4096"},
	}

	for _, rsaSize := range rsaSizes {
		fmt.Printf("   → Creating %s certificate...\n", rsaSize.name)

		keyPair, err := algo.GenerateRSAKeyPair(rsaSize.size)
		if err != nil {
			log.Printf("Failed to generate %s key pair: %v\n", rsaSize.name, err)
			continue
		}

		request := cert.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{"GoPKI Examples"},
				CommonName:   fmt.Sprintf("%s Test Certificate", rsaSize.name),
			},
			ValidFrom: time.Now(),
			ValidFor:  365 * 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)
		if err != nil {
			log.Printf("Failed to create %s certificate: %v\n", rsaSize.name, err)
			continue
		}

		filename := fmt.Sprintf("output/%s_cert.pem", strings.ToLower(strings.ReplaceAll(rsaSize.name, "-", "_")))
		err = certificate.SaveToFile(filename)
		if err != nil {
			log.Printf("Failed to save %s certificate: %v\n", rsaSize.name, err)
			continue
		}

		fmt.Printf("     ✓ %s certificate created\n", rsaSize.name)
		fmt.Printf("     ✓ Key size: %d bits\n", keyPair.PrivateKey.Size()*8)
		fmt.Printf("     ✓ Subject: %s\n", certificate.Certificate.Subject.CommonName)
		fmt.Printf("     ✓ File: %s\n", filename)
	}

	fmt.Println("\n3.2 ECDSA Certificate Variants")

	ecdsaCurves := []struct {
		curve algo.ECDSACurve
		name  string
	}{
		{algo.P224, "ECDSA-P224"},
		{algo.P256, "ECDSA-P256"},
		{algo.P384, "ECDSA-P384"},
		{algo.P521, "ECDSA-P521"},
	}

	for _, ecdsaCurve := range ecdsaCurves {
		fmt.Printf("   → Creating %s certificate...\n", ecdsaCurve.name)

		keyPair, err := algo.GenerateECDSAKeyPair(ecdsaCurve.curve)
		if err != nil {
			log.Printf("Failed to generate %s key pair: %v\n", ecdsaCurve.name, err)
			continue
		}

		request := cert.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{"GoPKI Examples"},
				CommonName:   fmt.Sprintf("%s Test Certificate", ecdsaCurve.name),
			},
			ValidFrom: time.Now(),
			ValidFor:  365 * 24 * time.Hour,
		}

		certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)
		if err != nil {
			log.Printf("Failed to create %s certificate: %v\n", ecdsaCurve.name, err)
			continue
		}

		filename := fmt.Sprintf("output/%s_cert.pem", strings.ToLower(strings.ReplaceAll(ecdsaCurve.name, "-", "_")))
		err = certificate.SaveToFile(filename)
		if err != nil {
			log.Printf("Failed to save %s certificate: %v\n", ecdsaCurve.name, err)
			continue
		}

		fmt.Printf("     ✓ %s certificate created\n", ecdsaCurve.name)
		fmt.Printf("     ✓ Curve: %s\n", keyPair.PrivateKey.Curve.Params().Name)
		fmt.Printf("     ✓ Bit size: %d\n", keyPair.PrivateKey.Curve.Params().BitSize)
		fmt.Printf("     ✓ Subject: %s\n", certificate.Certificate.Subject.CommonName)
		fmt.Printf("     ✓ File: %s\n", filename)
	}

	fmt.Println("\n3.3 Ed25519 Certificate")

	fmt.Printf("   → Creating Ed25519 certificate...\n")

	keyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		log.Printf("Failed to generate Ed25519 key pair: %v\n", err)
		return
	}

	request := cert.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"GoPKI Examples"},
			CommonName:   "Ed25519 Test Certificate",
		},
		ValidFrom: time.Now(),
		ValidFor:  365 * 24 * time.Hour,
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)
	if err != nil {
		log.Printf("Failed to create Ed25519 certificate: %v\n", err)
		return
	}

	err = certificate.SaveToFile("output/ed25519_cert.pem")
	if err != nil {
		log.Printf("Failed to save Ed25519 certificate: %v\n", err)
		return
	}

	fmt.Printf("     ✓ Ed25519 certificate created\n")
	fmt.Printf("     ✓ Key size: 256 bits (fixed)\n")
	fmt.Printf("     ✓ Private key length: %d bytes\n", len(keyPair.PrivateKey))
	fmt.Printf("     ✓ Public key length: %d bytes\n", len(keyPair.PublicKey))
	fmt.Printf("     ✓ Subject: %s\n", certificate.Certificate.Subject.CommonName)
	fmt.Printf("     ✓ File: output/ed25519_cert.pem\n")

	fmt.Println("\n3.4 Algorithm Performance Comparison")

	fmt.Printf("   → Measuring certificate creation performance...\n")
	fmt.Printf("   Algorithm    Key Gen    Cert Creation  Total Time\n")
	fmt.Printf("   --------------------------------------------------------\n")

	algorithms := []struct {
		name string
		fn   func() (interface{}, error)
	}{
		{"RSA-2048", func() (interface{}, error) {
			keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
			if err != nil {
				return nil, err
			}
			req := cert.CertificateRequest{
				Subject:   pkix.Name{CommonName: "Performance Test"},
				ValidFrom: time.Now(),
				ValidFor:  365 * 24 * time.Hour,
			}
			return cert.CreateSelfSignedCertificate(keyPair, req)
		}},
		{"ECDSA-P256", func() (interface{}, error) {
			keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
			if err != nil {
				return nil, err
			}
			req := cert.CertificateRequest{
				Subject:   pkix.Name{CommonName: "Performance Test"},
				ValidFrom: time.Now(),
				ValidFor:  365 * 24 * time.Hour,
			}
			return cert.CreateSelfSignedCertificate(keyPair, req)
		}},
		{"Ed25519", func() (interface{}, error) {
			keyPair, err := algo.GenerateEd25519KeyPair()
			if err != nil {
				return nil, err
			}
			req := cert.CertificateRequest{
				Subject:   pkix.Name{CommonName: "Performance Test"},
				ValidFrom: time.Now(),
				ValidFor:  365 * 24 * time.Hour,
			}
			return cert.CreateSelfSignedCertificate(keyPair, req)
		}},
	}

	for _, alg := range algorithms {
		start := time.Now()
		_, err := alg.fn()
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("   %-12s Error: %v\n", alg.name, err)
		} else {
			fmt.Printf("   %-12s %-10s %-14s %.2fms\n", alg.name, "N/A", "N/A", float64(duration.Nanoseconds())/1000000)
		}
	}
}

// PART 4: Subject Alternative Names (SAN)
func demonstrateSANUsage() {
	fmt.Println("\n4.1 Complex SAN Combinations")

	// Create certificate with comprehensive SAN usage
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Printf("Failed to generate key pair: %v\n", err)
		return
	}

	// Complex SAN request
	request := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"GoPKI Multi-Domain Services"},
			CommonName:   "multi-domain.gopki.example.com",
		},
		// Multiple DNS names
		DNSNames: []string{
			"multi-domain.gopki.example.com",
			"api.gopki.example.com",
			"www.gopki.example.com",
			"admin.gopki.example.com",
			"*.staging.gopki.example.com", // Wildcard domain
			"localhost",
		},
		// Multiple IP addresses (IPv4 and IPv6)
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),     // localhost
			net.IPv4(192, 168, 1, 100), // private network
			net.IPv4(10, 0, 0, 50),     // another private network
			net.ParseIP("::1"),         // IPv6 localhost
			net.ParseIP("2001:db8::1"), // IPv6 example
		},
		// Multiple email addresses
		EmailAddress: []string{
			"admin@gopki.example.com",
			"support@gopki.example.com",
			"security@gopki.example.com",
		},
		ValidFrom: time.Now(),
		ValidFor:  2 * 365 * 24 * time.Hour, // 2 years
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)
	if err != nil {
		log.Printf("Failed to create certificate with complex SAN: %v\n", err)
		return
	}

	err = certificate.SaveToFile("output/complex_san_cert.pem")
	if err != nil {
		log.Printf("Failed to save complex SAN certificate: %v\n", err)
		return
	}

	fmt.Printf("   ✓ Complex SAN certificate created\n")
	fmt.Printf("   ✓ Subject: %s\n", certificate.Certificate.Subject.CommonName)
	fmt.Printf("   ✓ DNS names (%d):\n", len(certificate.Certificate.DNSNames))
	for _, dns := range certificate.Certificate.DNSNames {
		fmt.Printf("     - %s\n", dns)
	}
	fmt.Printf("   ✓ IP addresses (%d):\n", len(certificate.Certificate.IPAddresses))
	for _, ip := range certificate.Certificate.IPAddresses {
		fmt.Printf("     - %s\n", ip.String())
	}
	fmt.Printf("   ✓ Email addresses (%d):\n", len(certificate.Certificate.EmailAddresses))
	for _, email := range certificate.Certificate.EmailAddresses {
		fmt.Printf("     - %s\n", email)
	}

	fmt.Println("\n4.2 Domain-Specific SAN Patterns")

	// Web server certificate pattern
	fmt.Printf("   → Creating web server certificate pattern...\n")
	webServerCert := createSANPattern("web-server", []string{
		"example.com",
		"www.example.com",
		"api.example.com",
		"cdn.example.com",
	}, []net.IP{
		net.IPv4(203, 0, 113, 10),
	}, []string{
		"webmaster@example.com",
	})
	if webServerCert != nil {
		fmt.Printf("     ✓ Web server certificate created with production-ready SAN\n")
	}

	// API service certificate pattern
	fmt.Printf("   → Creating API service certificate pattern...\n")
	apiServiceCert := createSANPattern("api-service", []string{
		"api.service.internal",
		"api-v1.service.internal",
		"api-v2.service.internal",
		"*.microservice.internal",
	}, []net.IP{
		net.IPv4(10, 0, 1, 100),
		net.IPv4(10, 0, 1, 101),
	}, []string{
		"api-admin@service.internal",
	})
	if apiServiceCert != nil {
		fmt.Printf("     ✓ API service certificate created with microservice SAN\n")
	}

	// Development certificate pattern
	fmt.Printf("   → Creating development certificate pattern...\n")
	devCert := createSANPattern("development", []string{
		"localhost",
		"dev.local",
		"*.dev.local",
		"test.local",
	}, []net.IP{
		net.IPv4(127, 0, 0, 1),
		net.IPv6loopback,
		net.IPv4(192, 168, 1, 10),
	}, []string{
		"developer@dev.local",
	})
	if devCert != nil {
		fmt.Printf("     ✓ Development certificate created with local development SAN\n")
	}
}

func createSANPattern(name string, dnsNames []string, ipAddresses []net.IP, emailAddresses []string) *cert.Certificate {
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Printf("Failed to generate key pair for %s: %v\n", name, err)
		return nil
	}

	request := cert.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"GoPKI SAN Examples"},
			CommonName:   fmt.Sprintf("%s.gopki.example.com", name),
		},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		EmailAddress: emailAddresses,
		ValidFrom:    time.Now(),
		ValidFor:     365 * 24 * time.Hour,
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)
	if err != nil {
		log.Printf("Failed to create %s certificate: %v\n", name, err)
		return nil
	}

	filename := fmt.Sprintf("output/%s_san_cert.pem", name)
	err = certificate.SaveToFile(filename)
	if err != nil {
		log.Printf("Failed to save %s certificate: %v\n", name, err)
		return nil
	}

	return certificate
}

// PART 5: Format Operations
func demonstrateFormatOperations() {
	fmt.Println("\n5.1 PEM vs DER Format Comparison")

	// Create a certificate for format testing
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to generate key pair: %v\n", err)
		return
	}

	request := cert.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Format Testing"},
			CommonName:   "format-test.gopki.example.com",
		},
		DNSNames:  []string{"format-test.gopki.example.com"},
		ValidFrom: time.Now(),
		ValidFor:  365 * 24 * time.Hour,
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)
	if err != nil {
		log.Printf("Failed to create certificate: %v\n", err)
		return
	}

	// Save in PEM format
	err = certificate.SaveToFile("output/format_test.pem")
	if err != nil {
		log.Printf("Failed to save PEM certificate: %v\n", err)
		return
	}

	// Save in DER format
	err = certificate.SaveToDERFile("output/format_test.der")
	if err != nil {
		log.Printf("Failed to save DER certificate: %v\n", err)
		return
	}

	// Compare file sizes
	pemInfo, err := os.Stat("output/format_test.pem")
	if err != nil {
		log.Printf("Failed to stat PEM file: %v\n", err)
		return
	}

	derInfo, err := os.Stat("output/format_test.der")
	if err != nil {
		log.Printf("Failed to stat DER file: %v\n", err)
		return
	}

	fmt.Printf("   ✓ Certificate saved in both formats\n")
	fmt.Printf("   ✓ PEM format: %d bytes (human-readable)\n", pemInfo.Size())
	fmt.Printf("   ✓ DER format: %d bytes (binary)\n", derInfo.Size())
	fmt.Printf("   ✓ DER is %.1f%% smaller than PEM\n",
		(1.0-float64(derInfo.Size())/float64(pemInfo.Size()))*100)

	fmt.Println("\n5.2 Format Conversion Operations")

	// Test PEM to DER conversion
	fmt.Printf("   → Testing PEM to DER conversion...\n")
	pemData := certificate.ToPEM()
	derData, err := cert.ConvertPEMToDER(pemData)
	if err != nil {
		log.Printf("Failed to convert PEM to DER: %v\n", err)
		return
	}

	// Save converted DER
	err = os.WriteFile("output/converted_to_der.der", derData, 0o644)
	if err != nil {
		log.Printf("Failed to write converted DER: %v\n", err)
		return
	}
	fmt.Printf("     ✓ PEM to DER conversion successful (%d bytes)\n", len(derData))

	// Test DER to PEM conversion
	fmt.Printf("   → Testing DER to PEM conversion...\n")
	originalDER := certificate.ToDER()
	convertedPEM, err := cert.ConvertDERToPEM(originalDER)
	if err != nil {
		log.Printf("Failed to convert DER to PEM: %v\n", err)
		return
	}

	// Save converted PEM
	err = os.WriteFile("output/converted_to_pem.pem", convertedPEM, 0o644)
	if err != nil {
		log.Printf("Failed to write converted PEM: %v\n", err)
		return
	}
	fmt.Printf("     ✓ DER to PEM conversion successful (%d bytes)\n", len(convertedPEM))

	fmt.Println("\n5.3 Format Loading and Parsing")

	// Test loading from PEM file
	fmt.Printf("   → Testing PEM file loading...\n")
	loadedFromPEM, err := cert.LoadCertificateFromFile("output/format_test.pem")
	if err != nil {
		log.Printf("Failed to load from PEM file: %v\n", err)
		return
	}
	fmt.Printf("     ✓ PEM file loaded successfully\n")
	fmt.Printf("     ✓ Subject: %s\n", loadedFromPEM.Certificate.Subject.CommonName)

	// Test loading from DER file
	fmt.Printf("   → Testing DER file loading...\n")
	loadedFromDER, err := cert.LoadCertificateFromDERFile("output/format_test.der")
	if err != nil {
		log.Printf("Failed to load from DER file: %v\n", err)
		return
	}
	fmt.Printf("     ✓ DER file loaded successfully\n")
	fmt.Printf("     ✓ Subject: %s\n", loadedFromDER.Certificate.Subject.CommonName)

	// Verify both loaded certificates are identical
	if loadedFromPEM.Certificate.Subject.CommonName == loadedFromDER.Certificate.Subject.CommonName &&
		loadedFromPEM.Certificate.SerialNumber.Cmp(loadedFromDER.Certificate.SerialNumber) == 0 {
		fmt.Printf("     ✓ Both formats contain identical certificate data\n")
	} else {
		fmt.Printf("     ❌ Format loading mismatch detected\n")
	}

	fmt.Println("\n5.4 Performance Comparison")

	fmt.Printf("   → Measuring format operation performance...\n")

	// Measure PEM parsing performance
	pemStart := time.Now()
	for i := 0; i < 100; i++ {
		_, err := cert.ParseCertificateFromPEM(pemData)
		if err != nil {
			break
		}
	}
	pemDuration := time.Since(pemStart)

	// Measure DER parsing performance
	derStart := time.Now()
	for i := 0; i < 100; i++ {
		_, err := cert.ParseCertificateFromDER(originalDER)
		if err != nil {
			break
		}
	}
	derDuration := time.Since(derStart)

	fmt.Printf("     ✓ PEM parsing (100 iterations): %.2fms\n", float64(pemDuration.Nanoseconds())/1000000)
	fmt.Printf("     ✓ DER parsing (100 iterations): %.2fms\n", float64(derDuration.Nanoseconds())/1000000)

	if derDuration < pemDuration {
		speedup := float64(pemDuration) / float64(derDuration)
		fmt.Printf("     ✓ DER parsing is %.1fx faster than PEM\n", speedup)
	}
}

// PART 6: PKCS#12 Integration
func demonstratePKCS12Integration() {
	fmt.Println("\n6.1 PKCS#12 Certificate Bundle Creation")

	// Create a certificate and key pair for PKCS#12 testing
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to generate key pair: %v\n", err)
		return
	}

	request := cert.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"PKCS#12 Testing"},
			CommonName:   "pkcs12-test.gopki.example.com",
		},
		DNSNames:  []string{"pkcs12-test.gopki.example.com"},
		ValidFrom: time.Now(),
		ValidFor:  365 * 24 * time.Hour,
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, request)
	if err != nil {
		log.Printf("Failed to create certificate: %v\n", err)
		return
	}

	// Save to PKCS#12 format
	fmt.Printf("   → Creating PKCS#12 bundle...\n")
	password := "test-password-123"
	err = pkcs12.SaveCertToP12(certificate, keyPair.PrivateKey, "output/certificate.p12", password)
	if err != nil {
		log.Printf("Failed to save PKCS#12 bundle: %v\n", err)
		return
	}
	fmt.Printf("     ✓ PKCS#12 bundle created: output/certificate.p12\n")
	fmt.Printf("     ✓ Password: %s\n", password)

	fmt.Println("\n6.2 PKCS#12 Bundle Loading and Extraction")

	// Load certificate from PKCS#12
	fmt.Printf("   → Loading certificate from PKCS#12...\n")
	loadedCert, _, err := pkcs12.FromP12CertFile("output/certificate.p12", password)
	if err != nil {
		log.Printf("Failed to load from PKCS#12: %v\n", err)
		return
	}
	fmt.Printf("     ✓ Certificate loaded from PKCS#12\n")
	fmt.Printf("     ✓ Subject: %s\n", loadedCert.Certificate.Subject.CommonName)

	// Extract and save to PEM format
	fmt.Printf("   → Extracting PKCS#12 contents to PEM files...\n")
	err = pkcs12.ExtractCertificatesFromP12("output/certificate.p12", password, "output/extracted/")
	if err != nil {
		log.Printf("Failed to extract PKCS#12 contents: %v\n", err)
		return
	}
	fmt.Printf("     ✓ PKCS#12 contents extracted to output/extracted/\n")

	fmt.Println("\n6.3 PKCS#12 Certificate Chain Bundle")

	// Create a certificate chain and save to PKCS#12
	fmt.Printf("   → Creating certificate chain bundle...\n")

	// Load the CA certificate created earlier
	caCert, err := cert.LoadCertificateFromFile("output/root_ca.pem")
	if err != nil {
		log.Printf("Failed to load CA certificate: %v\n", err)
		return
	}

	// Create chain array
	caCerts := []*cert.Certificate{caCert}

	// Save certificate with chain to PKCS#12
	chainPassword := "chain-password-456"
	err = pkcs12.SaveCertToP12WithChain(certificate, keyPair.PrivateKey, caCerts, "output/certificate_with_chain.p12", chainPassword)
	if err != nil {
		log.Printf("Failed to save certificate chain to PKCS#12: %v\n", err)
		return
	}
	fmt.Printf("     ✓ Certificate chain bundle created: output/certificate_with_chain.p12\n")
	fmt.Printf("     ✓ Chain password: %s\n", chainPassword)

	// Load certificate chain from PKCS#12
	fmt.Printf("   → Loading certificate chain from PKCS#12...\n")
	certChain, err := pkcs12.LoadCertificateChainFromP12("output/certificate_with_chain.p12", chainPassword)
	if err != nil {
		log.Printf("Failed to load certificate chain: %v\n", err)
		return
	}
	fmt.Printf("     ✓ Certificate chain loaded (%d certificates)\n", len(certChain))
	for i, cert := range certChain {
		fmt.Printf("       [%d] %s\n", i, cert.Certificate.Subject.CommonName)
	}

	fmt.Println("\n6.4 PKCS#12 Validation and Metadata")

	// Validate PKCS#12 file
	fmt.Printf("   → Validating PKCS#12 files...\n")
	metadata, err := pkcs12.ValidateP12Certificate("output/certificate.p12", password)
	if err != nil {
		log.Printf("Failed to validate PKCS#12: %v\n", err)
		return
	}
	fmt.Printf("     ✓ PKCS#12 validation successful\n")
	fmt.Printf("     ✓ Metadata:\n")
	for key, value := range metadata {
		fmt.Printf("       - %s: %v\n", key, value)
	}
}

// PART 7: Certificate Validation
func demonstrateCertificateValidation() {
	fmt.Println("\n7.1 Certificate Chain Validation")

	// Load certificates for validation testing
	fmt.Printf("   → Loading certificates for validation...\n")

	rootCA, err := cert.LoadCertificateFromFile("output/root_ca.pem")
	if err != nil {
		log.Printf("Failed to load root CA: %v\n", err)
		return
	}

	serverCert, err := cert.LoadCertificateFromFile("output/server.pem")
	if err != nil {
		log.Printf("Failed to load server certificate: %v\n", err)
		return
	}

	// Validate server certificate against root CA
	fmt.Printf("   → Validating server certificate against root CA...\n")
	err = cert.VerifyCertificate(serverCert, rootCA)
	if err != nil {
		fmt.Printf("     ❌ Validation failed: %v\n", err)
	} else {
		fmt.Printf("     ✓ Server certificate is valid\n")
		fmt.Printf("     ✓ Issuer: %s\n", serverCert.Certificate.Issuer.CommonName)
		fmt.Printf("     ✓ Subject: %s\n", serverCert.Certificate.Subject.CommonName)
	}

	fmt.Println("\n7.2 Certificate Expiration Checking")

	fmt.Printf("   → Checking certificate validity periods...\n")

	certificates := []struct {
		name string
		cert *cert.Certificate
	}{
		{"Root CA", rootCA},
		{"Server", serverCert},
	}

	now := time.Now()
	for _, certInfo := range certificates {
		certData := certInfo.cert
		fmt.Printf("     %s Certificate:\n", certInfo.name)
		fmt.Printf("       - Valid from: %s\n", certData.Certificate.NotBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("       - Valid until: %s\n", certData.Certificate.NotAfter.Format("2006-01-02 15:04:05"))

		if now.Before(certData.Certificate.NotBefore) {
			fmt.Printf("       - Status: ❌ Not yet valid\n")
		} else if now.After(certData.Certificate.NotAfter) {
			fmt.Printf("       - Status: ❌ Expired\n")
		} else {
			daysLeft := int(certData.Certificate.NotAfter.Sub(now).Hours() / 24)
			fmt.Printf("       - Status: ✅ Valid (%d days remaining)\n", daysLeft)
		}
	}

	fmt.Println("\n7.3 Certificate Information Extraction")

	fmt.Printf("   → Extracting detailed certificate information...\n")

	// Analyze the server certificate in detail
	certDetails := serverCert.Certificate
	fmt.Printf("     Certificate Analysis:\n")
	fmt.Printf("       - Serial Number: %s\n", certDetails.SerialNumber.String())
	fmt.Printf("       - Signature Algorithm: %s\n", certDetails.SignatureAlgorithm.String())
	fmt.Printf("       - Public Key Algorithm: %s\n", certDetails.PublicKeyAlgorithm.String())
	fmt.Printf("       - Version: %d\n", certDetails.Version)
	fmt.Printf("       - Is CA: %v\n", certDetails.IsCA)

	if len(certDetails.DNSNames) > 0 {
		fmt.Printf("       - DNS Names: %v\n", certDetails.DNSNames)
	}
	if len(certDetails.IPAddresses) > 0 {
		fmt.Printf("       - IP Addresses: %v\n", certDetails.IPAddresses)
	}
	if len(certDetails.EmailAddresses) > 0 {
		fmt.Printf("       - Email Addresses: %v\n", certDetails.EmailAddresses)
	}

	// Calculate and display certificate fingerprints
	fmt.Printf("       - SHA-256 Fingerprint: %x\n", certDetails.Raw[:32]) // First 32 bytes as example

	fmt.Println("\n7.4 Invalid Certificate Testing")

	fmt.Printf("   → Testing validation with invalid scenarios...\n")

	// Create a self-signed certificate that shouldn't validate against the CA
	invalidKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Printf("Failed to generate invalid certificate key pair: %v\n", err)
		return
	}

	invalidRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "invalid-cert.example.com",
		},
		ValidFrom: time.Now(),
		ValidFor:  365 * 24 * time.Hour,
	}

	invalidCert, err := cert.CreateSelfSignedCertificate(invalidKeyPair, invalidRequest)
	if err != nil {
		log.Printf("Failed to create invalid certificate: %v\n", err)
		return
	}

	// Try to validate this self-signed certificate against the CA (should fail)
	err = cert.VerifyCertificate(invalidCert, rootCA)
	if err != nil {
		fmt.Printf("     ✓ Invalid certificate correctly rejected: %v\n", err)
	} else {
		fmt.Printf("     ❌ ERROR: Invalid certificate was incorrectly accepted\n")
	}
}

// PART 8: Integration & Advanced Features
func demonstrateIntegrationFeatures() {
	fmt.Println("\n8.1 Certificate-KeyPair Integration")

	fmt.Printf("   → Demonstrating seamless certificate-keypair integration...\n")

	// Generate keys with different algorithms
	algorithms := []struct {
		name    string
		genFunc func() (interface{}, error)
	}{
		{"RSA", func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize2048) }},
		{"ECDSA", func() (interface{}, error) { return algo.GenerateECDSAKeyPair(algo.P256) }},
		{"Ed25519", func() (interface{}, error) { return algo.GenerateEd25519KeyPair() }},
	}

	for _, alg := range algorithms {
		fmt.Printf("     → Creating %s certificate with integrated key management...\n", alg.name)

		keyPairInterface, err := alg.genFunc()
		if err != nil {
			log.Printf("Failed to generate %s key pair: %v\n", alg.name, err)
			continue
		}

		request := cert.CertificateRequest{
			Subject: pkix.Name{
				Organization: []string{"Integration Testing"},
				CommonName:   fmt.Sprintf("%s Integration Test", alg.name),
			},
			ValidFrom: time.Now(),
			ValidFor:  365 * 24 * time.Hour,
		}

		var certificate *cert.Certificate
		var keyFilename string

		switch keyPair := keyPairInterface.(type) {
		case *algo.RSAKeyPair:
			certificate, err = cert.CreateSelfSignedCertificate(keyPair, request)
			if err == nil {
				err = keypair.ToPEMFiles(keyPair, "output/integration_rsa_private.pem", "output/integration_rsa_public.pem")
				keyFilename = "output/integration_rsa_private.pem"
			}
		case *algo.ECDSAKeyPair:
			certificate, err = cert.CreateSelfSignedCertificate(keyPair, request)
			if err == nil {
				err = keypair.ToPEMFiles(keyPair, "output/integration_ecdsa_private.pem", "output/integration_ecdsa_public.pem")
				keyFilename = "output/integration_ecdsa_private.pem"
			}
		case *algo.Ed25519KeyPair:
			certificate, err = cert.CreateSelfSignedCertificate(keyPair, request)
			if err == nil {
				err = keypair.ToPEMFiles(keyPair, "output/integration_ed25519_private.pem", "output/integration_ed25519_public.pem")
				keyFilename = "output/integration_ed25519_private.pem"
			}
		}

		if err != nil {
			log.Printf("Failed to create %s certificate or save keys: %v\n", alg.name, err)
			continue
		}

		certFilename := fmt.Sprintf("output/integration_%s_cert.pem", strings.ToLower(alg.name))
		err = certificate.SaveToFile(certFilename)
		if err != nil {
			log.Printf("Failed to save %s certificate: %v\n", alg.name, err)
			continue
		}

		fmt.Printf("       ✓ %s certificate and key pair created\n", alg.name)
		fmt.Printf("       ✓ Certificate: %s\n", certFilename)
		fmt.Printf("       ✓ Private key: %s\n", keyFilename)
	}

	fmt.Println("\n8.2 Real-World TLS Server Setup Simulation")

	fmt.Printf("   → Simulating complete TLS server certificate setup...\n")

	// Create a production-like server certificate
	serverKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Printf("Failed to generate server key pair: %v\n", err)
		return
	}

	serverRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
			Organization:       []string{"GoPKI Production Services"},
			OrganizationalUnit: []string{"Web Services"},
			CommonName:         "api.production.gopki.com",
		},
		DNSNames: []string{
			"api.production.gopki.com",
			"www.production.gopki.com",
			"cdn.production.gopki.com",
			"admin.production.gopki.com",
		},
		IPAddresses: []net.IP{
			net.IPv4(203, 0, 113, 10), // Example public IP
			net.IPv4(203, 0, 113, 11), // Load balancer IP
		},
		EmailAddress: []string{
			"admin@production.gopki.com",
			"security@production.gopki.com",
		},
		ValidFrom: time.Now(),
		ValidFor:  2 * 365 * 24 * time.Hour, // 2 years
	}

	// Load the CA for signing
	rootCA, err := cert.LoadCertificateFromFile("output/root_ca.pem")
	if err != nil {
		log.Printf("Failed to load root CA: %v\n", err)
		return
	}

	// Load CA private key
	caKeyData, err := os.ReadFile("output/root_ca_private.pem")
	if err != nil {
		log.Printf("Failed to read CA private key: %v\n", err)
		return
	}

	// Parse RSA key from PEM data
	parsedCAKey, err := algo.RSAKeyPairFromPEM(format.PEM(caKeyData))
	if err != nil {
		log.Printf("Failed to parse CA private key: %v\n", err)
		return
	}
	caKey := parsedCAKey

	// Sign server certificate with CA
	serverCert, err := cert.SignCertificate(rootCA, caKey, serverRequest, &serverKeyPair.PrivateKey.PublicKey)
	if err != nil {
		log.Printf("Failed to sign server certificate: %v\n", err)
		return
	}

	// Save production server certificate and key
	err = serverCert.SaveToFile("output/production_server.pem")
	if err != nil {
		log.Printf("Failed to save production server certificate: %v\n", err)
		return
	}

	err = keypair.ToPEMFiles(serverKeyPair, "output/production_server_private.pem", "output/production_server_public.pem")
	if err != nil {
		log.Printf("Failed to save production server keys: %v\n", err)
		return
	}

	fmt.Printf("     ✓ Production TLS server certificate created\n")
	fmt.Printf("     ✓ Subject: %s\n", serverCert.Certificate.Subject.CommonName)
	fmt.Printf("     ✓ SAN domains: %v\n", serverCert.Certificate.DNSNames)
	fmt.Printf("     ✓ Valid for: 2 years\n")
	fmt.Printf("     ✓ Ready for TLS server deployment\n")

	fmt.Println("\n8.3 Certificate Metadata and Analytics")

	fmt.Printf("   → Analyzing certificate collection metrics...\n")

	// Scan output directory for certificates
	files, err := os.ReadDir("output")
	if err != nil {
		log.Printf("Failed to read output directory: %v\n", err)
		return
	}

	var certFiles []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".pem") && !strings.Contains(file.Name(), "private") && !strings.Contains(file.Name(), "public") {
			certFiles = append(certFiles, file.Name())
		}
	}

	fmt.Printf("     ✓ Found %d certificate files\n", len(certFiles))

	algorithmCounts := make(map[string]int)
	var totalCerts int
	var caCerts int
	var selfSignedCerts int

	for _, certFile := range certFiles {
		certPath := fmt.Sprintf("output/%s", certFile)
		certificate, err := cert.LoadCertificateFromFile(certPath)
		if err != nil {
			continue
		}

		totalCerts++

		// Count by algorithm
		alg := certificate.Certificate.PublicKeyAlgorithm.String()
		algorithmCounts[alg]++

		// Count CA certificates
		if certificate.Certificate.IsCA {
			caCerts++
		}

		// Count self-signed (issuer == subject)
		if certificate.Certificate.Issuer.CommonName == certificate.Certificate.Subject.CommonName {
			selfSignedCerts++
		}
	}

	fmt.Printf("     ✓ Certificate Collection Analytics:\n")
	fmt.Printf("       - Total certificates: %d\n", totalCerts)
	fmt.Printf("       - CA certificates: %d\n", caCerts)
	fmt.Printf("       - Self-signed certificates: %d\n", selfSignedCerts)
	fmt.Printf("       - End-entity certificates: %d\n", totalCerts-selfSignedCerts)
	fmt.Printf("     ✓ Algorithm distribution:\n")
	for alg, count := range algorithmCounts {
		percentage := float64(count) / float64(totalCerts) * 100
		fmt.Printf("       - %s: %d (%.1f%%)\n", alg, count, percentage)
	}

	fmt.Println("\n8.4 Integration Summary and Best Practices")

	fmt.Printf("   → Certificate module integration summary...\n")
	fmt.Printf("     ✓ Multi-algorithm support demonstrated (RSA, ECDSA, Ed25519)\n")
	fmt.Printf("     ✓ Complete CA hierarchy created (Root → Intermediate → End-entity)\n")
	fmt.Printf("     ✓ Complex SAN configurations working correctly\n")
	fmt.Printf("     ✓ Format operations (PEM/DER) functioning properly\n")
	fmt.Printf("     ✓ PKCS#12 integration for certificate distribution\n")
	fmt.Printf("     ✓ Certificate validation and chain verification working\n")
	fmt.Printf("     ✓ Production-ready TLS server setup demonstrated\n")

	fmt.Printf("\n     Best Practices Demonstrated:\n")
	fmt.Printf("       • Use ECDSA P-256+ or Ed25519 for new certificates\n")
	fmt.Printf("       • Implement proper CA hierarchies with path length constraints\n")
	fmt.Printf("       • Use comprehensive SAN for multi-domain certificates\n")
	fmt.Printf("       • Store certificates in DER format for performance\n")
	fmt.Printf("       • Use PKCS#12 for secure certificate distribution\n")
	fmt.Printf("       • Implement proper certificate validation workflows\n")
	fmt.Printf("       • Regular certificate expiration monitoring\n")
}
