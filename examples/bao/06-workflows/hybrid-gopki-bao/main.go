//go:build example

// Package main demonstrates hybrid GoPKI and OpenBao operations.
//
// This example shows how to:
// - Generate keys locally with GoPKI
// - Create CSRs with GoPKI
// - Sign CSRs with OpenBao
// - Use GoPKI for local cryptographic operations
// - Combine strengths of both libraries
//
// Hybrid approach benefits:
// - Maximum security (keys never leave local system)
// - Flexibility in key management
// - Integration with existing systems
// - Best of both worlds
//
// Prerequisites:
// - OpenBao server running
//
// Usage:
//   go run main.go
package main

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jasoet/gopki/bao"
	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	client, err := bao.NewClient(&bao.Config{
		Address: getEnv("BAO_ADDR", "http://127.0.0.1:8200"),
		Token:   getEnv("BAO_TOKEN", ""),
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Step 1: Create CA in OpenBao
	fmt.Println("=== Step 1: Creating CA in OpenBao ===")
	caResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:       "internal",
		CommonName: "Hybrid Root CA",
		KeyType:    "rsa",
		KeyBits:    2048,
		TTL:        "87600h",
	})
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}

	issuer, err := client.GetIssuer(ctx, caResp.IssuerID)
	if err != nil {
		log.Fatalf("Failed to get issuer: %v", err)
	}
	fmt.Printf("✓ CA created in OpenBao: %s\n", caResp.IssuerID)

	// Configure client to use this specific issuer as default
	client.SetDefaultIssuer(ctx, caResp.IssuerID)

	// Step 2: Generate keys locally with GoPKI
	fmt.Println("\n=== Step 2: Generating Keys Locally (GoPKI) ===")

	rsaKey, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}
	fmt.Println("✓ RSA key generated locally with GoPKI")
	fmt.Println("  (Private key stays on local system)")

	// Generate additional examples
	rsaKey2, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}
	fmt.Println("✓ Second RSA key generated locally")

	rsaKey3, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}
	fmt.Println("✓ Third RSA key generated locally")

	// Step 3: Create CSRs with GoPKI
	fmt.Println("\n=== Step 3: Creating CSRs (GoPKI) ===")

	rsaCSR, err := cert.CreateCSR(rsaKey, cert.CSRRequest{
		Subject: pkix.Name{
			CommonName:   "service1.example.com",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create RSA CSR: %v", err)
	}
	fmt.Println("✓ CSR created for service1.example.com")

	rsaCSR2, err := cert.CreateCSR(rsaKey2, cert.CSRRequest{
		Subject: pkix.Name{
			CommonName:   "service2.example.com",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create second CSR: %v", err)
	}
	fmt.Println("✓ CSR created for service2.example.com")

	rsaCSR3, err := cert.CreateCSR(rsaKey3, cert.CSRRequest{
		Subject: pkix.Name{
			CommonName:   "service3.example.com",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create third CSR: %v", err)
	}
	fmt.Println("✓ CSR created for service3.example.com")

	// Step 4: Sign CSRs with OpenBao
	fmt.Println("\n=== Step 4: Signing CSRs (OpenBao) ===")

	// Sign first CSR
	cert1, err := issuer.SignCSR(ctx, rsaCSR, &bao.SignCertificateOptions{
		CommonName: "service1.example.com",
		TTL:        "720h",
	})
	if err != nil {
		log.Fatalf("Failed to sign first CSR: %v", err)
	}
	fmt.Printf("✓ Certificate signed: %s\n", cert1.Certificate.Subject.CommonName)

	// Sign second CSR
	cert2, err := issuer.SignCSR(ctx, rsaCSR2, &bao.SignCertificateOptions{
		CommonName: "service2.example.com",
		TTL:        "720h",
	})
	if err != nil {
		log.Fatalf("Failed to sign second CSR: %v", err)
	}
	fmt.Printf("✓ Certificate signed: %s\n", cert2.Certificate.Subject.CommonName)

	// Sign third CSR
	cert3, err := issuer.SignCSR(ctx, rsaCSR3, &bao.SignCertificateOptions{
		CommonName: "service3.example.com",
		TTL:        "720h",
	})
	if err != nil {
		log.Fatalf("Failed to sign third CSR: %v", err)
	}
	fmt.Printf("✓ Certificate signed: %s\n", cert3.Certificate.Subject.CommonName)

	// Step 5: Display certificate information
	fmt.Println("\n=== Step 5: Certificate Information ===")

	fmt.Println("All certificates signed successfully by OpenBao!")
	fmt.Printf("  service1.example.com: %s\n", cert1.Certificate.SerialNumber)
	fmt.Printf("  service2.example.com: %s\n", cert2.Certificate.SerialNumber)
	fmt.Printf("  service3.example.com: %s\n", cert3.Certificate.SerialNumber)

	fmt.Println("\n✓ Certificates are ready for deployment with their private keys")

	fmt.Println("\n✓ Hybrid GoPKI + OpenBao Workflow Completed!")

	fmt.Println("\nHybrid Approach Benefits:")
	fmt.Println("  ✓ Private keys never leave local system (GoPKI)")
	fmt.Println("  ✓ Centralized CA management (OpenBao)")
	fmt.Println("  ✓ Flexible key generation (GoPKI)")
	fmt.Println("  ✓ Enterprise PKI features (OpenBao)")
	fmt.Println("  ✓ Local cryptographic operations (GoPKI)")

	fmt.Println("\nWhen to Use Hybrid Approach:")
	fmt.Println("  • High-security environments")
	fmt.Println("  • HSM integration requirements")
	fmt.Println("  • Existing key management systems")
	fmt.Println("  • Compliance requirements")
	fmt.Println("  • Air-gapped systems")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
