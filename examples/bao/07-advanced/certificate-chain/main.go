//go:build example

// Package main demonstrates certificate chain building and validation.
//
// This example shows how to:
// - Build complete certificate chains
// - Verify chain validation
// - Export full chains for deployment
// - Handle intermediate CAs
//
// Certificate chains are critical for:
// - TLS/SSL validation
// - Trust establishment
// - Browser compatibility
// - Client verification
//
// Prerequisites:
// - OpenBao server running
//
// Usage:
//   go run main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jasoet/gopki/bao"
	"github.com/jasoet/gopki/cert"
)

func main() {
	client, err := bao.NewClient(&bao.Config{
		Address: getEnv("BAO_ADDR", "http://127.0.0.1:8200"),
		Token:   getEnv("BAO_TOKEN", ""),
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Step 1: Create root CA
	fmt.Println("=== Step 1: Creating Root CA ===")
	rootResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:          "internal",
		CommonName:    "Chain Test Root CA",
		KeyType:       "rsa",
		KeyBits:       2048,
		TTL:           "87600h",
		MaxPathLength: 2,
	})
	if err != nil {
		log.Fatalf("Failed to create root CA: %v", err)
	}
	fmt.Printf("✓ Root CA created: %s\n", rootResp.Certificate.Certificate.Subject.CommonName)

	rootIssuer, _ := client.GetIssuer(ctx, rootResp.IssuerID)

	// Step 2: Create intermediate CA
	fmt.Println("\n=== Step 2: Creating Intermediate CA ===")
	intermediateResp, err := client.GenerateIntermediateCA(ctx, &bao.CAOptions{
		Type:       "exported",
		CommonName: "Chain Test Intermediate CA",
		KeyType:    "rsa",
		KeyBits:    2048,
	})
	if err != nil {
		log.Fatalf("Failed to generate intermediate CSR: %v", err)
	}

	intermediateCSR, err := cert.ParseCSRFromPEM([]byte(intermediateResp.CSR))
	if err != nil {
		log.Fatalf("Failed to parse CSR: %v", err)
	}

	// Configure the client to use the specific root issuer as default
	client.SetDefaultIssuer(ctx, rootResp.IssuerID)

	// Sign intermediate CSR using client
	intermediateCert, err := client.SignIntermediateCSR(ctx, intermediateCSR, &bao.CAOptions{
		CommonName:    "Chain Test Intermediate CA",
		TTL:           "43800h",
		MaxPathLength: 1,
	})
	if err != nil {
		log.Fatalf("Failed to sign intermediate CSR: %v", err)
	}
	fmt.Printf("✓ Intermediate CA created: %s\n", intermediateCert.Certificate.Subject.CommonName)

	// Import intermediate CA with private key
	pemBundle := string(intermediateCert.ToPEM()) + "\n" + intermediateResp.PrivateKey
	intermediateIssuer, err := client.ImportCA(ctx, &bao.CABundle{
		PEMBundle: pemBundle,
	})
	if err != nil {
		log.Fatalf("Failed to import intermediate CA: %v", err)
	}

	// Step 3: Create role on intermediate CA
	_, err = intermediateIssuer.CreateRole(ctx, "chain-test", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}

	// Step 4: Issue end-entity certificate
	fmt.Println("\n=== Step 3: Issuing End-Entity Certificate ===")
	endCert, err := client.GenerateRSACertificate(ctx, "chain-test",
		&bao.GenerateCertificateOptions{
			CommonName: "www.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate: %v", err)
	}
	fmt.Printf("✓ End-entity certificate issued: %s\n", endCert.Certificate().Certificate.Subject.CommonName)

	// Step 5: Build and verify chain
	fmt.Println("\n=== Step 4: Building Certificate Chain ===")

	rootCert, _ := rootIssuer.Certificate()
	intermediateCertData, _ := intermediateIssuer.Certificate()
	endCertData := endCert.Certificate()

	fmt.Println("Certificate Chain:")
	fmt.Printf("  3. Root CA: %s\n", rootCert.Certificate.Subject.CommonName)
	fmt.Printf("  2. Intermediate CA: %s\n", intermediateCertData.Certificate.Subject.CommonName)
	fmt.Printf("  1. End-Entity: %s\n", endCertData.Certificate.Subject.CommonName)

	// Verify chain
	fmt.Println("\n=== Step 5: Verifying Chain ===")

	err = cert.VerifyCertificate(endCertData, intermediateCertData)
	if err != nil {
		log.Fatalf("End-entity to intermediate verification failed: %v", err)
	}
	fmt.Println("✓ End-entity → Intermediate: Verified")

	err = cert.VerifyCertificate(intermediateCertData, rootCert)
	if err != nil {
		log.Fatalf("Intermediate to root verification failed: %v", err)
	}
	fmt.Println("✓ Intermediate → Root: Verified")

	fmt.Println("✓ Complete chain verified")

	fmt.Println("\n✓ Certificate Chain Workflow Completed!")

	fmt.Println("\nChain Deployment:")
	fmt.Println("  For web servers, provide certificates in order:")
	fmt.Println("    1. End-entity certificate")
	fmt.Println("    2. Intermediate CA certificate")
	fmt.Println("    3. Root CA certificate (optional)")

	fmt.Println("\nChain Validation Best Practices:")
	fmt.Println("  ✓ Always include intermediate certificates")
	fmt.Println("  ✓ Order certificates correctly (leaf → root)")
	fmt.Println("  ✓ Test chain with online validators")
	fmt.Println("  ✓ Monitor chain expiration")
	fmt.Println("  ✓ Keep root CA offline for security")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
