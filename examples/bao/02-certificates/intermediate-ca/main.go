//go:build example

// Package main demonstrates how to create an intermediate CA with OpenBao.
//
// This example shows how to:
// - Create a root CA
// - Generate intermediate CA CSR
// - Sign intermediate CSR with root CA
// - Import intermediate CA into OpenBao
// - Issue end-entity certificates from intermediate CA
//
// CA Hierarchy:
//   Root CA
//     └── Intermediate CA
//           └── End-entity certificates
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

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Step 1: Create root CA
	fmt.Println("Step 1: Creating root CA...")
	rootResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:          "internal",
		CommonName:    "Example Root CA",
		Organization:  []string{"Example Corp"},
		KeyType:       "rsa",
		KeyBits:       4096,
		TTL:           "87600h",       // 10 years
		MaxPathLength: -1,             // Allow unlimited intermediate CAs
		IssuerName:    "root-ca-2024",
	})
	if err != nil {
		log.Fatalf("Failed to create root CA: %v", err)
	}

	rootIssuer, err := client.GetIssuer(ctx, rootResp.IssuerID)
	if err != nil {
		log.Fatalf("Failed to get root issuer: %v", err)
	}
	fmt.Printf("✓ Root CA created: %s\n", rootResp.IssuerID)

	// Step 2: Generate intermediate CA CSR
	fmt.Println("\nStep 2: Generating intermediate CA CSR...")
	intermediateResp, err := client.GenerateIntermediateCA(ctx, &bao.CAOptions{
		Type:         "exported", // Export to get CSR
		CommonName:   "Example Intermediate CA",
		Organization: []string{"Example Corp"},
		KeyType:      "rsa",
		KeyBits:      2048,
	})
	if err != nil {
		log.Fatalf("Failed to generate intermediate CSR: %v", err)
	}
	fmt.Println("✓ Intermediate CSR generated")

	// Step 3: Parse and sign the intermediate CSR with root CA
	fmt.Println("\nStep 3: Signing intermediate CSR with root CA...")
	intermediateCSR, err := cert.ParseCSRFromPEM([]byte(intermediateResp.CSR))
	if err != nil {
		log.Fatalf("Failed to parse CSR: %v", err)
	}

	// Configure the client to use the specific root issuer as default
	client.SetDefaultIssuer(ctx, rootResp.IssuerID)

	// Sign intermediate CSR using client
	signedCert, err := client.SignIntermediateCSR(ctx, intermediateCSR, &bao.CAOptions{
		CommonName:    "Example Intermediate CA",
		TTL:           "43800h", // 5 years
		MaxPathLength: 0,        // Can only sign end-entity certs
	})
	if err != nil {
		log.Fatalf("Failed to sign intermediate CSR: %v", err)
	}
	fmt.Println("✓ Intermediate CSR signed")

	// Step 4: Import signed intermediate certificate with private key
	fmt.Println("\nStep 4: Importing signed intermediate CA...")

	// Combine the signed certificate with the private key
	pemBundle := string(signedCert.ToPEM()) + "\n" + intermediateResp.PrivateKey

	intermediateIssuer, err := client.ImportCA(ctx, &bao.CABundle{
		PEMBundle: pemBundle,
	})
	if err != nil {
		log.Fatalf("Failed to import intermediate CA: %v", err)
	}
	fmt.Println("✓ Intermediate CA imported")

	// Step 5: Create role on intermediate CA
	fmt.Println("\nStep 5: Creating role on intermediate CA...")
	_, err = intermediateIssuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Println("✓ Role created")

	// Step 6: Issue end-entity certificate from intermediate CA
	fmt.Println("\nStep 6: Issuing end-entity certificate...")
	certClient, err := client.GenerateRSACertificate(ctx, "web-server",
		&bao.GenerateCertificateOptions{
			CommonName: "app.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate: %v", err)
	}

	endEntityCert := certClient.Certificate()
	fmt.Println("✓ End-entity certificate issued")

	// Step 7: Verify the full chain
	fmt.Println("\nStep 7: Verifying certificate chain...")
	intermediateCert, err := intermediateIssuer.Certificate()
	if err != nil {
		log.Fatalf("Failed to get intermediate cert: %v", err)
	}

	rootCert, err := rootIssuer.Certificate()
	if err != nil {
		log.Fatalf("Failed to get root cert: %v", err)
	}

	// Verify: End-entity -> Intermediate
	err = cert.VerifyCertificate(endEntityCert, intermediateCert)
	if err != nil {
		log.Fatalf("End-entity to intermediate verification failed: %v", err)
	}

	// Verify: Intermediate -> Root
	err = cert.VerifyCertificate(intermediateCert, rootCert)
	if err != nil {
		log.Fatalf("Intermediate to root verification failed: %v", err)
	}
	fmt.Println("✓ Full certificate chain verified")

	// Display CA hierarchy
	fmt.Println("\n✓ CA Hierarchy Created Successfully!")
	fmt.Println("\n  Root CA (Example Root CA)")
	fmt.Println("    └── Intermediate CA (Example Intermediate CA)")
	fmt.Println("          └── End-entity Certificate (app.example.com)")

	fmt.Println("\nCertificate Details:")
	fmt.Printf("  End-entity CN: %s\n", endEntityCert.Certificate.Subject.CommonName)
	fmt.Printf("  Intermediate CN: %s\n", intermediateCert.Certificate.Subject.CommonName)
	fmt.Printf("  Root CN: %s\n", rootCert.Certificate.Subject.CommonName)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
