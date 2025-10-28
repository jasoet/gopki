//go:build example

// Package main demonstrates how to retrieve certificates by serial number from OpenBao.
//
// This example shows how to:
// - Issue certificates and save their serial numbers
// - Retrieve certificates by serial number
// - Extract and display certificate information
// - Verify certificate properties
//
// Certificate retrieval is useful for:
// - Auditing and compliance
// - Certificate verification
// - Debugging TLS issues
// - Inventory management
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
)

func main() {
	client, err := bao.NewClient(&bao.Config{
		Address: getEnv("BAO_ADDR", "http://127.0.0.1:8200"),
		Token:   getEnv("BAO_TOKEN", ""),
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Setup CA and role
	fmt.Println("Setting up CA and role...")
	caResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:       "internal",
		CommonName: "Example Root CA",
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

	_, err = issuer.CreateRole(ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Println("✓ CA and role configured")

	// Step 1: Issue certificates
	fmt.Println("\n=== Issuing Certificates ===")

	cert1, err := client.GenerateRSACertificate(ctx, "web-server",
		&bao.GenerateCertificateOptions{
			CommonName: "api.example.com",
			AltNames:   []string{"api-v1.example.com"},
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate 1: %v", err)
	}
	serial1 := cert1.CertificateInfo().SerialNumber
	fmt.Printf("✓ Certificate 1 issued\n")
	fmt.Printf("  Serial: %s\n", serial1)
	fmt.Printf("  CN: %s\n", cert1.Certificate().Certificate.Subject.CommonName)

	cert2, err := client.GenerateRSACertificate(ctx, "web-server",
		&bao.GenerateCertificateOptions{
			CommonName: "web.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate 2: %v", err)
	}
	serial2 := cert2.CertificateInfo().SerialNumber
	fmt.Printf("✓ Certificate 2 issued\n")
	fmt.Printf("  Serial: %s\n", serial2)

	// Step 2: Retrieve certificate by serial
	fmt.Println("\n=== Retrieving Certificate ===")
	fmt.Printf("Retrieving certificate: %s\n", serial1)

	retrieved, err := client.GetCertificate(ctx, serial1)
	if err != nil {
		log.Fatalf("Failed to retrieve certificate: %v", err)
	}
	fmt.Println("✓ Certificate retrieved successfully")

	// Step 3: Display detailed information
	fmt.Println("\n=== Certificate Details ===")
	cert := retrieved.Certificate

	fmt.Println("Subject Information:")
	fmt.Printf("  Common Name: %s\n", cert.Subject.CommonName)
	fmt.Printf("  Organization: %v\n", cert.Subject.Organization)
	fmt.Printf("  Country: %v\n", cert.Subject.Country)

	fmt.Println("\nIssuer Information:")
	fmt.Printf("  Common Name: %s\n", cert.Issuer.CommonName)

	fmt.Println("\nValidity Period:")
	fmt.Printf("  Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not After: %s\n", cert.NotAfter.Format(time.RFC3339))
	remaining := time.Until(cert.NotAfter)
	fmt.Printf("  Time Remaining: %v\n", remaining)

	if len(cert.DNSNames) > 0 {
		fmt.Println("\nSubject Alternative Names (SANs):")
		for _, dns := range cert.DNSNames {
			fmt.Printf("  • %s\n", dns)
		}
	}

	fmt.Println("\nKey Information:")
	fmt.Printf("  Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("  Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("  Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)

	// Step 4: Retrieve second certificate
	fmt.Println("\n=== Retrieving Second Certificate ===")
	fmt.Printf("Retrieving: %s\n", serial2)

	retrieved2, err := client.GetCertificate(ctx, serial2)
	if err != nil {
		log.Fatalf("Failed to retrieve certificate 2: %v", err)
	}
	fmt.Printf("✓ Certificate retrieved: %s\n", retrieved2.Certificate.Subject.CommonName)

	fmt.Println("\n✓ Certificate retrieval completed!")

	fmt.Println("\nUse Cases:")
	fmt.Println("  • Certificate auditing and compliance")
	fmt.Println("  • Debugging TLS/SSL issues")
	fmt.Println("  • Certificate inventory management")
	fmt.Println("  • Monitoring certificate expiration")
	fmt.Println("  • Validating certificate properties")

	fmt.Println("\nBest Practices:")
	fmt.Println("  ✓ Store certificate serials for later retrieval")
	fmt.Println("  ✓ Implement periodic certificate audits")
	fmt.Println("  ✓ Monitor certificate expiration dates")
	fmt.Println("  ✓ Maintain certificate inventory")
	fmt.Println("  ✓ Verify certificates match expected properties")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
