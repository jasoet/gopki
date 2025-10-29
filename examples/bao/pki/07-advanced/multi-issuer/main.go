//go:build example

// Package main demonstrates managing multiple Certificate Authorities (issuers).
//
// This example shows how to:
// - Create multiple root CAs (production, development, staging)
// - Set default issuers
// - Issue certificates from specific issuers
// - Switch between issuers
// - Manage issuer lifecycle
//
// Multiple issuers are useful for:
// - Environment separation (prod, dev, staging)
// - Geographic distribution
// - Compliance requirements
// - Disaster recovery
// - CA rotation
//
// Prerequisites:
// - OpenBao server running
//
// Usage:
//
//	go run main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jasoet/gopki/bao/pki"
)

func main() {
	client, err := pki.NewClient(&pki.Config{
		Address: getEnv("BAO_ADDR", "http://127.0.0.1:8200"),
		Token:   getEnv("BAO_TOKEN", ""),
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Step 1: Create production CA
	fmt.Println("=== Step 1: Creating Production CA ===")
	prodCA, err := client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:         "internal",
		CommonName:   "Production Root CA",
		Organization: []string{"Example Corp"},
		KeyType:      "rsa",
		KeyBits:      4096,
		TTL:          "87600h",
		IssuerName:   "prod-root",
	})
	if err != nil {
		log.Fatalf("Failed to create production CA: %v", err)
	}
	fmt.Printf("✓ Production CA created: %s\n", prodCA.IssuerID)

	// Step 2: Create development CA
	fmt.Println("\n=== Step 2: Creating Development CA ===")
	devCA, err := client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:         "internal",
		CommonName:   "Development Root CA",
		Organization: []string{"Example Corp - Dev"},
		KeyType:      "rsa",
		KeyBits:      2048,
		TTL:          "43800h",
		IssuerName:   "dev-root",
	})
	if err != nil {
		log.Fatalf("Failed to create development CA: %v", err)
	}
	fmt.Printf("✓ Development CA created: %s\n", devCA.IssuerID)

	// Step 3: Create staging CA
	fmt.Println("\n=== Step 3: Creating Staging CA ===")
	stagingCA, err := client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:         "internal",
		CommonName:   "Staging Root CA",
		Organization: []string{"Example Corp - Staging"},
		KeyType:      "rsa",
		KeyBits:      2048,
		TTL:          "43800h",
		IssuerName:   "staging-root",
	})
	if err != nil {
		log.Fatalf("Failed to create staging CA: %v", err)
	}
	fmt.Printf("✓ Staging CA created: %s\n", stagingCA.IssuerID)

	// Step 4: List all issuers
	fmt.Println("\n=== Step 4: Listing All Issuers ===")
	issuers, err := client.ListIssuers(ctx)
	if err != nil {
		log.Fatalf("Failed to list issuers: %v", err)
	}
	fmt.Printf("Found %d issuer(s):\n", len(issuers))
	for i, issuerID := range issuers {
		issuer, _ := client.GetIssuer(ctx, issuerID)
		fmt.Printf("  %d. %s (ID: %s)\n", i+1, issuer.Name(), issuer.ID())
	}

	// Step 5: Set production as default
	fmt.Println("\n=== Step 5: Setting Production as Default Issuer ===")
	err = client.SetDefaultIssuer(ctx, prodCA.IssuerID)
	if err != nil {
		log.Fatalf("Failed to set default issuer: %v", err)
	}
	fmt.Println("✓ Production CA set as default")

	// Step 6: Create environment-specific roles
	fmt.Println("\n=== Step 6: Creating Environment-Specific Roles ===")

	prodIssuer, _ := client.GetIssuer(ctx, prodCA.IssuerID)
	_, err = prodIssuer.CreateRole(ctx, "prod-web", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create production role: %v", err)
	}
	fmt.Println("✓ Production role created")

	devIssuer, _ := client.GetIssuer(ctx, devCA.IssuerID)
	_, err = devIssuer.CreateRole(ctx, "dev-web", &pki.RoleOptions{
		AllowedDomains:  []string{"dev.example.com"},
		AllowSubdomains: true,
		TTL:             "168h",
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create development role: %v", err)
	}
	fmt.Println("✓ Development role created")

	// Step 7: Issue certificates from different issuers
	fmt.Println("\n=== Step 7: Issuing Certificates from Different Issuers ===")

	prodCert, err := client.GenerateRSACertificate(ctx, "prod-web",
		&pki.GenerateCertificateOptions{
			CommonName: "app.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue production certificate: %v", err)
	}
	fmt.Printf("✓ Production certificate issued: %s\n", prodCert.CertificateInfo().SerialNumber)
	fmt.Printf("  Issuer: %s\n", prodCert.Certificate().Certificate.Issuer.CommonName)

	devCert, err := client.GenerateRSACertificate(ctx, "dev-web",
		&pki.GenerateCertificateOptions{
			CommonName: "app.dev.example.com",
			TTL:        "168h",
		})
	if err != nil {
		log.Fatalf("Failed to issue development certificate: %v", err)
	}
	fmt.Printf("✓ Development certificate issued: %s\n", devCert.CertificateInfo().SerialNumber)
	fmt.Printf("  Issuer: %s\n", devCert.Certificate().Certificate.Issuer.CommonName)

	fmt.Println("\n✓ Multi-Issuer Workflow Completed!")

	fmt.Println("\nMulti-Issuer Architecture:")
	fmt.Println("  Production CA:")
	fmt.Println("    • Highest security (4096-bit RSA)")
	fmt.Println("    • Longer validity (10 years)")
	fmt.Println("    • Strict controls and auditing")
	fmt.Println("\n  Development CA:")
	fmt.Println("    • Faster operations (2048-bit RSA)")
	fmt.Println("    • Shorter validity (5 years)")
	fmt.Println("    • Relaxed controls")
	fmt.Println("\n  Staging CA:")
	fmt.Println("    • Production-like configuration")
	fmt.Println("    • Testing and validation")
	fmt.Println("    • Pre-production verification")

	fmt.Println("\nBest Practices:")
	fmt.Println("  ✓ Separate CAs for different environments")
	fmt.Println("  ✓ Higher security for production CAs")
	fmt.Println("  ✓ Shorter TTLs for non-production")
	fmt.Println("  ✓ Clear naming conventions")
	fmt.Println("  ✓ Regular CA rotation strategy")
	fmt.Println("  ✓ Disaster recovery procedures")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
