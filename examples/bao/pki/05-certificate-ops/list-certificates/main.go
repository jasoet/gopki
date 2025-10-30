//go:build example

// Package main demonstrates how to list and filter certificates in OpenBao.
//
// This example shows how to:
// - Issue multiple certificates
// - List all certificates
// - Filter certificates by properties
// - Monitor certificate inventory
//
// Certificate listing is useful for:
// - Certificate inventory and auditing
// - Monitoring certificate lifecycle
// - Finding certificates nearing expiration
// - Compliance reporting
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Setup CA and role
	fmt.Println("Setting up CA and role...")
	_, err = client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:       "internal",
		CommonName: "Example Root CA",
		KeyType:    "rsa",
		KeyBits:    2048,
		TTL:        "87600h",
	})
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}

	err = client.CreateRole(ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Println("✓ CA and role configured")

	// Step 1: Issue multiple certificates
	fmt.Println("\n=== Issuing Certificates ===")

	certNames := []string{
		"web1.example.com",
		"web2.example.com",
		"api.example.com",
		"admin.example.com",
		"app.example.com",
	}

	issuedCerts := make(map[string]string) // CN -> Serial

	for _, cn := range certNames {
		cert, err := client.GenerateRSACertificate(ctx, "web-server",
			&pki.GenerateCertificateOptions{
				CommonName: cn,
				TTL:        "720h",
			})
		if err != nil {
			log.Printf("Failed to issue certificate for %s: %v", cn, err)
			continue
		}
		serial := cert.CertificateInfo().SerialNumber
		issuedCerts[cn] = serial
		fmt.Printf("✓ Issued: %s (Serial: %s)\n", cn, serial)
	}

	fmt.Printf("\nTotal certificates issued: %d\n", len(issuedCerts))

	// Step 2: List all certificates
	fmt.Println("\n=== Listing All Certificates ===")

	certificates, err := client.ListCertificates(ctx)
	if err != nil {
		log.Fatalf("Failed to list certificates: %v", err)
	}

	fmt.Printf("Found %d certificate(s):\n\n", len(certificates))

	for i, serial := range certificates {
		cert, err := client.GetCertificate(ctx, serial)
		if err != nil {
			log.Printf("Warning: Could not retrieve certificate %s: %v", serial, err)
			continue
		}

		fmt.Printf("%d. Certificate: %s\n", i+1, serial)
		fmt.Printf("   CN: %s\n", cert.Certificate.Subject.CommonName)
		fmt.Printf("   Valid Until: %s\n", cert.Certificate.NotAfter.Format(time.RFC3339))

		// Calculate days until expiration
		daysUntilExpiry := int(time.Until(cert.Certificate.NotAfter).Hours() / 24)
		fmt.Printf("   Expires In: %d days\n", daysUntilExpiry)

		if len(cert.Certificate.DNSNames) > 0 {
			fmt.Printf("   SANs: %v\n", cert.Certificate.DNSNames)
		}
		fmt.Println()
	}

	// Step 3: Find certificates expiring soon
	fmt.Println("=== Certificates Expiring Soon (< 60 days) ===")

	expiringThreshold := 60 * 24 * time.Hour // 60 days
	expiringSoon := []string{}

	for _, serial := range certificates {
		cert, err := client.GetCertificate(ctx, serial)
		if err != nil {
			continue
		}

		timeUntilExpiry := time.Until(cert.Certificate.NotAfter)
		if timeUntilExpiry < expiringThreshold && timeUntilExpiry > 0 {
			expiringSoon = append(expiringSoon, serial)
			daysRemaining := int(timeUntilExpiry.Hours() / 24)
			fmt.Printf("⚠ %s - %s (expires in %d days)\n",
				cert.Certificate.Subject.CommonName,
				serial,
				daysRemaining)
		}
	}

	if len(expiringSoon) == 0 {
		fmt.Println("✓ No certificates expiring soon")
	} else {
		fmt.Printf("\n⚠ %d certificate(s) need renewal soon\n", len(expiringSoon))
	}

	// Summary
	fmt.Println("\n=== Certificate Inventory Summary ===")
	fmt.Printf("  Total Certificates: %d\n", len(certificates))
	fmt.Printf("  Expiring Soon (< 60 days): %d\n", len(expiringSoon))
	fmt.Printf("  Active: %d\n", len(certificates)-len(expiringSoon))

	fmt.Println("\n✓ Certificate listing completed!")

	fmt.Println("\nInventory Management Use Cases:")
	fmt.Println("  • Certificate lifecycle tracking")
	fmt.Println("  • Expiration monitoring and alerts")
	fmt.Println("  • Compliance auditing")
	fmt.Println("  • Renewal planning")
	fmt.Println("  • Orphaned certificate detection")

	fmt.Println("\nAutomation Recommendations:")
	fmt.Println("  • Schedule periodic inventory scans")
	fmt.Println("  • Alert on certificates expiring in < 30 days")
	fmt.Println("  • Generate compliance reports")
	fmt.Println("  • Automate renewal workflows")
	fmt.Println("  • Track certificate usage patterns")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
