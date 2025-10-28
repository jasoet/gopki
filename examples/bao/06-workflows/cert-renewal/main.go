//go:build example

// Package main demonstrates automated certificate renewal workflow.
//
// This example shows how to:
// - Monitor certificate expiration
// - Automatically renew certificates before expiry
// - Handle certificate rotation
// - Update deployed certificates
//
// Automated renewal is critical for:
// - Avoiding service disruptions
// - Maintaining security compliance
// - Reducing operational overhead
// - Supporting short-lived certificates
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

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Setup CA and role
	fmt.Println("Setup: Creating CA and role...")
	_, err = client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:       "internal",
		CommonName: "Renewal Test CA",
		KeyType:    "rsa",
		KeyBits:    2048,
		TTL:        "87600h",
	})
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}

	err = client.CreateRole(ctx, "web-server", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "168h", // 7 days (short for demonstration)
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Println("✓ CA and role created")

	// Step 1: Issue initial certificate
	fmt.Println("\n=== Step 1: Issuing Initial Certificate ===")
	cert, err := client.GenerateRSACertificate(ctx, "web-server",
		&bao.GenerateCertificateOptions{
			CommonName: "app.example.com",
			TTL:        "168h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate: %v", err)
	}

	certInfo := cert.CertificateInfo()
	certData := cert.Certificate()

	fmt.Printf("✓ Initial certificate issued: %s\n", certInfo.SerialNumber)
	fmt.Printf("  CN: %s\n", certData.Certificate.Subject.CommonName)
	fmt.Printf("  Valid Until: %s\n", certData.Certificate.NotAfter.Format(time.RFC3339))

	// Step 2: Check expiration
	fmt.Println("\n=== Step 2: Monitoring Certificate Expiration ===")
	timeUntilExpiry := time.Until(certData.Certificate.NotAfter)
	daysUntilExpiry := int(timeUntilExpiry.Hours() / 24)

	fmt.Printf("Time until expiration: %v\n", timeUntilExpiry)
	fmt.Printf("Days until expiration: %d\n", daysUntilExpiry)

	renewalThreshold := 30 * 24 * time.Hour // Renew if less than 30 days
	if timeUntilExpiry < renewalThreshold {
		fmt.Println("⚠ Certificate should be renewed")
	} else {
		fmt.Println("✓ Certificate does not need renewal yet")
	}

	// Step 3: Automatic renewal
	fmt.Println("\n=== Step 3: Renewing Certificate ===")
	fmt.Println("Simulating automatic renewal process...")

	newCert, err := client.GenerateRSACertificate(ctx, "web-server",
		&bao.GenerateCertificateOptions{
			CommonName: "app.example.com",
			TTL:        "168h",
		})
	if err != nil {
		log.Fatalf("Failed to renew certificate: %v", err)
	}

	newCertInfo := newCert.CertificateInfo()
	newCertData := newCert.Certificate()

	fmt.Printf("✓ New certificate issued: %s\n", newCertInfo.SerialNumber)
	fmt.Printf("  Valid Until: %s\n", newCertData.Certificate.NotAfter.Format(time.RFC3339))

	// Step 4: Certificate rotation
	fmt.Println("\n=== Step 4: Certificate Rotation ===")
	fmt.Println("1. Deploy new certificate to servers")
	fmt.Println("2. Test new certificate")
	fmt.Println("3. Switch traffic to new certificate")
	fmt.Println("4. Revoke old certificate")

	// Revoke old certificate
	err = cert.Revoke(ctx)
	if err != nil {
		log.Printf("Warning: Failed to revoke old certificate: %v", err)
	} else {
		fmt.Printf("✓ Old certificate revoked: %s\n", certInfo.SerialNumber)
	}

	// Summary
	fmt.Println("\n✓ Certificate Renewal Workflow Completed!")

	fmt.Println("\nRenewal Strategy:")
	fmt.Println("  • Renew certificates 30 days before expiration")
	fmt.Println("  • Allow overlap period for smooth transition")
	fmt.Println("  • Revoke old certificate after successful deployment")
	fmt.Println("  • Monitor renewal success/failure")

	fmt.Println("\nAutomation Recommendations:")
	fmt.Println("  ✓ Schedule periodic renewal checks (daily)")
	fmt.Println("  ✓ Alert on renewal failures")
	fmt.Println("  ✓ Implement retry logic")
	fmt.Println("  ✓ Test renewal process regularly")
	fmt.Println("  ✓ Maintain audit logs")

	fmt.Println("\nExample Renewal Schedule:")
	fmt.Println("  Certificate TTL: 90 days")
	fmt.Println("  Renewal threshold: 30 days before expiry")
	fmt.Println("  Overlap period: 7 days")
	fmt.Println("  Old cert revocation: After successful deployment")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
