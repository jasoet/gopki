//go:build example

// Package main demonstrates CSR creation from certificates for renewal workflows.
//
// This example shows how to:
// - Generate a certificate with OpenBao
// - Create a new CSR from an existing certificate for renewal
// - Use certificate metadata (serial number, algorithm, expiration)
// - Implement certificate renewal workflows
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
	"github.com/jasoet/gopki/cert"
)

func main() {
	client, err := pki.NewClient(&pki.Config{
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
	caResp, err := client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:       "internal",
		CommonName: "CSR Renewal Demo CA",
		KeyType:    "rsa",
		KeyBits:    2048,
		TTL:        "87600h",
	})
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}
	fmt.Printf("✓ CA created: %s\n", caResp.IssuerID)

	// Step 2: Get issuer and create role for certificate issuance
	fmt.Println("\n=== Step 2: Creating Role ===")
	issuer, err := client.GetIssuer(ctx, caResp.IssuerID)
	if err != nil {
		log.Fatalf("Failed to get issuer: %v", err)
	}

	role, err := issuer.CreateRole(ctx, "renewal-role", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		KeyType:         "rsa",
		KeyBits:         2048,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Printf("✓ Role created: %s\n", role.Name())

	// Step 3: Generate initial certificate
	fmt.Println("\n=== Step 3: Generating Initial Certificate ===")
	certClient, err := client.GenerateRSACertificate(ctx, "renewal-role", &pki.GenerateCertificateOptions{
		CommonName: "api.example.com",
		AltNames:   []string{"www.api.example.com", "admin.api.example.com"},
		TTL:        "720h",
	})
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	originalCert := certClient.Certificate()
	fmt.Printf("✓ Certificate generated: %s\n", originalCert.Certificate.Subject.CommonName)
	fmt.Printf("  Serial: %s\n", certClient.SerialNumber())
	fmt.Printf("  Algorithm: %s\n", certClient.PublicKeyAlgorithm())
	fmt.Printf("  Valid Until: %s\n", originalCert.Certificate.NotAfter)

	// Step 4: Display certificate metadata
	fmt.Println("\n=== Step 4: Certificate Metadata ===")
	certInfo := certClient.CertificateInfo()
	fmt.Printf("Serial Number: %s\n", certInfo.SerialNumber)
	fmt.Printf("Expiration: %s\n", certInfo.Expiration)
	fmt.Printf("Days until expiration: %.0f\n", time.Until(certInfo.Expiration).Hours()/24)

	// Check if expired (should be false for new cert)
	if certClient.IsExpired() {
		fmt.Println("⚠ Certificate is expired")
	} else {
		fmt.Println("✓ Certificate is valid")
	}

	// Step 5: Create CSR from existing certificate for renewal
	fmt.Println("\n=== Step 5: Creating CSR for Renewal ===")
	fmt.Println("Scenario: Certificate is approaching expiration, create renewal CSR")

	csrReq := cert.CSRRequest{
		Subject:  originalCert.Certificate.Subject,
		DNSNames: originalCert.Certificate.DNSNames,
		// Can add new SANs for renewal
		IPAddresses: originalCert.Certificate.IPAddresses,
	}

	renewalCSR, err := certClient.CreateCSR(csrReq)
	if err != nil {
		log.Fatalf("Failed to create renewal CSR: %v", err)
	}
	fmt.Printf("✓ Renewal CSR created\n")
	fmt.Printf("  Subject: %s\n", renewalCSR.Request.Subject.CommonName)
	fmt.Printf("  DNS Names: %v\n", renewalCSR.Request.DNSNames)

	// Step 6: Sign the renewal CSR
	fmt.Println("\n=== Step 6: Signing Renewal CSR ===")
	renewedCert, err := client.SignCSR(ctx, "renewal-role", renewalCSR, &pki.SignCertificateOptions{
		CommonName: "api.example.com",
		TTL:        "720h", // New validity period
	})
	if err != nil {
		log.Fatalf("Failed to sign renewal CSR: %v", err)
	}
	fmt.Printf("✓ Certificate renewed: %s\n", renewedCert.Certificate.Subject.CommonName)
	fmt.Printf("  New Serial: %s\n", renewedCert.Certificate.SerialNumber)
	fmt.Printf("  New Valid Until: %s\n", renewedCert.Certificate.NotAfter)

	// Step 7: Compare old and new certificates
	fmt.Println("\n=== Step 7: Certificate Comparison ===")
	fmt.Printf("Original Certificate:\n")
	fmt.Printf("  Serial: %s\n", originalCert.Certificate.SerialNumber)
	fmt.Printf("  Issued: %s\n", originalCert.Certificate.NotBefore)
	fmt.Printf("  Expires: %s\n", originalCert.Certificate.NotAfter)

	fmt.Printf("\nRenewed Certificate:\n")
	fmt.Printf("  Serial: %s\n", renewedCert.Certificate.SerialNumber)
	fmt.Printf("  Issued: %s\n", renewedCert.Certificate.NotBefore)
	fmt.Printf("  Expires: %s\n", renewedCert.Certificate.NotAfter)

	// Verify subject and SANs match
	if originalCert.Certificate.Subject.CommonName == renewedCert.Certificate.Subject.CommonName {
		fmt.Println("\n✓ Subject matches (successful renewal)")
	}

	// Step 8: Save renewed certificate
	fmt.Println("\n=== Step 8: Saving Renewed Certificate ===")
	tmpDir, err := os.MkdirTemp("", "bao-pki-renewal-")
	if err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	renewedCertPath := tmpDir + "/renewed-cert.pem"
	renewedCertPEM := renewedCert.ToPEM()
	err = os.WriteFile(renewedCertPath, renewedCertPEM, 0644)
	if err != nil {
		log.Fatalf("Failed to save renewed certificate: %v", err)
	}
	fmt.Printf("✓ Renewed certificate saved: %s\n", renewedCertPath)

	// Step 9: Demonstrate renewal workflow
	fmt.Println("\n=== Step 9: Renewal Workflow Example ===")
	fmt.Println("Typical renewal workflow:")
	fmt.Println("  1. Monitor certificate expiration dates")
	fmt.Println("  2. When approaching expiration (e.g., 30 days before):")
	fmt.Println("     a. Create CSR using CreateCSR() from existing cert")
	fmt.Println("     b. Sign CSR with OpenBao")
	fmt.Println("     c. Save new certificate")
	fmt.Println("     d. Deploy new certificate")
	fmt.Println("     e. Revoke old certificate (if needed)")

	// Summary
	fmt.Println("\n=== Summary ===")
	fmt.Println("✓ CSR Renewal Demo Completed!")
	fmt.Println("\nDemonstrated Features:")
	fmt.Println("  • Certificate generation with OpenBao")
	fmt.Println("  • Certificate metadata access (serial, algorithm, expiration)")
	fmt.Println("  • CSR creation from existing certificates")
	fmt.Println("  • Certificate renewal workflow")
	fmt.Println("  • Certificate comparison")
	fmt.Println("  • Expiration checking")

	fmt.Printf("\nFiles saved to: %s\n", tmpDir)
	fmt.Println("(Temporary directory will be cleaned up on exit)")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
