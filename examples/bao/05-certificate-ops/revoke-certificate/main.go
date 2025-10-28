//go:build example

// Package main demonstrates how to revoke certificates in OpenBao.
//
// This example shows how to:
// - Issue multiple certificates
// - Revoke individual certificates
// - Verify revocation status
// - Handle revoked certificates
//
// Certificate revocation is important for:
// - Compromised private keys
// - Employee termination
// - System decommissioning
// - Security incidents
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

	// Setup: Create CA and role
	fmt.Println("Setup: Creating CA and role...")
	caResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:       "internal",
		CommonName: "Revocation Test CA",
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

	_, err = issuer.CreateRole(ctx, "test-role", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Println("✓ CA and role created")

	// Step 1: Issue certificates
	fmt.Println("\n=== Step 1: Issuing Certificates ===")

	cert1, err := client.GenerateRSACertificate(ctx, "test-role",
		&bao.GenerateCertificateOptions{
			CommonName: "server1.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate 1: %v", err)
	}
	serial1 := cert1.CertificateInfo().SerialNumber
	fmt.Printf("✓ Certificate 1 issued: %s\n", serial1)
	fmt.Printf("  CN: %s\n", cert1.Certificate().Certificate.Subject.CommonName)

	cert2, err := client.GenerateRSACertificate(ctx, "test-role",
		&bao.GenerateCertificateOptions{
			CommonName: "server2.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate 2: %v", err)
	}
	serial2 := cert2.CertificateInfo().SerialNumber
	fmt.Printf("✓ Certificate 2 issued: %s\n", serial2)
	fmt.Printf("  CN: %s\n", cert2.Certificate().Certificate.Subject.CommonName)

	cert3, err := client.GenerateRSACertificate(ctx, "test-role",
		&bao.GenerateCertificateOptions{
			CommonName: "server3.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate 3: %v", err)
	}
	serial3 := cert3.CertificateInfo().SerialNumber
	fmt.Printf("✓ Certificate 3 issued: %s\n", serial3)
	fmt.Printf("  CN: %s\n", cert3.Certificate().Certificate.Subject.CommonName)

	// Step 2: Revoke certificate 1
	fmt.Println("\n=== Step 2: Revoking Certificate 1 ===")
	fmt.Printf("Revoking certificate: %s\n", serial1)

	err = cert1.Revoke(ctx)
	if err != nil {
		log.Fatalf("Failed to revoke certificate 1: %v", err)
	}

	fmt.Printf("✓ Certificate revoked: %s\n", serial1)
	fmt.Println("  Reason: Demonstration")

	// Step 3: Verify other certificates are still valid
	fmt.Println("\n=== Step 3: Verifying Other Certificates ===")

	retrieved2, err := client.GetCertificate(ctx, serial2)
	if err != nil {
		log.Fatalf("Failed to retrieve certificate 2: %v", err)
	}
	fmt.Printf("✓ Certificate 2 still valid: %s\n", retrieved2.Certificate.Subject.CommonName)

	retrieved3, err := client.GetCertificate(ctx, serial3)
	if err != nil {
		log.Fatalf("Failed to retrieve certificate 3: %v", err)
	}
	fmt.Printf("✓ Certificate 3 still valid: %s\n", retrieved3.Certificate.Subject.CommonName)

	// Step 4: Revoke certificate 2 using alternative method
	fmt.Println("\n=== Step 4: Revoking Certificate 2 by Serial ===")

	err = client.RevokeCertificate(ctx, serial2)
	if err != nil {
		log.Fatalf("Failed to revoke certificate 2: %v", err)
	}

	fmt.Printf("✓ Certificate revoked by serial: %s\n", serial2)

	// Step 5: Summary
	fmt.Println("\n=== Revocation Summary ===")
	fmt.Printf("  Total issued: 3\n")
	fmt.Printf("  Revoked: 2 (%s, %s)\n", serial1, serial2)
	fmt.Printf("  Active: 1 (%s)\n", serial3)

	fmt.Println("\n✓ Certificate revocation workflow completed!")

	fmt.Println("\nRevocation Use Cases:")
	fmt.Println("  1. Security Incidents:")
	fmt.Println("     • Compromised private key")
	fmt.Println("     • Unauthorized certificate issuance")
	fmt.Println("     • Certificate mis-issuance")

	fmt.Println("\n  2. Operational Changes:")
	fmt.Println("     • Server decommissioning")
	fmt.Println("     • Service migration")
	fmt.Println("     • Certificate replacement")

	fmt.Println("\n  3. Personnel Changes:")
	fmt.Println("     • Employee termination")
	fmt.Println("     • Role changes")
	fmt.Println("     • Access revocation")

	fmt.Println("\nBest Practices:")
	fmt.Println("  ✓ Maintain Certificate Revocation List (CRL)")
	fmt.Println("  ✓ Implement OCSP for real-time validation")
	fmt.Println("  ✓ Document revocation reasons")
	fmt.Println("  ✓ Notify affected systems promptly")
	fmt.Println("  ✓ Monitor for revoked certificate usage")
	fmt.Println("  ✓ Have incident response procedures ready")

	fmt.Println("\nNext Steps:")
	fmt.Println("  • Configure CRL distribution points")
	fmt.Println("  • Set up OCSP responder")
	fmt.Println("  • Implement automated revocation checks")
	fmt.Println("  • Create revocation notification system")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
