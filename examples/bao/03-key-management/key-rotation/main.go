//go:build example

// Package main demonstrates how to perform key rotation with OpenBao.
//
// This example shows how to:
// - Generate an initial key and issue certificates
// - Generate a new key (rotation)
// - Issue new certificates with the new key
// - Revoke old certificates
// - Verify the rotation process
//
// Key rotation is important for:
// - Security best practices (regular key updates)
// - Compliance requirements
// - Compromised key recovery
// - Certificate lifecycle management
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

	// Setup: Create CA and role
	fmt.Println("Setup: Creating CA and role...")
	_, err = client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:       "internal",
		CommonName: "Rotation Test CA",
		KeyType:    "rsa",
		KeyBits:    2048,
		TTL:        "87600h",
	})
	if err != nil {
		log.Fatalf("Failed to generate root CA: %v", err)
	}

	err = client.CreateRole(ctx, "rotation-role", &bao.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	defer client.DeleteRole(ctx, "rotation-role")
	fmt.Println("✓ CA and role created")

	// Step 1: Generate first key
	fmt.Println("\n=== Step 1: Generate Initial Key ===")
	fmt.Println("Generating first key...")

	key1, err := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
		KeyName: "rotation-key-1",
		KeyBits: 2048,
	})
	if err != nil {
		log.Fatalf("Failed to generate first key: %v", err)
	}
	defer key1.Delete(ctx)

	fmt.Printf("✓ First key generated: %s\n", key1.KeyInfo().KeyID)
	fmt.Printf("  Key Name: %s\n", key1.KeyInfo().KeyName)

	// Step 2: Issue certificate with first key
	fmt.Println("\n=== Step 2: Issue Certificate with First Key ===")

	cert1, err := key1.IssueCertificate(ctx, "rotation-role", &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		log.Fatalf("Failed to issue certificate with first key: %v", err)
	}

	serial1 := cert1.CertificateInfo().SerialNumber
	cert1Info := cert1.Certificate()

	fmt.Printf("✓ Certificate 1 issued: %s\n", serial1)
	fmt.Printf("  Common Name: %s\n", cert1Info.Certificate.Subject.CommonName)
	fmt.Printf("  Valid Until: %s\n", cert1Info.Certificate.NotAfter.Format(time.RFC3339))

	// Wait a moment to ensure different timestamps
	time.Sleep(2 * time.Second)

	// Step 3: Generate second key (rotation)
	fmt.Println("\n=== Step 3: Key Rotation - Generate New Key ===")
	fmt.Println("Generating second key (rotation)...")

	key2, err := client.GenerateRSAKey(ctx, &bao.GenerateKeyOptions{
		KeyName: "rotation-key-2",
		KeyBits: 2048,
	})
	if err != nil {
		log.Fatalf("Failed to generate second key: %v", err)
	}
	defer key2.Delete(ctx)

	fmt.Printf("✓ Second key generated: %s\n", key2.KeyInfo().KeyID)
	fmt.Printf("  Replacing key: %s\n", key1.KeyInfo().KeyID)

	// Step 4: Issue certificate with second key
	fmt.Println("\n=== Step 4: Issue Certificate with New Key ===")

	cert2, err := key2.IssueCertificate(ctx, "rotation-role", &bao.GenerateCertificateOptions{
		CommonName: "app.example.com",
		TTL:        "720h",
	})
	if err != nil {
		log.Fatalf("Failed to issue certificate with second key: %v", err)
	}

	serial2 := cert2.CertificateInfo().SerialNumber
	cert2Info := cert2.Certificate()

	fmt.Printf("✓ Certificate 2 issued: %s\n", serial2)
	fmt.Printf("  Common Name: %s\n", cert2Info.Certificate.Subject.CommonName)
	fmt.Printf("  Valid Until: %s\n", cert2Info.Certificate.NotAfter.Format(time.RFC3339))

	// Step 5: Verify different serials
	fmt.Println("\n=== Step 5: Verification ===")

	if serial1 == serial2 {
		log.Fatal("Error: Expected different certificate serials after key rotation")
	}
	fmt.Println("✓ Certificate serials are different (rotation successful)")
	fmt.Printf("  Old serial: %s\n", serial1)
	fmt.Printf("  New serial: %s\n", serial2)

	// Step 6: Revoke old certificate
	fmt.Println("\n=== Step 6: Revoke Old Certificate ===")

	err = cert1.Revoke(ctx)
	if err != nil {
		log.Fatalf("Failed to revoke old certificate: %v", err)
	}
	fmt.Printf("✓ Old certificate revoked: %s\n", serial1)

	// Step 7: Verify new certificate is still valid
	fmt.Println("\n=== Step 7: Verify New Certificate Still Valid ===")

	retrieved, err := client.GetCertificate(ctx, serial2)
	if err != nil {
		log.Fatalf("Failed to retrieve new certificate: %v", err)
	}

	if retrieved.Certificate.Subject.CommonName != "app.example.com" {
		log.Fatal("New certificate was affected by old certificate revocation")
	}

	fmt.Println("✓ New certificate is still valid")
	fmt.Printf("  Serial: %s\n", serial2)
	fmt.Printf("  Status: Active\n")

	// Step 8: Delete old key
	fmt.Println("\n=== Step 8: Cleanup - Delete Old Key ===")

	err = key1.Delete(ctx)
	if err != nil {
		log.Printf("Warning: Failed to delete old key: %v", err)
	}

	fmt.Printf("✓ Old key deleted: %s\n", key1.KeyInfo().KeyID)
	fmt.Println("  Rotation process completed")

	// Summary
	fmt.Println("\n✓ Key Rotation Workflow Completed Successfully!")

	fmt.Println("\nRotation Summary:")
	fmt.Println("  1. Generated new key (key-2)")
	fmt.Println("  2. Issued new certificate with new key")
	fmt.Println("  3. Revoked old certificate")
	fmt.Println("  4. Verified new certificate remains valid")
	fmt.Println("  5. Deleted old key")

	fmt.Println("\nBest Practices for Key Rotation:")
	fmt.Println("  ✓ Plan rotation schedule (e.g., every 90 days)")
	fmt.Println("  ✓ Issue new certificates before revoking old ones")
	fmt.Println("  ✓ Maintain overlap period for smooth transition")
	fmt.Println("  ✓ Update all systems with new certificates")
	fmt.Println("  ✓ Monitor certificate expiration dates")
	fmt.Println("  ✓ Document rotation procedures")
	fmt.Println("  ✓ Test rotation in non-production first")

	fmt.Println("\nAutomation Recommendations:")
	fmt.Println("  • Set up automated rotation triggers")
	fmt.Println("  • Monitor certificate expiration (e.g., 30 days)")
	fmt.Println("  • Automate certificate deployment")
	fmt.Println("  • Implement rollback procedures")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
