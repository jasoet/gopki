//go:build example

// Package main demonstrates how to update an existing role in OpenBao.
//
// This example shows how to:
// - Create an initial role with basic configuration
// - Update the role with new parameters
// - Verify the changes
// - Understand role update implications
//
// Common role updates:
// - Extending or reducing allowed domains
// - Adjusting TTL values
// - Changing key size requirements
// - Modifying key usage flags
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

	// Step 1: Create root CA
	fmt.Println("Setting up CA...")
	caResp, err := client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:          "internal",
		CommonName:    "Example Root CA",
		KeyType:       "rsa",
		KeyBits:       2048,
		TTL:           "87600h",
		MaxPathLength: -1,
	})
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}

	issuer, err := client.GetIssuer(ctx, caResp.IssuerID)
	if err != nil {
		log.Fatalf("Failed to get issuer: %v", err)
	}
	fmt.Println("✓ CA created")

	// Step 2: Create initial role with basic configuration
	fmt.Println("\n=== Step 1: Creating Initial Role ===")
	initialRole, err := issuer.CreateRole(ctx, "web-server", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",  // 30 days
		MaxTTL:          "8760h", // 1 year
		KeyType:         "rsa",
		KeyBits:         2048,
		ServerFlag:      true,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}

	fmt.Println("✓ Initial role created")
	fmt.Println("\n  Initial Configuration:")
	fmt.Printf("    Allowed Domains: %v\n", initialRole.Options().AllowedDomains)
	fmt.Printf("    TTL: %s\n", initialRole.Options().TTL)
	fmt.Printf("    Key Bits: %d\n", initialRole.Options().KeyBits)
	fmt.Printf("    Client Flag: %v\n", initialRole.Options().ClientFlag)

	// Step 3: Issue certificate with initial role
	fmt.Println("\nIssuing certificate with initial role...")
	cert1, err := client.GenerateRSACertificate(ctx, "web-server",
		&pki.GenerateCertificateOptions{
			CommonName: "app.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate: %v", err)
	}
	fmt.Printf("✓ Certificate issued: %s\n", cert1.Certificate().Certificate.Subject.CommonName)

	// Wait a moment to demonstrate the change
	time.Sleep(2 * time.Second)

	// Step 4: Update role with new configuration
	fmt.Println("\n=== Step 2: Updating Role ===")
	fmt.Println("Updating role with new requirements...")

	roleClient, err := client.GetRole(ctx, "web-server")
	if err != nil {
		log.Fatalf("Failed to get role: %v", err)
	}

	err = roleClient.Update(ctx, &pki.RoleOptions{
		// Expanded domain list
		AllowedDomains:  []string{"example.com", "example.org", "example.net"},
		AllowSubdomains: true,

		// Reduced TTL for better security
		TTL:    "168h", // 7 days
		MaxTTL: "720h", // 30 days

		// Stronger key requirements
		KeyType: "rsa",
		KeyBits: 4096, // Increased from 2048

		// Added client authentication
		ServerFlag: true,
		ClientFlag: true, // Now supports mTLS

		// Additional restrictions
		AllowIPSANs:      true,
		RequireCN:        true,
		EnforceHostnames: true,
	})
	if err != nil {
		log.Fatalf("Failed to update role: %v", err)
	}

	// Get updated role
	updatedRole, err := client.GetRole(ctx, "web-server")
	if err != nil {
		log.Fatalf("Failed to get updated role: %v", err)
	}

	fmt.Println("✓ Role updated successfully")
	fmt.Println("\n  Updated Configuration:")
	fmt.Printf("    Allowed Domains: %v\n", updatedRole.Options().AllowedDomains)
	fmt.Printf("    TTL: %s\n", updatedRole.Options().TTL)
	fmt.Printf("    Key Bits: %d\n", updatedRole.Options().KeyBits)
	fmt.Printf("    Client Flag: %v\n", updatedRole.Options().ClientFlag)

	// Step 5: Compare configurations
	fmt.Println("\n=== Comparison ===")
	fmt.Println("  Changes:")
	fmt.Printf("    • Domains: %v → %v\n", initialRole.Options().AllowedDomains, updatedRole.Options().AllowedDomains)
	fmt.Printf("    • TTL: %s → %s\n", initialRole.Options().TTL, updatedRole.Options().TTL)
	fmt.Printf("    • Key Bits: %d → %d\n", initialRole.Options().KeyBits, updatedRole.Options().KeyBits)
	fmt.Printf("    • Client Auth: %v → %v\n", initialRole.Options().ClientFlag, updatedRole.Options().ClientFlag)

	// Step 6: Issue new certificate with updated role
	fmt.Println("\n=== Step 3: Using Updated Role ===")
	fmt.Println("Issuing certificate with updated role...")

	// Now we can use new domains
	cert2, err := client.GenerateRSACertificate(ctx, "web-server",
		&pki.GenerateCertificateOptions{
			CommonName: "api.example.org", // New domain!
			TTL:        "168h",            // New default TTL
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate: %v", err)
	}

	cert2Info := cert2.Certificate()
	fmt.Printf("✓ Certificate issued with new domain: %s\n", cert2Info.Certificate.Subject.CommonName)
	fmt.Printf("  Key size: %d bits\n", cert2Info.Certificate.PublicKey)

	// Step 7: Important notes about existing certificates
	fmt.Println("\n=== Important Notes ===")
	fmt.Println("  ✓ Role updates apply to NEW certificates only")
	fmt.Println("  ✓ Existing certificates remain valid with old parameters")
	fmt.Println("  ✓ Previously issued certificate still has 2048-bit key")
	fmt.Println("  ✓ New certificates will use 4096-bit key")

	// Step 8: Demonstrate rollback scenario
	fmt.Println("\n=== Step 4: Rollback Scenario ===")
	fmt.Println("Rolling back to more permissive settings...")

	err = roleClient.Update(ctx, &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		KeyType:         "rsa",
		KeyBits:         2048,
		ServerFlag:      true,
		ClientFlag:      false,
	})
	if err != nil {
		log.Fatalf("Failed to rollback role: %v", err)
	}
	fmt.Println("✓ Role reverted to original configuration")

	fmt.Println("\n✓ Role update workflow completed!")

	fmt.Println("\nCommon Update Scenarios:")
	fmt.Println("  1. Security Incident Response:")
	fmt.Println("     - Increase key size requirements")
	fmt.Println("     - Reduce TTL values")
	fmt.Println("     - Add domain restrictions")

	fmt.Println("\n  2. Feature Expansion:")
	fmt.Println("     - Add new allowed domains")
	fmt.Println("     - Enable client authentication")
	fmt.Println("     - Allow IP SANs")

	fmt.Println("\n  3. Policy Changes:")
	fmt.Println("     - Adjust TTL for compliance")
	fmt.Println("     - Change organizational defaults")
	fmt.Println("     - Update key usage flags")

	fmt.Println("\nBest Practices:")
	fmt.Println("  ✓ Document role changes with reasons")
	fmt.Println("  ✓ Test updates in non-production first")
	fmt.Println("  ✓ Notify teams before tightening restrictions")
	fmt.Println("  ✓ Plan certificate rotation after key size changes")
	fmt.Println("  ✓ Keep role configurations in version control")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
