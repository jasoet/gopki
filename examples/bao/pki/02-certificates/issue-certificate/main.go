//go:build example

// Package main demonstrates how to issue a certificate using OpenBao.
//
// This example shows how to:
// - Create a CA and role for certificate issuance
// - Issue a certificate with specific properties
// - Configure Subject Alternative Names (SANs)
// - Set certificate validity period (TTL)
//
// Prerequisites:
// - OpenBao server running
// - PKI secrets engine enabled
//
// Usage:
//
//	go run main.go
//
// Expected Output:
//
//	✓ Certificate issued successfully
//	Serial: ...
//	CN: app.example.com
//	SANs: [app.example.com www.example.com api.example.com]
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
	fmt.Println("Creating root CA...")
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
	fmt.Println("✓ Root CA created")

	// Step 2: Create a role for web servers
	// Roles define policies for certificate issuance
	fmt.Println("\nCreating role for web servers...")
	_, err = issuer.CreateRole(ctx, "web-server", &pki.RoleOptions{
		// Domain constraints
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,

		// Certificate validity
		TTL:    "720h",  // 30 days
		MaxTTL: "8760h", // 1 year maximum

		// Certificate usage
		ServerFlag: true, // Enable TLS Server Authentication

		// Key constraints
		KeyType: "rsa",
		KeyBits: 2048,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Println("✓ Role created")

	// Step 3: Issue a certificate
	fmt.Println("\nIssuing certificate for app.example.com...")
	certClient, err := client.GenerateRSACertificate(ctx, "web-server",
		&pki.GenerateCertificateOptions{
			CommonName: "app.example.com",

			// Subject Alternative Names (SANs)
			// These allow the certificate to be valid for multiple hostnames
			AltNames: []string{
				"www.example.com",
				"api.example.com",
			},

			// Certificate validity period
			TTL: "720h", // 30 days

			// Optional: IP SANs for certificates valid for IP addresses
			// IPSANs: []string{"192.168.1.100"},

			// Optional: Other subject information
			// Organization: []string{"Example Org"},
			// Country: []string{"US"},
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate: %v", err)
	}

	// Step 4: Get certificate information
	cert := certClient.Certificate()
	certInfo := certClient.CertificateInfo()

	fmt.Println("\n✓ Certificate issued successfully!")
	fmt.Printf("  Serial Number: %s\n", certInfo.SerialNumber)
	fmt.Printf("  Common Name: %s\n", cert.Certificate.Subject.CommonName)
	fmt.Printf("  DNS Names (SANs): %v\n", cert.Certificate.DNSNames)
	fmt.Printf("  Valid From: %s\n", cert.Certificate.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Valid Until: %s\n", cert.Certificate.NotAfter.Format(time.RFC3339))

	fmt.Println("\nNext steps:")
	fmt.Println("  - Use this certificate for TLS/HTTPS servers")
	fmt.Println("  - Export certificate and key for deployment")
	fmt.Println("  - Set up automated renewal before expiry")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
