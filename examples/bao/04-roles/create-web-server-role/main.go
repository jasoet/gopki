//go:build example

// Package main demonstrates how to create a web server role in OpenBao.
//
// This example shows how to:
// - Create a root CA for web server certificates
// - Configure a role for web server certificates
// - Set appropriate key usage flags for TLS
// - Configure domain restrictions
// - Issue web server certificates
//
// Web server roles are used for:
// - HTTPS/TLS server authentication
// - Web applications and APIs
// - Load balancers and proxies
// - Microservices with TLS termination
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

	// Step 1: Create root CA for web servers
	fmt.Println("Creating root CA for web servers...")
	caResp, err := client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:          "internal",
		CommonName:    "Web Server Root CA",
		Organization:  []string{"Example Corp"},
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

	// Step 2: Create web server role
	fmt.Println("\nCreating web server role...")
	role, err := issuer.CreateRole(ctx, "web-server", &pki.RoleOptions{
		// Domain restrictions
		AllowedDomains:            []string{"example.com", "example.org"},
		AllowSubdomains:           true,
		AllowBareDomains:          true,
		AllowLocalhost:            false,
		AllowIPSANs:               true,  // Allow IP addresses in SANs
		AllowWildcardCertificates: false, // Disable wildcard certs for security

		// Certificate validity
		TTL:    "720h",  // 30 days (recommended for auto-renewal)
		MaxTTL: "8760h", // 1 year maximum

		// Key constraints
		KeyType: "rsa",
		KeyBits: 2048,

		// Key usage flags (critical for TLS servers)
		ServerFlag:          true,  // Enable TLS Server Authentication
		ClientFlag:          false, // Disable client authentication
		CodeSigningFlag:     false,
		EmailProtectionFlag: false,

		// Additional constraints
		RequireCN:        true,
		EnforceHostnames: true,
		AllowAnyName:     false,

		// Subject information defaults
		Organization:     []string{"Example Corp"},
		OrganizationUnit: []string{"Web Services"},
		Country:          []string{"US"},
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Println("✓ Web server role created")

	// Step 3: Display role configuration
	opts := role.Options()
	fmt.Println("\n✓ Role Configuration:")
	fmt.Printf("  Role Name: web-server\n")
	fmt.Printf("  Allowed Domains: %v\n", opts.AllowedDomains)
	fmt.Printf("  Allow Subdomains: %v\n", opts.AllowSubdomains)
	fmt.Printf("  TTL: %s\n", opts.TTL)
	fmt.Printf("  Max TTL: %s\n", opts.MaxTTL)
	fmt.Printf("  Key Type: %s\n", opts.KeyType)
	fmt.Printf("  Key Bits: %d\n", opts.KeyBits)
	fmt.Printf("  Server Flag: %v\n", opts.ServerFlag)
	fmt.Printf("  Client Flag: %v\n", opts.ClientFlag)

	// Step 4: Issue test certificates
	fmt.Println("\n=== Issuing Test Certificates ===")

	// Example 1: Web server certificate
	fmt.Println("\n1. Issuing certificate for web.example.com...")
	cert1, err := client.GenerateRSACertificate(ctx, "web-server",
		&pki.GenerateCertificateOptions{
			CommonName: "web.example.com",
			AltNames:   []string{"www.example.com"},
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue web certificate: %v", err)
	}
	fmt.Printf("✓ Certificate issued: %s\n", cert1.CertificateInfo().SerialNumber)
	fmt.Printf("  Subject: %s\n", cert1.Certificate().Certificate.Subject.CommonName)
	fmt.Printf("  SANs: %v\n", cert1.Certificate().Certificate.DNSNames)

	// Example 2: API server certificate
	fmt.Println("\n2. Issuing certificate for api.example.com...")
	cert2, err := client.GenerateRSACertificate(ctx, "web-server",
		&pki.GenerateCertificateOptions{
			CommonName: "api.example.com",
			AltNames:   []string{"api-v1.example.com", "api-v2.example.com"},
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue API certificate: %v", err)
	}
	fmt.Printf("✓ Certificate issued: %s\n", cert2.CertificateInfo().SerialNumber)
	fmt.Printf("  Subject: %s\n", cert2.Certificate().Certificate.Subject.CommonName)

	// Example 3: Certificate with IP SAN
	fmt.Println("\n3. Issuing certificate with IP address...")
	cert3, err := client.GenerateRSACertificate(ctx, "web-server",
		&pki.GenerateCertificateOptions{
			CommonName: "server.example.com",
			IPSANs:     []string{"192.168.1.100"},
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate with IP: %v", err)
	}
	fmt.Printf("✓ Certificate issued: %s\n", cert3.CertificateInfo().SerialNumber)
	fmt.Printf("  Subject: %s\n", cert3.Certificate().Certificate.Subject.CommonName)
	fmt.Printf("  IP SANs: %v\n", cert3.Certificate().Certificate.IPAddresses)

	// Summary
	fmt.Println("\n✓ Web server role workflow completed!")

	fmt.Println("\nRole Use Cases:")
	fmt.Println("  • HTTPS web servers (Apache, Nginx)")
	fmt.Println("  • REST APIs and microservices")
	fmt.Println("  • Load balancers and reverse proxies")
	fmt.Println("  • Application servers (Tomcat, IIS)")

	fmt.Println("\nSecurity Best Practices:")
	fmt.Println("  ✓ Use short TTLs with automated renewal")
	fmt.Println("  ✓ Enable enforce_hostnames for validation")
	fmt.Println("  ✓ Restrict allowed_domains to your organization")
	fmt.Println("  ✓ Disable wildcard certificates in production")
	fmt.Println("  ✓ Use 2048-bit or higher RSA keys")
	fmt.Println("  ✓ Enable Server Authentication key usage only")

	fmt.Println("\nNext Steps:")
	fmt.Println("  - Configure TLS on your web server")
	fmt.Println("  - Set up automated certificate renewal")
	fmt.Println("  - Monitor certificate expiration")
	fmt.Println("  - Test TLS configuration (SSLLabs, testssl.sh)")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
