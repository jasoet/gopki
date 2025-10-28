//go:build example

// Package main demonstrates how to create a client authentication role in OpenBao.
//
// This example shows how to:
// - Create a root CA for client authentication
// - Configure a role for client certificates
// - Set appropriate key usage for mutual TLS (mTLS)
// - Issue client certificates
//
// Client certificates are used for:
// - Mutual TLS (mTLS) authentication
// - API authentication
// - Service-to-service authentication
// - VPN client authentication
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: Create root CA for client authentication
	fmt.Println("Creating client authentication CA...")
	caResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:          "internal",
		CommonName:    "Client Authentication CA",
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
	fmt.Println("✓ Client authentication CA created")

	// Step 2: Create client authentication role
	fmt.Println("\nCreating client authentication role...")
	role, err := issuer.CreateRole(ctx, "client-auth", &bao.RoleOptions{
		// Domain restrictions (for client CN validation)
		AllowedDomains:    []string{"users.example.com", "services.example.com"},
		AllowSubdomains:   true,
		AllowBareDomains:  false,
		AllowLocalhost:    false,
		AllowIPSANs:       false, // Typically not needed for client certs

		// Certificate parameters
		TTL:            "720h",  // 30 days
		MaxTTL:         "8760h", // 1 year
		KeyType:        "rsa",
		KeyBits:        2048,

		// Key usage flags for client authentication
		ServerFlag:          false, // Disable server authentication
		ClientFlag:          true,  // Enable client authentication
		CodeSigningFlag:     false,
		EmailProtectionFlag: false,

		// Client-specific options
		RequireCN:        true,
		EnforceHostnames: true,
		AllowAnyName:     false,

		// Organization defaults
		Organization:       []string{"Example Corp"},
		OrganizationUnit: []string{"Engineering"},
		Country:            []string{"US"},
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Println("✓ Client authentication role created")

	// Step 3: Display role configuration
	fmt.Println("\n✓ Role Configuration:")
	fmt.Printf("  Role Name: client-auth\n")
	fmt.Printf("  Allowed Domains: %v\n", role.Options().AllowedDomains)
	fmt.Printf("  TTL: %s\n", role.Options().TTL)
	fmt.Printf("  Key Type: %s\n", role.Options().KeyType)
	fmt.Printf("  Client Flag: %v\n", role.Options().ClientFlag)
	fmt.Printf("  Server Flag: %v\n", role.Options().ServerFlag)

	// Step 4: Issue client certificates
	fmt.Println("\n=== Issuing Client Certificates ===")

	// User certificate
	userCert, err := client.GenerateRSACertificate(ctx, "client-auth",
		&bao.GenerateCertificateOptions{
			CommonName: "john.doe.users.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue user certificate: %v", err)
	}
	fmt.Println("✓ User certificate issued")
	fmt.Printf("  Subject: %s\n", userCert.Certificate().Certificate.Subject.CommonName)

	// Service certificate
	serviceCert, err := client.GenerateRSACertificate(ctx, "client-auth",
		&bao.GenerateCertificateOptions{
			CommonName: "api-gateway.services.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue service certificate: %v", err)
	}
	fmt.Println("✓ Service certificate issued")
	fmt.Printf("  Subject: %s\n", serviceCert.Certificate().Certificate.Subject.CommonName)

	// Step 5: Verify client authentication setup
	fmt.Println("\n✓ Client Authentication Setup:")
	fmt.Println("  1. Distribute CA certificate to servers")
	fmt.Println("  2. Configure servers to require client certificates")
	fmt.Println("  3. Issue client certificates to users/services")
	fmt.Println("  4. Configure clients to present certificates")

	// Step 6: Usage examples
	fmt.Println("\n✓ mTLS Usage Examples:")

	fmt.Println("\n  API Client (Go):")
	fmt.Println("    tlsConfig := &tls.Config{")
	fmt.Println("      Certificates: []tls.Certificate{clientCert},")
	fmt.Println("      RootCAs:      caCertPool,")
	fmt.Println("    }")
	fmt.Println("    client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}")

	fmt.Println("\n  API Server (Go):")
	fmt.Println("    tlsConfig := &tls.Config{")
	fmt.Println("      ClientAuth: tls.RequireAndVerifyClientCert,")
	fmt.Println("      ClientCAs:  caCertPool,")
	fmt.Println("    }")
	fmt.Println("    server := &http.Server{TLSConfig: tlsConfig}")

	fmt.Println("\n✓ Client authentication role workflow completed!")

	fmt.Println("\nUse Cases:")
	fmt.Println("  • Mutual TLS (mTLS) for microservices")
	fmt.Println("  • API authentication without passwords")
	fmt.Println("  • Service mesh identity")
	fmt.Println("  • VPN client authentication")
	fmt.Println("  • Database client authentication")

	fmt.Println("\nSecurity Benefits:")
	fmt.Println("  ✓ Strong cryptographic authentication")
	fmt.Println("  ✓ No password transmission over network")
	fmt.Println("  ✓ Mutual authentication (both parties verified)")
	fmt.Println("  ✓ Certificate-based authorization possible")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
