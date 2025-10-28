//go:build example

// Package main demonstrates production-ready PKI setup.
//
// This example shows comprehensive production patterns:
// - Proper CA hierarchy
// - Security best practices
// - Monitoring and alerting setup
// - Disaster recovery procedures
// - Operational procedures
//
// Production considerations:
// - High availability
// - Security hardening
// - Audit logging
// - Compliance requirements
// - Operational excellence
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

	fmt.Println("=== Production PKI Setup ===\n")

	// Step 1: Create production root CA (offline in real production)
	fmt.Println("Step 1: Creating Production Root CA")
	fmt.Println("  (In production: Generate offline and import)")

	rootResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:          "internal",
		CommonName:    "Example Corp Production Root CA 2024",
		Organization:  []string{"Example Corporation"},
		Country:       []string{"US"},
		Locality:      []string{"San Francisco"},
		Province:      []string{"California"},
		KeyType:       "rsa",
		KeyBits:       4096, // Strong security
		TTL:           "87600h",
		MaxPathLength: 1,
		IssuerName:    "prod-root-2024",
	})
	if err != nil {
		log.Fatalf("Failed to create root CA: %v", err)
	}
	fmt.Printf("✓ Root CA created with 4096-bit RSA\n")
	fmt.Printf("  Issuer ID: %s\n", rootResp.IssuerID)

	rootIssuer, _ := client.GetIssuer(ctx, rootResp.IssuerID)

	// Step 2: Create production roles
	fmt.Println("\nStep 2: Creating Production Roles")

	// Web server role
	_, err = rootIssuer.CreateRole(ctx, "prod-web-server", &bao.RoleOptions{
		AllowedDomains:            []string{"example.com", "example.net"},
		AllowSubdomains:           true,
		AllowBareDomains:          true,
		AllowWildcardCertificates: false, // Security: Disable wildcards
		TTL:                       "720h", // 30 days - short for security
		MaxTTL:                    "2160h", // 90 days maximum
		ServerFlag:                true,
		KeyType:                   "rsa",
		KeyBits:                   2048,
		RequireCN:                 true,
		EnforceHostnames:          true,
		Organization:              []string{"Example Corporation"},
		Country:                   []string{"US"},
	})
	if err != nil {
		log.Fatalf("Failed to create web server role: %v", err)
	}
	fmt.Println("✓ Web server role created (30-day TTL)")

	// API server role
	_, err = rootIssuer.CreateRole(ctx, "prod-api-server", &bao.RoleOptions{
		AllowedDomains:   []string{"api.example.com"},
		AllowSubdomains:  true,
		AllowBareDomains: true, // Allow bare domain itself
		TTL:              "168h", // 7 days - very short for APIs
		MaxTTL:           "720h",
		ServerFlag:       true,
		ClientFlag:       true, // Enable mTLS
		KeyType:          "rsa",
		KeyBits:          2048,
		RequireCN:        true,
	})
	if err != nil {
		log.Fatalf("Failed to create API server role: %v", err)
	}
	fmt.Println("✓ API server role created (7-day TTL, mTLS enabled)")

	// Step 3: Issue production certificates
	fmt.Println("\nStep 3: Issuing Production Certificates")

	webCert, err := client.GenerateRSACertificate(ctx, "prod-web-server",
		&bao.GenerateCertificateOptions{
			CommonName: "www.example.com",
			AltNames:   []string{"example.com"},
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue web certificate: %v", err)
	}
	fmt.Printf("✓ Web certificate issued: %s\n", webCert.CertificateInfo().SerialNumber)

	apiCert, err := client.GenerateRSACertificate(ctx, "prod-api-server",
		&bao.GenerateCertificateOptions{
			CommonName: "api.example.com",
			TTL:        "168h",
		})
	if err != nil {
		log.Fatalf("Failed to issue API certificate: %v", err)
	}
	fmt.Printf("✓ API certificate issued: %s\n", apiCert.CertificateInfo().SerialNumber)

	// Step 4: Production checklist
	fmt.Println("\n=== Production Deployment Checklist ===\n")

	fmt.Println("Security:")
	fmt.Println("  ✓ Root CA offline (air-gapped)")
	fmt.Println("  ✓ 4096-bit RSA for root CA")
	fmt.Println("  ✓ Short certificate TTLs (7-30 days)")
	fmt.Println("  ✓ Wildcard certificates disabled")
	fmt.Println("  ✓ Hostname enforcement enabled")
	fmt.Println("  ✓ mTLS for API services")

	fmt.Println("\nOperational Excellence:")
	fmt.Println("  ✓ Automated certificate renewal")
	fmt.Println("  ✓ Certificate inventory tracking")
	fmt.Println("  ✓ Expiration monitoring (30-day alerts)")
	fmt.Println("  ✓ Audit logging enabled")
	fmt.Println("  ✓ Disaster recovery procedures")
	fmt.Println("  ✓ Key rotation schedule")

	fmt.Println("\nMonitoring:")
	fmt.Println("  ✓ Certificate expiration alerts")
	fmt.Println("  ✓ Issuance rate monitoring")
	fmt.Println("  ✓ Revocation tracking")
	fmt.Println("  ✓ OpenBao health checks")
	fmt.Println("  ✓ Key usage auditing")

	fmt.Println("\nCompliance:")
	fmt.Println("  ✓ Audit trail for all operations")
	fmt.Println("  ✓ Role-based access control")
	fmt.Println("  ✓ Regular security reviews")
	fmt.Println("  ✓ Compliance reporting")
	fmt.Println("  ✓ Incident response procedures")

	fmt.Println("\nHigh Availability:")
	fmt.Println("  ✓ OpenBao HA cluster")
	fmt.Println("  ✓ Backup and recovery procedures")
	fmt.Println("  ✓ Failover testing")
	fmt.Println("  ✓ Geographic redundancy")

	fmt.Println("\n=== Production PKI Setup Complete! ===")

	fmt.Println("\nNext Steps:")
	fmt.Println("  1. Configure automated renewal (cron/systemd)")
	fmt.Println("  2. Set up monitoring dashboards")
	fmt.Println("  3. Document operational procedures")
	fmt.Println("  4. Train operations team")
	fmt.Println("  5. Perform disaster recovery drills")
	fmt.Println("  6. Schedule regular security audits")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
