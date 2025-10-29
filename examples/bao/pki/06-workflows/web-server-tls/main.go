//go:build example

// Package main demonstrates a complete web server TLS setup workflow.
//
// This example shows the end-to-end process of:
// - Setting up a CA for web servers
// - Creating a role for TLS certificates
// - Issuing web server certificates
// - Configuring TLS with the certificates
// - Testing the TLS setup
//
// This workflow covers the complete lifecycle for deploying
// TLS certificates on production web servers.
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
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
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

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Step 1: Create CA for web servers
	fmt.Println("=== Step 1: Creating Web Server CA ===")
	caResp, err := client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:          "internal",
		CommonName:    "Web Server Root CA",
		Organization:  []string{"Example Corp"},
		Country:       []string{"US"},
		KeyType:       "rsa",
		KeyBits:       2048,
		TTL:           "87600h",
		MaxPathLength: -1,
	})
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}
	fmt.Printf("✓ Root CA created: %s\n", caResp.IssuerID)

	issuer, err := client.GetIssuer(ctx, caResp.IssuerID)
	if err != nil {
		log.Fatalf("Failed to get issuer: %v", err)
	}

	// Step 2: Create TLS role
	fmt.Println("\n=== Step 2: Creating TLS Server Role ===")
	_, err = issuer.CreateRole(ctx, "web-tls", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com", "localhost"},
		AllowSubdomains: true,
		AllowLocalhost:  true,
		AllowIPSANs:     true,   // Allow IP addresses in SANs
		TTL:             "720h", // 30 days
		MaxTTL:          "8760h",
		ServerFlag:      true,
		KeyType:         "rsa",
		KeyBits:         2048,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Println("✓ TLS role created")

	// Step 3: Issue web server certificate
	fmt.Println("\n=== Step 3: Issuing Web Server Certificate ===")
	certClient, err := client.GenerateRSACertificate(ctx, "web-tls",
		&pki.GenerateCertificateOptions{
			CommonName: "localhost",
			IPSANs:     []string{"127.0.0.1", "::1"}, // IP addresses go in IPSANs only
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue certificate: %v", err)
	}

	cert := certClient.Certificate()
	certInfo := certClient.CertificateInfo()

	fmt.Printf("✓ Certificate issued: %s\n", certInfo.SerialNumber)
	fmt.Printf("  CN: %s\n", cert.Certificate.Subject.CommonName)
	fmt.Printf("  SANs: %v\n", cert.Certificate.DNSNames)
	fmt.Printf("  Valid Until: %s\n", cert.Certificate.NotAfter.Format(time.RFC3339))

	// Step 4: Get key pair for TLS configuration
	fmt.Println("\n=== Step 4: Configuring TLS ===")

	keyPair, err := certClient.KeyPair()
	if err != nil {
		log.Fatalf("Failed to get key pair: %v", err)
	}

	// Create TLS certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Certificate.Raw},
		PrivateKey:  keyPair.PrivateKey,
	}

	fmt.Println("✓ TLS certificate configured")
	fmt.Println("  Certificate and private key ready for use")

	// Step 5: Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	fmt.Println("✓ TLS config created")
	fmt.Println("  Min TLS Version: 1.2")
	fmt.Println("  Cipher suites: ECDHE-RSA-AES-GCM")

	// Step 6: Start test HTTPS server
	fmt.Println("\n=== Step 5: Starting Test HTTPS Server ===")

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Secure Hello from GoPKI + OpenBao!\n")
		fmt.Fprintf(w, "Certificate CN: %s\n", cert.Certificate.Subject.CommonName)
		fmt.Fprintf(w, "Serial: %s\n", certInfo.SerialNumber)
	})

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	fmt.Println("✓ HTTPS server configured")
	fmt.Println("  Listening on: https://localhost:8443")
	fmt.Println("\nTo test the server, run:")
	fmt.Println("  curl --insecure https://localhost:8443")
	fmt.Println("\n(Server will run for 10 seconds as a demonstration)")

	// Run server in goroutine
	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for 10 seconds
	time.Sleep(10 * time.Second)

	// Shutdown server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)

	fmt.Println("\n✓ Web Server TLS Workflow Completed!")

	fmt.Println("\nProduction Deployment Steps:")
	fmt.Println("  1. Export certificate and private key")
	fmt.Println("  2. Install on web server (Nginx, Apache, etc.)")
	fmt.Println("  3. Configure web server TLS settings")
	fmt.Println("  4. Test TLS configuration (SSLLabs, testssl.sh)")
	fmt.Println("  5. Set up automated renewal before expiration")
	fmt.Println("  6. Monitor certificate expiration")

	fmt.Println("\nNext Steps:")
	fmt.Println("  • Configure automated certificate renewal")
	fmt.Println("  • Set up monitoring and alerting")
	fmt.Println("  • Implement certificate rotation procedures")
	fmt.Println("  • Test disaster recovery scenarios")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
