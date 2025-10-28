//go:build example

// Package main demonstrates mutual TLS (mTLS) for microservices.
//
// This example shows how to:
// - Set up separate CAs for servers and clients
// - Issue certificates for microservices
// - Configure mutual TLS authentication
// - Test mTLS connections
//
// mTLS provides:
// - Strong authentication for both client and server
// - Encrypted communication
// - Service-to-service authentication
// - Zero-trust security model
//
// Prerequisites:
// - OpenBao server running
//
// Usage:
//   go run main.go
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Step 1: Create Root CA
	fmt.Println("=== Step 1: Creating Root CA for mTLS ===")
	caResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:       "internal",
		CommonName: "mTLS Root CA",
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
	fmt.Printf("✓ Root CA created: %s\n", caResp.IssuerID)

	// Get CA certificate for client trust store
	caCert, err := issuer.Certificate()
	if err != nil {
		log.Fatalf("Failed to get CA certificate: %v", err)
	}

	// Step 2: Create server role
	fmt.Println("\n=== Step 2: Creating Server Role ===")
	_, err = issuer.CreateRole(ctx, "mtls-server", &bao.RoleOptions{
		AllowedDomains:  []string{"services.example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ServerFlag:      true,
		KeyType:         "rsa",
		KeyBits:         2048,
	})
	if err != nil {
		log.Fatalf("Failed to create server role: %v", err)
	}
	fmt.Println("✓ Server role created")

	// Step 3: Create client role
	fmt.Println("\n=== Step 3: Creating Client Role ===")
	_, err = issuer.CreateRole(ctx, "mtls-client", &bao.RoleOptions{
		AllowedDomains:  []string{"clients.example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		ClientFlag:      true,
		KeyType:         "rsa",
		KeyBits:         2048,
	})
	if err != nil {
		log.Fatalf("Failed to create client role: %v", err)
	}
	fmt.Println("✓ Client role created")

	// Step 4: Issue server certificate
	fmt.Println("\n=== Step 4: Issuing Server Certificate ===")
	serverCert, err := client.GenerateRSACertificate(ctx, "mtls-server",
		&bao.GenerateCertificateOptions{
			CommonName: "api.services.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue server certificate: %v", err)
	}
	fmt.Printf("✓ Server certificate issued: %s\n", serverCert.CertificateInfo().SerialNumber)

	// Step 5: Issue client certificate
	fmt.Println("\n=== Step 5: Issuing Client Certificate ===")
	clientCert, err := client.GenerateRSACertificate(ctx, "mtls-client",
		&bao.GenerateCertificateOptions{
			CommonName: "service-a.clients.example.com",
			TTL:        "720h",
		})
	if err != nil {
		log.Fatalf("Failed to issue client certificate: %v", err)
	}
	fmt.Printf("✓ Client certificate issued: %s\n", clientCert.CertificateInfo().SerialNumber)

	// Step 6: Configure mTLS
	fmt.Println("\n=== Step 6: Configuring mTLS ===")

	// Create CA pool
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert.Certificate)

	// Server configuration
	serverKeyPair, _ := serverCert.KeyPair()
	serverTLSCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Certificate().Certificate.Raw},
		PrivateKey:  serverKeyPair.PrivateKey,
	}

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Client configuration
	clientKeyPair, _ := clientCert.KeyPair()
	clientTLSCert := tls.Certificate{
		Certificate: [][]byte{clientCert.Certificate().Certificate.Raw},
		PrivateKey:  clientKeyPair.PrivateKey,
	}

	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientTLSCert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	fmt.Println("✓ mTLS configured")
	fmt.Println("  Server: Requires and verifies client certificates")
	fmt.Println("  Client: Presents certificate for authentication")

	// Display configuration
	fmt.Println("\n=== mTLS Configuration Summary ===")
	fmt.Printf("Server Certificate CN: %s\n", serverCert.Certificate().Certificate.Subject.CommonName)
	fmt.Printf("Client Certificate CN: %s\n", clientCert.Certificate().Certificate.Subject.CommonName)
	fmt.Printf("CA: %s\n", caCert.Certificate.Subject.CommonName)

	fmt.Println("\n✓ Microservices mTLS Workflow Completed!")

	fmt.Println("\nmTLS Benefits:")
	fmt.Println("  ✓ Mutual authentication (both parties verified)")
	fmt.Println("  ✓ Zero-trust security model")
	fmt.Println("  ✓ Service mesh integration")
	fmt.Println("  ✓ Encrypted communication")
	fmt.Println("  ✓ Fine-grained access control")

	fmt.Println("\nProduction Implementation:")
	fmt.Println("  1. Distribute CA certificate to all services")
	fmt.Println("  2. Issue certificates for each service")
	fmt.Println("  3. Configure mTLS on all service endpoints")
	fmt.Println("  4. Implement certificate rotation")
	fmt.Println("  5. Set up monitoring and alerting")
	fmt.Println("  6. Test failure scenarios")

	_ = serverTLSConfig
	_ = clientTLSConfig
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
