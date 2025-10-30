//go:build example

// Package main demonstrates how to sign a Certificate Signing Request (CSR) with OpenBao.
//
// This example shows how to:
// - Generate a key locally with GoPKI
// - Create a CSR with GoPKI
// - Sign the CSR with OpenBao CA
// - Verify the issued certificate
//
// This workflow is useful when:
// - Private keys must remain on local systems (security requirement)
// - Integrating with existing key management
// - Using external HSMs or key stores
//
// Prerequisites:
// - OpenBao server running
// - GoPKI modules installed
//
// Usage:
//
//	go run main.go
package main

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jasoet/gopki/bao/pki"
	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
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

	// Step 1: Create root CA in OpenBao
	fmt.Println("Creating root CA in OpenBao...")
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

	// Step 2: Generate key pair locally with GoPKI
	// This keeps the private key on your local system
	fmt.Println("\nGenerating RSA key pair locally...")
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Println("✓ Key pair generated locally")
	fmt.Println("  (Private key never leaves this system)")

	// Step 3: Create Certificate Signing Request (CSR) with GoPKI
	fmt.Println("\nCreating CSR...")
	csrReq := cert.CSRRequest{
		Subject: pkix.Name{
			CommonName:   "service.example.com",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
			Locality:     []string{"San Francisco"},
			Province:     []string{"California"},
		},
		DNSNames: []string{
			"service.example.com",
			"service-backup.example.com",
		},
		// Optional: Add IP addresses
		// IPAddresses: []net.IP{net.ParseIP("192.168.1.100")},
	}

	csr, err := cert.CreateCSR(keyPair, csrReq)
	if err != nil {
		log.Fatalf("Failed to create CSR: %v", err)
	}
	fmt.Println("✓ CSR created")

	// Step 4: Sign the CSR with OpenBao CA
	fmt.Println("\nSigning CSR with OpenBao CA...")
	certificate, err := issuer.SignCSR(ctx, csr, &pki.SignCertificateOptions{
		CommonName: "service.example.com",
		TTL:        "720h",
		// Optional: Add additional SANs if not in CSR
		// AltNames: []string{"extra.example.com"},
	})
	if err != nil {
		log.Fatalf("Failed to sign CSR: %v", err)
	}
	fmt.Println("✓ CSR signed successfully")

	// Step 5: Verify the certificate with GoPKI
	fmt.Println("\nVerifying certificate...")
	rootCert, err := issuer.Certificate()
	if err != nil {
		log.Fatalf("Failed to get root cert: %v", err)
	}

	err = cert.VerifyCertificate(certificate, rootCert)
	if err != nil {
		log.Fatalf("Certificate verification failed: %v", err)
	}
	fmt.Println("✓ Certificate verified")

	// Step 6: Display certificate information
	fmt.Println("\n✓ Certificate Details:")
	fmt.Printf("  Serial: %s\n", certificate.Certificate.SerialNumber)
	fmt.Printf("  Subject: %s\n", certificate.Certificate.Subject.CommonName)
	fmt.Printf("  Issuer: %s\n", certificate.Certificate.Issuer.CommonName)
	fmt.Printf("  DNS Names: %v\n", certificate.Certificate.DNSNames)
	fmt.Printf("  Valid From: %s\n", certificate.Certificate.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Valid Until: %s\n", certificate.Certificate.NotAfter.Format(time.RFC3339))

	fmt.Println("\n✓ Workflow completed successfully!")
	fmt.Println("\nSecurity Benefits:")
	fmt.Println("  ✓ Private key never transmitted to OpenBao")
	fmt.Println("  ✓ Private key remains on local system")
	fmt.Println("  ✓ Suitable for high-security environments")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
