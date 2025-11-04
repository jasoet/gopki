//go:build example

// Package main demonstrates format conversion and file operations with bao/pki.
//
// This example shows how to:
// - Generate certificates with OpenBao
// - Convert between PEM and DER formats
// - Save certificates and keys to files with secure permissions
// - Export certificate and key bundles
// - Use the new convenience methods for gopki integration
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

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Step 1: Create CA in OpenBao
	fmt.Println("=== Step 1: Creating CA in OpenBao ===")
	caResp, err := client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:       "internal",
		CommonName: "Format Conversion Demo CA",
		KeyType:    "rsa",
		KeyBits:    2048,
		TTL:        "87600h",
	})
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}
	fmt.Printf("✓ CA created: %s\n", caResp.IssuerID)

	// Step 2: Get issuer and create role for certificate issuance
	fmt.Println("\n=== Step 2: Creating Role ===")
	issuer, err := client.GetIssuer(ctx, caResp.IssuerID)
	if err != nil {
		log.Fatalf("Failed to get issuer: %v", err)
	}

	role, err := issuer.CreateRole(ctx, "demo-role", &pki.RoleOptions{
		AllowedDomains:  []string{"example.com"},
		AllowSubdomains: true,
		TTL:             "720h",
		KeyType:         "rsa",
		KeyBits:         2048,
	})
	if err != nil {
		log.Fatalf("Failed to create role: %v", err)
	}
	fmt.Printf("✓ Role created: %s\n", role.Name())

	// Step 3: Generate certificate with key
	fmt.Println("\n=== Step 3: Generating Certificate ===")
	certClient, err := client.GenerateRSACertificate(ctx, "demo-role", &pki.GenerateCertificateOptions{
		CommonName: "app.example.com",
		AltNames:   []string{"www.app.example.com", "api.app.example.com"},
		TTL:        "720h",
	})
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}
	fmt.Printf("✓ Certificate generated: %s\n", certClient.Certificate().Certificate.Subject.CommonName)

	// Step 4: Convert to PEM format
	fmt.Println("\n=== Step 4: Converting to PEM Format ===")
	certPEM, err := certClient.ToPEM()
	if err != nil {
		log.Fatalf("Failed to convert certificate to PEM: %v", err)
	}
	fmt.Printf("✓ Certificate PEM (%d bytes)\n", len(certPEM))

	// Step 5: Convert to DER format
	fmt.Println("\n=== Step 5: Converting to DER Format ===")
	certDER, err := certClient.ToDER()
	if err != nil {
		log.Fatalf("Failed to convert certificate to DER: %v", err)
	}
	fmt.Printf("✓ Certificate DER (%d bytes)\n", len(certDER))

	// Step 6: Export certificate and key as PEM bundle
	fmt.Println("\n=== Step 6: Exporting PEM Bundle ===")
	certPEMBundle, keyPEM, err := certClient.ExportPEM()
	if err != nil {
		log.Fatalf("Failed to export PEM bundle: %v", err)
	}
	fmt.Printf("✓ Certificate PEM: %d bytes\n", len(certPEMBundle))
	fmt.Printf("✓ Private Key PEM: %d bytes\n", len(keyPEM))

	// Step 7: Save to files with secure permissions
	fmt.Println("\n=== Step 7: Saving to Files ===")

	// Create temp directory for files
	tmpDir, err := os.MkdirTemp("", "bao-pki-example-")
	if err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := tmpDir + "/certificate.pem"
	keyPath := tmpDir + "/private-key.pem"

	err = certClient.SaveToFiles(certPath, keyPath)
	if err != nil {
		log.Fatalf("Failed to save to files: %v", err)
	}

	// Verify file permissions
	certInfo, _ := os.Stat(certPath)
	keyInfo, _ := os.Stat(keyPath)

	fmt.Printf("✓ Certificate saved: %s (permissions: %v)\n", certPath, certInfo.Mode())
	fmt.Printf("✓ Private key saved: %s (permissions: %v)\n", keyPath, keyInfo.Mode())

	// Verify secure permissions on private key (should be 0600)
	if keyInfo.Mode().Perm() == 0600 {
		fmt.Println("✓ Private key has secure permissions (0600)")
	} else {
		fmt.Printf("⚠ Warning: Private key permissions are %v (expected 0600)\n", keyInfo.Mode().Perm())
	}

	// Step 8: Save just the certificate
	fmt.Println("\n=== Step 8: Saving Certificate Only ===")
	certOnlyPath := tmpDir + "/cert-only.pem"
	err = certClient.SaveCertificate(certOnlyPath)
	if err != nil {
		log.Fatalf("Failed to save certificate: %v", err)
	}
	fmt.Printf("✓ Certificate saved: %s\n", certOnlyPath)

	// Step 9: Parse saved certificate back
	fmt.Println("\n=== Step 9: Parsing Saved Certificate ===")
	savedCertData, err := os.ReadFile(certOnlyPath)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	parsedCert, err := pki.ParseCertificateFromPEM(savedCertData)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	fmt.Printf("✓ Certificate parsed: %s\n", parsedCert.Certificate.Subject.CommonName)
	fmt.Printf("  Serial Number: %s\n", parsedCert.Certificate.SerialNumber)
	fmt.Printf("  Valid Until: %s\n", parsedCert.Certificate.NotAfter)

	// Step 10: Demonstrate key operations
	fmt.Println("\n=== Step 10: Key Operations ===")
	keyClient, err := client.GenerateRSAKey(ctx, &pki.GenerateKeyOptions{
		KeyName: "demo-key",
		KeyBits: 2048,
	})
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Printf("✓ Key generated: %s\n", keyClient.KeyInfo().KeyID)

	// Save key pair to files
	privateKeyPath := tmpDir + "/demo-private.pem"
	publicKeyPath := tmpDir + "/demo-public.pem"

	err = keyClient.SaveKeyPairToFiles(privateKeyPath, publicKeyPath)
	if err != nil {
		log.Fatalf("Failed to save key pair: %v", err)
	}

	privInfo, _ := os.Stat(privateKeyPath)
	pubInfo, _ := os.Stat(publicKeyPath)

	fmt.Printf("✓ Private key saved: %s (permissions: %v)\n", privateKeyPath, privInfo.Mode())
	fmt.Printf("✓ Public key saved: %s (permissions: %v)\n", publicKeyPath, pubInfo.Mode())

	// Summary
	fmt.Println("\n=== Summary ===")
	fmt.Println("✓ Format Conversion Demo Completed!")
	fmt.Println("\nDemonstrated Features:")
	fmt.Println("  • Certificate generation with OpenBao")
	fmt.Println("  • PEM and DER format conversion")
	fmt.Println("  • Secure file saving (0600 for keys, 0644 for certs)")
	fmt.Println("  • Certificate and key export")
	fmt.Println("  • Key pair management")
	fmt.Println("  • Certificate parsing from files")

	fmt.Printf("\nAll files saved to: %s\n", tmpDir)
	fmt.Println("(Temporary directory will be cleaned up on exit)")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
