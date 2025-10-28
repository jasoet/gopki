//go:build example

// Package main demonstrates how to create a root Certificate Authority (CA) in OpenBao.
//
// This example shows how to:
// - Generate a root CA with specific parameters
// - Configure CA properties (key type, TTL, path length)
// - Retrieve and display CA information
// - Set CA as default issuer
//
// A root CA is the trust anchor for your PKI infrastructure.
//
// Prerequisites:
// - OpenBao server running
// - PKI secrets engine enabled
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Generate root CA
	fmt.Println("Generating root CA...")
	fmt.Println("  Common Name: Example Root CA")
	fmt.Println("  Key Type: RSA 4096")
	fmt.Println("  TTL: 10 years")

	caResp, err := client.GenerateRootCA(ctx, &bao.CAOptions{
		Type:          "internal", // Private key stays in OpenBao
		CommonName:    "Example Root CA",
		Organization:  []string{"Example Corp"},
		Country:       []string{"US"},
		KeyType:       "rsa",
		KeyBits:       4096,
		TTL:           "87600h", // 10 years
		MaxPathLength: -1,       // Unlimited intermediate CAs
		IssuerName:    "example-root-ca",
	})
	if err != nil {
		log.Fatalf("Failed to generate root CA: %v", err)
	}

	fmt.Println("\n✓ Root CA created successfully!")

	// Display CA information
	fmt.Println("\nCA Details:")
	fmt.Printf("  Issuer ID: %s\n", caResp.IssuerID)
	fmt.Printf("  Key ID: %s\n", caResp.KeyID)
	fmt.Printf("  Serial Number: %s\n", caResp.Certificate.Certificate.SerialNumber)
	fmt.Printf("  Subject: %s\n", caResp.Certificate.Certificate.Subject.CommonName)
	fmt.Printf("  Not Before: %s\n", caResp.Certificate.Certificate.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not After: %s\n", caResp.Certificate.Certificate.NotAfter.Format(time.RFC3339))

	// Get issuer client for more operations
	issuer, err := client.GetIssuer(ctx, caResp.IssuerID)
	if err != nil {
		log.Fatalf("Failed to get issuer: %v", err)
	}

	// Set as default issuer
	fmt.Println("\nSetting as default issuer...")
	err = issuer.SetAsDefault(ctx)
	if err != nil {
		log.Fatalf("Failed to set default issuer: %v", err)
	}
	fmt.Println("✓ Set as default issuer")

	// Verify default issuer
	defaultIssuerID, err := client.GetDefaultIssuer(ctx)
	if err != nil {
		log.Fatalf("Failed to get default issuer: %v", err)
	}
	fmt.Printf("✓ Default issuer verified: %s\n", defaultIssuerID)

	// Display certificate in PEM format
	fmt.Println("\n✓ Root CA Certificate (PEM):")
	fmt.Println(string(caResp.Certificate.ToPEM()))

	fmt.Println("\nNext steps:")
	fmt.Println("  1. Create a role for certificate issuance")
	fmt.Println("     See: examples/bao/04-roles/create-web-server-role")
	fmt.Println("  2. Issue certificates using the CA")
	fmt.Println("     See: examples/bao/02-certificates/issue-certificate")
	fmt.Println("  3. Create intermediate CAs")
	fmt.Println("     See: examples/bao/02-certificates/intermediate-ca")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
