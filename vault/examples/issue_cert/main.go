//go:build example
// +build example

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/vault"
)

func main() {
	fmt.Println("Vault Certificate Issuance Example")
	fmt.Println("===================================")
	fmt.Println()

	// TODO: Implement in Phase 1
	// This example will demonstrate:
	// 1. Connecting to Vault
	// 2. Generating local keypair
	// 3. Issuing certificate from Vault
	// 4. Using certificate with GoPKI modules

	fmt.Println("⚠️  This example is under development (Phase 1)")
	fmt.Println("See vault/README.md for implementation status")

	// Placeholder for future implementation:
	/*
		client, err := vault.NewClient(&vault.Config{
			Address: os.Getenv("VAULT_ADDR"),
			Token:   os.Getenv("VAULT_TOKEN"),
			Mount:   "pki",
		})
		if err != nil {
			log.Fatal(err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

		cert, err := client.IssueCertificateWithKeyPair(ctx, "web-server", keyPair, &vault.IssueOptions{
			CommonName: "app.example.com",
			TTL:        "720h",
		})
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Certificate issued: %s\n", cert.Certificate.Subject.CommonName)
	*/
}
