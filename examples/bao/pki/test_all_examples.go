//go:build integration

// Test runner for all bao examples
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/jasoet/gopki/bao/testcontainer"
	"github.com/openbao/openbao/api/v2"
)

type ExampleTest struct {
	Category string
	Name     string
	Path     string
}

var examples = []ExampleTest{
	// 01-basic
	{"01-basic", "connect", "01-basic/connect/main.go"},
	{"01-basic", "root-ca", "01-basic/root-ca/main.go"},
	{"01-basic", "generate-key", "01-basic/generate-key/main.go"},

	// 02-certificates
	{"02-certificates", "issue-certificate", "02-certificates/issue-certificate/main.go"},
	{"02-certificates", "sign-csr", "02-certificates/sign-csr/main.go"},
	{"02-certificates", "intermediate-ca", "02-certificates/intermediate-ca/main.go"},

	// 03-key-management
	{"03-key-management", "import-key", "03-key-management/import-key/main.go"},
	{"03-key-management", "export-key", "03-key-management/export-key/main.go"},
	{"03-key-management", "key-rotation", "03-key-management/key-rotation/main.go"},

	// 04-roles
	{"04-roles", "create-web-server-role", "04-roles/create-web-server-role/main.go"},
	{"04-roles", "create-client-role", "04-roles/create-client-role/main.go"},
	{"04-roles", "update-role", "04-roles/update-role/main.go"},

	// 05-certificate-ops
	{"05-certificate-ops", "revoke-certificate", "05-certificate-ops/revoke-certificate/main.go"},
	{"05-certificate-ops", "get-certificate", "05-certificate-ops/get-certificate/main.go"},
	{"05-certificate-ops", "list-certificates", "05-certificate-ops/list-certificates/main.go"},

	// 06-workflows
	{"06-workflows", "web-server-tls", "06-workflows/web-server-tls/main.go"},
	{"06-workflows", "microservices-mtls", "06-workflows/microservices-mtls/main.go"},
	{"06-workflows", "cert-renewal", "06-workflows/cert-renewal/main.go"},
	{"06-workflows", "hybrid-gopki-bao", "06-workflows/hybrid-gopki-bao/main.go"},

	// 07-advanced
	{"07-advanced", "multi-issuer", "07-advanced/multi-issuer/main.go"},
	{"07-advanced", "certificate-chain", "07-advanced/certificate-chain/main.go"},
	{"07-advanced", "production-ready", "07-advanced/production-ready/main.go"},
}

func main() {
	fmt.Println("=== OpenBao Examples Integration Test ===")

	// Start OpenBao container
	fmt.Println("Starting OpenBao testcontainer...")
	ctx := context.Background()

	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		log.Fatalf("Failed to start OpenBao container: %v", err)
	}
	defer container.Terminate(ctx)

	fmt.Printf("✓ OpenBao running at: %s\n", container.Address)
	fmt.Printf("✓ Token: %s\n\n", container.Token)

	// Enable PKI secrets engine using API
	fmt.Println("Enabling PKI secrets engine...")
	apiConfig := api.DefaultConfig()
	apiConfig.Address = container.Address
	apiClient, err := api.NewClient(apiConfig)
	if err != nil {
		log.Fatalf("Failed to create API client: %v", err)
	}
	apiClient.SetToken(container.Token)

	err = apiClient.Sys().Mount("pki", &api.MountInput{
		Type:        "pki",
		Description: "PKI Secrets Engine",
		Config: api.MountConfigInput{
			MaxLeaseTTL: "87600h",
		},
	})
	if err != nil && err.Error() != "existing mount at pki/" {
		log.Printf("Warning: Failed to enable PKI (might already be enabled): %v", err)
	}
	fmt.Println("✓ PKI secrets engine enabled")

	// Set environment variables for examples
	os.Setenv("BAO_ADDR", container.Address)
	os.Setenv("BAO_TOKEN", container.Token)

	// Run each example
	passed := 0
	failed := 0
	var failedTests []string

	for i, example := range examples {
		fmt.Printf("[%2d/%2d] Testing %s/%s...\n", i+1, len(examples), example.Category, example.Name)

		examplePath := filepath.Join("examples", "bao", "pki", example.Path)

		// Run the example with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "go", "run", "-tags", "example", examplePath)
		cmd.Env = append(os.Environ(),
			"BAO_ADDR="+container.Address,
			"BAO_TOKEN="+container.Token,
		)

		output, err := cmd.CombinedOutput()

		if err != nil {
			failed++
			failedTests = append(failedTests, fmt.Sprintf("%s/%s", example.Category, example.Name))
			fmt.Printf("  ✗ FAILED: %v\n", err)
			if len(output) > 0 {
				fmt.Printf("  Output: %s\n", string(output))
			}
		} else {
			passed++
			fmt.Printf("  ✓ PASSED\n")
		}

		// Small delay between tests
		time.Sleep(1 * time.Second)
	}

	// Summary
	fmt.Println("\n=== Test Summary ===")
	fmt.Printf("Total: %d\n", len(examples))
	fmt.Printf("Passed: %d ✓\n", passed)
	fmt.Printf("Failed: %d ✗\n", failed)

	if failed > 0 {
		fmt.Println("\nFailed tests:")
		for _, test := range failedTests {
			fmt.Printf("  - %s\n", test)
		}
		os.Exit(1)
	}

	fmt.Println("\n✓ All examples passed!")
}
