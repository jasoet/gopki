//go:build integration

// Test runner for all transit examples
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
	Name string
	Path string
}

var examples = []ExampleTest{
	{"simple_encryption", "simple_encryption/main.go"},
	{"batch_operations", "batch_operations/main.go"},
	{"signing", "signing/main.go"},
}

func main() {
	fmt.Println("=== OpenBao Transit Examples Integration Test ===")

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

	// Enable Transit secrets engine using API
	fmt.Println("Enabling Transit secrets engine...")
	apiConfig := api.DefaultConfig()
	apiConfig.Address = container.Address
	apiClient, err := api.NewClient(apiConfig)
	if err != nil {
		log.Fatalf("Failed to create API client: %v", err)
	}
	apiClient.SetToken(container.Token)

	err = apiClient.Sys().Mount("transit", &api.MountInput{
		Type:        "transit",
		Description: "Transit Secrets Engine",
	})
	if err != nil && err.Error() != "existing mount at transit/" {
		log.Printf("Warning: Failed to enable Transit (might already be enabled): %v", err)
	}
	fmt.Println("✓ Transit secrets engine enabled")

	// Set environment variables for examples
	os.Setenv("OPENBAO_ADDR", container.Address)
	os.Setenv("OPENBAO_TOKEN", container.Token)

	// Run each example
	passed := 0
	failed := 0
	var failedTests []string

	for i, example := range examples {
		fmt.Printf("[%d/%d] Testing %s...\n", i+1, len(examples), example.Name)

		examplePath := filepath.Join("examples", "bao", "transit", example.Path)

		// Run the example with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "go", "run", examplePath)
		cmd.Env = append(os.Environ(),
			"OPENBAO_ADDR="+container.Address,
			"OPENBAO_TOKEN="+container.Token,
		)

		output, err := cmd.CombinedOutput()

		if err != nil {
			failed++
			failedTests = append(failedTests, example.Name)
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
