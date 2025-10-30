//go:build integration

package transit_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/jasoet/gopki/bao/transit"
)

// TestIntegration_Hash tests basic hash operation.
func TestIntegration_Hash(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	// Hash some data
	input := base64.StdEncoding.EncodeToString([]byte("hello world"))

	result, err := client.Hash(ctx, input, nil)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if result.Sum == "" {
		t.Error("Hash() returned empty sum")
	}

	// Default should be SHA2-256, verify it's a valid hex string
	if len(result.Sum) != 64 { // SHA2-256 hex is 64 characters
		t.Errorf("Hash sum length = %d, expected 64 for SHA2-256 hex", len(result.Sum))
	}
}

// TestIntegration_HashAlgorithms tests different hash algorithms.
func TestIntegration_HashAlgorithms(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	input := base64.StdEncoding.EncodeToString([]byte("test data"))

	tests := []struct {
		name      string
		algorithm transit.HashAlgorithm
		hexLength int // Expected hex string length
	}{
		{"SHA2-256", transit.HashSHA2_256, 64},
		{"SHA2-384", transit.HashSHA2_384, 96},
		{"SHA2-512", transit.HashSHA2_512, 128},
		{"SHA3-256", transit.HashSHA3_256, 64},
		{"SHA3-384", transit.HashSHA3_384, 96},
		{"SHA3-512", transit.HashSHA3_512, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.Hash(ctx, input, &transit.HashOptions{
				Algorithm: tt.algorithm,
			})
			if err != nil {
				t.Fatalf("Hash() with %s error = %v", tt.algorithm, err)
			}

			if result.Sum == "" {
				t.Errorf("Hash() with %s returned empty sum", tt.algorithm)
			}

			// Verify expected length (default format is hex)
			if len(result.Sum) != tt.hexLength {
				t.Errorf("Hash sum length = %d, want %d for %s", len(result.Sum), tt.hexLength, tt.algorithm)
			}
		})
	}
}

// TestIntegration_HashFormats tests different output formats.
func TestIntegration_HashFormats(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	input := base64.StdEncoding.EncodeToString([]byte("test data"))

	tests := []struct {
		name   string
		format string
	}{
		{"Hex", "hex"},
		{"Base64", "base64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.Hash(ctx, input, &transit.HashOptions{
				Algorithm: transit.HashSHA2_256,
				Format:    tt.format,
			})
			if err != nil {
				t.Fatalf("Hash() with format %s error = %v", tt.format, err)
			}

			if result.Sum == "" {
				t.Errorf("Hash() with format %s returned empty sum", tt.format)
			}

			// Basic validation based on format
			if tt.format == "hex" && len(result.Sum) != 64 {
				t.Errorf("Hex format sum length = %d, want 64", len(result.Sum))
			}
			if tt.format == "base64" && len(result.Sum) < 40 {
				t.Errorf("Base64 format sum length = %d, seems too short", len(result.Sum))
			}
		})
	}
}

// TestIntegration_HashConsistency tests that hashing the same data produces the same result.
func TestIntegration_HashConsistency(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	input := base64.StdEncoding.EncodeToString([]byte("consistent data"))

	// Hash the same data 3 times
	results := make([]string, 3)
	for i := 0; i < 3; i++ {
		result, err := client.Hash(ctx, input, &transit.HashOptions{
			Algorithm: transit.HashSHA2_256,
		})
		if err != nil {
			t.Fatalf("Hash() iteration %d error = %v", i, err)
		}
		results[i] = result.Sum
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		if results[0] != results[i] {
			t.Errorf("Hash iteration %d = %s, want %s (inconsistent)", i, results[i], results[0])
		}
	}
}

// TestIntegration_HashDifferentData tests that different data produces different hashes.
func TestIntegration_HashDifferentData(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	data1 := base64.StdEncoding.EncodeToString([]byte("data one"))
	data2 := base64.StdEncoding.EncodeToString([]byte("data two"))

	result1, err := client.Hash(ctx, data1, nil)
	if err != nil {
		t.Fatalf("Hash() data1 error = %v", err)
	}

	result2, err := client.Hash(ctx, data2, nil)
	if err != nil {
		t.Fatalf("Hash() data2 error = %v", err)
	}

	if result1.Sum == result2.Sum {
		t.Error("Different data produced same hash (collision or error)")
	}
}

// TestIntegration_HashWithAlgorithmWrapper tests the convenience wrapper.
func TestIntegration_HashWithAlgorithmWrapper(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	input := base64.StdEncoding.EncodeToString([]byte("wrapper test"))

	sum, err := client.HashWithAlgorithm(ctx, input, transit.HashSHA2_512)
	if err != nil {
		t.Fatalf("HashWithAlgorithm() error = %v", err)
	}

	if sum == "" {
		t.Error("HashWithAlgorithm() returned empty sum")
	}

	// SHA2-512 hex should be 128 characters
	if len(sum) != 128 {
		t.Errorf("SHA2-512 sum length = %d, want 128", len(sum))
	}
}

// TestIntegration_HashSmallData tests hashing very small data.
func TestIntegration_HashSmallData(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	// Single byte
	input := base64.StdEncoding.EncodeToString([]byte("a"))

	result, err := client.Hash(ctx, input, nil)
	if err != nil {
		t.Fatalf("Hash() small data error = %v", err)
	}

	if result.Sum == "" {
		t.Error("Hash() small data returned empty sum")
	}

	// Verify it's a valid SHA2-256 hex hash
	if len(result.Sum) != 64 {
		t.Errorf("Hash sum length = %d, want 64", len(result.Sum))
	}
}
