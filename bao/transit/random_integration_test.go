//go:build integration

package transit_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/jasoet/gopki/bao/transit"
)

// TestIntegration_GenerateRandom tests basic random generation.
func TestIntegration_GenerateRandom(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	// Generate 32 random bytes
	result, err := client.GenerateRandom(ctx, 32, nil)
	if err != nil {
		t.Fatalf("GenerateRandom() error = %v", err)
	}

	if result.RandomBytes == "" {
		t.Error("GenerateRandom() returned empty bytes")
	}

	// Should be base64-encoded by default
	decoded, err := base64.StdEncoding.DecodeString(result.RandomBytes)
	if err != nil {
		t.Fatalf("RandomBytes not valid base64: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("Decoded bytes length = %d, want 32", len(decoded))
	}
}

// TestIntegration_GenerateRandomHex tests hex format.
func TestIntegration_GenerateRandomHex(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	// Generate 16 random bytes in hex format
	result, err := client.GenerateRandom(ctx, 16, &transit.RandomOptions{
		Format: transit.RandomFormatHex,
	})
	if err != nil {
		t.Fatalf("GenerateRandom() hex error = %v", err)
	}

	if result.RandomBytes == "" {
		t.Error("GenerateRandom() returned empty bytes")
	}

	// Should be hex-encoded
	decoded, err := hex.DecodeString(result.RandomBytes)
	if err != nil {
		t.Fatalf("RandomBytes not valid hex: %v", err)
	}

	if len(decoded) != 16 {
		t.Errorf("Decoded bytes length = %d, want 16", len(decoded))
	}
}

// TestIntegration_GenerateRandomSources tests different entropy sources.
func TestIntegration_GenerateRandomSources(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	tests := []struct {
		name   string
		source transit.RandomSource
	}{
		{"Platform", transit.RandomSourcePlatform},
		{"Seal", transit.RandomSourceSeal},
		{"All", transit.RandomSourceAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.GenerateRandom(ctx, 32, &transit.RandomOptions{
				Source: tt.source,
			})
			if err != nil {
				t.Fatalf("GenerateRandom() with source %s error = %v", tt.source, err)
			}

			if result.RandomBytes == "" {
				t.Errorf("GenerateRandom() with source %s returned empty bytes", tt.source)
			}

			// Verify base64 decoding
			decoded, err := base64.StdEncoding.DecodeString(result.RandomBytes)
			if err != nil {
				t.Fatalf("RandomBytes not valid base64: %v", err)
			}

			if len(decoded) != 32 {
				t.Errorf("Decoded bytes length = %d, want 32", len(decoded))
			}
		})
	}
}

// TestIntegration_GenerateRandomMultipleCalls tests that multiple calls produce different results.
func TestIntegration_GenerateRandomMultipleCalls(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	// Generate 5 random values
	results := make([]string, 5)
	for i := 0; i < 5; i++ {
		result, err := client.GenerateRandom(ctx, 32, nil)
		if err != nil {
			t.Fatalf("GenerateRandom() call %d error = %v", i, err)
		}
		results[i] = result.RandomBytes
	}

	// Verify all results are different
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[i] == results[j] {
				t.Errorf("Random call %d and %d produced same result (not random)", i, j)
			}
		}
	}
}

// TestIntegration_GenerateRandomBytes tests the convenience wrapper.
func TestIntegration_GenerateRandomBytes(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	randomBytes, err := client.GenerateRandomBytes(ctx, 32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes() error = %v", err)
	}

	if randomBytes == "" {
		t.Error("GenerateRandomBytes() returned empty string")
	}

	// Should be base64-encoded
	decoded, err := base64.StdEncoding.DecodeString(randomBytes)
	if err != nil {
		t.Fatalf("RandomBytes not valid base64: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("Decoded bytes length = %d, want 32", len(decoded))
	}
}

// TestIntegration_GenerateRandomHexWrapper tests the hex convenience wrapper.
func TestIntegration_GenerateRandomHexWrapper(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	randomHex, err := client.GenerateRandomHex(ctx, 16)
	if err != nil {
		t.Fatalf("GenerateRandomHex() error = %v", err)
	}

	if randomHex == "" {
		t.Error("GenerateRandomHex() returned empty string")
	}

	// Should be hex-encoded
	decoded, err := hex.DecodeString(randomHex)
	if err != nil {
		t.Fatalf("RandomHex not valid hex: %v", err)
	}

	if len(decoded) != 16 {
		t.Errorf("Decoded bytes length = %d, want 16", len(decoded))
	}
}

// TestIntegration_GenerateRandomVariousSizes tests different byte sizes.
func TestIntegration_GenerateRandomVariousSizes(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	sizes := []int{1, 16, 32, 64, 128, 256, 512, 1024}

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			result, err := client.GenerateRandom(ctx, size, nil)
			if err != nil {
				t.Fatalf("GenerateRandom(%d) error = %v", size, err)
			}

			decoded, err := base64.StdEncoding.DecodeString(result.RandomBytes)
			if err != nil {
				t.Fatalf("RandomBytes not valid base64: %v", err)
			}

			if len(decoded) != size {
				t.Errorf("Decoded bytes length = %d, want %d", len(decoded), size)
			}
		})
	}
}

// TestIntegration_GenerateRandomLarge tests generating larger amounts of random data.
func TestIntegration_GenerateRandomLarge(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	// Test 64KB
	result, err := client.GenerateRandom(ctx, 65536, nil)
	if err != nil {
		t.Fatalf("GenerateRandom(64KB) error = %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(result.RandomBytes)
	if err != nil {
		t.Fatalf("RandomBytes not valid base64: %v", err)
	}

	if len(decoded) != 65536 {
		t.Errorf("Decoded bytes length = %d, want 65536", len(decoded))
	}
}
