package transit

import (
	"context"
	"testing"
)

func TestHashOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *HashOptions
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &HashOptions{},
		},
		{
			name: "with algorithm",
			opts: &HashOptions{
				Algorithm: HashSHA2_256,
			},
		},
		{
			name: "with format",
			opts: &HashOptions{
				Format: "hex",
			},
		},
		{
			name: "all options",
			opts: &HashOptions{
				Algorithm: HashSHA2_512,
				Format:    "base64",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				_ = tt.opts.Algorithm
				_ = tt.opts.Format
			}
		})
	}
}

func TestHash_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test empty input (should fail validation before network call)
	_, err = client.Hash(ctx, "", nil)
	if err == nil {
		t.Error("Hash() with empty input should return error")
	}
}

func TestHashResult(t *testing.T) {
	result := &HashResult{
		Sum: "abc123def456",
	}

	if result.Sum != "abc123def456" {
		t.Errorf("Sum = %v, want abc123def456", result.Sum)
	}
}

func TestHashWithAlgorithm_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test empty input
	_, err = client.HashWithAlgorithm(ctx, "", HashSHA2_256)
	if err == nil {
		t.Error("HashWithAlgorithm() with empty input should return error")
	}
}
