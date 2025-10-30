package transit

import (
	"context"
	"testing"
)

func TestRandomSourceConstants(t *testing.T) {
	tests := []struct {
		name  string
		value RandomSource
		want  string
	}{
		{"Platform", RandomSourcePlatform, "platform"},
		{"Seal", RandomSourceSeal, "seal"},
		{"All", RandomSourceAll, "all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.value) != tt.want {
				t.Errorf("RandomSource %s = %v, want %v", tt.name, tt.value, tt.want)
			}
		})
	}
}

func TestRandomFormatConstants(t *testing.T) {
	tests := []struct {
		name  string
		value RandomFormat
		want  string
	}{
		{"Base64", RandomFormatBase64, "base64"},
		{"Hex", RandomFormatHex, "hex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.value) != tt.want {
				t.Errorf("RandomFormat %s = %v, want %v", tt.name, tt.value, tt.want)
			}
		})
	}
}

func TestRandomOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *RandomOptions
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &RandomOptions{},
		},
		{
			name: "with source",
			opts: &RandomOptions{
				Source: RandomSourcePlatform,
			},
		},
		{
			name: "with format",
			opts: &RandomOptions{
				Format: RandomFormatHex,
			},
		},
		{
			name: "all options",
			opts: &RandomOptions{
				Source: RandomSourceAll,
				Format: RandomFormatBase64,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				_ = tt.opts.Source
				_ = tt.opts.Format
			}
		})
	}
}

func TestGenerateRandom_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test zero bytes
	_, err = client.GenerateRandom(ctx, 0, nil)
	if err == nil {
		t.Error("GenerateRandom() with zero bytes should return error")
	}

	// Test negative bytes
	_, err = client.GenerateRandom(ctx, -1, nil)
	if err == nil {
		t.Error("GenerateRandom() with negative bytes should return error")
	}

	// Test exceeds limit
	_, err = client.GenerateRandom(ctx, 2097152, nil) // 2MB
	if err == nil {
		t.Error("GenerateRandom() exceeding limit should return error")
	}
}

func TestRandomResult(t *testing.T) {
	result := &RandomResult{
		RandomBytes: "dGVzdCBkYXRh",
	}

	if result.RandomBytes != "dGVzdCBkYXRh" {
		t.Errorf("RandomBytes = %v, want dGVzdCBkYXRh", result.RandomBytes)
	}
}

func TestGenerateRandomBytes_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test invalid input
	_, err = client.GenerateRandomBytes(ctx, 0)
	if err == nil {
		t.Error("GenerateRandomBytes() with 0 bytes should return error")
	}
}

func TestGenerateRandomHex_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test invalid input
	_, err = client.GenerateRandomHex(ctx, -1)
	if err == nil {
		t.Error("GenerateRandomHex() with negative bytes should return error")
	}
}
