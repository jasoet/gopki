package transit

import (
	"context"
	"testing"
)

func TestEncryptOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *EncryptOptions
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &EncryptOptions{},
		},
		{
			name: "with context",
			opts: &EncryptOptions{
				Context: "dGVzdC1jb250ZXh0", // base64: test-context
			},
		},
		{
			name: "with key version",
			opts: &EncryptOptions{
				KeyVersion: 2,
			},
		},
		{
			name: "with nonce",
			opts: &EncryptOptions{
				Nonce: "bm9uY2U=", // base64: nonce
			},
		},
		{
			name: "with type",
			opts: &EncryptOptions{
				Type: "hmac-sha256",
			},
		},
		{
			name: "with associated data",
			opts: &EncryptOptions{
				AssociatedData: "YXNzb2M=", // base64: assoc
			},
		},
		{
			name: "all options",
			opts: &EncryptOptions{
				Context:        "dGVzdA==",
				KeyVersion:     3,
				Nonce:          "bm9uY2U=",
				Type:           "hmac-sha512",
				AssociatedData: "YXNzb2M=",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that options can be created and accessed
			if tt.opts != nil {
				_ = tt.opts.Context
				_ = tt.opts.KeyVersion
				_ = tt.opts.Nonce
				_ = tt.opts.Type
				_ = tt.opts.AssociatedData
			}
		})
	}
}

func TestDecryptOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *DecryptOptions
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &DecryptOptions{},
		},
		{
			name: "with context",
			opts: &DecryptOptions{
				Context: "dGVzdC1jb250ZXh0",
			},
		},
		{
			name: "with nonce",
			opts: &DecryptOptions{
				Nonce: "bm9uY2U=",
			},
		},
		{
			name: "with associated data",
			opts: &DecryptOptions{
				AssociatedData: "YXNzb2M=",
			},
		},
		{
			name: "all options",
			opts: &DecryptOptions{
				Context:        "dGVzdA==",
				Nonce:          "bm9uY2U=",
				AssociatedData: "YXNzb2M=",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				_ = tt.opts.Context
				_ = tt.opts.Nonce
				_ = tt.opts.AssociatedData
			}
		})
	}
}

func TestEncrypt_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	tests := []struct {
		name      string
		keyName   string
		plaintext string
		wantErr   bool
	}{
		{
			name:      "empty key name",
			keyName:   "",
			plaintext: "dGVzdA==",
			wantErr:   true,
		},
		{
			name:      "empty plaintext",
			keyName:   "test-key",
			plaintext: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Encrypt(ctx, tt.keyName, tt.plaintext, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecrypt_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	tests := []struct {
		name       string
		keyName    string
		ciphertext string
		wantErr    bool
	}{
		{
			name:       "empty key name",
			keyName:    "",
			ciphertext: "vault:v1:abc",
			wantErr:    true,
		},
		{
			name:       "empty ciphertext",
			keyName:    "test-key",
			ciphertext: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Decrypt(ctx, tt.keyName, tt.ciphertext, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBatchEncryptItem(t *testing.T) {
	item := BatchEncryptItem{
		Plaintext:      "dGVzdA==",
		Context:        "Y29udGV4dA==",
		KeyVersion:     2,
		Nonce:          "bm9uY2U=",
		AssociatedData: "YXNzb2M=",
	}

	if item.Plaintext != "dGVzdA==" {
		t.Errorf("Plaintext = %v, want dGVzdA==", item.Plaintext)
	}
	if item.Context != "Y29udGV4dA==" {
		t.Errorf("Context = %v, want Y29udGV4dA==", item.Context)
	}
	if item.KeyVersion != 2 {
		t.Errorf("KeyVersion = %v, want 2", item.KeyVersion)
	}
	if item.Nonce != "bm9uY2U=" {
		t.Errorf("Nonce = %v, want bm9uY2U=", item.Nonce)
	}
	if item.AssociatedData != "YXNzb2M=" {
		t.Errorf("AssociatedData = %v, want YXNzb2M=", item.AssociatedData)
	}
}

func TestBatchDecryptItem(t *testing.T) {
	item := BatchDecryptItem{
		Ciphertext:     "vault:v1:abc",
		Context:        "Y29udGV4dA==",
		Nonce:          "bm9uY2U=",
		AssociatedData: "YXNzb2M=",
	}

	if item.Ciphertext != "vault:v1:abc" {
		t.Errorf("Ciphertext = %v, want vault:v1:abc", item.Ciphertext)
	}
	if item.Context != "Y29udGV4dA==" {
		t.Errorf("Context = %v, want Y29udGV4dA==", item.Context)
	}
	if item.Nonce != "bm9uY2U=" {
		t.Errorf("Nonce = %v, want bm9uY2U=", item.Nonce)
	}
	if item.AssociatedData != "YXNzb2M=" {
		t.Errorf("AssociatedData = %v, want YXNzb2M=", item.AssociatedData)
	}
}

func TestEncryptBatch_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	tests := []struct {
		name    string
		keyName string
		items   []BatchEncryptItem
		wantErr bool
	}{
		{
			name:    "empty key name",
			keyName: "",
			items: []BatchEncryptItem{
				{Plaintext: "dGVzdA=="},
			},
			wantErr: true,
		},
		{
			name:    "empty batch",
			keyName: "test-key",
			items:   []BatchEncryptItem{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.EncryptBatch(ctx, tt.keyName, tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptBatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecryptBatch_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	tests := []struct {
		name    string
		keyName string
		items   []BatchDecryptItem
		wantErr bool
	}{
		{
			name:    "empty key name",
			keyName: "",
			items: []BatchDecryptItem{
				{Ciphertext: "vault:v1:abc"},
			},
			wantErr: true,
		},
		{
			name:    "empty batch",
			keyName: "test-key",
			items:   []BatchDecryptItem{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.DecryptBatch(ctx, tt.keyName, tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptBatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestReEncrypt_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	tests := []struct {
		name       string
		keyName    string
		ciphertext string
		wantErr    bool
	}{
		{
			name:       "empty key name",
			keyName:    "",
			ciphertext: "vault:v1:abc",
			wantErr:    true,
		},
		{
			name:       "empty ciphertext",
			keyName:    "test-key",
			ciphertext: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.ReEncrypt(ctx, tt.keyName, tt.ciphertext, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReEncrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDataKeyOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *DataKeyOptions
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &DataKeyOptions{},
		},
		{
			name: "with context",
			opts: &DataKeyOptions{
				Context: "dGVzdA==",
			},
		},
		{
			name: "with key version",
			opts: &DataKeyOptions{
				KeyVersion: 2,
			},
		},
		{
			name: "with nonce",
			opts: &DataKeyOptions{
				Nonce: "bm9uY2U=",
			},
		},
		{
			name: "with bits",
			opts: &DataKeyOptions{
				Bits: 256,
			},
		},
		{
			name: "all options",
			opts: &DataKeyOptions{
				Context:    "dGVzdA==",
				KeyVersion: 3,
				Nonce:      "bm9uY2U=",
				Bits:       128,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				_ = tt.opts.Context
				_ = tt.opts.KeyVersion
				_ = tt.opts.Nonce
				_ = tt.opts.Bits
			}
		})
	}
}

func TestGenerateDataKey_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test empty key name
	_, err = client.GenerateDataKey(ctx, "", nil)
	if err == nil {
		t.Error("GenerateDataKey() with empty key name should return error")
	}
}

func TestGenerateWrappedDataKey_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test empty key name
	_, err = client.GenerateWrappedDataKey(ctx, "", nil)
	if err == nil {
		t.Error("GenerateWrappedDataKey() with empty key name should return error")
	}
}

func TestEncryptionResult(t *testing.T) {
	result := &EncryptionResult{
		Ciphertext: "vault:v2:abc123",
		KeyVersion: 2,
	}

	if result.Ciphertext != "vault:v2:abc123" {
		t.Errorf("Ciphertext = %v, want vault:v2:abc123", result.Ciphertext)
	}
	if result.KeyVersion != 2 {
		t.Errorf("KeyVersion = %v, want 2", result.KeyVersion)
	}
}

func TestDecryptionResult(t *testing.T) {
	result := &DecryptionResult{
		Plaintext: "dGVzdCBkYXRh",
	}

	if result.Plaintext != "dGVzdCBkYXRh" {
		t.Errorf("Plaintext = %v, want dGVzdCBkYXRh", result.Plaintext)
	}
}

func TestDataKeyResult(t *testing.T) {
	result := &DataKeyResult{
		Plaintext:  "cGxhaW50ZXh0",
		Ciphertext: "vault:v1:wrapped",
		KeyVersion: 1,
	}

	if result.Plaintext != "cGxhaW50ZXh0" {
		t.Errorf("Plaintext = %v, want cGxhaW50ZXh0", result.Plaintext)
	}
	if result.Ciphertext != "vault:v1:wrapped" {
		t.Errorf("Ciphertext = %v, want vault:v1:wrapped", result.Ciphertext)
	}
	if result.KeyVersion != 1 {
		t.Errorf("KeyVersion = %v, want 1", result.KeyVersion)
	}
}

func TestBatchEncryptResult(t *testing.T) {
	result := &BatchEncryptResult{
		Results: []EncryptionResult{
			{Ciphertext: "vault:v1:abc", KeyVersion: 1},
			{Ciphertext: "vault:v1:def", KeyVersion: 1},
		},
		Errors: []error{nil, nil},
	}

	if len(result.Results) != 2 {
		t.Errorf("Results length = %v, want 2", len(result.Results))
	}
	if len(result.Errors) != 2 {
		t.Errorf("Errors length = %v, want 2", len(result.Errors))
	}
	if result.Results[0].Ciphertext != "vault:v1:abc" {
		t.Errorf("Results[0].Ciphertext = %v, want vault:v1:abc", result.Results[0].Ciphertext)
	}
}

func TestBatchDecryptResult(t *testing.T) {
	result := &BatchDecryptResult{
		Results: []DecryptionResult{
			{Plaintext: "dGVzdDE="},
			{Plaintext: "dGVzdDI="},
		},
		Errors: []error{nil, nil},
	}

	if len(result.Results) != 2 {
		t.Errorf("Results length = %v, want 2", len(result.Results))
	}
	if len(result.Errors) != 2 {
		t.Errorf("Errors length = %v, want 2", len(result.Errors))
	}
	if result.Results[0].Plaintext != "dGVzdDE=" {
		t.Errorf("Results[0].Plaintext = %v, want dGVzdDE=", result.Results[0].Plaintext)
	}
}
