package transit

import (
	"context"
	"testing"
)

func TestSignOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *SignOptions
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &SignOptions{},
		},
		{
			name: "with key version",
			opts: &SignOptions{
				KeyVersion: 2,
			},
		},
		{
			name: "with hash algorithm",
			opts: &SignOptions{
				HashAlgorithm: HashSHA2_256,
			},
		},
		{
			name: "with context",
			opts: &SignOptions{
				Context: "dGVzdA==",
			},
		},
		{
			name: "with prehashed",
			opts: &SignOptions{
				Prehashed: true,
			},
		},
		{
			name: "with RSA signature algorithm",
			opts: &SignOptions{
				SignatureAlgorithm: SignatureAlgPSS,
			},
		},
		{
			name: "with ECDSA marshaling",
			opts: &SignOptions{
				MarshalingAlgorithm: MarshalingJWS,
			},
		},
		{
			name: "with salt length",
			opts: &SignOptions{
				SaltLength: "auto",
			},
		},
		{
			name: "all options",
			opts: &SignOptions{
				KeyVersion:          2,
				HashAlgorithm:       HashSHA2_512,
				Context:             "dGVzdA==",
				Prehashed:           true,
				SignatureAlgorithm:  SignatureAlgPKCS1v15,
				MarshalingAlgorithm: MarshalingASN1,
				SaltLength:          "hash",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				_ = tt.opts.KeyVersion
				_ = tt.opts.HashAlgorithm
				_ = tt.opts.Context
				_ = tt.opts.Prehashed
				_ = tt.opts.SignatureAlgorithm
				_ = tt.opts.MarshalingAlgorithm
				_ = tt.opts.SaltLength
			}
		})
	}
}

func TestVerifyOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *VerifyOptions
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &VerifyOptions{},
		},
		{
			name: "with hash algorithm",
			opts: &VerifyOptions{
				HashAlgorithm: HashSHA2_384,
			},
		},
		{
			name: "with context",
			opts: &VerifyOptions{
				Context: "dGVzdA==",
			},
		},
		{
			name: "all options",
			opts: &VerifyOptions{
				HashAlgorithm:       HashSHA3_512,
				Context:             "dGVzdA==",
				Prehashed:           true,
				SignatureAlgorithm:  SignatureAlgPSS,
				MarshalingAlgorithm: MarshalingJWS,
				SaltLength:          "auto",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				_ = tt.opts.HashAlgorithm
				_ = tt.opts.Context
				_ = tt.opts.Prehashed
				_ = tt.opts.SignatureAlgorithm
				_ = tt.opts.MarshalingAlgorithm
				_ = tt.opts.SaltLength
			}
		})
	}
}

func TestHMACOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *HMACOptions
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &HMACOptions{},
		},
		{
			name: "with key version",
			opts: &HMACOptions{
				KeyVersion: 3,
			},
		},
		{
			name: "with algorithm",
			opts: &HMACOptions{
				Algorithm: HashSHA3_256,
			},
		},
		{
			name: "all options",
			opts: &HMACOptions{
				KeyVersion: 2,
				Algorithm:  HashSHA2_512,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				_ = tt.opts.KeyVersion
				_ = tt.opts.Algorithm
			}
		})
	}
}

func TestHashAlgorithmConstants(t *testing.T) {
	tests := []struct {
		name  string
		value HashAlgorithm
		want  string
	}{
		{"SHA2-256", HashSHA2_256, "sha2-256"},
		{"SHA2-384", HashSHA2_384, "sha2-384"},
		{"SHA2-512", HashSHA2_512, "sha2-512"},
		{"SHA3-256", HashSHA3_256, "sha3-256"},
		{"SHA3-384", HashSHA3_384, "sha3-384"},
		{"SHA3-512", HashSHA3_512, "sha3-512"},
		{"None", HashNone, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.value) != tt.want {
				t.Errorf("HashAlgorithm %s = %v, want %v", tt.name, tt.value, tt.want)
			}
		})
	}
}

func TestSignatureAlgorithmConstants(t *testing.T) {
	tests := []struct {
		name  string
		value SignatureAlgorithm
		want  string
	}{
		{"PSS", SignatureAlgPSS, "pss"},
		{"PKCS1v15", SignatureAlgPKCS1v15, "pkcs1v15"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.value) != tt.want {
				t.Errorf("SignatureAlgorithm %s = %v, want %v", tt.name, tt.value, tt.want)
			}
		})
	}
}

func TestMarshalingAlgorithmConstants(t *testing.T) {
	tests := []struct {
		name  string
		value MarshalingAlgorithm
		want  string
	}{
		{"ASN1", MarshalingASN1, "asn1"},
		{"JWS", MarshalingJWS, "jws"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.value) != tt.want {
				t.Errorf("MarshalingAlgorithm %s = %v, want %v", tt.name, tt.value, tt.want)
			}
		})
	}
}

func TestSign_Validation(t *testing.T) {
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
		input   string
		wantErr bool
	}{
		{
			name:    "empty key name",
			keyName: "",
			input:   "dGVzdA==",
			wantErr: true,
		},
		{
			name:    "empty input",
			keyName: "test-key",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Sign(ctx, tt.keyName, tt.input, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerify_Validation(t *testing.T) {
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
		input     string
		signature string
		wantErr   bool
	}{
		{
			name:      "empty key name",
			keyName:   "",
			input:     "dGVzdA==",
			signature: "vault:v1:sig",
			wantErr:   true,
		},
		{
			name:      "empty input",
			keyName:   "test-key",
			input:     "",
			signature: "vault:v1:sig",
			wantErr:   true,
		},
		{
			name:      "empty signature",
			keyName:   "test-key",
			input:     "dGVzdA==",
			signature: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.Verify(ctx, tt.keyName, tt.input, tt.signature, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHMAC_Validation(t *testing.T) {
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
		input   string
		wantErr bool
	}{
		{
			name:    "empty key name",
			keyName: "",
			input:   "dGVzdA==",
			wantErr: true,
		},
		{
			name:    "empty input",
			keyName: "test-key",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.HMAC(ctx, tt.keyName, tt.input, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("HMAC() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyHMAC_Validation(t *testing.T) {
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
		input   string
		hmac    string
		wantErr bool
	}{
		{
			name:    "empty key name",
			keyName: "",
			input:   "dGVzdA==",
			hmac:    "vault:v1:hmac",
			wantErr: true,
		},
		{
			name:    "empty input",
			keyName: "test-key",
			input:   "",
			hmac:    "vault:v1:hmac",
			wantErr: true,
		},
		{
			name:    "empty hmac",
			keyName: "test-key",
			input:   "dGVzdA==",
			hmac:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.VerifyHMAC(ctx, tt.keyName, tt.input, tt.hmac, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyHMAC() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBatchSignItem(t *testing.T) {
	item := BatchSignItem{
		Input:               "dGVzdA==",
		Context:             "Y29udGV4dA==",
		KeyVersion:          2,
		HashAlgorithm:       "sha2-256",
		Prehashed:           true,
		SignatureAlgorithm:  "pss",
		MarshalingAlgorithm: "asn1",
		SaltLength:          "auto",
	}

	if item.Input != "dGVzdA==" {
		t.Errorf("Input = %v, want dGVzdA==", item.Input)
	}
	if item.Context != "Y29udGV4dA==" {
		t.Errorf("Context = %v, want Y29udGV4dA==", item.Context)
	}
	if item.KeyVersion != 2 {
		t.Errorf("KeyVersion = %v, want 2", item.KeyVersion)
	}
	if item.HashAlgorithm != "sha2-256" {
		t.Errorf("HashAlgorithm = %v, want sha2-256", item.HashAlgorithm)
	}
}

func TestBatchVerifyItem(t *testing.T) {
	item := BatchVerifyItem{
		Input:               "dGVzdA==",
		Signature:           "vault:v1:sig",
		HMAC:                "vault:v1:hmac",
		Context:             "Y29udGV4dA==",
		HashAlgorithm:       "sha2-512",
		Prehashed:           false,
		SignatureAlgorithm:  "pkcs1v15",
		MarshalingAlgorithm: "jws",
		SaltLength:          "hash",
	}

	if item.Input != "dGVzdA==" {
		t.Errorf("Input = %v, want dGVzdA==", item.Input)
	}
	if item.Signature != "vault:v1:sig" {
		t.Errorf("Signature = %v, want vault:v1:sig", item.Signature)
	}
	if item.HMAC != "vault:v1:hmac" {
		t.Errorf("HMAC = %v, want vault:v1:hmac", item.HMAC)
	}
}

func TestSignBatch_Validation(t *testing.T) {
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
		items   []BatchSignItem
		wantErr bool
	}{
		{
			name:    "empty key name",
			keyName: "",
			items: []BatchSignItem{
				{Input: "dGVzdA=="},
			},
			wantErr: true,
		},
		{
			name:    "empty batch",
			keyName: "test-key",
			items:   []BatchSignItem{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.SignBatch(ctx, tt.keyName, tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignBatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyBatch_Validation(t *testing.T) {
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
		items   []BatchVerifyItem
		wantErr bool
	}{
		{
			name:    "empty key name",
			keyName: "",
			items: []BatchVerifyItem{
				{Input: "dGVzdA==", Signature: "vault:v1:sig"},
			},
			wantErr: true,
		},
		{
			name:    "empty batch",
			keyName: "test-key",
			items:   []BatchVerifyItem{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.VerifyBatch(ctx, tt.keyName, tt.items)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyBatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignatureResult(t *testing.T) {
	result := &SignatureResult{
		Signature:  "vault:v1:sig123",
		KeyVersion: 1,
		PublicKey:  "-----BEGIN PUBLIC KEY-----",
	}

	if result.Signature != "vault:v1:sig123" {
		t.Errorf("Signature = %v, want vault:v1:sig123", result.Signature)
	}
	if result.KeyVersion != 1 {
		t.Errorf("KeyVersion = %v, want 1", result.KeyVersion)
	}
	if result.PublicKey != "-----BEGIN PUBLIC KEY-----" {
		t.Errorf("PublicKey = %v, want -----BEGIN PUBLIC KEY-----", result.PublicKey)
	}
}

func TestVerificationResult(t *testing.T) {
	result := &VerificationResult{
		Valid: true,
	}

	if !result.Valid {
		t.Error("Valid should be true")
	}
}

func TestHMACResult(t *testing.T) {
	result := &HMACResult{
		HMAC:       "vault:v1:hmac123",
		KeyVersion: 2,
	}

	if result.HMAC != "vault:v1:hmac123" {
		t.Errorf("HMAC = %v, want vault:v1:hmac123", result.HMAC)
	}
	if result.KeyVersion != 2 {
		t.Errorf("KeyVersion = %v, want 2", result.KeyVersion)
	}
}

func TestBatchSignResult(t *testing.T) {
	result := &BatchSignResult{
		Results: []SignatureResult{
			{Signature: "vault:v1:sig1", KeyVersion: 1},
			{Signature: "vault:v1:sig2", KeyVersion: 1},
		},
		Errors: []error{nil, nil},
	}

	if len(result.Results) != 2 {
		t.Errorf("Results length = %v, want 2", len(result.Results))
	}
	if len(result.Errors) != 2 {
		t.Errorf("Errors length = %v, want 2", len(result.Errors))
	}
}

func TestBatchVerifyResult(t *testing.T) {
	result := &BatchVerifyResult{
		Results: []VerificationResult{
			{Valid: true},
			{Valid: false},
		},
		Errors: []error{nil, nil},
	}

	if len(result.Results) != 2 {
		t.Errorf("Results length = %v, want 2", len(result.Results))
	}
	if !result.Results[0].Valid {
		t.Error("Results[0].Valid should be true")
	}
	if result.Results[1].Valid {
		t.Error("Results[1].Valid should be false")
	}
}

func TestGetIntFromInterface(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  int
	}{
		{"int", 42, 42},
		{"int64", int64(42), 42},
		{"float64", float64(42), 42},
		{"string", "42", 0},
		{"nil", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getIntFromInterface(tt.input)
			if got != tt.want {
				t.Errorf("getIntFromInterface(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
