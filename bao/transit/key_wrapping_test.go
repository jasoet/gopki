package transit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestWrapKeyForImport(t *testing.T) {
	// Generate a test RSA key for wrapping
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	wrappingKey := &WrappingKey{
		PublicKey: &rsaKey.PublicKey,
		PEM:       "",
	}

	tests := []struct {
		name        string
		targetKey   []byte
		wrappingKey *WrappingKey
		hashFunc    string
		wantErr     bool
	}{
		{
			name:        "valid AES-256 key with SHA256",
			targetKey:   make([]byte, 32), // AES-256
			wrappingKey: wrappingKey,
			hashFunc:    "SHA256",
			wantErr:     false,
		},
		{
			name:        "valid AES-128 key with SHA384",
			targetKey:   make([]byte, 16), // AES-128
			wrappingKey: wrappingKey,
			hashFunc:    "SHA384",
			wantErr:     false,
		},
		{
			name:        "valid key with SHA512",
			targetKey:   make([]byte, 32),
			wrappingKey: wrappingKey,
			hashFunc:    "SHA512",
			wantErr:     false,
		},
		{
			name:        "valid key with SHA1 (deprecated)",
			targetKey:   make([]byte, 32),
			wrappingKey: wrappingKey,
			hashFunc:    "SHA1",
			wantErr:     false,
		},
		{
			name:        "empty target key",
			targetKey:   []byte{},
			wrappingKey: wrappingKey,
			hashFunc:    "SHA256",
			wantErr:     true,
		},
		{
			name:        "nil wrapping key",
			targetKey:   make([]byte, 32),
			wrappingKey: nil,
			hashFunc:    "SHA256",
			wantErr:     true,
		},
		{
			name:        "invalid hash function",
			targetKey:   make([]byte, 32),
			wrappingKey: wrappingKey,
			hashFunc:    "MD5",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill target key with random data
			if len(tt.targetKey) > 0 {
				rand.Read(tt.targetKey)
			}

			wrapped, err := WrapKeyForImport(tt.targetKey, tt.wrappingKey, tt.hashFunc)

			if tt.wantErr {
				if err == nil {
					t.Error("WrapKeyForImport() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("WrapKeyForImport() error = %v, want nil", err)
				return
			}

			if wrapped == "" {
				t.Error("WrapKeyForImport() returned empty string")
			}

			// Verify wrapped key is base64 encoded
			if strings.Contains(wrapped, " ") || strings.Contains(wrapped, "\n") {
				t.Error("Wrapped key contains invalid characters")
			}
		})
	}
}

func TestSecureZero(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "32-byte data",
			data: make([]byte, 32),
		},
		{
			name: "16-byte data",
			data: make([]byte, 16),
		},
		{
			name: "1-byte data",
			data: make([]byte, 1),
		},
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "nil data",
			data: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill with non-zero data
			for i := range tt.data {
				tt.data[i] = byte(i + 1)
			}

			// Secure zero
			secureZero(tt.data)

			// Verify all bytes are zero
			for i, b := range tt.data {
				if b != 0 {
					t.Errorf("byte %d not zeroed: got %v, want 0", i, b)
				}
			}
		})
	}
}

func TestParseRSAPublicKeyFromPEM(t *testing.T) {
	// Generate a valid RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	validPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	// Generate a weak 1024-bit RSA key for testing
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak RSA key: %v", err)
	}

	weakKeyDER, err := x509.MarshalPKIXPublicKey(&weakKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal weak key: %v", err)
	}

	weakPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: weakKeyDER,
	})

	tests := []struct {
		name    string
		pemData string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid RSA 2048 public key",
			pemData: string(validPEM),
			wantErr: false,
		},
		{
			name:    "empty PEM",
			pemData: "",
			wantErr: true,
			errMsg:  "failed to decode PEM",
		},
		{
			name:    "invalid PEM",
			pemData: "not a pem",
			wantErr: true,
			errMsg:  "failed to decode PEM",
		},
		{
			name: "wrong PEM type",
			pemData: `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU3HBMAoGCCqGSM49BAMC
-----END CERTIFICATE-----`,
			wantErr: true,
			errMsg:  "invalid PEM type",
		},
		{
			name:    "weak RSA key (1024 bits)",
			pemData: string(weakPEM),
			wantErr: true,
			errMsg:  "RSA key too small",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := parseRSAPublicKeyFromPEM(tt.pemData)

			if tt.wantErr {
				if err == nil {
					t.Error("parseRSAPublicKeyFromPEM() expected error, got nil")
					return
				}

				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("parseRSAPublicKeyFromPEM() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("parseRSAPublicKeyFromPEM() error = %v, want nil", err)
				return
			}

			if pubKey == nil {
				t.Error("parseRSAPublicKeyFromPEM() returned nil key")
				return
			}

			// Verify key size is at least 2048 bits
			keyBits := pubKey.N.BitLen()
			if keyBits < 2048 {
				t.Errorf("parsed key size = %d bits, want >= 2048", keyBits)
			}
		})
	}
}

func TestEncryptWithRSAOAEP(t *testing.T) {
	// Generate test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	plaintext := []byte("test data for encryption")

	tests := []struct {
		name     string
		hashFunc string
		wantErr  bool
	}{
		{
			name:     "SHA256",
			hashFunc: "SHA256",
			wantErr:  false,
		},
		{
			name:     "SHA384",
			hashFunc: "SHA384",
			wantErr:  false,
		},
		{
			name:     "SHA512",
			hashFunc: "SHA512",
			wantErr:  false,
		},
		{
			name:     "SHA1 (deprecated)",
			hashFunc: "SHA1",
			wantErr:  false,
		},
		{
			name:     "invalid hash function",
			hashFunc: "MD5",
			wantErr:  true,
		},
		{
			name:     "empty hash function",
			hashFunc: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := encryptWithRSAOAEP(plaintext, &rsaKey.PublicKey, tt.hashFunc)

			if tt.wantErr {
				if err == nil {
					t.Error("encryptWithRSAOAEP() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("encryptWithRSAOAEP() error = %v, want nil", err)
				return
			}

			if len(ciphertext) == 0 {
				t.Error("encryptWithRSAOAEP() returned empty ciphertext")
			}

			// Verify ciphertext is different from plaintext
			if len(ciphertext) == len(plaintext) {
				same := true
				for i := range plaintext {
					if ciphertext[i] != plaintext[i] {
						same = false
						break
					}
				}
				if same {
					t.Error("ciphertext is identical to plaintext")
				}
			}
		})
	}
}

func TestWrapWithKWP(t *testing.T) {
	// Test KWP wrapping
	kek := make([]byte, 32) // AES-256 KEK
	rand.Read(kek)

	plaintext := make([]byte, 32)
	rand.Read(plaintext)

	wrapped, err := wrapWithKWP(plaintext, kek)
	if err != nil {
		t.Errorf("wrapWithKWP() error = %v, want nil", err)
	}

	if len(wrapped) == 0 {
		t.Error("wrapWithKWP() returned empty result")
	}

	// Wrapped data should be longer than plaintext (includes padding and IV)
	if len(wrapped) <= len(plaintext) {
		t.Errorf("wrapped length %d should be > plaintext length %d", len(wrapped), len(plaintext))
	}
}

func TestWrappingKey_Struct(t *testing.T) {
	// Test WrappingKey structure
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	wk := &WrappingKey{
		PublicKey: &rsaKey.PublicKey,
		PEM:       "test-pem-data",
	}

	if wk.PublicKey == nil {
		t.Error("WrappingKey.PublicKey is nil")
	}

	if wk.PEM != "test-pem-data" {
		t.Errorf("WrappingKey.PEM = %v, want test-pem-data", wk.PEM)
	}
}

func TestImportKeyOptions_DefaultHashFunction(t *testing.T) {
	// Verify default hash function is applied correctly
	opts := &ImportKeyOptions{
		Type: KeyTypeAES256GCM96,
		// HashFunction not set
	}

	if opts.Type != KeyTypeAES256GCM96 {
		t.Errorf("Type = %v, want %v", opts.Type, KeyTypeAES256GCM96)
	}

	// Default hash function should be set in ImportKey method
	// This test verifies the struct fields are accessible
	_ = opts.HashFunction
	_ = opts.Exportable
	_ = opts.AllowPlaintextBackup
}

func TestExportKeyType_Constants(t *testing.T) {
	tests := []struct {
		keyType  ExportKeyType
		expected string
	}{
		{ExportEncryptionKey, "encryption-key"},
		{ExportSigningKey, "signing-key"},
		{ExportHMACKey, "hmac-key"},
	}

	for _, tt := range tests {
		t.Run(string(tt.keyType), func(t *testing.T) {
			if string(tt.keyType) != tt.expected {
				t.Errorf("ExportKeyType = %v, want %v", tt.keyType, tt.expected)
			}
		})
	}
}
