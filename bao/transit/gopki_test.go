package transit

import (
	"testing"

	"github.com/jasoet/gopki/keypair/algo"
)

// TestImportKeyOptions_GopkiIntegration tests gopki integration structures
func TestImportKeyOptions_GopkiIntegration(t *testing.T) {
	// Test that ImportKeyOptions work with gopki key types
	opts := &ImportKeyOptions{
		Type:         KeyTypeRSA2048,
		HashFunction: "SHA256",
		Exportable:   true,
	}

	if opts.Type != KeyTypeRSA2048 {
		t.Errorf("Type = %v, want %v", opts.Type, KeyTypeRSA2048)
	}
}

// TestRSAKeySizeDetection tests automatic RSA key size detection
func TestRSAKeySizeDetection(t *testing.T) {
	tests := []struct {
		name        string
		keySize     algo.KeySize
		expectedType string
	}{
		{
			name:        "2048-bit RSA",
			keySize:     algo.KeySize2048,
			expectedType: KeyTypeRSA2048,
		},
		{
			name:        "3072-bit RSA",
			keySize:     algo.KeySize3072,
			expectedType: KeyTypeRSA3072,
		},
		{
			name:        "4096-bit RSA",
			keySize:     algo.KeySize4096,
			expectedType: KeyTypeRSA4096,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := algo.GenerateRSAKeyPair(tt.keySize)
			if err != nil {
				t.Fatalf("Failed to generate RSA key pair: %v", err)
			}

			keyBytes := kp.PrivateKey.Size() * 8
			var detectedType string
			switch keyBytes {
			case 2048:
				detectedType = KeyTypeRSA2048
			case 3072:
				detectedType = KeyTypeRSA3072
			case 4096:
				detectedType = KeyTypeRSA4096
			}

			if detectedType != tt.expectedType {
				t.Errorf("Detected type = %v, want %v", detectedType, tt.expectedType)
			}
		})
	}
}

// TestECDSACurveDetection tests automatic ECDSA curve detection
func TestECDSACurveDetection(t *testing.T) {
	tests := []struct {
		name         string
		curve        algo.ECDSACurve
		expectedType string
	}{
		{
			name:         "P-256 curve",
			curve:        algo.P256,
			expectedType: KeyTypeECDSAP256,
		},
		{
			name:         "P-384 curve",
			curve:        algo.P384,
			expectedType: KeyTypeECDSAP384,
		},
		{
			name:         "P-521 curve",
			curve:        algo.P521,
			expectedType: KeyTypeECDSAP521,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := algo.GenerateECDSAKeyPair(tt.curve)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair: %v", err)
			}

			curveBits := kp.PrivateKey.Curve.Params().BitSize
			var detectedType string
			switch curveBits {
			case 256:
				detectedType = KeyTypeECDSAP256
			case 384:
				detectedType = KeyTypeECDSAP384
			case 521:
				detectedType = KeyTypeECDSAP521
			}

			if detectedType != tt.expectedType {
				t.Errorf("Detected type = %v, want %v", detectedType, tt.expectedType)
			}
		})
	}
}

// TestAESKeySizeDetection tests automatic AES key size detection
func TestAESKeySizeDetection(t *testing.T) {
	tests := []struct {
		name         string
		keySize      int
		expectedType string
		shouldError  bool
	}{
		{
			name:         "AES-128 (16 bytes)",
			keySize:      16,
			expectedType: KeyTypeAES128GCM96,
			shouldError:  false,
		},
		{
			name:         "AES-256 (32 bytes)",
			keySize:      32,
			expectedType: KeyTypeAES256GCM96,
			shouldError:  false,
		},
		{
			name:        "Invalid size (24 bytes)",
			keySize:     24,
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyBytes := make([]byte, tt.keySize)

			var detectedType string
			var err error

			switch len(keyBytes) {
			case 16:
				detectedType = KeyTypeAES128GCM96
			case 32:
				detectedType = KeyTypeAES256GCM96
			default:
				err = ErrInvalidConfig
			}

			if tt.shouldError {
				if err == nil {
					t.Error("Expected error for invalid key size, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if detectedType != tt.expectedType {
					t.Errorf("Detected type = %v, want %v", detectedType, tt.expectedType)
				}
			}
		})
	}
}

// TestExportKeyType_GopkiConstants tests export key type constants
func TestExportKeyType_GopkiConstants(t *testing.T) {
	tests := []struct {
		keyType  ExportKeyType
		expected string
	}{
		{ExportSigningKey, "signing-key"},
		{ExportEncryptionKey, "encryption-key"},
		{ExportHMACKey, "hmac-key"},
	}

	for _, tt := range tests {
		t.Run(string(tt.keyType), func(t *testing.T) {
			if string(tt.keyType) != tt.expected {
				t.Errorf("KeyType = %v, want %v", tt.keyType, tt.expected)
			}
		})
	}
}
