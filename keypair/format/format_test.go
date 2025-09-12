package format

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected KeyFormat
		hasError bool
	}{
		{
			name:     "Empty data",
			data:     []byte{},
			expected: FormatAuto,
			hasError: true,
		},
		{
			name:     "PEM format",
			data:     []byte("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKB"),
			expected: FormatPEM,
			hasError: false,
		},
		{
			name:     "SSH RSA public key",
			data:     []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7VJTUt9Us8cKB user@host"),
			expected: FormatSSH,
			hasError: false,
		},
		{
			name:     "SSH Ed25519 public key",
			data:     []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host"),
			expected: FormatSSH,
			hasError: false,
		},
		{
			name:     "SSH ECDSA public key",
			data:     []byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAI user@host"),
			expected: FormatSSH,
			hasError: false,
		},
		{
			name: "Binary data (DER)",
			data: func() []byte {
				// Generate real DER data for testing
				kp, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
				derData, _ := PrivateKeyToDER(kp.PrivateKey)
				return derData
			}(),
			expected: FormatDER,
			hasError: false,
		},
		{
			name:     "Unknown format",
			data:     []byte("unknown format data"),
			expected: FormatAuto,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, err := DetectFormat(tt.data)
			
			if tt.hasError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.hasError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if format != tt.expected {
				t.Errorf("Expected format %v, got %v", tt.expected, format)
			}
		})
	}
}

func TestPrivateKeyToDER_RSA(t *testing.T) {
	// Generate RSA key pair
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Convert private key to DER
	derData, err := PrivateKeyToDER(rsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert RSA private key to DER: %v", err)
	}

	if len(derData) == 0 {
		t.Error("DER data should not be empty")
	}

	// Verify we can parse it back
	parsedKey, err := ParsePrivateKeyFromDER[*rsa.PrivateKey](derData)
	if err != nil {
		t.Fatalf("Failed to parse RSA private key from DER: %v", err)
	}

	// Verify key properties match
	if parsedKey.Size() != rsaKeyPair.PrivateKey.Size() {
		t.Errorf("Key sizes don't match: original %d, parsed %d", rsaKeyPair.PrivateKey.Size(), parsedKey.Size())
	}
}

func TestPrivateKeyToDER_ECDSA(t *testing.T) {
	// Generate ECDSA key pair
	ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	// Convert private key to DER
	derData, err := PrivateKeyToDER(ecdsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert ECDSA private key to DER: %v", err)
	}

	if len(derData) == 0 {
		t.Error("DER data should not be empty")
	}

	// Verify we can parse it back
	parsedKey, err := ParsePrivateKeyFromDER[*ecdsa.PrivateKey](derData)
	if err != nil {
		t.Fatalf("Failed to parse ECDSA private key from DER: %v", err)
	}

	// Verify curve matches
	if parsedKey.Curve.Params().Name != ecdsaKeyPair.PrivateKey.Curve.Params().Name {
		t.Errorf("Curves don't match: original %s, parsed %s", 
			ecdsaKeyPair.PrivateKey.Curve.Params().Name, 
			parsedKey.Curve.Params().Name)
	}
}

func TestPrivateKeyToDER_Ed25519(t *testing.T) {
	// Generate Ed25519 key pair
	ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Convert private key to DER
	derData, err := PrivateKeyToDER(ed25519KeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert Ed25519 private key to DER: %v", err)
	}

	if len(derData) == 0 {
		t.Error("DER data should not be empty")
	}

	// Verify we can parse it back
	parsedKey, err := ParsePrivateKeyFromDER[ed25519.PrivateKey](derData)
	if err != nil {
		t.Fatalf("Failed to parse Ed25519 private key from DER: %v", err)
	}

	// Verify key length matches
	if len(parsedKey) != len(ed25519KeyPair.PrivateKey) {
		t.Errorf("Key lengths don't match: original %d, parsed %d", 
			len(ed25519KeyPair.PrivateKey), len(parsedKey))
	}
}

func TestPublicKeyToDER_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name    string
		keyPair interface{}
	}{
		{
			name: "RSA",
			keyPair: func() interface{} {
				kp, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
				return kp
			}(),
		},
		{
			name: "ECDSA",
			keyPair: func() interface{} {
				kp, _ := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
				return kp
			}(),
		},
		{
			name: "Ed25519",
			keyPair: func() interface{} {
				kp, _ := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
				return kp
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var derData []byte
			var err error

			switch kp := tt.keyPair.(type) {
			case *algo.RSAKeyPair:
				derData, err = PublicKeyToDER(&kp.PrivateKey.PublicKey)
				if err != nil {
					t.Fatalf("Failed to convert RSA public key to DER: %v", err)
				}
				// Verify round-trip
				_, err = ParsePublicKeyFromDER[*rsa.PublicKey](derData)
			case *algo.ECDSAKeyPair:
				derData, err = PublicKeyToDER(&kp.PrivateKey.PublicKey)
				if err != nil {
					t.Fatalf("Failed to convert ECDSA public key to DER: %v", err)
				}
				// Verify round-trip
				_, err = ParsePublicKeyFromDER[*ecdsa.PublicKey](derData)
			case *algo.Ed25519KeyPair:
				derData, err = PublicKeyToDER(kp.PublicKey)
				if err != nil {
					t.Fatalf("Failed to convert Ed25519 public key to DER: %v", err)
				}
				// Verify round-trip
				_, err = ParsePublicKeyFromDER[ed25519.PublicKey](derData)
			}

			if err != nil {
				t.Fatalf("Round-trip test failed: %v", err)
			}

			if len(derData) == 0 {
				t.Error("DER data should not be empty")
			}
		})
	}
}

func TestConvertPEMToDER(t *testing.T) {
	// Generate a key and convert to PEM first
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	pemData, err := keypair.PrivateKeyToPEM(rsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert to PEM: %v", err)
	}

	// Convert PEM to DER
	derData, err := ConvertPEMToDER(pemData)
	if err != nil {
		t.Fatalf("Failed to convert PEM to DER: %v", err)
	}

	// Verify we can parse the DER data
	_, err = ParsePrivateKeyFromDER[*rsa.PrivateKey](derData)
	if err != nil {
		t.Fatalf("Failed to parse converted DER data: %v", err)
	}
}

func TestConvertDERToPEM(t *testing.T) {
	// Generate a key and convert to DER first
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	derData, err := PrivateKeyToDER(rsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert to DER: %v", err)
	}

	// Convert DER to PEM
	pemData, err := ConvertDERToPEM(derData, "RSA")
	if err != nil {
		t.Fatalf("Failed to convert DER to PEM: %v", err)
	}

	// Verify PEM format
	pemStr := string(pemData)
	if !strings.Contains(pemStr, "-----BEGIN PRIVATE KEY-----") {
		t.Error("PEM data should contain BEGIN header")
	}
	if !strings.Contains(pemStr, "-----END PRIVATE KEY-----") {
		t.Error("PEM data should contain END header")
	}

	// Verify we can parse the PEM data
	_, err = keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData)
	if err != nil {
		t.Fatalf("Failed to parse converted PEM data: %v", err)
	}
}

func TestGetKeyTypeFromDER(t *testing.T) {
	tests := []struct {
		name         string
		generateKey  func() ([]byte, error)
		expectedType string
	}{
		{
			name: "RSA private key",
			generateKey: func() ([]byte, error) {
				kp, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
				if err != nil {
					return nil, err
				}
				return PrivateKeyToDER(kp.PrivateKey)
			},
			expectedType: "RSA",
		},
		{
			name: "ECDSA private key",
			generateKey: func() ([]byte, error) {
				kp, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
				if err != nil {
					return nil, err
				}
				return PrivateKeyToDER(kp.PrivateKey)
			},
			expectedType: "ECDSA",
		},
		{
			name: "Ed25519 private key",
			generateKey: func() ([]byte, error) {
				kp, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
				if err != nil {
					return nil, err
				}
				return PrivateKeyToDER(kp.PrivateKey)
			},
			expectedType: "Ed25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			derData, err := tt.generateKey()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			keyType, err := GetKeyTypeFromDER(derData)
			if err != nil {
				t.Fatalf("Failed to get key type: %v", err)
			}

			if keyType != tt.expectedType {
				t.Errorf("Expected key type %s, got %s", tt.expectedType, keyType)
			}
		})
	}
}

func TestFormatError(t *testing.T) {
	err := NewFormatError(FormatDER, "test error", nil)
	
	expectedMsg := "DER format error: test error"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}

	if err.Format != FormatDER {
		t.Errorf("Expected format %v, got %v", FormatDER, err.Format)
	}
}

func TestKeyFormat_String(t *testing.T) {
	tests := []struct {
		format   KeyFormat
		expected string
	}{
		{FormatPEM, "PEM"},
		{FormatDER, "DER"},
		{FormatSSH, "SSH"},
		{FormatAuto, "AUTO"},
		{KeyFormat(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		if tt.format.String() != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, tt.format.String())
		}
	}
}