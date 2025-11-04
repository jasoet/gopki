package transit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/jasoet/gopki/keypair"
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

// TestParsePrivateKeyFromBase64_RSA tests parsing RSA keys from base64
func TestParsePrivateKeyFromBase64_RSA(t *testing.T) {
	// Generate a test RSA key
	rsaKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert to PKCS#8 DER
	derBytes, err := x509.MarshalPKCS8PrivateKey(rsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to marshal RSA key: %v", err)
	}

	// Encode to base64 (simulating Transit export format)
	base64Data := base64.StdEncoding.EncodeToString(derBytes)

	// Parse back
	parsedKey, err := parsePrivateKeyFromBase64(base64Data)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Verify it's an RSA key
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *rsa.PrivateKey, got %T", parsedKey)
	}

	// Verify key properties
	if rsaKey.N.Cmp(rsaKeyPair.PrivateKey.N) != 0 {
		t.Error("Parsed RSA key N doesn't match original")
	}
}

// TestParsePrivateKeyFromBase64_ECDSA tests parsing ECDSA keys from base64
func TestParsePrivateKeyFromBase64_ECDSA(t *testing.T) {
	// Generate a test ECDSA key
	ecdsaKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Convert to PKCS#8 DER
	derBytes, err := x509.MarshalPKCS8PrivateKey(ecdsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to marshal ECDSA key: %v", err)
	}

	// Encode to base64
	base64Data := base64.StdEncoding.EncodeToString(derBytes)

	// Parse back
	parsedKey, err := parsePrivateKeyFromBase64(base64Data)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Verify it's an ECDSA key
	ecdsaKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PrivateKey, got %T", parsedKey)
	}

	// Verify key properties
	if ecdsaKey.D.Cmp(ecdsaKeyPair.PrivateKey.D) != 0 {
		t.Error("Parsed ECDSA key D doesn't match original")
	}
}

// TestParsePrivateKeyFromBase64_Ed25519 tests parsing Ed25519 keys from base64
func TestParsePrivateKeyFromBase64_Ed25519(t *testing.T) {
	// Generate a test Ed25519 key
	ed25519KeyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Convert to PKCS#8 DER
	derBytes, err := x509.MarshalPKCS8PrivateKey(ed25519KeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to marshal Ed25519 key: %v", err)
	}

	// Encode to base64
	base64Data := base64.StdEncoding.EncodeToString(derBytes)

	// Parse back
	parsedKey, err := parsePrivateKeyFromBase64(base64Data)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Verify it's an Ed25519 key
	ed25519Key, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("Expected ed25519.PrivateKey, got %T", parsedKey)
	}

	// Verify key properties
	if !ed25519Key.Equal(ed25519KeyPair.PrivateKey) {
		t.Error("Parsed Ed25519 key doesn't match original")
	}
}

// TestParsePrivateKeyFromBase64_InvalidBase64 tests error handling for invalid base64
func TestParsePrivateKeyFromBase64_InvalidBase64(t *testing.T) {
	_, err := parsePrivateKeyFromBase64("invalid-base64!")
	if err == nil {
		t.Error("Expected error for invalid base64, got nil")
	}
}

// TestParsePrivateKeyFromBase64_InvalidPKCS8 tests error handling for invalid PKCS#8
func TestParsePrivateKeyFromBase64_InvalidPKCS8(t *testing.T) {
	// Valid base64 but invalid PKCS#8 data
	invalidData := base64.StdEncoding.EncodeToString([]byte("not-a-key"))
	_, err := parsePrivateKeyFromBase64(invalidData)
	if err == nil {
		t.Error("Expected error for invalid PKCS#8 data, got nil")
	}
}

// TestImportFromManager_RSA tests importing from RSA Manager
func TestImportFromManager_RSA(t *testing.T) {
	// Generate RSA manager
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA manager: %v", err)
	}

	// Verify manager is valid
	if !manager.IsValid() {
		t.Error("Generated manager is not valid")
	}

	// Test that we can extract the keypair
	kp := manager.KeyPair()
	if kp == nil {
		t.Error("Failed to extract keypair from manager")
	}

	if kp.PrivateKey == nil {
		t.Error("Manager keypair has nil private key")
	}
}

// TestImportFromManager_ECDSA tests importing from ECDSA Manager
func TestImportFromManager_ECDSA(t *testing.T) {
	// Generate ECDSA manager
	manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA manager: %v", err)
	}

	// Verify manager is valid
	if !manager.IsValid() {
		t.Error("Generated manager is not valid")
	}

	// Test that we can extract the keypair
	kp := manager.KeyPair()
	if kp == nil {
		t.Error("Failed to extract keypair from manager")
	}
}

// TestImportFromManager_Ed25519 tests importing from Ed25519 Manager
func TestImportFromManager_Ed25519(t *testing.T) {
	// Generate Ed25519 manager
	manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 manager: %v", err)
	}

	// Verify manager is valid
	if !manager.IsValid() {
		t.Error("Generated manager is not valid")
	}

	// Test that we can extract the keypair
	kp := manager.KeyPair()
	if kp == nil {
		t.Error("Failed to extract keypair from manager")
	}
}

// TestManagerRoundTrip tests creating a manager, exporting, and importing back
func TestManagerRoundTrip(t *testing.T) {
	// Generate RSA manager
	originalManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA manager: %v", err)
	}

	// Get the original keypair
	originalKP := originalManager.KeyPair()

	// Convert to DER (simulating export/import cycle)
	derBytes, err := x509.MarshalPKCS8PrivateKey(originalKP.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	// Parse back
	parsedKey, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *rsa.PrivateKey, got %T", parsedKey)
	}

	// Create new keypair
	newKP := &algo.RSAKeyPair{
		PrivateKey: rsaKey,
		PublicKey:  &rsaKey.PublicKey,
	}

	// Create new manager
	newManager := keypair.NewManager(newKP, newKP.PrivateKey, newKP.PublicKey)

	// Verify keys are equivalent
	if !originalManager.ComparePrivateKeys(newManager) {
		t.Error("Private keys don't match after round trip")
	}

	if !originalManager.ComparePublicKeys(newManager) {
		t.Error("Public keys don't match after round trip")
	}
}
