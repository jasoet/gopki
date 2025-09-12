package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"github.com/jasoet/gopki/keypair/algo"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRSAKeyPairGeneric(t *testing.T) {
	// Test the new generic function
	rsaKeyPair, err := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	if rsaKeyPair.PrivateKey.Size() != 256 { // 2048 bits = 256 bytes
		t.Errorf("Expected RSA key size 256 bytes, got %d", rsaKeyPair.PrivateKey.Size())
	}

	// Test that we get a real RSA private key
	if rsaKeyPair.PrivateKey.N == nil {
		t.Error("RSA private key modulus is nil")
	}

	// Test public key from key pair
	if rsaKeyPair.PublicKey.N.BitLen() != 2048 {
		t.Errorf("Expected RSA public key bit length 2048, got %d", rsaKeyPair.PublicKey.N.BitLen())
	}
}

func TestGenerateECDSAKeyPairGeneric(t *testing.T) {
	// Test the new generic function
	ecdsaKeyPair, err := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	if ecdsaKeyPair.PrivateKey.Curve.Params().Name != "P-256" {
		t.Errorf("Expected ECDSA curve P-256, got %s", ecdsaKeyPair.PrivateKey.Curve.Params().Name)
	}

	// Test that we get a real ECDSA private key
	if ecdsaKeyPair.PrivateKey.D == nil {
		t.Error("ECDSA private key D is nil")
	}

	// Test public key from key pair
	if ecdsaKeyPair.PublicKey.X == nil || ecdsaKeyPair.PublicKey.Y == nil {
		t.Error("ECDSA public key coordinates are nil")
	}
}

func TestGenerateEd25519KeyPairGeneric(t *testing.T) {
	// Test the new generic function
	ed25519KeyPair, err := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	if len(ed25519KeyPair.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("Expected Ed25519 private key size %d, got %d", ed25519.PrivateKeySize, len(ed25519KeyPair.PrivateKey))
	}

	if len(ed25519KeyPair.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("Expected Ed25519 public key size %d, got %d", ed25519.PublicKeySize, len(ed25519KeyPair.PublicKey))
	}
}

func TestPrivateKeyToPEMGeneric(t *testing.T) {
	// Test RSA
	rsaKeyPair, _ := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	rsaPEM, err := PrivateKeyToPEM(rsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert RSA private key to PEM: %v", err)
	}

	if !strings.Contains(string(rsaPEM), "BEGIN PRIVATE KEY") {
		t.Error("RSA PEM does not contain expected header")
	}

	// Test ECDSA
	ecdsaKeyPair, _ := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	ecdsaPEM, err := PrivateKeyToPEM(ecdsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert ECDSA private key to PEM: %v", err)
	}

	if !strings.Contains(string(ecdsaPEM), "BEGIN PRIVATE KEY") {
		t.Error("ECDSA PEM does not contain expected header")
	}

	// Test Ed25519
	ed25519KeyPair, _ := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	ed25519PEM, err := PrivateKeyToPEM(ed25519KeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert Ed25519 private key to PEM: %v", err)
	}

	if !strings.Contains(string(ed25519PEM), "BEGIN PRIVATE KEY") {
		t.Error("Ed25519 PEM does not contain expected header")
	}
}

func TestPublicKeyToPEMGeneric(t *testing.T) {
	// Test RSA
	rsaKeyPair, _ := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	rsaPEM, err := PublicKeyToPEM(rsaKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to convert RSA public key to PEM: %v", err)
	}

	if !strings.Contains(string(rsaPEM), "BEGIN PUBLIC KEY") {
		t.Error("RSA public PEM does not contain expected header")
	}

	// Test ECDSA
	ecdsaKeyPair, _ := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	ecdsaPEM, err := PublicKeyToPEM(ecdsaKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to convert ECDSA public key to PEM: %v", err)
	}

	if !strings.Contains(string(ecdsaPEM), "BEGIN PUBLIC KEY") {
		t.Error("ECDSA public PEM does not contain expected header")
	}

	// Test Ed25519
	ed25519KeyPair, _ := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	ed25519PEM, err := PublicKeyToPEM(ed25519KeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to convert Ed25519 public key to PEM: %v", err)
	}

	if !strings.Contains(string(ed25519PEM), "BEGIN PUBLIC KEY") {
		t.Error("Ed25519 public PEM does not contain expected header")
	}
}

func TestParsePrivateKeyFromPEMGeneric(t *testing.T) {
	// Test RSA round trip
	rsaKeyPair, _ := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	rsaPEM, _ := PrivateKeyToPEM(rsaKeyPair.PrivateKey)

	parsedRSA, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](rsaPEM)
	if err != nil {
		t.Fatalf("Failed to parse RSA private key from PEM: %v", err)
	}

	if parsedRSA.N.Cmp(rsaKeyPair.PrivateKey.N) != 0 {
		t.Error("Parsed RSA key does not match original")
	}

	// Test ECDSA round trip
	ecdsaKeyPair, _ := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	ecdsaPEM, _ := PrivateKeyToPEM(ecdsaKeyPair.PrivateKey)

	parsedECDSA, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](ecdsaPEM)
	if err != nil {
		t.Fatalf("Failed to parse ECDSA private key from PEM: %v", err)
	}

	if parsedECDSA.D.Cmp(ecdsaKeyPair.PrivateKey.D) != 0 {
		t.Error("Parsed ECDSA key does not match original")
	}

	// Test Ed25519 round trip
	ed25519KeyPair, _ := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	ed25519PEM, _ := PrivateKeyToPEM(ed25519KeyPair.PrivateKey)

	parsedEd25519, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](ed25519PEM)
	if err != nil {
		t.Fatalf("Failed to parse Ed25519 private key from PEM: %v", err)
	}

	if string(parsedEd25519) != string(ed25519KeyPair.PrivateKey) {
		t.Error("Parsed Ed25519 key does not match original")
	}
}

func TestPrivateKeyFromPEMWithDetection(t *testing.T) {
	// Test RSA detection
	rsaKeyPair, _ := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	rsaPEM, _ := PrivateKeyToPEM(rsaKeyPair.PrivateKey)

	parsedRSA, algorithm, err := PrivateKeyFromPEM[*rsa.PrivateKey](rsaPEM)
	if err != nil {
		t.Fatalf("Failed to detect and parse RSA key: %v", err)
	}

	if algorithm != "RSA" {
		t.Errorf("Expected algorithm RSA, got %s", algorithm)
	}

	if parsedRSA.N.Cmp(rsaKeyPair.PrivateKey.N) != 0 {
		t.Error("Detected RSA key does not match original")
	}

	// Test ECDSA detection
	ecdsaKeyPair, _ := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	ecdsaPEM, _ := PrivateKeyToPEM(ecdsaKeyPair.PrivateKey)

	parsedECDSA, algorithm, err := PrivateKeyFromPEM[*ecdsa.PrivateKey](ecdsaPEM)
	if err != nil {
		t.Fatalf("Failed to detect and parse ECDSA key: %v", err)
	}

	if algorithm != "ECDSA" {
		t.Errorf("Expected algorithm ECDSA, got %s", algorithm)
	}

	if parsedECDSA.D.Cmp(ecdsaKeyPair.PrivateKey.D) != 0 {
		t.Error("Detected ECDSA key does not match original")
	}

	// Test Ed25519 detection
	ed25519KeyPair, _ := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	ed25519PEM, _ := PrivateKeyToPEM(ed25519KeyPair.PrivateKey)

	parsedEd25519, algorithm, err := PrivateKeyFromPEM[ed25519.PrivateKey](ed25519PEM)
	if err != nil {
		t.Fatalf("Failed to detect and parse Ed25519 key: %v", err)
	}

	if algorithm != "Ed25519" {
		t.Errorf("Expected algorithm Ed25519, got %s", algorithm)
	}

	if string(parsedEd25519) != string(ed25519KeyPair.PrivateKey) {
		t.Error("Detected Ed25519 key does not match original")
	}
}

func TestKeyPairToFiles(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Test RSA key pair file operations
	rsaKeyPair, _ := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	privateFile := filepath.Join(tempDir, "test_rsa_private.pem")
	publicFile := filepath.Join(tempDir, "test_rsa_public.pem")

	err := ToFiles(rsaKeyPair, privateFile, publicFile)
	if err != nil {
		t.Fatalf("Failed to save RSA key pair to files: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(privateFile); os.IsNotExist(err) {
		t.Error("Private key file was not created")
	}

	if _, err := os.Stat(publicFile); os.IsNotExist(err) {
		t.Error("Public key file was not created")
	}

	// Test loading the private key back
	privateKeyData, err := os.ReadFile(privateFile)
	if err != nil {
		t.Fatalf("Failed to read private key file: %v", err)
	}

	parsedKey, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](privateKeyData)
	if err != nil {
		t.Fatalf("Failed to parse saved private key: %v", err)
	}

	if parsedKey.N.Cmp(rsaKeyPair.PrivateKey.N) != 0 {
		t.Error("Saved and loaded private key do not match")
	}
}

func TestValidatePEMFormat(t *testing.T) {
	// Test valid private key PEM
	rsaKeyPair, _ := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	privatePEM, _ := PrivateKeyToPEM(rsaKeyPair.PrivateKey)

	err := ValidatePEMFormat(privatePEM)
	if err != nil {
		t.Errorf("Valid private key PEM failed validation: %v", err)
	}

	// Test valid public key PEM
	publicPEM, _ := PublicKeyToPEM(rsaKeyPair.PublicKey)

	err = ValidatePEMFormat(publicPEM)
	if err != nil {
		t.Errorf("Valid public key PEM failed validation: %v", err)
	}

	// Test invalid PEM
	invalidPEM := []byte("not a PEM")
	err = ValidatePEMFormat(invalidPEM)
	if err == nil {
		t.Error("Invalid PEM should have failed validation")
	}

	// Test wrong PEM type
	wrongTypePEM := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBBQUAMBUxEzARBgNVBAoTCkFj
-----END CERTIFICATE-----`)

	err = ValidatePEMFormat(wrongTypePEM)
	if err == nil {
		t.Error("Wrong PEM type should have failed validation")
	}
}

func TestGetPublicKeyRSA(t *testing.T) {
	rsaKeyPair, err := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	publicKey, err := GetPublicKey[*rsa.PrivateKey, *rsa.PublicKey](rsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to get public key from RSA private key: %v", err)
	}

	if publicKey.N.Cmp(rsaKeyPair.PrivateKey.PublicKey.N) != 0 {
		t.Error("Public key modulus doesn't match private key's public key")
	}

	if publicKey.E != rsaKeyPair.PrivateKey.PublicKey.E {
		t.Error("Public key exponent doesn't match private key's public key")
	}
}

func TestGetPublicKeyECDSA(t *testing.T) {
	ecdsaKeyPair, err := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	publicKey, err := GetPublicKey[*ecdsa.PrivateKey, *ecdsa.PublicKey](ecdsaKeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to get public key from ECDSA private key: %v", err)
	}

	if publicKey.X.Cmp(ecdsaKeyPair.PrivateKey.PublicKey.X) != 0 {
		t.Error("Public key X coordinate doesn't match private key's public key")
	}

	if publicKey.Y.Cmp(ecdsaKeyPair.PrivateKey.PublicKey.Y) != 0 {
		t.Error("Public key Y coordinate doesn't match private key's public key")
	}

	if publicKey.Curve.Params().Name != ecdsaKeyPair.PrivateKey.Curve.Params().Name {
		t.Error("Public key curve doesn't match private key's curve")
	}
}

func TestGetPublicKeyEd25519(t *testing.T) {
	ed25519KeyPair, err := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	publicKey, err := GetPublicKey[ed25519.PrivateKey, ed25519.PublicKey](ed25519KeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to get public key from Ed25519 private key: %v", err)
	}

	expectedPublicKey := ed25519KeyPair.PrivateKey.Public().(ed25519.PublicKey)
	if string(publicKey) != string(expectedPublicKey) {
		t.Error("Public key doesn't match private key's public key")
	}

	if string(publicKey) != string(ed25519KeyPair.PublicKey) {
		t.Error("Extracted public key doesn't match key pair's public key")
	}
}

func TestGetPublicKeyTypeMismatch(t *testing.T) {
	rsaKeyPair, err := GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	_, err = GetPublicKey[*rsa.PrivateKey, *ecdsa.PublicKey](rsaKeyPair.PrivateKey)
	if err == nil {
		t.Error("Expected error when trying to extract ECDSA public key from RSA private key")
	}

	expectedError := "unsupported key type or type mismatch"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestGetPublicKeyCrossAlgorithm(t *testing.T) {
	ecdsaKeyPair, err := GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	_, err = GetPublicKey[*ecdsa.PrivateKey, ed25519.PublicKey](ecdsaKeyPair.PrivateKey)
	if err == nil {
		t.Error("Expected error when trying to extract Ed25519 public key from ECDSA private key")
	}

	ed25519KeyPair, err := GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	_, err = GetPublicKey[ed25519.PrivateKey, *rsa.PublicKey](ed25519KeyPair.PrivateKey)
	if err == nil {
		t.Error("Expected error when trying to extract RSA public key from Ed25519 private key")
	}
}
