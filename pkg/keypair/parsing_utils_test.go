package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/jasoet/gopki/pkg/utils"
)

func TestPEMValidation(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	validPrivatePEM, _ := keyPair.PrivateKeyToPEM()
	validPublicPEM, _ := keyPair.PublicKeyToPEM()

	err = ValidatePEMFormat(validPrivatePEM)
	if err != nil {
		t.Fatalf("Valid private PEM failed validation: %v", err)
	}

	err = ValidatePEMFormat(validPublicPEM)
	if err != nil {
		t.Fatalf("Valid public PEM failed validation: %v", err)
	}

	invalidPEM := []byte("This is not a PEM format")
	err = ValidatePEMFormat(invalidPEM)
	if err == nil {
		t.Fatal("Invalid PEM passed validation")
	}

	unsupportedPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
-----END CERTIFICATE-----`)
	err = ValidatePEMFormat(unsupportedPEM)
	if err == nil {
		t.Fatal("Unsupported PEM type passed validation")
	}
}

func TestParsePublicKeyFromPEM(t *testing.T) {
	rsaKeyPair, _ := GenerateRSAKeyPair(2048)
	ecdsaKeyPair, _ := GenerateECDSAKeyPair(P256)
	ed25519KeyPair, _ := GenerateEd25519KeyPair()

	rsaPublicPEM, _ := rsaKeyPair.PublicKeyToPEM()
	ecdsaPublicPEM, _ := ecdsaKeyPair.PublicKeyToPEM()
	ed25519PublicPEM, _ := ed25519KeyPair.PublicKeyToPEM()

	parsedRSA, err := ParsePublicKeyFromPEM[*rsa.PublicKey](rsaPublicPEM)
	if err != nil {
		t.Fatalf("Failed to parse RSA public key: %v", err)
	}
	if parsedRSA == nil {
		t.Fatal("Parsed RSA key is nil")
	}

	parsedECDSA, err := ParsePublicKeyFromPEM[*ecdsa.PublicKey](ecdsaPublicPEM)
	if err != nil {
		t.Fatalf("Failed to parse ECDSA public key: %v", err)
	}
	if parsedECDSA == nil {
		t.Fatal("Parsed ECDSA key is nil")
	}

	parsedEd25519, err := ParsePublicKeyFromPEM[ed25519.PublicKey](ed25519PublicPEM)
	if err != nil {
		t.Fatalf("Failed to parse Ed25519 public key: %v", err)
	}
	if len(parsedEd25519) == 0 {
		t.Fatal("Parsed Ed25519 key is empty")
	}
}

func TestParsePrivateKeyFromPEM(t *testing.T) {
	rsaKeyPair, _ := GenerateRSAKeyPair(2048)
	ecdsaKeyPair, _ := GenerateECDSAKeyPair(P256)
	ed25519KeyPair, _ := GenerateEd25519KeyPair()

	rsaPrivatePEM, _ := rsaKeyPair.PrivateKeyToPEM()
	ecdsaPrivatePEM, _ := ecdsaKeyPair.PrivateKeyToPEM()
	ed25519PrivatePEM, _ := ed25519KeyPair.PrivateKeyToPEM()

	parsedRSA, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](rsaPrivatePEM)
	if err != nil {
		t.Fatalf("Failed to parse RSA private key: %v", err)
	}
	if parsedRSA == nil {
		t.Fatal("Parsed RSA key is nil")
	}

	parsedECDSA, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](ecdsaPrivatePEM)
	if err != nil {
		t.Fatalf("Failed to parse ECDSA private key: %v", err)
	}
	if parsedECDSA == nil {
		t.Fatal("Parsed ECDSA key is nil")
	}

	parsedEd25519, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](ed25519PrivatePEM)
	if err != nil {
		t.Fatalf("Failed to parse Ed25519 private key: %v", err)
	}
	if len(parsedEd25519) == 0 {
		t.Fatal("Parsed Ed25519 key is empty")
	}
}

func TestFileExists(t *testing.T) {
	tempDir := t.TempDir()
	existingFile := filepath.Join(tempDir, "existing.txt")
	nonExistentFile := filepath.Join(tempDir, "nonexistent.txt")

	file, err := os.Create(existingFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	file.Close()

	if !utils.FileExists(existingFile) {
		t.Fatal("FileExists returned false for existing file")
	}

	if utils.FileExists(nonExistentFile) {
		t.Fatal("FileExists returned true for non-existent file")
	}
}

func TestSaveAndLoadPEMRoundtrip(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "roundtrip.pem")

	keyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalPEM, err := keyPair.PrivateKeyToPEM()
	if err != nil {
		t.Fatalf("Failed to convert to PEM: %v", err)
	}

	err = utils.SavePEMToFile(originalPEM, testFile)
	if err != nil {
		t.Fatalf("Failed to save PEM: %v", err)
	}

	loadedPEM, err := utils.LoadPEMFromFile(testFile)
	if err != nil {
		t.Fatalf("Failed to load PEM: %v", err)
	}

	if string(originalPEM) != string(loadedPEM) {
		t.Fatal("PEM data changed during save/load roundtrip")
	}
}

func TestPEMParsingWithInvalidData(t *testing.T) {
	invalidPEMData := []byte("invalid pem data")
	
	_, err := ParsePublicKeyFromPEM[*rsa.PublicKey](invalidPEMData)
	if err == nil {
		t.Fatal("Expected error when parsing invalid PEM as public key")
	}

	_, err = ParsePrivateKeyFromPEM[*rsa.PrivateKey](invalidPEMData)
	if err == nil {
		t.Fatal("Expected error when parsing invalid PEM as private key")
	}

	privatePEMAsPublic := []byte(`-----BEGIN PUBLIC KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7
-----END PUBLIC KEY-----`)
	
	_, err = ParsePublicKeyFromPEM[*rsa.PublicKey](privatePEMAsPublic)
	if err == nil {
		t.Fatal("Expected error when parsing malformed public key PEM")
	}
}