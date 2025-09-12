package keypair

import (
	"testing"
)

func TestGenerateRSAKeyPair(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	if keyPair.PrivateKey == nil {
		t.Fatal("Private key is nil")
	}

	if keyPair.PublicKey == nil {
		t.Fatal("Public key is nil")
	}

	if keyPair.PrivateKey.Size() != 256 {
		t.Fatalf("Expected key size 256 bytes, got %d", keyPair.PrivateKey.Size())
	}
}

func TestRSAKeyPairPEMConversion(t *testing.T) {
	keyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	privatePEM, err := keyPair.PrivateKeyToPEM()
	if err != nil {
		t.Fatalf("Failed to convert private key to PEM: %v", err)
	}

	publicPEM, err := keyPair.PublicKeyToPEM()
	if err != nil {
		t.Fatalf("Failed to convert public key to PEM: %v", err)
	}

	loadedKeyPair, err := RSAKeyPairFromPEM(privatePEM)
	if err != nil {
		t.Fatalf("Failed to load key pair from PEM: %v", err)
	}

	if loadedKeyPair.PrivateKey.Size() != keyPair.PrivateKey.Size() {
		t.Fatal("Loaded key pair does not match original")
	}

	if len(privatePEM) == 0 || len(publicPEM) == 0 {
		t.Fatal("PEM data is empty")
	}
}

func TestGenerateECDSAKeyPair(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair(P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	if keyPair.PrivateKey == nil {
		t.Fatal("Private key is nil")
	}

	if keyPair.PublicKey == nil {
		t.Fatal("Public key is nil")
	}
}

func TestECDSAKeyPairPEMConversion(t *testing.T) {
	keyPair, err := GenerateECDSAKeyPair(P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	privatePEM, err := keyPair.PrivateKeyToPEM()
	if err != nil {
		t.Fatalf("Failed to convert private key to PEM: %v", err)
	}

	publicPEM, err := keyPair.PublicKeyToPEM()
	if err != nil {
		t.Fatalf("Failed to convert public key to PEM: %v", err)
	}

	loadedKeyPair, err := ECDSAKeyPairFromPEM(privatePEM)
	if err != nil {
		t.Fatalf("Failed to load key pair from PEM: %v", err)
	}

	if loadedKeyPair.PrivateKey.Curve != keyPair.PrivateKey.Curve {
		t.Fatal("Loaded key pair does not match original")
	}

	if len(privatePEM) == 0 || len(publicPEM) == 0 {
		t.Fatal("PEM data is empty")
	}
}

func TestGenerateEd25519KeyPair(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	if keyPair.PrivateKey == nil {
		t.Fatal("Private key is nil")
	}

	if keyPair.PublicKey == nil {
		t.Fatal("Public key is nil")
	}

	if len(keyPair.PrivateKey) != 64 {
		t.Fatalf("Expected Ed25519 private key length 64, got %d", len(keyPair.PrivateKey))
	}

	if len(keyPair.PublicKey) != 32 {
		t.Fatalf("Expected Ed25519 public key length 32, got %d", len(keyPair.PublicKey))
	}
}

func TestEd25519KeyPairPEMConversion(t *testing.T) {
	keyPair, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	privatePEM, err := keyPair.PrivateKeyToPEM()
	if err != nil {
		t.Fatalf("Failed to convert private key to PEM: %v", err)
	}

	publicPEM, err := keyPair.PublicKeyToPEM()
	if err != nil {
		t.Fatalf("Failed to convert public key to PEM: %v", err)
	}

	loadedKeyPair, err := Ed25519KeyPairFromPEM(privatePEM)
	if err != nil {
		t.Fatalf("Failed to load key pair from PEM: %v", err)
	}

	if len(loadedKeyPair.PrivateKey) != len(keyPair.PrivateKey) {
		t.Fatal("Loaded key pair does not match original")
	}

	if len(privatePEM) == 0 || len(publicPEM) == 0 {
		t.Fatal("PEM data is empty")
	}
}

func TestRSAKeySizeValidation(t *testing.T) {
	_, err := GenerateRSAKeyPair(1024)
	if err == nil {
		t.Fatal("Expected error for RSA key size less than 2048")
	}
}