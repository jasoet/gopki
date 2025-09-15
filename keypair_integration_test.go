package gopki_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/keypair/format"
)

func TestPrivateKeyFromPEMWithDetection(t *testing.T) {
	// Test RSA detection
	rsaKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	rsaPEM, _ := keypair.PrivateKeyToPEM(rsaKeyPair.PrivateKey)

	parsedRSA, algorithm, err := format.PrivateKeyFromPEM[*rsa.PrivateKey](rsaPEM)
	if err != nil {
		t.Fatalf("Failed to detect and parse RSA key: %v", err)
	}

	if algorithm != "RSA" {
		t.Errorf("Expected algorithm RSA, got %s", algorithm)
	}

	if parsedRSA.N.Cmp(rsaKeyPair.PrivateKey.N) != 0 {
		t.Error("Parsed RSA key doesn't match original")
	}

	// Test ECDSA detection
	ecdsaKeyPair, _ := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	ecdsaPEM, _ := keypair.PrivateKeyToPEM(ecdsaKeyPair.PrivateKey)

	parsedECDSA, algorithm, err := format.PrivateKeyFromPEM[*ecdsa.PrivateKey](ecdsaPEM)
	if err != nil {
		t.Fatalf("Failed to detect and parse ECDSA key: %v", err)
	}

	if algorithm != "ECDSA" {
		t.Errorf("Expected algorithm ECDSA, got %s", algorithm)
	}

	if !parsedECDSA.PublicKey.Equal(&ecdsaKeyPair.PrivateKey.PublicKey) {
		t.Error("Parsed ECDSA key doesn't match original")
	}

	// Test Ed25519 detection
	ed25519KeyPair, _ := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	ed25519PEM, _ := keypair.PrivateKeyToPEM(ed25519KeyPair.PrivateKey)

	parsedEd25519, algorithm, err := format.PrivateKeyFromPEM[ed25519.PrivateKey](ed25519PEM)
	if err != nil {
		t.Fatalf("Failed to detect and parse Ed25519 key: %v", err)
	}

	if algorithm != "Ed25519" {
		t.Errorf("Expected algorithm Ed25519, got %s", algorithm)
	}

	if !parsedEd25519.Equal(ed25519KeyPair.PrivateKey) {
		t.Error("Parsed Ed25519 key doesn't match original")
	}
}