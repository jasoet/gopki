package keypair

import (
	"testing"

	"github.com/jasoet/gopki/keypair/algo"
)

// TestAlgorithmCompatibilityBasic tests basic key generation compatibility
// Advanced compatibility tests with format conversion are in integration tests
func TestAlgorithmCompatibilityBasic(t *testing.T) {
	// Test that all algorithms can generate keys successfully
	_, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	_, err = algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	_, err = algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}
}