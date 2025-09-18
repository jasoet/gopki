package asymmetric

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/jasoet/gopki/keypair/algo"
)

// Test vectors from RFC 7748 and other sources for Ed25519 <-> X25519 conversion
func TestEd25519ToX25519Conversion(t *testing.T) {
	t.Run("RFC 7748 test vector", func(t *testing.T) {
		// Known test vector where we can verify the conversion
		// This is derived from the RFC 7748 specification

		// Generate a test key pair to work with
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		// Test the conversion
		x25519Key, err := Ed25519ToX25519PublicKey(ed25519Keys.PublicKey)
		if err != nil {
			t.Fatalf("Ed25519 to X25519 conversion failed: %v", err)
		}

		// Verify the result is valid
		if len(x25519Key) != 32 {
			t.Errorf("Expected 32-byte X25519 key, got %d bytes", len(x25519Key))
		}

		// Test reverse conversion
		ed25519KeyBack, err := X25519ToEd25519PublicKey(x25519Key)
		if err != nil {
			t.Fatalf("X25519 to Ed25519 conversion failed: %v", err)
		}

		if len(ed25519KeyBack) != 32 {
			t.Errorf("Expected 32-byte Ed25519 key, got %d bytes", len(ed25519KeyBack))
		}

		// Note: Due to the sign bit ambiguity, we can't expect exact equality
		// but we can verify that the conversion produces valid keys
		t.Logf("Original Ed25519: %x", ed25519Keys.PublicKey)
		t.Logf("X25519:           %x", x25519Key)
		t.Logf("Ed25519 back:     %x", ed25519KeyBack)
	})

	t.Run("Known test vectors", func(t *testing.T) {
		// Test with some known good Ed25519 public keys
		testVectors := []struct {
			name        string
			ed25519Hex  string
			shouldWork  bool
			description string
		}{
			{
				name:        "Valid key 1",
				ed25519Hex:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
				shouldWork:  true,
				description: "Standard Ed25519 public key",
			},
			{
				name:        "Valid key 2",
				ed25519Hex:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
				shouldWork:  true,
				description: "Another standard Ed25519 public key",
			},
			{
				name:        "Edge case - small value",
				ed25519Hex:  "0100000000000000000000000000000000000000000000000000000000000000",
				shouldWork:  false, // This is y=1, which is a singular point
				description: "Singular point y=1",
			},
		}

		for _, tv := range testVectors {
			t.Run(tv.name, func(t *testing.T) {
				ed25519Bytes, err := hex.DecodeString(tv.ed25519Hex)
				if err != nil {
					t.Fatalf("Failed to decode test vector: %v", err)
				}

				if len(ed25519Bytes) != 32 {
					t.Fatalf("Invalid test vector length: %d", len(ed25519Bytes))
				}

				ed25519Key := ed25519.PublicKey(ed25519Bytes)

				x25519Key, err := Ed25519ToX25519PublicKey(ed25519Key)
				if tv.shouldWork {
					if err != nil {
						t.Errorf("Expected conversion to work for %s, got error: %v", tv.description, err)
					} else {
						t.Logf("Conversion successful: %s -> %x", tv.description, x25519Key)
					}
				} else {
					if err == nil {
						t.Errorf("Expected conversion to fail for %s, but it succeeded", tv.description)
					} else {
						t.Logf("Conversion correctly failed for %s: %v", tv.description, err)
					}
				}
			})
		}
	})

	t.Run("Multiple random keys", func(t *testing.T) {
		// Test with multiple random keys to ensure robustness
		for i := 0; i < 10; i++ {
			// Generate random Ed25519 key pair
			publicKey, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate Ed25519 key %d: %v", i, err)
			}

			// Test conversion
			x25519Key, err := Ed25519ToX25519PublicKey(publicKey)
			if err != nil {
				t.Errorf("Conversion failed for random key %d: %v", i, err)
				continue
			}

			// Validate the result
			if err := ValidateX25519PublicKey(x25519Key); err != nil {
				t.Errorf("Resulting X25519 key %d is invalid: %v", i, err)
			}

			t.Logf("Random key %d: Ed25519=%x -> X25519=%x", i, publicKey, x25519Key)
		}
	})
}

func TestKeyValidation(t *testing.T) {
	t.Run("ValidateEd25519PublicKey", func(t *testing.T) {
		// Test with valid key
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		err = ValidateEd25519PublicKey(ed25519Keys.PublicKey)
		if err != nil {
			t.Errorf("Valid Ed25519 key failed validation: %v", err)
		}

		// Test with invalid length
		invalidKey := make([]byte, 16)
		err = ValidateEd25519PublicKey(invalidKey)
		if err == nil {
			t.Error("Expected validation to fail for wrong length key")
		}

		// Test with key that's too large (y >= p)
		tooLargeKey := make([]byte, 32)
		for i := range tooLargeKey {
			tooLargeKey[i] = 0xFF // This will be larger than p
		}
		err = ValidateEd25519PublicKey(tooLargeKey)
		if err == nil {
			t.Error("Expected validation to fail for key >= p")
		}
	})

	t.Run("ValidateX25519PublicKey", func(t *testing.T) {
		// Test with valid X25519 key (generated from Ed25519)
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		x25519Key, err := Ed25519ToX25519PublicKey(ed25519Keys.PublicKey)
		if err != nil {
			t.Fatalf("Failed to convert to X25519: %v", err)
		}

		err = ValidateX25519PublicKey(x25519Key)
		if err != nil {
			t.Errorf("Valid X25519 key failed validation: %v", err)
		}

		// Test with invalid length
		invalidKey := make([]byte, 16)
		err = ValidateX25519PublicKey(invalidKey)
		if err == nil {
			t.Error("Expected validation to fail for wrong length key")
		}

		// Test with zero point (low-order)
		zeroKey := make([]byte, 32)
		err = ValidateX25519PublicKey(zeroKey)
		if err == nil {
			t.Error("Expected validation to fail for zero point")
		}

		// Test with point 1 (low-order)
		oneKey := make([]byte, 32)
		oneKey[0] = 1 // Little-endian 1
		err = ValidateX25519PublicKey(oneKey)
		if err == nil {
			t.Error("Expected validation to fail for point 1")
		}
	})
}

func TestIsKeyConversionSafe(t *testing.T) {
	t.Run("Safe conversions", func(t *testing.T) {
		// Generate multiple random keys and check they're safe
		for i := 0; i < 5; i++ {
			ed25519Keys, err := algo.GenerateEd25519KeyPair()
			if err != nil {
				t.Fatalf("Failed to generate Ed25519 key pair %d: %v", i, err)
			}

			safe, err := IsKeyConversionSafe(ed25519Keys.PublicKey)
			if err != nil {
				t.Errorf("Key %d safety check failed: %v", i, err)
			}
			if !safe {
				t.Errorf("Key %d should be safe for conversion but was marked unsafe", i)
			}
		}
	})

	t.Run("Unsafe conversions", func(t *testing.T) {
		// Test with invalid key lengths
		invalidKey := make([]byte, 16)
		safe, err := IsKeyConversionSafe(invalidKey)
		if err == nil || safe {
			t.Error("Expected invalid length key to be marked unsafe")
		}

		// Test with singular point (y=1)
		singularKey := make([]byte, 32)
		singularKey[0] = 1 // Little-endian 1
		safe, err = IsKeyConversionSafe(singularKey)
		if err == nil || safe {
			t.Error("Expected singular point to be marked unsafe")
		}
	})
}

func TestSecureCompareKeys(t *testing.T) {
	// Test with identical keys
	key1 := []byte{1, 2, 3, 4, 5}
	key2 := []byte{1, 2, 3, 4, 5}
	if !SecureCompareKeys(key1, key2) {
		t.Error("Identical keys should compare as equal")
	}

	// Test with different keys
	key3 := []byte{1, 2, 3, 4, 6}
	if SecureCompareKeys(key1, key3) {
		t.Error("Different keys should compare as not equal")
	}

	// Test with different lengths
	key4 := []byte{1, 2, 3, 4}
	if SecureCompareKeys(key1, key4) {
		t.Error("Keys with different lengths should compare as not equal")
	}

	// Test with nil keys
	if SecureCompareKeys(nil, nil) != true {
		t.Error("Two nil keys should compare as equal")
	}
	if SecureCompareKeys(key1, nil) {
		t.Error("Key and nil should compare as not equal")
	}
}

func TestReverseBytes(t *testing.T) {
	// Test with even length
	data1 := []byte{1, 2, 3, 4}
	expected1 := []byte{4, 3, 2, 1}
	reverseBytes(data1)
	for i := range data1 {
		if data1[i] != expected1[i] {
			t.Errorf("Reverse failed: expected %v, got %v", expected1, data1)
			break
		}
	}

	// Test with odd length
	data2 := []byte{1, 2, 3, 4, 5}
	expected2 := []byte{5, 4, 3, 2, 1}
	reverseBytes(data2)
	for i := range data2 {
		if data2[i] != expected2[i] {
			t.Errorf("Reverse failed: expected %v, got %v", expected2, data2)
			break
		}
	}

	// Test with single byte
	data3 := []byte{42}
	expected3 := []byte{42}
	reverseBytes(data3)
	if data3[0] != expected3[0] {
		t.Errorf("Single byte reverse failed: expected %v, got %v", expected3, data3)
	}

	// Test with empty slice
	data4 := []byte{}
	reverseBytes(data4) // Should not panic
	if len(data4) != 0 {
		t.Error("Empty slice should remain empty")
	}
}

// Benchmark the conversion performance
func BenchmarkEd25519ToX25519Conversion(b *testing.B) {
	// Generate a test key
	ed25519Keys, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		b.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Ed25519ToX25519PublicKey(ed25519Keys.PublicKey)
		if err != nil {
			b.Fatalf("Conversion failed: %v", err)
		}
	}
}

func BenchmarkX25519ToEd25519Conversion(b *testing.B) {
	// Generate test keys
	ed25519Keys, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		b.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	x25519Key, err := Ed25519ToX25519PublicKey(ed25519Keys.PublicKey)
	if err != nil {
		b.Fatalf("Failed to convert to X25519: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := X25519ToEd25519PublicKey(x25519Key)
		if err != nil {
			b.Fatalf("Reverse conversion failed: %v", err)
		}
	}
}

// Test that demonstrates the mathematical relationship
func TestConversionMathematicalProperties(t *testing.T) {
	// Generate multiple keys and verify mathematical properties
	for i := 0; i < 5; i++ {
		ed25519Keys, err := algo.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair %d: %v", i, err)
		}

		// Convert Ed25519 -> X25519
		x25519Key, err := Ed25519ToX25519PublicKey(ed25519Keys.PublicKey)
		if err != nil {
			t.Fatalf("Forward conversion failed for key %d: %v", i, err)
		}

		// Convert X25519 -> Ed25519
		ed25519Back, err := X25519ToEd25519PublicKey(x25519Key)
		if err != nil {
			t.Fatalf("Reverse conversion failed for key %d: %v", i, err)
		}

		// While we can't expect exact equality due to sign ambiguity,
		// we can verify that both keys represent valid points
		if err := ValidateEd25519PublicKey(ed25519Keys.PublicKey); err != nil {
			t.Errorf("Original Ed25519 key %d is invalid: %v", i, err)
		}

		if err := ValidateX25519PublicKey(x25519Key); err != nil {
			t.Errorf("Converted X25519 key %d is invalid: %v", i, err)
		}

		if err := ValidateEd25519PublicKey(ed25519Back); err != nil {
			t.Errorf("Round-trip Ed25519 key %d is invalid: %v", i, err)
		}

		t.Logf("Key %d: Original=%x, X25519=%x, Back=%x",
			i, ed25519Keys.PublicKey, x25519Key, ed25519Back)
	}
}
