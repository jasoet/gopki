package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"github.com/jasoet/gopki/keypair/algo"
	"testing"
)

func TestAlgorithmCompatibilityMatrix(t *testing.T) {
	rsaKeyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	ecdsaKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	ed25519KeyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	keyPairs := map[string]interface{}{
		"RSA":     rsaKeyPair,
		"ECDSA":   ecdsaKeyPair,
		"Ed25519": ed25519KeyPair,
	}

	for name, kp := range keyPairs {
		t.Run(name+" PEM roundtrip", func(t *testing.T) {
			var privatePEM, publicPEM []byte
			var err error

			switch v := kp.(type) {
			case *algo.RSAKeyPair:
				privatePEM, err = v.PrivateKeyToPEM()
				if err != nil {
					t.Fatalf("Failed to convert %s private key to PEM: %v", name, err)
				}
				publicPEM, err = v.PublicKeyToPEM()
				if err != nil {
					t.Fatalf("Failed to convert %s public key to PEM: %v", name, err)
				}
			case *algo.ECDSAKeyPair:
				privatePEM, err = v.PrivateKeyToPEM()
				if err != nil {
					t.Fatalf("Failed to convert %s private key to PEM: %v", name, err)
				}
				publicPEM, err = v.PublicKeyToPEM()
				if err != nil {
					t.Fatalf("Failed to convert %s public key to PEM: %v", name, err)
				}
			case *algo.Ed25519KeyPair:
				privatePEM, err = v.PrivateKeyToPEM()
				if err != nil {
					t.Fatalf("Failed to convert %s private key to PEM: %v", name, err)
				}
				publicPEM, err = v.PublicKeyToPEM()
				if err != nil {
					t.Fatalf("Failed to convert %s public key to PEM: %v", name, err)
				}
			}

			switch name {
			case "RSA":
				privateKey, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](privatePEM)
				if err != nil {
					t.Fatalf("Failed to parse %s private key: %v", name, err)
				}
				if privateKey == nil {
					t.Fatalf("Private key is nil")
				}

				publicKey, err := ParsePublicKeyFromPEM[*rsa.PublicKey](publicPEM)
				if err != nil {
					t.Fatalf("Failed to parse %s public key: %v", name, err)
				}
				if publicKey == nil {
					t.Fatalf("Public key is nil")
				}
			case "ECDSA":
				privateKey, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](privatePEM)
				if err != nil {
					t.Fatalf("Failed to parse %s private key: %v", name, err)
				}
				if privateKey == nil {
					t.Fatalf("Private key is nil")
				}

				publicKey, err := ParsePublicKeyFromPEM[*ecdsa.PublicKey](publicPEM)
				if err != nil {
					t.Fatalf("Failed to parse %s public key: %v", name, err)
				}
				if publicKey == nil {
					t.Fatalf("Public key is nil")
				}
			case "Ed25519":
				privateKey, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](privatePEM)
				if err != nil {
					t.Fatalf("Failed to parse %s private key: %v", name, err)
				}
				if len(privateKey) == 0 {
					t.Fatalf("Private key is empty")
				}

				publicKey, err := ParsePublicKeyFromPEM[ed25519.PublicKey](publicPEM)
				if err != nil {
					t.Fatalf("Failed to parse %s public key: %v", name, err)
				}
				if len(publicKey) == 0 {
					t.Fatalf("Public key is empty")
				}
			}
		})
	}
}

func TestMultipleCurveGeneration(t *testing.T) {
	curves := []algo.ECDSACurve{
		algo.P224,
		algo.P256,
		algo.P384,
		algo.P521,
	}

	curveNames := []string{"P-224", "P-256", "P-384", "P-521"}

	for i, curve := range curves {
		t.Run(curveNames[i], func(t *testing.T) {
			keyPair1, err := algo.GenerateECDSAKeyPair(curve)
			if err != nil {
				t.Fatalf("Failed to generate first %s key pair: %v", curveNames[i], err)
			}

			keyPair2, err := algo.GenerateECDSAKeyPair(curve)
			if err != nil {
				t.Fatalf("Failed to generate second %s key pair: %v", curveNames[i], err)
			}

			if keyPair1.PrivateKey.D.Cmp(keyPair2.PrivateKey.D) == 0 {
				t.Fatalf("Generated identical %s private keys", curveNames[i])
			}

			if keyPair1.PrivateKey.Curve != curve.Curve() {
				t.Fatalf("First key pair has wrong curve for %s", curveNames[i])
			}

			if keyPair2.PrivateKey.Curve != curve.Curve() {
				t.Fatalf("Second key pair has wrong curve for %s", curveNames[i])
			}

			pem1, err := keyPair1.PrivateKeyToPEM()
			if err != nil {
				t.Fatalf("Failed to convert first %s key to PEM: %v", curveNames[i], err)
			}

			pem2, err := keyPair2.PrivateKeyToPEM()
			if err != nil {
				t.Fatalf("Failed to convert second %s key to PEM: %v", curveNames[i], err)
			}

			if string(pem1) == string(pem2) {
				t.Fatalf("Generated identical %s PEM data", curveNames[i])
			}

			_, err = algo.ECDSAKeyPairFromPEM(pem1)
			if err != nil {
				t.Fatalf("Failed to parse first %s PEM: %v", curveNames[i], err)
			}

			_, err = algo.ECDSAKeyPairFromPEM(pem2)
			if err != nil {
				t.Fatalf("Failed to parse second %s PEM: %v", curveNames[i], err)
			}
		})
	}
}

func TestKeyUniqueness(t *testing.T) {
	const numKeys = 10

	t.Run("RSA key uniqueness", func(t *testing.T) {
		keys := make([]*algo.RSAKeyPair, numKeys)
		for i := 0; i < numKeys; i++ {
			key, err := algo.GenerateRSAKeyPair(2048)
			if err != nil {
				t.Fatalf("Failed to generate RSA key %d: %v", i, err)
			}
			keys[i] = key
		}

		for i := 0; i < numKeys; i++ {
			for j := i + 1; j < numKeys; j++ {
				if keys[i].PrivateKey.N.Cmp(keys[j].PrivateKey.N) == 0 {
					t.Fatalf("Generated identical RSA keys at positions %d and %d", i, j)
				}
			}
		}
	})

	t.Run("ECDSA key uniqueness", func(t *testing.T) {
		keys := make([]*algo.ECDSAKeyPair, numKeys)
		for i := 0; i < numKeys; i++ {
			key, err := algo.GenerateECDSAKeyPair(algo.P256)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key %d: %v", i, err)
			}
			keys[i] = key
		}

		for i := 0; i < numKeys; i++ {
			for j := i + 1; j < numKeys; j++ {
				if keys[i].PrivateKey.D.Cmp(keys[j].PrivateKey.D) == 0 {
					t.Fatalf("Generated identical ECDSA keys at positions %d and %d", i, j)
				}
			}
		}
	})

	t.Run("Ed25519 key uniqueness", func(t *testing.T) {
		keys := make([]*algo.Ed25519KeyPair, numKeys)
		for i := 0; i < numKeys; i++ {
			key, err := algo.GenerateEd25519KeyPair()
			if err != nil {
				t.Fatalf("Failed to generate Ed25519 key %d: %v", i, err)
			}
			keys[i] = key
		}

		for i := 0; i < numKeys; i++ {
			for j := i + 1; j < numKeys; j++ {
				if string(keys[i].PrivateKey) == string(keys[j].PrivateKey) {
					t.Fatalf("Generated identical Ed25519 keys at positions %d and %d", i, j)
				}
			}
		}
	})
}

func TestLargeKeyGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large key generation test in short mode")
	}

	t.Run("RSA 4096-bit", func(t *testing.T) {
		keyPair, err := algo.GenerateRSAKeyPair(4096)
		if err != nil {
			t.Fatalf("Failed to generate 4096-bit RSA key: %v", err)
		}

		if keyPair.PrivateKey.Size() != 512 {
			t.Fatalf("Expected 4096-bit key (512 bytes), got %d bytes", keyPair.PrivateKey.Size())
		}

		privatePEM, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert 4096-bit key to PEM: %v", err)
		}

		loadedKeyPair, err := algo.RSAKeyPairFromPEM(privatePEM)
		if err != nil {
			t.Fatalf("Failed to load 4096-bit key from PEM: %v", err)
		}

		if loadedKeyPair.PrivateKey.Size() != keyPair.PrivateKey.Size() {
			t.Fatal("Loaded 4096-bit key size doesn't match original")
		}
	})

	t.Run("ECDSA P-521", func(t *testing.T) {
		keyPair, err := algo.GenerateECDSAKeyPair(algo.P521)
		if err != nil {
			t.Fatalf("Failed to generate P-521 ECDSA key: %v", err)
		}

		if keyPair.PrivateKey.Curve.Params().BitSize != 521 {
			t.Fatalf("Expected P-521 curve, got %d-bit curve", keyPair.PrivateKey.Curve.Params().BitSize)
		}

		privatePEM, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert P-521 key to PEM: %v", err)
		}

		loadedKeyPair, err := algo.ECDSAKeyPairFromPEM(privatePEM)
		if err != nil {
			t.Fatalf("Failed to load P-521 key from PEM: %v", err)
		}

		if loadedKeyPair.PrivateKey.Curve.Params().BitSize != 521 {
			t.Fatal("Loaded P-521 key curve doesn't match original")
		}
	})
}
