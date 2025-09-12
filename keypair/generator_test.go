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
	// Test with explicit generic type
	rsaPrivateKey, err := GenerateRSAKeyPair[*rsa.PrivateKey](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	if rsaPrivateKey.Size() != 256 { // 2048 bits = 256 bytes
		t.Errorf("Expected RSA key size 256 bytes, got %d", rsaPrivateKey.Size())
	}

	// Test that we get a real RSA private key
	if rsaPrivateKey.N == nil {
		t.Error("RSA private key modulus is nil")
	}

	// Test getting public key
	publicKey := RSAPublicKeyFromPrivate(rsaPrivateKey)
	if publicKey.N.BitLen() != 2048 {
		t.Errorf("Expected RSA public key bit length 2048, got %d", publicKey.N.BitLen())
	}
}

func TestGenerateECDSAKeyPairGeneric(t *testing.T) {
	// Test with explicit generic type
	ecdsaPrivateKey, err := GenerateECDSAKeyPair[*ecdsa.PrivateKey](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	if ecdsaPrivateKey.Curve.Params().BitSize != 256 {
		t.Errorf("Expected ECDSA curve bit size 256, got %d", ecdsaPrivateKey.Curve.Params().BitSize)
	}

	// Test getting public key
	publicKey := ECDSAPublicKeyFromPrivate(ecdsaPrivateKey)
	if publicKey.Curve.Params().BitSize != 256 {
		t.Errorf("Expected ECDSA public key curve bit size 256, got %d", publicKey.Curve.Params().BitSize)
	}
}

func TestGenerateEd25519KeyPairGeneric(t *testing.T) {
	// Test with explicit generic type
	ed25519PrivateKey, err := GenerateEd25519KeyPair[ed25519.PrivateKey]()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	if len(ed25519PrivateKey) != 64 {
		t.Errorf("Expected Ed25519 private key length 64, got %d", len(ed25519PrivateKey))
	}

	// Test getting public key
	publicKey := Ed25519PublicKeyFromPrivate(ed25519PrivateKey)
	if len(publicKey) != 32 {
		t.Errorf("Expected Ed25519 public key length 32, got %d", len(publicKey))
	}
}

func TestConvenienceFunctions(t *testing.T) {
	// Test NewRSAKeyPair
	rsaPrivateKey, err := NewRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	if rsaPrivateKey.Size() != 256 {
		t.Errorf("Expected RSA key size 256 bytes, got %d", rsaPrivateKey.Size())
	}

	// Test NewECDSAKeyPair
	ecdsaPrivateKey, err := NewECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	if ecdsaPrivateKey.Curve.Params().BitSize != 256 {
		t.Errorf("Expected ECDSA curve bit size 256, got %d", ecdsaPrivateKey.Curve.Params().BitSize)
	}

	// Test NewEd25519KeyPair
	ed25519PrivateKey, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	if len(ed25519PrivateKey) != 64 {
		t.Errorf("Expected Ed25519 private key length 64, got %d", len(ed25519PrivateKey))
	}
}

func TestGenericPEMConversion(t *testing.T) {
	testCases := []struct {
		name    string
		keyType string
		genFunc func() (interface{}, interface{}, error)
	}{
		{
			name:    "RSA",
			keyType: "RSA",
			genFunc: func() (interface{}, interface{}, error) {
				priv, err := NewRSAKeyPair(2048)
				if err != nil {
					return nil, nil, err
				}
				pub := RSAPublicKeyFromPrivate(priv)
				return priv, pub, nil
			},
		},
		{
			name:    "ECDSA",
			keyType: "ECDSA",
			genFunc: func() (interface{}, interface{}, error) {
				priv, err := NewECDSAKeyPair(algo.P256)
				if err != nil {
					return nil, nil, err
				}
				pub := ECDSAPublicKeyFromPrivate(priv)
				return priv, pub, nil
			},
		},
		{
			name:    "Ed25519",
			keyType: "Ed25519",
			genFunc: func() (interface{}, interface{}, error) {
				priv, err := NewEd25519KeyPair()
				if err != nil {
					return nil, nil, err
				}
				pub := Ed25519PublicKeyFromPrivate(priv)
				return priv, pub, nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			priv, pub, err := tc.genFunc()
			if err != nil {
				t.Fatalf("Failed to generate %s key pair: %v", tc.name, err)
			}

			// Test private key PEM conversion using generics
			var privatePEM []byte
			switch p := priv.(type) {
			case *rsa.PrivateKey:
				privatePEM, err = PrivateKeyToPEM(p)
			case *ecdsa.PrivateKey:
				privatePEM, err = PrivateKeyToPEM(p)
			case ed25519.PrivateKey:
				privatePEM, err = PrivateKeyToPEM(p)
			}

			if err != nil {
				t.Fatalf("Failed to convert private key to PEM: %v", err)
			}

			if len(privatePEM) == 0 {
				t.Fatal("Private key PEM is empty")
			}

			// Test public key PEM conversion using generics
			var publicPEM []byte
			switch p := pub.(type) {
			case *rsa.PublicKey:
				publicPEM, err = PublicKeyToPEM(p)
			case *ecdsa.PublicKey:
				publicPEM, err = PublicKeyToPEM(p)
			case ed25519.PublicKey:
				publicPEM, err = PublicKeyToPEM(p)
			}

			if err != nil {
				t.Fatalf("Failed to convert public key to PEM: %v", err)
			}

			if len(publicPEM) == 0 {
				t.Fatal("Public key PEM is empty")
			}

			// Verify PEM headers
			if !strings.Contains(string(privatePEM), "BEGIN PRIVATE KEY") {
				t.Error("Private key PEM missing proper header")
			}

			if !strings.Contains(string(publicPEM), "BEGIN PUBLIC KEY") {
				t.Error("Public key PEM missing proper header")
			}
		})
	}
}

func TestGenericKeyPairToPEM(t *testing.T) {
	// Test RSA
	rsaPriv, err := NewRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	rsaPub := RSAPublicKeyFromPrivate(rsaPriv)

	rsaPrivPEM, rsaPubPEM, err := KeyPairToPEM(rsaPriv, rsaPub)
	if err != nil {
		t.Fatalf("Failed to convert RSA key pair to PEM: %v", err)
	}

	if len(rsaPrivPEM) == 0 || len(rsaPubPEM) == 0 {
		t.Fatal("RSA PEM data is empty")
	}

	// Test ECDSA
	ecdsaPriv, err := NewECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	ecdsaPub := ECDSAPublicKeyFromPrivate(ecdsaPriv)

	ecdsaPrivPEM, ecdsaPubPEM, err := KeyPairToPEM(ecdsaPriv, ecdsaPub)
	if err != nil {
		t.Fatalf("Failed to convert ECDSA key pair to PEM: %v", err)
	}

	if len(ecdsaPrivPEM) == 0 || len(ecdsaPubPEM) == 0 {
		t.Fatal("ECDSA PEM data is empty")
	}

	// Test Ed25519
	ed25519Priv, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	ed25519Pub := Ed25519PublicKeyFromPrivate(ed25519Priv)

	ed25519PrivPEM, ed25519PubPEM, err := KeyPairToPEM(ed25519Priv, ed25519Pub)
	if err != nil {
		t.Fatalf("Failed to convert Ed25519 key pair to PEM: %v", err)
	}

	if len(ed25519PrivPEM) == 0 || len(ed25519PubPEM) == 0 {
		t.Fatal("Ed25519 PEM data is empty")
	}
}

func TestParseWithGenerics(t *testing.T) {
	// Generate keys of different types
	rsaPriv, _ := NewRSAKeyPair(2048)
	ecdsaPriv, _ := NewECDSAKeyPair(algo.P256)
	ed25519Priv, _ := NewEd25519KeyPair()

	// Convert to PEM
	rsaPEM, _ := PrivateKeyToPEM(rsaPriv)
	ecdsaPEM, _ := PrivateKeyToPEM(ecdsaPriv)
	ed25519PEM, _ := PrivateKeyToPEM(ed25519Priv)

	// Test parsing with correct types using existing functions
	parsedRSA, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](rsaPEM)
	if err != nil {
		t.Fatalf("Failed to parse RSA key: %v", err)
	}
	if parsedRSA.Size() != rsaPriv.Size() {
		t.Error("Parsed RSA key doesn't match original")
	}

	parsedECDSA, err := ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](ecdsaPEM)
	if err != nil {
		t.Fatalf("Failed to parse ECDSA key: %v", err)
	}
	if parsedECDSA.Curve.Params().BitSize != ecdsaPriv.Curve.Params().BitSize {
		t.Error("Parsed ECDSA key doesn't match original")
	}

	parsedEd25519, err := ParsePrivateKeyFromPEM[ed25519.PrivateKey](ed25519PEM)
	if err != nil {
		t.Fatalf("Failed to parse Ed25519 key: %v", err)
	}
	if len(parsedEd25519) != len(ed25519Priv) {
		t.Error("Parsed Ed25519 key doesn't match original")
	}
}

func TestDetectAlgorithmFromPEM(t *testing.T) {
	// Generate keys of different types
	rsaPriv, _ := NewRSAKeyPair(2048)
	ecdsaPriv, _ := NewECDSAKeyPair(algo.P256)
	ed25519Priv, _ := NewEd25519KeyPair()

	// Convert to PEM
	rsaPEM, _ := PrivateKeyToPEM(rsaPriv)
	ecdsaPEM, _ := PrivateKeyToPEM(ecdsaPriv)
	ed25519PEM, _ := PrivateKeyToPEM(ed25519Priv)

	// Test algorithm detection
	rsaAlgo, err := DetectAlgorithmFromPEM(rsaPEM)
	if err != nil {
		t.Fatalf("Failed to detect RSA algorithm: %v", err)
	}
	if rsaAlgo != "RSA" {
		t.Errorf("Expected RSA, got %s", rsaAlgo)
	}

	ecdsaAlgo, err := DetectAlgorithmFromPEM(ecdsaPEM)
	if err != nil {
		t.Fatalf("Failed to detect ECDSA algorithm: %v", err)
	}
	if ecdsaAlgo != "ECDSA" {
		t.Errorf("Expected ECDSA, got %s", ecdsaAlgo)
	}

	ed25519Algo, err := DetectAlgorithmFromPEM(ed25519PEM)
	if err != nil {
		t.Fatalf("Failed to detect Ed25519 algorithm: %v", err)
	}
	if ed25519Algo != "Ed25519" {
		t.Errorf("Expected Ed25519, got %s", ed25519Algo)
	}
}

func TestParseAnyPrivateKeyFromPEM(t *testing.T) {
	// Generate keys of different types
	rsaPriv, _ := NewRSAKeyPair(2048)
	ecdsaPriv, _ := NewECDSAKeyPair(algo.P256)
	ed25519Priv, _ := NewEd25519KeyPair()

	// Convert to PEM
	rsaPEM, _ := PrivateKeyToPEM(rsaPriv)
	ecdsaPEM, _ := PrivateKeyToPEM(ecdsaPriv)
	ed25519PEM, _ := PrivateKeyToPEM(ed25519Priv)

	testCases := []struct {
		name     string
		pemData  []byte
		expected string
	}{
		{"RSA", rsaPEM, "RSA"},
		{"ECDSA", ecdsaPEM, "ECDSA"},
		{"Ed25519", ed25519PEM, "Ed25519"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, algorithm, err := ParseAnyPrivateKeyFromPEM(tc.pemData)
			if err != nil {
				t.Fatalf("Failed to parse %s key: %v", tc.name, err)
			}

			if algorithm != tc.expected {
				t.Errorf("Expected algorithm %s, got %s", tc.expected, algorithm)
			}

			if key == nil {
				t.Error("Parsed key is nil")
			}

			// Verify the key type
			switch tc.expected {
			case "RSA":
				if _, ok := key.(*rsa.PrivateKey); !ok {
					t.Error("Expected RSA private key")
				}
			case "ECDSA":
				if _, ok := key.(*ecdsa.PrivateKey); !ok {
					t.Error("Expected ECDSA private key")
				}
			case "Ed25519":
				if _, ok := key.(ed25519.PrivateKey); !ok {
					t.Error("Expected Ed25519 private key")
				}
			}
		})
	}
}

func TestSaveKeyPairToFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Test RSA
	rsaPriv, err := NewRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	rsaPub := RSAPublicKeyFromPrivate(rsaPriv)

	rsaPrivFile := filepath.Join(tempDir, "rsa_private.pem")
	rsaPubFile := filepath.Join(tempDir, "rsa_public.pem")

	err = SaveKeyPairToFiles(rsaPriv, rsaPub, rsaPrivFile, rsaPubFile)
	if err != nil {
		t.Fatalf("Failed to save RSA key pair: %v", err)
	}

	// Verify files exist and contain data
	if _, err := os.Stat(rsaPrivFile); os.IsNotExist(err) {
		t.Error("RSA private key file was not created")
	}

	if _, err := os.Stat(rsaPubFile); os.IsNotExist(err) {
		t.Error("RSA public key file was not created")
	}

	// Test loading the saved key
	savedPEM, err := os.ReadFile(rsaPrivFile)
	if err != nil {
		t.Fatalf("Failed to read saved RSA private key: %v", err)
	}

	loadedRSA, err := ParsePrivateKeyFromPEM[*rsa.PrivateKey](savedPEM)
	if err != nil {
		t.Fatalf("Failed to parse loaded RSA key: %v", err)
	}

	if loadedRSA.Size() != rsaPriv.Size() {
		t.Error("Loaded RSA key doesn't match original")
	}
}

func TestInvalidInputs(t *testing.T) {
	// Test invalid key size for RSA
	_, err := NewRSAKeyPair(1024) // Too small
	if err == nil {
		t.Error("Expected error for invalid RSA key size")
	}

	// Test invalid PEM data
	invalidPEM := []byte("invalid pem data")

	_, err = DetectAlgorithmFromPEM(invalidPEM)
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}

	_, _, err = ParseAnyPrivateKeyFromPEM(invalidPEM)
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}
}