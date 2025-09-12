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
	// Test the new function signature that returns both keys
	rsaPrivateKey, rsaPublicKey, err := GenerateRSAKeyPair(2048)
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

	// Test public key returned directly
	if rsaPublicKey.N.BitLen() != 2048 {
		t.Errorf("Expected RSA public key bit length 2048, got %d", rsaPublicKey.N.BitLen())
	}
}

func TestGenerateECDSAKeyPairGeneric(t *testing.T) {
	// Test the new function signature that returns both keys
	ecdsaPrivateKey, ecdsaPublicKey, err := GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	if ecdsaPrivateKey.Curve.Params().BitSize != 256 {
		t.Errorf("Expected ECDSA curve bit size 256, got %d", ecdsaPrivateKey.Curve.Params().BitSize)
	}

	// Test public key returned directly
	if ecdsaPublicKey.Curve.Params().BitSize != 256 {
		t.Errorf("Expected ECDSA public key curve bit size 256, got %d", ecdsaPublicKey.Curve.Params().BitSize)
	}
}

func TestGenerateEd25519KeyPairGeneric(t *testing.T) {
	// Test the new function signature that returns both keys
	ed25519PrivateKey, ed25519PublicKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	if len(ed25519PrivateKey) != 64 {
		t.Errorf("Expected Ed25519 private key length 64, got %d", len(ed25519PrivateKey))
	}

	// Test public key returned directly
	if len(ed25519PublicKey) != 32 {
		t.Errorf("Expected Ed25519 public key length 32, got %d", len(ed25519PublicKey))
	}
}

func TestGenerateKeyPairFunctions(t *testing.T) {
	// Test GenerateRSAKeyPair
	rsaPrivateKey, rsaPublicKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	if rsaPrivateKey.Size() != 256 {
		t.Errorf("Expected RSA key size 256 bytes, got %d", rsaPrivateKey.Size())
	}
	if rsaPublicKey.N.BitLen() != 2048 {
		t.Errorf("Expected RSA public key bit length 2048, got %d", rsaPublicKey.N.BitLen())
	}

	// Test GenerateECDSAKeyPair
	ecdsaPrivateKey, ecdsaPublicKey, err := GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	if ecdsaPrivateKey.Curve.Params().BitSize != 256 {
		t.Errorf("Expected ECDSA curve bit size 256, got %d", ecdsaPrivateKey.Curve.Params().BitSize)
	}
	if ecdsaPublicKey.Curve.Params().BitSize != 256 {
		t.Errorf("Expected ECDSA public key curve bit size 256, got %d", ecdsaPublicKey.Curve.Params().BitSize)
	}

	// Test GenerateEd25519KeyPair
	ed25519PrivateKey, ed25519PublicKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	if len(ed25519PrivateKey) != 64 {
		t.Errorf("Expected Ed25519 private key length 64, got %d", len(ed25519PrivateKey))
	}
	if len(ed25519PublicKey) != 32 {
		t.Errorf("Expected Ed25519 public key length 32, got %d", len(ed25519PublicKey))
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
				priv, pub, err := GenerateRSAKeyPair(2048)
				return priv, pub, err
			},
		},
		{
			name:    "ECDSA",
			keyType: "ECDSA",
			genFunc: func() (interface{}, interface{}, error) {
				priv, pub, err := GenerateECDSAKeyPair(algo.P256)
				return priv, pub, err
			},
		},
		{
			name:    "Ed25519",
			keyType: "Ed25519",
			genFunc: func() (interface{}, interface{}, error) {
				priv, pub, err := GenerateEd25519KeyPair()
				return priv, pub, err
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
	rsaPriv, rsaPub, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	rsaPrivPEM, rsaPubPEM, err := ConvertKeyPairToPEM(rsaPriv, rsaPub)
	if err != nil {
		t.Fatalf("Failed to convert RSA key pair to PEM: %v", err)
	}

	if len(rsaPrivPEM) == 0 || len(rsaPubPEM) == 0 {
		t.Fatal("RSA PEM data is empty")
	}

	// Test ECDSA
	ecdsaPriv, ecdsaPub, err := GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ecdsaPrivPEM, ecdsaPubPEM, err := ConvertKeyPairToPEM(ecdsaPriv, ecdsaPub)
	if err != nil {
		t.Fatalf("Failed to convert ECDSA key pair to PEM: %v", err)
	}

	if len(ecdsaPrivPEM) == 0 || len(ecdsaPubPEM) == 0 {
		t.Fatal("ECDSA PEM data is empty")
	}

	// Test Ed25519
	ed25519Priv, ed25519Pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	ed25519PrivPEM, ed25519PubPEM, err := ConvertKeyPairToPEM(ed25519Priv, ed25519Pub)
	if err != nil {
		t.Fatalf("Failed to convert Ed25519 key pair to PEM: %v", err)
	}

	if len(ed25519PrivPEM) == 0 || len(ed25519PubPEM) == 0 {
		t.Fatal("Ed25519 PEM data is empty")
	}
}

func TestParseWithGenerics(t *testing.T) {
	// Generate keys of different types
	rsaPriv, _, _ := GenerateRSAKeyPair(2048)
	ecdsaPriv, _, _ := GenerateECDSAKeyPair(algo.P256)
	ed25519Priv, _, _ := GenerateEd25519KeyPair()

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
	rsaPriv, _, _ := GenerateRSAKeyPair(2048)
	ecdsaPriv, _, _ := GenerateECDSAKeyPair(algo.P256)
	ed25519Priv, _, _ := GenerateEd25519KeyPair()

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
	rsaPriv, _, _ := GenerateRSAKeyPair(2048)
	ecdsaPriv, _, _ := GenerateECDSAKeyPair(algo.P256)
	ed25519Priv, _, _ := GenerateEd25519KeyPair()

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
	rsaPriv, rsaPub, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

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
	_, _, err := GenerateRSAKeyPair(1024) // Too small
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

func TestGenerateRSAKeyPair(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(2048)
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
	keyPair, err := algo.GenerateRSAKeyPair(2048)
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

	loadedKeyPair, err := algo.RSAKeyPairFromPEM(privatePEM)
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
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
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
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
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

	loadedKeyPair, err := algo.ECDSAKeyPairFromPEM(privatePEM)
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
	keyPair, err := algo.GenerateEd25519KeyPair()
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
	keyPair, err := algo.GenerateEd25519KeyPair()
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

	loadedKeyPair, err := algo.Ed25519KeyPairFromPEM(privatePEM)
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
	_, err := algo.GenerateRSAKeyPair(1024)
	if err == nil {
		t.Fatal("Expected error for RSA key size less than 2048")
	}
}

func TestPEMValidation(t *testing.T) {
	keyPair, err := algo.GenerateRSAKeyPair(2048)
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
	rsaKeyPair, _ := algo.GenerateRSAKeyPair(2048)
	ecdsaKeyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
	ed25519KeyPair, _ := algo.GenerateEd25519KeyPair()

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
	rsaKeyPair, _ := algo.GenerateRSAKeyPair(2048)
	ecdsaKeyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
	ed25519KeyPair, _ := algo.GenerateEd25519KeyPair()

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

	if _, err := os.Stat(existingFile); os.IsNotExist(err) {
		t.Fatal("FileExists returned false for existing file")
	}

	if _, err := os.Stat(nonExistentFile); !os.IsNotExist(err) {
		t.Fatal("FileExists returned true for non-existent file")
	}
}

func TestSaveAndLoadPEMRoundtrip(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "roundtrip.pem")

	keyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalPEM, err := keyPair.PrivateKeyToPEM()
	if err != nil {
		t.Fatalf("Failed to convert to PEM: %v", err)
	}

	err = os.WriteFile(testFile, originalPEM, 0600)
	if err != nil {
		t.Fatalf("Failed to save PEM: %v", err)
	}

	loadedPEM, err := os.ReadFile(testFile)
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
