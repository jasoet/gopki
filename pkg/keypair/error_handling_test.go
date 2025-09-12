package keypair

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jasoet/gopki/pkg/utils"
)

func TestRSAKeySizeEdgeCases(t *testing.T) {
	testCases := []struct {
		keySize     int
		expectError bool
		description string
	}{
		{1024, true, "1024-bit RSA (too small)"},
		{2047, true, "2047-bit RSA (one bit under minimum)"},
		{2048, false, "2048-bit RSA (minimum valid)"},
		{3072, false, "3072-bit RSA (valid)"},
		{4096, false, "4096-bit RSA (valid)"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			_, err := GenerateRSAKeyPair(tc.keySize)
			if tc.expectError && err == nil {
				t.Fatalf("Expected error for %s but got none", tc.description)
			}
			if !tc.expectError && err != nil {
				t.Fatalf("Unexpected error for %s: %v", tc.description, err)
			}
		})
	}
}

func TestECDSACurveTypes(t *testing.T) {
	curves := []ECDSACurve{
		P224,
		P256,
		P384,
		P521,
	}

	for _, curve := range curves {
		t.Run(curve.Curve().Params().Name, func(t *testing.T) {
			keyPair, err := GenerateECDSAKeyPair(curve)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair with curve %s: %v", curve.Curve().Params().Name, err)
			}

			if keyPair.PrivateKey.Curve != curve.Curve() {
				t.Fatalf("Generated key pair has wrong curve")
			}
		})
	}
}

func TestInvalidPEMParsing(t *testing.T) {
	testCases := []struct {
		name    string
		pemData []byte
	}{
		{
			name:    "Empty data",
			pemData: []byte(""),
		},
		{
			name:    "Non-PEM data",
			pemData: []byte("this is not pem data"),
		},
		{
			name: "Malformed PEM block",
			pemData: []byte(`-----BEGIN PRIVATE KEY-----
malformed data here
-----END PRIVATE KEY-----`),
		},
		{
			name: "Invalid key data",
			pemData: []byte(`-----BEGIN PRIVATE KEY-----
InvalidBase64DataThatCannotBeParsed!@#$%^&*()
-----END PRIVATE KEY-----`),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RSAKeyPairFromPEM(tc.pemData)
			if err == nil {
				t.Fatalf("Expected error for %s but got none", tc.name)
			}

			_, err = ECDSAKeyPairFromPEM(tc.pemData)
			if err == nil {
				t.Fatalf("Expected error for %s but got none", tc.name)
			}

			_, err = Ed25519KeyPairFromPEM(tc.pemData)
			if err == nil {
				t.Fatalf("Expected error for %s but got none", tc.name)
			}
		})
	}
}

func TestFileOperationErrors(t *testing.T) {
	t.Run("Load non-existent file", func(t *testing.T) {
		_, err := utils.LoadPEMFromFile("/non/existent/path/file.pem")
		if err == nil {
			t.Fatal("Expected error when loading non-existent file")
		}
	})

	t.Run("Save to invalid directory", func(t *testing.T) {
		keyPair, _ := GenerateRSAKeyPair(2048)
		pemData, _ := keyPair.PrivateKeyToPEM()
		
		err := utils.SavePEMToFile(pemData, "/invalid/directory/file.pem")
		if err == nil {
			t.Fatal("Expected error when saving to invalid directory")
		}
	})

	t.Run("Save to read-only directory", func(t *testing.T) {
		tempDir := t.TempDir()
		readOnlyDir := filepath.Join(tempDir, "readonly")
		
		err := os.Mkdir(readOnlyDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create test directory: %v", err)
		}
		
		err = os.Chmod(readOnlyDir, 0444)
		if err != nil {
			t.Fatalf("Failed to change directory permissions: %v", err)
		}
		
		defer os.Chmod(readOnlyDir, 0755)
		
		keyPair, _ := GenerateRSAKeyPair(2048)
		pemData, _ := keyPair.PrivateKeyToPEM()
		
		err = utils.SavePEMToFile(pemData, filepath.Join(readOnlyDir, "test.pem"))
		if err == nil {
			t.Fatal("Expected error when saving to read-only directory")
		}
	})
}

func TestNilKeyHandling(t *testing.T) {
	t.Run("RSA nil key PEM conversion", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Expected panic when converting nil RSA private key to PEM")
			}
		}()
		
		keyPair := &RSAKeyPair{}
		keyPair.PrivateKeyToPEM()
	})

	t.Run("ECDSA nil key PEM conversion", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Expected panic when converting nil ECDSA private key to PEM")
			}
		}()
		
		keyPair := &ECDSAKeyPair{}
		keyPair.PrivateKeyToPEM()
	})

	t.Run("Ed25519 nil key PEM conversion", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Expected panic when converting nil Ed25519 private key to PEM")
			}
		}()
		
		keyPair := &Ed25519KeyPair{}
		keyPair.PrivateKeyToPEM()
	})
}

func TestCrossAlgorithmKeyMisuse(t *testing.T) {
	rsaKeyPair, _ := GenerateRSAKeyPair(2048)
	ecdsaKeyPair, _ := GenerateECDSAKeyPair(P256)
	ed25519KeyPair, _ := GenerateEd25519KeyPair()

	rsaPEM, _ := rsaKeyPair.PrivateKeyToPEM()
	ecdsaPEM, _ := ecdsaKeyPair.PrivateKeyToPEM()
	ed25519PEM, _ := ed25519KeyPair.PrivateKeyToPEM()

	t.Run("Use RSA PEM with ECDSA parser", func(t *testing.T) {
		_, err := ECDSAKeyPairFromPEM(rsaPEM)
		if err == nil {
			t.Fatal("Expected error when parsing RSA key as ECDSA")
		}
	})

	t.Run("Use RSA PEM with Ed25519 parser", func(t *testing.T) {
		_, err := Ed25519KeyPairFromPEM(rsaPEM)
		if err == nil {
			t.Fatal("Expected error when parsing RSA key as Ed25519")
		}
	})

	t.Run("Use ECDSA PEM with RSA parser", func(t *testing.T) {
		_, err := RSAKeyPairFromPEM(ecdsaPEM)
		if err == nil {
			t.Fatal("Expected error when parsing ECDSA key as RSA")
		}
	})

	t.Run("Use ECDSA PEM with Ed25519 parser", func(t *testing.T) {
		_, err := Ed25519KeyPairFromPEM(ecdsaPEM)
		if err == nil {
			t.Fatal("Expected error when parsing ECDSA key as Ed25519")
		}
	})

	t.Run("Use Ed25519 PEM with RSA parser", func(t *testing.T) {
		_, err := RSAKeyPairFromPEM(ed25519PEM)
		if err == nil {
			t.Fatal("Expected error when parsing Ed25519 key as RSA")
		}
	})

	t.Run("Use Ed25519 PEM with ECDSA parser", func(t *testing.T) {
		_, err := ECDSAKeyPairFromPEM(ed25519PEM)
		if err == nil {
			t.Fatal("Expected error when parsing Ed25519 key as ECDSA")
		}
	})
}