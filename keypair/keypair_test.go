package keypair

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/keypair/format"
)

// Test Manager creation and basic functionality
func TestNewManager(t *testing.T) {
	// Test RSA key pair
	rsaKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	manager := NewManager(rsaKeyPair, rsaKeyPair.PrivateKey, rsaKeyPair.PublicKey)
	if manager == nil {
		t.Fatal("NewManager returned nil")
	}

	// Test that the manager stores the correct values
	if manager.KeyPair() != rsaKeyPair {
		t.Error("KeyPair() did not return the expected key pair")
	}

	if manager.PrivateKey() != rsaKeyPair.PrivateKey {
		t.Error("PrivateKey() did not return the expected private key")
	}

	if manager.PublicKey() != rsaKeyPair.PublicKey {
		t.Error("PublicKey() did not return the expected public key")
	}
}

// Test Generate function for all key types
func TestGenerate(t *testing.T) {
	tests := []struct {
		name      string
		param     interface{}
		keyType   string
		algorithm string
	}{
		{
			name:      "RSA 2048",
			param:     algo.KeySize2048,
			keyType:   "*algo.RSAKeyPair",
			algorithm: "RSA",
		},
		{
			name:      "RSA 3072",
			param:     algo.KeySize3072,
			keyType:   "*algo.RSAKeyPair",
			algorithm: "RSA",
		},
		{
			name:      "ECDSA P256",
			param:     algo.P256,
			keyType:   "*algo.ECDSAKeyPair",
			algorithm: "ECDSA",
		},
		{
			name:      "ECDSA P384",
			param:     algo.P384,
			keyType:   "*algo.ECDSAKeyPair",
			algorithm: "ECDSA",
		},
		{
			name:      "Ed25519",
			param:     algo.Ed25519Config(""),
			keyType:   "*algo.Ed25519KeyPair",
			algorithm: "Ed25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var manager interface{}
			var err error

			switch param := tt.param.(type) {
			case algo.KeySize:
				manager, err = Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](param)
			case algo.ECDSACurve:
				manager, err = Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](param)
			case algo.Ed25519Config:
				manager, err = Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](param)
			default:
				t.Fatalf("Unknown parameter type: %T", param)
			}

			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			if manager == nil {
				t.Fatal("Generate returned nil manager")
			}

			// Type-specific tests
			switch tt.algorithm {
			case "RSA":
				rsaManager := manager.(*Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey])
				if rsaManager.PrivateKey() == nil {
					t.Error("RSA private key is nil")
				}
				if rsaManager.PublicKey() == nil {
					t.Error("RSA public key is nil")
				}

				// Test key info
				info, err := rsaManager.GetInfo()
				if err != nil {
					t.Errorf("GetInfo failed: %v", err)
				}
				if info.Algorithm != "RSA" {
					t.Errorf("Expected algorithm RSA, got %s", info.Algorithm)
				}

			case "ECDSA":
				ecdsaManager := manager.(*Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey])
				if ecdsaManager.PrivateKey() == nil {
					t.Error("ECDSA private key is nil")
				}
				if ecdsaManager.PublicKey() == nil {
					t.Error("ECDSA public key is nil")
				}

				// Test key info
				info, err := ecdsaManager.GetInfo()
				if err != nil {
					t.Errorf("GetInfo failed: %v", err)
				}
				if info.Algorithm != "ECDSA" {
					t.Errorf("Expected algorithm ECDSA, got %s", info.Algorithm)
				}

			case "Ed25519":
				ed25519Manager := manager.(*Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey])
				if len(ed25519Manager.PrivateKey()) == 0 {
					t.Error("Ed25519 private key is empty")
				}
				if len(ed25519Manager.PublicKey()) == 0 {
					t.Error("Ed25519 public key is empty")
				}

				// Test key info
				info, err := ed25519Manager.GetInfo()
				if err != nil {
					t.Errorf("GetInfo failed: %v", err)
				}
				if info.Algorithm != "Ed25519" {
					t.Errorf("Expected algorithm Ed25519, got %s", info.Algorithm)
				}
			}
		})
	}
}

// Test format conversion methods
func TestFormatConversion(t *testing.T) {
	// Test with RSA key pair
	rsaManager, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA manager: %v", err)
	}

	t.Run("ToPEM", func(t *testing.T) {
		privatePEM, publicPEM, err := rsaManager.ToPEM()
		if err != nil {
			t.Fatalf("ToPEM failed: %v", err)
		}

		if len(privatePEM) == 0 {
			t.Error("Private key PEM is empty")
		}
		if len(publicPEM) == 0 {
			t.Error("Public key PEM is empty")
		}

		// Check PEM format
		if !strings.Contains(string(privatePEM), "-----BEGIN PRIVATE KEY-----") {
			t.Error("Private key PEM missing header")
		}
		if !strings.Contains(string(publicPEM), "-----BEGIN PUBLIC KEY-----") {
			t.Error("Public key PEM missing header")
		}
	})

	t.Run("ToDER", func(t *testing.T) {
		privateDER, publicDER, err := rsaManager.ToDER()
		if err != nil {
			t.Fatalf("ToDER failed: %v", err)
		}

		if len(privateDER) == 0 {
			t.Error("Private key DER is empty")
		}
		if len(publicDER) == 0 {
			t.Error("Public key DER is empty")
		}
	})

	t.Run("ToSSH", func(t *testing.T) {
		privateSSH, publicSSH, err := rsaManager.ToSSH("test@example.com", "")
		if err != nil {
			t.Fatalf("ToSSH failed: %v", err)
		}

		if len(privateSSH) == 0 {
			t.Error("Private key SSH is empty")
		}
		if len(publicSSH) == 0 {
			t.Error("Public key SSH is empty")
		}

		// Check SSH format
		if !strings.Contains(string(publicSSH), "ssh-rsa") {
			t.Error("Public key SSH missing ssh-rsa prefix")
		}
		if !strings.Contains(string(publicSSH), "test@example.com") {
			t.Error("Public key SSH missing comment")
		}
	})
}

// Test file I/O operations
func TestFileIO(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "keypair_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate test key pair
	manager, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate manager: %v", err)
	}

	t.Run("SaveToPEM", func(t *testing.T) {
		privateFile := filepath.Join(tempDir, "private.pem")
		publicFile := filepath.Join(tempDir, "public.pem")

		err := manager.SaveToPEM(privateFile, publicFile)
		if err != nil {
			t.Fatalf("SaveToPEM failed: %v", err)
		}

		// Verify files exist
		if _, err := os.Stat(privateFile); os.IsNotExist(err) {
			t.Error("Private key file was not created")
		}
		if _, err := os.Stat(publicFile); os.IsNotExist(err) {
			t.Error("Public key file was not created")
		}

		// Test loading back
		loadedManager, err := LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](privateFile)
		if err != nil {
			t.Fatalf("LoadFromPEM failed: %v", err)
		}

		// Compare keys
		if !manager.CompareWith(loadedManager) {
			t.Error("Loaded key pair does not match original")
		}
	})

	t.Run("SaveToDER", func(t *testing.T) {
		privateFile := filepath.Join(tempDir, "private.der")
		publicFile := filepath.Join(tempDir, "public.der")

		err := manager.SaveToDER(privateFile, publicFile)
		if err != nil {
			t.Fatalf("SaveToDER failed: %v", err)
		}

		// Verify files exist
		if _, err := os.Stat(privateFile); os.IsNotExist(err) {
			t.Error("Private key DER file was not created")
		}
		if _, err := os.Stat(publicFile); os.IsNotExist(err) {
			t.Error("Public key DER file was not created")
		}

		// Test loading back
		loadedManager, err := LoadFromDER[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](privateFile)
		if err != nil {
			t.Fatalf("LoadFromDER failed: %v", err)
		}

		// Compare keys
		if !manager.CompareWith(loadedManager) {
			t.Error("Loaded DER key pair does not match original")
		}
	})

	t.Run("SaveToSSH", func(t *testing.T) {
		privateFile := filepath.Join(tempDir, "id_rsa")
		publicFile := filepath.Join(tempDir, "id_rsa.pub")

		err := manager.SaveToSSH(privateFile, publicFile, "test@example.com", "")
		if err != nil {
			t.Fatalf("SaveToSSH failed: %v", err)
		}

		// Verify files exist
		if _, err := os.Stat(privateFile); os.IsNotExist(err) {
			t.Error("Private key SSH file was not created")
		}
		if _, err := os.Stat(publicFile); os.IsNotExist(err) {
			t.Error("Public key SSH file was not created")
		}

		// Test loading back
		loadedManager, err := LoadFromSSH[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](privateFile, "")
		if err != nil {
			t.Fatalf("LoadFromSSH failed: %v", err)
		}

		// Compare keys
		if !manager.CompareWith(loadedManager) {
			t.Error("Loaded SSH key pair does not match original")
		}
	})
}

// Test validation methods
func TestValidation(t *testing.T) {
	// Test valid key pair
	manager, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate manager: %v", err)
	}

	t.Run("Validate", func(t *testing.T) {
		err := manager.Validate()
		if err != nil {
			t.Errorf("Validation failed for valid key pair: %v", err)
		}
	})

	t.Run("ValidatePrivateKey", func(t *testing.T) {
		err := manager.ValidatePrivateKey()
		if err != nil {
			t.Errorf("Private key validation failed: %v", err)
		}
	})

	t.Run("IsValid", func(t *testing.T) {
		if !manager.IsValid() {
			t.Error("IsValid returned false for valid manager")
		}
	})

	t.Run("GetInfo", func(t *testing.T) {
		info, err := manager.GetInfo()
		if err != nil {
			t.Errorf("GetInfo failed: %v", err)
		}

		if info.Algorithm != "RSA" {
			t.Errorf("Expected algorithm RSA, got %s", info.Algorithm)
		}
		if info.KeySize != 2048 {
			t.Errorf("Expected key size 2048, got %d", info.KeySize)
		}
		if info.Curve != "" {
			t.Errorf("Expected empty curve for RSA, got %s", info.Curve)
		}
	})
}

// Test comparison methods
func TestComparison(t *testing.T) {
	// Generate two different key pairs
	manager1, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate first manager: %v", err)
	}

	manager2, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate second manager: %v", err)
	}

	// Create identical manager
	manager3 := NewManager(manager1.KeyPair(), manager1.PrivateKey(), manager1.PublicKey())

	t.Run("CompareWith", func(t *testing.T) {
		// Different key pairs should not be equal
		if manager1.CompareWith(manager2) {
			t.Error("Different key pairs should not be equal")
		}

		// Identical key pairs should be equal
		if !manager1.CompareWith(manager3) {
			t.Error("Identical key pairs should be equal")
		}
	})

	t.Run("ComparePrivateKeys", func(t *testing.T) {
		if manager1.ComparePrivateKeys(manager2) {
			t.Error("Different private keys should not be equal")
		}

		if !manager1.ComparePrivateKeys(manager3) {
			t.Error("Identical private keys should be equal")
		}
	})

	t.Run("ComparePublicKeys", func(t *testing.T) {
		if manager1.ComparePublicKeys(manager2) {
			t.Error("Different public keys should not be equal")
		}

		if !manager1.ComparePublicKeys(manager3) {
			t.Error("Identical public keys should be equal")
		}
	})
}

// Test utility methods
func TestUtilityMethods(t *testing.T) {
	manager, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate manager: %v", err)
	}

	t.Run("Clone", func(t *testing.T) {
		cloned := manager.Clone()
		if cloned == nil {
			t.Fatal("Clone returned nil")
		}

		// Should be different instances
		if manager == cloned {
			t.Error("Clone returned same instance")
		}

		// But should have same key data
		if !manager.CompareWith(cloned) {
			t.Error("Cloned manager should have identical keys")
		}
	})

	t.Run("IsValid", func(t *testing.T) {
		if !manager.IsValid() {
			t.Error("Valid manager should return true for IsValid")
		}

		// Test with nil manager
		var nilManager *Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]
		if nilManager.IsValid() {
			t.Error("Nil manager should return false for IsValid")
		}
	})
}

// Test LoadFromData functions with raw format data
func TestLoadFromData(t *testing.T) {
	// Generate test data
	manager, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate manager: %v", err)
	}

	t.Run("LoadFromPEMData", func(t *testing.T) {
		// Test RSA
		t.Run("RSA", func(t *testing.T) {
			privatePEM, _, err := manager.ToPEM()
			if err != nil {
				t.Fatalf("ToPEM failed: %v", err)
			}

			loadedManager, err := LoadFromPEMData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](privatePEM)
			if err != nil {
				t.Fatalf("LoadFromPEMData failed: %v", err)
			}

			if !manager.CompareWith(loadedManager) {
				t.Error("Loaded PEM data does not match original")
			}
		})

		// Test ECDSA
		t.Run("ECDSA", func(t *testing.T) {
			ecdsaManager, err := Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA manager: %v", err)
			}

			privatePEM, _, err := ecdsaManager.ToPEM()
			if err != nil {
				t.Fatalf("ToPEM failed: %v", err)
			}

			loadedManager, err := LoadFromPEMData[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](privatePEM)
			if err != nil {
				t.Fatalf("LoadFromPEMData failed: %v", err)
			}

			if !ecdsaManager.CompareWith(loadedManager) {
				t.Error("Loaded ECDSA PEM data does not match original")
			}
		})

		// Test Ed25519
		t.Run("Ed25519", func(t *testing.T) {
			ed25519Manager, err := Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Config(""))
			if err != nil {
				t.Fatalf("Failed to generate Ed25519 manager: %v", err)
			}

			privatePEM, _, err := ed25519Manager.ToPEM()
			if err != nil {
				t.Fatalf("ToPEM failed: %v", err)
			}

			loadedManager, err := LoadFromPEMData[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](privatePEM)
			if err != nil {
				t.Fatalf("LoadFromPEMData failed: %v", err)
			}

			if !ed25519Manager.CompareWith(loadedManager) {
				t.Error("Loaded Ed25519 PEM data does not match original")
			}
		})
	})

	t.Run("LoadFromDERData", func(t *testing.T) {
		// Test RSA
		t.Run("RSA", func(t *testing.T) {
			privateDER, _, err := manager.ToDER()
			if err != nil {
				t.Fatalf("ToDER failed: %v", err)
			}

			loadedManager, err := LoadFromDERData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](privateDER)
			if err != nil {
				t.Fatalf("LoadFromDERData failed: %v", err)
			}

			if !manager.CompareWith(loadedManager) {
				t.Error("Loaded DER data does not match original")
			}
		})

		// Test ECDSA
		t.Run("ECDSA", func(t *testing.T) {
			ecdsaManager, err := Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA manager: %v", err)
			}

			privateDER, _, err := ecdsaManager.ToDER()
			if err != nil {
				t.Fatalf("ToDER failed: %v", err)
			}

			loadedManager, err := LoadFromDERData[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](privateDER)
			if err != nil {
				t.Fatalf("LoadFromDERData failed: %v", err)
			}

			if !ecdsaManager.CompareWith(loadedManager) {
				t.Error("Loaded ECDSA DER data does not match original")
			}
		})

		// Test Ed25519
		t.Run("Ed25519", func(t *testing.T) {
			ed25519Manager, err := Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Config(""))
			if err != nil {
				t.Fatalf("Failed to generate Ed25519 manager: %v", err)
			}

			privateDER, _, err := ed25519Manager.ToDER()
			if err != nil {
				t.Fatalf("ToDER failed: %v", err)
			}

			loadedManager, err := LoadFromDERData[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](privateDER)
			if err != nil {
				t.Fatalf("LoadFromDERData failed: %v", err)
			}

			if !ed25519Manager.CompareWith(loadedManager) {
				t.Error("Loaded Ed25519 DER data does not match original")
			}
		})
	})

	t.Run("LoadFromSSHData", func(t *testing.T) {
		// Test RSA
		t.Run("RSA", func(t *testing.T) {
			privateSSH, _, err := manager.ToSSH("test@example.com", "")
			if err != nil {
				t.Fatalf("ToSSH failed: %v", err)
			}

			loadedManager, err := LoadFromSSHData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](privateSSH, "")
			if err != nil {
				t.Fatalf("LoadFromSSHData failed: %v", err)
			}

			if !manager.CompareWith(loadedManager) {
				t.Error("Loaded SSH data does not match original")
			}
		})

		// Test ECDSA
		t.Run("ECDSA", func(t *testing.T) {
			ecdsaManager, err := Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA manager: %v", err)
			}

			privateSSH, _, err := ecdsaManager.ToSSH("test@example.com", "")
			if err != nil {
				t.Fatalf("ToSSH failed: %v", err)
			}

			loadedManager, err := LoadFromSSHData[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](privateSSH, "")
			if err != nil {
				t.Fatalf("LoadFromSSHData failed: %v", err)
			}

			if !ecdsaManager.CompareWith(loadedManager) {
				t.Error("Loaded ECDSA SSH data does not match original")
			}
		})

		// Test Ed25519
		t.Run("Ed25519", func(t *testing.T) {
			ed25519Manager, err := Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Config(""))
			if err != nil {
				t.Fatalf("Failed to generate Ed25519 manager: %v", err)
			}

			privateSSH, _, err := ed25519Manager.ToSSH("test@example.com", "")
			if err != nil {
				t.Fatalf("ToSSH failed: %v", err)
			}

			loadedManager, err := LoadFromSSHData[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](privateSSH, "")
			if err != nil {
				t.Fatalf("LoadFromSSHData failed: %v", err)
			}

			if !ed25519Manager.CompareWith(loadedManager) {
				t.Error("Loaded Ed25519 SSH data does not match original")
			}
		})
	})
}

// Test error cases
func TestErrorCases(t *testing.T) {
	t.Run("LoadFromPEMData_InvalidData", func(t *testing.T) {
		_, err := LoadFromPEMData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](format.PEM("invalid pem data"))
		if err == nil {
			t.Error("Expected error for invalid PEM data")
		}
	})

	t.Run("LoadFromDERData_InvalidData", func(t *testing.T) {
		_, err := LoadFromDERData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](format.DER([]byte("invalid der data")))
		if err == nil {
			t.Error("Expected error for invalid DER data")
		}
	})

	t.Run("LoadFromSSHData_InvalidData", func(t *testing.T) {
		_, err := LoadFromSSHData[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](format.SSH("invalid ssh data"), "")
		if err == nil {
			t.Error("Expected error for invalid SSH data")
		}
	})
}

// Benchmark tests
func BenchmarkGenerate(b *testing.B) {
	b.Run("RSA2048", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
			if err != nil {
				b.Fatalf("Generate failed: %v", err)
			}
		}
	})

	b.Run("ECDSA_P256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
			if err != nil {
				b.Fatalf("Generate failed: %v", err)
			}
		}
	})

	b.Run("Ed25519", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Config(""))
			if err != nil {
				b.Fatalf("Generate failed: %v", err)
			}
		}
	})
}

func BenchmarkFormatConversion(b *testing.B) {
	manager, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		b.Fatalf("Failed to generate manager: %v", err)
	}

	b.Run("ToPEM", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := manager.ToPEM()
			if err != nil {
				b.Fatalf("ToPEM failed: %v", err)
			}
		}
	})

	b.Run("ToDER", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := manager.ToDER()
			if err != nil {
				b.Fatalf("ToDER failed: %v", err)
			}
		}
	})

	b.Run("ToSSH", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := manager.ToSSH("test@example.com", "")
			if err != nil {
				b.Fatalf("ToSSH failed: %v", err)
			}
		}
	})
}

// Test all algorithm types for format conversion methods
func TestFormatConversionAllTypes(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() (interface{}, error)
		testPEM func(manager interface{}) error
		testDER func(manager interface{}) error
		testSSH func(manager interface{}) error
	}{
		{
			name: "RSA",
			setup: func() (interface{}, error) {
				return Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
			},
			testPEM: func(manager interface{}) error {
				m := manager.(*Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey])
				_, _, err := m.ToPEM()
				return err
			},
			testDER: func(manager interface{}) error {
				m := manager.(*Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey])
				_, _, err := m.ToDER()
				return err
			},
			testSSH: func(manager interface{}) error {
				m := manager.(*Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey])
				_, _, err := m.ToSSH("test@example.com", "passphrase")
				return err
			},
		},
		{
			name: "ECDSA",
			setup: func() (interface{}, error) {
				return Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
			},
			testPEM: func(manager interface{}) error {
				m := manager.(*Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey])
				_, _, err := m.ToPEM()
				return err
			},
			testDER: func(manager interface{}) error {
				m := manager.(*Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey])
				_, _, err := m.ToDER()
				return err
			},
			testSSH: func(manager interface{}) error {
				m := manager.(*Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey])
				_, _, err := m.ToSSH("test@example.com", "passphrase")
				return err
			},
		},
		{
			name: "Ed25519",
			setup: func() (interface{}, error) {
				return Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Config(""))
			},
			testPEM: func(manager interface{}) error {
				m := manager.(*Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey])
				_, _, err := m.ToPEM()
				return err
			},
			testDER: func(manager interface{}) error {
				m := manager.(*Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey])
				_, _, err := m.ToDER()
				return err
			},
			testSSH: func(manager interface{}) error {
				m := manager.(*Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey])
				_, _, err := m.ToSSH("test@example.com", "passphrase")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := tt.setup()
			if err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			t.Run("ToPEM", func(t *testing.T) {
				if err := tt.testPEM(manager); err != nil {
					t.Errorf("ToPEM failed: %v", err)
				}
			})

			t.Run("ToDER", func(t *testing.T) {
				if err := tt.testDER(manager); err != nil {
					t.Errorf("ToDER failed: %v", err)
				}
			})

			t.Run("ToSSH", func(t *testing.T) {
				if err := tt.testSSH(manager); err != nil {
					t.Errorf("ToSSH failed: %v", err)
				}
			})
		})
	}
}

// Test validation for all key types
func TestValidationAllTypes(t *testing.T) {
	tests := []struct {
		name         string
		setup        func() (interface{}, error)
		testValidate func(manager interface{}) error
		testPrivate  func(manager interface{}) error
		testGetInfo  func(manager interface{}) (KeyInfo, error)
	}{
		{
			name: "RSA",
			setup: func() (interface{}, error) {
				return Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
			},
			testValidate: func(manager interface{}) error {
				m := manager.(*Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey])
				return m.Validate()
			},
			testPrivate: func(manager interface{}) error {
				m := manager.(*Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey])
				return m.ValidatePrivateKey()
			},
			testGetInfo: func(manager interface{}) (KeyInfo, error) {
				m := manager.(*Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey])
				return m.GetInfo()
			},
		},
		{
			name: "ECDSA",
			setup: func() (interface{}, error) {
				return Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P384)
			},
			testValidate: func(manager interface{}) error {
				m := manager.(*Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey])
				return m.Validate()
			},
			testPrivate: func(manager interface{}) error {
				m := manager.(*Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey])
				return m.ValidatePrivateKey()
			},
			testGetInfo: func(manager interface{}) (KeyInfo, error) {
				m := manager.(*Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey])
				return m.GetInfo()
			},
		},
		{
			name: "Ed25519",
			setup: func() (interface{}, error) {
				return Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Config(""))
			},
			testValidate: func(manager interface{}) error {
				m := manager.(*Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey])
				return m.Validate()
			},
			testPrivate: func(manager interface{}) error {
				m := manager.(*Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey])
				return m.ValidatePrivateKey()
			},
			testGetInfo: func(manager interface{}) (KeyInfo, error) {
				m := manager.(*Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey])
				return m.GetInfo()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := tt.setup()
			if err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			t.Run("Validate", func(t *testing.T) {
				if err := tt.testValidate(manager); err != nil {
					t.Errorf("Validate failed: %v", err)
				}
			})

			t.Run("ValidatePrivateKey", func(t *testing.T) {
				if err := tt.testPrivate(manager); err != nil {
					t.Errorf("ValidatePrivateKey failed: %v", err)
				}
			})

			t.Run("GetInfo", func(t *testing.T) {
				info, err := tt.testGetInfo(manager)
				if err != nil {
					t.Errorf("GetInfo failed: %v", err)
				} else {
					if info.Algorithm == "" {
						t.Error("Algorithm should not be empty")
					}
					if info.KeySize <= 0 {
						t.Error("KeySize should be positive")
					}
				}
			})
		})
	}
}

// Test comparison methods for all key types
func TestComparisonAllTypes(t *testing.T) {
	tests := []struct {
		name  string
		setup func() (interface{}, interface{}, error)
		test  func(manager1, manager2 interface{}) (bool, bool, bool)
	}{
		{
			name: "RSA",
			setup: func() (interface{}, interface{}, error) {
				m1, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
				if err != nil {
					return nil, nil, err
				}
				m2, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
				return m1, m2, err
			},
			test: func(manager1, manager2 interface{}) (bool, bool, bool) {
				m1 := manager1.(*Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey])
				m2 := manager2.(*Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey])
				return m1.CompareWith(m2), m1.ComparePrivateKeys(m2), m1.ComparePublicKeys(m2)
			},
		},
		{
			name: "ECDSA",
			setup: func() (interface{}, interface{}, error) {
				m1, err := Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
				if err != nil {
					return nil, nil, err
				}
				m2, err := Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
				return m1, m2, err
			},
			test: func(manager1, manager2 interface{}) (bool, bool, bool) {
				m1 := manager1.(*Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey])
				m2 := manager2.(*Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey])
				return m1.CompareWith(m2), m1.ComparePrivateKeys(m2), m1.ComparePublicKeys(m2)
			},
		},
		{
			name: "Ed25519",
			setup: func() (interface{}, interface{}, error) {
				m1, err := Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Config(""))
				if err != nil {
					return nil, nil, err
				}
				m2, err := Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Config(""))
				return m1, m2, err
			},
			test: func(manager1, manager2 interface{}) (bool, bool, bool) {
				m1 := manager1.(*Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey])
				m2 := manager2.(*Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey])
				return m1.CompareWith(m2), m1.ComparePrivateKeys(m2), m1.ComparePublicKeys(m2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager1, manager2, err := tt.setup()
			if err != nil {
				t.Fatalf("Setup failed: %v", err)
			}

			compareWith, comparePrivate, comparePublic := tt.test(manager1, manager2)

			// Different keys should not be equal
			if compareWith {
				t.Error("Different key pairs should not be equal")
			}
			if comparePrivate {
				t.Error("Different private keys should not be equal")
			}
			if comparePublic {
				t.Error("Different public keys should not be equal")
			}
		})
	}
}

// Test IsValid for different scenarios
func TestIsValidScenarios(t *testing.T) {
	t.Run("ValidRSAManager", func(t *testing.T) {
		manager, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate manager: %v", err)
		}
		if !manager.IsValid() {
			t.Error("Valid RSA manager should return true")
		}
	})

	t.Run("ValidECDSAManager", func(t *testing.T) {
		manager, err := Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate manager: %v", err)
		}
		if !manager.IsValid() {
			t.Error("Valid ECDSA manager should return true")
		}
	})

	t.Run("ValidEd25519Manager", func(t *testing.T) {
		manager, err := Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Config(""))
		if err != nil {
			t.Fatalf("Failed to generate manager: %v", err)
		}
		if !manager.IsValid() {
			t.Error("Valid Ed25519 manager should return true")
		}
	})

	t.Run("NilManager", func(t *testing.T) {
		var nilManager *Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]
		if nilManager.IsValid() {
			t.Error("Nil manager should return false")
		}
	})
}

// Test LoadFromData error paths with type mismatches
func TestLoadFromDataTypeMismatch(t *testing.T) {
	// Generate an RSA key and try to load it as ECDSA (should fail)
	rsaManager, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA manager: %v", err)
	}

	privatePEM, _, err := rsaManager.ToPEM()
	if err != nil {
		t.Fatalf("Failed to convert to PEM: %v", err)
	}

	t.Run("PEMTypeMismatch", func(t *testing.T) {
		// Try to load RSA key as ECDSA
		_, err := LoadFromPEMData[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](privatePEM)
		if err == nil {
			t.Error("Expected error when loading RSA key as ECDSA")
		}
	})

	privateDER, _, err := rsaManager.ToDER()
	if err != nil {
		t.Fatalf("Failed to convert to DER: %v", err)
	}

	t.Run("DERTypeMismatch", func(t *testing.T) {
		// Try to load RSA key as Ed25519
		_, err := LoadFromDERData[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](privateDER)
		if err == nil {
			t.Error("Expected error when loading RSA key as Ed25519")
		}
	})
}

// Test file I/O error paths
func TestFileIOErrors(t *testing.T) {
	manager, err := Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate manager: %v", err)
	}

	t.Run("SaveToInvalidPath", func(t *testing.T) {
		// Try to save to invalid path
		err := manager.SaveToPEM("/nonexistent/dir/private.pem", "/nonexistent/dir/public.pem")
		if err == nil {
			t.Error("Expected error when saving to invalid path")
		}
	})

	t.Run("SaveDERToInvalidPath", func(t *testing.T) {
		err := manager.SaveToDER("/nonexistent/dir/private.der", "/nonexistent/dir/public.der")
		if err == nil {
			t.Error("Expected error when saving DER to invalid path")
		}
	})

	t.Run("SaveSSHToInvalidPath", func(t *testing.T) {
		err := manager.SaveToSSH("/nonexistent/dir/id_rsa", "/nonexistent/dir/id_rsa.pub", "comment", "")
		if err == nil {
			t.Error("Expected error when saving SSH to invalid path")
		}
	})

	t.Run("LoadFromNonexistentFile", func(t *testing.T) {
		_, err := LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]("/nonexistent/file.pem")
		if err == nil {
			t.Error("Expected error when loading from nonexistent file")
		}
	})

	t.Run("LoadFromDERNonexistentFile", func(t *testing.T) {
		_, err := LoadFromDER[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]("/nonexistent/file.der")
		if err == nil {
			t.Error("Expected error when loading DER from nonexistent file")
		}
	})

	t.Run("LoadFromSSHNonexistentFile", func(t *testing.T) {
		_, err := LoadFromSSH[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]("/nonexistent/file", "")
		if err == nil {
			t.Error("Expected error when loading SSH from nonexistent file")
		}
	})
}

// Test individual format conversion functions
func TestIndividualFormatFunctions(t *testing.T) {
	// Test RSA
	rsaKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	t.Run("PrivateKeyToPEM", func(t *testing.T) {
		pemData, err := PrivateKeyToPEM(rsaKeyPair.PrivateKey)
		if err != nil {
			t.Errorf("PrivateKeyToPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Error("PEM data should not be empty")
		}
	})

	t.Run("PublicKeyToPEM", func(t *testing.T) {
		pemData, err := PublicKeyToPEM(rsaKeyPair.PublicKey)
		if err != nil {
			t.Errorf("PublicKeyToPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Error("PEM data should not be empty")
		}
	})

	t.Run("PrivateKeyToDER", func(t *testing.T) {
		derData, err := PrivateKeyToDER(rsaKeyPair.PrivateKey)
		if err != nil {
			t.Errorf("PrivateKeyToDER failed: %v", err)
		}
		if len(derData) == 0 {
			t.Error("DER data should not be empty")
		}
	})

	t.Run("PublicKeyToDER", func(t *testing.T) {
		derData, err := PublicKeyToDER(rsaKeyPair.PublicKey)
		if err != nil {
			t.Errorf("PublicKeyToDER failed: %v", err)
		}
		if len(derData) == 0 {
			t.Error("DER data should not be empty")
		}
	})

	t.Run("PrivateKeyToSSH", func(t *testing.T) {
		sshData, err := PrivateKeyToSSH(rsaKeyPair.PrivateKey, "comment", "passphrase")
		if err != nil {
			t.Errorf("PrivateKeyToSSH failed: %v", err)
		}
		if len(sshData) == 0 {
			t.Error("SSH data should not be empty")
		}
	})

	t.Run("PublicKeyToSSH", func(t *testing.T) {
		sshData, err := PublicKeyToSSH(rsaKeyPair.PublicKey, "comment")
		if err != nil {
			t.Errorf("PublicKeyToSSH failed: %v", err)
		}
		if len(sshData) == 0 {
			t.Error("SSH data should not be empty")
		}
	})

	// Test ECDSA
	ecdsaKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	t.Run("ECDSAPrivateKeyToPEM", func(t *testing.T) {
		pemData, err := PrivateKeyToPEM(ecdsaKeyPair.PrivateKey)
		if err != nil {
			t.Errorf("ECDSA PrivateKeyToPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Error("ECDSA PEM data should not be empty")
		}
	})

	// Test Ed25519
	ed25519KeyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	t.Run("Ed25519PrivateKeyToPEM", func(t *testing.T) {
		pemData, err := PrivateKeyToPEM(ed25519KeyPair.PrivateKey)
		if err != nil {
			t.Errorf("Ed25519 PrivateKeyToPEM failed: %v", err)
		}
		if len(pemData) == 0 {
			t.Error("Ed25519 PEM data should not be empty")
		}
	})
}
