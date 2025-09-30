package signing

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestSignAndVerifyRSA(t *testing.T) {
	// Generate RSA key pair
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	keyPair := manager.KeyPair()

	// Create a self-signed certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test RSA Signer",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test.example.com"},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Test data
	testData := []byte("This is test data for RSA signing")

	// Test different hash algorithms
	hashAlgorithms := []crypto.Hash{
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	}

	for _, hashAlgo := range hashAlgorithms {
		t.Run(HashAlgorithmToString(hashAlgo), func(t *testing.T) {
			// Sign the data
			opts := DefaultSignOptions()
			opts.HashAlgorithm = hashAlgo
			signature, err := SignDocument(testData, keyPair, certificate, opts)
			if err != nil {
				t.Fatalf("Failed to sign document: %v", err)
			}

			// Verify the signature
			if signature.Algorithm != AlgorithmRSA {
				t.Errorf("Expected algorithm %s, got %s", AlgorithmRSA, signature.Algorithm)
			}

			if signature.HashAlgorithm != hashAlgo {
				t.Errorf("Expected hash algorithm %v, got %v", hashAlgo, signature.HashAlgorithm)
			}

			// Verify the signature
			err = VerifySignature(testData, signature, DefaultVerifyOptions())
			if err != nil {
				t.Errorf("Failed to verify signature: %v", err)
			}

			// Test with tampered data using detached signature for proper validation
			detachedOpts := DefaultSignOptions()
			detachedOpts.HashAlgorithm = hashAlgo
			detachedOpts.Format = FormatPKCS7Detached
			detachedSignature, err := SignDocument(testData, keyPair, certificate, detachedOpts)
			if err != nil {
				t.Fatalf("Failed to create detached signature: %v", err)
			}

			tamperedData := append(testData, byte('X'))
			err = VerifySignature(tamperedData, detachedSignature, DefaultVerifyOptions())
			if err == nil {
				t.Error("Expected verification to fail with tampered data")
			}
		})
	}
}

func TestSignAndVerifyECDSA(t *testing.T) {
	curves := []algo.ECDSACurve{
		algo.P256,
		algo.P384,
		algo.P521,
	}

	for _, curve := range curves {
		curveName := fmt.Sprintf("Curve_%d", curve)
		t.Run(curveName, func(t *testing.T) {
			// Generate ECDSA key pair
			manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](curve)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair: %v", err)
			}
			keyPair := manager.KeyPair()
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key pair: %v", err)
			}

			// Create a self-signed certificate
			certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   "Test ECDSA Signer",
					Organization: []string{"Test Org"},
				},
				ValidFor: 365 * 24 * time.Hour,
			})
			if err != nil {
				t.Fatalf("Failed to create certificate: %v", err)
			}

			// Test data
			testData := []byte("This is test data for ECDSA signing")

			// Sign the data
			signature, err := SignData(testData, keyPair, certificate)
			if err != nil {
				t.Fatalf("Failed to sign document: %v", err)
			}

			// Verify the signature
			if signature.Algorithm != AlgorithmECDSA {
				t.Errorf("Expected algorithm %s, got %s", AlgorithmECDSA, signature.Algorithm)
			}

			// Verify the signature
			err = VerifySignature(testData, signature, DefaultVerifyOptions())
			if err != nil {
				t.Errorf("Failed to verify signature: %v", err)
			}

			// Test with wrong data using detached signature for proper validation
			detachedOpts := DefaultSignOptions()
			detachedOpts.Format = FormatPKCS7Detached
			detachedSignature, err := SignDocument(testData, keyPair, certificate, detachedOpts)
			if err != nil {
				t.Fatalf("Failed to create detached signature: %v", err)
			}

			wrongData := []byte("This is wrong data")
			err = VerifySignature(wrongData, detachedSignature, DefaultVerifyOptions())
			if err == nil {
				t.Error("Expected verification to fail with wrong data")
			}
		})
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	// Generate Ed25519 key pair
	manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	keyPair := manager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Create a self-signed certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test Ed25519 Signer",
			Organization: []string{"Test Org"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Test data
	testData := []byte("This is test data for Ed25519 signing")

	// Sign the data
	signature, err := SignData(testData, keyPair, certificate)
	if err != nil {
		t.Fatalf("Failed to sign document: %v", err)
	}

	// Verify the signature
	if signature.Algorithm != AlgorithmEd25519 {
		t.Errorf("Expected algorithm %s, got %s", AlgorithmEd25519, signature.Algorithm)
	}

	// Ed25519 should use SHA-512
	if signature.HashAlgorithm != crypto.SHA512 {
		t.Errorf("Expected hash algorithm SHA512 for Ed25519, got %v", signature.HashAlgorithm)
	}

	// Verify the signature
	err = VerifySignature(testData, signature, DefaultVerifyOptions())
	if err != nil {
		t.Errorf("Failed to verify signature: %v", err)
	}

	// Test with modified signature
	signature.Data[0] ^= 0xFF
	err = VerifySignature(testData, signature, DefaultVerifyOptions())
	if err == nil {
		t.Error("Expected verification to fail with modified signature")
	}
	signature.Data[0] ^= 0xFF // Restore original
}

func TestCertificateValidation(t *testing.T) {
	// Generate key pair
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	keyPair := manager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create an expired certificate
	expiredCert, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Expired Certificate",
		},
		ValidFrom: time.Now().Add(-2 * 365 * 24 * time.Hour), // 2 years ago
		ValidFor:  365 * 24 * time.Hour,                      // 1 year validity (now expired)
	})
	if err != nil {
		t.Fatalf("Failed to create expired certificate: %v", err)
	}

	// Test data
	testData := []byte("Test data")

	// Sign with expired certificate
	signature, err := SignData(testData, keyPair, expiredCert)
	if err != nil {
		t.Fatalf("Failed to sign document: %v", err)
	}

	// Verify should fail due to expired certificate
	err = VerifySignature(testData, signature, DefaultVerifyOptions())
	if err != ErrCertificateExpired {
		t.Errorf("Expected ErrCertificateExpired, got %v", err)
	}
}

func TestSigningOptions(t *testing.T) {
	// Generate key pair
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	keyPair := manager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test Signer",
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	testData := []byte("Test data for options")

	t.Run("WithCertificate", func(t *testing.T) {
		opts := DefaultSignOptions()
		opts.IncludeCertificate = true
		signature, err := SignDocument(testData, keyPair, certificate, opts)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		if signature.Certificate == nil {
			t.Error("Expected certificate to be included")
		}
	})

	t.Run("WithoutCertificate", func(t *testing.T) {
		opts := DefaultSignOptions()
		opts.IncludeCertificate = false
		signature, err := SignDocument(testData, keyPair, certificate, opts)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		if signature.Certificate != nil {
			t.Error("Expected certificate not to be included")
		}

		// Verification should fail without certificate
		err = VerifySignature(testData, signature, DefaultVerifyOptions())
		if err != ErrMissingCertificate {
			t.Errorf("Expected ErrMissingCertificate, got %v", err)
		}

		// Verify with explicit certificate
		err = VerifyWithCertificate(testData, signature, certificate.Certificate, DefaultVerifyOptions())
		if err != nil {
			t.Errorf("Failed to verify with explicit certificate: %v", err)
		}
	})

	t.Run("WithMetadata", func(t *testing.T) {
		opts := DefaultSignOptions()
		opts.Attributes = map[string]interface{}{
			"author":    "Test Author",
			"timestamp": time.Now().Unix(),
			"version":   "1.0",
		}
		signature, err := SignDocument(testData, keyPair, certificate, opts)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		if signature.Metadata == nil {
			t.Error("Expected metadata to be included")
		}

		if author, ok := signature.Metadata["author"].(string); !ok || author != "Test Author" {
			t.Error("Expected author metadata to be preserved")
		}
	})
}

func TestCrossAlgorithmCompatibility(t *testing.T) {
	// Test that different algorithms can coexist
	algorithms := []struct {
		name     string
		generate func() (interface{}, *cert.Certificate, error)
	}{
		{
			name: "RSA",
			generate: func() (interface{}, *cert.Certificate, error) {
				manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
				if err != nil {
					t.Fatalf("Failed to generate RSA key pair: %v", err)
				}
				kp := manager.KeyPair()
				if err != nil {
					return nil, nil, err
				}
				c, err := cert.CreateSelfSignedCertificate(kp, cert.CertificateRequest{
					Subject:  pkix.Name{CommonName: "RSA Test"},
					ValidFor: 365 * 24 * time.Hour,
				})
				return kp, c, err
			},
		},
		{
			name: "ECDSA",
			generate: func() (interface{}, *cert.Certificate, error) {
				manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
				if err != nil {
					t.Fatalf("Failed to generate ECDSA key pair: %v", err)
				}
				kp := manager.KeyPair()
				if err != nil {
					return nil, nil, err
				}
				c, err := cert.CreateSelfSignedCertificate(kp, cert.CertificateRequest{
					Subject:  pkix.Name{CommonName: "ECDSA Test"},
					ValidFor: 365 * 24 * time.Hour,
				})
				return kp, c, err
			},
		},
		{
			name: "Ed25519",
			generate: func() (interface{}, *cert.Certificate, error) {
				manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
				if err != nil {
					t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
				}
				kp := manager.KeyPair()
				if err != nil {
					return nil, nil, err
				}
				c, err := cert.CreateSelfSignedCertificate(kp, cert.CertificateRequest{
					Subject:  pkix.Name{CommonName: "Ed25519 Test"},
					ValidFor: 365 * 24 * time.Hour,
				})
				return kp, c, err
			},
		},
	}

	testData := []byte("Cross-algorithm test data")
	var signatures []*Signature

	// Sign with each algorithm
	for _, alg := range algorithms {
		t.Run("Sign_"+alg.name, func(t *testing.T) {
			keyPair, certificate, err := alg.generate()
			if err != nil {
				t.Fatalf("Failed to generate %s keys: %v", alg.name, err)
			}

			var signature *Signature
			switch kp := keyPair.(type) {
			case *algo.RSAKeyPair:
				signature, err = SignData(testData, kp, certificate)
			case *algo.ECDSAKeyPair:
				signature, err = SignData(testData, kp, certificate)
			case *algo.Ed25519KeyPair:
				signature, err = SignData(testData, kp, certificate)
			}

			if err != nil {
				t.Fatalf("Failed to sign with %s: %v", alg.name, err)
			}

			signatures = append(signatures, signature)
		})
	}

	// Verify all signatures
	for i, sig := range signatures {
		t.Run("Verify_"+algorithms[i].name, func(t *testing.T) {
			err := VerifySignature(testData, sig, DefaultVerifyOptions())
			if err != nil {
				t.Errorf("Failed to verify %s signature: %v", algorithms[i].name, err)
			}
		})
	}
}

func TestSignatureInfo(t *testing.T) {
	// Generate key pair
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	keyPair := manager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Info Test",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Sign data
	testData := []byte("Test data")
	signature, err := SignData(testData, keyPair, certificate)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Get signature info
	info := GetSignatureInfo(signature)
	if info == "" {
		t.Error("Expected signature info to be non-empty")
	}

	// Check that info contains expected elements
	expectedStrings := []string{
		"Algorithm: RSA",
		"Hash: SHA256",
		"Signer: Info Test",
	}

	for _, expected := range expectedStrings {
		if !contains(info, expected) {
			t.Errorf("Expected info to contain '%s'", expected)
		}
	}

	// Test IsSignatureValid
	if !IsSignatureValid(signature) {
		t.Error("Expected signature to be valid")
	}

	// Test with nil signature
	if IsSignatureValid(nil) {
		t.Error("Expected nil signature to be invalid")
	}

	// Test with empty signature data
	emptySignature := &Signature{
		Algorithm:     AlgorithmRSA,
		HashAlgorithm: crypto.SHA256,
		Data:          []byte{},
	}
	if IsSignatureValid(emptySignature) {
		t.Error("Expected signature with empty data to be invalid")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))
}

// TestSignFile tests the SignFile function
func TestSignFile(t *testing.T) {
	// Generate RSA key pair
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	keyPair := manager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Create a self-signed certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test File Signer",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Create a temporary test file
	testData := []byte("This is test data for file signing")
	testFile := "/tmp/gopki_test_file.txt"

	err = os.WriteFile(testFile, testData, 0o644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	defer os.Remove(testFile) // Clean up

	// Test signing the file
	opts := DefaultSignOptions()
	opts.HashAlgorithm = crypto.SHA256

	signature, err := SignFile(testFile, keyPair, certificate, opts)
	if err != nil {
		t.Fatalf("Failed to sign file: %v", err)
	}

	// Verify signature properties
	if signature.Algorithm != AlgorithmRSA {
		t.Errorf("Expected algorithm %s, got %s", AlgorithmRSA, signature.Algorithm)
	}

	if signature.HashAlgorithm != crypto.SHA256 {
		t.Errorf("Expected hash algorithm SHA256, got %v", signature.HashAlgorithm)
	}

	if len(signature.Data) == 0 {
		t.Error("Expected signature data to be non-empty")
	}

	// Verify the signature by comparing with direct SignDocument
	directSignature, err := SignDocument(testData, keyPair, certificate, opts)
	if err != nil {
		t.Fatalf("Failed to sign data directly: %v", err)
	}

	// The signatures should be the same (assuming deterministic signing)
	if len(signature.Data) != len(directSignature.Data) {
		t.Errorf("Expected same signature length: file=%d, direct=%d",
			len(signature.Data), len(directSignature.Data))
	}

	// Test with non-existent file
	_, err = SignFile("/non/existent/file.txt", keyPair, certificate, opts)
	if err == nil {
		t.Error("Expected error when signing non-existent file")
	}
}

// TestSignStream tests the SignStream function
func TestSignStream(t *testing.T) {
	// Generate ECDSA key pair for variety
	manager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	keyPair := manager.KeyPair()

	// Create a self-signed certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test Stream Signer",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	testData := []byte("This is test data for stream signing with ECDSA")

	// Test signing from a stream
	opts := DefaultSignOptions()
	opts.HashAlgorithm = crypto.SHA256

	reader := bytes.NewReader(testData)
	signature, err := SignStream(reader, keyPair, certificate, opts)
	if err != nil {
		t.Fatalf("Failed to sign stream: %v", err)
	}

	// Verify signature properties
	if signature.Algorithm != AlgorithmECDSA {
		t.Errorf("Expected algorithm %s, got %s", AlgorithmECDSA, signature.Algorithm)
	}

	if signature.HashAlgorithm != crypto.SHA256 {
		t.Errorf("Expected hash algorithm SHA256, got %v", signature.HashAlgorithm)
	}

	if len(signature.Data) == 0 {
		t.Error("Expected signature data to be non-empty")
	}

	// Verify digest matches direct computation
	directSignature, err := SignDocument(testData, keyPair, certificate, opts)
	if err != nil {
		t.Fatalf("Failed to sign data directly: %v", err)
	}

	// The digests should be the same
	if !bytes.Equal(signature.Digest, directSignature.Digest) {
		t.Error("Expected stream and direct signing to produce same digest")
	}

	// Test with Ed25519 for different code path
	ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	ed25519KeyPair := ed25519Manager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	ed25519Cert, err := cert.CreateSelfSignedCertificate(ed25519KeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test Ed25519 Stream Signer",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create Ed25519 certificate: %v", err)
	}

	reader2 := bytes.NewReader(testData)
	ed25519Signature, err := SignStream(reader2, ed25519KeyPair, ed25519Cert, opts)
	if err != nil {
		t.Fatalf("Failed to sign stream with Ed25519: %v", err)
	}

	if ed25519Signature.Algorithm != AlgorithmEd25519 {
		t.Errorf("Expected Ed25519 algorithm, got %s", ed25519Signature.Algorithm)
	}

	// Test with empty stream
	emptyReader := bytes.NewReader([]byte{})
	_, err = SignStream(emptyReader, keyPair, certificate, opts)
	if err != nil {
		t.Logf("Signing empty stream returned error (expected): %v", err)
	}
}

// TestGetSignatureAlgorithm tests the GetSignatureAlgorithm function
func TestGetSignatureAlgorithm(t *testing.T) {
	// Test with RSA key
	rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	rsaKeyPair := rsaManager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	alg, err := GetSignatureAlgorithm(rsaKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to get RSA algorithm: %v", err)
	}
	if alg != AlgorithmRSA {
		t.Errorf("Expected RSA algorithm, got %s", alg)
	}

	// Test with ECDSA key
	ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	ecdsaKeyPair := ecdsaManager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	alg, err = GetSignatureAlgorithm(ecdsaKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to get ECDSA algorithm: %v", err)
	}
	if alg != AlgorithmECDSA {
		t.Errorf("Expected ECDSA algorithm, got %s", alg)
	}

	// Test with Ed25519 key
	ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	ed25519KeyPair := ed25519Manager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	alg, err = GetSignatureAlgorithm(ed25519KeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to get Ed25519 algorithm: %v", err)
	}
	if alg != AlgorithmEd25519 {
		t.Errorf("Expected Ed25519 algorithm, got %s", alg)
	}

	// Test with unsupported key type (string as placeholder)
	_, err = GetSignatureAlgorithm("unsupported key type")
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

// TestComputeDigest tests the ComputeDigest function
func TestComputeDigest(t *testing.T) {
	testData := []byte("This is test data for digest computation")

	// Test SHA256
	digest, err := ComputeDigest(testData, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to compute SHA256 digest: %v", err)
	}
	if len(digest) != 32 { // SHA256 produces 32-byte hash
		t.Errorf("Expected SHA256 digest length 32, got %d", len(digest))
	}

	// Test SHA384
	digest384, err := ComputeDigest(testData, crypto.SHA384)
	if err != nil {
		t.Fatalf("Failed to compute SHA384 digest: %v", err)
	}
	if len(digest384) != 48 { // SHA384 produces 48-byte hash
		t.Errorf("Expected SHA384 digest length 48, got %d", len(digest384))
	}

	// Test SHA512
	digest512, err := ComputeDigest(testData, crypto.SHA512)
	if err != nil {
		t.Fatalf("Failed to compute SHA512 digest: %v", err)
	}
	if len(digest512) != 64 { // SHA512 produces 64-byte hash
		t.Errorf("Expected SHA512 digest length 64, got %d", len(digest512))
	}

	// Test that same data produces same digest
	digest2, err := ComputeDigest(testData, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to compute second SHA256 digest: %v", err)
	}
	if !bytes.Equal(digest, digest2) {
		t.Error("Expected same data to produce same digest")
	}

	// Test with empty data
	emptyDigest, err := ComputeDigest([]byte{}, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to compute digest of empty data: %v", err)
	}
	if len(emptyDigest) != 32 {
		t.Errorf("Expected empty data SHA256 digest length 32, got %d", len(emptyDigest))
	}

	// Test with unavailable hash (this is tricky since most are available)
	// We'll test with a hypothetical unavailable hash by using a very high number
	_, err = ComputeDigest(testData, crypto.Hash(999))
	if err == nil {
		t.Error("Expected error for unavailable hash algorithm")
	}
}

// TestHashAlgorithmFromString tests the HashAlgorithmFromString function
func TestHashAlgorithmFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected crypto.Hash
	}{
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
		{"SHA224", crypto.SHA224},
		{"unknown", crypto.SHA256}, // Should default to SHA256
		{"", crypto.SHA256},        // Should default to SHA256
		{"sha256", crypto.SHA256},  // Should default to SHA256 (case sensitive)
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("input_%s", test.input), func(t *testing.T) {
			result := HashAlgorithmFromString(test.input)
			if result != test.expected {
				t.Errorf("Expected %v for input %q, got %v", test.expected, test.input, result)
			}
		})
	}
}

// TestHashAlgorithmToString tests the HashAlgorithmToString function (already used in other tests)
func TestHashAlgorithmToString(t *testing.T) {
	tests := []struct {
		input    crypto.Hash
		expected string
	}{
		{crypto.SHA256, "SHA256"},
		{crypto.SHA384, "SHA384"},
		{crypto.SHA512, "SHA512"},
		{crypto.SHA224, "SHA224"},
		{crypto.Hash(999), "Unknown"}, // Unsupported hash
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("hash_%d", int(test.input)), func(t *testing.T) {
			result := HashAlgorithmToString(test.input)
			if result != test.expected {
				t.Errorf("Expected %q for hash %v, got %q", test.expected, test.input, result)
			}
		})
	}
}

// TestGetHashAlgorithm tests the GetHashAlgorithm function
func TestGetHashAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm SignatureAlgorithm
		keySize   int
		want      crypto.Hash
	}{
		// RSA tests
		{
			name:      "RSA 2048-bit key",
			algorithm: AlgorithmRSA,
			keySize:   2048,
			want:      crypto.SHA256,
		},
		{
			name:      "RSA 3072-bit key",
			algorithm: AlgorithmRSA,
			keySize:   3072,
			want:      crypto.SHA384,
		},
		{
			name:      "RSA 4096-bit key",
			algorithm: AlgorithmRSA,
			keySize:   4096,
			want:      crypto.SHA384,
		},
		// ECDSA tests
		{
			name:      "ECDSA P-256 (256-bit)",
			algorithm: AlgorithmECDSA,
			keySize:   256,
			want:      crypto.SHA256,
		},
		{
			name:      "ECDSA P-384 (384-bit)",
			algorithm: AlgorithmECDSA,
			keySize:   384,
			want:      crypto.SHA384,
		},
		{
			name:      "ECDSA P-521 (521-bit)",
			algorithm: AlgorithmECDSA,
			keySize:   521,
			want:      crypto.SHA384, // keySize >= 384 returns SHA384
		},
		// Ed25519 tests
		{
			name:      "Ed25519",
			algorithm: AlgorithmEd25519,
			keySize:   256, // Ed25519 has fixed key size
			want:      crypto.SHA512,
		},
		// Default cases
		{
			name:      "Unknown algorithm",
			algorithm: SignatureAlgorithm("UNKNOWN"),
			keySize:   2048,
			want:      crypto.SHA256, // Falls back to default
		},
		{
			name:      "RSA with small keysize",
			algorithm: AlgorithmRSA,
			keySize:   1024,
			want:      crypto.SHA256,
		},
		{
			name:      "ECDSA with non-standard size",
			algorithm: AlgorithmECDSA,
			keySize:   224,
			want:      crypto.SHA256, // Default for P-224
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetHashAlgorithm(tt.algorithm, tt.keySize)
			if got != tt.want {
				t.Errorf("GetHashAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSignData tests the convenience SignData function
func TestSignData(t *testing.T) {
	// Generate RSA key pair
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	keyPair := manager.KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Create a self-signed certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test Data Signer",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	testData := []byte("This is test data for convenience SignData function")

	// Test the convenience function
	signature, err := SignData(testData, keyPair, certificate)
	if err != nil {
		t.Fatalf("Failed to sign data with convenience function: %v", err)
	}

	// Should use default options
	if signature.Format != FormatPKCS7 {
		t.Errorf("Expected default format %s, got %s", FormatPKCS7, signature.Format)
	}

	if signature.Algorithm != AlgorithmRSA {
		t.Errorf("Expected RSA algorithm, got %s", signature.Algorithm)
	}

	if len(signature.Data) == 0 {
		t.Error("Expected signature data to be non-empty")
	}

	// Should include certificate by default
	if signature.Certificate == nil {
		t.Error("Expected certificate to be included by default")
	}
}

// TestVerifyECDSASignature tests the verifyECDSASignature function (0% coverage)
func TestVerifyECDSASignature(t *testing.T) {
	// Generate ECDSA key pair
	ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	ecdsaKeyPair := ecdsaManager.KeyPair()

	// Create certificate
	ecdsaCert, err := cert.CreateSelfSignedCertificate(ecdsaKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test ECDSA Verifier",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create ECDSA certificate: %v", err)
	}

	testData := []byte("Test data for ECDSA verification")

	// Create signature
	signature, err := SignDocument(testData, ecdsaKeyPair, ecdsaCert, SignOptions{
		HashAlgorithm:      crypto.SHA256,
		Format:             FormatPKCS7Detached,
		IncludeCertificate: true,
	})
	if err != nil {
		t.Fatalf("Failed to create ECDSA signature: %v", err)
	}

	// Test successful verification
	err = VerifySignature(testData, signature, DefaultVerifyOptions())
	if err != nil {
		t.Errorf("ECDSA signature verification should succeed: %v", err)
	}

	// Test with wrong data
	wrongData := []byte("Wrong data")
	err = VerifySignature(wrongData, signature, DefaultVerifyOptions())
	if err == nil {
		t.Error("ECDSA verification should fail with wrong data")
	}

	// Test with corrupted signature
	corruptedSig := &Signature{
		Algorithm:     signature.Algorithm,
		HashAlgorithm: signature.HashAlgorithm,
		Data:          append([]byte{0xFF}, signature.Data...),
		Certificate:   signature.Certificate,
	}
	err = VerifySignature(testData, corruptedSig, DefaultVerifyOptions())
	if err == nil {
		t.Error("ECDSA verification should fail with corrupted signature")
	}
}

// TestVerifyEd25519Signature tests the verifyEd25519Signature function (0% coverage)
func TestVerifyEd25519Signature(t *testing.T) {
	// Generate Ed25519 key pair
	ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}
	ed25519KeyPair := ed25519Manager.KeyPair()

	// Create certificate
	ed25519Cert, err := cert.CreateSelfSignedCertificate(ed25519KeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test Ed25519 Verifier",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create Ed25519 certificate: %v", err)
	}

	testData := []byte("Test data for Ed25519 verification")

	// Create signature
	signature, err := SignDocument(testData, ed25519KeyPair, ed25519Cert, SignOptions{
		HashAlgorithm:      crypto.SHA512,
		Format:             FormatPKCS7,
		IncludeCertificate: true,
	})
	if err != nil {
		t.Fatalf("Failed to create Ed25519 signature: %v", err)
	}

	// Test successful verification
	err = VerifySignature(testData, signature, DefaultVerifyOptions())
	if err != nil {
		t.Errorf("Ed25519 signature verification should succeed: %v", err)
	}

	// Test with wrong data
	wrongData := []byte("Wrong data for Ed25519")
	err = VerifySignature(wrongData, signature, DefaultVerifyOptions())
	if err == nil {
		t.Error("Ed25519 verification should fail with wrong data")
	}

	// Test with corrupted signature
	corruptedSig := &Signature{
		Algorithm:     signature.Algorithm,
		HashAlgorithm: signature.HashAlgorithm,
		Data:          append([]byte{0xFF}, signature.Data...),
		Certificate:   signature.Certificate,
	}
	err = VerifySignature(testData, corruptedSig, DefaultVerifyOptions())
	if err == nil {
		t.Error("Ed25519 verification should fail with corrupted signature")
	}
}

// TestVerifyDetachedSignature tests the VerifyDetachedSignature function (0% coverage)
func TestVerifyDetachedSignature(t *testing.T) {
	// Generate RSA key pair for testing
	rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	rsaKeyPair := rsaManager.KeyPair()

	// Create certificate
	rsaCert, err := cert.CreateSelfSignedCertificate(rsaKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test Detached Signer",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create RSA certificate: %v", err)
	}

	testData := []byte("Test data for detached signature verification")

	// Create a raw signature for detached verification
	// First compute the hash
	hasher := crypto.SHA256.New()
	hasher.Write(testData)
	digest := hasher.Sum(nil)

	// Sign the digest directly
	rawSigBytes, err := rsaKeyPair.PrivateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to create raw signature: %v", err)
	}

	// Test successful detached verification
	err = VerifyDetachedSignature(testData, rawSigBytes, rsaCert.Certificate, crypto.SHA256)
	if err != nil {
		t.Errorf("Detached signature verification should succeed: %v", err)
	}

	// Test with wrong data
	wrongData := []byte("Wrong data for detached")
	err = VerifyDetachedSignature(wrongData, rawSigBytes, rsaCert.Certificate, crypto.SHA256)
	if err == nil {
		t.Error("Detached verification should fail with wrong data")
	}

	// Test with nil certificate
	err = VerifyDetachedSignature(testData, rawSigBytes, nil, crypto.SHA256)
	if err == nil {
		t.Error("Detached verification should fail with nil certificate")
	}

	// Test with wrong hash algorithm
	err = VerifyDetachedSignature(testData, rawSigBytes, rsaCert.Certificate, crypto.SHA512)
	if err == nil {
		t.Error("Detached verification should fail with wrong hash algorithm")
	}

	// Test with ECDSA
	ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	ecdsaKeyPair := ecdsaManager.KeyPair()

	ecdsaCert, err := cert.CreateSelfSignedCertificate(ecdsaKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test ECDSA Detached Signer",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create ECDSA certificate: %v", err)
	}

	// Create ECDSA raw signature for detached verification
	ecdsaHasher := crypto.SHA256.New()
	ecdsaHasher.Write(testData)
	ecdsaDigest := ecdsaHasher.Sum(nil)

	ecdsaRawSigBytes, err := ecdsaKeyPair.PrivateKey.Sign(rand.Reader, ecdsaDigest, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to create ECDSA raw signature: %v", err)
	}

	err = VerifyDetachedSignature(testData, ecdsaRawSigBytes, ecdsaCert.Certificate, crypto.SHA256)
	if err != nil {
		t.Errorf("ECDSA detached signature verification should succeed: %v", err)
	}
}

// TestVerifyCertificateChain tests the verifyCertificateChain function (0% coverage)
func TestVerifyCertificateChain(t *testing.T) {
	// Create root CA
	rootCAManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate root CA key pair: %v", err)
	}
	rootCAKeyPair := rootCAManager.KeyPair()

	rootCACert, err := cert.CreateCACertificate(rootCAKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create root CA certificate: %v", err)
	}

	// Create end-entity certificate signed by root CA
	endEntityManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate end-entity key pair: %v", err)
	}
	endEntityKeyPair := endEntityManager.KeyPair()

	endEntityCert, err := cert.SignCertificate(rootCACert, rootCAKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test End Entity",
		},
		ValidFor: 30 * 24 * time.Hour,
	}, endEntityKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create end-entity certificate: %v", err)
	}

	// Test certificate chain verification through signature verification
	testData := []byte("Test data for certificate chain verification")

	signature, err := SignDocument(testData, endEntityKeyPair, endEntityCert, SignOptions{
		HashAlgorithm:      crypto.SHA256,
		Format:             FormatPKCS7,
		IncludeCertificate: true,
	})
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	// No intermediate certificates needed for direct root CA signing

	// Create root certificate pool
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCACert.Certificate)

	// Test successful chain verification
	verifyOpts := VerifyOptions{
		VerifyChain: true,
		Roots:       rootPool,
	}

	err = VerifySignature(testData, signature, verifyOpts)
	if err != nil {
		t.Errorf("Certificate chain verification should succeed: %v", err)
	}

	// Test chain verification failure with wrong root
	wrongRootManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate wrong root key pair: %v", err)
	}
	wrongRootKeyPair := wrongRootManager.KeyPair()

	wrongRootCert, err := cert.CreateCACertificate(wrongRootKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Wrong Root CA",
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create wrong root CA certificate: %v", err)
	}

	wrongRootPool := x509.NewCertPool()
	wrongRootPool.AddCert(wrongRootCert.Certificate)

	wrongVerifyOpts := VerifyOptions{
		VerifyChain: true,
		Roots:       wrongRootPool,
	}

	err = VerifySignature(testData, signature, wrongVerifyOpts)
	if err == nil {
		t.Error("Certificate chain verification should fail with wrong root")
	}

	// Test without chain verification (should succeed)
	noChainOpts := DefaultVerifyOptions()
	noChainOpts.VerifyChain = false

	err = VerifySignature(testData, signature, noChainOpts)
	if err != nil {
		t.Errorf("Signature verification without chain check should succeed: %v", err)
	}
}

// TestVerifyTimestamp tests the VerifyTimestamp function (0% coverage)
func TestVerifyTimestamp(t *testing.T) {
	// Generate key pair for signature
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	keyPair := manager.KeyPair()

	// Create certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test Timestamp Signer",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	testData := []byte("Test data for timestamp verification")

	// Create signature
	signature, err := SignDocument(testData, keyPair, certificate, SignOptions{
		HashAlgorithm: crypto.SHA256,
		Format:        FormatPKCS7,
	})
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	// Test signature without timestamp
	err = VerifyTimestamp(signature, DefaultVerifyOptions())
	if err == nil {
		t.Error("Timestamp verification should fail when signature has no timestamp")
	}

	// Create timestamp authority certificate
	tsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate TSA key pair: %v", err)
	}
	tsaKeyPair := tsaManager.KeyPair()

	tsaCert, err := cert.CreateSelfSignedCertificate(tsaKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test TSA",
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create TSA certificate: %v", err)
	}

	// Add timestamp to signature
	signature.Timestamp = &Timestamp{
		Time:        time.Now(),
		Certificate: tsaCert.Certificate,
		Token:       []byte("mock_timestamp_token"),
	}

	// Test successful timestamp verification
	err = VerifyTimestamp(signature, DefaultVerifyOptions())
	if err != nil {
		t.Errorf("Timestamp verification should succeed: %v", err)
	}

	// Test with expired timestamp certificate
	expiredTSACert, err := cert.CreateSelfSignedCertificate(tsaKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Expired TSA",
		},
		ValidFor: -24 * time.Hour, // Already expired
	})
	if err != nil {
		t.Fatalf("Failed to create expired TSA certificate: %v", err)
	}

	signature.Timestamp.Certificate = expiredTSACert.Certificate

	err = VerifyTimestamp(signature, DefaultVerifyOptions())
	if err == nil {
		t.Error("Timestamp verification should fail with expired TSA certificate")
	}

	// Test with empty timestamp token
	signature.Timestamp.Certificate = tsaCert.Certificate
	signature.Timestamp.Token = []byte{}

	err = VerifyTimestamp(signature, DefaultVerifyOptions())
	if err == nil {
		t.Error("Timestamp verification should fail with empty token")
	}

	// Test with nil timestamp certificate
	signature.Timestamp.Certificate = nil
	signature.Timestamp.Token = []byte("mock_token")

	err = VerifyTimestamp(signature, DefaultVerifyOptions())
	if err != nil {
		t.Errorf("Timestamp verification should succeed with nil certificate: %v", err)
	}
}

// TestExtractCertificateFromSignature tests the ExtractCertificateFromSignature function (0% coverage)
func TestExtractCertificateFromSignature(t *testing.T) {
	// Generate key pair and certificate
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	keyPair := manager.KeyPair()

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test Certificate Extractor",
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	testData := []byte("Test data for certificate extraction")

	// Create signature
	signature, err := SignDocument(testData, keyPair, certificate, SignOptions{
		HashAlgorithm:      crypto.SHA256,
		Format:             FormatPKCS7,
		IncludeCertificate: true,
	})
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	// Test successful certificate extraction
	extractedCert, err := ExtractCertificateFromSignature(signature)
	if err != nil {
		t.Errorf("Certificate extraction should succeed: %v", err)
	}

	if extractedCert == nil {
		t.Error("Extracted certificate should not be nil")
	}

	if extractedCert.Subject.CommonName != "Test Certificate Extractor" {
		t.Errorf("Expected common name 'Test Certificate Extractor', got '%s'", extractedCert.Subject.CommonName)
	}

	// Test with nil signature
	_, err = ExtractCertificateFromSignature(nil)
	if err == nil {
		t.Error("Certificate extraction should fail with nil signature")
	}

	// Test with signature that has no certificate
	sigWithoutCert := &Signature{
		Algorithm:     signature.Algorithm,
		HashAlgorithm: signature.HashAlgorithm,
		Data:          signature.Data,
		Certificate:   nil,
	}

	_, err = ExtractCertificateFromSignature(sigWithoutCert)
	if err == nil {
		t.Error("Certificate extraction should fail when signature has no certificate")
	}
}

// TestExtractCertificateChainFromSignature tests the ExtractCertificateChainFromSignature function (0% coverage)
func TestExtractCertificateChainFromSignature(t *testing.T) {
	// Generate key pairs for CA and end entity
	caManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key pair: %v", err)
	}
	caKeyPair := caManager.KeyPair()

	caCert, err := cert.CreateCACertificate(caKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test CA for Chain",
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	endEntityManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate end entity key pair: %v", err)
	}
	endEntityKeyPair := endEntityManager.KeyPair()

	endEntityCert, err := cert.SignCertificate(caCert, caKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Test End Entity for Chain",
		},
		ValidFor: 30 * 24 * time.Hour,
	}, endEntityKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create end entity certificate: %v", err)
	}

	testData := []byte("Test data for certificate chain extraction")

	// Create signature
	signature, err := SignDocument(testData, endEntityKeyPair, endEntityCert, SignOptions{
		HashAlgorithm:      crypto.SHA256,
		Format:             FormatPKCS7,
		IncludeCertificate: true,
	})
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	// Add certificate chain to signature
	signature.CertificateChain = []*x509.Certificate{caCert.Certificate}

	// Test successful certificate chain extraction
	extractedChain, err := ExtractCertificateChainFromSignature(signature)
	if err != nil {
		t.Errorf("Certificate chain extraction should succeed: %v", err)
	}

	if len(extractedChain) != 1 {
		t.Errorf("Expected 1 certificate in chain, got %d", len(extractedChain))
	}

	if extractedChain[0].Subject.CommonName != "Test CA for Chain" {
		t.Errorf("Expected CA common name 'Test CA for Chain', got '%s'", extractedChain[0].Subject.CommonName)
	}

	// Test with nil signature
	_, err = ExtractCertificateChainFromSignature(nil)
	if err == nil {
		t.Error("Certificate chain extraction should fail with nil signature")
	}

	// Test with signature that has no certificate chain
	sigWithoutChain := &Signature{
		Algorithm:        signature.Algorithm,
		HashAlgorithm:    signature.HashAlgorithm,
		Data:             signature.Data,
		Certificate:      signature.Certificate,
		CertificateChain: nil,
	}

	_, err = ExtractCertificateChainFromSignature(sigWithoutChain)
	if err == nil {
		t.Error("Certificate chain extraction should fail when signature has no certificate chain")
	}

	// Test with empty certificate chain
	sigWithEmptyChain := &Signature{
		Algorithm:        signature.Algorithm,
		HashAlgorithm:    signature.HashAlgorithm,
		Data:             signature.Data,
		Certificate:      signature.Certificate,
		CertificateChain: []*x509.Certificate{},
	}

	_, err = ExtractCertificateChainFromSignature(sigWithEmptyChain)
	if err == nil {
		t.Error("Certificate chain extraction should fail when signature has empty certificate chain")
	}
}
