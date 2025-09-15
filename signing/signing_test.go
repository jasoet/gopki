package signing

import (
	"crypto"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestSignAndVerifyRSA(t *testing.T) {
	// Generate RSA key pair
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

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

			// Test with tampered data
			tamperedData := append(testData, byte('X'))
			err = VerifySignature(tamperedData, signature, DefaultVerifyOptions())
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
			keyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](curve)
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

			// Test with wrong data
			wrongData := []byte("This is wrong data")
			err = VerifySignature(wrongData, signature, DefaultVerifyOptions())
			if err == nil {
				t.Error("Expected verification to fail with wrong data")
			}
		})
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	// Generate Ed25519 key pair
	keyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
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
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
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

	// Verify with expiration check disabled
	opts := DefaultVerifyOptions()
	opts.SkipExpirationCheck = true
	err = VerifySignature(testData, signature, opts)
	if err != nil {
		t.Errorf("Expected verification to succeed with SkipExpirationCheck, got %v", err)
	}
}

func TestSigningOptions(t *testing.T) {
	// Generate key pair
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
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
				kp, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
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
				kp, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
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
				kp, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
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
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
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