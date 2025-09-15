package formats

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestRawFormat(t *testing.T) {
	// Generate test key pair and certificate
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "Test Signer"},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	format := NewRawFormat()
	testData := []byte("Test data for raw format signing")

	// Test signing
	opts := SignOptions{
		HashAlgorithm:      crypto.SHA256,
		IncludeCertificate: true,
	}

	signature, err := format.Sign(testData, keyPair.PrivateKey, certificate.Certificate, opts)
	if err != nil {
		t.Fatalf("Failed to sign with raw format: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}

	// Test verification
	verifyOpts := VerifyOptions{}
	err = format.Verify(testData, signature, certificate.Certificate, verifyOpts)
	if err != nil {
		t.Errorf("Failed to verify raw signature: %v", err)
	}

	// Test with tampered data
	tamperedData := append(testData, byte('X'))
	err = format.Verify(tamperedData, signature, certificate.Certificate, verifyOpts)
	if err == nil {
		t.Error("Expected verification to fail with tampered data")
	}

	// Test parsing
	info, err := format.Parse(signature)
	if err != nil {
		t.Errorf("Failed to parse raw signature: %v", err)
	}

	if !info.Detached {
		t.Error("Raw format should always be detached")
	}

	// Test format properties
	if format.Name() != FormatRaw {
		t.Errorf("Expected format name %s, got %s", FormatRaw, format.Name())
	}

	if !format.SupportsDetached() {
		t.Error("Raw format should support detached signatures")
	}
}

func TestPKCS7Format(t *testing.T) {
	// Generate test key pair and certificate
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "PKCS#7 Test Signer",
			Organization: []string{"Test Org"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	testData := []byte("Test data for PKCS#7 format signing")

	t.Run("Attached", func(t *testing.T) {
		format := NewPKCS7Format(false) // Attached

		// Test signing
		opts := SignOptions{
			HashAlgorithm:      crypto.SHA256,
			IncludeCertificate: true,
		}

		signature, err := format.Sign(testData, keyPair.PrivateKey, certificate.Certificate, opts)
		if err != nil {
			t.Fatalf("Failed to sign with PKCS#7 attached format: %v", err)
		}

		if len(signature) == 0 {
			t.Error("PKCS#7 signature should not be empty")
		}

		// Test parsing
		info, err := format.Parse(signature)
		if err != nil {
			t.Fatalf("Failed to parse PKCS#7 signature: %v", err)
		}

		if info.Algorithm != "PKCS#7" {
			t.Errorf("Expected algorithm PKCS#7, got %s", info.Algorithm)
		}

		if info.Detached {
			t.Error("Attached PKCS#7 should not be marked as detached")
		}

		if info.Certificate == nil {
			t.Error("PKCS#7 signature should include certificate")
		}

		if info.Certificate.Subject.CommonName != "PKCS#7 Test Signer" {
			t.Error("Certificate subject mismatch")
		}

		// Test verification
		verifyOpts := VerifyOptions{}
		err = format.Verify(testData, signature, certificate.Certificate, verifyOpts)
		if err != nil {
			t.Errorf("Failed to verify PKCS#7 signature: %v", err)
		}

		// Test format properties
		if format.Name() != FormatPKCS7 {
			t.Errorf("Expected format name %s, got %s", FormatPKCS7, format.Name())
		}
	})

	t.Run("Detached", func(t *testing.T) {
		format := NewPKCS7Format(true) // Detached

		// Test signing
		opts := SignOptions{
			HashAlgorithm:      crypto.SHA384,
			IncludeCertificate: true,
		}

		signature, err := format.Sign(testData, keyPair.PrivateKey, certificate.Certificate, opts)
		if err != nil {
			t.Fatalf("Failed to sign with PKCS#7 detached format: %v", err)
		}

		// Test parsing
		info, err := format.Parse(signature)
		if err != nil {
			t.Fatalf("Failed to parse PKCS#7 detached signature: %v", err)
		}

		if !info.Detached {
			t.Error("Detached PKCS#7 should be marked as detached")
		}

		if info.HashAlgorithm != crypto.SHA384 {
			t.Errorf("Expected hash algorithm SHA384, got %v", info.HashAlgorithm)
		}

		// Test verification
		verifyOpts := VerifyOptions{}
		err = format.Verify(testData, signature, certificate.Certificate, verifyOpts)
		if err != nil {
			t.Errorf("Failed to verify PKCS#7 detached signature: %v", err)
		}

		// Test format properties
		if format.Name() != FormatPKCS7Detached {
			t.Errorf("Expected format name %s, got %s", FormatPKCS7Detached, format.Name())
		}
	})
}

func TestPKCS7WithDifferentAlgorithms(t *testing.T) {
	testData := []byte("Test data for different algorithms")

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
					Subject:  pkix.Name{CommonName: "RSA PKCS#7 Test"},
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
					Subject:  pkix.Name{CommonName: "ECDSA PKCS#7 Test"},
					ValidFor: 365 * 24 * time.Hour,
				})
				return kp, c, err
			},
		},
	}

	for _, alg := range algorithms {
		t.Run(alg.name, func(t *testing.T) {
			keyPair, certificate, err := alg.generate()
			if err != nil {
				t.Fatalf("Failed to generate %s keys: %v", alg.name, err)
			}

			format := NewPKCS7Format(false)

			opts := SignOptions{
				HashAlgorithm:      crypto.SHA256,
				IncludeCertificate: true,
			}

			var signer crypto.Signer
			switch kp := keyPair.(type) {
			case *algo.RSAKeyPair:
				signer = kp.PrivateKey
			case *algo.ECDSAKeyPair:
				signer = kp.PrivateKey
			}

			signature, err := format.Sign(testData, signer, certificate.Certificate, opts)
			if err != nil {
				t.Fatalf("Failed to sign with %s: %v", alg.name, err)
			}

			// Verify signature
			verifyOpts := VerifyOptions{}
			err = format.Verify(testData, signature, certificate.Certificate, verifyOpts)
			if err != nil {
				t.Errorf("Failed to verify %s PKCS#7 signature: %v", alg.name, err)
			}

			// Parse and check
			info, err := format.Parse(signature)
			if err != nil {
				t.Errorf("Failed to parse %s PKCS#7 signature: %v", alg.name, err)
			}

			if info.Certificate == nil {
				t.Errorf("PKCS#7 signature should include certificate for %s", alg.name)
			}
		})
	}
}

func TestFormatRegistry(t *testing.T) {
	// Test default registry
	formats := ListFormats()
	if len(formats) < 3 { // Should have at least raw, pkcs7, pkcs7-detached
		t.Errorf("Expected at least 3 formats, got %d", len(formats))
	}

	// Test getting formats
	rawFormat, exists := GetFormat(FormatRaw)
	if !exists {
		t.Error("Raw format should be registered")
	}
	if rawFormat.Name() != FormatRaw {
		t.Error("Raw format name mismatch")
	}

	pkcs7Format, exists := GetFormat(FormatPKCS7)
	if !exists {
		t.Error("PKCS#7 format should be registered")
	}
	if pkcs7Format.Name() != FormatPKCS7 {
		t.Error("PKCS#7 format name mismatch")
	}

	// Test custom registry
	customRegistry := NewFormatRegistry()
	if len(customRegistry.List()) != 0 {
		t.Error("New registry should be empty")
	}

	customFormat := NewRawFormat()
	customRegistry.Register(customFormat)

	if len(customRegistry.List()) != 1 {
		t.Error("Custom registry should have one format")
	}

	format, exists := customRegistry.Get(FormatRaw)
	if !exists {
		t.Error("Format should exist in custom registry")
	}
	if format.Name() != FormatRaw {
		t.Error("Format name mismatch in custom registry")
	}
}

func TestSignOptionsAndVerifyOptions(t *testing.T) {
	// Test that options are properly used
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Options Test"},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	format := NewPKCS7Format(false)
	testData := []byte("Test data for options")

	// Test with extra certificates
	extraCert, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Extra Cert"},
		ValidFor: 365 * 24 * time.Hour,
	})

	opts := SignOptions{
		HashAlgorithm:      crypto.SHA512,
		IncludeCertificate: true,
		ExtraCertificates:  []*x509.Certificate{extraCert.Certificate},
		Attributes: map[string]interface{}{
			"test": "value",
		},
	}

	signature, err := format.Sign(testData, keyPair.PrivateKey, certificate.Certificate, opts)
	if err != nil {
		t.Fatalf("Failed to sign with options: %v", err)
	}

	// Parse and verify the extra certificate is included
	info, err := format.Parse(signature)
	if err != nil {
		t.Fatalf("Failed to parse signature: %v", err)
	}

	if info.HashAlgorithm != crypto.SHA512 {
		t.Errorf("Expected SHA512 hash algorithm, got %v", info.HashAlgorithm)
	}

	// Should have at least 2 certificates (signing + extra)
	totalCerts := 1 // signing cert
	if len(info.CertificateChain) > 0 {
		totalCerts += len(info.CertificateChain)
	}

	if totalCerts < 2 {
		t.Errorf("Expected at least 2 certificates (signing + extra), got %d", totalCerts)
	}
}

func TestFormatErrors(t *testing.T) {
	format := NewPKCS7Format(false)

	// Test with invalid signature data
	_, err := format.Parse([]byte("invalid data"))
	if err == nil {
		t.Error("Expected error when parsing invalid PKCS#7 data")
	}

	// Test verification with invalid signature
	keyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Error Test"},
		ValidFor: 365 * 24 * time.Hour,
	})

	testData := []byte("test")
	verifyOpts := VerifyOptions{}

	err = format.Verify(testData, []byte("invalid"), certificate.Certificate, verifyOpts)
	if err == nil {
		t.Error("Expected error when verifying invalid PKCS#7 signature")
	}
}