package algo

import (
	"strings"
	"testing"
)

// Test data constants
const (
	testPEMPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wYfVGObvS7+VZjUoBeMWzJW0QLTG/wreqFXMLiYg2l5I5+Y1ZqUzTD5VLqhHTKkW
2E0EM3YM+Lp6KZGdNAiC8xpPV7x8kv6/6nF2YnK4DOHYQY1cMvR1m0VjpIzqBJiA
-----END PRIVATE KEY-----`

	testPEMPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1L7VLPHCgcGH1Rjm
70u/lWY1KAXjFsyVtEC0xv8K3qhVzC4mINpeSOfmNWalM0w+VS6oR0ypFthNBDN2
DPi6eimRnTQIgvMaT1e8fJL+v+pxdmJyuAzh2EGNXDLjTDa/Psp7QNy1/2cW2YCR
-----END PUBLIC KEY-----`

	testSSHPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAu1SU1L7VLPHCgcGH1Rjm70u/lWY1KAXjFsyVtEC0xv8K3qhV
zC4mINpeSOfmNWalM0w+VS6oR0ypFthNBDN2DPi6eimRnTQIgvMaT1e8fJL+v+px
dmJyuAzh2EGNXDLjTDa/Psp7QNy1/2cW2YCR
-----END OPENSSH PRIVATE KEY-----`

	testSSHPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDZlLOoGKr1QNRbCkpR5K7eGKSbkZWxOKj6m3YZkJNyqo8T6CU/V3q3YuEIhOv0UJQwJG2HTx1RgqwYTOLCp1Q6mOiHcI0pTJVG user@example.com`

	testEd25519SSHPublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99UMyRWs5RJJ9g8aOOzAl/7hMLqX6Xv6JvI user@example.com`

	testECDSASSHPublicKey = `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJhA2V4RFHNY user@example.com`

	testBinaryDER = "\x30\x82\x04\xbd\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x04\x82\x04\xa7\x30\x82\x04\xa3\x02\x01\x00\x02\x82\x01\x01\x00\xbb\x54\x94\xd4\xbe\xd5\x2c\xf1\xc2\x81\xc1\x87\xd5\x18\xe6\xef\x4b\xbf\x95\x66\x35\x28\x05\xe3\x16\xcc\x95\xb4\x40\xb4\xc6\xff\x0a\xde\xa8\x55\xcc\x2e\x26\x20\xda\x5e\x48\xe7\xe6\x35\x66\xa5\x33\x4c\x3e\x55\x2e\xa8\x47\x4c\xa9\x16\xd8\x4d\x04\x33\x76\x0c\xf8\xba\x7a\x29\x91\x9d\x34\x08\x82\xf3\x1a\x4f\x57\xbc\x7c\x92\xfe\xbf\xea\x71\x76\x62\x72\xb8\x0c\xe1\xd8\x41\x8d\x5c\x32"
)

func TestTypeAliases(t *testing.T) {
	t.Run("PEM type", func(t *testing.T) {
		pem := PEM(testPEMPrivateKey)
		if string(pem) != testPEMPrivateKey {
			t.Error("PEM type alias should preserve data")
		}
	})

	t.Run("DER type", func(t *testing.T) {
		der := DER(testBinaryDER)
		if string(der) != testBinaryDER {
			t.Error("DER type alias should preserve data")
		}
	})

	t.Run("SSH type", func(t *testing.T) {
		ssh := SSH(testSSHPublicKey)
		if string(ssh) != testSSHPublicKey {
			t.Error("SSH type alias should preserve data")
		}
	})
}

func TestFormatStructures(t *testing.T) {
	t.Run("PEMFormat creation and Format method", func(t *testing.T) {
		pemFormat := PEMFormat{Data: PEM(testPEMPrivateKey)}
		if pemFormat.Format() != "PEM" {
			t.Errorf("Expected Format() to return 'PEM', got '%s'", pemFormat.Format())
		}
		if string(pemFormat.Data) != testPEMPrivateKey {
			t.Error("PEMFormat should preserve data")
		}
	})

	t.Run("DERFormat creation and Format method", func(t *testing.T) {
		derFormat := DERFormat{Data: DER(testBinaryDER)}
		if derFormat.Format() != "DER" {
			t.Errorf("Expected Format() to return 'DER', got '%s'", derFormat.Format())
		}
		if string(derFormat.Data) != testBinaryDER {
			t.Error("DERFormat should preserve data")
		}
	})

	t.Run("SSHFormat creation and Format method", func(t *testing.T) {
		sshFormat := SSHFormat{Data: SSH(testSSHPublicKey)}
		if sshFormat.Format() != "SSH" {
			t.Errorf("Expected Format() to return 'SSH', got '%s'", sshFormat.Format())
		}
		if string(sshFormat.Data) != testSSHPublicKey {
			t.Error("SSHFormat should preserve data")
		}
	})
}

func TestIsPrintableText(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Empty data",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "PEM data (printable)",
			data:     []byte(testPEMPrivateKey),
			expected: true,
		},
		{
			name:     "SSH public key (printable)",
			data:     []byte(testSSHPublicKey),
			expected: true,
		},
		{
			name:     "Binary DER data (not printable)",
			data:     []byte(testBinaryDER),
			expected: false,
		},
		{
			name:     "Mixed printable/non-printable (< 95% printable)",
			data:     append([]byte("Hello World"), 0x00, 0x01, 0x02, 0x03, 0x04),
			expected: false,
		},
		{
			name:     "Text with newlines and tabs",
			data:     []byte("Hello\nWorld\tTest\r\n"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrintableText(tt.data)
			if result != tt.expected {
				t.Errorf("isPrintableText() = %v, expected %v for %s", result, tt.expected, tt.name)
			}
		})
	}
}

func TestAutoFormat(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedType   string
		expectError    bool
		errorSubstring string
	}{
		{
			name:           "Empty data",
			data:           []byte{},
			expectError:    true,
			errorSubstring: "empty data",
		},
		{
			name:         "PEM private key",
			data:         []byte(testPEMPrivateKey),
			expectedType: "PEMFormat",
		},
		{
			name:         "PEM public key",
			data:         []byte(testPEMPublicKey),
			expectedType: "PEMFormat",
		},
		{
			name:         "SSH private key (OpenSSH format)",
			data:         []byte(testSSHPrivateKey),
			expectedType: "SSHFormat",
		},
		{
			name:         "SSH RSA public key",
			data:         []byte(testSSHPublicKey),
			expectedType: "SSHFormat",
		},
		{
			name:         "SSH Ed25519 public key",
			data:         []byte(testEd25519SSHPublicKey),
			expectedType: "SSHFormat",
		},
		{
			name:         "SSH ECDSA public key",
			data:         []byte(testECDSASSHPublicKey),
			expectedType: "SSHFormat",
		},
		{
			name:         "DER binary data",
			data:         []byte(testBinaryDER),
			expectedType: "DERFormat",
		},
		{
			name:           "Unknown format (short printable text)",
			data:           []byte("Hello World"),
			expectError:    true,
			errorSubstring: "unable to detect format",
		},
		{
			name:           "Unknown format (short binary)",
			data:           []byte{0x00, 0x01, 0x02},
			expectError:    true,
			errorSubstring: "unable to detect format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AutoFormat(tt.data)

			if tt.expectError {
				if err == nil {
					t.Error("Expected an error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorSubstring) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorSubstring, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Check the type of the returned format wrapper
			switch result.(type) {
			case PEMFormat:
				if tt.expectedType != "PEMFormat" {
					t.Errorf("Expected %s, got PEMFormat", tt.expectedType)
				}
			case DERFormat:
				if tt.expectedType != "DERFormat" {
					t.Errorf("Expected %s, got DERFormat", tt.expectedType)
				}
			case SSHFormat:
				if tt.expectedType != "SSHFormat" {
					t.Errorf("Expected %s, got SSHFormat", tt.expectedType)
				}
			default:
				t.Errorf("Unexpected format type: %T", result)
			}
		})
	}
}

func TestAutoFormatDataPreservation(t *testing.T) {
	t.Run("PEM format data preservation", func(t *testing.T) {
		result, err := AutoFormat([]byte(testPEMPrivateKey))
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		pemFormat, ok := result.(PEMFormat)
		if !ok {
			t.Fatal("Expected PEMFormat")
		}

		if string(pemFormat.Data) != testPEMPrivateKey {
			t.Error("Data not preserved in PEMFormat")
		}
	})

	t.Run("DER format data preservation", func(t *testing.T) {
		result, err := AutoFormat([]byte(testBinaryDER))
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		derFormat, ok := result.(DERFormat)
		if !ok {
			t.Fatal("Expected DERFormat")
		}

		if string(derFormat.Data) != testBinaryDER {
			t.Error("Data not preserved in DERFormat")
		}
	})

	t.Run("SSH format data preservation", func(t *testing.T) {
		result, err := AutoFormat([]byte(testSSHPublicKey))
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		sshFormat, ok := result.(SSHFormat)
		if !ok {
			t.Fatal("Expected SSHFormat")
		}

		if string(sshFormat.Data) != testSSHPublicKey {
			t.Error("Data not preserved in SSHFormat")
		}
	})
}

func TestConvertPEMToDER(t *testing.T) {
	t.Run("Valid PEM conversion", func(t *testing.T) {
		// Generate a test RSA key pair to get valid PEM data
		keyPair, err := GenerateRSAKeyPair(KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate test key pair: %v", err)
		}

		pemData, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to get PEM data: %v", err)
		}

		derData, err := ConvertPEMToDER(pemData)
		if err != nil {
			t.Errorf("ConvertPEMToDER failed: %v", err)
		}

		if len(derData) == 0 {
			t.Error("DER data should not be empty")
		}
	})

	t.Run("Invalid PEM data", func(t *testing.T) {
		invalidPEM := PEM("invalid pem data")
		_, err := ConvertPEMToDER(invalidPEM)
		if err == nil {
			t.Error("Expected error for invalid PEM data")
		}
		if !strings.Contains(err.Error(), "failed to decode PEM block") {
			t.Errorf("Expected 'failed to decode PEM block' error, got: %v", err)
		}
	})

	t.Run("Empty PEM data", func(t *testing.T) {
		emptyPEM := PEM("")
		_, err := ConvertPEMToDER(emptyPEM)
		if err == nil {
			t.Error("Expected error for empty PEM data")
		}
	})
}

func TestConvertDERToPEM(t *testing.T) {
	t.Run("Valid DER conversion", func(t *testing.T) {
		// Generate a test RSA key pair to get valid DER data
		keyPair, err := GenerateRSAKeyPair(KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate test key pair: %v", err)
		}

		derData, err := keyPair.PrivateKeyToDER()
		if err != nil {
			t.Fatalf("Failed to get DER data: %v", err)
		}

		pemData, err := ConvertDERToPEM(derData, "")
		if err != nil {
			t.Errorf("ConvertDERToPEM failed: %v", err)
		}

		if len(pemData) == 0 {
			t.Error("PEM data should not be empty")
		}

		// Verify it's valid PEM format
		pemStr := string(pemData)
		if !strings.Contains(pemStr, "-----BEGIN") {
			t.Error("Result should contain PEM header")
		}
		if !strings.Contains(pemStr, "-----END") {
			t.Error("Result should contain PEM footer")
		}
	})

	t.Run("Invalid DER data", func(t *testing.T) {
		invalidDER := DER("invalid der data")
		pemData, err := ConvertDERToPEM(invalidDER, "")
		if err != nil {
			t.Errorf("ConvertDERToPEM should not fail for invalid DER: %v", err)
		}

		// Should still create a PEM structure, just with invalid content
		if len(pemData) == 0 {
			t.Error("Should still produce PEM output")
		}
	})

	t.Run("Empty DER data", func(t *testing.T) {
		emptyDER := DER("")
		pemData, err := ConvertDERToPEM(emptyDER, "")
		if err != nil {
			t.Errorf("ConvertDERToPEM should handle empty DER: %v", err)
		}

		if len(pemData) == 0 {
			t.Error("Should produce PEM output even for empty DER")
		}
	})
}

func TestFormatConversionRoundTrip(t *testing.T) {
	t.Run("PEM to DER to PEM round trip", func(t *testing.T) {
		// Generate a test RSA key pair
		keyPair, err := GenerateRSAKeyPair(KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate test key pair: %v", err)
		}

		// Get original PEM
		originalPEM, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to get PEM data: %v", err)
		}

		// Convert PEM to DER
		derData, err := ConvertPEMToDER(originalPEM)
		if err != nil {
			t.Fatalf("PEM to DER conversion failed: %v", err)
		}

		// Convert DER back to PEM
		resultPEM, err := ConvertDERToPEM(derData, "")
		if err != nil {
			t.Fatalf("DER to PEM conversion failed: %v", err)
		}

		// Verify we can parse the result
		_, err = RSAKeyPairFromPEM(resultPEM)
		if err != nil {
			t.Errorf("Failed to parse round-trip PEM: %v", err)
		}
	})
}

func TestFormatTypeMethods(t *testing.T) {
	t.Run("PEMFormat ToDER conversion", func(t *testing.T) {
		// Generate a test RSA key pair
		keyPair, err := GenerateRSAKeyPair(KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate test key pair: %v", err)
		}

		pemData, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to get PEM data: %v", err)
		}

		pemFormat := PEMFormat{Data: pemData}
		derFormat, err := pemFormat.ToDER()
		if err != nil {
			t.Errorf("PEMFormat.ToDER() failed: %v", err)
		}

		if derFormat.Format() != "DER" {
			t.Error("Result should be DER format")
		}

		if len(derFormat.Data) == 0 {
			t.Error("DER data should not be empty")
		}
	})

	t.Run("DERFormat ToPEM conversion", func(t *testing.T) {
		// Generate a test RSA key pair
		keyPair, err := GenerateRSAKeyPair(KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate test key pair: %v", err)
		}

		derData, err := keyPair.PrivateKeyToDER()
		if err != nil {
			t.Fatalf("Failed to get DER data: %v", err)
		}

		derFormat := DERFormat{Data: derData}
		pemFormat, err := derFormat.ToPEM()
		if err != nil {
			t.Errorf("DERFormat.ToPEM() failed: %v", err)
		}

		if pemFormat.Format() != "PEM" {
			t.Error("Result should be PEM format")
		}

		if len(pemFormat.Data) == 0 {
			t.Error("PEM data should not be empty")
		}

		// Verify it's valid PEM
		pemStr := string(pemFormat.Data)
		if !strings.Contains(pemStr, "-----BEGIN") || !strings.Contains(pemStr, "-----END") {
			t.Error("Result should be valid PEM format")
		}
	})
}

func TestParsingMethods(t *testing.T) {
	t.Run("PEMFormat parsing methods exist", func(t *testing.T) {
		// Generate test key pairs
		rsaKey, err := GenerateRSAKeyPair(KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		ecdsaKey, err := GenerateECDSAKeyPair(P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		ed25519Key, err := GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		// Test RSA parsing
		rsaPEM, err := rsaKey.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to get RSA PEM: %v", err)
		}

		pemFormat := PEMFormat{Data: rsaPEM}
		parsedRSA, err := pemFormat.ParseRSA()
		if err != nil {
			t.Errorf("PEMFormat.ParseRSA() failed: %v", err)
		}
		if parsedRSA == nil {
			t.Error("ParseRSA should return valid key pair")
		}

		// Test ECDSA parsing
		ecdsaPEM, err := ecdsaKey.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to get ECDSA PEM: %v", err)
		}

		pemFormat2 := PEMFormat{Data: ecdsaPEM}
		parsedECDSA, err := pemFormat2.ParseECDSA()
		if err != nil {
			t.Errorf("PEMFormat.ParseECDSA() failed: %v", err)
		}
		if parsedECDSA == nil {
			t.Error("ParseECDSA should return valid key pair")
		}

		// Test Ed25519 parsing
		ed25519PEM, err := ed25519Key.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to get Ed25519 PEM: %v", err)
		}

		pemFormat3 := PEMFormat{Data: ed25519PEM}
		parsedEd25519, err := pemFormat3.ParseEd25519()
		if err != nil {
			t.Errorf("PEMFormat.ParseEd25519() failed: %v", err)
		}
		if parsedEd25519 == nil {
			t.Error("ParseEd25519 should return valid key pair")
		}
	})

	t.Run("DERFormat parsing methods exist", func(t *testing.T) {
		// Generate test RSA key pair
		rsaKey, err := GenerateRSAKeyPair(KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		rsaDER, err := rsaKey.PrivateKeyToDER()
		if err != nil {
			t.Fatalf("Failed to get RSA DER: %v", err)
		}

		derFormat := DERFormat{Data: rsaDER}
		parsedRSA, err := derFormat.ParseRSA()
		if err != nil {
			t.Errorf("DERFormat.ParseRSA() failed: %v", err)
		}
		if parsedRSA == nil {
			t.Error("ParseRSA should return valid key pair")
		}

		// Test that parsing methods exist for all algorithms
		// (We test just one to verify the structure is correct)
	})

	t.Run("SSHFormat parsing methods exist", func(t *testing.T) {
		// Generate test RSA key pair
		rsaKey, err := GenerateRSAKeyPair(KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		rsaSSH, err := rsaKey.PrivateKeyToSSH("test@example.com", "")
		if err != nil {
			t.Fatalf("Failed to get RSA SSH: %v", err)
		}

		sshFormat := SSHFormat{Data: rsaSSH}
		parsedRSA, err := sshFormat.ParseRSA("")
		if err != nil {
			t.Errorf("SSHFormat.ParseRSA() failed: %v", err)
		}
		if parsedRSA == nil {
			t.Error("ParseRSA should return valid key pair")
		}

		// Test that parsing methods exist for all algorithms
		// (We test just one to verify the structure is correct)
	})
}

func TestIsPrivateKeyDER(t *testing.T) {
	t.Run("Valid private key DER", func(t *testing.T) {
		keyPair, err := GenerateRSAKeyPair(KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		derData, err := keyPair.PrivateKeyToDER()
		if err != nil {
			t.Fatalf("Failed to get DER data: %v", err)
		}

		if !isPrivateKeyDER(derData) {
			t.Error("Should detect valid private key DER")
		}
	})

	t.Run("Invalid DER data", func(t *testing.T) {
		invalidDER := DER("invalid data")
		if isPrivateKeyDER(invalidDER) {
			t.Error("Should not detect invalid data as private key DER")
		}
	})

	t.Run("Empty DER data", func(t *testing.T) {
		emptyDER := DER("")
		if isPrivateKeyDER(emptyDER) {
			t.Error("Should not detect empty data as private key DER")
		}
	})
}