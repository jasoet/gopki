package format

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestPublicKeyToSSH_RSA(t *testing.T) {
	// Generate RSA key pair
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Convert to SSH format
	sshData, err := PublicKeyToSSH(&rsaKeyPair.PrivateKey.PublicKey, "test@example.com")
	if err != nil {
		t.Fatalf("Failed to convert RSA public key to SSH: %v", err)
	}

	// Verify SSH format
	if !strings.HasPrefix(sshData, "ssh-rsa ") {
		t.Error("SSH RSA public key should start with 'ssh-rsa '")
	}

	if !strings.Contains(sshData, "test@example.com") {
		t.Error("SSH key should contain the comment")
	}

	// Verify round-trip
	parsedKey, err := ParsePublicKeyFromSSH[*rsa.PublicKey](sshData)
	if err != nil {
		t.Fatalf("Failed to parse SSH RSA public key: %v", err)
	}

	// Verify key properties match
	if parsedKey.N.Cmp(rsaKeyPair.PrivateKey.PublicKey.N) != 0 {
		t.Error("Public key modulus doesn't match after SSH round-trip")
	}
}

func TestPublicKeyToSSH_ECDSA(t *testing.T) {
	// Generate ECDSA key pair
	ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	// Convert to SSH format
	sshData, err := PublicKeyToSSH(&ecdsaKeyPair.PrivateKey.PublicKey, "ecdsa-test@example.com")
	if err != nil {
		t.Fatalf("Failed to convert ECDSA public key to SSH: %v", err)
	}

	// Verify SSH format
	if !strings.HasPrefix(sshData, "ecdsa-sha2-") {
		t.Error("SSH ECDSA public key should start with 'ecdsa-sha2-'")
	}

	if !strings.Contains(sshData, "ecdsa-test@example.com") {
		t.Error("SSH key should contain the comment")
	}

	// Verify round-trip
	parsedKey, err := ParsePublicKeyFromSSH[*ecdsa.PublicKey](sshData)
	if err != nil {
		t.Fatalf("Failed to parse SSH ECDSA public key: %v", err)
	}

	// Verify key properties match
	if parsedKey.X.Cmp(ecdsaKeyPair.PrivateKey.PublicKey.X) != 0 {
		t.Error("Public key X coordinate doesn't match after SSH round-trip")
	}
}

func TestPublicKeyToSSH_Ed25519(t *testing.T) {
	// Generate Ed25519 key pair
	ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	// Convert to SSH format
	sshData, err := PublicKeyToSSH(ed25519KeyPair.PublicKey, "ed25519-test@example.com")
	if err != nil {
		t.Fatalf("Failed to convert Ed25519 public key to SSH: %v", err)
	}

	// Verify SSH format
	if !strings.HasPrefix(sshData, "ssh-ed25519 ") {
		t.Error("SSH Ed25519 public key should start with 'ssh-ed25519 '")
	}

	if !strings.Contains(sshData, "ed25519-test@example.com") {
		t.Error("SSH key should contain the comment")
	}

	// Verify round-trip
	parsedKey, err := ParsePublicKeyFromSSH[ed25519.PublicKey](sshData)
	if err != nil {
		t.Fatalf("Failed to parse SSH Ed25519 public key: %v", err)
	}

	// Verify key data matches
	if string(parsedKey) != string(ed25519KeyPair.PublicKey) {
		t.Error("Public key data doesn't match after SSH round-trip")
	}
}

func TestPrivateKeyToSSH_RSA(t *testing.T) {
	// Generate RSA key pair
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Convert to SSH format (no passphrase)
	sshData, err := PrivateKeyToSSH(rsaKeyPair.PrivateKey, "rsa-private@example.com", "")
	if err != nil {
		t.Fatalf("Failed to convert RSA private key to SSH: %v", err)
	}

	// Verify SSH private key format
	if !strings.Contains(sshData, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Error("SSH private key should be in OpenSSH format")
	}

	// Note: We skip round-trip testing due to Go crypto/ssh package limitations
	// The SSH package doesn't expose underlying private keys for extraction
	t.Log("SSH private key generation successful - round-trip not supported by Go crypto/ssh")
}

func TestPrivateKeyToSSH_WithPassphrase(t *testing.T) {
	// Generate ECDSA key pair
	ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	passphrase := "test-passphrase-123"

	// Convert to SSH format with passphrase
	sshData, err := PrivateKeyToSSH(ecdsaKeyPair.PrivateKey, "encrypted-ecdsa@example.com", passphrase)
	if err != nil {
		t.Fatalf("Failed to convert ECDSA private key to SSH with passphrase: %v", err)
	}

	// Verify SSH private key format
	if !strings.Contains(sshData, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Error("SSH private key should be in OpenSSH format")
	}

	// Note: We skip round-trip testing due to Go crypto/ssh package limitations
	t.Log("SSH encrypted private key generation successful")

	// Test that parsing now works with passphrase
	parsedKey, err := ParsePrivateKeyFromSSH[*ecdsa.PrivateKey](sshData, passphrase)
	if err != nil {
		t.Error("ParsePrivateKeyFromSSH should now work with passphrase:", err)
	} else {
		t.Log("SSH private key parsing with passphrase successful!")

		// Verify the parsed key is valid
		if parsedKey.Curve.Params().Name != "P-256" {
			t.Error("Parsed key should be P-256 ECDSA")
		}
	}
}

func TestParseSSHPublicKeyInfo(t *testing.T) {
	tests := []struct {
		name            string
		sshKey          string
		expectedAlgo    string
		expectedComment string
		hasError        bool
	}{
		{
			name:            "RSA key with comment",
			sshKey:          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7VJTUt9Us8cKB user@host",
			expectedAlgo:    "ssh-rsa",
			expectedComment: "user@host",
			hasError:        false,
		},
		{
			name:            "Ed25519 key with comment",
			sshKey:          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ed25519@example.com",
			expectedAlgo:    "ssh-ed25519",
			expectedComment: "ed25519@example.com",
			hasError:        false,
		},
		{
			name:            "ECDSA key without comment",
			sshKey:          "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK",
			expectedAlgo:    "ecdsa-sha2-nistp256",
			expectedComment: "",
			hasError:        false,
		},
		{
			name:     "Invalid format",
			sshKey:   "invalid-key-format",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseSSHPublicKeyInfo(tt.sshKey)

			if tt.hasError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.hasError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if !tt.hasError && info != nil {
				if info.Algorithm != tt.expectedAlgo {
					t.Errorf("Expected algorithm %s, got %s", tt.expectedAlgo, info.Algorithm)
				}
				if info.Comment != tt.expectedComment {
					t.Errorf("Expected comment %s, got %s", tt.expectedComment, info.Comment)
				}
			}
		})
	}
}

func TestGetSSHKeyType(t *testing.T) {
	tests := []struct {
		algorithm string
		expected  string
	}{
		{"ssh-rsa", "RSA"},
		{"ssh-ed25519", "Ed25519"},
		{"ecdsa-sha2-nistp256", "ECDSA"},
		{"ecdsa-sha2-nistp384", "ECDSA"},
		{"ecdsa-sha2-nistp521", "ECDSA"},
		{"unknown-algorithm", "Unknown"},
	}

	for _, tt := range tests {
		result := GetSSHKeyType(tt.algorithm)
		if result != tt.expected {
			t.Errorf("GetSSHKeyType(%s) = %s, expected %s", tt.algorithm, result, tt.expected)
		}
	}
}

func TestConvertPEMToSSH_PublicKey(t *testing.T) {
	// Generate RSA key pair and get PEM
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	pemData, err := keypair.PublicKeyToPEM(&rsaKeyPair.PrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to convert to PEM: %v", err)
	}

	// Convert PEM to SSH
	sshData, err := ConvertPEMToSSH(pemData, "converted@example.com", false)
	if err != nil {
		t.Fatalf("Failed to convert PEM to SSH: %v", err)
	}

	// Verify SSH format
	if !strings.HasPrefix(sshData, "ssh-rsa ") {
		t.Error("Converted SSH key should be RSA format")
	}

	if !strings.Contains(sshData, "converted@example.com") {
		t.Error("Converted SSH key should contain comment")
	}
}

func TestConvertPEMToSSH_PrivateKey(t *testing.T) {
	// Generate Ed25519 key pair and get PEM
	ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	pemData, err := keypair.PrivateKeyToPEM(ed25519KeyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to convert to PEM: %v", err)
	}

	// Convert PEM to SSH
	sshData, err := ConvertPEMToSSH(pemData, "converted-private@example.com", true)
	if err != nil {
		t.Fatalf("Failed to convert PEM private key to SSH: %v", err)
	}

	// Verify SSH private key format
	if !strings.Contains(sshData, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Error("Converted SSH private key should be in OpenSSH format")
	}
}

func TestConvertDERToSSH(t *testing.T) {
	// Generate ECDSA key pair and get DER
	ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	derData, err := PublicKeyToDER(&ecdsaKeyPair.PrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to convert to DER: %v", err)
	}

	// Convert DER to SSH
	sshData, err := ConvertDERToSSH(derData, "der-converted@example.com", false)
	if err != nil {
		t.Fatalf("Failed to convert DER to SSH: %v", err)
	}

	// Verify SSH format
	if !strings.HasPrefix(sshData, "ecdsa-sha2-") {
		t.Error("Converted SSH key should be ECDSA format")
	}

	if !strings.Contains(sshData, "der-converted@example.com") {
		t.Error("Converted SSH key should contain comment")
	}
}

func TestConvertSSHToPEM(t *testing.T) {
	// Generate key pair and convert to SSH first
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	sshData, err := PublicKeyToSSH(&rsaKeyPair.PrivateKey.PublicKey, "ssh-test@example.com")
	if err != nil {
		t.Fatalf("Failed to convert to SSH: %v", err)
	}

	// Convert SSH public key back to PEM (this works)
	pemData, err := ConvertSSHToPEM(sshData, false, "")
	if err != nil {
		t.Fatalf("Failed to convert SSH to PEM: %v", err)
	}

	// Verify PEM format
	pemStr := string(pemData)
	if !strings.Contains(pemStr, "-----BEGIN PUBLIC KEY-----") {
		t.Error("Converted PEM should be in public key format")
	}

	// Verify round-trip by parsing the PEM
	_, err = ParsePublicKeyFromPEM[*rsa.PublicKey](pemData)
	if err != nil {
		t.Fatalf("Failed to parse converted PEM: %v", err)
	}

	// Test that private key conversion fails as expected
	_, err = ConvertSSHToPEM("some-private-key", true, "")
	if err == nil {
		t.Error("Expected SSH private key to PEM conversion to fail")
	}
}

func TestConvertSSHToDER(t *testing.T) {
	// Generate key pair and convert to SSH first
	ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	sshData, err := PublicKeyToSSH(ed25519KeyPair.PublicKey, "ssh-der-test@example.com")
	if err != nil {
		t.Fatalf("Failed to convert to SSH: %v", err)
	}

	// Convert SSH public key to DER (this works)
	derData, err := ConvertSSHToDER(sshData, false, "")
	if err != nil {
		t.Fatalf("Failed to convert SSH to DER: %v", err)
	}

	// Verify DER format by parsing
	_, err = ParsePublicKeyFromDER[ed25519.PublicKey](derData)
	if err != nil {
		t.Fatalf("Failed to parse converted DER: %v", err)
	}

	// Test that private key conversion fails as expected
	_, err = ConvertSSHToDER("some-private-key", true, "")
	if err == nil {
		t.Error("Expected SSH private key to DER conversion to fail")
	}
}

func TestFullFormatConversionMatrix(t *testing.T) {
	// Generate a test key
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Test all conversion paths for public key (what actually works)
	t.Run("Public Key Conversions", func(t *testing.T) {
		// Start with PEM
		pemData, err := keypair.PublicKeyToPEM(&rsaKeyPair.PrivateKey.PublicKey)
		if err != nil {
			t.Fatalf("Failed to create initial PEM: %v", err)
		}

		// PEM -> DER -> SSH -> PEM (round trip)
		derData, err := ConvertPEMToDER(pemData)
		if err != nil {
			t.Fatalf("PEM to DER conversion failed: %v", err)
		}

		sshData, err := ConvertDERToSSH(derData, "roundtrip@example.com", false)
		if err != nil {
			t.Fatalf("DER to SSH conversion failed: %v", err)
		}

		finalPEM, err := ConvertSSHToPEM(sshData, false, "")
		if err != nil {
			t.Fatalf("SSH to PEM conversion failed: %v", err)
		}

		// Verify we can parse the final result
		finalKey, err := ParsePublicKeyFromPEM[*rsa.PublicKey](finalPEM)
		if err != nil {
			t.Fatalf("Failed to parse final PEM: %v", err)
		}

		// Verify key integrity
		if finalKey.N.Cmp(rsaKeyPair.PrivateKey.PublicKey.N) != 0 {
			t.Error("Key integrity lost during format conversion chain")
		}
	})

	// Test private key round-trip conversions
	t.Run("Private Key Round-trip Conversion", func(t *testing.T) {
		// SSH private key generation works
		sshPrivateData, err := PrivateKeyToSSH(rsaKeyPair.PrivateKey, "test-private@example.com", "")
		if err != nil {
			t.Fatalf("SSH private key generation should work: %v", err)
		}

		if !strings.Contains(sshPrivateData, "-----BEGIN OPENSSH PRIVATE KEY-----") {
			t.Error("SSH private key should be generated correctly")
		}

		// SSH private key parsing should now work
		parsedPrivateKey, err := ParsePrivateKeyFromSSH[*rsa.PrivateKey](sshPrivateData, "")
		if err != nil {
			t.Error("SSH private key parsing should now work:", err)
		} else {
			t.Log("SSH private key round-trip conversion successful!")

			// Verify the parsed key matches original
			if parsedPrivateKey.Size() != rsaKeyPair.PrivateKey.Size() {
				t.Error("Parsed private key size should match original")
			}
		}
	})
}

func TestFormatDetectionWithSSH(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected KeyFormat
	}{
		{
			name:     "SSH RSA public key",
			data:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7VJTUt9Us8cKB test@example.com",
			expected: FormatSSH,
		},
		{
			name:     "SSH Ed25519 public key",
			data:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test",
			expected: FormatSSH,
		},
		{
			name:     "OpenSSH private key",
			data:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE",
			expected: FormatSSH,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, err := DetectFormat([]byte(tt.data))
			if err != nil {
				t.Fatalf("Format detection failed: %v", err)
			}
			if format != tt.expected {
				t.Errorf("Expected format %v, got %v", tt.expected, format)
			}
		})
	}
}
