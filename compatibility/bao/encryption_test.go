//go:build compatibility

package bao_test

import (
	"bytes"
	"testing"

	"github.com/jasoet/gopki/bao"
	"github.com/jasoet/gopki/encryption/asymmetric"
	"github.com/jasoet/gopki/encryption/certificate"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestEncryption_Bao_Compatibility(t *testing.T) {
	t.Parallel()

	t.Run("RSA_OAEP_Encryption", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Key_GoPKI_Encrypt_Decrypt", testRSAOAEPBaoKeyGoPKI)
		t.Run("GoPKI_Key_Bao_Issued_Cert_Encrypt", testRSAOAEPGoPKIKeyBaoCert)
	})

	t.Run("ECDH_Key_Agreement", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_ECDSA_Key_GoPKI_ECDH", testECDHBaoKey)
		t.Run("GoPKI_Bao_Key_Agreement", testECDHGoPKIBaoKeyAgreement)
	})

	t.Run("Certificate_Based_Encryption", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Cert_Encrypt_Decrypt", testCertificateBasedEncryption)
	})
}

// testRSAOAEPBaoKeyGoPKI tests RSA-OAEP encryption with Bao-generated keys.
func testRSAOAEPBaoKeyGoPKI(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao (exported)
	keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "encryption-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Get key pair for GoPKI use
	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Test data
	plaintext := []byte("Secret message to encrypt with Bao RSA key")

	// Encrypt with GoPKI
	ciphertext, err := asymmetric.EncryptRSAOAEP(plaintext, keyPair.Public())
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt with GoPKI
	decrypted, err := asymmetric.DecryptRSAOAEP(ciphertext, keyPair)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}

	t.Logf("✓ Successfully encrypted and decrypted with Bao RSA key using GoPKI")
}

// testRSAOAEPGoPKIKeyBaoCert tests RSA-OAEP with GoPKI key and Bao-issued certificate.
func testRSAOAEPGoPKIKeyBaoCert(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role and issue certificate
	err = issuer.CreateRole(env.Ctx, "encryption", &bao.RoleOptions{
		AllowedDomains:       []string{"example.com"},
		AllowSubdomains:      true,
		TTL:                  "720h",
		KeyEnciphermentFlag:  true,
		DataEnciphermentFlag: true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "encryption", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "encryption.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	certificate := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Test data
	plaintext := []byte("Secret message encrypted for Bao certificate")

	// Encrypt for certificate
	ciphertext, err := certificate.EncryptForCertificate(plaintext, certificate)
	if err != nil {
		t.Fatalf("Failed to encrypt for certificate: %v", err)
	}

	// Decrypt with key
	decrypted, err := asymmetric.DecryptRSAOAEP(ciphertext, keyPair)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}

	t.Logf("✓ Successfully encrypted for Bao certificate and decrypted with GoPKI")
}

// testECDHBaoKey tests ECDH key agreement with Bao-generated ECDSA keys.
func testECDHBaoKey(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate first key with Bao
	keyClient1, err := env.Client.GenerateECDSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "ecdh-key-1",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key 1: %v", err)
	}

	keyPair1, err := keyClient1.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair 1: %v", err)
	}

	// Generate second key with Bao
	keyClient2, err := env.Client.GenerateECDSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "ecdh-key-2",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key 2: %v", err)
	}

	keyPair2, err := keyClient2.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair 2: %v", err)
	}

	// Perform ECDH with GoPKI
	sharedSecret1, err := asymmetric.PerformECDH(keyPair1, keyPair2.Public())
	if err != nil {
		t.Fatalf("Failed to perform ECDH from key1: %v", err)
	}

	sharedSecret2, err := asymmetric.PerformECDH(keyPair2, keyPair1.Public())
	if err != nil {
		t.Fatalf("Failed to perform ECDH from key2: %v", err)
	}

	// Shared secrets should match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Errorf("Shared secrets don't match")
	}

	t.Logf("✓ Successfully performed ECDH with Bao ECDSA keys using GoPKI")
}

// testECDHGoPKIBaoKeyAgreement tests ECDH with mixed GoPKI and Bao keys.
func testECDHGoPKIBaoKeyAgreement(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	gopkiKey, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate GoPKI key: %v", err)
	}

	// Generate key with Bao
	baoKeyClient, err := env.Client.GenerateECDSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "ecdh-key",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate Bao key: %v", err)
	}

	baoKey, err := baoKeyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get Bao key pair: %v", err)
	}

	// Perform ECDH: GoPKI key with Bao public key
	sharedSecret1, err := asymmetric.PerformECDH(gopkiKey, baoKey.Public())
	if err != nil {
		t.Fatalf("Failed to perform ECDH (GoPKI → Bao): %v", err)
	}

	// Perform ECDH: Bao key with GoPKI public key
	sharedSecret2, err := asymmetric.PerformECDH(baoKey, gopkiKey.Public())
	if err != nil {
		t.Fatalf("Failed to perform ECDH (Bao → GoPKI): %v", err)
	}

	// Shared secrets should match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Errorf("Shared secrets don't match between GoPKI and Bao keys")
	}

	t.Logf("✓ Successfully performed ECDH with mixed GoPKI and Bao keys")
}

// testCertificateBasedEncryption tests certificate-based encryption with Bao certificates.
func testCertificateBasedEncryption(t *testing.T) {
	env, issuer := SetupBaoWithCA(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create role and issue certificate
	err = issuer.CreateRole(env.Ctx, "encryption", &bao.RoleOptions{
		AllowedDomains:       []string{"example.com"},
		AllowSubdomains:      true,
		TTL:                  "720h",
		KeyEnciphermentFlag:  true,
		DataEnciphermentFlag: true,
	})
	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	certClient, err := env.Client.IssueRSACertificate(env.Ctx, "encryption", keyPair, &bao.GenerateCertificateOptions{
		CommonName: "encryption.example.com",
		TTL:        "720h",
	})
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	cert, err := certClient.Certificate()
	if err != nil {
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Test data
	plaintext := []byte("Secret message for certificate-based encryption")

	// Encrypt for certificate using GoPKI
	ciphertext, err := certificate.EncryptForCertificate(plaintext, cert)
	if err != nil {
		t.Fatalf("Failed to encrypt for certificate: %v", err)
	}

	// Decrypt using certificate and key
	decrypted, err := certificate.DecryptWithCertificate(ciphertext, cert, keyPair)
	if err != nil {
		t.Fatalf("Failed to decrypt with certificate: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}

	t.Logf("✓ Successfully performed certificate-based encryption with Bao certificate")
}
