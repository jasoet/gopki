package keypair

import (
	"github.com/jasoet/gopki/keypair/algo"
	"os"
	"path/filepath"
	"testing"
)

func TestRSAKeyPairFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFile := filepath.Join(tempDir, "test_rsa_private.pem")
	publicKeyFile := filepath.Join(tempDir, "test_rsa_public.pem")

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

	err = os.WriteFile(privateKeyFile, privatePEM, 0600)
	if err != nil {
		t.Fatalf("Failed to save private key to file: %v", err)
	}

	err = os.WriteFile(publicKeyFile, publicPEM, 0600)
	if err != nil {
		t.Fatalf("Failed to save public key to file: %v", err)
	}

	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		t.Fatal("Private key file was not created")
	}

	if _, err := os.Stat(publicKeyFile); os.IsNotExist(err) {
		t.Fatal("Public key file was not created")
	}

	loadedPrivatePEM, err := os.ReadFile(privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to load private key from file: %v", err)
	}

	loadedKeyPair, err := algo.RSAKeyPairFromPEM(loadedPrivatePEM)
	if err != nil {
		t.Fatalf("Failed to parse loaded private key: %v", err)
	}

	if loadedKeyPair.PrivateKey.Size() != keyPair.PrivateKey.Size() {
		t.Fatal("Loaded key pair does not match original")
	}

	info, err := os.Stat(privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Fatalf("Private key file has incorrect permissions: %v", info.Mode().Perm())
	}
}

func TestECDSAKeyPairFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFile := filepath.Join(tempDir, "test_ecdsa_private.pem")
	publicKeyFile := filepath.Join(tempDir, "test_ecdsa_public.pem")

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

	err = os.WriteFile(privateKeyFile, privatePEM, 0600)
	if err != nil {
		t.Fatalf("Failed to save private key to file: %v", err)
	}

	err = os.WriteFile(publicKeyFile, publicPEM, 0600)
	if err != nil {
		t.Fatalf("Failed to save public key to file: %v", err)
	}

	loadedPrivatePEM, err := os.ReadFile(privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to load private key from file: %v", err)
	}

	loadedKeyPair, err := algo.ECDSAKeyPairFromPEM(loadedPrivatePEM)
	if err != nil {
		t.Fatalf("Failed to parse loaded private key: %v", err)
	}

	if loadedKeyPair.PrivateKey.Curve != keyPair.PrivateKey.Curve {
		t.Fatal("Loaded key pair curve does not match original")
	}
}

func TestEd25519KeyPairFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFile := filepath.Join(tempDir, "test_ed25519_private.pem")
	publicKeyFile := filepath.Join(tempDir, "test_ed25519_public.pem")

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

	err = os.WriteFile(privateKeyFile, privatePEM, 0600)
	if err != nil {
		t.Fatalf("Failed to save private key to file: %v", err)
	}

	err = os.WriteFile(publicKeyFile, publicPEM, 0600)
	if err != nil {
		t.Fatalf("Failed to save public key to file: %v", err)
	}

	loadedPrivatePEM, err := os.ReadFile(privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to load private key from file: %v", err)
	}

	loadedKeyPair, err := algo.Ed25519KeyPairFromPEM(loadedPrivatePEM)
	if err != nil {
		t.Fatalf("Failed to parse loaded private key: %v", err)
	}

	if len(loadedKeyPair.PrivateKey) != len(keyPair.PrivateKey) {
		t.Fatal("Loaded key pair does not match original")
	}
}

func TestMultipleKeyPairFiles(t *testing.T) {
	tempDir := t.TempDir()

	rsaKeyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	ecdsaKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ed25519KeyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	rsaPrivatePEM, _ := rsaKeyPair.PrivateKeyToPEM()
	ecdsaPrivatePEM, _ := ecdsaKeyPair.PrivateKeyToPEM()
	ed25519PrivatePEM, _ := ed25519KeyPair.PrivateKeyToPEM()

	rsaFile := filepath.Join(tempDir, "multi_rsa.pem")
	ecdsaFile := filepath.Join(tempDir, "multi_ecdsa.pem")
	ed25519File := filepath.Join(tempDir, "multi_ed25519.pem")

	os.WriteFile(rsaFile, rsaPrivatePEM, 0600)
	os.WriteFile(ecdsaFile, ecdsaPrivatePEM, 0600)
	os.WriteFile(ed25519File, ed25519PrivatePEM, 0600)

	loadedRSA, err := os.ReadFile(rsaFile)
	if err != nil {
		t.Fatalf("Failed to load RSA key: %v", err)
	}

	loadedECDSA, err := os.ReadFile(ecdsaFile)
	if err != nil {
		t.Fatalf("Failed to load ECDSA key: %v", err)
	}

	loadedEd25519, err := os.ReadFile(ed25519File)
	if err != nil {
		t.Fatalf("Failed to load Ed25519 key: %v", err)
	}

	_, err = algo.RSAKeyPairFromPEM(loadedRSA)
	if err != nil {
		t.Fatalf("Failed to parse RSA key: %v", err)
	}

	_, err = algo.ECDSAKeyPairFromPEM(loadedECDSA)
	if err != nil {
		t.Fatalf("Failed to parse ECDSA key: %v", err)
	}

	_, err = algo.Ed25519KeyPairFromPEM(loadedEd25519)
	if err != nil {
		t.Fatalf("Failed to parse Ed25519 key: %v", err)
	}
}
