package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jasoet/gopki/pkg/keypair"
	"github.com/jasoet/gopki/pkg/utils"
)

func TestRSAKeyPairFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyFile := filepath.Join(tempDir, "test_rsa_private.pem")
	publicKeyFile := filepath.Join(tempDir, "test_rsa_public.pem")

	keyPair, err := keypair.GenerateRSAKeyPair(2048)
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

	err = utils.SavePEMToFile(privatePEM, privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to save private key to file: %v", err)
	}

	err = utils.SavePEMToFile(publicPEM, publicKeyFile)
	if err != nil {
		t.Fatalf("Failed to save public key to file: %v", err)
	}

	if !utils.FileExists(privateKeyFile) {
		t.Fatal("Private key file was not created")
	}

	if !utils.FileExists(publicKeyFile) {
		t.Fatal("Public key file was not created")
	}

	loadedPrivatePEM, err := utils.LoadPEMFromFile(privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to load private key from file: %v", err)
	}

	loadedKeyPair, err := keypair.RSAKeyPairFromPEM(loadedPrivatePEM)
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

	keyPair, err := keypair.GenerateECDSAKeyPair(keypair.P256)
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

	err = utils.SavePEMToFile(privatePEM, privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to save private key to file: %v", err)
	}

	err = utils.SavePEMToFile(publicPEM, publicKeyFile)
	if err != nil {
		t.Fatalf("Failed to save public key to file: %v", err)
	}

	loadedPrivatePEM, err := utils.LoadPEMFromFile(privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to load private key from file: %v", err)
	}

	loadedKeyPair, err := keypair.ECDSAKeyPairFromPEM(loadedPrivatePEM)
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

	keyPair, err := keypair.GenerateEd25519KeyPair()
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

	err = utils.SavePEMToFile(privatePEM, privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to save private key to file: %v", err)
	}

	err = utils.SavePEMToFile(publicPEM, publicKeyFile)
	if err != nil {
		t.Fatalf("Failed to save public key to file: %v", err)
	}

	loadedPrivatePEM, err := utils.LoadPEMFromFile(privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to load private key from file: %v", err)
	}

	loadedKeyPair, err := keypair.Ed25519KeyPairFromPEM(loadedPrivatePEM)
	if err != nil {
		t.Fatalf("Failed to parse loaded private key: %v", err)
	}

	if len(loadedKeyPair.PrivateKey) != len(keyPair.PrivateKey) {
		t.Fatal("Loaded key pair does not match original")
	}
}

func TestMultipleKeyPairFiles(t *testing.T) {
	tempDir := t.TempDir()

	rsaKeyPair, err := keypair.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	ecdsaKeyPair, err := keypair.GenerateECDSAKeyPair(keypair.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ed25519KeyPair, err := keypair.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	rsaPrivatePEM, _ := rsaKeyPair.PrivateKeyToPEM()
	ecdsaPrivatePEM, _ := ecdsaKeyPair.PrivateKeyToPEM()
	ed25519PrivatePEM, _ := ed25519KeyPair.PrivateKeyToPEM()

	rsaFile := filepath.Join(tempDir, "multi_rsa.pem")
	ecdsaFile := filepath.Join(tempDir, "multi_ecdsa.pem")
	ed25519File := filepath.Join(tempDir, "multi_ed25519.pem")

	utils.SavePEMToFile(rsaPrivatePEM, rsaFile)
	utils.SavePEMToFile(ecdsaPrivatePEM, ecdsaFile)
	utils.SavePEMToFile(ed25519PrivatePEM, ed25519File)

	loadedRSA, err := utils.LoadPEMFromFile(rsaFile)
	if err != nil {
		t.Fatalf("Failed to load RSA key: %v", err)
	}

	loadedECDSA, err := utils.LoadPEMFromFile(ecdsaFile)
	if err != nil {
		t.Fatalf("Failed to load ECDSA key: %v", err)
	}

	loadedEd25519, err := utils.LoadPEMFromFile(ed25519File)
	if err != nil {
		t.Fatalf("Failed to load Ed25519 key: %v", err)
	}

	_, err = keypair.RSAKeyPairFromPEM(loadedRSA)
	if err != nil {
		t.Fatalf("Failed to parse RSA key: %v", err)
	}

	_, err = keypair.ECDSAKeyPairFromPEM(loadedECDSA)
	if err != nil {
		t.Fatalf("Failed to parse ECDSA key: %v", err)
	}

	_, err = keypair.Ed25519KeyPairFromPEM(loadedEd25519)
	if err != nil {
		t.Fatalf("Failed to parse Ed25519 key: %v", err)
	}
}