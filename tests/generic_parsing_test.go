package tests

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/jasoet/gopki/pkg/keypair"
)

func TestGenericPublicKeyParsing(t *testing.T) {
	t.Run("RSA public key parsing", func(t *testing.T) {
		keyPair, err := keypair.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		publicPEM, err := keyPair.PublicKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert to PEM: %v", err)
		}

		parsedKey, err := keypair.ParsePublicKeyFromPEM[*rsa.PublicKey](publicPEM)
		if err != nil {
			t.Fatalf("Failed to parse RSA public key: %v", err)
		}

		if parsedKey.N.Cmp(keyPair.PublicKey.N) != 0 {
			t.Fatal("Parsed RSA public key doesn't match original")
		}

		if parsedKey.E != keyPair.PublicKey.E {
			t.Fatal("Parsed RSA public key exponent doesn't match original")
		}
	})

	t.Run("ECDSA public key parsing", func(t *testing.T) {
		keyPair, err := keypair.GenerateECDSAKeyPair(keypair.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		publicPEM, err := keyPair.PublicKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert to PEM: %v", err)
		}

		parsedKey, err := keypair.ParsePublicKeyFromPEM[*ecdsa.PublicKey](publicPEM)
		if err != nil {
			t.Fatalf("Failed to parse ECDSA public key: %v", err)
		}

		if parsedKey.X.Cmp(keyPair.PublicKey.X) != 0 || parsedKey.Y.Cmp(keyPair.PublicKey.Y) != 0 {
			t.Fatal("Parsed ECDSA public key doesn't match original")
		}

		if parsedKey.Curve != keyPair.PublicKey.Curve {
			t.Fatal("Parsed ECDSA public key curve doesn't match original")
		}
	})

	t.Run("Ed25519 public key parsing", func(t *testing.T) {
		keyPair, err := keypair.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		publicPEM, err := keyPair.PublicKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert to PEM: %v", err)
		}

		parsedKey, err := keypair.ParsePublicKeyFromPEM[ed25519.PublicKey](publicPEM)
		if err != nil {
			t.Fatalf("Failed to parse Ed25519 public key: %v", err)
		}

		if string(parsedKey) != string(keyPair.PublicKey) {
			t.Fatal("Parsed Ed25519 public key doesn't match original")
		}
	})
}

func TestGenericPrivateKeyParsing(t *testing.T) {
	t.Run("RSA private key parsing", func(t *testing.T) {
		keyPair, err := keypair.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		privatePEM, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert to PEM: %v", err)
		}

		parsedKey, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](privatePEM)
		if err != nil {
			t.Fatalf("Failed to parse RSA private key: %v", err)
		}

		if parsedKey.N.Cmp(keyPair.PrivateKey.N) != 0 {
			t.Fatal("Parsed RSA private key doesn't match original")
		}

		if parsedKey.D.Cmp(keyPair.PrivateKey.D) != 0 {
			t.Fatal("Parsed RSA private key D doesn't match original")
		}
	})

	t.Run("ECDSA private key parsing", func(t *testing.T) {
		keyPair, err := keypair.GenerateECDSAKeyPair(keypair.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		privatePEM, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert to PEM: %v", err)
		}

		parsedKey, err := keypair.ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](privatePEM)
		if err != nil {
			t.Fatalf("Failed to parse ECDSA private key: %v", err)
		}

		if parsedKey.D.Cmp(keyPair.PrivateKey.D) != 0 {
			t.Fatal("Parsed ECDSA private key doesn't match original")
		}

		if parsedKey.Curve != keyPair.PrivateKey.Curve {
			t.Fatal("Parsed ECDSA private key curve doesn't match original")
		}
	})

	t.Run("Ed25519 private key parsing", func(t *testing.T) {
		keyPair, err := keypair.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		privatePEM, err := keyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert to PEM: %v", err)
		}

		parsedKey, err := keypair.ParsePrivateKeyFromPEM[ed25519.PrivateKey](privatePEM)
		if err != nil {
			t.Fatalf("Failed to parse Ed25519 private key: %v", err)
		}

		if string(parsedKey) != string(keyPair.PrivateKey) {
			t.Fatal("Parsed Ed25519 private key doesn't match original")
		}
	})
}

func TestGenericParsingTypeErrors(t *testing.T) {
	rsaKeyPair, _ := keypair.GenerateRSAKeyPair(2048)
	ecdsaKeyPair, _ := keypair.GenerateECDSAKeyPair(keypair.P256)
	ed25519KeyPair, _ := keypair.GenerateEd25519KeyPair()

	rsaPublicPEM, _ := rsaKeyPair.PublicKeyToPEM()
	ecdsaPublicPEM, _ := ecdsaKeyPair.PublicKeyToPEM()
	ed25519PublicPEM, _ := ed25519KeyPair.PublicKeyToPEM()

	rsaPrivatePEM, _ := rsaKeyPair.PrivateKeyToPEM()
	ecdsaPrivatePEM, _ := ecdsaKeyPair.PrivateKeyToPEM()
	ed25519PrivatePEM, _ := ed25519KeyPair.PrivateKeyToPEM()

	t.Run("Wrong public key type expectations", func(t *testing.T) {
		_, err := keypair.ParsePublicKeyFromPEM[*ecdsa.PublicKey](rsaPublicPEM)
		if err == nil {
			t.Fatal("Expected error when parsing RSA key as ECDSA")
		}

		_, err = keypair.ParsePublicKeyFromPEM[ed25519.PublicKey](rsaPublicPEM)
		if err == nil {
			t.Fatal("Expected error when parsing RSA key as Ed25519")
		}

		_, err = keypair.ParsePublicKeyFromPEM[*rsa.PublicKey](ecdsaPublicPEM)
		if err == nil {
			t.Fatal("Expected error when parsing ECDSA key as RSA")
		}

		_, err = keypair.ParsePublicKeyFromPEM[ed25519.PublicKey](ecdsaPublicPEM)
		if err == nil {
			t.Fatal("Expected error when parsing ECDSA key as Ed25519")
		}

		_, err = keypair.ParsePublicKeyFromPEM[*rsa.PublicKey](ed25519PublicPEM)
		if err == nil {
			t.Fatal("Expected error when parsing Ed25519 key as RSA")
		}

		_, err = keypair.ParsePublicKeyFromPEM[*ecdsa.PublicKey](ed25519PublicPEM)
		if err == nil {
			t.Fatal("Expected error when parsing Ed25519 key as ECDSA")
		}
	})

	t.Run("Wrong private key type expectations", func(t *testing.T) {
		_, err := keypair.ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](rsaPrivatePEM)
		if err == nil {
			t.Fatal("Expected error when parsing RSA key as ECDSA")
		}

		_, err = keypair.ParsePrivateKeyFromPEM[ed25519.PrivateKey](rsaPrivatePEM)
		if err == nil {
			t.Fatal("Expected error when parsing RSA key as Ed25519")
		}

		_, err = keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](ecdsaPrivatePEM)
		if err == nil {
			t.Fatal("Expected error when parsing ECDSA key as RSA")
		}

		_, err = keypair.ParsePrivateKeyFromPEM[ed25519.PrivateKey](ecdsaPrivatePEM)
		if err == nil {
			t.Fatal("Expected error when parsing ECDSA key as Ed25519")
		}

		_, err = keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](ed25519PrivatePEM)
		if err == nil {
			t.Fatal("Expected error when parsing Ed25519 key as RSA")
		}

		_, err = keypair.ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](ed25519PrivatePEM)
		if err == nil {
			t.Fatal("Expected error when parsing Ed25519 key as ECDSA")
		}
	})
}

func TestGenericParsingWithInvalidPEM(t *testing.T) {
	invalidPEM := []byte("invalid pem data")

	t.Run("Invalid PEM for public key", func(t *testing.T) {
		_, err := keypair.ParsePublicKeyFromPEM[*rsa.PublicKey](invalidPEM)
		if err == nil {
			t.Fatal("Expected error when parsing invalid PEM as RSA public key")
		}

		_, err = keypair.ParsePublicKeyFromPEM[*ecdsa.PublicKey](invalidPEM)
		if err == nil {
			t.Fatal("Expected error when parsing invalid PEM as ECDSA public key")
		}

		_, err = keypair.ParsePublicKeyFromPEM[ed25519.PublicKey](invalidPEM)
		if err == nil {
			t.Fatal("Expected error when parsing invalid PEM as Ed25519 public key")
		}
	})

	t.Run("Invalid PEM for private key", func(t *testing.T) {
		_, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](invalidPEM)
		if err == nil {
			t.Fatal("Expected error when parsing invalid PEM as RSA private key")
		}

		_, err = keypair.ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](invalidPEM)
		if err == nil {
			t.Fatal("Expected error when parsing invalid PEM as ECDSA private key")
		}

		_, err = keypair.ParsePrivateKeyFromPEM[ed25519.PrivateKey](invalidPEM)
		if err == nil {
			t.Fatal("Expected error when parsing invalid PEM as Ed25519 private key")
		}
	})
}

func TestGenericParsingRoundTrip(t *testing.T) {
	t.Run("RSA round trip test", func(t *testing.T) {
		originalKeyPair, err := keypair.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		privatePEM, err := originalKeyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert private key to PEM: %v", err)
		}

		publicPEM, err := originalKeyPair.PublicKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert public key to PEM: %v", err)
		}

		parsedPrivateKey, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](privatePEM)
		if err != nil {
			t.Fatalf("Failed to parse private key: %v", err)
		}

		parsedPublicKey, err := keypair.ParsePublicKeyFromPEM[*rsa.PublicKey](publicPEM)
		if err != nil {
			t.Fatalf("Failed to parse public key: %v", err)
		}

		if parsedPrivateKey.N.Cmp(originalKeyPair.PrivateKey.N) != 0 {
			t.Fatal("Parsed private key doesn't match original")
		}

		if parsedPublicKey.N.Cmp(originalKeyPair.PublicKey.N) != 0 {
			t.Fatal("Parsed public key doesn't match original")
		}
	})

	t.Run("ECDSA round trip test", func(t *testing.T) {
		originalKeyPair, err := keypair.GenerateECDSAKeyPair(keypair.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		privatePEM, err := originalKeyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert private key to PEM: %v", err)
		}

		parsedPrivateKey, err := keypair.ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](privatePEM)
		if err != nil {
			t.Fatalf("Failed to parse private key: %v", err)
		}

		if parsedPrivateKey.D.Cmp(originalKeyPair.PrivateKey.D) != 0 {
			t.Fatal("Parsed private key doesn't match original")
		}
	})

	t.Run("Ed25519 round trip test", func(t *testing.T) {
		originalKeyPair, err := keypair.GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
		}

		privatePEM, err := originalKeyPair.PrivateKeyToPEM()
		if err != nil {
			t.Fatalf("Failed to convert private key to PEM: %v", err)
		}

		parsedPrivateKey, err := keypair.ParsePrivateKeyFromPEM[ed25519.PrivateKey](privatePEM)
		if err != nil {
			t.Fatalf("Failed to parse private key: %v", err)
		}

		if string(parsedPrivateKey) != string(originalKeyPair.PrivateKey) {
			t.Fatal("Parsed private key doesn't match original")
		}
	})
}