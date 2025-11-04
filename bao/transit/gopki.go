// Package transit provides gopki integration for seamless key import/export
// with OpenBao Transit secrets engine.
package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

// ImportRSAKeyPair imports an RSA keypair from gopki into Transit.
// This helper automatically converts the key to the correct format.
//
// Example:
//
//	rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
//	err := client.ImportRSAKeyPair(ctx, "my-signing-key", rsaKeyPair, &transit.ImportKeyOptions{
//	    Exportable: true,
//	})
func (c *Client) ImportRSAKeyPair(ctx context.Context, name string, kp *algo.RSAKeyPair, opts *ImportKeyOptions) error {
	// Convert private key to PKCS#8 DER format
	keyBytes, err := keypair.PrivateKeyToDER(kp.PrivateKey)
	if err != nil {
		return fmt.Errorf("convert RSA key to DER: %w", err)
	}
	defer secureZero(keyBytes)

	// Set default options if not provided
	if opts == nil {
		opts = &ImportKeyOptions{}
	}

	// Auto-detect key type if not specified
	if opts.Type == "" {
		keySize := kp.PrivateKey.Size() * 8 // Convert bytes to bits
		switch keySize {
		case 2048:
			opts.Type = KeyTypeRSA2048
		case 3072:
			opts.Type = KeyTypeRSA3072
		case 4096:
			opts.Type = KeyTypeRSA4096
		default:
			return fmt.Errorf("unsupported RSA key size: %d bits", keySize)
		}
	}

	return c.ImportKey(ctx, name, keyBytes, opts)
}

// ImportECDSAKeyPair imports an ECDSA keypair from gopki into Transit.
// This helper automatically converts the key to the correct format.
//
// Example:
//
//	ecdsaKeyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
//	err := client.ImportECDSAKeyPair(ctx, "my-signing-key", ecdsaKeyPair, &transit.ImportKeyOptions{
//	    Exportable: true,
//	})
func (c *Client) ImportECDSAKeyPair(ctx context.Context, name string, kp *algo.ECDSAKeyPair, opts *ImportKeyOptions) error {
	// Convert private key to PKCS#8 DER format
	keyBytes, err := keypair.PrivateKeyToDER(kp.PrivateKey)
	if err != nil {
		return fmt.Errorf("convert ECDSA key to DER: %w", err)
	}
	defer secureZero(keyBytes)

	// Set default options if not provided
	if opts == nil {
		opts = &ImportKeyOptions{}
	}

	// Auto-detect key type if not specified
	if opts.Type == "" {
		curveBits := kp.PrivateKey.Curve.Params().BitSize
		switch curveBits {
		case 256:
			opts.Type = KeyTypeECDSAP256
		case 384:
			opts.Type = KeyTypeECDSAP384
		case 521:
			opts.Type = KeyTypeECDSAP521
		default:
			return fmt.Errorf("unsupported ECDSA curve size: %d bits", curveBits)
		}
	}

	return c.ImportKey(ctx, name, keyBytes, opts)
}

// ImportEd25519KeyPair imports an Ed25519 keypair from gopki into Transit.
// This helper automatically converts the key to the correct format.
//
// Example:
//
//	ed25519KeyPair, _ := algo.GenerateEd25519KeyPair()
//	err := client.ImportEd25519KeyPair(ctx, "my-signing-key", ed25519KeyPair, &transit.ImportKeyOptions{
//	    Exportable: true,
//	})
func (c *Client) ImportEd25519KeyPair(ctx context.Context, name string, kp *algo.Ed25519KeyPair, opts *ImportKeyOptions) error {
	// Convert private key to PKCS#8 DER format
	keyBytes, err := keypair.PrivateKeyToDER(kp.PrivateKey)
	if err != nil {
		return fmt.Errorf("convert Ed25519 key to DER: %w", err)
	}
	defer secureZero(keyBytes)

	// Set default options if not provided
	if opts == nil {
		opts = &ImportKeyOptions{}
	}

	// Set Ed25519 key type
	if opts.Type == "" {
		opts.Type = KeyTypeEd25519
	}

	return c.ImportKey(ctx, name, keyBytes, opts)
}

// ImportAESKey imports an AES encryption key into Transit.
// The key must be either 16 bytes (AES-128) or 32 bytes (AES-256).
//
// Example:
//
//	aesKey := make([]byte, 32) // AES-256
//	rand.Read(aesKey)
//	err := client.ImportAESKey(ctx, "my-aes-key", aesKey, &transit.ImportKeyOptions{
//	    Exportable: true,
//	})
func (c *Client) ImportAESKey(ctx context.Context, name string, keyBytes []byte, opts *ImportKeyOptions) error {
	if opts == nil {
		opts = &ImportKeyOptions{}
	}

	// Auto-detect AES key type based on size
	if opts.Type == "" {
		switch len(keyBytes) {
		case 16:
			opts.Type = KeyTypeAES128GCM96
		case 32:
			opts.Type = KeyTypeAES256GCM96
		default:
			return fmt.Errorf("invalid AES key size: %d bytes (must be 16 or 32)", len(keyBytes))
		}
	}

	return c.ImportKey(ctx, name, keyBytes, opts)
}

// ExportToRSAKeyPair exports a Transit RSA key and converts it to gopki format.
// The key must have been created with exportable=true.
//
// Example:
//
//	rsaKeyPair, err := client.ExportToRSAKeyPair(ctx, "my-rsa-key", 1)
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *Client) ExportToRSAKeyPair(ctx context.Context, name string, version int) (*algo.RSAKeyPair, error) {
	// Export key from Transit
	exported, err := c.ExportKey(ctx, name, ExportSigningKey, version)
	if err != nil {
		return nil, fmt.Errorf("export key: %w", err)
	}

	// Get the first (and should be only) version
	var keyData string
	for _, data := range exported {
		keyData = data
		break
	}

	if keyData == "" {
		return nil, fmt.Errorf("no key data returned")
	}

	// Parse the private key (it's in base64-encoded DER format)
	// Note: Transit returns the raw key bytes, we need to parse as PKCS#8
	privateKey, err := parsePrivateKeyFromBase64(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	rsaPriv, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA key, got %T", privateKey)
	}

	return &algo.RSAKeyPair{
		PrivateKey: rsaPriv,
		PublicKey:  &rsaPriv.PublicKey,
	}, nil
}

// ExportToECDSAKeyPair exports a Transit ECDSA key and converts it to gopki format.
// The key must have been created with exportable=true.
//
// Example:
//
//	ecdsaKeyPair, err := client.ExportToECDSAKeyPair(ctx, "my-ecdsa-key", 1)
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *Client) ExportToECDSAKeyPair(ctx context.Context, name string, version int) (*algo.ECDSAKeyPair, error) {
	// Export key from Transit
	exported, err := c.ExportKey(ctx, name, ExportSigningKey, version)
	if err != nil {
		return nil, fmt.Errorf("export key: %w", err)
	}

	// Get the first (and should be only) version
	var keyData string
	for _, data := range exported {
		keyData = data
		break
	}

	if keyData == "" {
		return nil, fmt.Errorf("no key data returned")
	}

	// Parse the private key
	privateKey, err := parsePrivateKeyFromBase64(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	ecdsaPriv, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA key, got %T", privateKey)
	}

	return &algo.ECDSAKeyPair{
		PrivateKey: ecdsaPriv,
		PublicKey:  &ecdsaPriv.PublicKey,
	}, nil
}

// ExportToEd25519KeyPair exports a Transit Ed25519 key and converts it to gopki format.
// The key must have been created with exportable=true.
//
// Example:
//
//	ed25519KeyPair, err := client.ExportToEd25519KeyPair(ctx, "my-ed25519-key", 1)
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *Client) ExportToEd25519KeyPair(ctx context.Context, name string, version int) (*algo.Ed25519KeyPair, error) {
	// Export key from Transit
	exported, err := c.ExportKey(ctx, name, ExportSigningKey, version)
	if err != nil {
		return nil, fmt.Errorf("export key: %w", err)
	}

	// Get the first (and should be only) version
	var keyData string
	for _, data := range exported {
		keyData = data
		break
	}

	if keyData == "" {
		return nil, fmt.Errorf("no key data returned")
	}

	// Parse the private key
	privateKey, err := parsePrivateKeyFromBase64(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	ed25519Priv, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected Ed25519 key, got %T", privateKey)
	}

	return &algo.Ed25519KeyPair{
		PrivateKey: ed25519Priv,
		PublicKey:  ed25519Priv.Public().(ed25519.PublicKey),
	}, nil
}

// parsePrivateKeyFromBase64 is a helper to parse base64-encoded PKCS#8 private keys
func parsePrivateKeyFromBase64(base64Data string) (interface{}, error) {
	// Transit returns keys in base64-encoded format
	// We need to decode and then parse as PKCS#8
	// This is a placeholder - actual implementation needs to handle Transit's specific format
	return nil, fmt.Errorf("not yet implemented - needs Transit format handling")
}
