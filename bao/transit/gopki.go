// Package transit provides gopki integration for seamless key import/export
// with OpenBao Transit secrets engine.
package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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

// ImportFromManager imports a keypair from a gopki Manager into Transit.
// This helper automatically detects the key type from the Manager and imports it.
//
// Supports all Manager types:
//   - Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]
//   - Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey]
//   - Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]
//
// Example:
//
//	manager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
//	err := client.ImportFromManager(ctx, "my-key", manager, &transit.ImportKeyOptions{
//	    Exportable: true,
//	})
func (c *Client) ImportFromManager(ctx context.Context, name string, manager interface{}, opts *ImportKeyOptions) error {
	// Try to extract the keypair from the manager and import based on type
	switch m := manager.(type) {
	case *keypair.Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]:
		return c.ImportRSAKeyPair(ctx, name, m.KeyPair(), opts)
	case *keypair.Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey]:
		return c.ImportECDSAKeyPair(ctx, name, m.KeyPair(), opts)
	case *keypair.Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]:
		return c.ImportEd25519KeyPair(ctx, name, m.KeyPair(), opts)
	default:
		return fmt.Errorf("unsupported manager type: %T", manager)
	}
}

// ExportToRSAManager exports a Transit RSA key and wraps it in a gopki Manager.
// The key must have been created with exportable=true.
//
// Example:
//
//	manager, err := client.ExportToRSAManager(ctx, "my-rsa-key", 1)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Use manager for PEM/DER/SSH conversion, validation, etc.
func (c *Client) ExportToRSAManager(ctx context.Context, name string, version int) (*keypair.Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey], error) {
	rsaKeyPair, err := c.ExportToRSAKeyPair(ctx, name, version)
	if err != nil {
		return nil, err
	}

	return keypair.NewManager(rsaKeyPair, rsaKeyPair.PrivateKey, rsaKeyPair.PublicKey), nil
}

// ExportToECDSAManager exports a Transit ECDSA key and wraps it in a gopki Manager.
// The key must have been created with exportable=true.
//
// Example:
//
//	manager, err := client.ExportToECDSAManager(ctx, "my-ecdsa-key", 1)
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *Client) ExportToECDSAManager(ctx context.Context, name string, version int) (*keypair.Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey], error) {
	ecdsaKeyPair, err := c.ExportToECDSAKeyPair(ctx, name, version)
	if err != nil {
		return nil, err
	}

	return keypair.NewManager(ecdsaKeyPair, ecdsaKeyPair.PrivateKey, ecdsaKeyPair.PublicKey), nil
}

// ExportToEd25519Manager exports a Transit Ed25519 key and wraps it in a gopki Manager.
// The key must have been created with exportable=true.
//
// Example:
//
//	manager, err := client.ExportToEd25519Manager(ctx, "my-ed25519-key", 1)
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *Client) ExportToEd25519Manager(ctx context.Context, name string, version int) (*keypair.Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey], error) {
	ed25519KeyPair, err := c.ExportToEd25519KeyPair(ctx, name, version)
	if err != nil {
		return nil, err
	}

	return keypair.NewManager(ed25519KeyPair, ed25519KeyPair.PrivateKey, ed25519KeyPair.PublicKey), nil
}

// parsePrivateKeyFromBase64 parses base64-encoded PKCS#8 private keys from Transit.
// Transit exports keys as base64-encoded DER format (PKCS#8).
//
// This function:
//  1. Decodes the base64 string to get raw DER bytes
//  2. Parses the DER bytes as PKCS#8 private key
//  3. Returns the native Go crypto private key type
//
// Supported key types:
//   - *rsa.PrivateKey
//   - *ecdsa.PrivateKey
//   - ed25519.PrivateKey
func parsePrivateKeyFromBase64(base64Data string) (interface{}, error) {
	// Decode base64 to get DER bytes
	derBytes, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	// Parse PKCS#8 private key
	privateKey, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}

	return privateKey, nil
}
