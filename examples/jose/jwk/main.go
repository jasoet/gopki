//go:build example

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jasoet/gopki/jose/jwk"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	fmt.Println("=== GoPKI JWK Module - Comprehensive Examples ===")
	fmt.Println("Demonstrating JWK (JSON Web Key) functionality")
	fmt.Println()

	// Create outputs directory
	if err := os.MkdirAll("output", 0o755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Part 1: JWK Export
	fmt.Println("📤 PART 1: Export Keys to JWK Format")
	fmt.Println(strings.Repeat("=", 70))
	jwkExportExample()

	// Part 2: JWK Import
	fmt.Println("\n📥 PART 2: Import Keys from JWK Format")
	fmt.Println(strings.Repeat("=", 70))
	jwkImportExample()

	// Part 3: JWK Sets (JWKS)
	fmt.Println("\n📚 PART 3: JWK Sets (JWKS)")
	fmt.Println(strings.Repeat("=", 70))
	jwkSetExample()

	// Part 4: Key Rotation
	fmt.Println("\n🔄 PART 4: Key Rotation")
	fmt.Println(strings.Repeat("=", 70))
	keyRotationExample()

	// Part 5: Real-World Use Cases
	fmt.Println("\n🌐 PART 5: Real-World Use Cases")
	fmt.Println(strings.Repeat("=", 70))
	oidcDiscoveryExample()
	multiAlgorithmExample()

	fmt.Println("\n✅ All examples completed successfully!")
	fmt.Println("📁 JWK files saved to output/jwk_*.json")
}

func jwkExportExample() {
	// RSA Key Export
	fmt.Println("\n🔑 RSA Key Export:")
	rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}

	rsaJWK, err := jwk.FromPublicKey(rsaKeys.PublicKey, "sig", "rsa-signing-key-2024")
	if err != nil {
		log.Fatal("Failed to export RSA key:", err)
	}

	fmt.Println("   Key Type: RSA")
	fmt.Println("   Use: Signature")
	fmt.Println("   Key ID: rsa-signing-key-2024")
	fmt.Printf("   Parameters: n (modulus), e (exponent)\n")

	// Marshal to JSON
	rsaJSON, _ := rsaJWK.MarshalIndent("", "  ")
	os.WriteFile("output/jwk_rsa_public.json", rsaJSON, 0o644)
	fmt.Println("   ✓ Saved to output/jwk_rsa_public.json")

	// ECDSA Key Export (P-256)
	fmt.Println("\n🔑 ECDSA P-256 Key Export:")
	ecKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
	ecJWK, _ := jwk.FromPublicKey(ecKeys.PublicKey, "sig", "ec-p256-key-2024")

	fmt.Println("   Key Type: EC")
	fmt.Println("   Curve: P-256")
	fmt.Println("   Use: Signature")
	fmt.Printf("   Parameters: crv (curve), x, y (coordinates)\n")

	ecJSON, _ := ecJWK.MarshalIndent("", "  ")
	os.WriteFile("output/jwk_ec_p256_public.json", ecJSON, 0o644)
	fmt.Println("   ✓ Saved to output/jwk_ec_p256_public.json")

	// ECDSA P-384
	fmt.Println("\n🔑 ECDSA P-384 Key Export:")
	ecP384Keys, _ := algo.GenerateECDSAKeyPair(algo.P384)
	ecP384JWK, _ := jwk.FromPublicKey(ecP384Keys.PublicKey, "sig", "ec-p384-key-2024")
	fmt.Println("   Curve: P-384")
	ecP384JSON, _ := ecP384JWK.MarshalIndent("", "  ")
	os.WriteFile("output/jwk_ec_p384_public.json", ecP384JSON, 0o644)
	fmt.Println("   ✓ Saved to output/jwk_ec_p384_public.json")

	// ECDSA P-521
	fmt.Println("\n🔑 ECDSA P-521 Key Export:")
	ecP521Keys, _ := algo.GenerateECDSAKeyPair(algo.P521)
	ecP521JWK, _ := jwk.FromPublicKey(ecP521Keys.PublicKey, "sig", "ec-p521-key-2024")
	fmt.Println("   Curve: P-521")
	ecP521JSON, _ := ecP521JWK.MarshalIndent("", "  ")
	os.WriteFile("output/jwk_ec_p521_public.json", ecP521JSON, 0o644)
	fmt.Println("   ✓ Saved to output/jwk_ec_p521_public.json")

	// Ed25519 Key Export
	fmt.Println("\n🔑 Ed25519 Key Export:")
	edKeys, _ := algo.GenerateEd25519KeyPair()
	edJWK, _ := jwk.FromPublicKey(edKeys.PublicKey, "sig", "ed25519-key-2024")

	fmt.Println("   Key Type: OKP (Octet Key Pair)")
	fmt.Println("   Curve: Ed25519")
	fmt.Println("   Use: Signature")
	fmt.Printf("   Parameters: crv (curve), x (public key bytes)\n")

	edJSON, _ := edJWK.MarshalIndent("", "  ")
	os.WriteFile("output/jwk_ed25519_public.json", edJSON, 0o644)
	fmt.Println("   ✓ Saved to output/jwk_ed25519_public.json")
}

func jwkImportExample() {
	// Generate and export a key
	fmt.Println("\n📥 Import RSA Key from JWK:")
	rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	exportedJWK, _ := jwk.FromPublicKey(rsaKeys.PublicKey, "sig", "import-test")

	// Marshal to JSON
	jsonBytes, _ := exportedJWK.Marshal()
	fmt.Printf("   JWK JSON: %s...\n", string(jsonBytes[:60]))

	// Parse JWK from JSON
	parsedJWK, err := jwk.Parse(jsonBytes)
	if err != nil {
		log.Fatal("Failed to parse JWK:", err)
	}

	fmt.Println("   ✓ Parsed JWK from JSON")
	fmt.Printf("   - Key Type: %s\n", parsedJWK.KeyType)
	fmt.Printf("   - Key ID: %s\n", parsedJWK.KeyID)
	fmt.Printf("   - Use: %s\n", parsedJWK.Use)

	// Convert to public key
	publicKey, err := parsedJWK.ToPublicKey()
	if err != nil {
		log.Fatal("Failed to convert to public key:", err)
	}

	fmt.Println("   ✓ Converted to Go public key")
	fmt.Printf("   - Type: %T\n", publicKey)

	// Round-trip test for different key types
	fmt.Println("\n📥 Round-trip Test (Export → Import):")

	// ECDSA
	ecKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
	ecJWK, _ := jwk.FromPublicKey(ecKeys.PublicKey, "sig", "roundtrip-ec")
	ecJSON, _ := ecJWK.Marshal()
	ecParsed, _ := jwk.Parse(ecJSON)
	ecPubKey, _ := ecParsed.ToPublicKey()
	fmt.Printf("   ✓ ECDSA P-256: %T\n", ecPubKey)

	// Ed25519
	edKeys, _ := algo.GenerateEd25519KeyPair()
	edJWK, _ := jwk.FromPublicKey(edKeys.PublicKey, "sig", "roundtrip-ed")
	edJSON, _ := edJWK.Marshal()
	edParsed, _ := jwk.Parse(edJSON)
	edPubKey, _ := edParsed.ToPublicKey()
	fmt.Printf("   ✓ Ed25519: %T\n", edPubKey)
}

func jwkSetExample() {
	fmt.Println("\n📚 Creating JWK Set with Multiple Keys:")

	// Create JWK Set
	jwkSet := &jwk.JWKSet{}

	// Add RSA key
	rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	rsaJWK, _ := jwk.FromPublicKey(rsaKeys.PublicKey, "sig", "rsa-2024-10")
	jwkSet.Add(rsaJWK)
	fmt.Println("   ✓ Added RSA key (kid: rsa-2024-10)")

	// Add ECDSA key
	ecKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
	ecJWK, _ := jwk.FromPublicKey(ecKeys.PublicKey, "sig", "ec-2024-10")
	jwkSet.Add(ecJWK)
	fmt.Println("   ✓ Added ECDSA P-256 key (kid: ec-2024-10)")

	// Add Ed25519 key
	edKeys, _ := algo.GenerateEd25519KeyPair()
	edJWK, _ := jwk.FromPublicKey(edKeys.PublicKey, "sig", "ed-2024-10")
	jwkSet.Add(edJWK)
	fmt.Println("   ✓ Added Ed25519 key (kid: ed-2024-10)")

	// Add encryption key
	rsaEncKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	rsaEncJWK, _ := jwk.FromPublicKey(rsaEncKeys.PublicKey, "enc", "rsa-enc-2024-10")
	jwkSet.Add(rsaEncJWK)
	fmt.Println("   ✓ Added RSA encryption key (kid: rsa-enc-2024-10)")

	fmt.Printf("\n   Total keys in set: %d\n", jwkSet.Len())

	// Marshal JWKS
	jwksJSON, _ := jwkSet.MarshalIndent("", "  ")
	os.WriteFile("output/jwks_example.json", jwksJSON, 0o644)
	fmt.Println("   ✓ Saved to output/jwks_example.json")

	// Query operations
	fmt.Println("\n📚 JWKS Query Operations:")

	// Find by key ID
	foundKey, err := jwkSet.FindByKeyID("ec-2024-10")
	if err == nil {
		fmt.Printf("   ✓ Found key by ID: %s (type: %s)\n", foundKey.KeyID, foundKey.KeyType)
	}

	// Find by use
	sigKeys := jwkSet.FindByUse("sig")
	fmt.Printf("   ✓ Found %d signature keys\n", len(sigKeys))

	encKeys := jwkSet.FindByUse("enc")
	fmt.Printf("   ✓ Found %d encryption keys\n", len(encKeys))

	// Remove a key
	removed := jwkSet.Remove("rsa-2024-10")
	if removed {
		fmt.Printf("   ✓ Removed key: rsa-2024-10 (remaining: %d)\n", jwkSet.Len())
	}
}

func keyRotationExample() {
	fmt.Println("\n🔄 Key Rotation Scenario:")

	// Initial JWKS with current key
	jwkSet := &jwk.JWKSet{}

	currentKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	currentJWK, _ := jwk.FromPublicKey(currentKeys.PublicKey, "sig", "2024-10")
	jwkSet.Add(currentJWK)

	fmt.Println("\n   Initial State:")
	fmt.Println("   - Current key: 2024-10 (October)")
	fmt.Printf("   - Total keys: %d\n", jwkSet.Len())

	// Add new key for rotation
	fmt.Println("\n   Step 1: Add New Key (Rotation Period Starts)")
	newKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	newJWK, _ := jwk.FromPublicKey(newKeys.PublicKey, "sig", "2024-11")
	jwkSet.Add(newJWK)

	fmt.Println("   - New key: 2024-11 (November)")
	fmt.Printf("   - Total keys: %d\n", jwkSet.Len())
	fmt.Println("   - Both keys active for gradual migration")

	// Save rotation state
	rotationJSON, _ := jwkSet.MarshalIndent("", "  ")
	os.WriteFile("output/jwks_rotation.json", rotationJSON, 0o644)
	fmt.Println("   ✓ Saved rotation JWKS to output/jwks_rotation.json")

	// Remove old key after grace period
	fmt.Println("\n   Step 2: Remove Old Key (After Grace Period)")
	jwkSet.Remove("2024-10")
	fmt.Println("   - Removed old key: 2024-10")
	fmt.Printf("   - Total keys: %d\n", jwkSet.Len())
	fmt.Println("   - Only new key remains")

	// Timeline
	fmt.Println("\n   Rotation Timeline:")
	fmt.Println("   Day 0: Add new key 2024-11, keep old key 2024-10")
	fmt.Println("   Day 1-30: Both keys active (grace period)")
	fmt.Println("   Day 31: Remove old key 2024-10")
	fmt.Println("   Result: Zero-downtime key rotation")
}

func oidcDiscoveryExample() {
	fmt.Println("\n🌐 Use Case: OIDC Discovery Endpoint")
	fmt.Println("   (OpenID Connect /.well-known/jwks.json)")

	// Create JWKS for OIDC provider
	jwkSet := &jwk.JWKSet{}

	// Current signing key (RSA)
	currentRSA, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	currentJWK, _ := jwk.FromPublicKey(currentRSA.PublicKey, "sig", "oidc-2024-10-primary")
	jwkSet.Add(currentJWK)

	// Backup signing key (ECDSA)
	backupEC, _ := algo.GenerateECDSAKeyPair(algo.P256)
	backupJWK, _ := jwk.FromPublicKey(backupEC.PublicKey, "sig", "oidc-2024-10-backup")
	jwkSet.Add(backupJWK)

	// Previous key (for validation during rotation)
	previousRSA, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	previousJWK, _ := jwk.FromPublicKey(previousRSA.PublicKey, "sig", "oidc-2024-09")
	jwkSet.Add(previousJWK)

	fmt.Println("\n   OIDC Provider Keys:")
	fmt.Println("   - Primary: RSA 2048 (oidc-2024-10-primary)")
	fmt.Println("   - Backup: ECDSA P-256 (oidc-2024-10-backup)")
	fmt.Println("   - Previous: RSA 2048 (oidc-2024-09)")
	fmt.Printf("   - Total: %d keys\n", jwkSet.Len())

	// Save as OIDC JWKS
	jwksJSON, _ := jwkSet.MarshalIndent("", "  ")
	os.WriteFile("output/jwks_oidc_discovery.json", jwksJSON, 0o644)

	fmt.Println("\n   Endpoint: /.well-known/jwks.json")
	fmt.Println("   ✓ Saved to output/jwks_oidc_discovery.json")

	fmt.Println("\n   Client Usage:")
	fmt.Println("   1. Client fetches JWKS from discovery endpoint")
	fmt.Println("   2. Client extracts 'kid' from JWT header")
	fmt.Println("   3. Client finds matching key in JWKS")
	fmt.Println("   4. Client verifies JWT signature")
}

func multiAlgorithmExample() {
	fmt.Println("\n🔐 Use Case: Multi-Algorithm Support")
	fmt.Println("   (Support clients with different cryptographic preferences)")

	jwkSet := &jwk.JWKSet{}

	// Algorithm 1: RSA (widely supported, compatible)
	rsaKeys, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	rsaJWK, _ := jwk.FromPublicKey(rsaKeys.PublicKey, "sig", "rsa-for-compatibility")
	jwkSet.Add(rsaJWK)

	// Algorithm 2: ECDSA (smaller signatures, modern)
	ecKeys, _ := algo.GenerateECDSAKeyPair(algo.P256)
	ecJWK, _ := jwk.FromPublicKey(ecKeys.PublicKey, "sig", "ec-for-modern-clients")
	jwkSet.Add(ecJWK)

	// Algorithm 3: Ed25519 (fastest, most secure)
	edKeys, _ := algo.GenerateEd25519KeyPair()
	edJWK, _ := jwk.FromPublicKey(edKeys.PublicKey, "sig", "ed-for-high-security")
	jwkSet.Add(edJWK)

	fmt.Println("\n   Supported Algorithms:")
	fmt.Println("   1. RS256 (RSA-SHA256)")
	fmt.Println("      - Use: Legacy/compatibility")
	fmt.Println("      - Key: rsa-for-compatibility")
	fmt.Println("      - Clients: All clients")

	fmt.Println("\n   2. ES256 (ECDSA-P256-SHA256)")
	fmt.Println("      - Use: Modern applications")
	fmt.Println("      - Key: ec-for-modern-clients")
	fmt.Println("      - Clients: Modern browsers, mobile apps")

	fmt.Println("\n   3. EdDSA (Ed25519)")
	fmt.Println("      - Use: High-security applications")
	fmt.Println("      - Key: ed-for-high-security")
	fmt.Println("      - Clients: Cutting-edge systems")

	// Save
	jwksJSON, _ := jwkSet.MarshalIndent("", "  ")
	os.WriteFile("output/jwks_multi_algorithm.json", jwksJSON, 0o644)

	fmt.Println("\n   ✓ Saved to output/jwks_multi_algorithm.json")

	fmt.Println("\n   Client Selection Strategy:")
	fmt.Println("   - Client specifies preferred algorithm in request")
	fmt.Println("   - Server signs with corresponding key")
	fmt.Println("   - Client verifies using matching public key from JWKS")

	fmt.Println("\n   Benefits:")
	fmt.Println("   - Support old and new clients simultaneously")
	fmt.Println("   - Gradual algorithm migration")
	fmt.Println("   - Performance optimization per client capability")
}
