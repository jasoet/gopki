//go:build compatibility

package bao_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jasoet/gopki/bao"
	"github.com/jasoet/gopki/jose/jwk"
	"github.com/jasoet/gopki/jose/jws"
	"github.com/jasoet/gopki/jose/jwt"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestJOSE_Bao_Compatibility(t *testing.T) {
	t.Parallel()

	t.Run("JWK_Export_Import", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_RSA_Key_To_JWK", testBaoRSAKeyToJWK)
		t.Run("Bao_ECDSA_Key_To_JWK", testBaoECDSAKeyToJWK)
		t.Run("Bao_Ed25519_Key_To_JWK", testBaoEd25519KeyToJWK)
		t.Run("JWK_To_Bao_Import", testJWKToBaoImport)
	})

	t.Run("JWS_Signing", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Key_JWS_Sign_Verify_RS256", testBaoKeyJWSSignVerifyRS256)
		t.Run("Bao_Key_JWS_Sign_Verify_ES256", testBaoKeyJWSSignVerifyES256)
		t.Run("Bao_Key_JWS_Sign_Verify_EdDSA", testBaoKeyJWSSignVerifyEdDSA)
	})

	t.Run("JWT_Operations", func(t *testing.T) {
		t.Parallel()
		t.Run("Bao_Key_JWT_Sign_Verify", testBaoKeyJWTSignVerify)
		t.Run("Bao_Key_JWT_Claims_Validation", testBaoKeyJWTClaimsValidation)
	})
}

// testBaoRSAKeyToJWK tests exporting Bao RSA keys to JWK format.
func testBaoRSAKeyToJWK(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao
	keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "rsa-jwk-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Export to JWK
	publicJWK, err := jwk.FromPublicKey(keyPair.Public())
	if err != nil {
		t.Fatalf("Failed to export public key to JWK: %v", err)
	}

	if publicJWK.KeyType != "RSA" {
		t.Errorf("Expected RSA key type, got %s", publicJWK.KeyType)
	}

	// Export private key to JWK
	privateJWK, err := jwk.FromPrivateKey(keyPair)
	if err != nil {
		t.Fatalf("Failed to export private key to JWK: %v", err)
	}

	if privateJWK.KeyType != "RSA" {
		t.Errorf("Expected RSA key type, got %s", privateJWK.KeyType)
	}

	t.Logf("✓ Successfully exported Bao RSA key to JWK format")
}

// testBaoECDSAKeyToJWK tests exporting Bao ECDSA keys to JWK format.
func testBaoECDSAKeyToJWK(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao
	keyClient, err := env.Client.GenerateECDSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "ecdsa-jwk-key",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Export to JWK
	publicJWK, err := jwk.FromPublicKey(keyPair.Public())
	if err != nil {
		t.Fatalf("Failed to export public key to JWK: %v", err)
	}

	if publicJWK.KeyType != "EC" {
		t.Errorf("Expected EC key type, got %s", publicJWK.KeyType)
	}

	// Export private key to JWK
	privateJWK, err := jwk.FromPrivateKey(keyPair)
	if err != nil {
		t.Fatalf("Failed to export private key to JWK: %v", err)
	}

	if privateJWK.KeyType != "EC" {
		t.Errorf("Expected EC key type, got %s", privateJWK.KeyType)
	}

	t.Logf("✓ Successfully exported Bao ECDSA key to JWK format")
}

// testBaoEd25519KeyToJWK tests exporting Bao Ed25519 keys to JWK format.
func testBaoEd25519KeyToJWK(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao
	keyClient, err := env.Client.GenerateEd25519Key(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "ed25519-jwk-key",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Export to JWK
	publicJWK, err := jwk.FromPublicKey(keyPair.Public())
	if err != nil {
		t.Fatalf("Failed to export public key to JWK: %v", err)
	}

	if publicJWK.KeyType != "OKP" {
		t.Errorf("Expected OKP key type, got %s", publicJWK.KeyType)
	}

	// Export private key to JWK
	privateJWK, err := jwk.FromPrivateKey(keyPair)
	if err != nil {
		t.Fatalf("Failed to export private key to JWK: %v", err)
	}

	if privateJWK.KeyType != "OKP" {
		t.Errorf("Expected OKP key type, got %s", privateJWK.KeyType)
	}

	t.Logf("✓ Successfully exported Bao Ed25519 key to JWK format")
}

// testJWKToBaoImport tests importing JWK keys to Bao.
func testJWKToBaoImport(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with GoPKI
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Export to JWK
	privateJWK, err := jwk.FromPrivateKey(keyPair)
	if err != nil {
		t.Fatalf("Failed to export to JWK: %v", err)
	}

	// Import JWK back to key pair
	importedKey, err := jwk.ToPrivateKey(privateJWK)
	if err != nil {
		t.Fatalf("Failed to import from JWK: %v", err)
	}

	// Convert to RSAKeyPair
	rsaKey, ok := importedKey.(*algo.RSAKeyPair)
	if !ok {
		t.Fatalf("Imported key is not RSAKeyPair")
	}

	// Import to Bao
	keyClient, err := env.Client.ImportRSAKey(env.Ctx, "jwk-imported-key", rsaKey, &bao.ImportKeyOptions{})
	if err != nil {
		t.Fatalf("Failed to import JWK key to Bao: %v", err)
	}

	// Verify key is accessible
	keyInfo, err := keyClient.GetKeyInfo(env.Ctx)
	if err != nil {
		t.Fatalf("Failed to get key info: %v", err)
	}

	t.Logf("Key type: %s", keyInfo.KeyType)
	t.Logf("✓ Successfully imported JWK key to Bao")
}

// testBaoKeyJWSSignVerifyRS256 tests JWS signing with Bao RSA keys (RS256).
func testBaoKeyJWSSignVerifyRS256(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao
	keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "jws-rsa-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Sign payload
	payload := []byte(`{"message": "Hello from Bao RSA key"}`)
	compact, err := jws.SignCompact(payload, keyPair, jws.RS256)
	if err != nil {
		t.Fatalf("Failed to sign JWS: %v", err)
	}

	// Verify signature
	verified, err := jws.VerifyCompact(compact, keyPair.Public())
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	if string(verified) != string(payload) {
		t.Errorf("Verified payload doesn't match original")
	}

	t.Logf("✓ Successfully signed and verified JWS with Bao RSA key (RS256)")
}

// testBaoKeyJWSSignVerifyES256 tests JWS signing with Bao ECDSA keys (ES256).
func testBaoKeyJWSSignVerifyES256(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao
	keyClient, err := env.Client.GenerateECDSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "jws-ecdsa-key",
		Curve:   "P256",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Sign payload
	payload := []byte(`{"message": "Hello from Bao ECDSA key"}`)
	compact, err := jws.SignCompact(payload, keyPair, jws.ES256)
	if err != nil {
		t.Fatalf("Failed to sign JWS: %v", err)
	}

	// Verify signature
	verified, err := jws.VerifyCompact(compact, keyPair.Public())
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	if string(verified) != string(payload) {
		t.Errorf("Verified payload doesn't match original")
	}

	t.Logf("✓ Successfully signed and verified JWS with Bao ECDSA key (ES256)")
}

// testBaoKeyJWSSignVerifyEdDSA tests JWS signing with Bao Ed25519 keys (EdDSA).
func testBaoKeyJWSSignVerifyEdDSA(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao
	keyClient, err := env.Client.GenerateEd25519Key(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "jws-ed25519-key",
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Sign payload
	payload := []byte(`{"message": "Hello from Bao Ed25519 key"}`)
	compact, err := jws.SignCompact(payload, keyPair, jws.EdDSA)
	if err != nil {
		t.Fatalf("Failed to sign JWS: %v", err)
	}

	// Verify signature
	verified, err := jws.VerifyCompact(compact, keyPair.Public())
	if err != nil {
		t.Fatalf("Failed to verify JWS: %v", err)
	}

	if string(verified) != string(payload) {
		t.Errorf("Verified payload doesn't match original")
	}

	t.Logf("✓ Successfully signed and verified JWS with Bao Ed25519 key (EdDSA)")
}

// testBaoKeyJWTSignVerify tests JWT signing and verification with Bao keys.
func testBaoKeyJWTSignVerify(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao
	keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "jwt-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Create JWT claims
	claims := jwt.Claims{
		Subject:   "user123",
		Issuer:    "bao-test",
		Audience:  []string{"test-audience"},
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	// Sign JWT
	token, err := jwt.Sign(claims, keyPair, jwt.RS256)
	if err != nil {
		t.Fatalf("Failed to sign JWT: %v", err)
	}

	// Verify JWT
	verifiedClaims, err := jwt.Verify(token, keyPair.Public())
	if err != nil {
		t.Fatalf("Failed to verify JWT: %v", err)
	}

	if verifiedClaims.Subject != claims.Subject {
		t.Errorf("Subject mismatch: expected %s, got %s", claims.Subject, verifiedClaims.Subject)
	}

	if verifiedClaims.Issuer != claims.Issuer {
		t.Errorf("Issuer mismatch: expected %s, got %s", claims.Issuer, verifiedClaims.Issuer)
	}

	t.Logf("✓ Successfully signed and verified JWT with Bao RSA key")
}

// testBaoKeyJWTClaimsValidation tests JWT claims validation with Bao keys.
func testBaoKeyJWTClaimsValidation(t *testing.T) {
	env := SetupBaoTest(t)
	defer env.Cleanup()

	// Generate key with Bao
	keyClient, err := env.Client.GenerateRSAKey(env.Ctx, &bao.GenerateKeyOptions{
		KeyName: "jwt-validation-key",
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	keyPair, err := keyClient.KeyPair()
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	// Create JWT claims
	claims := jwt.Claims{
		Subject:   "user123",
		Issuer:    "bao-test",
		Audience:  []string{"test-audience"},
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
	}

	// Sign JWT
	token, err := jwt.Sign(claims, keyPair, jwt.RS256)
	if err != nil {
		t.Fatalf("Failed to sign JWT: %v", err)
	}

	// Verify with validation options
	verifiedClaims, err := jwt.VerifyWithOptions(token, keyPair.Public(), jwt.ValidationOptions{
		ValidateExpiry:   true,
		ValidateNotBefore: true,
		ValidateIssuer:   true,
		ExpectedIssuer:   "bao-test",
		ValidateAudience: true,
		ExpectedAudience: "test-audience",
	})
	if err != nil {
		t.Fatalf("Failed to verify JWT with validation: %v", err)
	}

	if verifiedClaims.Subject != claims.Subject {
		t.Errorf("Subject mismatch")
	}

	// Test with wrong issuer (should fail)
	_, err = jwt.VerifyWithOptions(token, keyPair.Public(), jwt.ValidationOptions{
		ValidateIssuer: true,
		ExpectedIssuer: "wrong-issuer",
	})
	if err == nil {
		t.Errorf("Verification should fail with wrong issuer")
	} else if !strings.Contains(err.Error(), "issuer") {
		t.Logf("Validation correctly rejected wrong issuer")
	}

	t.Logf("✓ JWT claims validation works correctly with Bao key")
}
