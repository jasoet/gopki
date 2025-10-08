//go:build example

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jasoet/gopki/jose/jwt"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	fmt.Println("=== GoPKI JWT Module - Comprehensive Examples ===")
	fmt.Println("Demonstrating JWT (JSON Web Token) functionality")
	fmt.Println()

	// Create outputs directory
	if err := os.MkdirAll("output", 0o755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Part 1: RSA Signature Algorithms
	fmt.Println("🔐 PART 1: RSA Signature Algorithms (RS256, RS384, RS512)")
	fmt.Println(strings.Repeat("=", 70))
	rsaSignatureExample()

	// Part 2: ECDSA Signature Algorithms
	fmt.Println("\n🔐 PART 2: ECDSA Signature Algorithms (ES256, ES384, ES512)")
	fmt.Println(strings.Repeat("=", 70))
	ecdsaSignatureExample()

	// Part 3: Ed25519 Signature
	fmt.Println("\n🔐 PART 3: Ed25519 Signature (EdDSA)")
	fmt.Println(strings.Repeat("=", 70))
	ed25519SignatureExample()

	// Part 4: HMAC Symmetric Signatures
	fmt.Println("\n🔐 PART 4: HMAC Symmetric Signatures (HS256, HS384, HS512)")
	fmt.Println(strings.Repeat("=", 70))
	hmacSignatureExample()

	// Part 5: Claims Validation
	fmt.Println("\n✅ PART 5: Claims Validation")
	fmt.Println(strings.Repeat("=", 70))
	claimsValidationExample()

	// Part 6: Real-World Use Cases
	fmt.Println("\n🌐 PART 6: Real-World Use Cases")
	fmt.Println(strings.Repeat("=", 70))
	apiAuthenticationExample()
	serviceToServiceExample()

	fmt.Println("\n✅ All examples completed successfully!")
	fmt.Println("📁 Tokens saved to output/jwt_*.txt")
}

func rsaSignatureExample() {
	// Generate RSA key pair
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}

	// Create claims
	claims := jwt.Claims{
		Issuer:    "auth.example.com",
		Subject:   "user-12345",
		Audience:  jwt.Audience{"web-app", "mobile-app"},
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		JWTID:     "jwt-rsa-example-001",
	}

	// Test RS256
	fmt.Println("\n📝 RS256 (RSASSA-PKCS1-v1_5 with SHA-256):")
	tokenRS256, err := jwt.Sign(&claims, keyPair.PrivateKey, jwt.RS256, &jwt.SignOptions{KeyID: "rsa-key-2024"})
	if err != nil {
		log.Fatal("Failed to sign with RS256:", err)
	}
	fmt.Printf("   Token: %s...\n", tokenRS256[:60])
	fmt.Printf("   Length: %d bytes\n", len(tokenRS256))

	// Verify RS256
	verifiedClaims, err := jwt.Verify(tokenRS256, keyPair.PublicKey, nil)
	if err != nil {
		log.Fatal("Failed to verify RS256 token:", err)
	}
	fmt.Printf("   ✓ Verified: subject=%s, issuer=%s\n", verifiedClaims.Subject, verifiedClaims.Issuer)

	// Save to file
	os.WriteFile("output/jwt_rs256.txt", []byte(tokenRS256), 0o644)

	// Test RS384
	fmt.Println("\n📝 RS384 (RSASSA-PKCS1-v1_5 with SHA-384):")
	tokenRS384, _ := jwt.Sign(&claims, keyPair.PrivateKey, jwt.RS384, &jwt.SignOptions{KeyID: "rsa-key-2024"})
	fmt.Printf("   Token: %s...\n", tokenRS384[:60])
	jwt.Verify(tokenRS384, keyPair.PublicKey, nil)
	fmt.Println("   ✓ Verified successfully")
	os.WriteFile("output/jwt_rs384.txt", []byte(tokenRS384), 0o644)

	// Test RS512
	fmt.Println("\n📝 RS512 (RSASSA-PKCS1-v1_5 with SHA-512):")
	tokenRS512, _ := jwt.Sign(&claims, keyPair.PrivateKey, jwt.RS512, &jwt.SignOptions{KeyID: "rsa-key-2024"})
	fmt.Printf("   Token: %s...\n", tokenRS512[:60])
	jwt.Verify(tokenRS512, keyPair.PublicKey, nil)
	fmt.Println("   ✓ Verified successfully")
	os.WriteFile("output/jwt_rs512.txt", []byte(tokenRS512), 0o644)
}

func ecdsaSignatureExample() {
	// Test ES256 (P-256)
	fmt.Println("\n📝 ES256 (ECDSA with P-256 and SHA-256):")
	keyPairP256, _ := algo.GenerateECDSAKeyPair(algo.P256)
	claims := jwt.Claims{
		Issuer:    "api.example.com",
		Subject:   "service-abc",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	tokenES256, err := jwt.Sign(&claims, keyPairP256.PrivateKey, jwt.ES256, &jwt.SignOptions{KeyID: "ec-p256-key"})
	if err != nil {
		log.Fatal("Failed to sign with ES256:", err)
	}
	fmt.Printf("   Token: %s...\n", tokenES256[:60])
	jwt.Verify(tokenES256, keyPairP256.PublicKey, nil)
	fmt.Println("   ✓ Verified successfully")
	os.WriteFile("output/jwt_es256.txt", []byte(tokenES256), 0o644)

	// Test ES384 (P-384)
	fmt.Println("\n📝 ES384 (ECDSA with P-384 and SHA-384):")
	keyPairP384, _ := algo.GenerateECDSAKeyPair(algo.P384)
	tokenES384, _ := jwt.Sign(&claims, keyPairP384.PrivateKey, jwt.ES384, &jwt.SignOptions{KeyID: "ec-p384-key"})
	fmt.Printf("   Token: %s...\n", tokenES384[:60])
	jwt.Verify(tokenES384, keyPairP384.PublicKey, nil)
	fmt.Println("   ✓ Verified successfully")
	os.WriteFile("output/jwt_es384.txt", []byte(tokenES384), 0o644)

	// Test ES512 (P-521)
	fmt.Println("\n📝 ES512 (ECDSA with P-521 and SHA-512):")
	keyPairP521, _ := algo.GenerateECDSAKeyPair(algo.P521)
	tokenES512, _ := jwt.Sign(&claims, keyPairP521.PrivateKey, jwt.ES512, &jwt.SignOptions{KeyID: "ec-p521-key"})
	fmt.Printf("   Token: %s...\n", tokenES512[:60])
	jwt.Verify(tokenES512, keyPairP521.PublicKey, nil)
	fmt.Println("   ✓ Verified successfully")
	os.WriteFile("output/jwt_es512.txt", []byte(tokenES512), 0o644)
}

func ed25519SignatureExample() {
	// Generate Ed25519 key pair
	keyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key:", err)
	}

	claims := jwt.Claims{
		Issuer:    "secure.example.com",
		Subject:   "admin-user",
		Audience:  jwt.Audience{"admin-panel"},
		ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	fmt.Println("\n📝 EdDSA (Ed25519 signature):")
	tokenEdDSA, err := jwt.Sign(&claims, keyPair.PrivateKey, jwt.EdDSA, &jwt.SignOptions{KeyID: "ed25519-key-001"})
	if err != nil {
		log.Fatal("Failed to sign with EdDSA:", err)
	}
	fmt.Printf("   Token: %s...\n", tokenEdDSA[:60])
	fmt.Printf("   Length: %d bytes\n", len(tokenEdDSA))

	verifiedClaims, err := jwt.Verify(tokenEdDSA, keyPair.PublicKey, nil)
	if err != nil {
		log.Fatal("Failed to verify EdDSA token:", err)
	}
	fmt.Printf("   ✓ Verified: subject=%s\n", verifiedClaims.Subject)
	os.WriteFile("output/jwt_eddsa.txt", []byte(tokenEdDSA), 0o644)
}

func hmacSignatureExample() {
	secret := []byte("my-super-secret-key-change-this-in-production-min-32-bytes")

	claims := jwt.Claims{
		Issuer:    "internal-service",
		Subject:   "background-job",
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	// Test HS256
	fmt.Println("\n📝 HS256 (HMAC with SHA-256):")
	tokenHS256, err := jwt.SignWithSecret(&claims, secret, jwt.HS256)
	if err != nil {
		log.Fatal("Failed to sign with HS256:", err)
	}
	fmt.Printf("   Token: %s...\n", tokenHS256[:60])
	jwt.VerifyWithSecret(tokenHS256, secret, nil)
	fmt.Println("   ✓ Verified successfully")
	os.WriteFile("output/jwt_hs256.txt", []byte(tokenHS256), 0o644)

	// Test HS384
	fmt.Println("\n📝 HS384 (HMAC with SHA-384):")
	tokenHS384, _ := jwt.SignWithSecret(&claims, secret, jwt.HS384)
	fmt.Printf("   Token: %s...\n", tokenHS384[:60])
	jwt.VerifyWithSecret(tokenHS384, secret, nil)
	fmt.Println("   ✓ Verified successfully")

	// Test HS512
	fmt.Println("\n📝 HS512 (HMAC with SHA-512):")
	tokenHS512, _ := jwt.SignWithSecret(&claims, secret, jwt.HS512)
	fmt.Printf("   Token: %s...\n", tokenHS512[:60])
	jwt.VerifyWithSecret(tokenHS512, secret, nil)
	fmt.Println("   ✓ Verified successfully")
}

func claimsValidationExample() {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	// Example 1: Expired token
	fmt.Println("\n📝 Example 1: Expired Token Detection")
	expiredClaims := jwt.Claims{
		Issuer:    "auth.example.com",
		Subject:   "user-123",
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
	}
	expiredToken, _ := jwt.Sign(&expiredClaims, keyPair.PrivateKey, jwt.RS256, &jwt.SignOptions{KeyID: "test-key"})

	opts := &jwt.VerifyOptions{
		Validation: &jwt.ValidationOptions{
			ValidateExpiry: true,
		},
	}
	_, err := jwt.Verify(expiredToken, keyPair.PublicKey, opts)
	if err != nil {
		fmt.Printf("   ✓ Correctly rejected: %v\n", err)
	}

	// Example 2: Not yet valid token
	fmt.Println("\n📝 Example 2: Not Yet Valid Token")
	futureClaims := jwt.Claims{
		Issuer:    "auth.example.com",
		Subject:   "user-456",
		NotBefore: time.Now().Add(1 * time.Hour).Unix(), // Valid in 1 hour
		ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
	}
	futureToken, _ := jwt.Sign(&futureClaims, keyPair.PrivateKey, jwt.RS256, &jwt.SignOptions{KeyID: "test-key"})

	opts = &jwt.VerifyOptions{
		Validation: &jwt.ValidationOptions{
			ValidateNotBefore: true,
		},
	}
	_, err = jwt.Verify(futureToken, keyPair.PublicKey, opts)
	if err != nil {
		fmt.Printf("   ✓ Correctly rejected: %v\n", err)
	}

	// Example 3: Issuer validation
	fmt.Println("\n📝 Example 3: Issuer Validation")
	claims := jwt.Claims{
		Issuer:    "wrong-issuer.com",
		Subject:   "user-789",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	token, _ := jwt.Sign(&claims, keyPair.PrivateKey, jwt.RS256, &jwt.SignOptions{KeyID: "test-key"})

	opts = &jwt.VerifyOptions{
		Validation: &jwt.ValidationOptions{
			ValidateIssuer: true,
			ExpectedIssuer: "auth.example.com",
		},
	}
	_, err = jwt.Verify(token, keyPair.PublicKey, opts)
	if err != nil {
		fmt.Printf("   ✓ Correctly rejected: %v\n", err)
	}

	// Example 4: Audience validation
	fmt.Println("\n📝 Example 4: Audience Validation")
	claims = jwt.Claims{
		Issuer:    "auth.example.com",
		Subject:   "user-101",
		Audience:  jwt.Audience{"web-app"},
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	token, _ = jwt.Sign(&claims, keyPair.PrivateKey, jwt.RS256, &jwt.SignOptions{KeyID: "test-key"})

	opts = &jwt.VerifyOptions{
		Validation: &jwt.ValidationOptions{
			ValidateAudience: true,
			ExpectedAudience: []string{"mobile-app"}, // Different audience
		},
	}
	_, err = jwt.Verify(token, keyPair.PublicKey, opts)
	if err != nil {
		fmt.Printf("   ✓ Correctly rejected: %v\n", err)
	}

	// Example 5: Clock skew tolerance
	fmt.Println("\n📝 Example 5: Clock Skew Tolerance")
	skewClaims := jwt.Claims{
		Issuer:    "auth.example.com",
		Subject:   "user-202",
		ExpiresAt: time.Now().Add(-30 * time.Second).Unix(), // Expired 30 seconds ago
	}
	skewToken, _ := jwt.Sign(&skewClaims, keyPair.PrivateKey, jwt.RS256, &jwt.SignOptions{KeyID: "test-key"})

	opts = &jwt.VerifyOptions{
		Validation: &jwt.ValidationOptions{
			ValidateExpiry: true,
			ClockSkew:      60 * time.Second, // Allow 60 second skew
		},
	}
	verifiedClaims, err := jwt.Verify(skewToken, keyPair.PublicKey, opts)
	if err == nil {
		fmt.Printf("   ✓ Accepted with clock skew: subject=%s\n", verifiedClaims.Subject)
	}
}

func apiAuthenticationExample() {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	fmt.Println("\n📝 Use Case: API Authentication Flow")

	// 1. User logs in, server issues JWT
	fmt.Println("\n   Step 1: User Login → Server Issues JWT")
	loginClaims := jwt.Claims{
		Issuer:    "api.myapp.com",
		Subject:   "user-alice-123",
		Audience:  jwt.Audience{"api.myapp.com"},
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		JWTID:     "session-abc-def-456",
		Extra: map[string]interface{}{
			"email": "alice@example.com",
			"role":  "admin",
			"perms": []string{"read", "write", "delete"},
		},
	}

	accessToken, _ := jwt.Sign(&loginClaims, keyPair.PrivateKey, jwt.RS256, &jwt.SignOptions{KeyID: "api-key-2024-10"})
	fmt.Printf("   Generated access token: %s...\n", accessToken[:50])

	// Save token
	os.WriteFile("output/jwt_api_access_token.txt", []byte(accessToken), 0o644)

	// 2. Client includes JWT in API requests
	fmt.Println("\n   Step 2: Client → API Request with JWT in Authorization header")
	fmt.Printf("   Authorization: Bearer %s...\n", accessToken[:30])

	// 3. Server validates JWT on each request
	fmt.Println("\n   Step 3: Server Validates JWT")
	opts := &jwt.VerifyOptions{
		Validation: &jwt.ValidationOptions{
			ValidateExpiry:    true,
			ValidateNotBefore: true,
			ValidateIssuer:    true,
			ExpectedIssuer:    "api.myapp.com",
			ValidateAudience:  true,
			ExpectedAudience:  []string{"api.myapp.com"},
			ClockSkew:         10 * time.Second,
		},
	}

	verifiedClaims, err := jwt.Verify(accessToken, keyPair.PublicKey, opts)
	if err != nil {
		log.Fatal("Token validation failed:", err)
	}

	fmt.Printf("   ✓ Token valid: user=%s\n", verifiedClaims.Subject)
	fmt.Printf("   ✓ Role: %v\n", verifiedClaims.Extra["role"])
	fmt.Printf("   ✓ Permissions: %v\n", verifiedClaims.Extra["perms"])
	fmt.Printf("   ✓ Token expires in: %.0f hours\n",
		time.Until(time.Unix(verifiedClaims.ExpiresAt, 0)).Hours())
}

func serviceToServiceExample() {
	// Service A and Service B share a secret
	sharedSecret := []byte("service-mesh-shared-secret-min-32-bytes-required")

	fmt.Println("\n📝 Use Case: Service-to-Service Authentication (HMAC)")

	// Service A calls Service B
	fmt.Println("\n   Service A → Service B Request")

	serviceClaims := jwt.Claims{
		Issuer:    "service-a.internal",
		Subject:   "service-a",
		Audience:  jwt.Audience{"service-b.internal"},
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
		Extra: map[string]interface{}{
			"request_id": "req-789-xyz",
			"operation":  "fetch-user-data",
		},
	}

	serviceToken, _ := jwt.SignWithSecret(&serviceClaims, sharedSecret, jwt.HS256)
	fmt.Printf("   Generated service token: %s...\n", serviceToken[:50])

	// Service B validates the token
	fmt.Println("\n   Service B Validates Token")
	verifiedClaims, err := jwt.VerifyWithSecret(serviceToken, sharedSecret, nil)
	if err != nil {
		log.Fatal("Service token validation failed:", err)
	}

	fmt.Printf("   ✓ Token valid from: %s\n", verifiedClaims.Issuer)
	fmt.Printf("   ✓ Operation: %v\n", verifiedClaims.Extra["operation"])
	fmt.Printf("   ✓ Request ID: %v\n", verifiedClaims.Extra["request_id"])

	// Pretty print full claims
	fmt.Println("\n   Full Claims (JSON):")
	claimsJSON, _ := json.MarshalIndent(verifiedClaims, "   ", "  ")
	fmt.Printf("   %s\n", claimsJSON)
}
