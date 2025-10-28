// +build integration

package transit_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/jasoet/gopki/bao/transit"
)

// TestIntegration_RSASignVerify tests RSA signature operations.
func TestIntegration_RSASignVerify(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-rsa-sign-key"

	// Create RSA-2048 key
	_, err := client.CreateRSA2048Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateRSA2048Key() error = %v", err)
	}

	// Prepare data to sign
	data := base64.StdEncoding.EncodeToString([]byte("Important document"))

	// Sign data
	signResult, err := client.Sign(ctx, keyName, data, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if signResult.Signature == "" {
		t.Error("Sign() returned empty signature")
	}

	if signResult.KeyVersion != 1 {
		t.Errorf("KeyVersion = %v, want 1", signResult.KeyVersion)
	}

	// Verify signature
	verifyResult, err := client.Verify(ctx, keyName, data, signResult.Signature, nil)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !verifyResult.Valid {
		t.Error("Verify() returned false for valid signature")
	}

	// Verify with wrong data
	wrongData := base64.StdEncoding.EncodeToString([]byte("Different document"))
	wrongVerify, err := client.Verify(ctx, keyName, wrongData, signResult.Signature, nil)
	if err != nil {
		t.Fatalf("Verify() with wrong data error = %v", err)
	}

	if wrongVerify.Valid {
		t.Error("Verify() returned true for invalid signature")
	}
}

// TestIntegration_ECDSASignVerify tests ECDSA signature operations.
func TestIntegration_ECDSASignVerify(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-ecdsa-sign-key"

	// Create ECDSA P-256 key
	_, err := client.CreateECDSAP256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateECDSAP256Key() error = %v", err)
	}

	// Prepare data
	data := base64.StdEncoding.EncodeToString([]byte("ECDSA signed data"))

	// Sign with default (ASN.1) marshaling
	signResult, err := client.Sign(ctx, keyName, data, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify signature
	verifyResult, err := client.Verify(ctx, keyName, data, signResult.Signature, nil)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !verifyResult.Valid {
		t.Error("Verify() returned false for valid ECDSA signature")
	}
}

// TestIntegration_Ed25519SignVerify tests Ed25519 signature operations.
func TestIntegration_Ed25519SignVerify(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-ed25519-sign-key"

	// Create Ed25519 key
	_, err := client.CreateEd25519Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateEd25519Key() error = %v", err)
	}

	// Prepare data
	data := base64.StdEncoding.EncodeToString([]byte("Ed25519 signed data"))

	// Sign data
	signResult, err := client.Sign(ctx, keyName, data, nil)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify signature
	verifyResult, err := client.Verify(ctx, keyName, data, signResult.Signature, nil)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !verifyResult.Valid {
		t.Error("Verify() returned false for valid Ed25519 signature")
	}
}

// TestIntegration_SignWithHashAlgorithms tests different hash algorithms.
func TestIntegration_SignWithHashAlgorithms(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-hash-algo-key"

	// Create RSA key
	_, err := client.CreateRSA2048Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateRSA2048Key() error = %v", err)
	}

	data := base64.StdEncoding.EncodeToString([]byte("test data"))

	tests := []struct {
		name      string
		algorithm transit.HashAlgorithm
	}{
		{"SHA2-256", transit.HashSHA2_256},
		{"SHA2-384", transit.HashSHA2_384},
		{"SHA2-512", transit.HashSHA2_512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sign with specific hash algorithm
			signResult, err := client.Sign(ctx, keyName, data, &transit.SignOptions{
				HashAlgorithm: tt.algorithm,
			})
			if err != nil {
				t.Fatalf("Sign() with %s error = %v", tt.algorithm, err)
			}

			// Verify with same hash algorithm
			verifyResult, err := client.Verify(ctx, keyName, data, signResult.Signature, &transit.VerifyOptions{
				HashAlgorithm: tt.algorithm,
			})
			if err != nil {
				t.Fatalf("Verify() with %s error = %v", tt.algorithm, err)
			}

			if !verifyResult.Valid {
				t.Errorf("Verify() with %s returned false", tt.algorithm)
			}
		})
	}
}

// TestIntegration_RSASignatureAlgorithms tests RSA-PSS and PKCS#1v15.
func TestIntegration_RSASignatureAlgorithms(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-rsa-sig-algo-key"

	// Create RSA key
	_, err := client.CreateRSA2048Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateRSA2048Key() error = %v", err)
	}

	data := base64.StdEncoding.EncodeToString([]byte("test data"))

	tests := []struct {
		name      string
		algorithm transit.SignatureAlgorithm
	}{
		{"PSS", transit.SignatureAlgPSS},
		{"PKCS1v15", transit.SignatureAlgPKCS1v15},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sign with specific signature algorithm
			signResult, err := client.Sign(ctx, keyName, data, &transit.SignOptions{
				SignatureAlgorithm: tt.algorithm,
			})
			if err != nil {
				t.Fatalf("Sign() with %s error = %v", tt.algorithm, err)
			}

			// Verify with same signature algorithm
			verifyResult, err := client.Verify(ctx, keyName, data, signResult.Signature, &transit.VerifyOptions{
				SignatureAlgorithm: tt.algorithm,
			})
			if err != nil {
				t.Fatalf("Verify() with %s error = %v", tt.algorithm, err)
			}

			if !verifyResult.Valid {
				t.Errorf("Verify() with %s returned false", tt.algorithm)
			}
		})
	}
}

// TestIntegration_ECDSAMarshalingFormats tests ASN.1 and JWS marshaling.
func TestIntegration_ECDSAMarshalingFormats(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-ecdsa-marshaling-key"

	// Create ECDSA key
	_, err := client.CreateECDSAP256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateECDSAP256Key() error = %v", err)
	}

	data := base64.StdEncoding.EncodeToString([]byte("test data"))

	tests := []struct {
		name      string
		marshaling transit.MarshalingAlgorithm
	}{
		{"ASN1", transit.MarshalingASN1},
		{"JWS", transit.MarshalingJWS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sign with specific marshaling format
			signResult, err := client.Sign(ctx, keyName, data, &transit.SignOptions{
				MarshalingAlgorithm: tt.marshaling,
			})
			if err != nil {
				t.Fatalf("Sign() with %s error = %v", tt.marshaling, err)
			}

			// Verify with same marshaling format
			verifyResult, err := client.Verify(ctx, keyName, data, signResult.Signature, &transit.VerifyOptions{
				MarshalingAlgorithm: tt.marshaling,
			})
			if err != nil {
				t.Fatalf("Verify() with %s error = %v", tt.marshaling, err)
			}

			if !verifyResult.Valid {
				t.Errorf("Verify() with %s returned false", tt.marshaling)
			}
		})
	}
}

// TestIntegration_HMAC tests HMAC generation and verification.
func TestIntegration_HMAC(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-hmac-key"

	// Create AES-256 key (can be used for HMAC)
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	// Prepare data
	data := base64.StdEncoding.EncodeToString([]byte("Data to authenticate"))

	// Generate HMAC
	hmacResult, err := client.HMAC(ctx, keyName, data, nil)
	if err != nil {
		t.Fatalf("HMAC() error = %v", err)
	}

	if hmacResult.HMAC == "" {
		t.Error("HMAC() returned empty HMAC")
	}

	// Note: KeyVersion may not be returned by all OpenBao versions
	if hmacResult.KeyVersion > 0 {
		t.Logf("HMAC KeyVersion = %d", hmacResult.KeyVersion)
	}

	// Verify HMAC
	verifyResult, err := client.VerifyHMAC(ctx, keyName, data, hmacResult.HMAC, nil)
	if err != nil {
		t.Fatalf("VerifyHMAC() error = %v", err)
	}

	if !verifyResult.Valid {
		t.Error("VerifyHMAC() returned false for valid HMAC")
	}

	// Verify with wrong data
	wrongData := base64.StdEncoding.EncodeToString([]byte("Different data"))
	wrongVerify, err := client.VerifyHMAC(ctx, keyName, wrongData, hmacResult.HMAC, nil)
	if err != nil {
		t.Fatalf("VerifyHMAC() with wrong data error = %v", err)
	}

	if wrongVerify.Valid {
		t.Error("VerifyHMAC() returned true for invalid HMAC")
	}
}

// TestIntegration_HMACWithAlgorithms tests different HMAC algorithms.
func TestIntegration_HMACWithAlgorithms(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-hmac-algo-key"

	// Create key
	_, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	data := base64.StdEncoding.EncodeToString([]byte("test data"))

	tests := []struct {
		name      string
		algorithm transit.HashAlgorithm
	}{
		{"SHA2-256", transit.HashSHA2_256},
		{"SHA2-512", transit.HashSHA2_512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate HMAC with specific algorithm
			hmacResult, err := client.HMAC(ctx, keyName, data, &transit.HMACOptions{
				Algorithm: tt.algorithm,
			})
			if err != nil {
				t.Fatalf("HMAC() with %s error = %v", tt.algorithm, err)
			}

			// Verify HMAC with same algorithm
			verifyResult, err := client.VerifyHMAC(ctx, keyName, data, hmacResult.HMAC, &transit.HMACOptions{
				Algorithm: tt.algorithm,
			})
			if err != nil {
				t.Fatalf("VerifyHMAC() with %s error = %v", tt.algorithm, err)
			}

			if !verifyResult.Valid {
				t.Errorf("VerifyHMAC() with %s returned false", tt.algorithm)
			}
		})
	}
}

// TestIntegration_SignWithKeyVersion tests signing with specific key versions.
func TestIntegration_SignWithKeyVersion(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-sign-version-key"

	// Create key
	keyClient, err := client.CreateRSA2048Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateRSA2048Key() error = %v", err)
	}

	// Rotate key twice
	keyClient.Rotate(ctx)
	keyClient.Rotate(ctx)

	// Now we have versions 1, 2, 3
	data := base64.StdEncoding.EncodeToString([]byte("test data"))

	// Sign with version 2
	signResult, err := client.Sign(ctx, keyName, data, &transit.SignOptions{
		KeyVersion: 2,
	})
	if err != nil {
		t.Fatalf("Sign() with version 2 error = %v", err)
	}

	// KeyVersion in result should be 2
	if signResult.KeyVersion != 2 {
		t.Errorf("KeyVersion = %v, want 2", signResult.KeyVersion)
	}

	// Verify signature (should automatically use correct version from signature)
	verifyResult, err := client.Verify(ctx, keyName, data, signResult.Signature, nil)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !verifyResult.Valid {
		t.Error("Verify() returned false for valid signature with version 2")
	}
}

// TestIntegration_BatchSign tests batch signing operations.
func TestIntegration_BatchSign(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-batch-sign-key"

	// Create key
	_, err := client.CreateRSA2048Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateRSA2048Key() error = %v", err)
	}

	// Prepare batch items
	items := []transit.BatchSignItem{
		{Input: base64.StdEncoding.EncodeToString([]byte("document 1"))},
		{Input: base64.StdEncoding.EncodeToString([]byte("document 2"))},
		{Input: base64.StdEncoding.EncodeToString([]byte("document 3"))},
	}

	// Sign batch
	signResult, err := client.SignBatch(ctx, keyName, items)
	if err != nil {
		t.Fatalf("SignBatch() error = %v", err)
	}

	if len(signResult.Results) != 3 {
		t.Errorf("SignBatch() results count = %v, want 3", len(signResult.Results))
	}

	// Check for errors
	for i, err := range signResult.Errors {
		if err != nil {
			t.Errorf("SignBatch() item %d error: %v", i, err)
		}
	}

	// Verify all signatures are non-empty
	for i, result := range signResult.Results {
		if result.Signature == "" {
			t.Errorf("SignBatch() result %d has empty signature", i)
		}
	}
}

// TestIntegration_BatchVerify tests batch verification operations.
func TestIntegration_BatchVerify(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-batch-verify-key"

	// Create key
	_, err := client.CreateEd25519Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateEd25519Key() error = %v", err)
	}

	// Sign some data first
	data1 := base64.StdEncoding.EncodeToString([]byte("message 1"))
	data2 := base64.StdEncoding.EncodeToString([]byte("message 2"))

	sig1, err := client.Sign(ctx, keyName, data1, nil)
	if err != nil {
		t.Fatalf("Sign() data1 error = %v", err)
	}

	sig2, err := client.Sign(ctx, keyName, data2, nil)
	if err != nil {
		t.Fatalf("Sign() data2 error = %v", err)
	}

	// Prepare batch verify items
	items := []transit.BatchVerifyItem{
		{Input: data1, Signature: sig1.Signature},
		{Input: data2, Signature: sig2.Signature},
	}

	// Verify batch
	verifyResult, err := client.VerifyBatch(ctx, keyName, items)
	if err != nil {
		t.Fatalf("VerifyBatch() error = %v", err)
	}

	if len(verifyResult.Results) != 2 {
		t.Errorf("VerifyBatch() results count = %v, want 2", len(verifyResult.Results))
	}

	// Check all signatures are valid
	for i, result := range verifyResult.Results {
		if verifyResult.Errors[i] != nil {
			t.Errorf("VerifyBatch() item %d error: %v", i, verifyResult.Errors[i])
		}
		if !result.Valid {
			t.Errorf("VerifyBatch() item %d returned false", i)
		}
	}
}

// TestIntegration_LargeBatchSign tests automatic chunking for large batches.
func TestIntegration_LargeBatchSign(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-large-batch-sign-key"

	// Create key
	_, err := client.CreateEd25519Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateEd25519Key() error = %v", err)
	}

	// Create 300 items to test chunking (default max is 250)
	items := make([]transit.BatchSignItem, 300)
	for i := 0; i < 300; i++ {
		data := base64.StdEncoding.EncodeToString([]byte("data " + string(rune(i))))
		items[i] = transit.BatchSignItem{Input: data}
	}

	// Sign batch (should auto-chunk)
	signResult, err := client.SignBatch(ctx, keyName, items)
	if err != nil {
		t.Fatalf("SignBatch() large batch error = %v", err)
	}

	if len(signResult.Results) != 300 {
		t.Errorf("SignBatch() results count = %v, want 300", len(signResult.Results))
	}

	// Verify no errors
	for i, err := range signResult.Errors {
		if err != nil {
			t.Errorf("SignBatch() item %d error: %v", i, err)
		}
	}
}

// TestIntegration_HMACKeyRotation tests HMAC with key rotation.
func TestIntegration_HMACKeyRotation(t *testing.T) {
	_, client := setupTestContainer(t)
	ctx := context.Background()

	keyName := "test-hmac-rotation-key"

	// Create key
	keyClient, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		t.Fatalf("CreateAES256Key() error = %v", err)
	}

	data := base64.StdEncoding.EncodeToString([]byte("test data"))

	// Generate HMAC with v1
	hmac1, err := client.HMAC(ctx, keyName, data, &transit.HMACOptions{
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("HMAC() v1 error = %v", err)
	}

	// Rotate key
	keyClient.Rotate(ctx)

	// Generate HMAC with v2
	hmac2, err := client.HMAC(ctx, keyName, data, &transit.HMACOptions{
		KeyVersion: 2,
	})
	if err != nil {
		t.Fatalf("HMAC() v2 error = %v", err)
	}

	// HMACs should be different
	if hmac1.HMAC == hmac2.HMAC {
		t.Error("HMACs from different key versions should be different")
	}

	// Both should verify correctly
	verify1, err := client.VerifyHMAC(ctx, keyName, data, hmac1.HMAC, nil)
	if err != nil {
		t.Fatalf("VerifyHMAC() v1 error = %v", err)
	}
	if !verify1.Valid {
		t.Error("HMAC v1 should still be valid after rotation")
	}

	verify2, err := client.VerifyHMAC(ctx, keyName, data, hmac2.HMAC, nil)
	if err != nil {
		t.Fatalf("VerifyHMAC() v2 error = %v", err)
	}
	if !verify2.Valid {
		t.Error("HMAC v2 should be valid")
	}
}
