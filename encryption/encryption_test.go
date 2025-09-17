package encryption

import (
	"testing"
	"time"

	"github.com/jasoet/gopki/keypair/algo"
)

func TestDefaultEncryptOptions(t *testing.T) {
	opts := DefaultEncryptOptions()

	// Test default values
	if opts.Algorithm != AlgorithmEnvelope {
		t.Errorf("Expected default algorithm to be AlgorithmEnvelope, got %s", opts.Algorithm)
	}

	if opts.Format != FormatCMS {
		t.Errorf("Expected default format to be FormatCMS, got %s", opts.Format)
	}

	if opts.IncludeCertificate != false {
		t.Errorf("Expected default IncludeCertificate to be false, got %v", opts.IncludeCertificate)
	}

	if opts.CertificateRecipients != nil {
		t.Errorf("Expected default CertificateRecipients to be nil, got %v", opts.CertificateRecipients)
	}

	if opts.KDF != nil {
		t.Errorf("Expected default KDF to be nil, got %v", opts.KDF)
	}

	if opts.Metadata == nil {
		t.Error("Expected default Metadata to be initialized, got nil")
	}

	if len(opts.Metadata) != 0 {
		t.Errorf("Expected default Metadata to be empty, got %d entries", len(opts.Metadata))
	}
}

func TestDefaultDecryptOptions(t *testing.T) {
	opts := DefaultDecryptOptions()

	// Test default values
	if opts.ExpectedAlgorithm != "" {
		t.Errorf("Expected default ExpectedAlgorithm to be empty, got %s", opts.ExpectedAlgorithm)
	}

	if opts.VerifyTimestamp != false {
		t.Errorf("Expected default VerifyTimestamp to be false, got %v", opts.VerifyTimestamp)
	}

	expectedMaxAge := 24 * time.Hour
	if opts.MaxAge != expectedMaxAge {
		t.Errorf("Expected default MaxAge to be %v, got %v", expectedMaxAge, opts.MaxAge)
	}

	if !opts.VerifyTime.IsZero() {
		t.Errorf("Expected default VerifyTime to be zero time, got %v", opts.VerifyTime)
	}

	if opts.SkipExpirationCheck != false {
		t.Errorf("Expected default SkipExpirationCheck to be false, got %v", opts.SkipExpirationCheck)
	}

	if opts.ValidationOptions == nil {
		t.Error("Expected default ValidationOptions to be initialized, got nil")
	}

	if len(opts.ValidationOptions) != 0 {
		t.Errorf("Expected default ValidationOptions to be empty, got %d entries", len(opts.ValidationOptions))
	}
}

func TestGetAlgorithmForKeyType(t *testing.T) {
	testCases := []struct {
		keyType     string
		expectedAlg Algorithm
	}{
		{"RSA", AlgorithmRSAOAEP},
		{"ECDSA", AlgorithmECDH},
		{"Ed25519", AlgorithmX25519},
		{"Unknown", AlgorithmEnvelope},
		{"", AlgorithmEnvelope},
		{"lowercase-rsa", AlgorithmEnvelope},
		{"random", AlgorithmEnvelope},
	}

	for _, tc := range testCases {
		t.Run(tc.keyType, func(t *testing.T) {
			result := GetAlgorithmForKeyType(tc.keyType)
			if result != tc.expectedAlg {
				t.Errorf("For key type %s, expected %s, got %s", tc.keyType, tc.expectedAlg, result)
			}
		})
	}
}

func TestValidateEncryptOptions(t *testing.T) {
	t.Run("ValidOptions", func(t *testing.T) {
		validAlgorithms := []Algorithm{
			AlgorithmRSAOAEP,
			AlgorithmECDH,
			AlgorithmX25519,
			AlgorithmAESGCM,
			AlgorithmEnvelope,
		}

		for _, alg := range validAlgorithms {
			opts := EncryptOptions{
				Algorithm: alg,
				Format:    FormatCMS,
			}

			err := ValidateEncryptOptions(opts)
			if err != nil {
				t.Errorf("Expected valid options for algorithm %s to pass validation, got error: %v", alg, err)
			}
		}
	})

	t.Run("InvalidAlgorithm", func(t *testing.T) {
		opts := EncryptOptions{
			Algorithm: Algorithm("INVALID"),
			Format:    FormatCMS,
		}

		err := ValidateEncryptOptions(opts)
		if err != ErrUnsupportedAlgorithm {
			t.Errorf("Expected ErrUnsupportedAlgorithm for invalid algorithm, got: %v", err)
		}
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		opts := EncryptOptions{
			Algorithm: AlgorithmRSAOAEP,
			Format:    Format("INVALID"),
		}

		err := ValidateEncryptOptions(opts)
		if err != ErrUnsupportedFormat {
			t.Errorf("Expected ErrUnsupportedFormat for invalid format, got: %v", err)
		}
	})

	t.Run("EmptyAlgorithm", func(t *testing.T) {
		opts := EncryptOptions{
			Algorithm: "",
			Format:    FormatCMS,
		}

		err := ValidateEncryptOptions(opts)
		if err != ErrUnsupportedAlgorithm {
			t.Errorf("Expected ErrUnsupportedAlgorithm for empty algorithm, got: %v", err)
		}
	})

	t.Run("EmptyFormat", func(t *testing.T) {
		opts := EncryptOptions{
			Algorithm: AlgorithmRSAOAEP,
			Format:    "",
		}

		err := ValidateEncryptOptions(opts)
		if err != ErrUnsupportedFormat {
			t.Errorf("Expected ErrUnsupportedFormat for empty format, got: %v", err)
		}
	})
}

func TestValidateDecryptOptions(t *testing.T) {
	t.Run("ValidOptions", func(t *testing.T) {
		validOptions := []DecryptOptions{
			{MaxAge: 0},
			{MaxAge: time.Hour},
			{MaxAge: 24 * time.Hour},
			{MaxAge: 365 * 24 * time.Hour},
		}

		for i, opts := range validOptions {
			err := ValidateDecryptOptions(opts)
			if err != nil {
				t.Errorf("Valid options case %d should pass validation, got error: %v", i, err)
			}
		}
	})

	t.Run("NegativeMaxAge", func(t *testing.T) {
		opts := DecryptOptions{
			MaxAge: -time.Hour,
		}

		err := ValidateDecryptOptions(opts)
		if err != ErrInvalidParameters {
			t.Errorf("Expected ErrInvalidParameters for negative MaxAge, got: %v", err)
		}
	})

	t.Run("VeryNegativeMaxAge", func(t *testing.T) {
		opts := DecryptOptions{
			MaxAge: -365 * 24 * time.Hour,
		}

		err := ValidateDecryptOptions(opts)
		if err != ErrInvalidParameters {
			t.Errorf("Expected ErrInvalidParameters for very negative MaxAge, got: %v", err)
		}
	})
}

func TestEncodeData(t *testing.T) {
	t.Run("NilData", func(t *testing.T) {
		result, err := EncodeData(nil)
		if err == nil {
			t.Error("Expected error for nil data, got nil")
		}
		if result != nil {
			t.Error("Expected nil result for nil data")
		}
		expectedMsg := "encrypted data is nil"
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("ValidDataWithoutRecipients", func(t *testing.T) {
		// This will test the path where EncodeToCMS is called but fails due to no recipients
		encData := &EncryptedData{
			Algorithm:  AlgorithmEnvelope,
			Format:     FormatCMS,
			Data:       []byte("test data"),
			Recipients: nil, // No recipients - will cause EncodeToCMS to fail
			Timestamp:  time.Now(),
			Metadata:   make(map[string]any),
		}

		_, err := EncodeData(encData)
		if err == nil {
			t.Error("Expected error for data without recipients, got nil")
		}
		// The exact error message comes from EncodeToCMS
		if err.Error() != "no recipients available for CMS envelope encryption" {
			t.Errorf("Expected specific error message, got: %s", err.Error())
		}
	})
}

func TestDecodeDataWithKey(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		// Generate a test key and certificate
		rsaKeys, err := algo.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		cert := createTestCertificate(t, rsaKeys.PublicKey, rsaKeys.PrivateKey)

		result, err := DecodeDataWithKey([]byte{}, cert, rsaKeys.PrivateKey)
		if err == nil {
			t.Error("Expected error for empty data, got nil")
		}
		if result != nil {
			t.Error("Expected nil result for empty data")
		}
		expectedMsg := "data is empty"
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("InvalidCMSData", func(t *testing.T) {
		// Generate a test key and certificate
		rsaKeys, err := algo.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		cert := createTestCertificate(t, rsaKeys.PublicKey, rsaKeys.PrivateKey)

		// Pass invalid CMS data
		invalidData := []byte("invalid cms data")
		result, err := DecodeDataWithKey(invalidData, cert, rsaKeys.PrivateKey)
		if err == nil {
			t.Error("Expected error for invalid CMS data, got nil")
		}
		if result != nil {
			t.Error("Expected nil result for invalid CMS data")
		}
		// The error should come from DecodeFromCMS (PKCS7 parsing)
	})

	t.Run("TypeSafety", func(t *testing.T) {
		// This test ensures the generic constraint works at compile time
		rsaKeys, err := algo.GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key pair: %v", err)
		}

		ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key pair: %v", err)
		}

		cert := createTestCertificate(t, rsaKeys.PublicKey, rsaKeys.PrivateKey)
		dummyData := []byte("dummy")

		// These should compile with different private key types
		_, _ = DecodeDataWithKey(dummyData, cert, rsaKeys.PrivateKey)   // *rsa.PrivateKey
		_, _ = DecodeDataWithKey(dummyData, cert, ecdsaKeys.PrivateKey) // *ecdsa.PrivateKey

		t.Log("Generic function accepts multiple private key types at compile time")
	})
}

func TestValidateEncodedData(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		err := ValidateEncodedData([]byte{})
		if err == nil {
			t.Error("Expected error for empty data, got nil")
		}
		// Error comes from ValidateCMS
		expectedMsg := "CMS data is empty"
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
	})

	t.Run("InvalidData", func(t *testing.T) {
		invalidData := []byte("invalid cms data")
		err := ValidateEncodedData(invalidData)
		if err == nil {
			t.Error("Expected error for invalid data, got nil")
		}
		// Error comes from ValidateCMS which uses pkcs7.Parse
	})
}

func TestEncryptionAlgorithmConstants(t *testing.T) {
	// Test that algorithm constants have expected values
	expectedAlgorithms := map[Algorithm]string{
		AlgorithmRSAOAEP:  "RSA-OAEP",
		AlgorithmECDH:     "ECDH",
		AlgorithmX25519:   "X25519",
		AlgorithmAESGCM:   "AES-GCM",
		AlgorithmEnvelope: "Envelope",
	}

	for alg, expectedValue := range expectedAlgorithms {
		if string(alg) != expectedValue {
			t.Errorf("Algorithm constant %s has unexpected value: expected %s, got %s",
				expectedValue, expectedValue, string(alg))
		}
	}
}

func TestEncryptionFormatConstants(t *testing.T) {
	// Test that format constants have expected values
	if string(FormatCMS) != "cms" {
		t.Errorf("FormatCMS constant has unexpected value: expected 'cms', got '%s'", string(FormatCMS))
	}
}

func TestErrorConstants(t *testing.T) {
	// Test that error constants are properly defined
	errors := []error{
		ErrUnsupportedAlgorithm,
		ErrUnsupportedFormat,
		ErrInvalidKey,
		ErrDecryptionFailed,
		ErrDataTooLarge,
		ErrInvalidRecipient,
		ErrExpiredData,
		ErrInvalidFormat,
		ErrInvalidParameters,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("Error constant should not be nil")
		}
		if err.Error() == "" {
			t.Error("Error constant should have a non-empty message")
		}
	}
}

func TestEncryptedDataStructure(t *testing.T) {
	// Test that EncryptedData struct can be created and used
	now := time.Now()
	metadata := make(map[string]any)
	metadata["test"] = "value"

	encData := &EncryptedData{
		Algorithm:    AlgorithmRSAOAEP,
		Format:       FormatCMS,
		Data:         []byte("test data"),
		EncryptedKey: []byte("encrypted key"),
		IV:           []byte("initialization vector"),
		Tag:          []byte("auth tag"),
		KDF:          nil,
		Recipients:   []*RecipientInfo{},
		Timestamp:    now,
		Metadata:     metadata,
	}

	// Verify all fields are accessible
	if encData.Algorithm != AlgorithmRSAOAEP {
		t.Error("Algorithm field not properly set")
	}
	if encData.Format != FormatCMS {
		t.Error("Format field not properly set")
	}
	if string(encData.Data) != "test data" {
		t.Error("Data field not properly set")
	}
	if !encData.Timestamp.Equal(now) {
		t.Error("Timestamp field not properly set")
	}
	if encData.Metadata["test"] != "value" {
		t.Error("Metadata field not properly set")
	}
}

func TestRecipientInfoStructure(t *testing.T) {
	// Test that RecipientInfo struct can be created and used
	rsaKeys, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	cert := createTestCertificate(t, rsaKeys.PublicKey, rsaKeys.PrivateKey)

	recipInfo := &RecipientInfo{
		Certificate:            cert,
		KeyID:                  []byte("key-id"),
		EncryptedKey:           []byte("encrypted key"),
		KeyEncryptionAlgorithm: AlgorithmRSAOAEP,
		EphemeralKey:           []byte("ephemeral key"),
		KeyIV:                  []byte("key iv"),
		KeyTag:                 []byte("key tag"),
	}

	// Verify all fields are accessible
	if recipInfo.Certificate != cert {
		t.Error("Certificate field not properly set")
	}
	if string(recipInfo.KeyID) != "key-id" {
		t.Error("KeyID field not properly set")
	}
	if recipInfo.KeyEncryptionAlgorithm != AlgorithmRSAOAEP {
		t.Error("KeyEncryptionAlgorithm field not properly set")
	}
}

func TestKDFParamsStructure(t *testing.T) {
	// Test that KDFParams struct can be created and used
	params := make(map[string]any)
	params["test"] = "value"

	kdfParams := &KDFParams{
		Algorithm:  "PBKDF2",
		Salt:       []byte("salt"),
		Iterations: 10000,
		KeyLength:  32,
		Params:     params,
	}

	// Verify all fields are accessible
	if kdfParams.Algorithm != "PBKDF2" {
		t.Error("Algorithm field not properly set")
	}
	if string(kdfParams.Salt) != "salt" {
		t.Error("Salt field not properly set")
	}
	if kdfParams.Iterations != 10000 {
		t.Error("Iterations field not properly set")
	}
	if kdfParams.KeyLength != 32 {
		t.Error("KeyLength field not properly set")
	}
	if kdfParams.Params["test"] != "value" {
		t.Error("Params field not properly set")
	}
}

// Note: createTestCertificate function is defined in cms_generic_test.go
