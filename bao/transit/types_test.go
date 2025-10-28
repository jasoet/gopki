package transit

import (
	"testing"
)

func TestKeyType_Implementations(t *testing.T) {
	tests := []struct {
		name               string
		keyType            KeyType
		expectedName       string
		supportsEncryption bool
		supportsSigning    bool
	}{
		{
			name:               "AES256",
			keyType:            KeyTypeAES256{},
			expectedName:       KeyTypeAES256GCM96,
			supportsEncryption: true,
			supportsSigning:    false,
		},
		{
			name:               "AES128",
			keyType:            KeyTypeAES128{},
			expectedName:       KeyTypeAES128GCM96,
			supportsEncryption: true,
			supportsSigning:    false,
		},
		{
			name:               "ChaCha20",
			keyType:            KeyTypeChaCha20{},
			expectedName:       KeyTypeChaCha20Poly1305,
			supportsEncryption: true,
			supportsSigning:    false,
		},
		{
			name:               "XChaCha20",
			keyType:            KeyTypeXChaCha20{},
			expectedName:       KeyTypeXChaCha20Poly1305,
			supportsEncryption: true,
			supportsSigning:    false,
		},
		{
			name:               "RSA2048",
			keyType:            RSA2048{},
			expectedName:       KeyTypeRSA2048,
			supportsEncryption: true,
			supportsSigning:    true,
		},
		{
			name:               "RSA3072",
			keyType:            RSA3072{},
			expectedName:       KeyTypeRSA3072,
			supportsEncryption: true,
			supportsSigning:    true,
		},
		{
			name:               "RSA4096",
			keyType:            RSA4096{},
			expectedName:       KeyTypeRSA4096,
			supportsEncryption: true,
			supportsSigning:    true,
		},
		{
			name:               "ECDSA P256",
			keyType:            ECDSAP256{},
			expectedName:       KeyTypeECDSAP256,
			supportsEncryption: false,
			supportsSigning:    true,
		},
		{
			name:               "ECDSA P384",
			keyType:            ECDSAP384{},
			expectedName:       KeyTypeECDSAP384,
			supportsEncryption: false,
			supportsSigning:    true,
		},
		{
			name:               "ECDSA P521",
			keyType:            ECDSAP521{},
			expectedName:       KeyTypeECDSAP521,
			supportsEncryption: false,
			supportsSigning:    true,
		},
		{
			name:               "Ed25519",
			keyType:            Ed25519{},
			expectedName:       KeyTypeEd25519,
			supportsEncryption: false,
			supportsSigning:    true,
		},
		{
			name:               "HMAC",
			keyType:            HMAC{},
			expectedName:       KeyTypeHMAC,
			supportsEncryption: false,
			supportsSigning:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.keyType.KeyTypeName(); got != tt.expectedName {
				t.Errorf("KeyTypeName() = %v, want %v", got, tt.expectedName)
			}

			if got := tt.keyType.SupportsEncryption(); got != tt.supportsEncryption {
				t.Errorf("SupportsEncryption() = %v, want %v", got, tt.supportsEncryption)
			}

			if got := tt.keyType.SupportsSigning(); got != tt.supportsSigning {
				t.Errorf("SupportsSigning() = %v, want %v", got, tt.supportsSigning)
			}
		})
	}
}

func TestTransitError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *TransitError
		wantErr string
	}{
		{
			name: "with underlying error",
			err: &TransitError{
				Operation:  "Encrypt",
				StatusCode: 500,
				Err:        ErrInvalidCiphertext,
			},
			wantErr: "transit Encrypt: status 500: bao: invalid ciphertext",
		},
		{
			name: "with error messages",
			err: &TransitError{
				Operation:  "CreateKey",
				StatusCode: 400,
				Errors:     []string{"key already exists", "duplicate key name"},
			},
			wantErr: "transit CreateKey: status 400: key already exists",
		},
		{
			name: "with status code only",
			err: &TransitError{
				Operation:  "GetKey",
				StatusCode: 404,
			},
			wantErr: "transit GetKey: status 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantErr {
				t.Errorf("Error() = %v, want %v", got, tt.wantErr)
			}
		})
	}
}

func TestTransitError_Unwrap(t *testing.T) {
	underlying := ErrInvalidCiphertext
	err := &TransitError{
		Operation:  "Decrypt",
		StatusCode: 400,
		Err:        underlying,
	}

	if unwrapped := err.Unwrap(); unwrapped != underlying {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, underlying)
	}

	// Test with no underlying error
	err = &TransitError{
		Operation:  "CreateKey",
		StatusCode: 400,
	}

	if unwrapped := err.Unwrap(); unwrapped != nil {
		t.Errorf("Unwrap() = %v, want nil", unwrapped)
	}
}

func TestBatchSizeConstants(t *testing.T) {
	if DefaultMaxBatchSize != 250 {
		t.Errorf("DefaultMaxBatchSize = %d, want 250", DefaultMaxBatchSize)
	}

	if AbsoluteMaxBatchSize != 1000 {
		t.Errorf("AbsoluteMaxBatchSize = %d, want 1000", AbsoluteMaxBatchSize)
	}

	// Ensure default is less than absolute max
	if DefaultMaxBatchSize >= AbsoluteMaxBatchSize {
		t.Errorf("DefaultMaxBatchSize (%d) should be < AbsoluteMaxBatchSize (%d)",
			DefaultMaxBatchSize, AbsoluteMaxBatchSize)
	}
}

func TestKeyInfo_Fields(t *testing.T) {
	// This test ensures KeyInfo structure is correctly defined
	keyInfo := KeyInfo{
		Name:                 "test-key",
		Type:                 KeyTypeAES256GCM96,
		DeletionAllowed:      true,
		Derived:              false,
		Exportable:           true,
		AllowPlaintextBackup: false,
		LatestVersion:        5,
		MinDecryptionVersion: 1,
		MinEncryptionVersion: 3,
		SupportsEncryption:   true,
		SupportsDecryption:   true,
		SupportsSigning:      false,
		SupportsDerivation:   false,
		ConvergentEncryption: false,
		ConvergentVersion:    0,
	}

	if keyInfo.Name != "test-key" {
		t.Errorf("Name = %v, want test-key", keyInfo.Name)
	}

	if keyInfo.LatestVersion != 5 {
		t.Errorf("LatestVersion = %v, want 5", keyInfo.LatestVersion)
	}
}
