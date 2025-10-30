package transit

import (
	"context"
	"testing"
	"time"
)

func TestCreateKeyOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *CreateKeyOptions
	}{
		{
			name: "nil options",
			opts: nil,
		},
		{
			name: "empty options",
			opts: &CreateKeyOptions{},
		},
		{
			name: "with derived",
			opts: &CreateKeyOptions{
				Derived: true,
			},
		},
		{
			name: "with exportable",
			opts: &CreateKeyOptions{
				Exportable: true,
			},
		},
		{
			name: "with convergent encryption",
			opts: &CreateKeyOptions{
				ConvergentEncryption: true,
				Derived:              true,
			},
		},
		{
			name: "with auto rotate",
			opts: &CreateKeyOptions{
				AutoRotatePeriod: 365 * 24 * time.Hour,
			},
		},
		{
			name: "all options",
			opts: &CreateKeyOptions{
				Derived:              true,
				Exportable:           true,
				AllowPlaintextBackup: true,
				ConvergentEncryption: true,
				AutoRotatePeriod:     30 * 24 * time.Hour,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test just ensures the struct can be created
			// and all fields are accessible
			if tt.opts != nil {
				_ = tt.opts.Derived
				_ = tt.opts.Exportable
				_ = tt.opts.AllowPlaintextBackup
				_ = tt.opts.ConvergentEncryption
				_ = tt.opts.AutoRotatePeriod
			}
		})
	}
}

func TestUpdateKeyOptions(t *testing.T) {
	minDecVer := 1
	minEncVer := 2
	deletionAllowed := true
	exportable := false
	period := 24 * time.Hour

	opts := &UpdateKeyOptions{
		MinDecryptionVersion: &minDecVer,
		MinEncryptionVersion: &minEncVer,
		DeletionAllowed:      &deletionAllowed,
		Exportable:           &exportable,
		AutoRotatePeriod:     &period,
	}

	if *opts.MinDecryptionVersion != 1 {
		t.Error("MinDecryptionVersion not set correctly")
	}
	if *opts.MinEncryptionVersion != 2 {
		t.Error("MinEncryptionVersion not set correctly")
	}
	if !*opts.DeletionAllowed {
		t.Error("DeletionAllowed not set correctly")
	}
	if *opts.Exportable {
		t.Error("Exportable not set correctly")
	}
	if *opts.AutoRotatePeriod != 24*time.Hour {
		t.Error("AutoRotatePeriod not set correctly")
	}
}

func TestImportKeyOptions(t *testing.T) {
	opts := &ImportKeyOptions{
		Type:                 KeyTypeAES256GCM96,
		HashFunction:         "SHA256",
		Exportable:           true,
		AllowPlaintextBackup: false,
		AllowRotation:        true,
		Derived:              true,
		ConvergentEncryption: true,
		AutoRotatePeriod:     365 * 24 * time.Hour,
	}

	if opts.Type != KeyTypeAES256GCM96 {
		t.Errorf("Type = %v, want %v", opts.Type, KeyTypeAES256GCM96)
	}

	if opts.HashFunction != "SHA256" {
		t.Errorf("HashFunction = %v, want SHA256", opts.HashFunction)
	}

	if !opts.Exportable {
		t.Error("Exportable should be true")
	}

	if !opts.AllowRotation {
		t.Error("AllowRotation should be true")
	}
}

func TestExportKeyType(t *testing.T) {
	tests := []struct {
		name     string
		keyType  ExportKeyType
		expected string
	}{
		{
			name:     "encryption key",
			keyType:  ExportEncryptionKey,
			expected: "encryption-key",
		},
		{
			name:     "signing key",
			keyType:  ExportSigningKey,
			expected: "signing-key",
		},
		{
			name:     "HMAC key",
			keyType:  ExportHMACKey,
			expected: "hmac-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.keyType) != tt.expected {
				t.Errorf("ExportKeyType = %v, want %v", tt.keyType, tt.expected)
			}
		})
	}
}

func TestParseKeyInfo(t *testing.T) {
	tests := []struct {
		name     string
		keyName  string
		data     map[string]interface{}
		wantErr  bool
		validate func(*testing.T, *KeyInfo)
	}{
		{
			name:    "minimal key info",
			keyName: "test-key",
			data: map[string]interface{}{
				"type":           KeyTypeAES256GCM96,
				"latest_version": 1,
			},
			wantErr: false,
			validate: func(t *testing.T, ki *KeyInfo) {
				if ki.Name != "test-key" {
					t.Errorf("Name = %v, want test-key", ki.Name)
				}
				if ki.Type != KeyTypeAES256GCM96 {
					t.Errorf("Type = %v, want %v", ki.Type, KeyTypeAES256GCM96)
				}
				if ki.LatestVersion != 1 {
					t.Errorf("LatestVersion = %v, want 1", ki.LatestVersion)
				}
			},
		},
		{
			name:    "full key info",
			keyName: "full-key",
			data: map[string]interface{}{
				"type":                   KeyTypeRSA2048,
				"deletion_allowed":       true,
				"derived":                true,
				"exportable":             true,
				"allow_plaintext_backup": false,
				"latest_version":         5,
				"min_decryption_version": 1,
				"min_encryption_version": 3,
				"supports_encryption":    true,
				"supports_decryption":    true,
				"supports_signing":       true,
				"supports_derivation":    true,
				"convergent_encryption":  true,
				"convergent_version":     2,
				"auto_rotate_period":     86400, // 1 day in seconds
			},
			wantErr: false,
			validate: func(t *testing.T, ki *KeyInfo) {
				if ki.Name != "full-key" {
					t.Errorf("Name = %v, want full-key", ki.Name)
				}
				if ki.Type != KeyTypeRSA2048 {
					t.Errorf("Type = %v, want %v", ki.Type, KeyTypeRSA2048)
				}
				if !ki.DeletionAllowed {
					t.Error("DeletionAllowed should be true")
				}
				if !ki.Derived {
					t.Error("Derived should be true")
				}
				if !ki.Exportable {
					t.Error("Exportable should be true")
				}
				if ki.LatestVersion != 5 {
					t.Errorf("LatestVersion = %v, want 5", ki.LatestVersion)
				}
				if ki.MinDecryptionVersion != 1 {
					t.Errorf("MinDecryptionVersion = %v, want 1", ki.MinDecryptionVersion)
				}
				if ki.MinEncryptionVersion != 3 {
					t.Errorf("MinEncryptionVersion = %v, want 3", ki.MinEncryptionVersion)
				}
				if !ki.SupportsEncryption {
					t.Error("SupportsEncryption should be true")
				}
				if !ki.SupportsSigning {
					t.Error("SupportsSigning should be true")
				}
				if !ki.ConvergentEncryption {
					t.Error("ConvergentEncryption should be true")
				}
				if ki.AutoRotatePeriod != 24*time.Hour {
					t.Errorf("AutoRotatePeriod = %v, want 24h", ki.AutoRotatePeriod)
				}
			},
		},
		{
			name:    "with key versions",
			keyName: "versioned-key",
			data: map[string]interface{}{
				"type":           KeyTypeEd25519,
				"latest_version": 3,
				"keys": map[string]interface{}{
					"1": map[string]interface{}{
						"creation_time": "2025-01-01T00:00:00Z",
						"public_key":    "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
					},
					"2": map[string]interface{}{
						"creation_time": "2025-01-02T00:00:00Z",
						"public_key":    "-----BEGIN PUBLIC KEY-----\ntest2\n-----END PUBLIC KEY-----",
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, ki *KeyInfo) {
				if len(ki.Keys) != 2 {
					t.Errorf("Keys count = %v, want 2", len(ki.Keys))
				}

				if v1, ok := ki.Keys[1]; ok {
					if v1.PublicKey == "" {
						t.Error("Version 1 public key is empty")
					}
					if v1.CreationTime.IsZero() {
						t.Error("Version 1 creation time is zero")
					}
				} else {
					t.Error("Version 1 not found")
				}

				if v2, ok := ki.Keys[2]; ok {
					if v2.PublicKey == "" {
						t.Error("Version 2 public key is empty")
					}
				} else {
					t.Error("Version 2 not found")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyInfo, err := parseKeyInfo(tt.keyName, tt.data)

			if tt.wantErr && err == nil {
				t.Error("parseKeyInfo() expected error, got nil")
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("parseKeyInfo() error = %v, want nil", err)
				return
			}

			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, keyInfo)
			}
		})
	}
}

func TestKeyClient_Accessors(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	keyClient := &KeyClient[KeyTypeAES256]{
		client:  client,
		keyName: "test-key",
		keyType: KeyTypeAES256{},
	}

	// Test Name()
	if keyClient.Name() != "test-key" {
		t.Errorf("Name() = %v, want test-key", keyClient.Name())
	}

	// Test Type()
	keyType := keyClient.Type()
	if keyType.KeyTypeName() != KeyTypeAES256GCM96 {
		t.Errorf("Type().KeyTypeName() = %v, want %v", keyType.KeyTypeName(), KeyTypeAES256GCM96)
	}
}

func TestClient_createKey_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test empty key name
	err = client.createKey(ctx, "", KeyTypeAES256GCM96, nil)
	if err == nil {
		t.Error("createKey() with empty name should return error")
	}
}

func TestClient_UpdateKeyConfig_NilOptions(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Test with nil options (should not error, just no-op)
	err = client.UpdateKeyConfig(ctx, "test-key", nil)
	if err != nil {
		t.Errorf("UpdateKeyConfig() with nil options error = %v, want nil", err)
	}

	// Test with empty name
	err = client.UpdateKeyConfig(ctx, "", &UpdateKeyOptions{})
	if err == nil {
		t.Error("UpdateKeyConfig() with empty name should return error")
	}
}

func TestClient_TrimKeyVersions_Validation(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	tests := []struct {
		name       string
		keyName    string
		minVersion int
		wantErr    bool
	}{
		{
			name:       "empty key name",
			keyName:    "",
			minVersion: 1,
			wantErr:    true,
		},
		{
			name:       "minVersion zero",
			keyName:    "test-key",
			minVersion: 0,
			wantErr:    true,
		},
		{
			name:       "minVersion negative",
			keyName:    "test-key",
			minVersion: -1,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.TrimKeyVersions(ctx, tt.keyName, tt.minVersion)

			if tt.wantErr && err == nil {
				t.Error("TrimKeyVersions() expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("TrimKeyVersions() error = %v, want nil", err)
			}
		})
	}
}
