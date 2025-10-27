package bao

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jasoet/gopki/keypair/algo"
)

// ============================================================================
// Tests for Client Methods (type-agnostic operations)
// ============================================================================

func TestListKeys(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantErr    bool
		wantCount  int
	}{
		{
			name:       "Successful list with multiple keys",
			statusCode: 200,
			response: `{
				"data": {
					"keys": [
						"key-1",
						"key-2",
						"key-3"
					]
				}
			}`,
			wantErr:   false,
			wantCount: 3,
		},
		{
			name:       "Empty key list",
			statusCode: 200,
			response: `{
				"data": {
					"keys": []
				}
			}`,
			wantErr:   false,
			wantCount: 0,
		},
		{
			name:       "Vault error response",
			statusCode: 500,
			response:   `{"errors": ["internal server error"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Errorf("Expected GET request, got %s", r.Method)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			// Create client
			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			// Call function
			result, err := client.ListKeys(context.Background())

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Validate result
			if len(result) != tt.wantCount {
				t.Errorf("Expected %d keys, got %d", tt.wantCount, len(result))
			}
		})
	}
}

func TestGetKey(t *testing.T) {
	tests := []struct {
		name       string
		keyRef     string
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "Successful get by key ID",
			keyRef:     "test-key-id",
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "test-key-id",
					"key_name": "my-key",
					"key_type": "rsa",
					"key_bits": 2048
				}
			}`,
			wantErr: false,
		},
		{
			name:       "Successful get by key name",
			keyRef:     "my-key",
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "abc-123",
					"key_name": "my-key",
					"key_type": "ec",
					"key_bits": 256
				}
			}`,
			wantErr: false,
		},
		{
			name:    "Empty key reference",
			keyRef:  "",
			wantErr: true,
			errMsg:  "key reference is required",
		},
		{
			name:       "Key not found",
			keyRef:     "non-existent",
			statusCode: 404,
			response:   `{"errors": ["key not found"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !tt.wantErr || tt.statusCode > 0 {
					if r.Method != "GET" {
						t.Errorf("Expected GET request, got %s", r.Method)
					}
					w.WriteHeader(tt.statusCode)
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			// Create client
			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			// Call function
			result, err := client.GetKey(context.Background(), tt.keyRef)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Validate result
			if result == nil {
				t.Fatal("Expected result, got nil")
			}
		})
	}
}

func TestDeleteKey(t *testing.T) {
	tests := []struct {
		name       string
		keyRef     string
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "Successful delete",
			keyRef:     "test-key",
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:       "Successful delete with 200 status",
			keyRef:     "test-key",
			statusCode: 200,
			response:   "",
			wantErr:    false,
		},
		{
			name:    "Empty key reference",
			keyRef:  "",
			wantErr: true,
			errMsg:  "key reference is required",
		},
		{
			name:       "Key not found",
			keyRef:     "non-existent",
			statusCode: 404,
			response:   `{"errors": ["key not found"]}`,
			wantErr:    true,
		},
		{
			name:       "Key in use",
			keyRef:     "in-use-key",
			statusCode: 400,
			response:   `{"errors": ["key is in use by issuer"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !tt.wantErr || tt.statusCode > 0 {
					if r.Method != "DELETE" {
						t.Errorf("Expected DELETE request, got %s", r.Method)
					}
					w.WriteHeader(tt.statusCode)
					if tt.response != "" {
						w.Write([]byte(tt.response))
					}
				}
			}))
			defer server.Close()

			// Create client
			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			// Call function
			err := client.DeleteKey(context.Background(), tt.keyRef)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestUpdateKeyName(t *testing.T) {
	tests := []struct {
		name       string
		keyRef     string
		newName    string
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "Successful update",
			keyRef:     "test-key",
			newName:    "renamed-key",
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:       "Successful update with 200 status",
			keyRef:     "test-key",
			newName:    "renamed-key",
			statusCode: 200,
			response:   "",
			wantErr:    false,
		},
		{
			name:    "Empty key reference",
			keyRef:  "",
			newName: "renamed-key",
			wantErr: true,
			errMsg:  "key reference is required",
		},
		{
			name:    "Empty new name",
			keyRef:  "test-key",
			newName: "",
			wantErr: true,
			errMsg:  "new key name is required",
		},
		{
			name:       "Key not found",
			keyRef:     "non-existent",
			newName:    "renamed-key",
			statusCode: 404,
			response:   `{"errors": ["key not found"]}`,
			wantErr:    true,
		},
		{
			name:       "Name already exists",
			keyRef:     "test-key",
			newName:    "existing-name",
			statusCode: 400,
			response:   `{"errors": ["key name already exists"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !tt.wantErr || tt.statusCode > 0 {
					if r.Method != "PUT" {
						t.Errorf("Expected PUT request, got %s", r.Method)
					}

					// Validate request body
					var reqBody map[string]interface{}
					if err := json.NewDecoder(r.Body).Decode(&reqBody); err == nil {
						if keyName, ok := reqBody["key_name"].(string); ok && keyName != tt.newName {
							t.Errorf("Expected key_name %q, got %q", tt.newName, keyName)
						}
					}

					w.WriteHeader(tt.statusCode)
					if tt.response != "" {
						w.Write([]byte(tt.response))
					}
				}
			}))
			defer server.Close()

			// Create client
			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			// Call function
			err := client.UpdateKeyName(context.Background(), tt.keyRef, tt.newName)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// Tests for Type-Safe Generic API (New)
// ============================================================================

func TestGenerateRSAKey_TypeSafe(t *testing.T) {
	tests := []struct {
		name       string
		opts       *GenerateKeyOptions
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "Successful RSA key generation with name",
			opts: &GenerateKeyOptions{
				KeyName: "test-rsa-key",
				KeyBits: 2048,
			},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"key_id":   "key-123",
				"key_name": "test-rsa-key",
				"key_type": "rsa",
				"key_bits": 2048,
			}),
			wantErr: false,
		},
		{
			name: "RSA key generation with default bits",
			opts: &GenerateKeyOptions{
				KeyName: "test-rsa-default",
			},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"key_id":   "key-456",
				"key_name": "test-rsa-default",
				"key_type": "rsa",
				"key_bits": 2048,
			}),
			wantErr: false,
		},
		{
			name:       "Nil options",
			opts:       nil,
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"key_id":   "key-789",
				"key_type": "rsa",
				"key_bits": 2048,
			}),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			result, err := client.CreateRSAKey(context.Background(), tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Fatal("Expected result, got nil")
			}

			if result.KeyInfo() == nil {
				t.Fatal("Expected key info, got nil")
			}

			if result.KeyInfo().KeyType != "rsa" {
				t.Errorf("Expected key type 'rsa', got '%s'", result.KeyInfo().KeyType)
			}
		})
	}
}

func TestGenerateECDSAKey_TypeSafe(t *testing.T) {
	tests := []struct {
		name       string
		opts       *GenerateKeyOptions
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name: "Successful ECDSA key generation",
			opts: &GenerateKeyOptions{
				KeyName: "test-ec-key",
				KeyBits: 256,
			},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"key_id":   "key-ec-123",
				"key_name": "test-ec-key",
				"key_type": "ec",
				"key_bits": 256,
			}),
			wantErr: false,
		},
		{
			name: "ECDSA key generation with default bits",
			opts: &GenerateKeyOptions{
				KeyName: "test-ec-default",
			},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"key_id":   "key-ec-456",
				"key_name": "test-ec-default",
				"key_type": "ec",
				"key_bits": 256,
			}),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			result, err := client.CreateECDSAKey(context.Background(), tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil || result.KeyInfo() == nil {
				t.Fatal("Expected result with key info, got nil")
			}

			if result.KeyInfo().KeyType != "ec" {
				t.Errorf("Expected key type 'ec', got '%s'", result.KeyInfo().KeyType)
			}
		})
	}
}

func TestGenerateEd25519Key_TypeSafe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(createJSONResponse(map[string]interface{}{
			"key_id":   "key-ed-123",
			"key_name": "test-ed25519-key",
			"key_type": "ed25519",
		})))
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
		Mount:   "pki",
	})

	result, err := client.CreateEd25519Key(context.Background(), &GenerateKeyOptions{
		KeyName: "test-ed25519-key",
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil || result.KeyInfo() == nil {
		t.Fatal("Expected result with key info, got nil")
	}

	if result.KeyInfo().KeyType != "ed25519" {
		t.Errorf("Expected key type 'ed25519', got '%s'", result.KeyInfo().KeyType)
	}
}

func TestImportRSAKey_TypeSafe(t *testing.T) {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	tests := []struct {
		name       string
		keyPair    *algo.RSAKeyPair
		opts       *ImportKeyOptions
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name:    "Successful RSA key import",
			keyPair: keyPair,
			opts: &ImportKeyOptions{
				KeyName: "imported-rsa-key",
			},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"key_id":   "key-imp-123",
				"key_name": "imported-rsa-key",
				"key_type": "rsa",
			}),
			wantErr: false,
		},
		{
			name:       "Import without name",
			keyPair:    keyPair,
			opts:       &ImportKeyOptions{},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"key_id":   "key-imp-456",
				"key_type": "rsa",
			}),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			result, err := client.ImportRSAKey(context.Background(), tt.keyPair, tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil || result.KeyInfo() == nil {
				t.Fatal("Expected result with key info, got nil")
			}

			if result.KeyInfo().KeyType != "rsa" {
				t.Errorf("Expected key type 'rsa', got '%s'", result.KeyInfo().KeyType)
			}
		})
	}
}

func TestImportECDSAKey_TypeSafe(t *testing.T) {
	keyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(createJSONResponse(map[string]interface{}{
			"key_id":   "key-ec-imp-123",
			"key_name": "imported-ec-key",
			"key_type": "ec",
		})))
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
		Mount:   "pki",
	})

	result, err := client.ImportECDSAKey(context.Background(), keyPair, &ImportKeyOptions{
		KeyName: "imported-ec-key",
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil || result.KeyInfo() == nil {
		t.Fatal("Expected result with key info, got nil")
	}

	if result.KeyInfo().KeyType != "ec" {
		t.Errorf("Expected key type 'ec', got '%s'", result.KeyInfo().KeyType)
	}
}

func TestImportEd25519Key_TypeSafe(t *testing.T) {
	keyPair, _ := algo.GenerateEd25519KeyPair()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(createJSONResponse(map[string]interface{}{
			"key_id":   "key-ed-imp-123",
			"key_name": "imported-ed25519-key",
			"key_type": "ed25519",
		})))
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
		Mount:   "pki",
	})

	result, err := client.ImportEd25519Key(context.Background(), keyPair, &ImportKeyOptions{
		KeyName: "imported-ed25519-key",
	})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil || result.KeyInfo() == nil {
		t.Fatal("Expected result with key info, got nil")
	}

	if result.KeyInfo().KeyType != "ed25519" {
		t.Errorf("Expected key type 'ed25519', got '%s'", result.KeyInfo().KeyType)
	}
}

func TestGetRSAKey_TypeSafe(t *testing.T) {
	tests := []struct {
		name       string
		keyRef     string
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "Successful get by ID",
			keyRef:     "key-123",
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"key_id":   "key-123",
				"key_name": "my-rsa-key",
				"key_type": "rsa",
				"key_bits": 2048,
			}),
			wantErr: false,
		},
		{
			name:    "Empty key reference",
			keyRef:  "",
			wantErr: true,
			errMsg:  "key reference is required",
		},
		{
			name:       "Type mismatch - expected RSA but got EC",
			keyRef:     "key-456",
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"key_id":   "key-456",
				"key_name": "my-ec-key",
				"key_type": "ec",
				"key_bits": 256,
			}),
			wantErr: true,
			errMsg:  "key type mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.statusCode > 0 {
					w.WriteHeader(tt.statusCode)
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			result, err := client.GetRSAKey(context.Background(), tt.keyRef)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil || result.KeyInfo() == nil {
				t.Fatal("Expected result with key info, got nil")
			}

			if result.KeyInfo().KeyType != "rsa" {
				t.Errorf("Expected key type 'rsa', got '%s'", result.KeyInfo().KeyType)
			}
		})
	}
}

func TestGetECDSAKey_TypeSafe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(createJSONResponse(map[string]interface{}{
			"key_id":   "key-ec-123",
			"key_name": "my-ec-key",
			"key_type": "ec",
			"key_bits": 256,
		})))
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
		Mount:   "pki",
	})

	result, err := client.GetECDSAKey(context.Background(), "key-ec-123")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil || result.KeyInfo() == nil {
		t.Fatal("Expected result with key info, got nil")
	}

	if result.KeyInfo().KeyType != "ec" {
		t.Errorf("Expected key type 'ec', got '%s'", result.KeyInfo().KeyType)
	}
}

func TestGetEd25519Key_TypeSafe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(createJSONResponse(map[string]interface{}{
			"key_id":   "key-ed-123",
			"key_name": "my-ed25519-key",
			"key_type": "ed25519",
		})))
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
		Mount:   "pki",
	})

	result, err := client.GetEd25519Key(context.Background(), "key-ed-123")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil || result.KeyInfo() == nil {
		t.Fatal("Expected result with key info, got nil")
	}

	if result.KeyInfo().KeyType != "ed25519" {
		t.Errorf("Expected key type 'ed25519', got '%s'", result.KeyInfo().KeyType)
	}
}

// Export functionality has been removed - use GenerateXXXKey() functions instead
// which return the keypair directly when keys are generated.
//
// Example:
//   keyPair, keyInfo, err := client.GenerateRSAKey(ctx, &GenerateKeyOptions{...})
//   // Use keyPair.PrivateKey immediately

func TestKeyClient_Delete(t *testing.T) {
	tests := []struct {
		name       string
		keyInfo    *KeyInfo
		statusCode int
		wantErr    bool
		errMsg     string
	}{
		{
			name: "Successful delete",
			keyInfo: &KeyInfo{
				KeyID:   "key-123",
				KeyName: "test-key",
				KeyType: "rsa",
			},
			statusCode: 204,
			wantErr:    false,
		},
		{
			name:    "Delete with nil key info",
			keyInfo: nil,
			wantErr: true,
			errMsg:  "key info not available",
		},
		{
			name: "Delete with empty key ID",
			keyInfo: &KeyInfo{
				KeyID: "",
			},
			wantErr: true,
			errMsg:  "key info not available",
		},
		{
			name: "Delete non-existent key",
			keyInfo: &KeyInfo{
				KeyID:   "non-existent",
				KeyName: "non-existent",
				KeyType: "rsa",
			},
			statusCode: 404,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "DELETE" && tt.statusCode > 0 {
					t.Errorf("Expected DELETE request, got %s", r.Method)
				}
				if tt.statusCode > 0 {
					w.WriteHeader(tt.statusCode)
				}
			}))
			defer server.Close()

			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			kc := &KeyClient[*algo.RSAKeyPair]{
				client:  client,
				keyInfo: tt.keyInfo,
			}

			err := kc.Delete(context.Background())

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestKeyClient_UpdateName(t *testing.T) {
	tests := []struct {
		name       string
		keyInfo    *KeyInfo
		newName    string
		statusCode int
		wantErr    bool
		errMsg     string
	}{
		{
			name: "Successful update",
			keyInfo: &KeyInfo{
				KeyID:   "key-123",
				KeyName: "old-name",
				KeyType: "rsa",
			},
			newName:    "new-name",
			statusCode: 204,
			wantErr:    false,
		},
		{
			name:    "Update with nil key info",
			keyInfo: nil,
			newName: "new-name",
			wantErr: true,
			errMsg:  "key info not available",
		},
		{
			name: "Update with empty key ID",
			keyInfo: &KeyInfo{
				KeyID: "",
			},
			newName: "new-name",
			wantErr: true,
			errMsg:  "key info not available",
		},
		{
			name: "Update with empty new name",
			keyInfo: &KeyInfo{
				KeyID:   "key-123",
				KeyName: "old-name",
				KeyType: "rsa",
			},
			newName: "",
			wantErr: true,
			errMsg:  "new key name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.statusCode > 0 {
					if r.Method != "PUT" {
						t.Errorf("Expected PUT request, got %s", r.Method)
					}
					w.WriteHeader(tt.statusCode)
				}
			}))
			defer server.Close()

			client, _ := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
			})

			kc := &KeyClient[*algo.RSAKeyPair]{
				client:  client,
				keyInfo: tt.keyInfo,
			}

			err := kc.UpdateName(context.Background(), tt.newName)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Verify cached keyInfo was updated
			if kc.keyInfo.KeyName != tt.newName {
				t.Errorf("Expected cached key name '%s', got '%s'", tt.newName, kc.keyInfo.KeyName)
			}
		})
	}
}

func TestKeyClient_KeyInfo(t *testing.T) {
	keyInfo := &KeyInfo{
		KeyID:   "key-123",
		KeyName: "test-key",
		KeyType: "rsa",
		KeyBits: 2048,
	}

	kc := &KeyClient[*algo.RSAKeyPair]{
		client:  nil, // Not needed for this test
		keyInfo: keyInfo,
	}

	result := kc.KeyInfo()

	if result != keyInfo {
		t.Error("Expected same KeyInfo instance")
	}
}

func TestKeyClient_HasKeyPair(t *testing.T) {
	t.Run("KeyPair is available", func(t *testing.T) {
		keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
		if err != nil {
			t.Fatalf("Failed to generate test key pair: %v", err)
		}

		keyInfo := &KeyInfo{
			KeyID:   "key-123",
			KeyName: "test-key",
			KeyType: "rsa",
			KeyBits: 2048,
		}

		kc := &KeyClient[*algo.RSAKeyPair]{
			client:  nil, // Not needed for this test
			keyInfo: keyInfo,
			keyPair: keyPair,
		}

		if !kc.HasKeyPair() {
			t.Error("Expected HasKeyPair() to return true when keypair is set")
		}

		// Also verify KeyPair() works
		retrievedKeyPair, err := kc.KeyPair()
		if err != nil {
			t.Errorf("Expected KeyPair() to succeed, got error: %v", err)
		}
		if retrievedKeyPair != keyPair {
			t.Error("Expected same keypair instance")
		}
	})

	t.Run("KeyPair is not available", func(t *testing.T) {
		keyInfo := &KeyInfo{
			KeyID:   "key-123",
			KeyName: "test-key",
			KeyType: "rsa",
			KeyBits: 2048,
		}

		kc := &KeyClient[*algo.RSAKeyPair]{
			client:  nil, // Not needed for this test
			keyInfo: keyInfo,
			// keyPair is nil (not set)
		}

		if kc.HasKeyPair() {
			t.Error("Expected HasKeyPair() to return false when keypair is not set")
		}

		// Also verify KeyPair() returns error
		_, err := kc.KeyPair()
		if err == nil {
			t.Error("Expected KeyPair() to return error when keypair is not available")
		}
	})
}
