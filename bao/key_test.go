package bao

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jasoet/gopki/keypair/algo"
)

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name       string
		opts       *GenerateKeyOptions
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "Successful RSA key generation",
			opts: &GenerateKeyOptions{
				KeyName: "test-rsa-key",
				KeyType: "rsa",
				KeyBits: 2048,
			},
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "7c9e6b1a-9c3d-4f8e-a1b2-3c4d5e6f7a8b",
					"key_name": "test-rsa-key",
					"key_type": "rsa",
					"key_bits": 2048
				}
			}`,
			wantErr: false,
		},
		{
			name: "Successful EC key generation",
			opts: &GenerateKeyOptions{
				KeyName: "test-ec-key",
				KeyType: "ec",
				KeyBits: 256,
			},
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "8d0f7c2b-0d4e-5f9f-b2c3-4d5e6f7a8b9c",
					"key_name": "test-ec-key",
					"key_type": "ec",
					"key_bits": 256
				}
			}`,
			wantErr: false,
		},
		{
			name: "Successful Ed25519 key generation",
			opts: &GenerateKeyOptions{
				KeyName: "test-ed25519-key",
				KeyType: "ed25519",
			},
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "9e1f8d3c-1e5f-6f0f-c3d4-5e6f7a8b9c0d",
					"key_name": "test-ed25519-key",
					"key_type": "ed25519"
				}
			}`,
			wantErr: false,
		},
		{
			name: "RSA key with default key bits",
			opts: &GenerateKeyOptions{
				KeyName: "test-rsa-default",
				KeyType: "rsa",
			},
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "0f2g9e4d-2f6g-7g1g-d4e5-6f7a8b9c0d1e",
					"key_name": "test-rsa-default",
					"key_type": "rsa",
					"key_bits": 2048
				}
			}`,
			wantErr: false,
		},
		{
			name:    "Nil options",
			opts:    nil,
			wantErr: true,
			errMsg:  "key options are required",
		},
		{
			name: "Missing key type",
			opts: &GenerateKeyOptions{
				KeyName: "test-key",
			},
			wantErr: true,
			errMsg:  "key type is required",
		},
		{
			name: "Invalid key type",
			opts: &GenerateKeyOptions{
				KeyName: "test-key",
				KeyType: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid key type",
		},
		{
			name: "Vault error response",
			opts: &GenerateKeyOptions{
				KeyName: "test-key",
				KeyType: "rsa",
				KeyBits: 2048,
			},
			statusCode: 400,
			response:   `{"errors": ["invalid key configuration"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Only validate if we expect a successful call
				if !tt.wantErr || tt.statusCode > 0 {
					if r.Method != "PUT" {
						t.Errorf("Expected PUT request, got %s", r.Method)
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
			result, err := client.GenerateKey(context.Background(), tt.opts)

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
			if result.KeyType != tt.opts.KeyType {
				t.Errorf("Expected key type %s, got %s", tt.opts.KeyType, result.KeyType)
			}
		})
	}
}

func TestImportKey(t *testing.T) {
	// Generate test key pairs
	rsaKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	ecdsaKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	ed25519KeyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key pair: %v", err)
	}

	tests := []struct {
		name       string
		keyPair    interface{}
		opts       *ImportKeyOptions
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name:    "Successful RSA key import",
			keyPair: rsaKeyPair,
			opts: &ImportKeyOptions{
				KeyName: "imported-rsa-key",
			},
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
					"key_name": "imported-rsa-key",
					"key_type": "rsa"
				}
			}`,
			wantErr: false,
		},
		{
			name:    "Successful ECDSA key import",
			keyPair: ecdsaKeyPair,
			opts: &ImportKeyOptions{
				KeyName: "imported-ec-key",
			},
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e",
					"key_name": "imported-ec-key",
					"key_type": "ec"
				}
			}`,
			wantErr: false,
		},
		{
			name:    "Successful Ed25519 key import",
			keyPair: ed25519KeyPair,
			opts: &ImportKeyOptions{
				KeyName: "imported-ed25519-key",
			},
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f",
					"key_name": "imported-ed25519-key",
					"key_type": "ed25519"
				}
			}`,
			wantErr: false,
		},
		{
			name:    "Import without key name",
			keyPair: rsaKeyPair,
			opts:    &ImportKeyOptions{},
			statusCode: 200,
			response: `{
				"data": {
					"key_id": "4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f9a",
					"key_type": "rsa"
				}
			}`,
			wantErr: false,
		},
		{
			name:    "Nil key pair",
			keyPair: nil,
			opts:    &ImportKeyOptions{KeyName: "test"},
			wantErr: true,
			errMsg:  "key pair is required",
		},
		{
			name:    "Unsupported key type",
			keyPair: "invalid-key-type",
			opts:    &ImportKeyOptions{KeyName: "test"},
			wantErr: true,
			errMsg:  "unsupported key pair type",
		},
		{
			name:    "Vault error response",
			keyPair: rsaKeyPair,
			opts:    &ImportKeyOptions{KeyName: "test"},
			statusCode: 400,
			response:   `{"errors": ["invalid key format"]}`,
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
			result, err := client.ImportKey(context.Background(), tt.keyPair, tt.opts)

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

func TestExportKey(t *testing.T) {
	// Generate a real RSA key for valid PEM data
	testKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	privKeyPEM, err := testKeyPair.PrivateKeyToPEM()
	if err != nil {
		t.Fatalf("Failed to convert private key to PEM: %v", err)
	}

	tests := []struct {
		name       string
		keyRef     string
		keyType    string
		statusCode int
		getResp    string
		exportResp string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "Successful RSA key export",
			keyRef:     "test-rsa-key",
			keyType:    "rsa",
			statusCode: 200,
			getResp: `{
				"data": {
					"key_id": "test-rsa-key",
					"key_name": "my-rsa-key",
					"key_type": "rsa",
					"key_bits": 2048
				}
			}`,
			exportResp: createJSONResponse(map[string]interface{}{
				"private_key": string(privKeyPEM),
				"key_type":    "rsa",
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
			name:       "Key not exportable",
			keyRef:     "non-exportable",
			keyType:    "rsa",
			statusCode: 403,
			getResp: `{
				"data": {
					"key_id": "non-exportable",
					"key_name": "my-key",
					"key_type": "rsa",
					"key_bits": 2048
				}
			}`,
			exportResp: `{"errors": ["key is not exportable"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Track request count
			requestCount := 0

			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount++

				if !tt.wantErr || tt.statusCode > 0 {
					if requestCount == 1 {
						// First request: GetKey
						if r.Method != "GET" {
							t.Errorf("Expected GET request, got %s", r.Method)
						}
						w.WriteHeader(200)
						w.Write([]byte(tt.getResp))
					} else {
						// Second request: Export
						if r.Method != "GET" {
							t.Errorf("Expected GET request, got %s", r.Method)
						}
						w.WriteHeader(tt.statusCode)
						w.Write([]byte(tt.exportResp))
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
			result, err := client.ExportKey(context.Background(), tt.keyRef)

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

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
