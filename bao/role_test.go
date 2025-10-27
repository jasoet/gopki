package bao

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateRole(t *testing.T) {
	tests := []struct {
		name       string
		roleName   string
		opts       *RoleOptions
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name:     "Successful role creation with basic options",
			roleName: "web-server",
			opts: &RoleOptions{
				TTL:             "720h",
				MaxTTL:          "8760h",
				AllowedDomains:  []string{"example.com"},
				AllowSubdomains: true,
				ServerFlag:      true,
				ClientFlag:      false,
				KeyType:         "rsa",
				KeyBits:         2048,
			},
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:     "Successful role creation with 200 status",
			roleName: "client-cert",
			opts: &RoleOptions{
				TTL:        "720h",
				MaxTTL:     "8760h",
				ClientFlag: true,
				ServerFlag: false,
				KeyType:    "ec",
				KeyBits:    256,
			},
			statusCode: 200,
			response:   "",
			wantErr:    false,
		},
		{
			name:     "Role with multiple domain options",
			roleName: "wildcard-role",
			opts: &RoleOptions{
				AllowedDomains:            []string{"*.example.com", "*.test.com"},
				AllowSubdomains:           true,
				AllowWildcardCertificates: true,
				AllowBareDomains:          true,
				ServerFlag:                true,
			},
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:     "Role with IP SANs",
			roleName: "server-with-ip",
			opts: &RoleOptions{
				AllowIPSANs:   true,
				AllowedIPSANs: []string{"10.0.0.0/8", "192.168.0.0/16"},
				ServerFlag:    true,
			},
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:     "Role with URI SANs",
			roleName: "uri-role",
			opts: &RoleOptions{
				AllowedURISANs: []string{"spiffe://example.com/*"},
				ServerFlag:     true,
			},
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:     "Role with organization details",
			roleName: "org-role",
			opts: &RoleOptions{
				Organization:     []string{"Acme Inc"},
				OrganizationUnit: []string{"Engineering", "Security"},
				Country:          []string{"US"},
				Locality:         []string{"San Francisco"},
				Province:         []string{"CA"},
				ServerFlag:       true,
			},
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:     "Role with extended key usage",
			roleName: "code-signing-role",
			opts: &RoleOptions{
				CodeSigningFlag: true,
				KeyType:         "rsa",
				KeyBits:         3072,
			},
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:     "Role with email protection",
			roleName: "email-role",
			opts: &RoleOptions{
				EmailProtectionFlag: true,
				KeyType:             "rsa",
				KeyBits:             2048,
			},
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:     "Empty role name",
			roleName: "",
			opts:     &RoleOptions{},
			wantErr:  true,
			errMsg:   "role name is required",
		},
		{
			name:     "Nil options",
			roleName: "test-role",
			opts:     nil,
			wantErr:  true,
			errMsg:   "role options are required",
		},
		{
			name:     "Vault error response",
			roleName: "test-role",
			opts: &RoleOptions{
				TTL: "invalid",
			},
			statusCode: 400,
			response:   `{"errors": ["invalid TTL format"]}`,
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

					// Validate request body structure
					var reqBody map[string]interface{}
					if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
						t.Errorf("Failed to decode request body: %v", err)
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
			err := client.CreateRole(context.Background(), tt.roleName, tt.opts)

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

func TestGetRole(t *testing.T) {
	tests := []struct {
		name       string
		roleName   string
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
		validate   func(*testing.T, *Role)
	}{
		{
			name:       "Successful get role",
			roleName:   "web-server",
			statusCode: 200,
			response: `{
				"data": {
					"ttl": "720h",
					"max_ttl": "8760h",
					"allowed_domains": ["example.com"],
					"allow_subdomains": true,
					"server_flag": true,
					"client_flag": false,
					"key_type": "rsa",
					"key_bits": 2048
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, role *Role) {
				if role.Name != "web-server" {
					t.Errorf("Expected role name 'web-server', got %s", role.Name)
				}
				if role.RoleOptions == nil {
					t.Fatal("Expected role options, got nil")
				}
				if role.TTL != "720h" {
					t.Errorf("Expected TTL '720h', got %s", role.TTL)
				}
				if role.KeyType != "rsa" {
					t.Errorf("Expected key type 'rsa', got %s", role.KeyType)
				}
				if role.KeyBits != 2048 {
					t.Errorf("Expected key bits 2048, got %d", role.KeyBits)
				}
			},
		},
		{
			name:       "Get role with all options",
			roleName:   "complex-role",
			statusCode: 200,
			response: `{
				"data": {
					"ttl": "720h",
					"max_ttl": "8760h",
					"allowed_domains": ["example.com", "test.com"],
					"allow_subdomains": true,
					"allow_bare_domains": true,
					"allow_wildcard_certificates": true,
					"allow_ip_sans": true,
					"allowed_ip_sans": ["10.0.0.0/8"],
					"allowed_uri_sans": ["spiffe://example.com/*"],
					"server_flag": true,
					"client_flag": true,
					"code_signing_flag": false,
					"email_protection_flag": false,
					"key_type": "ec",
					"key_bits": 256,
					"organization": ["Acme Inc"],
					"ou": ["Engineering"],
					"country": ["US"],
					"locality": ["San Francisco"],
					"province": ["CA"]
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, role *Role) {
				if role.Name != "complex-role" {
					t.Errorf("Expected role name 'complex-role', got %s", role.Name)
				}
				if len(role.AllowedDomains) != 2 {
					t.Errorf("Expected 2 allowed domains, got %d", len(role.AllowedDomains))
				}
				if !role.AllowSubdomains {
					t.Error("Expected AllowSubdomains to be true")
				}
				if !role.ServerFlag {
					t.Error("Expected ServerFlag to be true")
				}
				if !role.ClientFlag {
					t.Error("Expected ClientFlag to be true")
				}
			},
		},
		{
			name:     "Empty role name",
			roleName: "",
			wantErr:  true,
			errMsg:   "role name is required",
		},
		{
			name:       "Role not found",
			roleName:   "non-existent",
			statusCode: 404,
			response:   `{"errors": ["role not found"]}`,
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
					w.Header().Set("Content-Type", "application/json")
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
			result, err := client.GetRole(context.Background(), tt.roleName)

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

			// Run custom validation if provided
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestListRoles(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantErr    bool
		wantCount  int
		wantRoles  []string
	}{
		{
			name:       "Successful list with multiple roles",
			statusCode: 200,
			response: `{
				"data": {
					"keys": [
						"web-server",
						"client-cert",
						"code-signing"
					]
				}
			}`,
			wantErr:   false,
			wantCount: 3,
			wantRoles: []string{"web-server", "client-cert", "code-signing"},
		},
		{
			name:       "Empty role list",
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
			name:       "Single role",
			statusCode: 200,
			response: `{
				"data": {
					"keys": ["default"]
				}
			}`,
			wantErr:   false,
			wantCount: 1,
			wantRoles: []string{"default"},
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
			result, err := client.ListRoles(context.Background())

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
				t.Errorf("Expected %d roles, got %d", tt.wantCount, len(result))
			}

			// Validate specific role names if provided
			if tt.wantRoles != nil {
				for i, want := range tt.wantRoles {
					if i >= len(result) {
						t.Errorf("Expected role at index %d, but result is too short", i)
						continue
					}
					if result[i] != want {
						t.Errorf("Expected role %q at index %d, got %q", want, i, result[i])
					}
				}
			}
		})
	}
}

func TestDeleteRole(t *testing.T) {
	tests := []struct {
		name       string
		roleName   string
		statusCode int
		response   string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "Successful delete",
			roleName:   "test-role",
			statusCode: 204,
			response:   "",
			wantErr:    false,
		},
		{
			name:       "Successful delete with 200 status",
			roleName:   "test-role",
			statusCode: 200,
			response:   "",
			wantErr:    false,
		},
		{
			name:     "Empty role name",
			roleName: "",
			wantErr:  true,
			errMsg:   "role name is required",
		},
		{
			name:       "Role not found",
			roleName:   "non-existent",
			statusCode: 404,
			response:   `{"errors": ["role not found"]}`,
			wantErr:    true,
		},
		{
			name:       "Vault error",
			roleName:   "test-role",
			statusCode: 500,
			response:   `{"errors": ["internal server error"]}`,
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
			err := client.DeleteRole(context.Background(), tt.roleName)

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
