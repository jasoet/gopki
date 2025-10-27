package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// createTestServer creates a test HTTP server with custom handler.
func createTestServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// createTestClient creates a test client connected to a test server.
func createTestClient(t *testing.T, serverURL string) *Client {
	client, err := NewClient(&Config{
		Address: serverURL,
		Token:   "test-token",
		Mount:   "pki",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}
	return client
}

func TestNewClient(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		client, err := NewClient(&Config{
			Address: "https://vault.example.com",
			Token:   "test-token",
			Mount:   "pki",
		})

		if err != nil {
			t.Errorf("NewClient() failed: %v", err)
		}
		if client == nil {
			t.Error("NewClient() returned nil client")
		}
		if client.config.Mount != "pki" {
			t.Errorf("Mount = %s, want pki", client.config.Mount)
		}
	})

	t.Run("Missing address", func(t *testing.T) {
		_, err := NewClient(&Config{
			Token: "test-token",
		})

		if err == nil {
			t.Error("NewClient() should fail with missing address")
		}
	})

	t.Run("Missing token", func(t *testing.T) {
		_, err := NewClient(&Config{
			Address: "https://vault.example.com",
		})

		if err == nil {
			t.Error("NewClient() should fail with missing token")
		}
	})

	t.Run("Invalid URL", func(t *testing.T) {
		_, err := NewClient(&Config{
			Address: "not a valid url",
			Token:   "test-token",
		})

		if err == nil {
			t.Error("NewClient() should fail with invalid URL")
		}
	})

	t.Run("Default mount path", func(t *testing.T) {
		client, err := NewClient(&Config{
			Address: "https://vault.example.com",
			Token:   "test-token",
			// Mount not specified
		})

		if err != nil {
			t.Fatalf("NewClient() failed: %v", err)
		}
		if client.config.Mount != "pki" {
			t.Errorf("Default mount = %s, want pki", client.config.Mount)
		}
	})
}

func TestClient_Health(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name:       "Healthy - 200 OK",
			statusCode: 200,
			response:   `{"initialized":true,"sealed":false,"standby":false}`,
			wantErr:    false,
		},
		{
			name:       "Standby - 429",
			statusCode: 429,
			response:   `{"initialized":true,"sealed":false,"standby":true}`,
			wantErr:    false,
		},
		{
			name:       "DR Mode - 472",
			statusCode: 472,
			response:   `{"initialized":true,"sealed":false,"standby":false}`,
			wantErr:    true, // SDK treats non-standard codes as errors
		},
		{
			name:       "Performance Standby - 473",
			statusCode: 473,
			response:   `{"initialized":true,"sealed":false,"standby":false}`,
			wantErr:    true, // SDK treats non-standard codes as errors
		},
		{
			name:       "Not Initialized - 501",
			statusCode: 501,
			response:   `{"initialized":false,"sealed":false,"standby":false}`,
			wantErr:    true,
		},
		{
			name:       "Sealed - 503",
			statusCode: 503,
			response:   `{"initialized":true,"sealed":true,"standby":false}`,
			wantErr:    true,
		},
		{
			name:       "Unexpected Status - 500",
			statusCode: 500,
			response:   `{"initialized":true,"sealed":false,"standby":false}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				// Verify endpoint
				if r.URL.Path != "/v1/sys/health" {
					t.Errorf("Health() called wrong endpoint: %s", r.URL.Path)
				}

				// Verify method
				if r.Method != "GET" {
					t.Errorf("Health() used wrong method: %s", r.Method)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			})
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			err := client.Health(ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("Health() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_Health_Timeout(t *testing.T) {
	// Create server that delays response
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
	})
	defer server.Close()

	client := createTestClient(t, server.URL)

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := client.Health(ctx)

	if err == nil {
		t.Error("Health() should fail with timeout")
	}

	if !IsRetryable(err) {
		t.Error("Timeout error should be retryable")
	}
}

func TestClient_Health_Cancellation(t *testing.T) {
	// Create server that delays response
	server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
	})
	defer server.Close()

	client := createTestClient(t, server.URL)

	// Create context and cancel immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := client.Health(ctx)

	if err == nil {
		t.Error("Health() should fail with cancellation")
	}
}

func TestClient_ValidateConnection(t *testing.T) {
	t.Run("Successful validation", func(t *testing.T) {
		server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
			// Handle health check
			if r.URL.Path == "/v1/sys/health" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
				return
			}

			// Handle PKI mount check
			if r.URL.Path == "/v1/pki/config/urls" {
				// Verify authentication header
				token := r.Header.Get("X-Vault-Token")
				if token != "test-token" {
					t.Errorf("Missing or wrong token: %s", token)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				w.Write([]byte(`{"data":{}}`))
				return
			}

			t.Errorf("Unexpected request: %s", r.URL.Path)
		})
		defer server.Close()

		client := createTestClient(t, server.URL)
		ctx := context.Background()

		err := client.ValidateConnection(ctx)
		if err != nil {
			t.Errorf("ValidateConnection() failed: %v", err)
		}
	})

	t.Run("Health check fails", func(t *testing.T) {
		server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
			// Health check fails
			if r.URL.Path == "/v1/sys/health" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(503) // Sealed
				w.Write([]byte(`{"initialized":true,"sealed":true,"standby":false}`))
				return
			}
		})
		defer server.Close()

		client := createTestClient(t, server.URL)
		ctx := context.Background()

		err := client.ValidateConnection(ctx)
		if err == nil {
			t.Error("ValidateConnection() should fail when health check fails")
		}
	})

	t.Run("Mount not found", func(t *testing.T) {
		server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/sys/health" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
				return
			}

			// Mount not found
			if r.URL.Path == "/v1/pki/config/urls" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(404)
				w.Write([]byte(`{"errors":["mount not found"]}`))
				return
			}
		})
		defer server.Close()

		client := createTestClient(t, server.URL)
		ctx := context.Background()

		err := client.ValidateConnection(ctx)
		if err == nil {
			t.Error("ValidateConnection() should fail when mount not found")
			return
		}
		t.Logf("Error received: %v", err)
		t.Logf("Error type: %T", err)
		if !IsNotFoundError(err) {
			t.Errorf("Error should be not found error, got: %v", err)
		}
	})

	t.Run("Permission denied", func(t *testing.T) {
		server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/sys/health" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
				return
			}

			// Permission denied
			if r.URL.Path == "/v1/pki/config/urls" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(403)
				w.Write([]byte(`{"errors":["permission denied"]}`))
				return
			}
		})
		defer server.Close()

		client := createTestClient(t, server.URL)
		ctx := context.Background()

		err := client.ValidateConnection(ctx)
		if err == nil {
			t.Error("ValidateConnection() should fail with permission denied")
		}
		if !IsAuthError(err) {
			t.Error("Error should be auth error")
		}
	})
}

// Note: The following tests are commented out as they test internal HTTP methods
// that have been removed after migrating to OpenBao SDK.
// The SDK handles authentication, headers, and HTTP requests internally.

/*
func TestClient_addAuthHeaders(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		wantToken string
		wantNS    string
	}{
		{
			name: "Token only",
			config: &Config{
				Address: "https://vault.example.com",
				Token:   "test-token-123",
			},
			wantToken: "test-token-123",
			wantNS:    "",
		},
		{
			name: "Token and namespace",
			config: &Config{
				Address:   "https://vault.example.com",
				Token:     "test-token-456",
				Namespace: "admin/team",
			},
			wantToken: "test-token-456",
			wantNS:    "admin/team",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := NewClient(tt.config)

			req, _ := http.NewRequest("GET", "https://example.com", nil)
			client.addAuthHeaders(req)

			// Check token header
			if got := req.Header.Get("X-Vault-Token"); got != tt.wantToken {
				t.Errorf("X-Vault-Token = %s, want %s", got, tt.wantToken)
			}

			// Check namespace header
			if got := req.Header.Get("X-Vault-Namespace"); got != tt.wantNS {
				t.Errorf("X-Vault-Namespace = %s, want %s", got, tt.wantNS)
			}

			// Check user agent
			if got := req.Header.Get("User-Agent"); got == "" {
				t.Error("User-Agent header not set")
			}
		})
	}
}

func TestClient_parseErrorResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    error
	}{
		{
			name:       "401 Unauthorized",
			statusCode: 401,
			body:       `{"errors":["invalid token"]}`,
			wantErr:    ErrUnauthorized,
		},
		{
			name:       "403 Permission Denied",
			statusCode: 403,
			body:       `{"errors":["permission denied"]}`,
			wantErr:    ErrPermissionDenied,
		},
		{
			name:       "404 Not Found",
			statusCode: 404,
			body:       `{"errors":["not found"]}`,
			wantErr:    ErrCertificateNotFound,
		},
		{
			name:       "429 Rate Limit",
			statusCode: 429,
			body:       `{"errors":["rate limit exceeded"]}`,
			wantErr:    ErrRateLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := NewClient(&Config{
				Address: "https://vault.example.com",
				Token:   "test",
			})

			err := client.parseErrorResponse(&http.Response{
				StatusCode: tt.statusCode,
			}, []byte(tt.body))

			if err == nil {
				t.Fatal("parseErrorResponse() should return error")
			}

			var vaultErr *VaultError
			if !IsVaultError(err, &vaultErr) {
				t.Errorf("Error should be VaultError, got %T", err)
			}

			if vaultErr.StatusCode != tt.statusCode {
				t.Errorf("StatusCode = %d, want %d", vaultErr.StatusCode, tt.statusCode)
			}

			if len(vaultErr.Errors) == 0 {
				t.Error("Errors slice should not be empty")
			}
		})
	}
}

func TestClient_buildURL(t *testing.T) {
	client, _ := NewClient(&Config{
		Address: "https://vault.example.com:8200",
		Token:   "test",
	})

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "With leading slash",
			path: "/v1/pki/issue/role",
			want: "https://vault.example.com:8200/v1/pki/issue/role",
		},
		{
			name: "Without leading slash",
			path: "v1/pki/issue/role",
			want: "https://vault.example.com:8200/v1/pki/issue/role",
		},
		{
			name: "Root path",
			path: "/",
			want: "https://vault.example.com:8200/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.buildURL(tt.path)
			if got != tt.want {
				t.Errorf("buildURL() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClient_doRequest(t *testing.T) {
	t.Run("Successful request with body", func(t *testing.T) {
		server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
			// Verify method
			if r.Method != "POST" {
				t.Errorf("Method = %s, want POST", r.Method)
			}

			// Verify content type
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %s, want application/json", ct)
			}

			// Verify auth header
			if token := r.Header.Get("X-Vault-Token"); token != "test-token" {
				t.Errorf("Token = %s, want test-token", token)
			}

			// Parse body
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("Failed to decode body: %v", err)
			}

			if body["test"] != "value" {
				t.Error("Body not correctly sent")
			}

			w.WriteHeader(200)
		})
		defer server.Close()

		client := createTestClient(t, server.URL)
		ctx := context.Background()

		reqBody := map[string]string{"test": "value"}
		resp, err := client.doRequest(ctx, "POST", "/v1/test", reqBody)
		if err != nil {
			t.Fatalf("doRequest() failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("Request timeout", func(t *testing.T) {
		server := createTestServer(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(200)
		})
		defer server.Close()

		client := createTestClient(t, server.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := client.doRequest(ctx, "GET", "/v1/test", nil)
		if err == nil {
			t.Error("doRequest() should fail with timeout")
		}

		if !IsRetryable(err) {
			t.Error("Timeout should be retryable")
		}
	})
}
*/

// Helper function to check if error is VaultError
func IsVaultError(err error, target **VaultError) bool {
	if err == nil {
		return false
	}
	ve, ok := err.(*VaultError)
	if ok && target != nil {
		*target = ve
	}
	return ok
}
