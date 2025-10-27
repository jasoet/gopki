package bao

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid configuration",
			config: &Config{
				Address: "https://vault.example.com",
				Token:   "test-token",
				Mount:   "pki",
			},
			wantErr: false,
		},
		{
			name:    "Nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config is required",
		},
		{
			name: "Missing address",
			config: &Config{
				Token: "test-token",
			},
			wantErr: true,
			errMsg:  "address is required",
		},
		{
			name: "Missing token",
			config: &Config{
				Address: "https://vault.example.com",
			},
			wantErr: true,
			errMsg:  "token is required",
		},
		{
			name: "Invalid URL",
			config: &Config{
				Address: "not a valid url ::: %%%",
				Token:   "test-token",
			},
			wantErr: true,
		},
		{
			name: "Default mount path",
			config: &Config{
				Address: "https://vault.example.com",
				Token:   "test-token",
			},
			wantErr: false,
		},
		{
			name: "Custom mount path",
			config: &Config{
				Address: "https://vault.example.com",
				Token:   "test-token",
				Mount:   "pki-intermediate",
			},
			wantErr: false,
		},
		{
			name: "With namespace",
			config: &Config{
				Address:   "https://vault.example.com",
				Token:     "test-token",
				Namespace: "admin/team",
			},
			wantErr: false,
		},
		{
			name: "With TLS config",
			config: &Config{
				Address: "https://vault.example.com",
				Token:   "test-token",
				TLSConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			wantErr: false,
		},
		{
			name: "With custom timeout",
			config: &Config{
				Address: "https://vault.example.com",
				Token:   "test-token",
				Timeout: 60 * time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("NewClient() should return error")
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message = %v, should contain %q", err, tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("NewClient() unexpected error = %v", err)
				return
			}

			if client == nil {
				t.Error("NewClient() returned nil client")
				return
			}

			// Verify config is stored
			if client.Config() == nil {
				t.Error("Client.Config() returned nil")
			}

			// Verify SDK client is created
			if client.Sys() == nil {
				t.Error("Client.Sys() returned nil")
			}

			if client.Logical() == nil {
				t.Error("Client.Logical() returned nil")
			}
		})
	}
}

func TestClient_Config(t *testing.T) {
	config := &Config{
		Address: "https://vault.example.com",
		Token:   "test-token",
		Mount:   "pki-test",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	gotConfig := client.Config()
	if gotConfig == nil {
		t.Fatal("Config() returned nil")
	}

	if gotConfig.Mount != "pki-test" {
		t.Errorf("Config().Mount = %s, want pki-test", gotConfig.Mount)
	}
}

func TestClient_Close(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://vault.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	err = client.Close()
	if err != nil {
		t.Errorf("Close() unexpected error = %v", err)
	}
}

func TestClient_Health(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantErr    bool
		errCheck   func(error) bool
	}{
		{
			name:       "Healthy server",
			statusCode: http.StatusOK,
			response:   `{"initialized":true,"sealed":false,"standby":false}`,
			wantErr:    false,
		},
		{
			name:       "Standby node",
			statusCode: 429, // Standby
			response:   `{"initialized":true,"sealed":false,"standby":true}`,
			wantErr:    false,
		},
		{
			name:       "Not initialized",
			statusCode: 501,
			response:   `{"initialized":false,"sealed":false,"standby":false}`,
			wantErr:    true,
			errCheck: func(err error) bool {
				return errors.Is(err, ErrHealthCheckFailed)
			},
		},
		{
			name:       "Sealed",
			statusCode: 503,
			response:   `{"initialized":true,"sealed":true,"standby":false}`,
			wantErr:    true,
			errCheck: func(err error) bool {
				return errors.Is(err, ErrHealthCheckFailed)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/sys/health" {
					t.Errorf("Unexpected path: %s", r.URL.Path)
				}
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					t.Errorf("Unexpected method: %s", r.Method)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client, err := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Timeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatalf("NewClient() failed: %v", err)
			}

			ctx := context.Background()
			err = client.Health(ctx)

			if tt.wantErr {
				if err == nil {
					t.Error("Health() should return error")
					return
				}
				if tt.errCheck != nil && !tt.errCheck(err) {
					t.Errorf("Health() error check failed for: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Health() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestClient_Health_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"initialized":true,"sealed":false}`))
	}))
	defer server.Close()

	client, err := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err = client.Health(ctx)
	if err == nil {
		t.Error("Health() should timeout")
		return
	}

	if !errors.Is(err, ErrTimeout) && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Health() error should be timeout, got: %v", err)
	}
}

func TestClient_Health_Cancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = client.Health(ctx)
	if err == nil {
		t.Error("Health() should fail with cancelled context")
	}
}

func TestClient_ValidateConnection(t *testing.T) {
	tests := []struct {
		name       string
		setupMock  func(*httptest.Server) http.HandlerFunc
		wantErr    bool
		errCheck   func(error) bool
	}{
		{
			name: "Successful validation",
			setupMock: func(server *httptest.Server) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/sys/health" {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"initialized":true,"sealed":false}`))
						return
					}
					if r.URL.Path == "/v1/pki/config/urls" {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"data":{}}`))
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: false,
		},
		{
			name: "Health check fails",
			setupMock: func(server *httptest.Server) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/sys/health" {
						w.WriteHeader(503) // Sealed
						w.Write([]byte(`{"initialized":true,"sealed":true}`))
						return
					}
					w.WriteHeader(http.StatusOK)
				}
			},
			wantErr: true,
			errCheck: func(err error) bool {
				return errors.Is(err, ErrHealthCheckFailed)
			},
		},
		{
			name: "Mount not found (404)",
			setupMock: func(server *httptest.Server) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/sys/health" {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"initialized":true,"sealed":false}`))
						return
					}
					if r.URL.Path == "/v1/pki/config/urls" {
						w.WriteHeader(http.StatusNotFound)
						w.Write([]byte(`{"errors":["not found"]}`))
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}
			},
			wantErr: true,
			errCheck: func(err error) bool {
				return errors.Is(err, ErrMountNotFound)
			},
		},
		{
			name: "Unauthorized (401)",
			setupMock: func(server *httptest.Server) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/sys/health" {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"initialized":true,"sealed":false}`))
						return
					}
					if r.URL.Path == "/v1/pki/config/urls" {
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte(`{"errors":["unauthorized"]}`))
						return
					}
					w.WriteHeader(http.StatusUnauthorized)
				}
			},
			wantErr: true,
			errCheck: func(err error) bool {
				return errors.Is(err, ErrUnauthorized)
			},
		},
		{
			name: "Permission denied (403)",
			setupMock: func(server *httptest.Server) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/sys/health" {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{"initialized":true,"sealed":false}`))
						return
					}
					if r.URL.Path == "/v1/pki/config/urls" {
						w.WriteHeader(http.StatusForbidden)
						w.Write([]byte(`{"errors":["permission denied"]}`))
						return
					}
					w.WriteHeader(http.StatusForbidden)
				}
			},
			wantErr: true,
			errCheck: func(err error) bool {
				return errors.Is(err, ErrPermissionDenied)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(nil)
			defer server.Close()

			server.Config.Handler = tt.setupMock(server)

			client, err := NewClient(&Config{
				Address: server.URL,
				Token:   "test-token",
				Mount:   "pki",
				Timeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatalf("NewClient() failed: %v", err)
			}

			ctx := context.Background()
			err = client.ValidateConnection(ctx)

			if tt.wantErr {
				if err == nil {
					t.Error("ValidateConnection() should return error")
					return
				}
				if tt.errCheck != nil && !tt.errCheck(err) {
					t.Errorf("ValidateConnection() error check failed for: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateConnection() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestClient_Ping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"initialized":true,"sealed":false}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, err := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	ctx := context.Background()
	err = client.Ping(ctx)
	if err != nil {
		t.Errorf("Ping() unexpected error = %v", err)
	}
}

func TestClient_Sys(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://vault.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	sys := client.Sys()
	if sys == nil {
		t.Error("Sys() returned nil")
	}

	// Verify it's the correct type
	var _ *api.Sys = sys
}

func TestClient_Logical(t *testing.T) {
	client, err := NewClient(&Config{
		Address: "https://vault.example.com",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	logical := client.Logical()
	if logical == nil {
		t.Error("Logical() returned nil")
	}

	// Verify it's the correct type
	var _ *api.Logical = logical
}
