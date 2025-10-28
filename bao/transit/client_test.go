package transit

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "invalid config - missing address",
			config: &Config{
				Token: "test-token",
			},
			wantErr: true,
		},
		{
			name: "invalid config - missing token",
			config: &Config{
				Address: "https://openbao.example.com",
			},
			wantErr: true,
		},
		{
			name: "with TLS config",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				TLSConfig: &tls.Config{
					ServerName: "openbao.example.com",
				},
			},
			wantErr: false,
		},
		{
			name: "with namespace",
			config: &Config{
				Address:   "https://openbao.example.com",
				Token:     "test-token",
				Namespace: "admin/dev",
			},
			wantErr: false,
		},
		{
			name: "with custom mount",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				Mount:   "custom-transit",
			},
			wantErr: false,
		},
		{
			name: "with custom timeout",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				Timeout: 60 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "with retry config",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				RetryConfig: &RetryConfig{
					MaxRetries: 5,
					BaseDelay:  2 * time.Second,
					MaxDelay:   60 * time.Second,
					Multiplier: 2.0,
				},
			},
			wantErr: false,
		},
		{
			name: "with cache enabled",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				Cache: &CacheConfig{
					Enabled: true,
					TTL:     10 * time.Minute,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("NewClient() = nil, want error")
				}
				return
			}

			if err != nil {
				t.Errorf("NewClient() error = %v, want nil", err)
				return
			}

			if client == nil {
				t.Error("NewClient() returned nil client")
				return
			}

			// Verify client initialization
			if client.config == nil {
				t.Error("client.config is nil")
			}

			if client.client == nil {
				t.Error("client.client (API client) is nil")
			}

			// Clean up
			if err := client.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
}

func TestClient_Config(t *testing.T) {
	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	returnedConfig := client.Config()
	if returnedConfig == nil {
		t.Error("Config() returned nil")
		return
	}

	if returnedConfig.Address != config.Address {
		t.Errorf("Config().Address = %v, want %v", returnedConfig.Address, config.Address)
	}

	if returnedConfig.Token != config.Token {
		t.Errorf("Config().Token = %v, want %v", returnedConfig.Token, config.Token)
	}
}

func TestClient_SetToken(t *testing.T) {
	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "old-token",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	newToken := "new-token"
	client.SetToken(newToken)

	if client.config.Token != newToken {
		t.Errorf("SetToken() did not update config.Token, got %v, want %v", client.config.Token, newToken)
	}
}

func TestClient_SetNamespace(t *testing.T) {
	config := &Config{
		Address:   "https://openbao.example.com",
		Token:     "test-token",
		Namespace: "old-namespace",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	newNamespace := "new-namespace"
	client.SetNamespace(newNamespace)

	if client.config.Namespace != newNamespace {
		t.Errorf("SetNamespace() did not update config.Namespace, got %v, want %v", client.config.Namespace, newNamespace)
	}
}

func TestClient_buildPath(t *testing.T) {
	tests := []struct {
		name     string
		mount    string
		endpoint string
		want     string
	}{
		{
			name:     "default mount",
			mount:    "transit",
			endpoint: "keys/my-key",
			want:     "transit/keys/my-key",
		},
		{
			name:     "custom mount",
			mount:    "custom-transit",
			endpoint: "encrypt/my-key",
			want:     "custom-transit/encrypt/my-key",
		},
		{
			name:     "root endpoint",
			mount:    "transit",
			endpoint: "keys",
			want:     "transit/keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				Mount:   tt.mount,
			}

			client, err := NewClient(config)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}
			defer client.Close()

			got := client.buildPath(tt.endpoint)
			if got != tt.want {
				t.Errorf("buildPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClient_Close(t *testing.T) {
	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Close should not return error
	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	// Multiple calls to Close should be safe
	if err := client.Close(); err != nil {
		t.Errorf("Second Close() error = %v, want nil", err)
	}
}

func TestClient_HTTPClient(t *testing.T) {
	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	httpClient := client.HTTPClient()
	if httpClient == nil {
		t.Error("HTTPClient() returned nil")
	}
}

func TestClient_Sys(t *testing.T) {
	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	sys := client.Sys()
	if sys == nil {
		t.Error("Sys() returned nil")
	}
}

func TestClient_Logical(t *testing.T) {
	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	logical := client.Logical()
	if logical == nil {
		t.Error("Logical() returned nil")
	}
}

// TestClient_DefaultsAfterValidation ensures that defaults are properly set
// during validation when creating a new client.
func TestClient_DefaultsAfterValidation(t *testing.T) {
	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
		// Don't set Mount, Timeout, MaxBatchSize, RetryConfig
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	// Check that defaults were set
	if client.config.Mount == "" {
		t.Error("Mount was not set to default")
	}

	if client.config.Timeout == 0 {
		t.Error("Timeout was not set to default")
	}

	if client.config.MaxBatchSize == 0 {
		t.Error("MaxBatchSize was not set to default")
	}

	if client.config.RetryConfig == nil {
		t.Error("RetryConfig was not set to default")
	}
}
