package pki

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid HTTPS config",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
			},
			wantErr: false,
		},
		{
			name: "Valid HTTP config (insecure)",
			config: &Config{
				Address: "http://localhost:8200",
				Token:   "test-token",
			},
			wantErr: false,
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
				Address: "https://openbao.example.com",
			},
			wantErr: true,
			errMsg:  "token is required",
		},
		{
			name: "Invalid URL",
			config: &Config{
				Address: "not a valid url :// %%%",
				Token:   "test-token",
			},
			wantErr: true,
			errMsg:  "invalid address",
		},
		{
			name: "Invalid scheme",
			config: &Config{
				Address: "ftp://openbao.example.com",
				Token:   "test-token",
			},
			wantErr: true,
			errMsg:  "must use http or https scheme",
		},
		{
			name: "Sets default mount",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				// Mount not specified
			},
			wantErr: false,
		},
		{
			name: "Custom mount",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				Mount:   "pki-intermediate",
			},
			wantErr: false,
		},
		{
			name: "With namespace",
			config: &Config{
				Address:   "https://openbao.example.com",
				Token:     "test-token",
				Namespace: "admin/engineering",
			},
			wantErr: false,
		},
		{
			name: "With TLS config",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				TLSConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() should return error")
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, should contain %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error = %v", err)
				}

				// Check defaults are set
				if tt.config.Mount == "" {
					t.Error("Validate() should set default mount")
				}
				if tt.config.Mount != "" && tt.config.Mount != "pki" && tt.config.Mount != "pki-intermediate" {
					// Custom mount should be preserved
					return
				}
				if tt.config.Timeout == 0 {
					t.Error("Validate() should set default timeout")
				}
			}
		})
	}
}

func TestConfig_ValidateDefaults(t *testing.T) {
	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	if config.Mount != "pki" {
		t.Errorf("Default Mount = %s, want pki", config.Mount)
	}

	if config.Timeout != 30*time.Second {
		t.Errorf("Default Timeout = %v, want 30s", config.Timeout)
	}
}

func TestConfig_ValidatePreservesCustomValues(t *testing.T) {
	customMount := "pki-intermediate"
	customTimeout := 60 * time.Second

	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
		Mount:   customMount,
		Timeout: customTimeout,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	if config.Mount != customMount {
		t.Errorf("Mount changed from %s to %s", customMount, config.Mount)
	}

	if config.Timeout != customTimeout {
		t.Errorf("Timeout changed from %v to %v", customTimeout, config.Timeout)
	}
}

func TestDefaultRetryConfig(t *testing.T) {
	rc := DefaultRetryConfig()

	if rc == nil {
		t.Fatal("DefaultRetryConfig() returned nil")
	}

	if rc.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", rc.MaxRetries)
	}

	if rc.BaseDelay != 1*time.Second {
		t.Errorf("BaseDelay = %v, want 1s", rc.BaseDelay)
	}

	if rc.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay = %v, want 30s", rc.MaxDelay)
	}

	if rc.Multiplier != 2.0 {
		t.Errorf("Multiplier = %f, want 2.0", rc.Multiplier)
	}
}

func TestRetryConfig(t *testing.T) {
	config := &Config{
		Address: "https://openbao.example.com",
		Token:   "test-token",
		RetryConfig: &RetryConfig{
			MaxRetries: 5,
			BaseDelay:  2 * time.Second,
			MaxDelay:   60 * time.Second,
			Multiplier: 3.0,
		},
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	if config.RetryConfig.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", config.RetryConfig.MaxRetries)
	}
}

func TestConfig_HTTPClient(t *testing.T) {
	customClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	config := &Config{
		Address:    "https://openbao.example.com",
		Token:      "test-token",
		HTTPClient: customClient,
	}

	err := config.Validate()
	if err != nil {
		t.Fatalf("Validate() failed: %v", err)
	}

	if config.HTTPClient != customClient {
		t.Error("Custom HTTPClient was not preserved")
	}
}
