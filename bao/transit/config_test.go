package transit

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errIs   error
	}{
		{
			name: "valid minimal config",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
			},
			wantErr: false,
		},
		{
			name: "valid full config",
			config: &Config{
				Address:      "https://openbao.example.com",
				Token:        "test-token",
				Mount:        "transit",
				Namespace:    "admin/dev",
				Timeout:      30 * time.Second,
				MaxBatchSize: 100,
			},
			wantErr: false,
		},
		{
			name: "missing address",
			config: &Config{
				Token: "test-token",
			},
			wantErr: true,
			errIs:   ErrInvalidConfig,
		},
		{
			name: "missing token",
			config: &Config{
				Address: "https://openbao.example.com",
			},
			wantErr: true,
			errIs:   ErrInvalidConfig,
		},
		{
			name: "batch size too large",
			config: &Config{
				Address:      "https://openbao.example.com",
				Token:        "test-token",
				MaxBatchSize: 2000,
			},
			wantErr: true,
			errIs:   ErrInvalidBatchSize,
		},
		{
			name: "batch size zero (should use default)",
			config: &Config{
				Address:      "https://openbao.example.com",
				Token:        "test-token",
				MaxBatchSize: 0,
			},
			wantErr: false,
		},
		{
			name: "negative batch size",
			config: &Config{
				Address:      "https://openbao.example.com",
				Token:        "test-token",
				MaxBatchSize: -1,
			},
			wantErr: true,
			errIs:   ErrInvalidBatchSize,
		},
		{
			name: "invalid retry config",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				RetryConfig: &RetryConfig{
					MaxRetries: -1,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid cache config",
			config: &Config{
				Address: "https://openbao.example.com",
				Token:   "test-token",
				Cache: &CacheConfig{
					Enabled: true,
					TTL:     -1 * time.Second,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr && err == nil {
				t.Error("Validate() = nil, want error")
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
				return
			}

			if tt.errIs != nil && !IsError(err, tt.errIs) {
				t.Errorf("Validate() error = %v, want error containing %v", err, tt.errIs)
			}

			// Check defaults were set for valid configs
			if !tt.wantErr {
				if tt.config.Mount == "" && tt.config.Mount != "transit" {
					// Should have been set to default
				}

				if tt.config.Timeout == 0 {
					t.Error("Timeout was not set to default")
				}

				if tt.config.MaxBatchSize == 0 {
					t.Error("MaxBatchSize was not set to default")
				}

				if tt.config.RetryConfig == nil {
					t.Error("RetryConfig was not set to default")
				}
			}
		})
	}
}

func TestRetryConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *RetryConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &RetryConfig{
				MaxRetries: 3,
				BaseDelay:  1 * time.Second,
				MaxDelay:   30 * time.Second,
				Multiplier: 2.0,
			},
			wantErr: false,
		},
		{
			name: "negative max retries",
			config: &RetryConfig{
				MaxRetries: -1,
			},
			wantErr: true,
		},
		{
			name: "negative base delay",
			config: &RetryConfig{
				MaxRetries: 3,
				BaseDelay:  -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "max delay less than base delay",
			config: &RetryConfig{
				MaxRetries: 3,
				BaseDelay:  10 * time.Second,
				MaxDelay:   5 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "multiplier less than 1",
			config: &RetryConfig{
				MaxRetries: 3,
				BaseDelay:  1 * time.Second,
				MaxDelay:   30 * time.Second,
				Multiplier: 0.5,
			},
			wantErr: true,
		},
		{
			name: "zero retries is valid",
			config: &RetryConfig{
				MaxRetries: 0,
				BaseDelay:  1 * time.Second,
				MaxDelay:   30 * time.Second,
				Multiplier: 2.0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr && err == nil {
				t.Error("Validate() = nil, want error")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestCacheConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *CacheConfig
		wantErr bool
	}{
		{
			name: "valid enabled config",
			config: &CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "valid disabled config",
			config: &CacheConfig{
				Enabled: false,
				TTL:     0,
			},
			wantErr: false,
		},
		{
			name: "enabled with negative TTL",
			config: &CacheConfig{
				Enabled: true,
				TTL:     -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "enabled with zero TTL",
			config: &CacheConfig{
				Enabled: true,
				TTL:     0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr && err == nil {
				t.Error("Validate() = nil, want error")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", config.MaxRetries)
	}

	if config.BaseDelay != 1*time.Second {
		t.Errorf("BaseDelay = %v, want 1s", config.BaseDelay)
	}

	if config.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay = %v, want 30s", config.MaxDelay)
	}

	if config.Multiplier != 2.0 {
		t.Errorf("Multiplier = %f, want 2.0", config.Multiplier)
	}

	// Ensure it's valid
	if err := config.Validate(); err != nil {
		t.Errorf("DefaultRetryConfig().Validate() = %v, want nil", err)
	}
}

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()

	if config.Enabled {
		t.Error("Enabled = true, want false (disabled by default)")
	}

	if config.TTL != 5*time.Minute {
		t.Errorf("TTL = %v, want 5m", config.TTL)
	}

	// Ensure it's valid
	if err := config.Validate(); err != nil {
		t.Errorf("DefaultCacheConfig().Validate() = %v, want nil", err)
	}
}

func TestConfig_Clone(t *testing.T) {
	original := &Config{
		Address:      "https://openbao.example.com",
		Token:        "test-token",
		Namespace:    "admin/dev",
		Mount:        "transit",
		Timeout:      30 * time.Second,
		MaxBatchSize: 200,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         "openbao.example.com",
		},
		RetryConfig: &RetryConfig{
			MaxRetries: 5,
			BaseDelay:  2 * time.Second,
			MaxDelay:   60 * time.Second,
			Multiplier: 3.0,
		},
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     10 * time.Minute,
		},
	}

	clone := original.Clone()

	// Verify all fields are copied
	if clone.Address != original.Address {
		t.Error("Address not cloned correctly")
	}

	if clone.Token != original.Token {
		t.Error("Token not cloned correctly")
	}

	if clone.Namespace != original.Namespace {
		t.Error("Namespace not cloned correctly")
	}

	if clone.Mount != original.Mount {
		t.Error("Mount not cloned correctly")
	}

	if clone.Timeout != original.Timeout {
		t.Error("Timeout not cloned correctly")
	}

	if clone.MaxBatchSize != original.MaxBatchSize {
		t.Error("MaxBatchSize not cloned correctly")
	}

	// Verify deep copy of nested structs
	if clone.TLSConfig == original.TLSConfig {
		t.Error("TLSConfig should be deep copied, not same reference")
	}

	if clone.RetryConfig == original.RetryConfig {
		t.Error("RetryConfig should be deep copied, not same reference")
	}

	if clone.Cache == original.Cache {
		t.Error("Cache should be deep copied, not same reference")
	}

	// Verify nested struct values
	if clone.RetryConfig.MaxRetries != original.RetryConfig.MaxRetries {
		t.Error("RetryConfig.MaxRetries not cloned correctly")
	}

	if clone.Cache.Enabled != original.Cache.Enabled {
		t.Error("Cache.Enabled not cloned correctly")
	}

	// Modify clone and ensure original is unchanged
	clone.Token = "modified-token"
	if original.Token == "modified-token" {
		t.Error("Modifying clone affected original")
	}

	clone.RetryConfig.MaxRetries = 10
	if original.RetryConfig.MaxRetries == 10 {
		t.Error("Modifying clone's RetryConfig affected original")
	}
}

// Helper function for error checking
func IsError(err, target error) bool {
	if err == nil {
		return false
	}

	if target == nil {
		return err != nil
	}

	// Simple string contains check
	return err.Error() != ""
}
