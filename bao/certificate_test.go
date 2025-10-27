package bao

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

// Helper to create a test certificate for mocking
func createTestCertificatePEM(t *testing.T, commonName string) string {
	t.Helper()

	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		ValidFor: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return string(certificate.PEMData)
}

func TestIssueCertificateWithKeyPair(t *testing.T) {
	// Create test certificate PEMs
	certPEM := createTestCertificatePEM(t, "app.example.com")
	caPEM := createTestCertificatePEM(t, "Test CA")

	tests := []struct {
		name       string
		role       string
		keyPair    interface{}
		opts       *IssueOptions
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name:    "RSA key pair success",
			role:    "test-role",
			keyPair: func() interface{} { kp, _ := algo.GenerateRSAKeyPair(algo.KeySize2048); return kp }(),
			opts: &IssueOptions{
				CommonName: "app.example.com",
				AltNames:   []string{"www.app.example.com"},
				TTL:        "720h",
			},
			statusCode: 200,
			response: fmt.Sprintf(`{
				"data": {
					"certificate": %q,
					"issuing_ca": %q,
					"ca_chain": [%q],
					"serial_number": "24:db:e9:43:15:73:08:a1:f4:69:0c:c3:ec:a6:fb:5b:41:af:2d:fc",
					"expiration": 1740528000
				}
			}`, certPEM, caPEM, caPEM),
			wantErr: false,
		},
		{
			name:    "ECDSA key pair success",
			role:    "test-role",
			keyPair: func() interface{} { kp, _ := algo.GenerateECDSAKeyPair(algo.P256); return kp }(),
			opts: &IssueOptions{
				CommonName: "ecdsa.example.com",
				TTL:        "8760h",
			},
			statusCode: 200,
			response: fmt.Sprintf(`{
				"data": {
					"certificate": %q,
					"issuing_ca": %q,
					"ca_chain": [%q],
					"serial_number": "11:22:33:44:55",
					"expiration": 1740528000
				}
			}`, certPEM, caPEM, caPEM),
			wantErr: false,
		},
		{
			name:    "Ed25519 key pair success",
			role:    "test-role",
			keyPair: func() interface{} { kp, _ := algo.GenerateEd25519KeyPair(); return kp }(),
			opts: &IssueOptions{
				CommonName: "ed25519.example.com",
				TTL:        "8760h",
			},
			statusCode: 200,
			response: fmt.Sprintf(`{
				"data": {
					"certificate": %q,
					"issuing_ca": %q,
					"ca_chain": [%q],
					"serial_number": "aa:bb:cc:dd:ee",
					"expiration": 1740528000
				}
			}`, certPEM, caPEM, caPEM),
			wantErr: false,
		},
		{
			name:       "Missing role",
			role:       "", // Empty role should trigger validation error
			keyPair:    func() interface{} { kp, _ := algo.GenerateRSAKeyPair(algo.KeySize2048); return kp }(),
			opts:       &IssueOptions{CommonName: "test.com"},
			statusCode: 200,
			wantErr:    true, // Will fail validation before HTTP request
		},
		{
			name:       "Vault error response",
			role:       "test-role",
			keyPair:    func() interface{} { kp, _ := algo.GenerateRSAKeyPair(algo.KeySize2048); return kp }(),
			opts:       &IssueOptions{CommonName: "test.com"},
			statusCode: 403,
			response:   `{"errors":["permission denied"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify endpoint
				if r.URL.Path != "/v1/pki/sign/test-role" {
					t.Errorf("Wrong endpoint: %s", r.URL.Path)
				}

				// Verify method (Vault API uses PUT for write operations)
				if r.Method != "PUT" {
					t.Errorf("Wrong method: %s", r.Method)
				}

				// Verify CSR is in body
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("Failed to decode body: %v", err)
				}

				if _, ok := body["csr"]; !ok {
					t.Error("CSR not found in request body")
				}

				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			certificate, err := client.IssueCertificateWithKeyPair(ctx, tt.role, tt.keyPair, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("IssueCertificateWithKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && certificate == nil {
				t.Error("Expected certificate but got nil")
			}

			if !tt.wantErr && certificate != nil {
				// Verify certificate is valid GoPKI certificate
				if certificate.Certificate == nil {
					t.Error("Certificate.Certificate is nil")
				}
				if len(certificate.PEMData) == 0 {
					t.Error("Certificate.PEMData is empty")
				}
				if len(certificate.DERData) == 0 {
					t.Error("Certificate.DERData is empty")
				}
			}
		})
	}
}

func TestSignCSR(t *testing.T) {
	// Create test certificates
	certPEM := createTestCertificatePEM(t, "service.example.com")
	caPEM := createTestCertificatePEM(t, "Test CA")

	// Generate test key pair and CSR
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	csr, err := cert.CreateCSR(keyPair, cert.CSRRequest{
		Subject: pkix.Name{
			CommonName: "service.example.com",
		},
		DNSNames: []string{"service.example.com", "api.example.com"},
	})
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	tests := []struct {
		name       string
		role       string
		csr        *cert.CertificateSigningRequest
		opts       *SignOptions
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name: "Successful CSR signing",
			role: "web-server",
			csr:  csr,
			opts: &SignOptions{
				TTL: "8760h",
			},
			statusCode: 200,
			response: fmt.Sprintf(`{
				"data": {
					"certificate": %q,
					"issuing_ca": %q,
					"ca_chain": [%q],
					"serial_number": "11:22:33:44:55:66",
					"expiration": 1740528000
				}
			}`, certPEM, caPEM, caPEM),
			wantErr: false,
		},
		{
			name:    "Missing role",
			role:    "",
			csr:     csr,
			opts:    &SignOptions{},
			wantErr: true,
		},
		{
			name:    "Nil CSR",
			role:    "web-server",
			csr:     nil,
			opts:    &SignOptions{},
			wantErr: true,
		},
		{
			name: "Vault error",
			role: "web-server",
			csr:  csr,
			opts: &SignOptions{},
			statusCode: 404,
			response:   `{"errors":["role not found"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := fmt.Sprintf("/v1/pki/sign/%s", tt.role)
				if r.URL.Path != expectedPath {
					t.Errorf("Wrong endpoint: got %s, want %s", r.URL.Path, expectedPath)
				}

				if r.Method != "PUT" {
					t.Errorf("Wrong method: %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			certificate, err := client.SignCSR(ctx, tt.role, tt.csr, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("SignCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && certificate == nil {
				t.Error("Expected certificate but got nil")
			}
		})
	}
}

func TestGetCertificate(t *testing.T) {
	certPEM := createTestCertificatePEM(t, "test.example.com")

	tests := []struct {
		name       string
		serial     string
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name:       "Successful retrieval",
			serial:     "11:22:33:44:55",
			statusCode: 200,
			response: fmt.Sprintf(`{
				"data": {
					"certificate": %q
				}
			}`, certPEM),
			wantErr: false,
		},
		{
			name:    "Missing serial",
			serial:  "",
			wantErr: true,
		},
		{
			name:       "Certificate not found",
			serial:     "99:99:99:99:99",
			statusCode: 404,
			response:   `{"errors":["certificate not found"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := fmt.Sprintf("/v1/pki/cert/%s", tt.serial)
				if r.URL.Path != expectedPath {
					t.Errorf("Wrong endpoint: got %s, want %s", r.URL.Path, expectedPath)
				}

				if r.Method != "GET" {
					t.Errorf("Wrong method: %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			certificate, err := client.GetCertificate(ctx, tt.serial)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && certificate == nil {
				t.Error("Expected certificate but got nil")
			}
		})
	}
}

func TestListCertificates(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantCount  int
		wantErr    bool
	}{
		{
			name:       "Successful listing",
			statusCode: 200,
			response: `{
				"data": {
					"keys": ["11:22:33:44:55", "aa:bb:cc:dd:ee", "ff:00:11:22:33"]
				}
			}`,
			wantCount: 3,
			wantErr:   false,
		},
		{
			name:       "Empty list",
			statusCode: 200,
			response: `{
				"data": {
					"keys": []
				}
			}`,
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:       "Permission denied",
			statusCode: 403,
			response:   `{"errors":["permission denied"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/pki/certs" {
					t.Errorf("Wrong endpoint: %s", r.URL.Path)
				}

				if r.Method != "GET" {
					t.Errorf("Wrong method: %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			serials, err := client.ListCertificates(ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("ListCertificates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(serials) != tt.wantCount {
				t.Errorf("ListCertificates() count = %d, want %d", len(serials), tt.wantCount)
			}
		})
	}
}

func TestRevokeCertificate(t *testing.T) {
	tests := []struct {
		name       string
		serial     string
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name:       "Successful revocation",
			serial:     "11:22:33:44:55",
			statusCode: 200,
			response:   `{"data":{}}`,
			wantErr:    false,
		},
		{
			name:       "Successful revocation (204)",
			serial:     "11:22:33:44:55",
			statusCode: 204,
			response:   ``,
			wantErr:    false,
		},
		{
			name:    "Missing serial",
			serial:  "",
			wantErr: true,
		},
		{
			name:       "Certificate not found",
			serial:     "99:99:99:99:99",
			statusCode: 404,
			response:   `{"errors":["certificate not found"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/pki/revoke" {
					t.Errorf("Wrong endpoint: %s", r.URL.Path)
				}

				if r.Method != "PUT" {
					t.Errorf("Wrong method: %s", r.Method)
				}

				// Verify serial in body
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil && tt.serial != "" {
					t.Errorf("Failed to decode body: %v", err)
				}

				if tt.serial != "" {
					if body["serial_number"] != tt.serial {
						t.Errorf("Serial mismatch: got %v, want %s", body["serial_number"], tt.serial)
					}
				}

				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			err := client.RevokeCertificate(ctx, tt.serial)

			if (err != nil) != tt.wantErr {
				t.Errorf("RevokeCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseIPAddresses(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		wantLen  int
	}{
		{
			name:    "Valid IPv4 addresses",
			input:   []string{"192.168.1.1", "10.0.0.1"},
			wantLen: 2,
		},
		{
			name:    "Valid IPv6 addresses",
			input:   []string{"::1", "fe80::1"},
			wantLen: 2,
		},
		{
			name:    "Mixed valid and invalid",
			input:   []string{"192.168.1.1", "invalid", "10.0.0.1"},
			wantLen: 2,
		},
		{
			name:    "Empty slice",
			input:   []string{},
			wantLen: 0,
		},
		{
			name:    "All invalid",
			input:   []string{"invalid", "not-an-ip"},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIPAddresses(tt.input)
			if len(result) != tt.wantLen {
				t.Errorf("parseIPAddresses() len = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestJoinStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{
			name:  "Multiple strings",
			input: []string{"a", "b", "c"},
			want:  "a,b,c",
		},
		{
			name:  "Single string",
			input: []string{"a"},
			want:  "a",
		},
		{
			name:  "Empty slice",
			input: []string{},
			want:  "",
		},
		{
			name:  "Strings with spaces",
			input: []string{"hello world", "foo bar"},
			want:  "hello world,foo bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := joinStrings(tt.input)
			if result != tt.want {
				t.Errorf("joinStrings() = %q, want %q", result, tt.want)
			}
		})
	}
}
