package bao

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair/algo"
)

// Helper function to create properly escaped JSON response
func createJSONResponse(data interface{}) string {
	response := map[string]interface{}{
		"data": data,
	}
	jsonBytes, _ := json.Marshal(response)
	return string(jsonBytes)
}

func TestGenerateRootCA(t *testing.T) {
	// Create test certificate PEM
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "Test Root CA"},
		IsCA:    true,
	})
	certPEM := string(certificate.PEMData)

	tests := []struct {
		name       string
		opts       *CAOptions
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name: "Successful internal root CA generation",
			opts: &CAOptions{
				Type:         "internal",
				CommonName:   "Test Root CA",
				Organization: []string{"Test Org"},
				KeyType:      "rsa",
				KeyBits:      2048,
				TTL:          "87600h",
			},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"certificate":   certPEM,
				"issuing_ca":    certPEM,
				"ca_chain":      []string{certPEM},
				"serial_number": "01:02:03:04:05",
				"issuer_id":     "issuer-123",
				"key_id":        "key-456",
			}),
			wantErr: false,
		},
		{
			name: "Successful exported root CA generation",
			opts: &CAOptions{
				Type:       "exported",
				CommonName: "Test Root CA",
				KeyType:    "rsa",
				KeyBits:    2048,
			},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"certificate":      certPEM,
				"issuing_ca":       certPEM,
				"serial_number":    "01:02:03:04:05",
				"issuer_id":        "issuer-123",
				"key_id":           "key-456",
				"private_key":      "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
				"private_key_type": "rsa",
			}),
			wantErr: false,
		},
		{
			name:       "Missing options",
			opts:       nil,
			statusCode: 200,
			wantErr:    true,
		},
		{
			name: "Missing common name",
			opts: &CAOptions{
				Type: "internal",
			},
			statusCode: 200,
			wantErr:    true,
		},
		{
			name: "Invalid type",
			opts: &CAOptions{
				Type:       "invalid",
				CommonName: "Test CA",
			},
			statusCode: 200,
			wantErr:    true,
		},
		{
			name: "Vault error response",
			opts: &CAOptions{
				Type:       "internal",
				CommonName: "Test CA",
			},
			statusCode: 403,
			response:   `{"errors":["permission denied"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			resp, err := client.GenerateRootCA(ctx, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRootCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp == nil {
					t.Error("Expected response but got nil")
					return
				}
				if resp.Certificate == nil {
					t.Error("Expected certificate but got nil")
				}
				if resp.IssuerID == "" {
					t.Error("Expected issuer ID")
				}
				if resp.KeyID == "" {
					t.Error("Expected key ID")
				}
			}
		})
	}
}

func TestGenerateIntermediateCA(t *testing.T) {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "Test Intermediate CA"},
		IsCA:    true,
	})
	certPEM := string(certificate.PEMData)

	tests := []struct {
		name       string
		opts       *IntermediateCAOptions
		statusCode int
		response   string
		wantErr    bool
		checkCSR   bool
	}{
		{
			name: "Successful internal intermediate CA",
			opts: &IntermediateCAOptions{
				Type:       "internal",
				CommonName: "Test Intermediate CA",
				KeyType:    "rsa",
				KeyBits:    2048,
			},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"certificate":   certPEM,
				"issuing_ca":    certPEM,
				"serial_number": "01:02:03:04:05",
				"issuer_id":     "issuer-789",
				"key_id":        "key-012",
			}),
			wantErr:  false,
			checkCSR: false,
		},
		{
			name: "Successful exported intermediate CA (CSR)",
			opts: &IntermediateCAOptions{
				Type:       "exported",
				CommonName: "Test Intermediate CA",
				KeyType:    "rsa",
				KeyBits:    2048,
			},
			statusCode: 200,
			response: `{
				"data": {
					"csr": "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
					"serial_number": "01:02:03:04:05",
					"key_id": "key-012"
				}
			}`,
			wantErr:  false,
			checkCSR: true,
		},
		{
			name:       "Missing options",
			opts:       nil,
			statusCode: 200,
			wantErr:    true,
		},
		{
			name: "Missing common name",
			opts: &IntermediateCAOptions{
				Type: "internal",
			},
			statusCode: 200,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			resp, err := client.GenerateIntermediateCA(ctx, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateIntermediateCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp == nil {
					t.Error("Expected response but got nil")
					return
				}
				if tt.checkCSR {
					if resp.CSR == "" {
						t.Error("Expected CSR but got empty string")
					}
				} else {
					if resp.Certificate == nil {
						t.Error("Expected certificate but got nil")
					}
				}
			}
		})
	}
}

func TestSignIntermediateCSR(t *testing.T) {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	csr, _ := cert.CreateCSR(keyPair, cert.CSRRequest{
		Subject: pkix.Name{CommonName: "Test Intermediate CA"},
		IsCA:    true,
	})

	certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "Test Intermediate CA"},
		IsCA:    true,
	})
	certPEM := string(certificate.PEMData)

	tests := []struct {
		name       string
		csr        *cert.CertificateSigningRequest
		opts       *CAOptions
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name: "Successful CSR signing",
			csr:  csr,
			opts: &CAOptions{
				CommonName: "Test Intermediate CA",
				TTL:        "43800h",
			},
			statusCode: 200,
			response: createJSONResponse(map[string]interface{}{
				"certificate":   certPEM,
				"issuing_ca":    certPEM,
				"serial_number": "01:02:03:04:05",
			}),
			wantErr: false,
		},
		{
			name:       "Nil CSR",
			csr:        nil,
			opts:       &CAOptions{},
			statusCode: 200,
			wantErr:    true,
		},
		{
			name:       "Vault error",
			csr:        csr,
			opts:       &CAOptions{},
			statusCode: 400,
			response:   `{"errors":["invalid CSR"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			cert, err := client.SignIntermediateCSR(ctx, tt.csr, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("SignIntermediateCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && cert == nil {
				t.Error("Expected certificate but got nil")
			}
		})
	}
}

func TestImportCA(t *testing.T) {
	keyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	certificate, _ := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{CommonName: "Imported CA"},
		IsCA:    true,
	})
	certPEM := string(certificate.PEMData)

	tests := []struct {
		name       string
		bundle     *CABundle
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name: "Successful CA import",
			bundle: &CABundle{
				PEMBundle: certPEM,
			},
			statusCode: 200,
			response: `{
				"data": {
					"imported_issuers": ["issuer-123"],
					"imported_keys": ["key-456"],
					"mapping": {"issuer-123": "key-456"}
				}
			}`,
			wantErr: false,
		},
		{
			name:       "Nil bundle",
			bundle:     nil,
			statusCode: 200,
			wantErr:    true,
		},
		{
			name: "Empty PEM bundle",
			bundle: &CABundle{
				PEMBundle: "",
			},
			statusCode: 200,
			wantErr:    true,
		},
		{
			name: "No issuers imported",
			bundle: &CABundle{
				PEMBundle: certPEM,
			},
			statusCode: 200,
			response: `{
				"data": {
					"imported_issuers": [],
					"imported_keys": []
				}
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var getIssuerCalled bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/pki/issuer/issuer-123" {
					getIssuerCalled = true
					w.WriteHeader(200)
					issuerResponse := createJSONResponse(map[string]interface{}{
						"issuer_id":   "issuer-123",
						"issuer_name": "imported-ca",
						"key_id":      "key-456",
						"certificate": certPEM,
					})
					w.Write([]byte(issuerResponse))
					return
				}
				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			issuer, err := client.ImportCA(ctx, tt.bundle)

			if (err != nil) != tt.wantErr {
				t.Errorf("ImportCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if issuer == nil {
					t.Error("Expected issuer info but got nil")
					return
				}
				if !getIssuerCalled {
					t.Error("Expected GetIssuer to be called")
				}
				if issuer.IssuerID != "issuer-123" {
					t.Errorf("Expected issuer ID 'issuer-123', got '%s'", issuer.IssuerID)
				}
			}
		})
	}
}

func TestGetIssuer(t *testing.T) {
	tests := []struct {
		name       string
		issuerRef  string
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name:       "Successful issuer retrieval",
			issuerRef:  "issuer-123",
			statusCode: 200,
			response: `{
				"data": {
					"issuer_id": "issuer-123",
					"issuer_name": "test-issuer",
					"key_id": "key-456",
					"certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					"usage": "issuing-certificates,crl-signing"
				}
			}`,
			wantErr: false,
		},
		{
			name:       "Empty issuer reference",
			issuerRef:  "",
			statusCode: 200,
			wantErr:    true,
		},
		{
			name:       "Issuer not found",
			issuerRef:  "nonexistent",
			statusCode: 404,
			response:   `{"errors":["issuer not found"]}`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			issuer, err := client.GetIssuer(ctx, tt.issuerRef)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetIssuer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if issuer == nil {
					t.Error("Expected issuer but got nil")
					return
				}
				if issuer.IssuerID != "issuer-123" {
					t.Errorf("Expected issuer ID 'issuer-123', got '%s'", issuer.IssuerID)
				}
			}
		})
	}
}

func TestListIssuers(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantCount  int
		wantErr    bool
	}{
		{
			name:       "Successful list with multiple issuers",
			statusCode: 200,
			response: `{
				"data": {
					"keys": ["issuer-1", "issuer-2", "issuer-3"]
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
				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			issuers, err := client.ListIssuers(ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("ListIssuers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(issuers) != tt.wantCount {
				t.Errorf("Expected %d issuers, got %d", tt.wantCount, len(issuers))
			}
		})
	}
}

func TestUpdateIssuer(t *testing.T) {
	tests := []struct {
		name       string
		issuerRef  string
		config     *IssuerConfig
		statusCode int
		wantErr    bool
	}{
		{
			name:      "Successful update",
			issuerRef: "issuer-123",
			config: &IssuerConfig{
				IssuerName:           "updated-issuer",
				LeafNotAfterBehavior: "truncate",
				Usage:                "issuing-certificates,crl-signing",
			},
			statusCode: 200,
			wantErr:    false,
		},
		{
			name:       "Empty issuer reference",
			issuerRef:  "",
			config:     &IssuerConfig{},
			statusCode: 200,
			wantErr:    true,
		},
		{
			name:       "Nil config",
			issuerRef:  "issuer-123",
			config:     nil,
			statusCode: 200,
			wantErr:    true,
		},
		{
			name:       "Issuer not found",
			issuerRef:  "nonexistent",
			config:     &IssuerConfig{},
			statusCode: 404,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PUT" && !tt.wantErr {
					t.Errorf("Expected PUT request, got %s", r.Method)
				}
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			err := client.UpdateIssuer(ctx, tt.issuerRef, tt.config)

			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDeleteIssuer(t *testing.T) {
	tests := []struct {
		name       string
		issuerRef  string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "Successful deletion",
			issuerRef:  "issuer-123",
			statusCode: 204,
			wantErr:    false,
		},
		{
			name:       "Empty issuer reference",
			issuerRef:  "",
			statusCode: 200,
			wantErr:    true,
		},
		{
			name:       "Issuer not found",
			issuerRef:  "nonexistent",
			statusCode: 404,
			wantErr:    true,
		},
		{
			name:       "Issuer in use",
			issuerRef:  "issuer-123",
			statusCode: 400,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "DELETE" && !tt.wantErr {
					t.Errorf("Expected DELETE request, got %s", r.Method)
				}
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			err := client.DeleteIssuer(ctx, tt.issuerRef)

			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSetDefaultIssuer(t *testing.T) {
	tests := []struct {
		name       string
		issuerRef  string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "Successful set default",
			issuerRef:  "issuer-123",
			statusCode: 200,
			wantErr:    false,
		},
		{
			name:       "Empty issuer reference",
			issuerRef:  "",
			statusCode: 200,
			wantErr:    true,
		},
		{
			name:       "Issuer not found",
			issuerRef:  "nonexistent",
			statusCode: 404,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PUT" && !tt.wantErr {
					t.Errorf("Expected PUT request, got %s", r.Method)
				}

				// Verify request body contains default field
				if !tt.wantErr {
					var body map[string]interface{}
					json.NewDecoder(r.Body).Decode(&body)
					if _, ok := body["default"]; !ok {
						t.Error("Expected 'default' field in request body")
					}
				}

				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			err := client.SetDefaultIssuer(ctx, tt.issuerRef)

			if (err != nil) != tt.wantErr {
				t.Errorf("SetDefaultIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetDefaultIssuer(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantID     string
		wantErr    bool
	}{
		{
			name:       "Successful get default",
			statusCode: 200,
			response: `{
				"data": {
					"default": "issuer-123"
				}
			}`,
			wantID:  "issuer-123",
			wantErr: false,
		},
		{
			name:       "No default set",
			statusCode: 200,
			response: `{
				"data": {
					"default": ""
				}
			}`,
			wantID:  "",
			wantErr: false,
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
				w.WriteHeader(tt.statusCode)
				if tt.response != "" {
					w.Write([]byte(tt.response))
				}
			}))
			defer server.Close()

			client := createTestClient(t, server.URL)
			ctx := context.Background()

			issuerID, err := client.GetDefaultIssuer(ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetDefaultIssuer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && issuerID != tt.wantID {
				t.Errorf("Expected issuer ID '%s', got '%s'", tt.wantID, issuerID)
			}
		})
	}
}
