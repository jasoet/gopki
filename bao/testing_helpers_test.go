package bao

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// createTestServer creates a test HTTP server with custom handler.
func createTestServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// createTestClient creates a test client connected to a test server.
func createTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
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

// contains checks if a string contains a substring.
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
