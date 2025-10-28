//go:build compatibility

package bao_test

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/jasoet/gopki/bao/pki"
	"github.com/jasoet/gopki/bao/testcontainer"
	"github.com/jasoet/gopki/cert"
)

// TestEnvironment holds the test environment for compatibility tests.
type TestEnvironment struct {
	Container *testcontainer.Container
	Client    *pki.Client
	Ctx       context.Context
	Cleanup   func()
}

// SetupBaoTest initializes an OpenBao test environment.
func SetupBaoTest(t *testing.T) *TestEnvironment {
	t.Helper()

	ctx := context.Background()

	// Start OpenBao container
	container, err := testcontainer.Start(ctx, testcontainer.DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to start OpenBao container: %v", err)
	}

	// Wait for OpenBao to be healthy
	err = container.WaitForHealthy(ctx, 30*time.Second)
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("OpenBao not healthy: %v", err)
	}

	// Enable PKI secrets engine
	err = container.EnablePKI(ctx, "pki", "87600h")
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to enable PKI: %v", err)
	}

	// Create bao client
	client, err := pki.NewClient(&pki.Config{
		Address: container.Address,
		Token:   container.Token,
		Mount:   "pki",
		Timeout: 30 * time.Second,
	})
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to create bao client: %v", err)
	}

	cleanup := func() {
		container.Terminate(ctx)
	}

	return &TestEnvironment{
		Container: container,
		Client:    client,
		Ctx:       ctx,
		Cleanup:   cleanup,
	}
}

// SetupBaoWithCA initializes OpenBao with a test CA.
func SetupBaoWithCA(t *testing.T) (*TestEnvironment, *pki.IssuerClient) {
	t.Helper()

	env := SetupBaoTest(t)

	// Create root CA
	caResp, err := env.Client.GenerateRootCA(env.Ctx, &pki.CAOptions{
		Type:       "internal",
		CommonName: "Test Root CA",
		KeyType:    "rsa",
		KeyBits:    2048,
		IssuerName: "test-root-ca",
		TTL:        "87600h",
	})
	if err != nil {
		env.Cleanup()
		t.Fatalf("Failed to create root CA: %v", err)
	}

	// Get issuer client
	issuer, err := env.Client.GetIssuer(env.Ctx, caResp.IssuerID)
	if err != nil {
		env.Cleanup()
		t.Fatalf("Failed to get issuer: %v", err)
	}

	return env, issuer
}

// SetupBaoWithCAAndRole initializes OpenBao with a test CA and role.
func SetupBaoWithCAAndRole(t *testing.T, roleName string, roleOpts *pki.RoleOptions) (*TestEnvironment, *pki.IssuerClient) {
	t.Helper()

	env, issuer := SetupBaoWithCA(t)

	// Create role
	_, err := issuer.CreateRole(env.Ctx, roleName, roleOpts)
	if err != nil {
		env.Cleanup()
		t.Fatalf("Failed to create role: %v", err)
	}

	return env, issuer
}

// CreateTestRootCA creates a test root CA in OpenBao.
func CreateTestRootCA(ctx context.Context, client *pki.Client, issuerName, keyType string, keyBits int) (*pki.IssuerClient, error) {
	caResp, err := client.GenerateRootCA(ctx, &pki.CAOptions{
		Type:          "internal",
		CommonName:    "Test Root CA",
		KeyType:       keyType,
		KeyBits:       keyBits,
		IssuerName:    issuerName,
		TTL:           "87600h",
		MaxPathLength: -1, // Allow unlimited intermediate CAs
	})
	if err != nil {
		return nil, err
	}

	// Get issuer client
	issuer, err := client.GetIssuer(ctx, caResp.IssuerID)
	if err != nil {
		return nil, err
	}

	return issuer, nil
}

// CreateTestIntermediateCA creates a test intermediate CA in OpenBao.
func CreateTestIntermediateCA(ctx context.Context, client *pki.Client, parentIssuer *pki.IssuerClient, issuerName, keyType string, keyBits int) (*pki.IssuerClient, error) {
	// Generate intermediate CSR (exported to get private key)
	intermediateResp, err := client.GenerateIntermediateCA(ctx, &pki.CAOptions{
		Type:       "exported",
		CommonName: "Test Intermediate CA",
		KeyType:    keyType,
		KeyBits:    keyBits,
	})
	if err != nil {
		return nil, err
	}

	// Parse CSR from PEM
	csrParsed, err := cert.ParseCSRFromPEM([]byte(intermediateResp.CSR))
	if err != nil {
		return nil, err
	}

	// Sign intermediate with parent using client's SignIntermediateCSR
	signedCert, err := client.SignIntermediateCSR(ctx, csrParsed, &pki.CAOptions{
		CommonName:    "Test Intermediate CA",
		TTL:           "43800h", // 5 years
		MaxPathLength: 0,
	})
	if err != nil {
		return nil, err
	}

	// Create PEM bundle (signed cert + private key)
	pemBundle := string(signedCert.PEMData) + "\n" + intermediateResp.PrivateKey

	// Import signed intermediate
	importedIssuer, err := client.ImportCA(ctx, &pki.CABundle{
		PEMBundle: pemBundle,
	})
	if err != nil {
		return nil, err
	}

	return importedIssuer, nil
}

// CreateStandardTestRole creates a standard test role with common settings.
func CreateStandardTestRole(ctx context.Context, issuer *pki.IssuerClient, roleName string) error {
	_, err := issuer.CreateRole(ctx, roleName, &pki.RoleOptions{
		AllowedDomains:  []string{"example.com", "test.local"},
		AllowSubdomains: true,
		TTL:             "720h",
		MaxTTL:          "8760h",
		ServerFlag:      true,
		ClientFlag:      true,
		KeyType:         "any",
	})
	return err
}

// ValidateCertificateChain validates a certificate chain.
func ValidateCertificateChain(t *testing.T, cert *x509.Certificate, caCert *x509.Certificate) {
	t.Helper()

	// Create cert pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify certificate
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("Certificate chain validation failed: %v", err)
	}
}

// AssertCertificateMatches validates certificate attributes.
func AssertCertificateMatches(t *testing.T, cert *x509.Certificate, expectedCN string, expectedDNSNames []string) {
	t.Helper()

	if cert.Subject.CommonName != expectedCN {
		t.Errorf("Expected CN %q, got %q", expectedCN, cert.Subject.CommonName)
	}

	if len(expectedDNSNames) > 0 {
		if len(cert.DNSNames) != len(expectedDNSNames) {
			t.Errorf("Expected %d DNS names, got %d", len(expectedDNSNames), len(cert.DNSNames))
		}

		dnsMap := make(map[string]bool)
		for _, dns := range cert.DNSNames {
			dnsMap[dns] = true
		}

		for _, expected := range expectedDNSNames {
			if !dnsMap[expected] {
				t.Errorf("Expected DNS name %q not found in certificate", expected)
			}
		}
	}
}
