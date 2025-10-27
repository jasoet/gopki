//go:build integration

package vault

import (
	"context"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func TestIntegration_GenerateRootCA(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVaultContainer(ctx, t)
	defer vaultContainer.Cleanup(ctx, t)

	// Create client
	client := vaultContainer.CreateTestClient(t)
	vaultContainer.WaitForVaultReady(ctx, t, client)
	vaultContainer.EnablePKI(ctx, t, client)

	t.Run("Generate internal root CA", func(t *testing.T) {
		resp, err := client.GenerateRootCA(ctx, &CAOptions{
			Type:         "internal",
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
			TTL:          "87600h", // 10 years
			KeyType:      "rsa",
			KeyBits:      2048,
		})
		if err != nil {
			t.Fatalf("GenerateRootCA failed: %v", err)
		}

		if resp.Certificate == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if resp.IssuerID == "" {
			t.Error("Expected issuer ID, got empty string")
		}
		if resp.KeyID == "" {
			t.Error("Expected key ID, got empty string")
		}
		if resp.SerialNumber == "" {
			t.Error("Expected serial number, got empty string")
		}

		// Verify certificate properties
		if resp.Certificate.Certificate.Subject.CommonName != "Test Root CA" {
			t.Errorf("Expected CN 'Test Root CA', got '%s'", resp.Certificate.Certificate.Subject.CommonName)
		}
	})

	t.Run("Generate exported root CA", func(t *testing.T) {
		resp, err := client.GenerateRootCA(ctx, &CAOptions{
			Type:       "exported",
			CommonName: "Test Exported Root CA",
			TTL:        "87600h",
			KeyType:    "ec",
			KeyBits:    256,
		})
		if err != nil {
			t.Fatalf("GenerateRootCA failed: %v", err)
		}

		if resp.Certificate == nil {
			t.Fatal("Expected certificate, got nil")
		}
		if resp.PrivateKey == "" {
			t.Error("Expected private key for exported type, got empty string")
		}
		if resp.PrivateKeyType == "" {
			t.Error("Expected private key type, got empty string")
		}
	})
}

func TestIntegration_CAWorkflow(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVaultContainer(ctx, t)
	defer vaultContainer.Cleanup(ctx, t)

	// Create client
	client := vaultContainer.CreateTestClient(t)
	vaultContainer.WaitForVaultReady(ctx, t, client)
	vaultContainer.EnablePKI(ctx, t, client)

	// Step 1: Generate root CA
	t.Log("Step 1: Generating root CA...")
	rootResp, err := client.GenerateRootCA(ctx, &CAOptions{
		Type:       "internal",
		CommonName: "Test Root CA",
		TTL:        "87600h",
		KeyType:    "rsa",
		KeyBits:    2048,
		IssuerName: "root-ca",
	})
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}
	t.Logf("Root CA generated with issuer ID: %s", rootResp.IssuerID)

	// Step 2: Get issuer
	t.Log("Step 2: Getting issuer details...")
	issuer, err := client.GetIssuer(ctx, rootResp.IssuerID)
	if err != nil {
		t.Fatalf("GetIssuer failed: %v", err)
	}
	if issuer.IssuerID != rootResp.IssuerID {
		t.Errorf("Expected issuer ID %s, got %s", rootResp.IssuerID, issuer.IssuerID)
	}
	if issuer.IssuerName != "root-ca" {
		t.Errorf("Expected issuer name 'root-ca', got '%s'", issuer.IssuerName)
	}

	// Step 3: List issuers
	t.Log("Step 3: Listing issuers...")
	issuers, err := client.ListIssuers(ctx)
	if err != nil {
		t.Fatalf("ListIssuers failed: %v", err)
	}
	if len(issuers) == 0 {
		t.Fatal("Expected at least one issuer")
	}
	found := false
	for _, id := range issuers {
		if id == rootResp.IssuerID {
			found = true
			break
		}
	}
	if !found {
		t.Error("Root CA issuer not found in list")
	}

	// Step 4: Set as default issuer
	t.Log("Step 4: Setting default issuer...")
	err = client.SetDefaultIssuer(ctx, rootResp.IssuerID)
	if err != nil {
		t.Fatalf("SetDefaultIssuer failed: %v", err)
	}

	// Step 5: Get default issuer
	t.Log("Step 5: Getting default issuer...")
	defaultIssuer, err := client.GetDefaultIssuer(ctx)
	if err != nil {
		t.Fatalf("GetDefaultIssuer failed: %v", err)
	}
	if defaultIssuer != rootResp.IssuerID {
		t.Errorf("Expected default issuer %s, got %s", rootResp.IssuerID, defaultIssuer)
	}

	// Step 6: Update issuer
	t.Log("Step 6: Updating issuer configuration...")
	err = client.UpdateIssuer(ctx, rootResp.IssuerID, &IssuerConfig{
		IssuerName: "updated-root-ca",
		Usage:      "issuing-certificates,crl-signing",
	})
	if err != nil {
		t.Fatalf("UpdateIssuer failed: %v", err)
	}

	// Verify update
	updatedIssuer, err := client.GetIssuer(ctx, rootResp.IssuerID)
	if err != nil {
		t.Fatalf("GetIssuer after update failed: %v", err)
	}
	if updatedIssuer.IssuerName != "updated-root-ca" {
		t.Errorf("Expected updated issuer name 'updated-root-ca', got '%s'", updatedIssuer.IssuerName)
	}
}

func TestIntegration_IntermediateCAWorkflow(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVaultContainer(ctx, t)
	defer vaultContainer.Cleanup(ctx, t)

	// Create client
	client := vaultContainer.CreateTestClient(t)
	vaultContainer.WaitForVaultReady(ctx, t, client)
	vaultContainer.EnablePKI(ctx, t, client)

	// Generate root CA first
	t.Log("Generating root CA...")
	_, err := client.GenerateRootCA(ctx, &CAOptions{
		Type:          "internal",
		CommonName:    "Test Root CA",
		TTL:           "87600h",
		KeyType:       "rsa",
		KeyBits:       2048,
		MaxPathLength: 1, // Allow signing intermediate CAs
	})
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	// Generate intermediate CSR
	t.Log("Generating intermediate CSR...")
	intermediateResp, err := client.GenerateIntermediateCA(ctx, &IntermediateCAOptions{
		Type:       "exported",
		CommonName: "Test Intermediate CA",
		TTL:        "43800h", // 5 years
		KeyType:    "rsa",
		KeyBits:    2048,
	})
	if err != nil {
		t.Fatalf("GenerateIntermediateCA failed: %v", err)
	}

	if intermediateResp.CSR == "" {
		t.Fatal("Expected CSR for exported intermediate, got empty string")
	}

	// Parse CSR
	x509CSR, err := parseCSRFromPEM(intermediateResp.CSR)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	// Wrap in cert.CertificateSigningRequest
	csr := &cert.CertificateSigningRequest{
		Request: x509CSR,
		PEMData: []byte(intermediateResp.CSR),
	}

	// Sign intermediate CSR with root CA
	t.Log("Signing intermediate CSR...")
	signedCert, err := client.SignIntermediateCSR(ctx, csr, &CAOptions{
		CommonName:    "Test Intermediate CA",
		TTL:           "43800h",
		MaxPathLength: 0, // Can only sign end-entity certs
	})
	if err != nil {
		t.Fatalf("SignIntermediateCSR failed: %v", err)
	}

	if signedCert.Certificate.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("Expected CN 'Test Intermediate CA', got '%s'", signedCert.Certificate.Subject.CommonName)
	}
}

func TestIntegration_ImportCA(t *testing.T) {
	ctx := context.Background()

	// Setup Vault container
	vaultContainer := SetupVaultContainer(ctx, t)
	defer vaultContainer.Cleanup(ctx, t)

	// Create client
	client := vaultContainer.CreateTestClient(t)
	vaultContainer.WaitForVaultReady(ctx, t, client)
	
	// Enable a SEPARATE PKI mount for import test
	// (to avoid conflicts with existing issuers)
	t.Log("Enabling separate PKI mount for import test...")
	err := vaultContainer.EnablePKIAtPath(ctx, t, client, "pki-import")
	if err != nil {
		t.Fatalf("Failed to enable PKI at custom path: %v", err)
	}
	
	// Create a new client config for the import mount
	importConfig := client.config
	importConfig.Mount = "pki-import"
	
	// Create new client with import mount
	importClient, err := NewClient(importConfig)
	if err != nil {
		t.Fatalf("Failed to create import client: %v", err)
	}

	// Generate an external CA using GoPKI (not in OpenBao)
	t.Log("Generating external CA with GoPKI...")
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	rootCert, err := cert.CreateCACertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "External Test CA",
		},
		ValidFor: 365 * 24 * time.Hour, // 1 year
	})
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Export private key to PEM
	privateKeyPEM, err := keypair.PrivateKeyToPEM(keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	// Create PEM bundle (cert + key)
	pemBundle := string(rootCert.PEMData) + "\n" + string(privateKeyPEM)

	// Import the CA bundle
	t.Log("Importing CA bundle to OpenBao...")
	importedIssuer, err := importClient.ImportCA(ctx, &CABundle{
		PEMBundle: pemBundle,
	})
	if err != nil {
		t.Fatalf("ImportCA failed: %v", err)
	}

	if importedIssuer.IssuerID == "" {
		t.Error("Expected issuer ID, got empty string")
	}
	if importedIssuer.KeyID == "" {
		t.Error("Expected key ID, got empty string")
	}

	// Verify the imported issuer
	issuer, err := importClient.GetIssuer(ctx, importedIssuer.IssuerID)
	if err != nil {
		t.Fatalf("GetIssuer failed: %v", err)
	}
	if issuer.IssuerID != importedIssuer.IssuerID {
		t.Errorf("Expected issuer ID %s, got %s", importedIssuer.IssuerID, issuer.IssuerID)
	}
	
	t.Logf("Successfully imported CA with issuer ID: %s", importedIssuer.IssuerID)
}
