package main

import (
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	fmt.Println("=== GoPKI Certificate Examples ===")

	// Create outputs directory
	if err := os.MkdirAll("certs", 0755); err != nil {
		log.Fatal("Failed to create certs directory:", err)
	}

	// Generate a key pair for the CA using unified API
	fmt.Println("Generating CA key pair...")
	caKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatalf("Failed to generate CA key pair: %v", err)
	}

	// Create CA certificate request
	caRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Test CA Organization"},
			OrganizationalUnit: []string{"IT Department"},
			CommonName:         "Test Root CA",
		},
		ValidFrom: time.Now(),
		ValidFor:  10 * 365 * 24 * time.Hour, // 10 years
	}

	// Create self-signed CA certificate
	fmt.Println("Creating CA certificate...")
	caCert, err := cert.CreateCACertificate(caKeyPair, caRequest)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}

	// Save CA certificate to file
	err = caCert.SaveToFile("certs/ca-cert.pem")
	if err != nil {
		log.Fatalf("Failed to save CA certificate: %v", err)
	}
	fmt.Println("CA certificate saved to certs/ca-cert.pem")

	// Generate a key pair for the server certificate using unified API
	fmt.Println("Generating server key pair...")
	serverKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatalf("Failed to generate server key pair: %v", err)
	}

	// Create server certificate request
	serverRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Test Organization"},
			OrganizationalUnit: []string{"Web Services"},
			CommonName:         "localhost",
		},
		DNSNames:     []string{"localhost", "example.com", "www.example.com"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		EmailAddress: []string{"admin@example.com"},
		ValidFrom:    time.Now(),
		ValidFor:     365 * 24 * time.Hour, // 1 year
	}

	// Sign server certificate with CA
	fmt.Println("Signing server certificate with CA...")
	serverCert, err := cert.SignCertificate(caCert, caKeyPair, serverRequest, &serverKeyPair.PrivateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to sign server certificate: %v", err)
	}

	// Save server certificate to file
	err = serverCert.SaveToFile("certs/server-cert.pem")
	if err != nil {
		log.Fatalf("Failed to save server certificate: %v", err)
	}
	fmt.Println("Server certificate saved to certs/server-cert.pem")

	// Verify server certificate against CA
	fmt.Println("Verifying server certificate...")
	err = cert.VerifyCertificate(serverCert, caCert)
	if err != nil {
		log.Fatalf("Certificate verification failed: %v", err)
	}
	fmt.Println("Server certificate verification successful!")

	// Create a self-signed certificate example
	fmt.Println("Creating self-signed certificate...")
	selfSignedKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	selfSignedRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Self-Signed Organization"},
			CommonName:   "self-signed.example.com",
		},
		DNSNames:  []string{"self-signed.example.com"},
		ValidFrom: time.Now(),
		ValidFor:  365 * 24 * time.Hour, // 1 year
	}

	selfSignedCert, err := cert.CreateSelfSignedCertificate(selfSignedKeyPair, selfSignedRequest)
	if err != nil {
		log.Fatalf("Failed to create self-signed certificate: %v", err)
	}

	err = selfSignedCert.SaveToFile("certs/self-signed-cert.pem")
	if err != nil {
		log.Fatalf("Failed to save self-signed certificate: %v", err)
	}
	fmt.Println("Self-signed certificate saved to certs/self-signed-cert.pem")

	// Save key pairs to files as well
	fmt.Println("Saving key pairs...")
	err = keypair.ToFiles(caKeyPair, "certs/ca_private.pem", "certs/ca_public.pem")
	if err != nil {
		log.Fatalf("Failed to save CA key pair: %v", err)
	}

	err = keypair.ToFiles(serverKeyPair, "certs/server_private.pem", "certs/server_public.pem")
	if err != nil {
		log.Fatalf("Failed to save server key pair: %v", err)
	}

	err = keypair.ToFiles(selfSignedKeyPair, "certs/selfsigned_private.pem", "certs/selfsigned_public.pem")
	if err != nil {
		log.Fatalf("Failed to save self-signed key pair: %v", err)
	}

	// Display certificate information
	fmt.Println("\n=== Certificate Information ===")
	fmt.Printf("CA Certificate Subject: %s\n", caCert.Certificate.Subject.CommonName)
	fmt.Printf("CA Certificate Valid From: %s\n", caCert.Certificate.NotBefore)
	fmt.Printf("CA Certificate Valid Until: %s\n", caCert.Certificate.NotAfter)
	fmt.Printf("CA Certificate Is CA: %v\n", caCert.Certificate.IsCA)

	fmt.Printf("\nServer Certificate Subject: %s\n", serverCert.Certificate.Subject.CommonName)
	fmt.Printf("Server Certificate Valid From: %s\n", serverCert.Certificate.NotBefore)
	fmt.Printf("Server Certificate Valid Until: %s\n", serverCert.Certificate.NotAfter)
	fmt.Printf("Server Certificate DNS Names: %v\n", serverCert.Certificate.DNSNames)
	fmt.Printf("Server Certificate IP Addresses: %v\n", serverCert.Certificate.IPAddresses)

	fmt.Printf("\nSelf-Signed Certificate Subject: %s\n", selfSignedCert.Certificate.Subject.CommonName)
	fmt.Printf("Self-Signed Certificate Valid From: %s\n", selfSignedCert.Certificate.NotBefore)
	fmt.Printf("Self-Signed Certificate Valid Until: %s\n", selfSignedCert.Certificate.NotAfter)

	fmt.Println("\n=== Generated Files ===")
	fmt.Println("Certificates:")
	fmt.Println("  - certs/ca-cert.pem")
	fmt.Println("  - certs/server-cert.pem")
	fmt.Println("  - certs/self-signed-cert.pem")
	fmt.Println("Key Pairs:")
	fmt.Println("  - certs/ca_private.pem, certs/ca_public.pem")
	fmt.Println("  - certs/server_private.pem, certs/server_public.pem")
	fmt.Println("  - certs/selfsigned_private.pem, certs/selfsigned_public.pem")

	fmt.Println("\n=== Certificate operations completed successfully! ===")
}
