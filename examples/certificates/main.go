//go:build example

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
	if err := os.MkdirAll("output", 0755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Generate a key pair for the CA using algo function
	fmt.Println("Generating CA key pair...")
	caKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	err = caCert.SaveToFile("output/ca-cert.pem")
	if err != nil {
		log.Fatalf("Failed to save CA certificate: %v", err)
	}
	fmt.Println("CA certificate saved to output/ca-cert.pem")

	// Generate a key pair for the server certificate using algo function
	fmt.Println("Generating server key pair...")
	serverKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	err = serverCert.SaveToFile("output/server-cert.pem")
	if err != nil {
		log.Fatalf("Failed to save server certificate: %v", err)
	}
	fmt.Println("Server certificate saved to output/server-cert.pem")

	// Verify server certificate against CA
	fmt.Println("Verifying server certificate...")
	err = cert.VerifyCertificate(serverCert, caCert)
	if err != nil {
		log.Fatalf("Certificate verification failed: %v", err)
	}
	fmt.Println("Server certificate verification successful!")

	// Create a self-signed certificate example
	fmt.Println("Creating self-signed certificate...")
	selfSignedKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
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

	err = selfSignedCert.SaveToFile("output/self-signed-cert.pem")
	if err != nil {
		log.Fatalf("Failed to save self-signed certificate: %v", err)
	}
	fmt.Println("Self-signed certificate saved to output/self-signed-cert.pem")

	// Save key pairs to files as well
	fmt.Println("Saving key pairs...")
	err = keypair.ToPEMFiles(caKeyPair, "output/ca_private.pem", "output/ca_public.pem")
	if err != nil {
		log.Fatalf("Failed to save CA key pair: %v", err)
	}

	err = keypair.ToPEMFiles(serverKeyPair, "output/server_private.pem", "output/server_public.pem")
	if err != nil {
		log.Fatalf("Failed to save server key pair: %v", err)
	}

	err = keypair.ToPEMFiles(selfSignedKeyPair, "output/selfsigned_private.pem", "output/selfsigned_public.pem")
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
	fmt.Println("  - output/ca-cert.pem")
	fmt.Println("  - output/server-cert.pem")
	fmt.Println("  - output/self-signed-cert.pem")
	fmt.Println("Key Pairs:")
	fmt.Println("  - output/ca_private.pem, output/ca_public.pem")
	fmt.Println("  - output/server_private.pem, output/server_public.pem")
	fmt.Println("  - output/selfsigned_private.pem, output/selfsigned_public.pem")

	fmt.Println("\n=== Certificate operations completed successfully! ===")
}
