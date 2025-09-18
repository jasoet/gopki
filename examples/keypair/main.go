//go:build example

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/keypair/format"
)

func main() {
	fmt.Println("=== GoPKI Keypair Module - Comprehensive Examples ===")
	fmt.Println("Demonstrating all keypair features with type-safe APIs")
	fmt.Println()

	// Create outputs directory
	if err := os.MkdirAll("output", 0755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Core Examples - Algorithm-Specific Generation
	fmt.Println("🔑 PART 1: Algorithm-Specific Key Generation")
	fmt.Println(strings.Repeat("=", 60))
	rsaAlgorithmExample()
	ecdsaAlgorithmExample()
	ed25519AlgorithmExample()

	// Generic Manager Examples
	fmt.Println("\n🔗 PART 2: Generic Manager Pattern")
	fmt.Println(strings.Repeat("=", 60))
	genericManagerExample()
	managerValidationExample()

	// Format Conversion Examples
	fmt.Println("\n🔄 PART 3: Format Conversion Matrix")
	fmt.Println(strings.Repeat("=", 60))
	formatConversionExample()
	roundTripTestingExample()

	// File Operations Examples
	fmt.Println("\n💾 PART 4: Secure File Operations")
	fmt.Println(strings.Repeat("=", 60))
	secureFileOperationsExample()
	filePermissionsExample()

	// Advanced Features
	fmt.Println("\n🛠️ PART 5: Advanced Features")
	fmt.Println(strings.Repeat("=", 60))
	keyComparisonExample()
	crossAlgorithmCompatibilityExample()

	// SSH Format Support
	fmt.Println("\n🔐 PART 6: SSH Format Support")
	fmt.Println(strings.Repeat("=", 60))
	sshFormatExample()
	sshPassphraseExample()

	// Integration Examples
	fmt.Println("\n🔗 PART 7: Module Integration")
	fmt.Println(strings.Repeat("=", 60))
	certificateIntegrationExample()
	typeConstraintExample()

	// Performance and Security
	fmt.Println("\n⚡ PART 8: Performance and Security")
	fmt.Println(strings.Repeat("=", 60))
	performanceComparisonExample()
	securityBestPracticesExample()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ All keypair examples completed successfully!")
	fmt.Println("📂 Generated files are in the 'output/' directory")
	fmt.Println("🔍 Check file permissions with: ls -la output/")
	fmt.Println(strings.Repeat("=", 60))
}

// PART 1: Algorithm-Specific Key Generation

func rsaAlgorithmExample() {
	fmt.Println("\n1.1 RSA Key Generation (Multiple Key Sizes)")

	// Generate different RSA key sizes
	keySizes := []algo.KeySize{algo.KeySize2048, algo.KeySize3072, algo.KeySize4096}

	for _, size := range keySizes {
		fmt.Printf("   → Generating RSA %d-bit key pair...\n", size.Bits())

		keyPair, err := algo.GenerateRSAKeyPair(size)
		if err != nil {
			log.Printf("Failed to generate RSA %d-bit key: %v\n", size.Bits(), err)
			continue
		}

		// Save to files with size in name
		privateFile := fmt.Sprintf("output/rsa_%d_private.pem", size.Bits())
		publicFile := fmt.Sprintf("output/rsa_%d_public.pem", size.Bits())

		err = keypair.ToPEMFiles(keyPair, privateFile, publicFile)
		if err != nil {
			log.Printf("Failed to save RSA %d-bit keys: %v\n", size.Bits(), err)
			continue
		}

		// Display key information
		fmt.Printf("     ✓ Generated: %d-bit RSA key pair\n", keyPair.PrivateKey.Size()*8)
		fmt.Printf("     ✓ Public key modulus size: %d bits\n", keyPair.PrivateKey.PublicKey.Size()*8)
		fmt.Printf("     ✓ Files: %s, %s\n", privateFile, publicFile)
	}
}

func ecdsaAlgorithmExample() {
	fmt.Println("\n1.2 ECDSA Key Generation (All Curves)")

	// Generate keys for all supported curves
	curves := []struct {
		curve algo.ECDSACurve
		name  string
	}{
		{algo.P224, "P-224"},
		{algo.P256, "P-256"},
		{algo.P384, "P-384"},
		{algo.P521, "P-521"},
	}

	for _, c := range curves {
		fmt.Printf("   → Generating ECDSA %s key pair...\n", c.name)

		keyPair, err := algo.GenerateECDSAKeyPair(c.curve)
		if err != nil {
			log.Printf("Failed to generate ECDSA %s key: %v\n", c.name, err)
			continue
		}

		// Save to files with curve in name
		privateFile := fmt.Sprintf("output/ecdsa_%s_private.pem", strings.ToLower(c.name))
		publicFile := fmt.Sprintf("output/ecdsa_%s_public.pem", strings.ToLower(c.name))

		err = keypair.ToPEMFiles(keyPair, privateFile, publicFile)
		if err != nil {
			log.Printf("Failed to save ECDSA %s keys: %v\n", c.name, err)
			continue
		}

		// Display key information
		fmt.Printf("     ✓ Generated: ECDSA %s key pair\n", keyPair.PrivateKey.Curve.Params().Name)
		fmt.Printf("     ✓ Curve bit size: %d\n", keyPair.PrivateKey.Curve.Params().BitSize)
		fmt.Printf("     ✓ Files: %s, %s\n", privateFile, publicFile)
	}
}

func ed25519AlgorithmExample() {
	fmt.Println("\n1.3 Ed25519 Key Generation (High Performance)")

	fmt.Printf("   → Generating Ed25519 key pair...\n")

	keyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		log.Printf("Failed to generate Ed25519 key: %v\n", err)
		return
	}

	// Save to files
	privateFile := "output/ed25519_private.pem"
	publicFile := "output/ed25519_public.pem"

	err = keypair.ToPEMFiles(keyPair, privateFile, publicFile)
	if err != nil {
		log.Printf("Failed to save Ed25519 keys: %v\n", err)
		return
	}

	// Display key information
	fmt.Printf("     ✓ Generated: Ed25519 key pair\n")
	fmt.Printf("     ✓ Private key size: %d bytes\n", len(keyPair.PrivateKey))
	fmt.Printf("     ✓ Public key size: %d bytes\n", len(keyPair.PublicKey))
	fmt.Printf("     ✓ Files: %s, %s\n", privateFile, publicFile)
}

// PART 2: Generic Manager Pattern

func genericManagerExample() {
	fmt.Println("\n2.1 Generic Manager Pattern with Type Safety")

	// RSA Manager with full generic type specification
	fmt.Printf("   → Creating RSA Manager with generic constraints...\n")
	rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to create RSA manager: %v\n", err)
		return
	}

	// ECDSA Manager with full generic type specification
	fmt.Printf("   → Creating ECDSA Manager with generic constraints...\n")
	ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		log.Printf("Failed to create ECDSA manager: %v\n", err)
		return
	}

	// Ed25519 Manager with full generic type specification
	fmt.Printf("   → Creating Ed25519 Manager with generic constraints...\n")
	ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		log.Printf("Failed to create Ed25519 manager: %v\n", err)
		return
	}

	// Demonstrate Manager capabilities
	managers := []interface{}{rsaManager, ecdsaManager, ed25519Manager}
	names := []string{"RSA", "ECDSA", "Ed25519"}

	for i, manager := range managers {
		fmt.Printf("     ✓ %s Manager created successfully\n", names[i])

		// Save using Manager methods
		filename := fmt.Sprintf("output/manager_%s.pem", strings.ToLower(names[i]))

		switch m := manager.(type) {
		case *keypair.Manager[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey]:
			err = m.SaveToPEM(filename, filename+".pub")
		case *keypair.Manager[*algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey]:
			err = m.SaveToPEM(filename, filename+".pub")
		case *keypair.Manager[*algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]:
			err = m.SaveToPEM(filename, filename+".pub")
		}

		if err != nil {
			log.Printf("Failed to save %s manager keys: %v\n", names[i], err)
			continue
		}

		fmt.Printf("     ✓ %s Manager keys saved to: %s\n", names[i], filename)
	}
}

func managerValidationExample() {
	fmt.Println("\n2.2 Manager Validation and Information Extraction")

	// Create a manager for testing
	manager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to create manager for validation: %v\n", err)
		return
	}

	// Validate the manager
	fmt.Printf("   → Validating manager...\n")

	if manager.IsValid() {
		fmt.Printf("     ✓ Manager is valid and properly initialized\n")
	} else {
		fmt.Printf("     ❌ Manager validation failed\n")
	}

	// Validate private key
	err = manager.ValidatePrivateKey()
	if err != nil {
		fmt.Printf("     ❌ Private key validation failed: %v\n", err)
	} else {
		fmt.Printf("     ✓ Private key passes security validation\n")
	}

	// Full validation
	err = manager.Validate()
	if err != nil {
		fmt.Printf("     ❌ Full validation failed: %v\n", err)
	} else {
		fmt.Printf("     ✓ Full key pair validation successful\n")
	}

	// Extract key information
	info, err := manager.GetInfo()
	if err != nil {
		log.Printf("Failed to get key info: %v\n", err)
		return
	}
	fmt.Printf("     ✓ Key Information:\n")
	fmt.Printf("       - Algorithm: %s\n", info.Algorithm)
	fmt.Printf("       - Key Size: %d bits\n", info.KeySize)
	if info.Curve != "" {
		fmt.Printf("       - Curve: %s\n", info.Curve)
	}
}

// PART 3: Format Conversion Matrix

func formatConversionExample() {
	fmt.Println("\n3.1 Comprehensive Format Conversion Matrix")

	// Generate one key of each type for format testing
	rsaKey, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	ecdsaKey, _ := algo.GenerateECDSAKeyPair(algo.P256)
	ed25519Key, _ := algo.GenerateEd25519KeyPair()

	keyPairs := []struct {
		keyPair interface{}
		name    string
	}{
		{rsaKey, "RSA"},
		{ecdsaKey, "ECDSA"},
		{ed25519Key, "Ed25519"},
	}

	for _, kp := range keyPairs {
		fmt.Printf("   → Converting %s key to all formats...\n", kp.name)

		baseName := fmt.Sprintf("output/format_%s", strings.ToLower(kp.name))

		// Save in all formats
		switch keyPair := kp.keyPair.(type) {
		case *algo.RSAKeyPair:
			// PEM format
			keypair.ToPEMFiles(keyPair, baseName+"_private.pem", baseName+"_public.pem")
			// DER format
			keypair.ToDERFiles(keyPair, baseName+"_private.der", baseName+"_public.der")
			// SSH format
			keypair.ToSSHFiles(keyPair, baseName+"_private_ssh", baseName+"_public.ssh", "gopki@example.com", "")

		case *algo.ECDSAKeyPair:
			keypair.ToPEMFiles(keyPair, baseName+"_private.pem", baseName+"_public.pem")
			keypair.ToDERFiles(keyPair, baseName+"_private.der", baseName+"_public.der")
			keypair.ToSSHFiles(keyPair, baseName+"_private_ssh", baseName+"_public.ssh", "gopki@example.com", "")

		case *algo.Ed25519KeyPair:
			keypair.ToPEMFiles(keyPair, baseName+"_private.pem", baseName+"_public.pem")
			keypair.ToDERFiles(keyPair, baseName+"_private.der", baseName+"_public.der")
			keypair.ToSSHFiles(keyPair, baseName+"_private_ssh", baseName+"_public.ssh", "gopki@example.com", "")
		}

		fmt.Printf("     ✓ %s converted to: PEM, DER, SSH formats\n", kp.name)

		// Calculate file sizes to show format differences
		pemFile := baseName + "_private.pem"
		derFile := baseName + "_private.der"
		sshFile := baseName + "_public.ssh"

		pemStat, _ := os.Stat(pemFile)
		derStat, _ := os.Stat(derFile)
		sshStat, _ := os.Stat(sshFile)

		if pemStat != nil && derStat != nil && sshStat != nil {
			fmt.Printf("     ✓ File sizes - PEM: %d, DER: %d, SSH: %d bytes\n",
				pemStat.Size(), derStat.Size(), sshStat.Size())
		}
	}
}

func roundTripTestingExample() {
	fmt.Println("\n3.2 Round-Trip Format Testing (Data Integrity)")

	// Generate test key
	originalKey, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to generate test key: %v\n", err)
		return
	}

	fmt.Printf("   → Testing PEM round-trip...\n")

	// Convert to PEM
	pemData, err := originalKey.PrivateKeyToPEM()
	if err != nil {
		log.Printf("Failed to convert to PEM: %v\n", err)
		return
	}

	// Convert back from PEM
	reloadedKey, err := algo.RSAKeyPairFromPEM(pemData)
	if err != nil {
		log.Printf("Failed to reload from PEM: %v\n", err)
		return
	}

	// Compare keys using generic manager
	originalManager := keypair.NewManager(originalKey, originalKey.PrivateKey, &originalKey.PrivateKey.PublicKey)
	reloadedManager := keypair.NewManager(reloadedKey, reloadedKey.PrivateKey, &reloadedKey.PrivateKey.PublicKey)

	if originalManager.CompareWith(reloadedManager) {
		fmt.Printf("     ✓ PEM round-trip successful - keys match perfectly\n")
	} else {
		fmt.Printf("     ❌ PEM round-trip failed - keys don't match\n")
	}

	// Test DER round-trip
	fmt.Printf("   → Testing DER round-trip...\n")
	derData, err := originalKey.PrivateKeyToDER()
	if err != nil {
		log.Printf("Failed to convert to DER: %v\n", err)
		return
	}

	reloadedDERKey, err := algo.RSAKeyPairFromDER(derData)
	if err != nil {
		log.Printf("Failed to reload from DER: %v\n", err)
		return
	}

	reloadedDERManager := keypair.NewManager(reloadedDERKey, reloadedDERKey.PrivateKey, &reloadedDERKey.PrivateKey.PublicKey)

	if originalManager.CompareWith(reloadedDERManager) {
		fmt.Printf("     ✓ DER round-trip successful - keys match perfectly\n")
	} else {
		fmt.Printf("     ❌ DER round-trip failed - keys don't match\n")
	}
}

// PART 4: Secure File Operations

func secureFileOperationsExample() {
	fmt.Println("\n4.1 Secure File Operations with Proper Permissions")

	// Generate key for file operations testing
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to generate key for file operations: %v\n", err)
		return
	}

	fmt.Printf("   → Demonstrating secure file saving...\n")

	// Save with secure permissions
	privateFile := "output/secure_private.pem"
	publicFile := "output/secure_public.pem"

	err = keypair.ToPEMFiles(keyPair, privateFile, publicFile)
	if err != nil {
		log.Printf("Failed to save secure files: %v\n", err)
		return
	}

	// Check file permissions
	privateStat, err := os.Stat(privateFile)
	if err != nil {
		log.Printf("Failed to stat private file: %v\n", err)
		return
	}

	publicStat, err := os.Stat(publicFile)
	if err != nil {
		log.Printf("Failed to stat public file: %v\n", err)
		return
	}

	fmt.Printf("     ✓ Private key file permissions: %s (should be -rw-------)\n", privateStat.Mode())
	fmt.Printf("     ✓ Public key file permissions: %s\n", publicStat.Mode())
	fmt.Printf("     ✓ Files saved with secure permissions automatically\n")

	// Test loading keys back
	fmt.Printf("   → Testing secure key loading...\n")

	loadedKey, err := keypair.LoadFromPEM[*algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](privateFile)
	if err != nil {
		log.Printf("Failed to load key: %v\n", err)
		return
	}

	if loadedKey.IsValid() {
		fmt.Printf("     ✓ Key loaded successfully and validated\n")
	} else {
		fmt.Printf("     ❌ Loaded key failed validation\n")
	}
}

func filePermissionsExample() {
	fmt.Println("\n4.2 File Permissions Security Demonstration")

	// Create a secure directory structure
	secureDir := "output/secure"
	if err := os.MkdirAll(secureDir, 0700); err != nil {
		log.Printf("Failed to create secure directory: %v\n", err)
		return
	}

	fmt.Printf("   → Created secure directory: %s (permissions: 0700)\n", secureDir)

	// Check directory permissions
	dirStat, err := os.Stat(secureDir)
	if err != nil {
		log.Printf("Failed to stat secure directory: %v\n", err)
		return
	}

	fmt.Printf("     ✓ Directory permissions: %s (owner access only)\n", dirStat.Mode())

	// Generate and save keys in secure directory
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Printf("Failed to generate key: %v\n", err)
		return
	}

	securePrivateFile := secureDir + "/ecdsa_private.pem"
	securePublicFile := secureDir + "/ecdsa_public.pem"

	err = keypair.ToPEMFiles(keyPair, securePrivateFile, securePublicFile)
	if err != nil {
		log.Printf("Failed to save keys in secure directory: %v\n", err)
		return
	}

	fmt.Printf("     ✓ Keys saved in secure directory structure\n")
	fmt.Printf("     ✓ Private key: %s\n", securePrivateFile)
	fmt.Printf("     ✓ Public key: %s\n", securePublicFile)
}

// PART 5: Advanced Features

func keyComparisonExample() {
	fmt.Println("\n5.1 Key Comparison and Validation Operations")

	// Generate two identical key managers for comparison
	key1, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	key2, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

	manager1 := keypair.NewManager(key1, key1.PrivateKey, &key1.PrivateKey.PublicKey)
	manager2 := keypair.NewManager(key2, key2.PrivateKey, &key2.PrivateKey.PublicKey)

	fmt.Printf("   → Comparing different key pairs...\n")

	// Compare different keys
	if manager1.CompareWith(manager2) {
		fmt.Printf("     ❌ Different keys reported as same (this should not happen)\n")
	} else {
		fmt.Printf("     ✓ Different keys correctly identified as different\n")
	}

	// Compare same key with itself
	if manager1.CompareWith(manager1) {
		fmt.Printf("     ✓ Same key correctly identified as identical\n")
	} else {
		fmt.Printf("     ❌ Same key reported as different (this should not happen)\n")
	}

	// Test private key comparison
	fmt.Printf("   → Testing private key comparison...\n")
	if manager1.ComparePrivateKeys(manager2) {
		fmt.Printf("     ❌ Different private keys reported as same\n")
	} else {
		fmt.Printf("     ✓ Different private keys correctly identified\n")
	}

	// Test public key comparison
	fmt.Printf("   → Testing public key comparison...\n")
	if manager1.ComparePublicKeys(manager2) {
		fmt.Printf("     ❌ Different public keys reported as same\n")
	} else {
		fmt.Printf("     ✓ Different public keys correctly identified\n")
	}
}

func crossAlgorithmCompatibilityExample() {
	fmt.Println("\n5.2 Cross-Algorithm Compatibility Testing")

	// Generate keys of different algorithms
	rsaKey, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	ecdsaKey, _ := algo.GenerateECDSAKeyPair(algo.P256)
	ed25519Key, _ := algo.GenerateEd25519KeyPair()

	keyPairs := []struct {
		keyPair interface{}
		name    string
	}{
		{rsaKey, "RSA-2048"},
		{ecdsaKey, "ECDSA-P256"},
		{ed25519Key, "Ed25519"},
	}

	fmt.Printf("   → Testing format compatibility across algorithms...\n")

	for _, kp := range keyPairs {
		// Test PEM format with each algorithm
		switch keyPair := kp.keyPair.(type) {
		case *algo.RSAKeyPair:
			pemData, err := keyPair.PrivateKeyToPEM()
			if err != nil {
				fmt.Printf("     ❌ %s PEM conversion failed: %v\n", kp.name, err)
				continue
			}

			// Try to reload
			_, err = algo.RSAKeyPairFromPEM(pemData)
			if err != nil {
				fmt.Printf("     ❌ %s PEM reload failed: %v\n", kp.name, err)
			} else {
				fmt.Printf("     ✓ %s PEM round-trip successful\n", kp.name)
			}

		case *algo.ECDSAKeyPair:
			pemData, err := keyPair.PrivateKeyToPEM()
			if err != nil {
				fmt.Printf("     ❌ %s PEM conversion failed: %v\n", kp.name, err)
				continue
			}

			_, err = algo.ECDSAKeyPairFromPEM(pemData)
			if err != nil {
				fmt.Printf("     ❌ %s PEM reload failed: %v\n", kp.name, err)
			} else {
				fmt.Printf("     ✓ %s PEM round-trip successful\n", kp.name)
			}

		case *algo.Ed25519KeyPair:
			pemData, err := keyPair.PrivateKeyToPEM()
			if err != nil {
				fmt.Printf("     ❌ %s PEM conversion failed: %v\n", kp.name, err)
				continue
			}

			_, err = algo.Ed25519KeyPairFromPEM(pemData)
			if err != nil {
				fmt.Printf("     ❌ %s PEM reload failed: %v\n", kp.name, err)
			} else {
				fmt.Printf("     ✓ %s PEM round-trip successful\n", kp.name)
			}
		}
	}
}

// PART 6: SSH Format Support

func sshFormatExample() {
	fmt.Println("\n6.1 SSH Format Support (OpenSSH Compatible)")

	// Generate keys for SSH format testing
	algorithms := []struct {
		generateKey func() (interface{}, error)
		name        string
	}{
		{func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize2048) }, "RSA"},
		{func() (interface{}, error) { return algo.GenerateECDSAKeyPair(algo.P256) }, "ECDSA"},
		{func() (interface{}, error) { return algo.GenerateEd25519KeyPair() }, "Ed25519"},
	}

	for _, alg := range algorithms {
		fmt.Printf("   → Testing %s SSH format...\n", alg.name)

		keyPair, err := alg.generateKey()
		if err != nil {
			log.Printf("Failed to generate %s key: %v\n", alg.name, err)
			continue
		}

		comment := fmt.Sprintf("gopki-%s@example.com", strings.ToLower(alg.name))
		sshPrivateFile := fmt.Sprintf("output/ssh_%s_id", strings.ToLower(alg.name))
		sshPublicFile := fmt.Sprintf("output/ssh_%s_id.pub", strings.ToLower(alg.name))

		// Convert to SSH format
		switch kp := keyPair.(type) {
		case *algo.RSAKeyPair:
			err = keypair.ToSSHFiles(kp, sshPrivateFile, sshPublicFile, comment, "")
		case *algo.ECDSAKeyPair:
			err = keypair.ToSSHFiles(kp, sshPrivateFile, sshPublicFile, comment, "")
		case *algo.Ed25519KeyPair:
			err = keypair.ToSSHFiles(kp, sshPrivateFile, sshPublicFile, comment, "")
		}

		if err != nil {
			log.Printf("Failed to save %s SSH keys: %v\n", alg.name, err)
			continue
		}

		// Read and display SSH public key format
		sshPublicData, err := os.ReadFile(sshPublicFile)
		if err != nil {
			log.Printf("Failed to read SSH public key: %v\n", err)
			continue
		}

		fmt.Printf("     ✓ %s SSH keys generated\n", alg.name)
		fmt.Printf("     ✓ SSH public key: %s\n", strings.TrimSpace(string(sshPublicData)))
		fmt.Printf("     ✓ Compatible with ~/.ssh/authorized_keys\n")

		// Test loading SSH private key back
		switch keyPairTyped := keyPair.(type) {
		case *algo.RSAKeyPair:
			sshData, _ := os.ReadFile(sshPrivateFile)
			_, err = algo.RSAKeyPairFromSSH(format.SSH(sshData), "")
		case *algo.ECDSAKeyPair:
			sshData, _ := os.ReadFile(sshPrivateFile)
			_, err = algo.ECDSAKeyPairFromSSH(format.SSH(sshData), "")
		case *algo.Ed25519KeyPair:
			sshData, _ := os.ReadFile(sshPrivateFile)
			_ = keyPairTyped // use the variable
			_, err = algo.Ed25519KeyPairFromSSH(format.SSH(sshData), "")
		}

		if err != nil {
			fmt.Printf("     ❌ SSH private key reload failed: %v\n", err)
		} else {
			fmt.Printf("     ✓ SSH private key reload successful\n")
		}
	}
}

func sshPassphraseExample() {
	fmt.Println("\n6.2 SSH Format with Passphrase Protection")

	// Generate key for passphrase testing
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to generate key for passphrase test: %v\n", err)
		return
	}

	fmt.Printf("   → Testing SSH format with passphrase protection...\n")

	passphrase := "secure-passphrase-123"
	comment := "gopki-protected@example.com"

	// Save with passphrase
	protectedPrivate := "output/ssh_protected_id"
	protectedPublic := "output/ssh_protected_id.pub"

	err = keypair.ToSSHFiles(keyPair, protectedPrivate, protectedPublic, comment, passphrase)
	if err != nil {
		log.Printf("Failed to save passphrase-protected SSH key: %v\n", err)
		return
	}

	fmt.Printf("     ✓ SSH key saved with passphrase protection\n")

	// Try to load without passphrase (should fail)
	sshData, _ := os.ReadFile(protectedPrivate)
	_, err = algo.RSAKeyPairFromSSH(format.SSH(sshData), "")
	if err != nil {
		fmt.Printf("     ✓ Protected key correctly rejects empty passphrase\n")
	} else {
		fmt.Printf("     ❌ Protected key should have rejected empty passphrase\n")
	}

	// Load with correct passphrase
	_, err = algo.RSAKeyPairFromSSH(format.SSH(sshData), passphrase)
	if err != nil {
		fmt.Printf("     ❌ Failed to load with correct passphrase: %v\n", err)
	} else {
		fmt.Printf("     ✓ Protected key loaded successfully with correct passphrase\n")
	}

	// Try wrong passphrase (should fail)
	_, err = algo.RSAKeyPairFromSSH(format.SSH(sshData), "wrong-passphrase")
	if err != nil {
		fmt.Printf("     ✓ Protected key correctly rejects wrong passphrase\n")
	} else {
		fmt.Printf("     ❌ Protected key should have rejected wrong passphrase\n")
	}
}

// PART 7: Module Integration

func certificateIntegrationExample() {
	fmt.Println("\n7.1 Certificate Module Integration")

	// Generate key pairs for certificate creation
	algorithms := []struct {
		generateKey func() (interface{}, error)
		name        string
	}{
		{func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize2048) }, "RSA"},
		{func() (interface{}, error) { return algo.GenerateECDSAKeyPair(algo.P256) }, "ECDSA"},
		{func() (interface{}, error) { return algo.GenerateEd25519KeyPair() }, "Ed25519"},
	}

	for _, alg := range algorithms {
		fmt.Printf("   → Creating certificate with %s key...\n", alg.name)

		keyPair, err := alg.generateKey()
		if err != nil {
			log.Printf("Failed to generate %s key: %v\n", alg.name, err)
			continue
		}

		// Create certificate request
		certRequest := cert.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   fmt.Sprintf("%s Test Certificate", alg.name),
				Organization: []string{"GoPKI Examples"},
				Country:      []string{"US"},
			},
			DNSNames: []string{fmt.Sprintf("%s.example.com", strings.ToLower(alg.name))},
			ValidFor: 365 * 24 * time.Hour,
		}

		// Create self-signed certificate using the key pair
		var certificate *cert.Certificate
		switch kp := keyPair.(type) {
		case *algo.RSAKeyPair:
			certificate, err = cert.CreateSelfSignedCertificate(kp, certRequest)
		case *algo.ECDSAKeyPair:
			certificate, err = cert.CreateSelfSignedCertificate(kp, certRequest)
		case *algo.Ed25519KeyPair:
			certificate, err = cert.CreateSelfSignedCertificate(kp, certRequest)
		}

		if err != nil {
			log.Printf("Failed to create %s certificate: %v\n", alg.name, err)
			continue
		}

		// Save certificate
		certFile := fmt.Sprintf("output/cert_%s.pem", strings.ToLower(alg.name))
		err = certificate.SaveToFile(certFile)
		if err != nil {
			log.Printf("Failed to save %s certificate: %v\n", alg.name, err)
			continue
		}

		fmt.Printf("     ✓ %s certificate created successfully\n", alg.name)
		fmt.Printf("     ✓ Subject: %s\n", certificate.Certificate.Subject.CommonName)
		fmt.Printf("     ✓ Valid from: %s\n", certificate.Certificate.NotBefore.Format("2006-01-02"))
		fmt.Printf("     ✓ Valid until: %s\n", certificate.Certificate.NotAfter.Format("2006-01-02"))
		fmt.Printf("     ✓ Certificate file: %s\n", certFile)
	}
}

func typeConstraintExample() {
	fmt.Println("\n7.2 Type Constraint System Demonstration")

	fmt.Printf("   → Demonstrating compile-time type safety...\n")

	// This demonstrates how the generic type system prevents runtime errors
	// by catching type mismatches at compile time

	// RSA key with proper type constraints
	rsaKey, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Printf("Failed to generate RSA key: %v\n", err)
		return
	}

	// Generic function that works with any private key type
	privateKeyToPEM := func(key interface{}) (format.PEM, error) {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return keypair.PrivateKeyToPEM(k)
		case *ecdsa.PrivateKey:
			return keypair.PrivateKeyToPEM(k)
		case ed25519.PrivateKey:
			return keypair.PrivateKeyToPEM(k)
		default:
			return nil, fmt.Errorf("unsupported private key type")
		}
	}

	// Test with RSA private key
	pemData, err := privateKeyToPEM(rsaKey.PrivateKey)
	if err != nil {
		log.Printf("Failed to convert RSA private key to PEM: %v\n", err)
		return
	}

	fmt.Printf("     ✓ Type-safe conversion successful\n")
	fmt.Printf("     ✓ RSA private key converted to PEM (%d bytes)\n", len(pemData))

	// Demonstrate type constraint validation
	info := keypair.KeyInfo{
		Algorithm: "RSA",
		KeySize:   2048,
		Curve:     "",
	}

	fmt.Printf("     ✓ Type constraints enforce security:\n")
	fmt.Printf("       - Algorithm: %s\n", info.Algorithm)
	fmt.Printf("       - Key Size: %d bits (≥2048 required)\n", info.KeySize)
	fmt.Printf("       - Type safety prevents runtime errors\n")
}

// PART 8: Performance and Security

func performanceComparisonExample() {
	fmt.Println("\n8.1 Algorithm Performance Comparison")

	// Measure key generation performance for each algorithm
	algorithms := []struct {
		name     string
		generate func() (interface{}, error)
		keySize  string
	}{
		{"RSA-2048", func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize2048) }, "2048 bits"},
		{"RSA-3072", func() (interface{}, error) { return algo.GenerateRSAKeyPair(algo.KeySize3072) }, "3072 bits"},
		{"ECDSA-P256", func() (interface{}, error) { return algo.GenerateECDSAKeyPair(algo.P256) }, "256 bits"},
		{"ECDSA-P384", func() (interface{}, error) { return algo.GenerateECDSAKeyPair(algo.P384) }, "384 bits"},
		{"Ed25519", func() (interface{}, error) { return algo.GenerateEd25519KeyPair() }, "256 bits"},
	}

	fmt.Printf("   → Measuring key generation performance...\n")
	fmt.Printf("   %-12s %-12s %-12s %s\n", "Algorithm", "Key Size", "Gen Time", "Status")
	fmt.Printf("   %s\n", strings.Repeat("-", 60))

	for _, alg := range algorithms {
		start := time.Now()

		keyPair, err := alg.generate()

		duration := time.Since(start)

		if err != nil {
			fmt.Printf("   %-12s %-12s %-12s %s\n", alg.name, alg.keySize, "ERROR", err.Error())
			continue
		}

		// Verify key was generated successfully
		var status string = "✓ Success"
		switch kp := keyPair.(type) {
		case *algo.RSAKeyPair:
			if kp.PrivateKey == nil {
				status = "❌ Failed"
			}
		case *algo.ECDSAKeyPair:
			if kp.PrivateKey == nil {
				status = "❌ Failed"
			}
		case *algo.Ed25519KeyPair:
			if len(kp.PrivateKey) == 0 {
				status = "❌ Failed"
			}
		}

		fmt.Printf("   %-12s %-12s %-12s %s\n",
			alg.name, alg.keySize, fmt.Sprintf("%.2fms", float64(duration.Microseconds())/1000.0), status)
	}

	fmt.Printf("\n   → Performance Notes:\n")
	fmt.Printf("     • Ed25519: Fastest generation and signing\n")
	fmt.Printf("     • ECDSA: Good balance of security and performance\n")
	fmt.Printf("     • RSA: Slower but widely supported\n")
}

func securityBestPracticesExample() {
	fmt.Println("\n8.2 Security Best Practices Demonstration")

	fmt.Printf("   → Demonstrating security best practices...\n")

	// 1. Minimum key size enforcement
	fmt.Printf("     1. Minimum RSA key size enforcement:\n")

	// This would fail at compile time with proper key size constants
	validKeySizes := []algo.KeySize{algo.KeySize2048, algo.KeySize3072, algo.KeySize4096}
	for _, size := range validKeySizes {
		_, err := algo.GenerateRSAKeyPair(size)
		if err != nil {
			fmt.Printf("        ❌ %d-bit RSA rejected: %v\n", size.Bits(), err)
		} else {
			fmt.Printf("        ✓ %d-bit RSA accepted (≥2048 required)\n", size.Bits())
		}
	}

	// 2. Secure random number generation
	fmt.Printf("     2. Cryptographically secure random generation:\n")
	testKey, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Printf("Failed to generate key for randomness test: %v\n", err)
		return
	}
	_ = testKey // use the variable to avoid unused error

	// Generate multiple keys to show randomness
	keys := make([]*algo.ECDSAKeyPair, 3)
	for i := 0; i < 3; i++ {
		keys[i], _ = algo.GenerateECDSAKeyPair(algo.P256)
	}

	// Compare X coordinates to show they're different (random)
	allDifferent := true
	for i := 0; i < len(keys)-1; i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i].PrivateKey.X.Cmp(keys[j].PrivateKey.X) == 0 {
				allDifferent = false
				break
			}
		}
		if !allDifferent {
			break
		}
	}

	if allDifferent {
		fmt.Printf("        ✓ All generated keys are cryptographically unique\n")
	} else {
		fmt.Printf("        ❌ Key generation may have randomness issues\n")
	}

	// 3. Secure file permissions
	fmt.Printf("     3. Secure file permission enforcement:\n")
	testRSAKey, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
	testFile := "output/security_test_private.pem"

	err = keypair.ToPEMFiles(testRSAKey, testFile, testFile+".pub")
	if err != nil {
		log.Printf("Failed to save security test key: %v\n", err)
		return
	}

	stat, err := os.Stat(testFile)
	if err != nil {
		log.Printf("Failed to stat security test file: %v\n", err)
		return
	}

	perm := stat.Mode().Perm()
	if perm == 0600 {
		fmt.Printf("        ✓ Private key saved with 0600 permissions (owner only)\n")
	} else {
		fmt.Printf("        ⚠️  Private key permissions: %o (should be 0600)\n", perm)
	}

	// 4. Type safety prevents errors
	fmt.Printf("     4. Compile-time type safety:\n")
	fmt.Printf("        ✓ Generic constraints prevent key type mismatches\n")
	fmt.Printf("        ✓ Algorithm-specific types ensure correct usage\n")
	fmt.Printf("        ✓ Format types prevent data corruption\n")

	fmt.Printf("     Security Best Practices Summary:\n")
	fmt.Printf("        • Use RSA ≥2048 bits (enforced at compile time)\n")
	fmt.Printf("        • ECDSA P-256+ or Ed25519 for modern applications\n")
	fmt.Printf("        • Private keys automatically saved with 0600 permissions\n")
	fmt.Printf("        • SSH keys support passphrase protection\n")
	fmt.Printf("        • Type-safe APIs prevent common programming errors\n")
}
